# Copyright 2026 actiongate-oss
# Licensed under the Apache License, Version 2.0

"""Core engine for RuleGate."""

from __future__ import annotations

import time
from functools import wraps
from typing import Any, Callable, ParamSpec, TypeVar

from .core import (
    BlockReason, Context, Decision, Mode, NamedPredicate,
    Predicate, Result, Rule, Ruleset, Status,
)
from .emitter import Emitter
from .store import MemoryStore, Store

P = ParamSpec("P")
T = TypeVar("T")


class PolicyViolation(RuntimeError):
    """Raised when action violates policy in HARD mode."""
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.message or f"Policy violation: {decision.reason}")
        self.decision = decision


def _predicate_name(predicate: Predicate | NamedPredicate) -> str:
    if isinstance(predicate, NamedPredicate):
        return predicate.name
    name = getattr(predicate, "__qualname__", None) or getattr(predicate, "__name__", None)
    return name or repr(predicate)


class Engine:
    """RuleGate engine for policy enforcement on agent actions."""

    __slots__ = ("_store", "_clock", "_rulesets", "_emitter", "_store_errors")

    def __init__(self, store: Store | None = None, clock: Callable[[], float] | None = None,
                 emitter: Emitter | None = None) -> None:
        self._store: Store = store or MemoryStore()
        self._clock = clock or time.monotonic
        self._rulesets: dict[Rule, Ruleset] = {}
        self._emitter = emitter or Emitter()
        self._store_errors = 0

    def register(self, rule: Rule, ruleset: Ruleset) -> None:
        self._rulesets[rule] = ruleset

    def ruleset_for(self, rule: Rule) -> Ruleset | None:
        return self._rulesets.get(rule)

    def on_decision(self, listener: Callable[[Decision], None]) -> None:
        self._emitter.add(listener)

    @property
    def listener_errors(self) -> int:
        return self._emitter.error_count

    def check(self, rule: Rule, ruleset: Ruleset | None = None, *,
              args: tuple[Any, ...] = (), kwargs: dict[str, Any] | None = None,
              meta: dict[str, Any] | None = None) -> Decision:
        return self._evaluate(rule, ruleset, args=args, kwargs=kwargs, meta=meta, short_circuit=True)

    def check_all(self, rule: Rule, ruleset: Ruleset | None = None, *,
                  args: tuple[Any, ...] = (), kwargs: dict[str, Any] | None = None,
                  meta: dict[str, Any] | None = None) -> Decision:
        return self._evaluate(rule, ruleset, args=args, kwargs=kwargs, meta=meta, short_circuit=False)

    def enforce(self, decision: Decision) -> None:
        if decision.blocked and decision.ruleset.mode == Mode.HARD:
            raise PolicyViolation(decision)

    def clear(self, rule: Rule) -> None:
        self._store.clear(rule)

    def clear_all(self) -> None:
        self._store.clear_all()

    def guard(self, rule: Rule, ruleset: Ruleset | None = None, *,
              meta: dict[str, Any] | None = None) -> Callable[[Callable[P, T]], Callable[P, T]]:
        if ruleset is not None:
            self.register(rule, ruleset)
        def decorator(fn: Callable[P, T]) -> Callable[P, T]:
            @wraps(fn)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                decision = self.check(rule, args=args, kwargs=dict(kwargs), meta=meta or {})
                if decision.blocked:
                    raise PolicyViolation(decision)
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    def guard_result(self, rule: Rule, ruleset: Ruleset | None = None, *,
                     meta: dict[str, Any] | None = None) -> Callable[[Callable[P, T]], Callable[P, Result[T]]]:
        if ruleset is not None:
            self.register(rule, ruleset)
        def decorator(fn: Callable[P, T]) -> Callable[P, Result[T]]:
            @wraps(fn)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T]:
                decision = self.check(rule, args=args, kwargs=dict(kwargs), meta=meta or {})
                if decision.blocked:
                    return Result(decision=decision)
                value = fn(*args, **kwargs)
                return Result(decision=decision, _value=value)
            return wrapper
        return decorator

    def _evaluate(self, rule: Rule, ruleset: Ruleset | None, *, args: tuple[Any, ...],
                  kwargs: dict[str, Any] | None, meta: dict[str, Any] | None,
                  short_circuit: bool) -> Decision:
        now = self._clock()
        ruleset = ruleset or self.ruleset_for(rule)
        if ruleset is None:
            method = "check" if short_circuit else "check_all"
            raise ValueError(f"No ruleset registered for {rule}. Call engine.register() or pass ruleset to {method}().")
        ctx = Context(rule=rule, args=args, kwargs=kwargs or {}, meta=meta or {})
        violated: list[str] = []
        evaluated = 0
        for predicate in ruleset.predicates:
            evaluated += 1
            try:
                result = predicate(ctx)
            except Exception as e:
                name = _predicate_name(predicate)
                violated.append(f"{name} (raised: {type(e).__name__}: {e})")
                if short_circuit:
                    break
                continue
            if not result:
                violated.append(_predicate_name(predicate))
                if short_circuit:
                    break
        if violated:
            decision = self._decide(rule, ruleset, status=Status.BLOCK,
                                    reason=BlockReason.POLICY_VIOLATION,
                                    message=f"Policy violation: {', '.join(violated)}",
                                    violated_rules=tuple(violated), evaluated_count=evaluated)
        else:
            decision = self._decide(rule, ruleset, status=Status.ALLOW, evaluated_count=evaluated)
        try:
            self._store.record(rule, now, decision)
        except Exception:
            self._store_errors += 1
        return decision

    def _decide(self, rule: Rule, ruleset: Ruleset, *, status: Status,
                reason: BlockReason | None = None, message: str | None = None,
                violated_rules: tuple[str, ...] = (), evaluated_count: int = 0) -> Decision:
        decision = Decision(status=status, rule=rule, ruleset=ruleset, reason=reason,
                            message=message, violated_rules=violated_rules,
                            evaluated_count=evaluated_count)
        self._emitter.emit(decision)
        return decision
