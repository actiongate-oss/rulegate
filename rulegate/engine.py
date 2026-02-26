# Copyright 2026 actiongate-oss
# Licensed under the Business Source License 1.1 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""Core engine for RuleGate."""

from __future__ import annotations

import time
from functools import wraps
from typing import Any, Callable, ParamSpec, TypeVar

from .core import (
    BlockReason,
    Context,
    Decision,
    Mode,
    NamedPredicate,
    Predicate,
    Result,
    Rule,
    Ruleset,
    Status,
)
from .store import MemoryStore, Store

P = ParamSpec("P")
T = TypeVar("T")


class PolicyViolation(RuntimeError):
    """Raised when action violates policy in HARD mode."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.message or f"Policy violation: {decision.reason}")
        self.decision = decision


def _predicate_name(predicate: Predicate | NamedPredicate) -> str:
    """Extract a human-readable name from a predicate."""
    if isinstance(predicate, NamedPredicate):
        return predicate.name
    name = getattr(predicate, "__qualname__", None) or getattr(predicate, "__name__", None)
    return name or repr(predicate)


class Engine:
    """RuleGate engine for policy enforcement on agent actions.

    RuleGate evaluates callable predicates against action context
    before execution. All predicates in a ruleset must pass for
    the action to be allowed (conjunction / AND logic).

    Rules are stateless: evaluation depends only on the predicates
    and the context at call time, never on stored state. The store
    is used only for audit logging of evaluation outcomes.

    Example:
        engine = Engine()

        def no_pii(ctx: Context) -> bool:
            return "ssn" not in str(ctx.kwargs.get("query", "")).lower()

        def business_hours(ctx: Context) -> bool:
            return 9 <= ctx.meta["hour"] < 17

        @engine.guard(
            Rule("api", "search"),
            Ruleset(predicates=(no_pii, business_hours)),
        )
        def search(query: str) -> list[str]:
            return db.search(query)

        try:
            results = search(query="find user")
        except PolicyViolation as e:
            print(f"Blocked: {e.decision.violated_rules}")

        # Or use guard_result for no-exception handling:
        @engine.guard_result(
            Rule("api", "fetch"),
            Ruleset(predicates=(no_pii,), mode=Mode.SOFT),
        )
        def fetch(url: str) -> dict:
            return requests.get(url).json()

        result = fetch(url="https://api.example.com")
        data = result.unwrap_or({"error": "policy violation"})
    """

    __slots__ = ("_store", "_clock", "_rulesets", "_listeners", "_errors")

    def __init__(
        self,
        store: Store | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._store: Store = store or MemoryStore()
        self._clock = clock or time.monotonic
        self._rulesets: dict[Rule, Ruleset] = {}
        self._listeners: list[Callable[[Decision], None]] = []
        self._errors = 0

    # ─────────────────────────────────────────────────────────────
    # Configuration
    # ─────────────────────────────────────────────────────────────

    def register(self, rule: Rule, ruleset: Ruleset) -> None:
        """Register a ruleset for a rule."""
        self._rulesets[rule] = ruleset

    def ruleset_for(self, rule: Rule) -> Ruleset | None:
        """Get ruleset for rule (None if not registered)."""
        return self._rulesets.get(rule)

    def on_decision(self, listener: Callable[[Decision], None]) -> None:
        """Add a listener for decisions (for logging/metrics)."""
        self._listeners.append(listener)

    @property
    def listener_errors(self) -> int:
        """Count of listener exceptions (never block execution)."""
        return self._errors

    # ─────────────────────────────────────────────────────────────
    # Core API
    # ─────────────────────────────────────────────────────────────

    def check(
        self,
        rule: Rule,
        ruleset: Ruleset | None = None,
        *,
        args: tuple[Any, ...] = (),
        kwargs: dict[str, Any] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> Decision:
        """Evaluate all predicates in the ruleset against the action context.

        All predicates must return True for the action to be allowed.
        Evaluation short-circuits on the first failure.

        Args:
            rule: The rule identity to evaluate.
            ruleset: Ruleset to use (overrides registered). Required if not registered.
            args: Positional arguments to the guarded function.
            kwargs: Keyword arguments to the guarded function.
            meta: Arbitrary metadata for predicates to inspect.

        Returns:
            Decision with status ALLOW or BLOCK.

        Raises:
            ValueError: If no ruleset is registered or provided.
        """
        return self._evaluate(
            rule, ruleset, args=args, kwargs=kwargs, meta=meta, short_circuit=True,
        )

    def check_all(
        self,
        rule: Rule,
        ruleset: Ruleset | None = None,
        *,
        args: tuple[Any, ...] = (),
        kwargs: dict[str, Any] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> Decision:
        """Evaluate ALL predicates without short-circuiting.

        Unlike check(), this evaluates every predicate even after a failure.
        Useful for diagnostics: shows all violated rules, not just the first.

        Same signature and return type as check().
        """
        return self._evaluate(
            rule, ruleset, args=args, kwargs=kwargs, meta=meta, short_circuit=False,
        )

    def enforce(self, decision: Decision) -> None:
        """Raise PolicyViolation if decision is blocked in HARD mode."""
        if decision.blocked and decision.ruleset.mode == Mode.HARD:
            raise PolicyViolation(decision)

    def clear(self, rule: Rule) -> None:
        """Clear evaluation records for a rule."""
        self._store.clear(rule)

    def clear_all(self) -> None:
        """Clear all evaluation records."""
        self._store.clear_all()

    # ─────────────────────────────────────────────────────────────
    # Decorator API
    # ─────────────────────────────────────────────────────────────

    def guard(
        self,
        rule: Rule,
        ruleset: Ruleset | None = None,
        *,
        meta: dict[str, Any] | None = None,
    ) -> Callable[[Callable[P, T]], Callable[P, T]]:
        """Decorator that returns T directly.

        Evaluates all predicates before executing the guarded function.
        The function's args and kwargs are passed to predicates via Context.

        Raises PolicyViolation on block regardless of mode.
        Use guard_result for no-exception handling.

        Args:
            rule: The rule identity.
            ruleset: Ruleset to register (optional if already registered).
            meta: Static metadata passed to every evaluation.

        Example:
            @engine.guard(Rule("api", "search"), Ruleset(predicates=(no_pii,)))
            def search(query: str) -> list[str]:
                return db.search(query)

            results = search("hello")  # Returns list[str] or raises PolicyViolation
        """
        if ruleset is not None:
            self.register(rule, ruleset)

        def decorator(fn: Callable[P, T]) -> Callable[P, T]:
            @wraps(fn)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                decision = self.check(
                    rule,
                    args=args,
                    kwargs=dict(kwargs),
                    meta=meta or {},
                )
                if decision.blocked:
                    raise PolicyViolation(decision)
                return fn(*args, **kwargs)

            return wrapper

        return decorator

    def guard_result(
        self,
        rule: Rule,
        ruleset: Ruleset | None = None,
        *,
        meta: dict[str, Any] | None = None,
    ) -> Callable[[Callable[P, T]], Callable[P, Result[T]]]:
        """Decorator that returns Result[T] (never raises).

        Use this when you want to handle policy violations gracefully
        without exceptions.

        Example:
            @engine.guard_result(
                Rule("api", "fetch"),
                Ruleset(predicates=(no_pii,), mode=Mode.SOFT),
            )
            def fetch(url: str) -> dict:
                return requests.get(url).json()

            result = fetch(url="https://api.example.com")
            data = result.unwrap_or({"error": "policy violation"})
        """
        if ruleset is not None:
            self.register(rule, ruleset)

        def decorator(fn: Callable[P, T]) -> Callable[P, Result[T]]:
            @wraps(fn)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T]:
                decision = self.check(
                    rule,
                    args=args,
                    kwargs=dict(kwargs),
                    meta=meta or {},
                )

                if decision.blocked:
                    return Result(decision=decision)

                value = fn(*args, **kwargs)
                return Result(decision=decision, _value=value)

            return wrapper

        return decorator

    # ─────────────────────────────────────────────────────────────
    # Internal
    # ─────────────────────────────────────────────────────────────

    def _evaluate(
        self,
        rule: Rule,
        ruleset: Ruleset | None,
        *,
        args: tuple[Any, ...],
        kwargs: dict[str, Any] | None,
        meta: dict[str, Any] | None,
        short_circuit: bool,
    ) -> Decision:
        """Shared evaluation logic for check() and check_all()."""
        now = self._clock()
        ruleset = ruleset or self.ruleset_for(rule)

        if ruleset is None:
            method = "check" if short_circuit else "check_all"
            raise ValueError(
                f"No ruleset registered for {rule}. "
                f"Call engine.register() or pass ruleset to {method}()."
            )

        ctx = Context(
            rule=rule,
            args=args,
            kwargs=kwargs or {},
            meta=meta or {},
        )

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
            decision = self._decide(
                rule,
                ruleset,
                status=Status.BLOCK,
                reason=BlockReason.POLICY_VIOLATION,
                message=f"Policy violation: {', '.join(violated)}",
                violated_rules=tuple(violated),
                evaluated_count=evaluated,
            )
        else:
            decision = self._decide(
                rule,
                ruleset,
                status=Status.ALLOW,
                evaluated_count=evaluated,
            )

        # Audit log (fire-and-forget, never affects decision)
        try:
            self._store.record(rule, now, decision)
        except Exception:
            self._errors += 1

        return decision

    def _decide(
        self,
        rule: Rule,
        ruleset: Ruleset,
        *,
        status: Status,
        reason: BlockReason | None = None,
        message: str | None = None,
        violated_rules: tuple[str, ...] = (),
        evaluated_count: int = 0,
    ) -> Decision:
        decision = Decision(
            status=status,
            rule=rule,
            ruleset=ruleset,
            reason=reason,
            message=message,
            violated_rules=violated_rules,
            evaluated_count=evaluated_count,
        )
        self._emit(decision)
        return decision

    def _emit(self, decision: Decision) -> None:
        for listener in self._listeners:
            try:
                listener(decision)
            except Exception:
                self._errors += 1
