# Copyright 2026 actiongate-oss
# Licensed under the Business Source License 1.1 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""Core types for RuleGate."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable


class Mode(Enum):
    """Enforcement mode for blocked actions."""
    HARD = auto()  # Raise exception on block
    SOFT = auto()  # Return blocked decision (caller handles fallback)


class StoreErrorMode(Enum):
    """Behavior when store backend fails."""
    FAIL_CLOSED = auto()  # Block action (safe default)
    FAIL_OPEN = auto()    # Allow action (availability over safety)


class Status(Enum):
    """Decision outcome."""
    ALLOW = auto()
    BLOCK = auto()


class BlockReason(Enum):
    """Why an action was blocked."""
    POLICY_VIOLATION = auto()  # One or more rules failed
    STORE_ERROR = auto()       # Backend failure (behavior depends on ruleset)


@dataclass(frozen=True, slots=True)
class Rule:
    """Identifies a policy-checked action stream.

    Examples:
        Rule("api", "search", "user:123")       # per-user policy
        Rule("support", "escalate", "agent:42")  # per-agent policy
        Rule("billing", "refund", "global")      # global policy
    """
    namespace: str
    action: str
    principal: str = "global"

    def __str__(self) -> str:
        return f"{self.namespace}:{self.action}@{self.principal}"

    @property
    def key(self) -> str:
        """Redis-friendly key string."""
        return f"rg:{self.namespace}:{self.action}:{self.principal}"


@dataclass(frozen=True, slots=True)
class Context:
    """Immutable context passed to rule predicates.

    Carries the arguments and metadata of the action being evaluated.
    Rules inspect this to decide allow/deny without side effects.

    Args:
        rule: The rule being evaluated.
        args: Positional arguments to the guarded function.
        kwargs: Keyword arguments to the guarded function.
        meta: Arbitrary metadata (e.g., headers, session info).
    """
    rule: Rule
    args: tuple[Any, ...] = ()
    kwargs: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)


# Type alias for rule predicates.
# A predicate receives a Context and returns True (allow) or False (deny).
Predicate = Callable[[Context], bool]


@dataclass(frozen=True, slots=True)
class NamedPredicate:
    """A predicate with a human-readable name for diagnostics.

    When a predicate fails, the name appears in Decision.violated_rules
    so operators can identify which rule blocked the action.
    """
    name: str
    fn: Predicate

    def __call__(self, ctx: Context) -> bool:
        return self.fn(ctx)


@dataclass(frozen=True, slots=True)
class Ruleset:
    """Policy rules for a gated action.

    A ruleset contains one or more predicates. ALL must pass for the action
    to be allowed (conjunction / AND logic). Any failure blocks the action.

    Predicates can be plain callables or NamedPredicate instances.
    Plain callables use their __name__ or __qualname__ for diagnostics.

    Args:
        predicates: One or more rule predicates (all must pass).
        mode: HARD raises on block, SOFT returns decision.
        on_store_error: FAIL_CLOSED blocks, FAIL_OPEN allows.

    Example:
        def no_pii(ctx: Context) -> bool:
            return "ssn" not in str(ctx.kwargs.get("query", "")).lower()

        Ruleset(
            predicates=[no_pii],
            mode=Mode.HARD,
        )
    """
    predicates: tuple[Predicate | NamedPredicate, ...] = ()
    mode: Mode = Mode.HARD
    on_store_error: StoreErrorMode = StoreErrorMode.FAIL_CLOSED

    def __post_init__(self) -> None:
        if not self.predicates:
            raise ValueError("predicates must not be empty")
        for p in self.predicates:
            if not callable(p):
                raise TypeError(f"predicate must be callable, got {type(p).__name__}")


@dataclass(frozen=True, slots=True)
class Decision:
    """Result of evaluating an action against its ruleset."""
    status: Status
    rule: Rule
    ruleset: Ruleset
    reason: BlockReason | None = None
    message: str | None = None
    violated_rules: tuple[str, ...] = ()
    evaluated_count: int = 0

    @property
    def allowed(self) -> bool:
        return self.status == Status.ALLOW

    @property
    def blocked(self) -> bool:
        return self.status == Status.BLOCK

    def __bool__(self) -> bool:
        """Truthy = allowed."""
        return self.allowed


class _Missing:
    """Sentinel for distinguishing None from missing value."""
    __slots__ = ()
    def __repr__(self) -> str:
        return "<MISSING>"

MISSING = _Missing()


@dataclass(frozen=True, slots=True)
class Result[T]:
    """Wrapper for guarded function results.

    Uses a sentinel to distinguish between:
    - Function returned None (legitimate value)
    - Function was blocked (no value)
    """
    decision: Decision
    _value: T | _Missing = MISSING

    @property
    def ok(self) -> bool:
        return self.decision.allowed

    @property
    def has_value(self) -> bool:
        return not isinstance(self._value, _Missing)

    @property
    def value(self) -> T | None:
        """Get value or None if blocked/missing."""
        if isinstance(self._value, _Missing):
            return None
        return self._value

    def unwrap(self) -> T:
        """Get value or raise if blocked."""
        if isinstance(self._value, _Missing):
            raise ValueError(f"No value: {self.decision.message or 'blocked'}")
        return self._value

    def unwrap_or(self, default: T) -> T:
        """Get value or return default if blocked."""
        if isinstance(self._value, _Missing):
            return default
        return self._value
