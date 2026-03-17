# Copyright 2026 actiongate-oss
# Licensed under the Apache License, Version 2.0;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""RuleGate: Deterministic policy enforcement for agent systems.

Evaluates callable predicates against action context before execution.
All rules must pass for the action to proceed. Pairs with ActionGate
and BudgetGate as composable primitives in the agent execution layer.

Example:
    from rulegate import Engine, Rule, Ruleset, Context, PolicyViolationError

    engine = Engine()

    def no_pii(ctx: Context) -> bool:
        return "ssn" not in str(ctx.kwargs.get("query", "")).lower()

    @engine.guard(Rule("api", "search"), Ruleset(predicates=(no_pii,)))
    def search(query: str) -> list[str]:
        return api.search(query)

    try:
        results = search(query="find user")
    except PolicyViolationError as e:
        print(f"Blocked: {e.decision.violated_rules}")
"""

from .core import (
    MISSING,
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
    StoreErrorMode,
)
from .emitter import Emitter
from .engine import Engine, PolicyViolationError
from .store import AsyncMemoryStore, AsyncStore, EvalRecord, MemoryStore, Store

__all__ = [
    # Core types
    "Rule",
    "Ruleset",
    "Context",
    "Decision",
    "Result",
    "MISSING",
    "Predicate",
    "NamedPredicate",
    # Enums
    "Mode",
    "Status",
    "BlockReason",
    "StoreErrorMode",
    # Engine
    "Engine",
    "PolicyViolationError",
    "Emitter",
    # Store
    "Store",
    "AsyncStore",
    "MemoryStore",
    "AsyncMemoryStore",
    "EvalRecord",
]

__version__ = "0.3.0"
