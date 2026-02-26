# Copyright 2026 actiongate-oss
# Licensed under the Business Source License 1.1 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""Storage backends for RuleGate.

RuleGate rules are stateless predicates — they don't accumulate events
like ActionGate or BudgetGate. The store records evaluation outcomes
for observability and audit purposes.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol

from .core import Decision, Rule


@dataclass(slots=True)
class EvalRecord:
    """A recorded rule evaluation."""
    ts: float
    decision: Decision


class Store(Protocol):
    """Storage backend protocol for evaluation records.

    Implementations provide audit logging of rule evaluation outcomes.
    Unlike ActionGate/BudgetGate stores, the RuleGate store is NOT
    in the critical path — evaluation does not depend on store state.
    Store failures never affect the allow/deny decision.
    """

    def record(self, rule: Rule, now: float, decision: Decision) -> None:
        """Record an evaluation outcome.

        This is fire-and-forget. Failures are silently ignored
        (they do not affect the decision).
        """
        ...

    def get_records(
        self,
        rule: Rule,
        now: float,
        window: float | None,
    ) -> list[EvalRecord]:
        """Get evaluation records for a rule within a time window.

        Args:
            rule: The rule to query.
            now: Current timestamp.
            window: Rolling window in seconds (None = all records).

        Returns:
            List of evaluation records, oldest first.
        """
        ...

    def clear(self, rule: Rule) -> None:
        """Clear evaluation records for a specific rule."""
        ...

    def clear_all(self) -> None:
        """Clear all evaluation records."""
        ...


class MemoryStore:
    """Thread-safe in-memory store for evaluation records.

    Lock ordering (must always acquire in this order to prevent deadlock):
        1. _global_lock
        2. rule-specific lock from _locks

    Suitable for single-process deployments and testing.
    """

    __slots__ = ("_records", "_locks", "_global_lock")

    def __init__(self) -> None:
        self._records: dict[Rule, list[EvalRecord]] = {}
        self._locks: dict[Rule, threading.Lock] = {}
        self._global_lock = threading.Lock()

    def _get_lock(self, rule: Rule) -> threading.Lock:
        """Get or create lock for rule. Must hold _global_lock when calling."""
        if rule not in self._locks:
            self._locks[rule] = threading.Lock()
        return self._locks[rule]

    def _prune(
        self,
        records: list[EvalRecord],
        now: float,
        window: float | None,
    ) -> list[EvalRecord]:
        """Remove records outside the window."""
        if window is None:
            return list(records)
        cutoff = now - window
        return [r for r in records if r.ts >= cutoff]

    def record(self, rule: Rule, now: float, decision: Decision) -> None:
        with self._global_lock:
            lock = self._get_lock(rule)
            with lock:
                records = self._records.get(rule, [])
                records.append(EvalRecord(ts=now, decision=decision))
                self._records[rule] = records

    def get_records(
        self,
        rule: Rule,
        now: float,
        window: float | None,
    ) -> list[EvalRecord]:
        with self._global_lock:
            lock = self._get_lock(rule)
            with lock:
                records = self._records.get(rule, [])
                pruned = self._prune(records, now, window)
                self._records[rule] = pruned
                return list(pruned)

    def clear(self, rule: Rule) -> None:
        with self._global_lock:
            lock = self._get_lock(rule)
            with lock:
                self._records.pop(rule, None)

    def clear_all(self) -> None:
        with self._global_lock:
            self._records.clear()
            self._locks.clear()
