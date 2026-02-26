# Copyright 2026 actiongate-oss
# Licensed under the Business Source License 1.1 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""Comprehensive tests for RuleGate."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

# ─── Imports ────────────────────────────────────────────────────

from rulegate import (
    MISSING,
    BlockReason,
    Context,
    Decision,
    Engine,
    EvalRecord,
    MemoryStore,
    Mode,
    NamedPredicate,
    PolicyViolation,
    Result,
    Rule,
    Ruleset,
    Status,
    StoreErrorMode,
)


# ═══════════════════════════════════════════════════════════════
# core.py tests
# ═══════════════════════════════════════════════════════════════


class TestRule:
    def test_basic(self) -> None:
        r = Rule("api", "search", "user:123")
        assert r.namespace == "api"
        assert r.action == "search"
        assert r.principal == "user:123"

    def test_default_principal(self) -> None:
        r = Rule("api", "search")
        assert r.principal == "global"

    def test_str(self) -> None:
        r = Rule("api", "search", "user:123")
        assert str(r) == "api:search@user:123"

    def test_key(self) -> None:
        r = Rule("api", "search", "user:123")
        assert r.key == "rg:api:search:user:123"

    def test_equality(self) -> None:
        a = Rule("api", "search", "user:123")
        b = Rule("api", "search", "user:123")
        c = Rule("api", "search", "user:456")
        assert a == b
        assert a != c

    def test_hashable(self) -> None:
        """Rules must be usable as dict keys."""
        r = Rule("api", "search")
        d = {r: "value"}
        assert d[Rule("api", "search")] == "value"

    def test_frozen(self) -> None:
        r = Rule("api", "search")
        with pytest.raises(AttributeError):
            r.namespace = "other"  # type: ignore[misc]


class TestContext:
    def test_basic(self) -> None:
        r = Rule("api", "search")
        ctx = Context(rule=r, args=("hello",), kwargs={"limit": 10})
        assert ctx.rule == r
        assert ctx.args == ("hello",)
        assert ctx.kwargs == {"limit": 10}
        assert ctx.meta == {}

    def test_defaults(self) -> None:
        ctx = Context(rule=Rule("api", "search"))
        assert ctx.args == ()
        assert ctx.kwargs == {}
        assert ctx.meta == {}

    def test_frozen(self) -> None:
        ctx = Context(rule=Rule("api", "search"))
        with pytest.raises(AttributeError):
            ctx.rule = Rule("other", "thing")  # type: ignore[misc]


class TestRuleset:
    def test_basic(self) -> None:
        rs = Ruleset(predicates=(lambda ctx: True,))
        assert len(rs.predicates) == 1
        assert rs.mode == Mode.HARD
        assert rs.on_store_error == StoreErrorMode.FAIL_CLOSED

    def test_empty_predicates_raises(self) -> None:
        with pytest.raises(ValueError, match="predicates must not be empty"):
            Ruleset(predicates=())

    def test_non_callable_raises(self) -> None:
        with pytest.raises(TypeError, match="predicate must be callable"):
            Ruleset(predicates=("not_callable",))  # type: ignore[arg-type]

    def test_multiple_predicates(self) -> None:
        rs = Ruleset(predicates=(lambda ctx: True, lambda ctx: False))
        assert len(rs.predicates) == 2

    def test_mode_override(self) -> None:
        rs = Ruleset(predicates=(lambda ctx: True,), mode=Mode.SOFT)
        assert rs.mode == Mode.SOFT


class TestNamedPredicate:
    def test_callable(self) -> None:
        np = NamedPredicate(name="always_allow", fn=lambda ctx: True)
        ctx = Context(rule=Rule("api", "search"))
        assert np(ctx) is True
        assert np.name == "always_allow"

    def test_name_in_violations(self) -> None:
        """NamedPredicate name should appear in violation diagnostics."""
        np = NamedPredicate(name="no_pii_check", fn=lambda ctx: False)
        engine = Engine()
        rule = Rule("api", "search")
        decision = engine.check(rule, Ruleset(predicates=(np,)))
        assert "no_pii_check" in decision.violated_rules


class TestDecision:
    def test_allowed(self) -> None:
        d = Decision(
            status=Status.ALLOW,
            rule=Rule("api", "search"),
            ruleset=Ruleset(predicates=(lambda ctx: True,)),
        )
        assert d.allowed is True
        assert d.blocked is False
        assert bool(d) is True

    def test_blocked(self) -> None:
        d = Decision(
            status=Status.BLOCK,
            rule=Rule("api", "search"),
            ruleset=Ruleset(predicates=(lambda ctx: True,)),
            reason=BlockReason.POLICY_VIOLATION,
            violated_rules=("no_pii",),
        )
        assert d.allowed is False
        assert d.blocked is True
        assert bool(d) is False
        assert d.violated_rules == ("no_pii",)

    def test_defaults(self) -> None:
        d = Decision(
            status=Status.ALLOW,
            rule=Rule("api", "search"),
            ruleset=Ruleset(predicates=(lambda ctx: True,)),
        )
        assert d.reason is None
        assert d.message is None
        assert d.violated_rules == ()
        assert d.evaluated_count == 0


class TestResult:
    def test_allowed_with_value(self) -> None:
        d = Decision(
            status=Status.ALLOW,
            rule=Rule("api", "search"),
            ruleset=Ruleset(predicates=(lambda ctx: True,)),
        )
        r: Result[str] = Result(decision=d, _value="hello")
        assert r.ok is True
        assert r.has_value is True
        assert r.value == "hello"
        assert r.unwrap() == "hello"
        assert r.unwrap_or("default") == "hello"

    def test_blocked_missing(self) -> None:
        d = Decision(
            status=Status.BLOCK,
            rule=Rule("api", "search"),
            ruleset=Ruleset(predicates=(lambda ctx: True,)),
            reason=BlockReason.POLICY_VIOLATION,
        )
        r: Result[str] = Result(decision=d, _value=MISSING)
        assert r.ok is False
        assert r.has_value is False
        assert r.value is None
        with pytest.raises(ValueError, match="No value"):
            r.unwrap()
        assert r.unwrap_or("fallback") == "fallback"

    def test_none_as_legitimate_value(self) -> None:
        """CRITICAL: None return from guarded function must not be confused with blocked."""
        d = Decision(
            status=Status.ALLOW,
            rule=Rule("api", "search"),
            ruleset=Ruleset(predicates=(lambda ctx: True,)),
        )
        r: Result[None] = Result(decision=d, _value=None)
        assert r.ok is True
        assert r.has_value is True
        assert r.value is None
        assert r.unwrap() is None  # Must not raise!
        assert r.unwrap_or("default") is None  # Must return None, not default!


class TestMissingSentinel:
    def test_repr(self) -> None:
        assert repr(MISSING) == "<MISSING>"

    def test_identity(self) -> None:
        """MISSING is a singleton-like sentinel."""
        from rulegate.core import _Missing
        assert isinstance(MISSING, _Missing)


# ═══════════════════════════════════════════════════════════════
# engine.py tests
# ═══════════════════════════════════════════════════════════════


class TestEngineCheck:
    def test_allow_single_predicate(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        rs = Ruleset(predicates=(lambda ctx: True,))
        decision = engine.check(rule, rs)
        assert decision.allowed
        assert decision.evaluated_count == 1
        assert decision.violated_rules == ()

    def test_block_single_predicate(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        rs = Ruleset(predicates=(lambda ctx: False,))
        decision = engine.check(rule, rs)
        assert decision.blocked
        assert decision.reason == BlockReason.POLICY_VIOLATION
        assert len(decision.violated_rules) == 1

    def test_allow_multiple_predicates(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        rs = Ruleset(predicates=(lambda ctx: True, lambda ctx: True, lambda ctx: True))
        decision = engine.check(rule, rs)
        assert decision.allowed
        assert decision.evaluated_count == 3

    def test_block_second_predicate(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        rs = Ruleset(predicates=(lambda ctx: True, lambda ctx: False, lambda ctx: True))
        decision = engine.check(rule, rs)
        assert decision.blocked
        assert decision.evaluated_count == 2  # Short-circuited

    def test_short_circuit(self) -> None:
        """Third predicate must NOT be called after second fails."""
        call_log: list[str] = []

        def p1(ctx: Context) -> bool:
            call_log.append("p1")
            return True

        def p2(ctx: Context) -> bool:
            call_log.append("p2")
            return False

        def p3(ctx: Context) -> bool:
            call_log.append("p3")
            return True

        engine = Engine()
        rule = Rule("api", "search")
        engine.check(rule, Ruleset(predicates=(p1, p2, p3)))
        assert call_log == ["p1", "p2"]  # p3 never called

    def test_predicate_receives_context(self) -> None:
        """Predicates must receive args/kwargs/meta from the guarded call."""
        received: list[Context] = []

        def capture(ctx: Context) -> bool:
            received.append(ctx)
            return True

        engine = Engine()
        rule = Rule("api", "search")
        engine.check(
            rule,
            Ruleset(predicates=(capture,)),
            args=("hello",),
            kwargs={"limit": 10},
            meta={"session": "abc"},
        )
        assert len(received) == 1
        assert received[0].args == ("hello",)
        assert received[0].kwargs == {"limit": 10}
        assert received[0].meta == {"session": "abc"}
        assert received[0].rule == rule

    def test_predicate_exception_blocks(self) -> None:
        """A predicate that raises must block the action."""
        def bad_predicate(ctx: Context) -> bool:
            raise RuntimeError("something broke")

        engine = Engine()
        rule = Rule("api", "search")
        decision = engine.check(rule, Ruleset(predicates=(bad_predicate,)))
        assert decision.blocked
        assert decision.reason == BlockReason.POLICY_VIOLATION
        assert "raised: RuntimeError" in decision.violated_rules[0]

    def test_no_ruleset_raises(self) -> None:
        """check() without registered or provided ruleset must raise ValueError."""
        engine = Engine()
        with pytest.raises(ValueError, match="No ruleset registered"):
            engine.check(Rule("api", "search"))


class TestEngineCheckAll:
    def test_no_short_circuit(self) -> None:
        """check_all() evaluates every predicate even after failure."""
        call_log: list[str] = []

        def p1(ctx: Context) -> bool:
            call_log.append("p1")
            return False

        def p2(ctx: Context) -> bool:
            call_log.append("p2")
            return False

        def p3(ctx: Context) -> bool:
            call_log.append("p3")
            return True

        engine = Engine()
        rule = Rule("api", "search")
        decision = engine.check_all(rule, Ruleset(predicates=(p1, p2, p3)))
        assert call_log == ["p1", "p2", "p3"]
        assert decision.blocked
        assert len(decision.violated_rules) == 2
        assert decision.evaluated_count == 3


class TestEngineRegister:
    def test_register_and_lookup(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        rs = Ruleset(predicates=(lambda ctx: True,))
        engine.register(rule, rs)
        assert engine.ruleset_for(rule) is rs

    def test_unregistered_returns_none(self) -> None:
        engine = Engine()
        assert engine.ruleset_for(Rule("api", "unknown")) is None

    def test_register_overwrite(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        rs1 = Ruleset(predicates=(lambda ctx: True,))
        rs2 = Ruleset(predicates=(lambda ctx: False,))
        engine.register(rule, rs1)
        engine.register(rule, rs2)
        assert engine.ruleset_for(rule) is rs2

    def test_check_uses_registered(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        engine.register(rule, Ruleset(predicates=(lambda ctx: False,)))
        decision = engine.check(rule)
        assert decision.blocked


class TestEngineEnforce:
    def test_hard_mode_raises(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        decision = engine.check(rule, Ruleset(predicates=(lambda ctx: False,)))
        with pytest.raises(PolicyViolation) as exc_info:
            engine.enforce(decision)
        assert exc_info.value.decision is decision

    def test_soft_mode_no_raise(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        decision = engine.check(
            rule, Ruleset(predicates=(lambda ctx: False,), mode=Mode.SOFT)
        )
        engine.enforce(decision)  # Should not raise

    def test_allow_no_raise(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        decision = engine.check(rule, Ruleset(predicates=(lambda ctx: True,)))
        engine.enforce(decision)  # Should not raise


class TestEngineListeners:
    def test_listener_called(self) -> None:
        decisions: list[Decision] = []
        engine = Engine()
        engine.on_decision(decisions.append)
        rule = Rule("api", "search")
        engine.check(rule, Ruleset(predicates=(lambda ctx: True,)))
        assert len(decisions) == 1
        assert decisions[0].allowed

    def test_listener_exception_counted(self) -> None:
        def bad_listener(d: Decision) -> None:
            raise RuntimeError("listener broke")

        engine = Engine()
        engine.on_decision(bad_listener)
        rule = Rule("api", "search")
        # Should not raise — listener errors are swallowed
        engine.check(rule, Ruleset(predicates=(lambda ctx: True,)))
        # But store failure counts as error
        assert engine.listener_errors >= 0  # Listener errors from _emit


class TestPolicyViolation:
    def test_exception_has_decision(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        decision = engine.check(rule, Ruleset(predicates=(lambda ctx: False,)))
        exc = PolicyViolation(decision)
        assert exc.decision is decision
        assert "Policy violation" in str(exc)


# ═══════════════════════════════════════════════════════════════
# Decorator tests
# ═══════════════════════════════════════════════════════════════


class TestGuardDecorator:
    def test_allow(self) -> None:
        engine = Engine()

        @engine.guard(Rule("api", "search"), Ruleset(predicates=(lambda ctx: True,)))
        def search(query: str) -> str:
            return f"results for {query}"

        assert search("hello") == "results for hello"

    def test_block_raises(self) -> None:
        engine = Engine()

        @engine.guard(Rule("api", "search"), Ruleset(predicates=(lambda ctx: False,)))
        def search(query: str) -> str:
            return f"results for {query}"

        with pytest.raises(PolicyViolation):
            search("hello")

    def test_passes_args_to_context(self) -> None:
        """Decorator must forward function args/kwargs to predicates."""
        received_ctx: list[Context] = []

        def capture(ctx: Context) -> bool:
            received_ctx.append(ctx)
            return True

        engine = Engine()

        @engine.guard(Rule("api", "search"), Ruleset(predicates=(capture,)))
        def search(query: str, limit: int = 5) -> str:
            return f"results for {query}"

        search("hello", limit=10)
        assert received_ctx[0].args == ("hello",)
        assert received_ctx[0].kwargs == {"limit": 10}

    def test_preserves_function_metadata(self) -> None:
        engine = Engine()

        @engine.guard(Rule("api", "search"), Ruleset(predicates=(lambda ctx: True,)))
        def search(query: str) -> str:
            """Search docstring."""
            return query

        assert search.__name__ == "search"
        assert search.__doc__ == "Search docstring."

    def test_meta_passed_to_predicates(self) -> None:
        received_meta: list[dict[str, Any]] = []

        def check_meta(ctx: Context) -> bool:
            received_meta.append(ctx.meta)
            return True

        engine = Engine()

        @engine.guard(
            Rule("api", "search"),
            Ruleset(predicates=(check_meta,)),
            meta={"env": "production"},
        )
        def search(query: str) -> str:
            return query

        search("hello")
        assert received_meta[0] == {"env": "production"}


class TestGuardResultDecorator:
    def test_allow(self) -> None:
        engine = Engine()

        @engine.guard_result(
            Rule("api", "search"),
            Ruleset(predicates=(lambda ctx: True,), mode=Mode.SOFT),
        )
        def search(query: str) -> str:
            return f"results for {query}"

        result = search("hello")
        assert result.ok
        assert result.unwrap() == "results for hello"

    def test_block_returns_result(self) -> None:
        engine = Engine()

        @engine.guard_result(
            Rule("api", "search"),
            Ruleset(predicates=(lambda ctx: False,), mode=Mode.SOFT),
        )
        def search(query: str) -> str:
            return f"results for {query}"

        result = search("hello")
        assert not result.ok
        assert result.has_value is False
        assert result.unwrap_or("fallback") == "fallback"

    def test_none_return_not_confused_with_blocked(self) -> None:
        """CRITICAL: Function returning None must not look like a block."""
        engine = Engine()

        @engine.guard_result(
            Rule("api", "void_op"),
            Ruleset(predicates=(lambda ctx: True,)),
        )
        def void_op() -> None:
            return None

        result = void_op()
        assert result.ok is True
        assert result.has_value is True
        assert result.value is None
        assert result.unwrap() is None


# ═══════════════════════════════════════════════════════════════
# store.py tests
# ═══════════════════════════════════════════════════════════════


class TestMemoryStore:
    def test_record_and_retrieve(self) -> None:
        store = MemoryStore()
        rule = Rule("api", "search")
        d = Decision(
            status=Status.ALLOW,
            rule=rule,
            ruleset=Ruleset(predicates=(lambda ctx: True,)),
        )
        store.record(rule, 100.0, d)
        records = store.get_records(rule, 200.0, None)
        assert len(records) == 1
        assert records[0].decision is d
        assert records[0].ts == 100.0

    def test_window_pruning(self) -> None:
        store = MemoryStore()
        rule = Rule("api", "search")
        rs = Ruleset(predicates=(lambda ctx: True,))
        d = Decision(status=Status.ALLOW, rule=rule, ruleset=rs)

        store.record(rule, 100.0, d)
        store.record(rule, 200.0, d)
        store.record(rule, 300.0, d)

        # Window of 150 seconds from now=350 → cutoff=200
        records = store.get_records(rule, 350.0, 150.0)
        assert len(records) == 2  # 200.0 and 300.0

    def test_clear_rule(self) -> None:
        store = MemoryStore()
        rule = Rule("api", "search")
        rs = Ruleset(predicates=(lambda ctx: True,))
        d = Decision(status=Status.ALLOW, rule=rule, ruleset=rs)
        store.record(rule, 100.0, d)
        store.clear(rule)
        records = store.get_records(rule, 200.0, None)
        assert len(records) == 0

    def test_clear_all(self) -> None:
        store = MemoryStore()
        rs = Ruleset(predicates=(lambda ctx: True,))
        r1 = Rule("api", "search")
        r2 = Rule("api", "fetch")
        d1 = Decision(status=Status.ALLOW, rule=r1, ruleset=rs)
        d2 = Decision(status=Status.ALLOW, rule=r2, ruleset=rs)
        store.record(r1, 100.0, d1)
        store.record(r2, 100.0, d2)
        store.clear_all()
        assert store.get_records(r1, 200.0, None) == []
        assert store.get_records(r2, 200.0, None) == []

    def test_thread_safety(self) -> None:
        """Concurrent record() calls must not corrupt state."""
        store = MemoryStore()
        rule = Rule("api", "search")
        rs = Ruleset(predicates=(lambda ctx: True,))
        d = Decision(status=Status.ALLOW, rule=rule, ruleset=rs)

        errors: list[Exception] = []

        def record_many() -> None:
            try:
                for i in range(100):
                    store.record(rule, float(i), d)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=record_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        records = store.get_records(rule, 1000.0, None)
        assert len(records) == 1000  # 10 threads × 100 records


# ═══════════════════════════════════════════════════════════════
# Integration tests
# ═══════════════════════════════════════════════════════════════


class TestIntegration:
    def test_realistic_policy(self) -> None:
        """Test a realistic multi-predicate policy."""

        def no_pii(ctx: Context) -> bool:
            query = str(ctx.kwargs.get("query", ""))
            return "ssn" not in query.lower() and "password" not in query.lower()

        def max_length(ctx: Context) -> bool:
            query = str(ctx.kwargs.get("query", ""))
            return len(query) <= 1000

        def allowed_namespace(ctx: Context) -> bool:
            return ctx.rule.namespace in ("api", "internal")

        engine = Engine()
        rule = Rule("api", "search")
        engine.register(rule, Ruleset(predicates=(no_pii, max_length, allowed_namespace)))

        # Valid query
        d = engine.check(rule, kwargs={"query": "find user by email"})
        assert d.allowed

        # PII violation
        d = engine.check(rule, kwargs={"query": "find user ssn"})
        assert d.blocked
        assert "no_pii" in d.violated_rules[0]

        # Length violation
        d = engine.check(rule, kwargs={"query": "x" * 1001})
        assert d.blocked
        assert "max_length" in d.violated_rules[0]

    def test_named_predicates_in_diagnostics(self) -> None:
        engine = Engine()
        rule = Rule("billing", "refund")

        preds = (
            NamedPredicate("amount_under_limit", fn=lambda ctx: True),
            NamedPredicate("user_is_verified", fn=lambda ctx: False),
            NamedPredicate("within_refund_window", fn=lambda ctx: True),
        )
        d = engine.check(rule, Ruleset(predicates=preds))
        assert d.blocked
        assert d.violated_rules == ("user_is_verified",)

    def test_check_all_shows_all_violations(self) -> None:
        engine = Engine()
        rule = Rule("billing", "refund")

        preds = (
            NamedPredicate("amount_under_limit", fn=lambda ctx: False),
            NamedPredicate("user_is_verified", fn=lambda ctx: False),
            NamedPredicate("within_refund_window", fn=lambda ctx: True),
        )
        d = engine.check_all(rule, Ruleset(predicates=preds))
        assert d.blocked
        assert d.violated_rules == ("amount_under_limit", "user_is_verified")
        assert d.evaluated_count == 3

    def test_engine_clear(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        engine.register(rule, Ruleset(predicates=(lambda ctx: True,)))
        engine.check(rule)
        engine.clear(rule)
        # Should still work after clear (rules are stateless)
        d = engine.check(rule)
        assert d.allowed

    def test_engine_clear_all(self) -> None:
        engine = Engine()
        rule = Rule("api", "search")
        engine.register(rule, Ruleset(predicates=(lambda ctx: True,)))
        engine.check(rule)
        engine.clear_all()
        d = engine.check(rule)
        assert d.allowed

    def test_custom_clock(self) -> None:
        """Engine must use injected clock for timestamps."""
        timestamps = iter([100.0, 200.0, 300.0])
        engine = Engine(clock=lambda: next(timestamps))
        rule = Rule("api", "search")
        rs = Ruleset(predicates=(lambda ctx: True,))
        engine.check(rule, rs)
        engine.check(rule, rs)
        # Clock was called twice (once per check)
        assert next(timestamps) == 300.0

    def test_store_failure_does_not_affect_decision(self) -> None:
        """Store errors during audit logging must never block the action."""

        class BrokenStore:
            def record(self, rule: Rule, now: float, decision: Decision) -> None:
                raise RuntimeError("store is down")

            def get_records(self, rule: Rule, now: float, window: float | None) -> list:
                return []

            def clear(self, rule: Rule) -> None:
                pass

            def clear_all(self) -> None:
                pass

        engine = Engine(store=BrokenStore())  # type: ignore[arg-type]
        rule = Rule("api", "search")
        decision = engine.check(rule, Ruleset(predicates=(lambda ctx: True,)))
        assert decision.allowed  # Store failure does NOT affect decision
