# Copyright 2026 actiongate-oss
# Licensed under the Apache License, Version 2.0

"""Async tests for RuleGate."""

from __future__ import annotations

from typing import Any

import pytest

from rulegate import (
    AsyncMemoryStore,
    BlockReason,
    Context,
    Decision,
    Engine,
    Mode,
    NamedPredicate,
    PolicyViolationError,
    Rule,
    Ruleset,
)

# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════


class MockClock:
    """Controllable clock for testing."""

    def __init__(self, start: float = 0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class AsyncBrokenStore:
    """Async store that always raises."""

    async def record(self, rule: Rule, now: float, decision: Decision) -> None:
        raise RuntimeError("store is down")

    async def get_records(
        self, rule: Rule, now: float, window: float | None
    ) -> list:
        return []

    async def clear(self, rule: Rule) -> None:
        pass

    async def clear_all(self) -> None:
        pass


# ═══════════════════════════════════════════════════════════════
# async_check
# ═══════════════════════════════════════════════════════════════


class TestAsyncCheck:
    """async_check mirrors sync check behavior."""

    async def test_allow_single_predicate(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())
        rule = Rule("api", "search")
        rs = Ruleset(predicates=(lambda ctx: True,))
        decision = await engine.async_check(rule, rs)
        assert decision.allowed
        assert decision.evaluated_count == 1

    async def test_block_single_predicate(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())
        rule = Rule("api", "search")
        rs = Ruleset(predicates=(lambda ctx: False,))
        decision = await engine.async_check(rule, rs)
        assert decision.blocked
        assert decision.reason == BlockReason.POLICY_VIOLATION
        assert len(decision.violated_rules) == 1

    async def test_short_circuit(self) -> None:
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

        engine = Engine(async_store=AsyncMemoryStore())
        rule = Rule("api", "search")
        await engine.async_check(rule, Ruleset(predicates=(p1, p2, p3)))
        assert call_log == ["p1", "p2"]

    async def test_predicate_receives_context(self) -> None:
        received: list[Context] = []

        def capture(ctx: Context) -> bool:
            received.append(ctx)
            return True

        engine = Engine(async_store=AsyncMemoryStore())
        rule = Rule("api", "search")
        await engine.async_check(
            rule,
            Ruleset(predicates=(capture,)),
            args=("hello",),
            kwargs={"limit": 10},
            meta={"session": "abc"},
        )
        assert received[0].args == ("hello",)
        assert received[0].kwargs == {"limit": 10}
        assert received[0].meta == {"session": "abc"}

    async def test_predicate_exception_blocks(self) -> None:
        def bad_predicate(ctx: Context) -> bool:
            raise RuntimeError("something broke")

        engine = Engine(async_store=AsyncMemoryStore())
        rule = Rule("api", "search")
        decision = await engine.async_check(rule, Ruleset(predicates=(bad_predicate,)))
        assert decision.blocked
        assert "raised: RuntimeError" in decision.violated_rules[0]

    async def test_no_ruleset_raises(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())
        with pytest.raises(ValueError, match="No ruleset registered"):
            await engine.async_check(Rule("api", "search"))

    async def test_uses_registered_ruleset(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())
        rule = Rule("api", "search")
        engine.register(rule, Ruleset(predicates=(lambda ctx: False,)))
        decision = await engine.async_check(rule)
        assert decision.blocked

    async def test_named_predicates_in_violations(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())
        rule = Rule("billing", "refund")
        preds = (
            NamedPredicate("amount_check", fn=lambda ctx: True),
            NamedPredicate("user_verified", fn=lambda ctx: False),
        )
        d = await engine.async_check(rule, Ruleset(predicates=preds))
        assert d.blocked
        assert d.violated_rules == ("user_verified",)


# ═══════════════════════════════════════════════════════════════
# async_enforce
# ═══════════════════════════════════════════════════════════════


class TestAsyncEnforce:
    """async_enforce mirrors sync enforce."""

    async def test_hard_mode_raises(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())
        rule = Rule("api", "search")
        decision = await engine.async_check(rule, Ruleset(predicates=(lambda ctx: False,)))
        with pytest.raises(PolicyViolationError) as exc_info:
            await engine.async_enforce(decision)
        assert exc_info.value.decision is decision

    async def test_soft_mode_no_raise(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())
        rule = Rule("api", "search")
        decision = await engine.async_check(
            rule, Ruleset(predicates=(lambda ctx: False,), mode=Mode.SOFT)
        )
        await engine.async_enforce(decision)  # Should not raise
        assert decision.blocked

    async def test_allow_no_raise(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())
        rule = Rule("api", "search")
        decision = await engine.async_check(
            rule, Ruleset(predicates=(lambda ctx: True,))
        )
        await engine.async_enforce(decision)


# ═══════════════════════════════════════════════════════════════
# async_guard
# ═══════════════════════════════════════════════════════════════


class TestAsyncGuard:
    """@engine.async_guard decorator."""

    async def test_allow(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())

        @engine.async_guard(Rule("api", "search"), Ruleset(predicates=(lambda ctx: True,)))
        async def search(query: str) -> str:
            return f"results for {query}"

        assert await search("hello") == "results for hello"

    async def test_block_raises(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())

        @engine.async_guard(Rule("api", "search"), Ruleset(predicates=(lambda ctx: False,)))
        async def search(query: str) -> str:
            return f"results for {query}"

        with pytest.raises(PolicyViolationError):
            await search("hello")

    async def test_passes_args_to_context(self) -> None:
        received_ctx: list[Context] = []

        def capture(ctx: Context) -> bool:
            received_ctx.append(ctx)
            return True

        engine = Engine(async_store=AsyncMemoryStore())

        @engine.async_guard(Rule("api", "search"), Ruleset(predicates=(capture,)))
        async def search(query: str, limit: int = 5) -> str:
            return f"results for {query}"

        await search("hello", limit=10)
        assert received_ctx[0].args == ("hello",)
        assert received_ctx[0].kwargs == {"limit": 10}

    async def test_preserves_function_metadata(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())

        @engine.async_guard(Rule("api", "search"), Ruleset(predicates=(lambda ctx: True,)))
        async def search(query: str) -> str:
            """Search docstring."""
            return query

        assert search.__name__ == "search"
        assert search.__doc__ == "Search docstring."

    async def test_meta_passed_to_predicates(self) -> None:
        received_meta: list[dict[str, Any]] = []

        def check_meta(ctx: Context) -> bool:
            received_meta.append(ctx.meta)
            return True

        engine = Engine(async_store=AsyncMemoryStore())

        @engine.async_guard(
            Rule("api", "search"),
            Ruleset(predicates=(check_meta,)),
            meta={"env": "production"},
        )
        async def search(query: str) -> str:
            return query

        await search("hello")
        assert received_meta[0] == {"env": "production"}


# ═══════════════════════════════════════════════════════════════
# async_guard_result
# ═══════════════════════════════════════════════════════════════


class TestAsyncGuardResult:
    """@engine.async_guard_result decorator."""

    async def test_allow(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())

        @engine.async_guard_result(
            Rule("api", "search"),
            Ruleset(predicates=(lambda ctx: True,), mode=Mode.SOFT),
        )
        async def search(query: str) -> str:
            return f"results for {query}"

        result = await search("hello")
        assert result.ok
        assert result.unwrap() == "results for hello"

    async def test_block_returns_result(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())

        @engine.async_guard_result(
            Rule("api", "search"),
            Ruleset(predicates=(lambda ctx: False,), mode=Mode.SOFT),
        )
        async def search(query: str) -> str:
            return f"results for {query}"

        result = await search("hello")
        assert not result.ok
        assert not result.has_value
        assert result.unwrap_or("fallback") == "fallback"

    async def test_none_return_not_confused_with_blocked(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())

        @engine.async_guard_result(
            Rule("api", "void_op"),
            Ruleset(predicates=(lambda ctx: True,)),
        )
        async def void_op() -> None:
            return None

        result = await void_op()
        assert result.ok is True
        assert result.has_value is True
        assert result.value is None
        assert result.unwrap() is None

    async def test_unwrap_or_default(self) -> None:
        engine = Engine(async_store=AsyncMemoryStore())

        @engine.async_guard_result(
            Rule("api", "action"),
            Ruleset(predicates=(lambda ctx: False,), mode=Mode.SOFT),
        )
        async def action() -> int:
            return 42

        assert (await action()).unwrap_or(0) == 0


# ═══════════════════════════════════════════════════════════════
# Async store error handling
# ═══════════════════════════════════════════════════════════════


class TestAsyncStoreErrors:
    """Async store failures must not affect decisions."""

    async def test_store_failure_does_not_block(self) -> None:
        engine = Engine(async_store=AsyncBrokenStore())  # type: ignore[arg-type]
        rule = Rule("api", "search")
        decision = await engine.async_check(rule, Ruleset(predicates=(lambda ctx: True,)))
        assert decision.allowed


# ═══════════════════════════════════════════════════════════════
# Async listeners
# ═══════════════════════════════════════════════════════════════


class TestAsyncListeners:
    """Async decisions still emit to listeners."""

    async def test_listener_receives_async_decisions(self) -> None:
        decisions: list[Decision] = []
        engine = Engine(async_store=AsyncMemoryStore())
        engine.on_decision(decisions.append)

        rule = Rule("api", "search")
        await engine.async_check(rule, Ruleset(predicates=(lambda ctx: True,)))
        await engine.async_check(rule, Ruleset(predicates=(lambda ctx: False,)))

        assert len(decisions) == 2
        assert decisions[0].allowed
        assert decisions[1].blocked
