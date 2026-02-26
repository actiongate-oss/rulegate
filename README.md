# RuleGate

Deterministic, pre-execution policy enforcement for semantic actions in agent systems.

## Source of Truth

The canonical source is [github.com/actiongate-oss/rulegate](https://github.com/actiongate-oss/rulegate). PyPI distribution is a convenience mirror.

**Vendoring and forking are permitted** under the terms of the [BSL 1.1 license](LICENSE). If you vendor RuleGate, you must preserve the LICENSE file, preserve copyright headers in source files, and not remove or modify the BSL terms. The production use restriction applies to vendored copies. See [SEMANTICS.md](SEMANTICS.md) for the behavioral contract if you reimplement.

---

## Quick Start

```python
from rulegate import Engine, Rule, Ruleset, Context, PolicyViolation

engine = Engine()

def no_pii(ctx: Context) -> bool:
    return "ssn" not in str(ctx.kwargs.get("query", "")).lower()

@engine.guard(Rule("api", "search"), Ruleset(predicates=(no_pii,)))
def search(query: str) -> list[str]:
    return api.search(query)

try:
    results = search(query="find user")
except PolicyViolation as e:
    print(f"Blocked: {e.decision.violated_rules}")
```

---

## Core Concepts

### Rule

Identifies what's being policy-checked:

```python
Rule(namespace, action, principal)

Rule("api", "search", "user:123")       # per-user policy
Rule("support", "escalate", "agent:42")  # per-agent policy
Rule("billing", "refund", "global")      # global policy
```

### Ruleset

```python
Ruleset(
    predicates=(no_pii, business_hours),  # all must pass (AND logic)
    mode=Mode.HARD,                        # HARD raises, SOFT returns decision
    on_store_error=StoreErrorMode.FAIL_CLOSED,
)
```

### Predicates

A predicate is a callable that receives a `Context` and returns `True` (allow) or `False` (deny). Predicates must be pure functions — no I/O, no side effects, no mutations. All external state (time, configuration, session data) should be passed via `meta`:

```python
def no_pii(ctx: Context) -> bool:
    return "ssn" not in str(ctx.kwargs.get("query", "")).lower()

def business_hours(ctx: Context) -> bool:
    return 9 <= ctx.meta["hour"] < 17
```

For diagnostics, wrap predicates in `NamedPredicate`:

```python
from rulegate import NamedPredicate

no_pii_named = NamedPredicate("no_pii", no_pii)
```

If a predicate raises an exception, the action is blocked. A predicate that cannot execute cannot assert permission.

### Context

Every predicate receives the full action context:

```python
Context(
    rule=Rule("api", "search"),       # the rule being evaluated
    args=("hello",),                   # positional args to guarded function
    kwargs={"query": "find user"},     # keyword args to guarded function
    meta={"role": "admin", "hour": 14},# arbitrary metadata (time, session, etc.)
)
```

### Decision

Every check returns a Decision:

```python
decision.allowed           # bool
decision.blocked           # bool
decision.violated_rules    # tuple of predicate names that failed
decision.evaluated_count   # number of predicates evaluated
decision.reason            # BlockReason.POLICY_VIOLATION or None
```

### Two Decorator Styles

```python
@engine.guard(rule, ruleset)        # returns T, raises PolicyViolation
@engine.guard_result(rule, ruleset) # returns Result[T], never raises
```

---

## Short-Circuit vs. Exhaustive

```python
# Production path: stops at first failure
decision = engine.check(rule, ruleset)

# Diagnostic path: evaluates all predicates, reports every violation
decision = engine.check_all(rule, ruleset)
```

---

## Determinism Guarantee

The allow/deny decision is always deterministic relative to the predicates and context. Specifically:

- The store is write-only from the engine's perspective and is never consulted during evaluation. Predicate results are computed independently of store state.
- Store audit write failures are counted and silently ignored. The `on_store_error` field on `Ruleset` is accepted for forward compatibility but is not consulted in v0.2 — the store is not in the decision path.
- Given the same predicates and the same context, the same decision is produced every time.

---

## Scope & Non-Goals

**RuleGate does:**
- Pre-execution policy enforcement (all predicates must pass)
- Stateless evaluation (decision depends only on predicates and context)
- Short-circuit and exhaustive evaluation modes
- Full decision explainability (which predicates failed and why)

**RuleGate does not:**
- Make LLM or model inference calls
- Perform rate limiting or throttling (use [ActionGate](https://github.com/actiongate-oss/actiongate))
- Manage costs, budgets, or billing (use [BudgetGate](https://github.com/actiongate-oss/budgetgate))
- Provide authentication or authorization
- Evaluate rules based on stored state or historical patterns
- Make network calls or perform I/O during evaluation

See [SEMANTICS.md](SEMANTICS.md) for the formal behavioral contract.

---

## Observability

```python
engine.on_decision(lambda d: logger.info(f"{d.status}: {d.rule} {d.violated_rules}"))
```

Every decision includes: status, rule, ruleset, reason, violated_rules, evaluated_count. The store records evaluation outcomes for audit purposes but is never in the decision path.

---

## Relation to ActionGate and BudgetGate

RuleGate is one of three composable primitives in the agent execution layer:

| Primitive | Limits | Use case |
|-----------|--------|----------|
| [ActionGate](https://github.com/actiongate-oss/actiongate) | calls/time | Rate limiting |
| [BudgetGate](https://github.com/actiongate-oss/budgetgate) | cost/time | Spend limiting |
| RuleGate | policy predicates | Policy enforcement |

All three are deterministic, pre-execution, and decorator-friendly. They compose via stacking:

```python
from decimal import Decimal

@actiongate_engine.guard(Gate("api", "search"), Policy(max_calls=100))
@budgetgate_engine.guard(Ledger("api", "search"), Budget(max_spend=Decimal("1.00")), cost=Decimal("0.01"))
@rulegate_engine.guard(Rule("api", "search"), Ruleset(predicates=(no_pii, business_hours)))
def search(query: str) -> list:
    ...
```

---

## Benchmarks

```bash
python -m rulegate.bench
```

Single-thread latency, CPython 3.12, default GC, no `PYTHONOPTIMIZE`. Measured on Linux (container, 2 vCPU). Run `bench_rulegate.py` on your target hardware — Docker, VM, and bare metal will produce different tail profiles:

| Scenario | p50 | p95 | p99 |
|----------|-----|-----|-----|
| 1 trivial predicate | ~4μs | ~7μs | ~12μs |
| 5 enterprise predicates | ~4.5μs | ~7μs | ~12μs |
| 10 predicates (all pass) | ~4.5μs | ~7μs | ~12μs |
| NullStore (no audit) | ~3μs | ~3μs | ~5μs |

Predicate count adds ~30–50ns per predicate. The MemoryStore audit write is the dominant fixed cost (~1.5μs). Decision logic is bounded at 3–6μs regardless of composition.

---

## API Reference

| Type | Purpose |
|------|---------|
| `Engine` | Core policy evaluation |
| `Rule` | Action identity tuple |
| `Ruleset` | Policy configuration (predicates + mode) |
| `Context` | Immutable context passed to predicates |
| `Decision` | Evaluation result with full diagnostics |
| `Result[T]` | Wrapper for `guard_result` |
| `PolicyViolation` | Exception from `guard` |
| `NamedPredicate` | Predicate with human-readable name |
| `MemoryStore` | Single-process audit backend |

| Enum | Values |
|------|--------|
| `Mode` | `HARD`, `SOFT` |
| `StoreErrorMode` | `FAIL_CLOSED`, `FAIL_OPEN` |
| `Status` | `ALLOW`, `BLOCK` |
| `BlockReason` | `POLICY_VIOLATION`, `STORE_ERROR` |

---

## License

RuleGate is licensed under the [Business Source License 1.1](LICENSE).

```
Licensor:             actiongate-oss
Licensed Work:        RuleGate
Additional Use Grant: None
Change Date:          2030-02-25 (four years from initial publication)
Change License:       Mozilla Public License 2.0
```

**What this means:** You may copy, modify, create derivative works, redistribute, and make non-production use of RuleGate. The Additional Use Grant is "None", which means any use in a live environment that provides value to end users or internal business operations — including SaaS, internal enterprise deployment, and paid betas — requires a commercial license from the licensor. On the Change Date, RuleGate becomes available under [MPL 2.0](https://www.mozilla.org/en-US/MPL/2.0/) and the production restriction terminates. Each version has its own Change Date calculated from its publication.

**If you vendor RuleGate:** Preserve the LICENSE file and copyright headers. Do not remove or modify the BSL terms. The production restriction applies to all copies, vendored or otherwise.

**Licensing difference from siblings:** [ActionGate](https://github.com/actiongate-oss/actiongate) and [BudgetGate](https://github.com/actiongate-oss/budgetgate) are Apache 2.0. RuleGate is BSL 1.1. If composing all three, ensure your use complies with both license terms.

See [LICENSE](LICENSE) for the legally binding text.
