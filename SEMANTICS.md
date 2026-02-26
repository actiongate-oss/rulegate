# RuleGate Semantics

This document defines the normative behavior of RuleGate. Any implementation claiming compatibility must conform to these semantics.

Version: 0.2

---

## 1. Purpose

RuleGate is a **deterministic, pre-execution policy gate** for AI agents. It evaluates callable predicates against action context and blocks actions that violate policy rules.

It is not a rate limiter, cost manager, authorization system, or access control list.

---

## 2. Rule Identity

A policy-checked action is identified by a **Rule**, a 3-tuple:

```
Rule = (namespace: string, action: string, principal: string)
```

| Field       | Purpose              | Examples                                   |
|-------------|----------------------|--------------------------------------------|
| `namespace` | Domain or subsystem  | `"api"`, `"support"`, `"billing"`          |
| `action`    | Operation name       | `"search"`, `"escalate"`, `"refund"`       |
| `principal` | Scope of enforcement | `"user:123"`, `"agent:42"`, `"global"`     |

Two rules are equal if and only if all three fields are equal. Evaluation state is **not shared** across distinct rules.

---

## 3. Ruleset

A **Ruleset** defines enforcement parameters:

| Parameter        | Type                       | Meaning                                     |
|------------------|----------------------------|---------------------------------------------|
| `predicates`     | tuple of callables         | One or more predicates; all must pass        |
| `mode`           | HARD \| SOFT               | HARD raises on block; SOFT returns decision  |
| `on_store_error` | FAIL_CLOSED \| FAIL_OPEN   | Behavior when storage backend fails          |

A ruleset **must** contain at least one predicate.

---

## 4. Predicates

### 4.1 Definition

A **predicate** is a callable that accepts a `Context` and returns a boolean:

```
Predicate = Callable[[Context], bool]
```

- `True` means the action is permitted by this rule.
- `False` means the action violates this rule.

Predicates **must** be pure functions with no side effects. They **must not** mutate the context, call external services, or perform I/O.

### 4.2 Context

A **Context** is an immutable value passed to every predicate:

| Field    | Type              | Meaning                                          |
|----------|-------------------|--------------------------------------------------|
| `rule`   | Rule              | The rule being evaluated                         |
| `args`   | tuple             | Positional arguments to the guarded function     |
| `kwargs` | dict[str, Any]    | Keyword arguments to the guarded function        |
| `meta`   | dict[str, Any]    | Arbitrary metadata (headers, session info, etc.) |

### 4.3 Named Predicates

Predicates may be wrapped in a `NamedPredicate` to provide human-readable names for diagnostics. When a plain callable is used, its `__qualname__` or `__name__` is used for diagnostic output.

### 4.4 Predicate Exceptions

If a predicate raises an exception during evaluation, the action **must** be blocked. The exception details **must** appear in the decision's `violated_rules` for diagnostics.

Rationale: A failing predicate cannot assert that the action is permitted. The safe default is to block.

---

## 5. Decision Logic

Given a rule R and ruleset S, with context C:

1. **Build context**: Construct `Context(rule=R, args=..., kwargs=..., meta=...)`
2. **Evaluate predicates** in order:
   - For each predicate P in `S.predicates`:
     - Call `P(C)`
     - If `P(C)` returns `False` → record violation, **BLOCK** (short-circuit)
     - If `P(C)` raises → record violation with exception details, **BLOCK** (short-circuit)
3. If all predicates return `True` → **ALLOW**

### 5.1 Short-Circuit Evaluation

The default `check()` method short-circuits on the first failure. This is the production path: fail fast, minimize predicate execution.

### 5.2 Exhaustive Evaluation

The `check_all()` method evaluates every predicate regardless of failures. This is the diagnostic path: identify all violations in a single evaluation.

### 5.3 Conjunction Semantics

All predicates must pass (logical AND). There is no built-in OR or precedence logic. Disjunction can be expressed by composing predicates:

```python
def either_admin_or_business_hours(ctx: Context) -> bool:
    return is_admin(ctx) or is_business_hours(ctx)
```

---

## 6. Statefulness

Rule evaluation is **stateless**. The decision depends only on the predicates and the context at evaluation time. Unlike ActionGate (which tracks call counts) and BudgetGate (which tracks spend), RuleGate does not read from its store to make decisions.

The store is used **only** for audit logging of evaluation outcomes. Store operations are fire-and-forget: store failures never affect the allow/deny decision.

### 6.1 Atomicity

Because evaluation is stateless, there is no check-and-reserve operation to make atomic. Concurrent evaluations of the same rule with the same context will produce the same decision (assuming predicates are pure).

---

## 7. Failure Semantics

### 7.1 Predicate Failure

If a predicate raises an exception:

| Behavior | Result                                            |
|----------|---------------------------------------------------|
| Default  | BLOCK with violation name including exception info |

There is no fail-open mode for predicate exceptions. A predicate that cannot execute cannot assert permission.

### 7.2 Store Failure

When the audit store is unavailable or errors:

| Behavior        | Result                                            |
|-----------------|---------------------------------------------------|
| Always          | Decision is unaffected; store error is counted    |

The `on_store_error` field on `Ruleset` is accepted for forward compatibility (e.g., if store-backed rule loading is added in a future version) but is not consulted in v0.1. In this version, the store is never in the decision path.

---

## 8. Decision Structure

Every evaluation **must** return a Decision containing at minimum:

| Field             | Type              | Meaning                                       |
|-------------------|-------------------|-----------------------------------------------|
| `status`          | ALLOW \| BLOCK    | Outcome                                       |
| `rule`            | Rule              | The evaluated rule                            |
| `ruleset`         | Ruleset           | The ruleset used                              |
| `reason`          | BlockReason \| null | Why blocked (null if allowed)               |
| `violated_rules`  | tuple of strings  | Names of predicates that failed (empty if allowed) |
| `evaluated_count` | int               | Number of predicates evaluated                |

This enables full observability and auditability of every decision.

---

## 9. Out of Scope

RuleGate **does not** and **must not**:

- Make LLM or model inference calls
- Perform rate limiting or throttling
- Manage costs, budgets, or billing
- Provide authentication or identity verification
- Implement authorization (role-based, attribute-based, or otherwise)
- Evaluate rules based on stored state or historical patterns
- Implement a policy DSL or query language
- Make network calls or perform I/O during evaluation

RuleGate is a **stateless predicate evaluator**. It examines the action context through pure functions, never the payload directly.

---

## 10. Compatibility

An implementation is **RuleGate-compatible** if and only if:

1. It implements the Rule identity model (§2)
2. It implements the Ruleset parameters (§3)
3. Predicates follow the specification (§4)
4. It follows the decision logic exactly (§5)
5. Evaluation is stateless (§6)
6. Failure modes match the specification (§7)
7. Decisions include all required fields (§8)
8. It does not extend scope beyond §9

Compatible implementations may:

- Use any storage backend for audit logging
- Be written in any language
- Add non-normative fields to Decision
- Provide additional observability hooks
- Implement both short-circuit and exhaustive evaluation

Compatible implementations must not:

- Change the decision logic or predicate semantics
- Make allow/deny decisions based on stored state
- Allow actions when predicates raise exceptions
- Skip predicate evaluation for registered rules

---

## 11. Reference Implementation

The canonical reference implementation is at:

```
https://github.com/actiongate-oss/rulegate
```

When this specification and the reference implementation conflict, **this specification governs**.

---

## Changelog

- **0.2** (2026-02): License changed to BSL 1.1
- **0.1** (2026-01): Initial specification

---

## License

RuleGate is licensed under the Business Source License 1.1 (BSL 1.1). See the LICENSE file for full terms.
