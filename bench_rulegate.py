#!/usr/bin/env python3
"""Latency benchmark for RuleGate.

Tests p50/p95/p99 across different predicate compositions to characterize
how latency changes with ruleset shape.
"""

import time
import statistics
import sys

sys.path.insert(0, "/home/claude")

from rulegate import Engine, Rule, Ruleset, Context, NamedPredicate, Mode


# ─── Helpers ───────────────────────────────────────────────────

def percentile(data: list[float], p: float) -> float:
    k = (len(data) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(data) - 1)
    return data[f] + (k - f) * (data[c] - data[f])


def bench(name: str, fn, iterations: int = 50_000, warmup: int = 5_000) -> dict:
    for _ in range(warmup):
        fn()

    latencies = []
    t_start = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1_000_000)  # microseconds
    wall = time.perf_counter() - t_start

    latencies.sort()
    result = {
        "name": name,
        "n": iterations,
        "p50": percentile(latencies, 50),
        "p95": percentile(latencies, 95),
        "p99": percentile(latencies, 99),
        "min": latencies[0],
        "max": latencies[-1],
        "mean": statistics.mean(latencies),
        "stdev": statistics.stdev(latencies),
        "ops_sec": iterations / wall,
    }
    return result


def print_result(r: dict):
    print(f"\n  {r['name']}")
    print(f"    n={r['n']:,}  ops/s={r['ops_sec']:,.0f}")
    print(f"    p50={r['p50']:.2f}μs  p95={r['p95']:.2f}μs  p99={r['p99']:.2f}μs")
    print(f"    min={r['min']:.2f}μs  max={r['max']:.2f}μs")
    print(f"    mean={r['mean']:.2f}μs  stdev={r['stdev']:.2f}μs")


# ─── Predicates ────────────────────────────────────────────────

def trivial_pass(ctx: Context) -> bool:
    return True

def trivial_fail(ctx: Context) -> bool:
    return False

def kwarg_check(ctx: Context) -> bool:
    return "ssn" not in str(ctx.kwargs.get("query", "")).lower()

def meta_check(ctx: Context) -> bool:
    return ctx.meta.get("role") == "admin"

def multi_field_check(ctx: Context) -> bool:
    q = str(ctx.kwargs.get("query", "")).lower()
    return "ssn" not in q and "password" not in q and "secret" not in q

named_pred = NamedPredicate("no_pii", kwarg_check)


# ─── Scenarios ─────────────────────────────────────────────────

def run_benchmarks():
    results = []
    N = 50_000

    # --- 1. Single trivial predicate (baseline) ---
    engine = Engine()
    rule = Rule("bench", "trivial")
    rs = Ruleset(predicates=(trivial_pass,))
    engine.register(rule, rs)
    results.append(bench("1 trivial predicate (pass)", lambda: engine.check(rule), N))

    # --- 2. Single predicate that inspects kwargs ---
    engine2 = Engine()
    rule2 = Rule("bench", "kwarg")
    rs2 = Ruleset(predicates=(kwarg_check,))
    engine2.register(rule2, rs2)
    results.append(bench(
        "1 kwarg predicate (pass)",
        lambda: engine2.check(rule2, kwargs={"query": "find user"}),
        N,
    ))

    # --- 3. Single predicate that inspects kwargs (blocked) ---
    results.append(bench(
        "1 kwarg predicate (block)",
        lambda: engine2.check(rule2, kwargs={"query": "find SSN"}),
        N,
    ))

    # --- 4. NamedPredicate wrapper ---
    engine3 = Engine()
    rule3 = Rule("bench", "named")
    rs3 = Ruleset(predicates=(named_pred,))
    engine3.register(rule3, rs3)
    results.append(bench(
        "1 NamedPredicate (pass)",
        lambda: engine3.check(rule3, kwargs={"query": "find user"}),
        N,
    ))

    # --- 5. 3 predicates, all pass ---
    engine5 = Engine()
    rule5 = Rule("bench", "three_pass")
    rs5 = Ruleset(predicates=(trivial_pass, kwarg_check, meta_check))
    engine5.register(rule5, rs5)
    results.append(bench(
        "3 predicates (all pass)",
        lambda: engine5.check(rule5, kwargs={"query": "ok"}, meta={"role": "admin"}),
        N,
    ))

    # --- 6. 3 predicates, first fails (short-circuit) ---
    engine6 = Engine()
    rule6 = Rule("bench", "three_sc")
    rs6 = Ruleset(predicates=(trivial_fail, kwarg_check, meta_check))
    engine6.register(rule6, rs6)
    results.append(bench(
        "3 predicates (1st fails, short-circuit)",
        lambda: engine6.check(rule6, kwargs={"query": "ok"}, meta={"role": "admin"}),
        N,
    ))

    # --- 7. 3 predicates, last fails ---
    engine7 = Engine()
    rule7 = Rule("bench", "three_last")
    rs7 = Ruleset(predicates=(trivial_pass, kwarg_check, trivial_fail))
    engine7.register(rule7, rs7)
    results.append(bench(
        "3 predicates (last fails)",
        lambda: engine7.check(rule7, kwargs={"query": "ok"}),
        N,
    ))

    # --- 8. 10 predicates, all pass ---
    engine8 = Engine()
    rule8 = Rule("bench", "ten_pass")
    rs8 = Ruleset(predicates=tuple(trivial_pass for _ in range(10)))
    engine8.register(rule8, rs8)
    results.append(bench(
        "10 predicates (all pass)",
        lambda: engine8.check(rule8),
        N,
    ))

    # --- 9. 10 predicates, 5th fails (short-circuit) ---
    preds_9 = [trivial_pass] * 4 + [trivial_fail] + [trivial_pass] * 5
    engine9 = Engine()
    rule9 = Rule("bench", "ten_mid")
    rs9 = Ruleset(predicates=tuple(preds_9))
    engine9.register(rule9, rs9)
    results.append(bench(
        "10 predicates (5th fails, short-circuit)",
        lambda: engine9.check(rule9),
        N,
    ))

    # --- 10. check_all exhaustive (3 preds, 2 fail) ---
    engine10 = Engine()
    rule10 = Rule("bench", "exhaust")
    rs10 = Ruleset(predicates=(trivial_fail, trivial_pass, trivial_fail))
    engine10.register(rule10, rs10)
    results.append(bench(
        "check_all: 3 predicates (2 fail, no short-circuit)",
        lambda: engine10.check_all(rule10),
        N,
    ))

    # --- 11. Heavy predicate (string scanning) ---
    engine11 = Engine()
    rule11 = Rule("bench", "heavy")
    rs11 = Ruleset(predicates=(multi_field_check,))
    engine11.register(rule11, rs11)
    results.append(bench(
        "1 heavy predicate (multi-field string scan)",
        lambda: engine11.check(rule11, kwargs={"query": "find user records in database"}),
        N,
    ))

    # --- 12. guard decorator overhead ---
    engine12 = Engine()

    @engine12.guard(Rule("bench", "decorated"), Ruleset(predicates=(trivial_pass,)))
    def guarded_fn(x: int) -> int:
        return x

    results.append(bench("guard decorator (trivial pass)", lambda: guarded_fn(42), N))

    # --- 13. guard_result decorator overhead ---
    engine13 = Engine()

    @engine13.guard_result(Rule("bench", "result_dec"), Ruleset(predicates=(trivial_pass,)))
    def guarded_result_fn(x: int) -> int:
        return x

    results.append(bench("guard_result decorator (trivial pass)", lambda: guarded_result_fn(42), N))

    # --- 14. Many distinct rules (lock contention proxy) ---
    engine14 = Engine()
    rules_14 = [Rule("bench", "multi", f"user:{i}") for i in range(100)]
    rs14 = Ruleset(predicates=(trivial_pass,))
    for r in rules_14:
        engine14.register(r, rs14)
    counter = [0]

    def multi_rule():
        engine14.check(rules_14[counter[0] % 100])
        counter[0] += 1

    results.append(bench("100 distinct rules (round-robin)", multi_rule, N))

    # --- 15. No store (measure store overhead) ---
    class NullStore:
        def record(self, rule, now, decision): pass
        def get_records(self, rule, now, window): return []
        def clear(self, rule): pass
        def clear_all(self): pass

    engine15 = Engine(store=NullStore())
    rule15 = Rule("bench", "nullstore")
    rs15 = Ruleset(predicates=(trivial_pass,))
    engine15.register(rule15, rs15)
    results.append(bench("1 trivial predicate (NullStore)", lambda: engine15.check(rule15), N))

    return results


# ─── Run ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 66)
    print("RuleGate Latency Benchmark")
    print("=" * 66)

    # Run 3 rounds to show variance
    all_rounds = []
    for round_num in range(1, 4):
        print(f"\n{'─' * 66}")
        print(f"  Round {round_num}")
        print(f"{'─' * 66}")
        results = run_benchmarks()
        for r in results:
            print_result(r)
        all_rounds.append(results)

    # Cross-round variance summary
    print(f"\n{'=' * 66}")
    print("  Cross-Round Variance (p50 μs across 3 rounds)")
    print(f"{'=' * 66}")
    for i, name in enumerate(r["name"] for r in all_rounds[0]):
        p50s = [all_rounds[rd][i]["p50"] for rd in range(3)]
        lo, hi = min(p50s), max(p50s)
        spread = hi - lo
        mean = statistics.mean(p50s)
        cv = (statistics.stdev(p50s) / mean * 100) if mean > 0 else 0
        print(f"  {name}")
        print(f"    p50 range: {lo:.2f}–{hi:.2f}μs  spread={spread:.2f}μs  CV={cv:.1f}%")
