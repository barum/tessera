#!/usr/bin/env python3
"""timing-histogram.py — automated TesseraSeal decrypt-path timing regression.

TSEAL-00048 / TP-150 (security-audit-v1.2.md open item #1). Measures N good-vs-bad decrypt
pairs against the Python reference (tessera-seal/python/tessera_seal.py) and asserts that
the bad (authentication-failure) path is not timing-distinguishable from the good path:

  * good  = decrypt of a valid envelope (returns plaintext),
  * bad   = decrypt of the same envelope with its final byte flipped (UtC commitment-tag
            region -> authentication-class DecryptionError; the full KEM-decaps + KDF +
            AEAD + synthetic-pad path runs on both sides).

Pairs are measured back-to-back with time.perf_counter_ns(), alternating good/bad order
per pair to cancel ordering bias, with the GC disabled inside the timed region. The
PRIMARY metric (the "median delta") is the median of the per-pair deltas
(bad_ns - good_ns) after a p95 contention crop: pairs where either measurement exceeds
its distribution's 95th percentile are discarded, because a scheduler preemption inside
ONE of the two calls breaks the pair's drift cancellation (percentile cropping is the
standard practice for timing measurement on non-isolated hosts, cf. dudect). The
uncropped per-pair median, the difference-of-medians (the statistic of the historical
manual measurement in security-audit-v1.2.md), the p99 delta, and the
difference-of-minima are all reported alongside (informational — p99 is dominated by
host contention and never gates).

Threshold profiles (--profile, overridable with --warn-ns / --fail-ns):
  * default (quiet-host / manual dispatch):
      <= 50 ns OK | >50–500 ns WARN (exit 0; exit 1 with --strict) | >500 ns FAIL (exit 2)
  * ci (GitHub Actions shared runners — TSEAL-00048 §Security considerations):
      <= 10 µs OK | >10–50 µs WARN (exit 0; exit 1 with --strict) | >50 µs FAIL (exit 2)
    Real early-return regressions shift the bad path by tens of µs–ms; the relaxed CI
    fail band catches those without flaking on contended-host noise (±1 µs observed).

A JSON artifact (--json-out, schema_version 1) records parameters, environment, full
statistics, exit_code, gate_passed, and the verdict for CI parsers and trend tracking.

Optionally (--c-runner auto|PATH|skip, default skip) a COARSE, informational-only C-port
comparison runs through the prebuilt conformance runner at
tools/conformance/c/tessera_seal_runner: K duplicated decrypt records vs K duplicated
decrypt_should_fail records, timed at process granularity over R repetitions, per-record
delta = (median(T_bad) - median(T_good)) / K. Process spawn noise dominates at the
nanosecond scale, so the C numbers NEVER affect the exit status.

Wired as a blocking step in .github/workflows/conformance.yml (--profile ci) and as a
dispatch step in .github/workflows/tessera-seal.yml (default profile, manual only).
No timing assertion lives under tessera-seal/conformance/vectors/ — KyberSlash-class
coverage uses kyberslash_regression.json for functional rejection; timing flatness is
this script's job.

Usage:
    python3 tools/scripts/timing-histogram.py --pairs 20000 --json-out timing-report.json
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from typing import List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
sys.path.insert(0, os.path.join(REPO_ROOT, "tessera-seal", "python"))

SCHEMA_VERSION = 1
CROP_PCT = 0.95   # pair survives only if BOTH measurements are below their p95
PROFILES = {
    "default": {"warn_ns": 50.0, "fail_ns": 500.0, "pairs": 20000},
    # Shared CI runners: catch tens-of-µs early-return regressions; ignore ±1 µs noise.
    "ci": {"warn_ns": 10_000.0, "fail_ns": 50_000.0, "pairs": 5000},
}
AD = b"timing-histogram TSEAL-00048"
DEFAULT_C_RUNNER = os.path.join(REPO_ROOT, "tools", "conformance", "c", "tessera_seal_runner")


def p99(values: List[int]) -> float:
    s = sorted(values)
    return float(s[min(len(s) - 1, int(0.99 * len(s)))])


def build_envelopes(ts, suite: int, count: int) -> Tuple[object, List[bytes], List[bytes]]:
    """One keypair; `count` distinct good envelopes plus a tampered twin for each."""
    priv, pub = ts.generate_keypair(suite)
    goods, bads = [], []
    for i in range(count):
        env = ts.encrypt(b"timing plaintext %04d" % i, pub, suite=suite, associated_data=AD)
        bad = bytearray(env)
        bad[-1] ^= 0x01  # final byte = UtC commitment-tag tail -> auth-class failure
        goods.append(env)
        bads.append(bytes(bad))
    # Sanity: good decrypts, bad raises the single auth-class error.
    assert ts.decrypt(goods[0], priv, expected_ad=AD) == b"timing plaintext 0000"
    try:
        ts.decrypt(bads[0], priv, expected_ad=AD)
        raise SystemExit("tampered envelope unexpectedly decrypted")
    except ts.DecryptionError:
        pass
    return priv, goods, bads


def measure_python(ts, suite: int, pairs: int, warmup: int, envelopes: int) -> dict:
    priv, goods, bads = build_envelopes(ts, suite, min(envelopes, max(pairs, 1)))
    n_env = len(goods)
    decrypt, derr = ts.decrypt, ts.DecryptionError
    perf = time.perf_counter_ns

    def one(env: bytes) -> int:
        t0 = perf()
        try:
            decrypt(env, priv, expected_ad=AD)
        except derr:
            pass
        return perf() - t0

    for i in range(warmup):
        one(goods[i % n_env])
        one(bads[i % n_env])

    good_ns: List[int] = []
    bad_ns: List[int] = []
    deltas: List[int] = []
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for i in range(pairs):
            g_env, b_env = goods[i % n_env], bads[i % n_env]
            if i & 1:  # alternate order to cancel ordering bias
                tb = one(b_env)
                tg = one(g_env)
            else:
                tg = one(g_env)
                tb = one(b_env)
            good_ns.append(tg)
            bad_ns.append(tb)
            deltas.append(tb - tg)
    finally:
        if gc_was_enabled:
            gc.enable()

    # p95 contention crop: a preemption inside one call of a pair breaks the
    # pair's drift cancellation; drop pairs where either side is a p95 outlier.
    g_cut = sorted(good_ns)[int(CROP_PCT * (len(good_ns) - 1))]
    b_cut = sorted(bad_ns)[int(CROP_PCT * (len(bad_ns) - 1))]
    cropped = [d for d, g, b in zip(deltas, good_ns, bad_ns) if g <= g_cut and b <= b_cut]

    return {
        "pairs": pairs,
        "distinct_envelopes": n_env,
        "cropped_pairs": len(cropped),
        "crop_percentile": CROP_PCT,
        "cropped_median_pairwise_delta_ns": statistics.median(cropped),
        "median_good_ns": statistics.median(good_ns),
        "median_bad_ns": statistics.median(bad_ns),
        "p99_good_ns": p99(good_ns),
        "p99_bad_ns": p99(bad_ns),
        "median_pairwise_delta_ns": statistics.median(deltas),
        "p99_pairwise_delta_ns": p99(deltas),
        "delta_of_medians_ns": statistics.median(bad_ns) - statistics.median(good_ns),
        "delta_of_p99_ns": p99(bad_ns) - p99(good_ns),
        # min-vs-min is the lowest-noise estimator of the systematic path difference
        # (both minima approach the uncontended execution floor); diagnostic only.
        "delta_of_minima_ns": min(bad_ns) - min(good_ns),
    }


def measure_c_runner(ts, runner: str, suite: int, batch: int, reps: int) -> Optional[dict]:
    """Coarse process-granularity C comparison; informational only, never gates."""
    if not (os.path.isfile(runner) and os.access(runner, os.X_OK)):
        return None
    priv, pub = ts.generate_keypair(suite)
    env = ts.encrypt(b"c-runner timing plaintext", pub, suite=suite, associated_data=AD)
    bad = bytearray(env)
    bad[-1] ^= 0x01
    sk_hex = priv.to_bytes().hex()
    good_recs = [{
        "name": f"timing_good_{i:04d}", "op": "decrypt", "suite": suite,
        "private_key_hex": sk_hex, "envelope_hex": env.hex(),
        "expected_ad_hex": AD.hex(), "expected_plaintext_hex": b"c-runner timing plaintext".hex(),
    } for i in range(batch)]
    bad_recs = [{
        "name": f"timing_bad_{i:04d}", "op": "decrypt_should_fail", "suite": suite,
        "private_key_hex": sk_hex, "envelope_hex": bytes(bad).hex(),
        "expected_ad_hex": AD.hex(), "error_kind": "DECRYPT_FAILED",
    } for i in range(batch)]

    def timed_runs(records: List[dict]) -> Optional[List[int]]:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(records, fh)
            path = fh.name
        try:
            times = []
            for _ in range(reps):
                t0 = time.perf_counter_ns()
                r = subprocess.run([runner, path], capture_output=True)
                t = time.perf_counter_ns() - t0
                if r.returncode != 0:
                    sys.stderr.write(r.stdout.decode(errors="replace"))
                    return None
                times.append(t)
            return times
        finally:
            os.unlink(path)

    tg = timed_runs(good_recs)
    tb = timed_runs(bad_recs)
    if tg is None or tb is None:
        return None
    return {
        "runner": runner,
        "batch_records": batch,
        "repetitions": reps,
        "median_good_run_ns": statistics.median(tg),
        "median_bad_run_ns": statistics.median(tb),
        "per_record_delta_ns": (statistics.median(tb) - statistics.median(tg)) / batch,
        "note": "process-granularity batch measurement; informational only, never gates",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--profile", choices=sorted(PROFILES), default="default",
                    help="threshold preset: default (50/500 ns) or ci (10/50 µs for shared runners)")
    ap.add_argument("-n", "--pairs", type=int, default=None,
                    help="number of good/bad decrypt pairs (default: profile default)")
    ap.add_argument("--warn-ns", type=float, default=None,
                    help="override WARN threshold on |cropped median per-pair delta| (nanoseconds)")
    ap.add_argument("--fail-ns", type=float, default=None,
                    help="override FAIL threshold on |cropped median per-pair delta| (nanoseconds)")
    ap.add_argument("--suite", type=lambda s: int(s, 0), default=0x01,
                    help="TesseraSeal suite byte (default 0x01)")
    ap.add_argument("--warmup", type=int, default=100, help="warmup pairs (default 100)")
    ap.add_argument("--envelopes", type=int, default=64,
                    help="distinct envelopes cycled through (default 64)")
    ap.add_argument("--json-out", default="timing-histogram-report.json",
                    help="JSON artifact path (default ./timing-histogram-report.json)")
    ap.add_argument("--strict", action="store_true",
                    help="treat the WARN band (>50 ns, <=500 ns) as a failure (exit 1)")
    ap.add_argument("--c-runner", default="skip", metavar="auto|PATH|skip",
                    help="optional coarse C-port comparison via the conformance runner "
                         "binary; 'auto' probes tools/conformance/c/tessera_seal_runner "
                         "(default: skip)")
    ap.add_argument("--c-batch", type=int, default=200, help="records per C batch file")
    ap.add_argument("--c-reps", type=int, default=9, help="C runner repetitions per file")
    args = ap.parse_args()

    import tessera_seal as ts  # noqa: E402 — path injected above

    prof = PROFILES[args.profile]
    pairs = args.pairs if args.pairs is not None else prof["pairs"]
    warn_ns = args.warn_ns if args.warn_ns is not None else prof["warn_ns"]
    fail_ns = args.fail_ns if args.fail_ns is not None else prof["fail_ns"]

    print(f"timing-histogram: profile={args.profile} suite=0x{args.suite:02x} pairs={pairs} "
          f"warmup={args.warmup} envelopes={args.envelopes} "
          f"thresholds warn={warn_ns:.0f}ns fail={fail_ns:.0f}ns")
    py_stats = measure_python(ts, args.suite, pairs, args.warmup, args.envelopes)

    c_stats = None
    if args.c_runner != "skip":
        runner = DEFAULT_C_RUNNER if args.c_runner == "auto" else args.c_runner
        c_stats = measure_c_runner(ts, runner, args.suite, args.c_batch, args.c_reps)
        if c_stats is None:
            print(f"c-runner: skipped (binary missing/not executable/failed: {runner})")

    primary = abs(py_stats["cropped_median_pairwise_delta_ns"])
    if primary > fail_ns:
        verdict, exit_code = "FAIL", 2
    elif primary > warn_ns:
        verdict, exit_code = "WARN", 1 if args.strict else 0
    else:
        verdict, exit_code = "OK", 0

    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": "tools/scripts/timing-histogram.py",
        "ticket": "TSEAL-00048",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "params": {"profile": args.profile, "suite": args.suite, "pairs": pairs,
                   "warmup": args.warmup, "envelopes": args.envelopes, "strict": args.strict},
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "perf_counter_resolution_s": time.get_clock_info("perf_counter").resolution,
        },
        "thresholds_ns": {"warn": warn_ns, "fail": fail_ns,
                          "metric": "abs(p95-cropped median of per-pair deltas: bad_ns - good_ns)"},
        "primary_metric_ns": primary,
        "python_reference": py_stats,
        "c_runner": c_stats,
        "verdict": verdict,
        "exit_code": exit_code,
        "gate_passed": exit_code == 0,
    }
    with open(args.json_out, "w") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")

    print(f"  median good          : {py_stats['median_good_ns'] / 1e3:12.3f} us")
    print(f"  median bad           : {py_stats['median_bad_ns'] / 1e3:12.3f} us")
    print(f"  p99 good             : {py_stats['p99_good_ns'] / 1e3:12.3f} us")
    print(f"  p99 bad              : {py_stats['p99_bad_ns'] / 1e3:12.3f} us")
    print(f"  cropped median delta : {py_stats['cropped_median_pairwise_delta_ns']:12.1f} ns  "
          f"(primary metric; {py_stats['cropped_pairs']}/{py_stats['pairs']} pairs survive p95 crop)")
    print(f"  median pairwise delta: {py_stats['median_pairwise_delta_ns']:12.1f} ns  (uncropped)")
    print(f"  delta of medians     : {py_stats['delta_of_medians_ns']:12.1f} ns")
    print(f"  p99 delta            : {py_stats['delta_of_p99_ns']:12.1f} ns  (informational; contention-dominated)")
    print(f"  delta of minima      : {py_stats['delta_of_minima_ns']:12.1f} ns  (diagnostic; lowest-noise estimator)")
    if c_stats:
        print(f"  C per-record delta   : {c_stats['per_record_delta_ns']:12.1f} ns  ({c_stats['note']})")
    print(f"  artifact             : {args.json_out}")
    print(f"timing-histogram verdict: {verdict} "
          f"(|cropped median pairwise delta| = {primary:.1f} ns; warn > {warn_ns:.0f}, fail > {fail_ns:.0f}; "
          f"exit_code={exit_code} gate_passed={exit_code == 0})")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
