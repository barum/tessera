#!/usr/bin/env bash
# Cross-language Tessera conformance harness.
#
# Builds every per-language runner and runs every vectors/*.json against
# each. Vectors come from tessera-id/conformance/vectors/,
# tessera-hash/conformance/vectors/, and tessera-seal/conformance/vectors/.
#
# Usage:
#   bash tools/conformance/run.sh                            # all langs, all projects
#   bash tools/conformance/run.sh python go                  # subset of languages
#   TESSERA_CONFORMANCE_SKIP="java cpython" run.sh           # skip languages
#   TESSERA_CONFORMANCE_SKIP="cpp typescript java cpython" run.sh   # TesseraSeal v1 alpha set
#
# Portable bash 3.2 compatible — no associative arrays.
#
# Each runner emits exactly one PASS/FAIL/SKIP line per JSON record ('doc'
# pseudo-records and unexecutable records emit SKIP). The harness checks every
# runner invocation's exit code AND reconciles PASS+FAIL+SKIP against the
# file's record count, so a crashed, missing, or silently-undercounting
# runner turns the run red instead of contributing 0/0 (TESS-00007 / TP-020).
#
# set -u: undefined variables are bugs. `set -e` is DELIBERATELY omitted
# (TP-024): runners exit nonzero whenever a vector record fails, and the
# harness must keep aggregating per-language results rather than abort at the
# first red file — every exit status below is checked explicitly instead.
set -u -o pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"             # tools/conformance/
TOOLS="$(cd "$HERE/.." && pwd)"                   # tools/
ROOT="$(cd "$TOOLS/.." && pwd)"                   # repo root
VECTOR_DIRS="$ROOT/tessera-id/conformance/vectors $ROOT/tessera-hash/conformance/vectors $ROOT/tessera-seal/conformance/vectors"

ALL_LANGS="python c cpp go rust typescript java cpython"

runner_cmd() {
    case "$1" in
        python)     echo "python3 $HERE/python/python_runner.py" ;;
        c)          echo "$HERE/c/conformance_runner" ;;
        cpp)        echo "$HERE/cpp/conformance_runner" ;;
        go)         echo "$HERE/go/conformance_runner" ;;
        rust)       echo "$ROOT/target/release/conformance_runner" ;;
        typescript) echo "node $HERE/typescript/dist/conformance_runner.js" ;;
        java)       echo "java -cp $HERE/java/build com.tessera.conformance.ConformanceRunner" ;;
        cpython)    echo "python3 $HERE/cpython/conformance_runner.py" ;;
        *)          return 1 ;;
    esac
}

# Per-language TesseraSeal-only runner. The tessera-id/tessera-hash vectors are
# the historical scope of `runner_cmd`; the tessera-seal vector dir is consumed
# by these dedicated binaries (TSEAL-00015). Languages that do not have a
# tessera-seal runner yet (cpp, typescript, java, cpython) skip the seal vector
# dir entirely via the empty-case (there is no Python-runner fallback).
tessera_seal_runner_cmd() {
    case "$1" in
        python)     echo "python3 $HERE/python/python_runner.py" ;;
        c)          echo "$HERE/c/tessera_seal_runner" ;;
        go)         echo "$ROOT/target-go/tessera_seal_runner" ;;
        rust)       echo "$ROOT/target/release/tessera_seal_runner" ;;
        *)          return 1 ;;  # cpp/typescript/java/cpython: skip seal vectors for now
    esac
}

build_lang() {
    case "$1" in
        python)     return 0 ;;
        c)          ( cd "$HERE/c"   && make -s ) ;;
        cpp)        ( cd "$HERE/cpp" && make -s ) ;;
        go)         ( cd "$HERE/go"  && go build -o conformance_runner .
                      cd "$HERE/go/tessera_seal_runner" && go build -o "$ROOT/target-go/tessera_seal_runner" .
                    ) ;;
        rust)       ( cd "$HERE/rust" && cargo build --release --bin conformance_runner --bin tessera_seal_runner --quiet ) ;;
        typescript) (
                        cd "$ROOT/tessera-id/typescript" && { [ -d node_modules ] || npm install --silent; } && npx tsc &&
                        cd "$ROOT/tessera-hash/typescript" && { [ -d node_modules ] || npm install --silent; } && npx tsc &&
                        cd "$HERE/typescript" && { [ -d node_modules ] || npm install --silent; } && npx tsc
                    ) ;;
        java)       ( cd "$HERE/java" && make -s build ) ;;
        cpython)    ( cd "$ROOT/tessera-id/cpython" && python3 setup.py build_ext --inplace >/dev/null 2>&1 ) ;;
        *)          return 1 ;;
    esac
}

# Ensure target-go/ exists for the Go tessera_seal_runner output.
mkdir -p "$ROOT/target-go"

if [ $# -gt 0 ]; then
    LANGS="$*"
else
    LANGS="$ALL_LANGS"
fi

SKIP="${TESSERA_CONFORMANCE_SKIP:-}"

# Warn loudly on unknown skip tokens (TP-024): a typo'd token would otherwise
# no-op silently while you believe the language was skipped.
for s in $SKIP; do
    known=0
    for l in $ALL_LANGS; do
        [ "$s" = "$l" ] && known=1
    done
    if [ "$known" = "0" ]; then
        echo "WARNING: TESSERA_CONFORMANCE_SKIP token '$s' is not a known language (expected one of: $ALL_LANGS)" >&2
    fi
done

FILTERED=""
for l in $LANGS; do
    skip=0
    for s in $SKIP; do
        [ "$l" = "$s" ] && skip=1
    done
    [ "$skip" = "0" ] && FILTERED="$FILTERED $l"
done
LANGS=$(echo "$FILTERED" | sed 's/^ *//')

if [ -z "$LANGS" ]; then
    echo "no languages selected" >&2
    exit 2
fi

echo "=== tessera conformance harness ==="
echo "vectors: $VECTOR_DIRS"
echo "languages: $LANGS"
echo

for lang in $LANGS; do
    printf "build %s ... " "$lang"
    if build_lang "$lang" >"/tmp/tessera_build_${lang}.log" 2>&1; then
        echo "ok"
    else
        echo "FAILED (see /tmp/tessera_build_${lang}.log)"
        cat "/tmp/tessera_build_${lang}.log" >&2
        exit 2
    fi
done
echo

overall_fail=0
TESSERA_SEAL_VEC_DIR="$ROOT/tessera-seal/conformance/vectors"

# --- Record-count enforcement (TP-020) -------------------------------------
# Precompute the record count of every vector file once. Runners must emit
# exactly one PASS/FAIL/SKIP line per record; any shortfall or excess means a
# crash mid-file, a silently-dropped record, or double counting — all hard
# failures. python3 is a hard prerequisite of the harness (the python runner
# needs it anyway).
COUNTS_FILE="$(mktemp /tmp/tessera_vector_counts.XXXXXX)"
trap 'rm -f "$COUNTS_FILE"' EXIT
if ! python3 - $VECTOR_DIRS >"$COUNTS_FILE" <<'PYEOF'
import glob
import json
import os
import sys

for d in sys.argv[1:]:
    for p in sorted(glob.glob(os.path.join(d, "*.json"))):
        with open(p) as f:
            print(p, len(json.load(f)))
PYEOF
then
    echo "FATAL: cannot count vector records (python3 + valid JSON required)" >&2
    exit 2
fi

expected_count() {
    awk -v f="$1" '$1 == f { print $2 }' "$COUNTS_FILE"
}

# Languages whose tessera-seal CONFORMANCE RUNNER consumes the hybrid_*.json
# (suite 0x06) vectors. Vectors matching hybrid_*.json are only fed to these.
# Runner-hybrid: Python (PQCK-00021), Rust (PQCK-00028), Go (PQCK-00029),
# and C (TSEAL-00030). C++/TS/Java/CPython ext have no tessera-seal runner, so
# the harness skips hybrid_*.json (and all seal vectors) for them. The LIBRARY
# axis differs: C++ (TSEAL-00031), TS (TSEAL-00032), and the CPython ext
# (TSEAL-00034) now implement 0x06 at the library level; only Java (TSEAL-00033)
# still rejects 0x06 as UNKNOWN_SUITE.
hybrid_supported() {
    case "$1" in
        python) return 0 ;;
        rust)   return 0 ;;
        go)     return 0 ;;
        c)      return 0 ;;
        *)      return 1 ;;
    esac
}

for lang in $LANGS; do
    cmd=$(runner_cmd "$lang")
    seal_cmd=$(tessera_seal_runner_cmd "$lang" 2>/dev/null || echo "")
    pass=0
    fail=0
    skip=0
    for vdir in $VECTOR_DIRS; do
        if [ "$vdir" = "$TESSERA_SEAL_VEC_DIR" ]; then
            if [ -n "$seal_cmd" ]; then
                this_cmd="$seal_cmd"
            else
                # cpp/typescript/java/cpython have NO tessera-seal runner. Skip the
                # seal vector dir entirely for them — feeding seal vectors to
                # their tessera-id/tessera-hash runner would FAIL with "unknown op".
                # (There is no Python-runner fallback.) These languages run
                # tessera-id + tessera-hash only until their v1.4 seal ports land.
                continue
            fi
        else
            this_cmd="$cmd"
        fi
        for v in "$vdir"/*.json; do
            base=$(basename "$v")
            # Skip hybrid vector files for languages that don't support hybrid yet.
            case "$base" in
                hybrid_*)
                    if ! hybrid_supported "$lang"; then continue; fi
                    ;;
            esac
            out=$($this_cmd "$v" 2>&1)
            rc=$?
            p=$(echo "$out" | grep -c "^PASS")
            f=$(echo "$out" | grep -c "^FAIL")
            s=$(echo "$out" | grep -c "^SKIP")
            pass=$((pass + p))
            fail=$((fail + f))
            skip=$((skip + s))
            if [ "$f" -gt 0 ]; then
                echo "[$lang] $base:"
                echo "$out" | grep "^FAIL" | sed 's/^/  /'
            fi
            hard=0
            # TP-020: nonzero exit with zero FAIL lines = the runner crashed
            # (segfault, missing binary, unhandled exception) before it could
            # report. Count and report it — never a silent 0/0.
            if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then
                echo "[$lang] $base: HARD FAILURE — runner exited rc=$rc with no FAIL lines"
                echo "$out" | tail -5 | sed 's/^/  /'
                fail=$((fail + 1))
                hard=1
            fi
            # TP-020: reconcile emitted result lines against the record count.
            if [ "$hard" -eq 0 ]; then
                expected=$(expected_count "$v")
                if [ -z "$expected" ]; then
                    echo "[$lang] $base: HARD FAILURE — no record count known for $v"
                    fail=$((fail + 1))
                elif [ $((p + f + s)) -ne "$expected" ]; then
                    echo "[$lang] $base: COUNT MISMATCH — PASS+FAIL+SKIP=$((p + f + s)) but file has $expected records"
                    fail=$((fail + 1))
                fi
            fi
        done
    done
    printf "%s %d %d %d\n" "$lang" "$pass" "$fail" "$skip" > "/tmp/tessera_result_${lang}"
    [ "$fail" -gt 0 ] && overall_fail=1
done

echo
echo "=== Summary ==="
printf "%-12s %8s %8s %8s\n" "language" "PASS" "FAIL" "SKIP"
for lang in $LANGS; do
    line=$(cat "/tmp/tessera_result_${lang}")
    printf "%-12s %8s %8s %8s\n" "$(echo "$line" | awk '{print $1}')" \
        "$(echo "$line" | awk '{print $2}')" \
        "$(echo "$line" | awk '{print $3}')" \
        "$(echo "$line" | awk '{print $4}')"
done

if [ "$overall_fail" = "0" ]; then
    echo
    echo "ALL LANGUAGES GREEN"
    exit 0
else
    echo
    echo "CONFORMANCE FAILURES — see per-language output above"
    exit 1
fi
