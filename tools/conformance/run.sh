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

set -o pipefail

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

# Languages with hybrid (suite 0x06) support. Vectors matching hybrid_*.json
# are only fed to these languages; others would FAIL with UNKNOWN_SUITE.
# Hybrid (suite 0x06) shipped in Python (TSEAL-00021), Rust (TSEAL-00028), and
# Go (TSEAL-00029). C/C++/TypeScript/Java/CPython ext remain on the v1.4 hybrid
# backlog (TSEAL-00030) and reject 0x06 as UNKNOWN_SUITE for now.
hybrid_supported() {
    case "$1" in
        python) return 0 ;;
        rust)   return 0 ;;
        go)     return 0 ;;
        *)      return 1 ;;
    esac
}

for lang in $LANGS; do
    cmd=$(runner_cmd "$lang")
    seal_cmd=$(tessera_seal_runner_cmd "$lang" 2>/dev/null || echo "")
    pass=0
    fail=0
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
            p=$(echo "$out" | grep -c "^PASS")
            f=$(echo "$out" | grep -c "^FAIL")
            pass=$((pass + p))
            fail=$((fail + f))
            if [ "$f" -gt 0 ]; then
                echo "[$lang] $base:"
                echo "$out" | grep "^FAIL" | sed 's/^/  /'
            fi
        done
    done
    printf "%s %d %d\n" "$lang" "$pass" "$fail" > "/tmp/tessera_result_${lang}"
    [ "$fail" -gt 0 ] && overall_fail=1
done

echo
echo "=== Summary ==="
printf "%-12s %8s %8s\n" "language" "PASS" "FAIL"
for lang in $LANGS; do
    line=$(cat "/tmp/tessera_result_${lang}")
    printf "%-12s %8s %8s\n" "$(echo "$line" | awk '{print $1}')" \
        "$(echo "$line" | awk '{print $2}')" \
        "$(echo "$line" | awk '{print $3}')"
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
