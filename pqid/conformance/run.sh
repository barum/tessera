#!/usr/bin/env bash
# Cross-language PQID conformance harness.
#
# Builds every per-language runner and runs every vectors/*.json against
# each. Exits 0 iff every language passes every vector.
#
# Usage:
#   bash pqid/conformance/run.sh                 # run all languages
#   bash pqid/conformance/run.sh python go       # subset
#   PQID_CONFORMANCE_SKIP="java cpython" run.sh  # skip languages
#
# Portable bash 3.2 compatible — uses no associative arrays.

set -o pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VECTORS="$HERE/vectors"

ALL_LANGS="python c cpp go rust typescript java cpython"

runner_cmd() {
    case "$1" in
        python)     echo "python3 $HERE/runners/python_runner.py" ;;
        c)          echo "$ROOT/c/conformance_runner" ;;
        cpp)        echo "$ROOT/cpp/conformance_runner" ;;
        go)         echo "$HERE/.build/go_runner" ;;
        rust)       echo "$ROOT/rust/target/release/conformance_runner" ;;
        typescript) echo "node $ROOT/typescript/dist/conformance_runner.js" ;;
        java)       echo "java -cp $ROOT/java/build com.pqid.ConformanceRunner" ;;
        cpython)    echo "python3 $ROOT/cpython/conformance_runner.py" ;;
        *)          return 1 ;;
    esac
}

build_lang() {
    case "$1" in
        python)     return 0 ;;
        c)          ( cd "$ROOT/c"   && make -s conformance_runner ) ;;
        cpp)        ( cd "$ROOT/cpp" && make -s conformance_runner ) ;;
        go)
            mkdir -p "$HERE/.build"
            ( cd "$ROOT/go" && go build -o "$HERE/.build/go_runner" ./cmd/conformance_runner )
            ;;
        rust)       ( cd "$ROOT/rust" && cargo build --release --bin conformance_runner --quiet ) ;;
        typescript) ( cd "$ROOT/typescript" && { [ -d node_modules ] || npm install --silent; } && npx tsc ) ;;
        java)       ( cd "$ROOT/java" && make -s build ) ;;
        cpython)    ( cd "$ROOT/cpython" && python3 setup.py build_ext --inplace >/dev/null 2>&1 ) ;;
        *)          return 1 ;;
    esac
}

# Select language list.
if [ $# -gt 0 ]; then
    LANGS="$*"
else
    LANGS="$ALL_LANGS"
fi

# Apply skip list.
SKIP="${PQID_CONFORMANCE_SKIP:-}"
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

echo "=== PQID conformance harness ==="
echo "vectors: $VECTORS"
echo "languages: $LANGS"
echo

# Build.
for lang in $LANGS; do
    printf "build %s ... " "$lang"
    if build_lang "$lang" >"/tmp/pqid_build_${lang}.log" 2>&1; then
        echo "ok"
    else
        echo "FAILED (see /tmp/pqid_build_${lang}.log)"
        cat "/tmp/pqid_build_${lang}.log" >&2
        exit 2
    fi
done
echo

# Run vectors per language. Write per-lang results to /tmp/pqid_result_$lang.
overall_fail=0
for lang in $LANGS; do
    cmd=$(runner_cmd "$lang")
    pass=0
    fail=0
    for v in "$VECTORS"/*.json; do
        out=$($cmd "$v" 2>&1)
        p=$(echo "$out" | grep -c "^PASS")
        f=$(echo "$out" | grep -c "^FAIL")
        pass=$((pass + p))
        fail=$((fail + f))
        if [ "$f" -gt 0 ]; then
            echo "[$lang] $(basename "$v"):"
            echo "$out" | grep "^FAIL" | sed 's/^/  /'
        fi
    done
    printf "%s %d %d\n" "$lang" "$pass" "$fail" > "/tmp/pqid_result_${lang}"
    [ "$fail" -gt 0 ] && overall_fail=1
done

echo
echo "=== Summary ==="
printf "%-12s %8s %8s\n" "language" "PASS" "FAIL"
for lang in $LANGS; do
    line=$(cat "/tmp/pqid_result_${lang}")
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
