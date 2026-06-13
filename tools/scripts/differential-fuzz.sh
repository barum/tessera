#!/usr/bin/env bash
# differential-fuzz.sh — cross-language differential fuzzer (TESS-00016 / TP-097).
#
# A cryptofuzz-style differential oracle built on top of the existing 8
# conformance runners. It:
#
#   1. Generates N random STRUCTURED inputs from the Python reference —
#      random valid TesseraIDs/TesseraHashes plus targeted mutations
#      (wrong variant, truncation, non-canonical Base64URL/Crockford pad
#      bits, bad alphabet). Python is the authority (repo authority order:
#      whitepaper -> Python -> C -> rest), so each record's EXPECTED result
#      is exactly what the Python reference does with that input.
#   2. Writes those records to a SINGLE differential vector file under
#      $TMPDIR (never the repo vectors dir — these are throwaway, not the
#      frozen append-only KAT contract).
#   3. Feeds the SAME file to every language's general conformance runner.
#   4. Diffs accept/reject + output bytes across languages: any record where
#      a language disagrees with the Python oracle (FAIL line) is a
#      divergence. On any divergence the script writes a minimal repro file
#      and exits 1; a clean run exits 0.
#
# This converts the polyglot matrix into a correctness oracle: no other
# greenfield format project has 8 first-party implementations to diff.
#
# Usage:
#   bash tools/conformance/../scripts/differential-fuzz.sh                 # 200 inputs, all 8 langs
#   N=500 bash tools/scripts/differential-fuzz.sh                          # more inputs
#   TESSERA_DIFF_SEED=20260610 bash tools/scripts/differential-fuzz.sh     # pin the seed (reproducible)
#   TESSERA_DIFF_LANGS="python go rust" bash tools/scripts/differential-fuzz.sh   # subset
#
# See tools/conformance/DIFFERENTIAL.md for the full design and the repro
# workflow when a divergence is found.
set -u -o pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"             # tools/scripts/
ROOT="$(cd "$HERE/../.." && pwd)"                 # repo root
CONF="$ROOT/tools/conformance"

N="${N:-200}"
SEED="${TESSERA_DIFF_SEED:-$(date +%s)$$}"
LANGS="${TESSERA_DIFF_LANGS:-python c cpp go rust typescript java cpython}"
SKIP="${TESSERA_DIFF_SKIP:-}"

WORK="$(mktemp -d /tmp/tessera-differential.XXXXXX)"
VECTOR="$WORK/differential.json"
REPRO="$WORK/repro.json"

echo "=== tessera differential fuzzer (TP-097) ==="
echo "inputs:    $N"
echo "seed:      $SEED   (re-run with TESSERA_DIFF_SEED=$SEED to reproduce)"
echo "languages: $LANGS"
echo "vector:    $VECTOR   (throwaway — NOT a repo KAT vector)"
echo

# --- 1. Generate the differential vector from the Python reference ----------
python3 - "$VECTOR" "$N" "$SEED" "$ROOT" <<'PYEOF'
import json
import random
import sys
from pathlib import Path

vector_path, n, seed, root = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
sys.path.insert(0, str(Path(root) / "tessera-id" / "python"))
sys.path.insert(0, str(Path(root) / "tessera-hash" / "python"))
import tessera_id
import tessera_hash

rng = random.Random(seed)
B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
CROCK = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

records = []


def rand_id(variant):
    ts = rng.getrandbits(48).to_bytes(6, "big")
    ctr = rng.getrandbits(16).to_bytes(2, "big")
    tail = bytes(rng.getrandbits(8) for _ in range(32))
    return ts + bytes([variant]) + ctr + tail


def rand_hash():
    ts = rng.getrandbits(48).to_bytes(6, "big")
    ctr = rng.getrandbits(16).to_bytes(2, "big")
    tail = bytes(rng.getrandbits(8) for _ in range(64))
    return ts[:6] + bytes([0x03]) + ctr + tail


def id_decode_record(name, raw):
    d = tessera_id.decode(raw)
    records.append({
        "name": name, "op": "decode", "input_hex": raw.hex(),
        "expected": {"variant": d.variant, "timestamp_ms": d.timestamp_ms,
                     "counter": d.counter, "random_hex": d.random.hex()},
    })


def id_text_record(name, raw, kind):
    if kind == "b64":
        records.append({"name": name, "op": "decode_b64",
                        "input_str": tessera_id.encode_b64(raw),
                        "expected_hex": raw.hex()})
    else:
        records.append({"name": name, "op": "decode_crockford",
                        "input_str": tessera_id.encode_b32(raw),
                        "expected_hex": raw.hex()})


def id_invalid_record(name, kind, value):
    """Record a should-reject input — but only after CONFIRMING the Python
    oracle actually rejects it. If Python accepts, reclassify as a valid
    decode/text record so the oracle stays truthful."""
    try:
        if kind == "binary_hex":
            tessera_id.decode(bytes.fromhex(value))
        elif kind == "b64":
            tessera_id.decode(tessera_id.decode_b64(value))
        elif kind == "crockford":
            tessera_id.decode(tessera_id.decode_b32(value))
    except tessera_id.TesseraIDError:
        rec = {"name": name, "op": "validate_invalid", "input_kind": kind,
               "expected_error": "rejected"}
        rec["input_hex" if kind == "binary_hex" else "input_str"] = value
        records.append(rec)
        return
    # Python accepted it — not actually invalid. Drop it (keep the oracle honest).


def hash_decode_record(name, raw):
    d = tessera_hash.decode(raw)
    records.append({
        "name": name, "op": "tessera_hash_decode", "input_hex": raw.hex(),
        "expected": {"variant": d.variant, "timestamp_ms": d.timestamp_ms,
                     "counter": d.counter, "tail_hex": d.tail.hex()},
    })


def hash_text_record(name, raw, kind):
    if kind == "b64":
        records.append({"name": name, "op": "tessera_hash_decode_b64",
                        "input_str": tessera_hash.encode_b64(raw),
                        "expected_hex": raw.hex()})
    else:
        records.append({"name": name, "op": "tessera_hash_decode_crockford",
                        "input_str": tessera_hash.encode_b32(raw),
                        "expected_hex": raw.hex()})


def hash_invalid_record(name, kind, value):
    try:
        if kind == "binary_hex":
            tessera_hash.decode(bytes.fromhex(value))
        elif kind == "b64":
            tessera_hash.decode(tessera_hash.decode_b64(value))
        elif kind == "crockford":
            tessera_hash.decode(tessera_hash.decode_b32(value))
    except tessera_hash.TesseraHashError:
        rec = {"name": name, "op": "tessera_hash_validate_invalid", "input_kind": kind,
               "expected_error": "rejected"}
        rec["input_hex" if kind == "binary_hex" else "input_str"] = value
        records.append(rec)
        return


def flip_pad_b64(s, alphabet):
    last = alphabet.index(s[-1])
    return s[:-1] + alphabet[last | 0x03]


def flip_pad_crock(s):
    last = CROCK.index(s[-1].upper())
    return s[:-1] + CROCK[last | 0x03]


i = 0
while len(records) < n:
    i += 1
    choice = rng.randrange(12)
    nm = f"diff_{i:04d}"
    try:
        if choice == 0:
            id_decode_record(f"{nm}_id_std", rand_id(0x01))
        elif choice == 1:
            id_decode_record(f"{nm}_id_hlc", rand_id(0x02))
        elif choice == 2:
            id_text_record(f"{nm}_id_b64", rand_id(rng.choice([1, 2])), "b64")
        elif choice == 3:
            id_text_record(f"{nm}_id_crock", rand_id(rng.choice([1, 2])), "crockford")
        elif choice == 4:
            # Wrong variant byte (anything but 0x01/0x02).
            v = rng.choice([0x00, 0x03, 0x04, 0x05, 0x10, 0x7f, 0xfe, 0xff])
            id_invalid_record(f"{nm}_id_badvar", "binary_hex", rand_id(v).hex())
        elif choice == 5:
            # Truncated / overlong binary.
            raw = rand_id(0x01)
            cut = rng.choice([0, 1, 40, 42, 80])
            id_invalid_record(f"{nm}_id_badlen", "binary_hex", raw[:cut].hex() if cut <= 41 else (raw + raw[:cut - 41]).hex())
        elif choice == 6:
            # Non-canonical Base64URL pad bits.
            s = tessera_id.encode_b64(rand_id(0x01))
            id_invalid_record(f"{nm}_id_b64pad", "b64", flip_pad_b64(s, B64_ALPHABET))
        elif choice == 7:
            # Non-canonical Crockford pad bits.
            s = tessera_id.encode_b32(rand_id(0x01))
            id_invalid_record(f"{nm}_id_crockpad", "crockford", flip_pad_crock(s))
        elif choice == 8:
            hash_decode_record(f"{nm}_hash", rand_hash())
        elif choice == 9:
            hash_text_record(f"{nm}_hash_b64", rand_hash(), "b64")
        elif choice == 10:
            hash_text_record(f"{nm}_hash_crock", rand_hash(), "crockford")
        else:
            # Hash mutations: wrong variant, truncation, bad pad bits.
            sub = rng.randrange(3)
            if sub == 0:
                raw = bytearray(rand_hash())
                raw[6] = rng.choice([0x00, 0x01, 0x02, 0x04, 0xff])
                hash_invalid_record(f"{nm}_hash_badvar", "binary_hex", bytes(raw).hex())
            elif sub == 1:
                raw = rand_hash()
                hash_invalid_record(f"{nm}_hash_badlen", "binary_hex", raw[:rng.choice([0, 72])].hex())
            else:
                s = tessera_hash.encode_b32(rand_hash())
                hash_invalid_record(f"{nm}_hash_crockpad", "crockford", flip_pad_crock(s))
    except Exception as e:  # generator bug — fail loudly, never emit a bad vector
        print(f"generator error on {nm}: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(3)

records = records[:n]
Path(vector_path).write_text(json.dumps(records, indent=0))
print(f"generated {len(records)} differential records", file=sys.stderr)
PYEOF
gen_rc=$?
if [ "$gen_rc" -ne 0 ]; then
    echo "FATAL: differential vector generation failed (rc=$gen_rc)" >&2
    rm -rf "$WORK"
    exit 2
fi

REC_COUNT=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "$VECTOR")
echo "vector ready: $REC_COUNT records"
echo

# --- runner command + build (mirrors tools/conformance/run.sh) --------------
runner_cmd() {
    case "$1" in
        python)     echo "python3 $CONF/python/python_runner.py" ;;
        c)          echo "$CONF/c/conformance_runner" ;;
        cpp)        echo "$CONF/cpp/conformance_runner" ;;
        go)         echo "$CONF/go/conformance_runner" ;;
        rust)       echo "$ROOT/target/release/conformance_runner" ;;
        typescript) echo "node $CONF/typescript/dist/conformance_runner.js" ;;
        java)       echo "java -cp $CONF/java/build com.tessera.conformance.ConformanceRunner" ;;
        cpython)    echo "python3 $CONF/cpython/conformance_runner.py" ;;
        *)          return 1 ;;
    esac
}

build_lang() {
    case "$1" in
        python)     return 0 ;;
        c)          ( cd "$CONF/c"   && make -s ) ;;
        cpp)        ( cd "$CONF/cpp" && make -s ) ;;
        go)         ( cd "$CONF/go"  && go build -o conformance_runner . ) ;;
        rust)       ( cd "$CONF/rust" && cargo build --release --bin conformance_runner --quiet ) ;;
        typescript) (
                        cd "$ROOT/tessera-id/typescript" && { [ -d node_modules ] || npm install --silent; } && npx tsc &&
                        cd "$ROOT/tessera-hash/typescript" && { [ -d node_modules ] || npm install --silent; } && npx tsc &&
                        cd "$CONF/typescript" && { [ -d node_modules ] || npm install --silent; } && npx tsc
                    ) ;;
        java)       ( cd "$CONF/java" && make -s build ) ;;
        cpython)    ( cd "$ROOT/tessera-id/cpython" && python3 setup.py build_ext --inplace >/dev/null 2>&1 ) ;;
        *)          return 1 ;;
    esac
}

# Apply skip list.
FILTERED=""
for l in $LANGS; do
    skip=0
    for s in $SKIP; do [ "$l" = "$s" ] && skip=1; done
    [ "$skip" = "0" ] && FILTERED="$FILTERED $l"
done
LANGS=$(echo "$FILTERED" | sed 's/^ *//')

for lang in $LANGS; do
    printf "build %-10s ... " "$lang"
    if build_lang "$lang" >"$WORK/build_${lang}.log" 2>&1; then
        echo "ok"
    else
        echo "FAILED (see $WORK/build_${lang}.log)"
        cat "$WORK/build_${lang}.log" >&2
        rm -rf "$WORK"
        exit 2
    fi
done
echo

# --- 3+4. Run every language; collect the set of FAILed record names --------
divergence=0
for lang in $LANGS; do
    cmd=$(runner_cmd "$lang")
    out=$($cmd "$VECTOR" 2>&1)
    rc=$?
    p=$(echo "$out" | grep -c "^PASS")
    f=$(echo "$out" | grep -c "^FAIL")
    s=$(echo "$out" | grep -c "^SKIP")
    printf "%-12s PASS=%-4s FAIL=%-4s SKIP=%-4s rc=%s\n" "$lang" "$p" "$f" "$s" "$rc"
    if [ "$f" -gt 0 ]; then
        divergence=1
        echo "  --- $lang diverged from the Python oracle on:"
        echo "$out" | grep "^FAIL" | sed 's/^/    /'
        echo "$out" | grep "^FAIL" | awk '{print $2}' >> "$WORK/diverged_names.txt"
    fi
    # A crash (nonzero rc with no FAIL lines) is also a divergence.
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then
        divergence=1
        echo "  --- $lang HARD FAILURE (rc=$rc, no FAIL lines):"
        echo "$out" | tail -5 | sed 's/^/    /'
    fi
done

echo
if [ "$divergence" -eq 0 ]; then
    echo "DIFFERENTIAL CLEAN — all $REC_COUNT inputs decoded identically across: $LANGS"
    rm -rf "$WORK"
    exit 0
fi

# --- Write a minimal repro file with only the diverging records -------------
python3 - "$VECTOR" "$REPRO" "$WORK/diverged_names.txt" <<'PYEOF'
import json
import sys
from pathlib import Path

vector, repro, names_file = sys.argv[1], sys.argv[2], sys.argv[3]
names = set()
p = Path(names_file)
if p.exists():
    names = {ln.strip() for ln in p.read_text().splitlines() if ln.strip()}
recs = json.load(open(vector))
diverging = [r for r in recs if r.get("name") in names]
Path(repro).write_text(json.dumps(diverging, indent=2))
print(f"wrote {len(diverging)} diverging record(s) to {repro}", file=sys.stderr)
PYEOF

echo
echo "DIVERGENCE FOUND — repro vector: $REPRO"
echo "Reproduce a single language with:"
echo "  \$(<runner_cmd>) $REPRO"
echo "The work dir ($WORK) is intentionally NOT removed so you can inspect it."
exit 1
