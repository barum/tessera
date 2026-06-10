#!/usr/bin/env bash
# run-examples.sh — execute every example under */examples/ so the snippets in
# the READMEs cannot rot.
#
# Covers, per project (tessera-id, tessera-hash, tessera-seal):
#   - examples/python/example.py          library basics (PYTHONPATH form)
#   - examples/go/example.go              library basics (go run via go.work)
#   - python interop emitter | go interop consumer   cross-language byte-identity
#
# Requirements: python3 (tessera-seal additionally needs its Python deps —
# `pip install -r tessera-seal/python/requirements.txt`) and a Go toolchain
# matching the go.work directive. Run from anywhere; paths resolve from the
# script location.
#
# Exit status: 0 = every example ran green; nonzero = first failure (set -e).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PY=python3
pass=0

run() {
  local desc="$1"
  shift
  echo "==> ${desc}"
  "$@"
  pass=$((pass + 1))
}

run_pipe() {
  # run_pipe <desc> <emitter...> '|' <consumer...> — explicit two-stage pipe so
  # failures in EITHER side fail the script (set -o pipefail).
  local desc="$1"
  shift
  echo "==> ${desc}"
  local emitter=() consumer=() seen_pipe=0
  for a in "$@"; do
    if [[ "$a" == "|" ]]; then
      seen_pipe=1
      continue
    fi
    if [[ $seen_pipe -eq 0 ]]; then emitter+=("$a"); else consumer+=("$a"); fi
  done
  "${emitter[@]}" | "${consumer[@]}"
  pass=$((pass + 1))
}

# --- tessera-id -------------------------------------------------------------
run "tessera-id python example" \
  env PYTHONPATH=tessera-id/python "$PY" tessera-id/examples/python/example.py
run "tessera-id go example" \
  go run ./tessera-id/examples/go
run_pipe "tessera-id interop (python encode -> go decode)" \
  env PYTHONPATH=tessera-id/python "$PY" tessera-id/examples/python/interop_encode.py \
  '|' go run ./tessera-id/examples/go/interop

# --- tessera-hash -----------------------------------------------------------
run "tessera-hash python example" \
  env PYTHONPATH=tessera-hash/python "$PY" tessera-hash/examples/python/example.py
run "tessera-hash go example" \
  go run ./tessera-hash/examples/go
run_pipe "tessera-hash interop (python hash_at -> go verify+recompute)" \
  env PYTHONPATH=tessera-hash/python "$PY" tessera-hash/examples/python/interop_encode.py \
  '|' go run ./tessera-hash/examples/go/interop

# --- tessera-seal -----------------------------------------------------------
run "tessera-seal python example" \
  env PYTHONPATH=tessera-id/python:tessera-seal/python "$PY" tessera-seal/examples/python/example.py
run "tessera-seal go example" \
  go run ./tessera-seal/examples/go
run_pipe "tessera-seal interop (python encrypt -> go decrypt)" \
  env PYTHONPATH=tessera-id/python:tessera-seal/python "$PY" tessera-seal/examples/python/interop_encrypt.py \
  '|' go run ./tessera-seal/examples/go/interop

echo "run-examples: ${pass}/9 examples green"
