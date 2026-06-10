#!/usr/bin/env bash
# check-vector-freeze.sh — enforce the append-only conformance-vector contract (TP-023 / TESS-00007).
#
# Shipped vectors under */conformance/vectors/*.json are FROZEN: regeneration may append new records or add
# new files, but MUST NOT change or remove any existing record. This script diffs every vector file in the
# working tree against a git ref (default HEAD) record-by-record (keyed by the record's "name" field) and
# fails if any record present at the ref has different bytes now, or has disappeared.
set -euo pipefail

REF="${1:-HEAD}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

fail=0
while IFS= read -r f; do
  if ! git cat-file -e "$REF:$f" 2>/dev/null; then
    continue # new file — always allowed
  fi
  out=$(python3 - "$f" "$REF" <<'PYEOF'
import json, subprocess, sys
path, ref = sys.argv[1], sys.argv[2]
old = json.loads(subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True, check=True).stdout)
new = json.load(open(path))

def records(doc):
    if isinstance(doc, list):
        recs = doc
    else:
        recs = doc.get("records", doc.get("vectors", []))
    out = {}
    for i, r in enumerate(recs):
        key = r.get("name", f"<unnamed-{i}>") if isinstance(r, dict) else f"<scalar-{i}>"
        out[key] = json.dumps(r, sort_keys=True)
    return out

o, n = records(old), records(new)
problems = []
for k, v in o.items():
    if k not in n:
        problems.append(f"REMOVED record '{k}'")
    elif n[k] != v:
        problems.append(f"MUTATED record '{k}'")
for p in problems:
    print(p)
sys.exit(1 if problems else 0)
PYEOF
  ) || { echo "FROZEN-VECTOR VIOLATION in $f:"; echo "$out" | sed 's/^/  /'; fail=1; }
done < <(git ls-files '*/conformance/vectors/*.json')

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "Existing conformance records are frozen (append-only). If a record is genuinely wrong, that is a"
  echo "spec-level erratum: document it in release notes and bump the vector file's schema/version field"
  echo "rather than silently rewriting bytes. See CLAUDE.md 'Polyglot discipline' item 4."
  exit 1
fi
echo "vector freeze check OK (ref: $REF)"
