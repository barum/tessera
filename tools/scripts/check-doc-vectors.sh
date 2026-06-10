#!/usr/bin/env bash
# check-doc-vectors.sh — verify that every example TesseraID string published in
# the TesseraID documentation decodes against the Python reference.
#
# Scans:
#   tessera-id/latex/sec*.tex      (LaTeX whitepaper sources, incl. Appendix A/C)
#   tessera-id/docs/wp_*.js        (non-normative DOCX pipeline sources)
#
# Rules enforced (TID-00021 / TP-047):
#   * every 55-char Base64URL token must decode via tessera_id.decode_b64()
#   * every 66-char Crockford token must decode via tessera_id.decode_b32()
#   * any other identifier-like run of >= 40 chars (not pure hex, not pure
#     punctuation) is flagged as a suspicious near-ID — fabricated examples of
#     the wrong length become structurally impossible to publish.
#
# Exit status: 0 when every example decodes, 1 on any failure.
# Not wired into CI yet (manual / pre-commit use).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PYTHON_BIN="${PYTHON_BIN:-python3}"

exec "${PYTHON_BIN}" - "${REPO_ROOT}" <<'PYEOF'
import glob
import os
import re
import sys

repo_root = sys.argv[1]
sys.path.insert(0, os.path.join(repo_root, "tessera-id", "python"))

import tessera_id  # noqa: E402  (the readable canonical reference)

SCAN_GLOBS = [
    os.path.join(repo_root, "tessera-id", "latex", "sec*.tex"),
    os.path.join(repo_root, "tessera-id", "docs", "wp_*.js"),
]

# Maximal runs of the Base64URL alphabet (a superset of the uppercase Crockford
# alphabet), with boundaries so substrings of longer runs never match.
TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{40,}(?![A-Za-z0-9_\-])")
CROCKFORD_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{66}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
PUNCT_RE = re.compile(r"^[-_]+$")

checked = 0
failures = []

for pattern in SCAN_GLOBS:
    for path in sorted(glob.glob(pattern)):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        # LaTeX escapes underscores inside \code{...}; normalize before matching.
        if path.endswith(".tex"):
            text = text.replace(r"\_", "_")
        rel = os.path.relpath(path, repo_root)
        for m in TOKEN_RE.finditer(text):
            tok = m.group(0)
            line = text.count("\n", 0, m.start()) + 1
            where = f"{rel}:{line}"
            if PUNCT_RE.match(tok):
                continue  # ASCII-art rules/separators
            if HEX_RE.match(tok):
                continue  # raw hex dumps of binary forms (verified via encodings)
            if len(tok) == 55:
                checked += 1
                try:
                    raw = tessera_id.decode_b64(tok)
                    assert len(raw) == tessera_id.TESSERA_ID_SIZE_BYTES
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"{where}: Base64URL example does not decode: {tok!r} ({exc})")
            elif len(tok) == 66 and CROCKFORD_RE.match(tok):
                checked += 1
                try:
                    raw = tessera_id.decode_b32(tok)
                    assert len(raw) == tessera_id.TESSERA_ID_SIZE_BYTES
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"{where}: Crockford example does not decode: {tok!r} ({exc})")
            else:
                failures.append(
                    f"{where}: suspicious near-ID string of length {len(tok)} "
                    f"(valid examples are 55-char Base64URL or 66-char Crockford): {tok!r}"
                )

print(f"check-doc-vectors: {checked} example string(s) checked across TesseraID docs")
if failures:
    for f in failures:
        print(f"FAIL {f}", file=sys.stderr)
    print(f"check-doc-vectors: {len(failures)} failure(s)", file=sys.stderr)
    sys.exit(1)
print("check-doc-vectors: all example strings decode against the Python reference")
PYEOF
