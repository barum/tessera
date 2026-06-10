# THASH-00008 — Python packaging (pyproject.toml) + installable `tessera-hash` CLI

**Date:** 2026-06-10
**Type:** feat
**Ticket:** THASH-00008 (remediation plan TP-070/TP-077 wave; sibling notes: TID-00022, TSEAL-00046)

## Summary

`tessera-hash/python/` is now an installable distribution: `pip install -e tessera-hash/python` produces the
`tessera-hash` console command and installs the library modules (`tessera_hash`, `tessera_hash_cli`) with a
`py.typed` marker. A from-checkout launcher keeps `python3 tessera-hash/python/cli.py` working without any
install. Distribution posture is **publish-ready, not published** — PyPI publication stays gated on the
name-clearance decision ([docs/decisions/2026-06-10-name-clearance.md](../../../docs/decisions/2026-06-10-name-clearance.md)).

## Wire/API changes

**Wire format: none.** No change to the 73-byte layout, SHAKE-256 tail, encodings, or variant handling.

New files (no existing module was modified by the packaging itself):

- `python/pyproject.toml` — setuptools backend; `name = "tessera-hash"`, `version = "1.3.1"`,
  `requires-python = ">=3.9"`, `license = "Apache-2.0"`, zero runtime dependencies (SHAKE-256 from stdlib
  `hashlib`). Flat `py-modules = ["tessera_hash", "tessera_hash_cli"]` — deliberately NOT restructured into a
  package directory. Console script: `tessera-hash = "tessera_hash_cli:main"`.
- `python/tessera_hash_cli.py` — CLI implementation (argparse; Python 3.9+). Subcommands, all verified against
  a fresh editable install:
  - `tessera-hash hash (FILE | --stdin)` — 73-byte TesseraHash over the content; prints the canonical 98-char
    Base64URL form (fresh provenance header; tail is a pure function of content).
  - `tessera-hash verify HASH (FILE | --stdin)` — tail check only; prints `OK` and exits 0 on match, exits 1 on
    mismatch or invalid input. HASH is Base64URL (98) or Crockford (117), auto-detected.
  - `tessera-hash decode STRING` — prints fields plus both text encodings; non-canonical pad bits, bad length,
    or variant != `0x03` exit 1.
  - Exit status: 0 success, 1 invalid input or verification failure, 2 usage error.
- `python/cli.py` — from-checkout shim (`python3 tessera-hash/python/cli.py ...`). Intentionally NOT installed:
  all three sibling projects ship a `cli.py`, so the installed module name must be unique per project
  (`tessera_hash_cli`) for the three distributions to coexist in one environment.
- `python/py.typed` — PEP 561 marker.

## Migration guidance

- No action required for existing `PYTHONPATH`-style consumers; module import paths are unchanged.
- New supported install: `pip install -e tessera-hash/python` (the `tessera-hash` command appears on `PATH`).
- All three sibling distributions (`tessera-id`, `tessera-hash`, `tessera-seal`) install cleanly into one venv.
- Do NOT publish to PyPI yet — see the distribution-posture decision record.

## Test plan

Verified 2026-06-10 in a fresh venv (`python3 -m venv` + editable install of all three projects):

```bash
pip install -e tessera-hash/python
printf 'hello' | tessera-hash hash --stdin           # 98-char Base64URL printed
tessera-hash hash /path/to/file                       # file form
tessera-hash verify "$(tessera-hash hash f)" f        # prints OK, exit 0
tessera-hash decode "$(tessera-hash hash f)"          # fields + both encodings
python3 tessera-hash/python/cli.py hash --stdin < f   # from-checkout form, no install
python3 -m pytest tessera-hash/python/test_tessera_hash.py   # suite unchanged, green
```

## Rollback

Delete `python/pyproject.toml`, `python/tessera_hash_cli.py`, `python/cli.py`, `python/py.typed` and
`pip uninstall tessera-hash`. No schema, no migrations, no library-code changes — rollback is file removal only.
