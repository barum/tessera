# TID-00022 — Python packaging (pyproject.toml) + installable `tessera-id` CLI

**Date:** 2026-06-10
**Type:** feat
**Ticket:** TID-00022 (remediation plan TP-070/TP-077 wave; sibling notes: THASH-00008, TSEAL-00046)

## Summary

`tessera-id/python/` is now an installable distribution: `pip install -e tessera-id/python` produces the
`tessera-id` console command and installs the library modules (`tessera_id`, `tessera_id_fast`,
`tessera_id_cli`) with a `py.typed` marker. A from-checkout launcher keeps `python3 tessera-id/python/cli.py`
working without any install. Distribution posture is **publish-ready, not published** — PyPI publication stays
gated on the name-clearance decision ([docs/decisions/2026-06-10-name-clearance.md](../../../docs/decisions/2026-06-10-name-clearance.md)).

## Wire/API changes

**Wire format: none.** No change to the 41-byte layout, encodings, variants, or generator semantics.

New files (no existing module was modified by the packaging itself):

- `python/pyproject.toml` — setuptools backend; `name = "tessera-id"`, `version = "1.3.1"`,
  `requires-python = ">=3.9"`, `license = "Apache-2.0"`, zero runtime dependencies. Flat
  `py-modules = ["tessera_id", "tessera_id_fast", "tessera_id_cli"]` — deliberately NOT restructured into a
  package directory. Console script: `tessera-id = "tessera_id_cli:main"`.
- `python/tessera_id_cli.py` — CLI implementation (argparse; Python 3.9+). Subcommands, all verified against a
  fresh editable install:
  - `tessera-id new` — Standard (variant `0x01`) ID, prints the canonical 55-char Base64URL form.
  - `tessera-id new-hlc` — HLC (variant `0x02`) ID.
  - `tessera-id decode STRING` — Base64URL (55) or Crockford (66) auto-detected by length; prints fields plus
    both encodings and hex; invalid input (bad length/chars, non-canonical pad bits, unknown variant) exits 1.
  - `tessera-id encode (--b32 | --b64) HEX` — 82 hex chars → chosen text form; unknown variants are refused.
  - Exit status: 0 success, 1 invalid input, 2 usage error.
- `python/cli.py` — from-checkout shim (`python3 tessera-id/python/cli.py ...`). Intentionally NOT installed:
  all three sibling projects ship a `cli.py`, so the installed module name must be unique per project
  (`tessera_id_cli`) for the three distributions to coexist in one environment.
- `python/py.typed` — PEP 561 marker.

## Migration guidance

- No action required for existing `PYTHONPATH`-style consumers; module import paths are unchanged.
- New supported install: `pip install -e tessera-id/python` (the `tessera-id` command appears on `PATH`).
- All three sibling distributions (`tessera-id`, `tessera-hash`, `tessera-seal`) install cleanly into one venv.
- Do NOT publish to PyPI yet — see the distribution-posture decision record.

## Test plan

Verified 2026-06-10 in a fresh venv (`python3 -m venv` + editable install of all three projects):

```bash
pip install -e tessera-id/python
tessera-id new                      # 55-char Base64URL printed
tessera-id new-hlc                  # 55-char Base64URL printed
tessera-id decode "$(tessera-id new)"   # fields + both encodings + hex
tessera-id encode --b32 <82-hex>    # 66-char Crockford printed
python3 tessera-id/python/cli.py new   # from-checkout form, no install
python3 -m pytest tessera-id/python/test_tessera_id.py   # suite unchanged, green
```

## Rollback

Delete `python/pyproject.toml`, `python/tessera_id_cli.py`, `python/cli.py`, `python/py.typed` and
`pip uninstall tessera-id`. No schema, no migrations, no library-code changes — rollback is file removal only.
