# TSEAL-00039 — CLI `keygen` rejects unsupported `--suite` values (was: silently ignored)

**Date:** 2026-06-10
**Scope:** `sec(TSEAL-00039)` — security-relevant. Fixes a silent security-posture
downgrade in the Python reference CLI. Remediation item TP-071 (P0) in
`docs/remediation-plan-2026-06-10.md`.
**Status:** released

## Summary

`tessera-seal keygen --suite 0x06` parsed the flag but never forwarded it: `cmd_keygen`
delegated to the reference keyfile plugin, whose keygen path has no `--suite` parameter
and always calls `tessera_seal.generate_keypair()` with the default suite `0x01`.
A user following the module docstring's "Generate a hybrid keypair" example received a
**pure ML-KEM-1024 key while believing they had X25519 defense-in-depth** — a silent
security downgrade. `keygen` now hard-errors (exit 2, message on stderr) on any
`--suite` value the keyfile plugin cannot honor — everything except `0x01` — and the
docstring example is corrected to show `0x01`-only with a "hybrid keyfiles are planned
for v1.4 (TSEAL-00030..34)" note.

## Wire / API changes

- **No wire-format change.** Envelope bytes, keyfile format (`.tseal-key-v1.1`), KDF
  labels, and all conformance vectors are untouched. Python library API
  (`tessera_seal.py`) is untouched.
- **CLI behavior change (Python CLI only, `tessera-seal/python/cli.py`):**
  - `keygen --suite 0x06` (and `0x02`, and any alias such as `hybrid`/`chacha`):
    previously exit 0 with a **suite-`0x01` keyfile written anyway**; now exit `2`,
    nothing written, stderr message:
    `tessera-seal keygen: --suite 0x06 (hybrid X25519+ML-KEM-1024 + AES-256-GCM) is
    not supported: hybrid keyfiles land in v1.4 (TSEAL-00030..34); keygen currently
    supports --suite 0x01 only`
  - `keygen --suite 0x01` (explicit) and `keygen` with no flag: unchanged — delegate
    to the reference plugin and write a suite-`0x01` v1.1 keyfile, exit 0.
  - Unknown suite strings (e.g. `--suite 0x09`): unchanged — `_parse_suite` exits
    nonzero with `unknown suite`, as before.
- All other subcommands (`pubkey`, `encrypt`, `decrypt`, `info`) are behaviorally
  identical.

## Code changes

- `tessera-seal/python/cli.py`:
  - `cmd_keygen` (now lines 110–128): parses `args.suite` via `_parse_suite` and
    returns exit code `2` with a stderr message for any suite other than
    `SUITE_MLKEM1024_AESGCM` (0x01), with a comment explaining the plugin keygen
    path's 0x01-only support; the 0x01 path still delegates to
    `tessera_seal_plugin_file.py keygen` unchanged.
  - Module docstring synopsis (lines 7–11) no longer advertises "(or hybrid)"
    keygen; example block (lines 30–33) replaces the false
    `keygen --out alice.tseal-key --suite 0x06` hybrid example with a `0x01`
    example plus a planned-v1.4 note.
  - `keygen --suite` argparse help text (lines 319–323) now reads "only 0x01 is
    supported today (hybrid keyfiles land in v1.4, TSEAL-00030..34)" instead of
    listing 0x02/0x06 as if accepted.
- `tessera-seal/plugin/tessera_seal_plugin_file.py`: **unchanged** (read-only
  confirmation that its keygen path supports suite 0x01 only).

## Migration

- Scripts that ran `keygen --suite 0x02` or `--suite 0x06` were *already* getting
  suite-`0x01` keyfiles; they will now fail fast with exit 2 instead of succeeding
  misleadingly. Drop the flag (or pass `--suite 0x01`) to keep the previous actual
  behavior. There is no keyfile migration: every keyfile ever produced by `keygen`
  was suite `0x01`.
- Hybrid (`0x06`) keyfile generation lands with the v1.4 hybrid plugin work
  (TSEAL-00030..34); until then use the in-process Python API
  (`tessera_seal.generate_keypair(suite=SUITE_HYBRID_X25519_MLKEM1024_AESGCM)`) and
  your own key custody if you need hybrid keys.

## Test plan

Executed 2026-06-10 in a temp dir with `TESSERA_SEAL_PASSPHRASE` set:

- `keygen --out k --suite 0x06` → exit 2, stderr message above, no file written. PASS
- `keygen --out k --suite 0x02` → exit 2, analogous message, no file written. PASS
- `keygen --out k --suite 0x09` → exit 1 (`unknown suite '0x09'`, pre-existing path). PASS
- `keygen --out alice.tseal-key --suite 0x01` → exit 0, v1.1 keyfile written. PASS
- `keygen --out bob.tseal-key` (no flag) → exit 0, v1.1 keyfile written. PASS
- Roundtrip with the generated key: `pubkey` → `encrypt --ad tp071` (1669-byte
  suite-0x01 envelope) → `decrypt --ad tp071` → plaintext recovered byte-identical;
  `info` shows variant 0x04 / suite 0x01 / kem_ct_len 1568. PASS
- `python3 -m pytest test_tessera_seal.py -q` → **65 passed** (library untouched).
- `python3 -m py_compile cli.py` → OK.

## Rollback

Revert the single-file change to `tessera-seal/python/cli.py` (`git revert` of this
commit). No wire, keyfile, vector, schema, or dependency impact — but rolling back
**reintroduces the silent downgrade** (keygen will again ignore `--suite` and write a
pure ML-KEM key for hybrid requests), so rollback should be paired with removing the
flag from the keygen parser entirely.

## Security considerations

- Failure mode fixed: a user requesting hybrid (X25519 + ML-KEM-1024) key material
  silently received pure-ML-KEM material; under a future Module-LWE break their
  expected classical fallback would not exist. The CLI now fails closed: any
  security-relevant flag it cannot honor is a hard error, never silently ignored.
- No change to randomness sources, KDF labels (frozen `pqcrypt v1 ...` tags
  untouched), AEAD/commit construction, decrypt error classes, or timing posture.

## Linked items

- TP-071 (remediation plan 2026-06-10, P0/sec, cli-reject-unsupported-suite-flag)
- TSEAL-00030..34 — v1.4 hybrid ports (C/C++/TS/Java/CPython ext) incl. hybrid
  keyfile/plugin support
- TSEAL-00022 — original CLI
