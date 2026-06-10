# TSEAL-00046 — Python packaging (pyproject.toml) + installable `tessera-seal` CLI

**Date:** 2026-06-10
**Type:** feat
**Ticket:** TSEAL-00046 (remediation plan TP-070; sibling notes: TID-00022, THASH-00008)

## Summary

`tessera-seal/python/` is now an installable distribution: `pip install -e tessera-seal/python` produces the
`tessera-seal` console command and installs the library modules (`tessera_seal`, `tessera_seal_cli`) with a
`py.typed` marker. This fixes the TP-070 finding that the only documented invocation
(`python -m tessera_seal.cli`) could never work — `tessera-seal/python/` is a flat module, not a package, and
previously had no `pyproject.toml`. The documented commands now match the implemented flags exactly
(`pubkey --in`, `encrypt --recipient URI` — the old README showed nonexistent `pubkey --keyfile` /
`encrypt --pubkey` flags). Distribution posture is **publish-ready, not published** — PyPI publication stays
gated on the name-clearance decision ([docs/decisions/2026-06-10-name-clearance.md](../../../docs/decisions/2026-06-10-name-clearance.md)).

## Wire/API changes

**Wire format: none.** No change to the envelope, suites, KDF labels, or `tessera_seal.py` library semantics.

- `python/pyproject.toml` (new) — setuptools backend; `name = "tessera-seal"`, `version = "1.3.1"`,
  `requires-python = ">=3.9"`, `license = "Apache-2.0"`. Flat
  `py-modules = ["tessera_seal", "tessera_seal_cli"]` — deliberately NOT restructured into a package directory.
  Console script: `tessera-seal = "tessera_seal_cli:main"`. Dependencies mirror `requirements.txt` verbatim
  (security-reviewed floors): `cryptography>=46.0.0`, `kyber-py>=1.0.0`, `pycryptodome>=3.20.0` (conformance
  DRBG only), `argon2-cffi>=23.1.0` (required by the keygen/decrypt key-custody path — the file plugin fails
  closed without it per TSEAL-00040; the `tessera_seal` library module itself never imports it).
- `python/tessera_seal_cli.py` (new) — the CLI implementation, moved out of `cli.py` so the installed module
  name is unique across the three sibling projects. Subcommands (synopsis == argparse definitions; all verified
  against a fresh editable install):
  - `tessera-seal keygen --out FILE [--suite 0x01]` — v1.1 keyfile via the file plugin; prompts for a
    passphrase (`TESSERA_SEAL_PASSPHRASE` env var for non-interactive use). Only `--suite 0x01` is honored;
    any other value exits 2 (TSEAL-00039 — no silently-ignored security flags).
  - `tessera-seal pubkey --in FILE` — prints the `tseal1file1<base64url>` recipient URI.
  - `tessera-seal encrypt --recipient URI [--ad AD] [--in FILE] [--out FILE] [--suite 0x01|0x02]` — stdin→stdout
    when `--in`/`--out` omitted; a hybrid recipient URI forces suite `0x06`; `--suite 0x06` with a non-hybrid
    recipient is rejected.
  - `tessera-seal decrypt --keyfile FILE [--ad AD] [--in FILE] [--out FILE]` — key custody via the plugin
    protocol subprocess (`tessera_seal_plugin_file.py serve`); the long-term sk never enters the CLI process.
  - `tessera-seal info [--in FILE]` — prints header fields (variant, suite, timestamp_ms, counter, kem_ct_len,
    ad_len, envelope_len); no key needed.
- `python/cli.py` (changed: implementation → shim) — from-checkout launcher
  (`python3 tessera-seal/python/cli.py ...`); intentionally NOT installed.
- `python/py.typed` (new) — PEP 561 marker.

The CLI buffers whole files in memory; large-payload guidance lives in the new
[docs/chunking-recipe.md](../chunking-recipe.md) (TESS-00012 docs wave).

## Migration guidance

- Replace any `python -m tessera_seal.cli ...` invocation (it never worked) with either
  `tessera-seal ...` (after `pip install -e tessera-seal/python`) or `python3 tessera-seal/python/cli.py ...`.
- Flag fixes: `pubkey --keyfile FILE` → `pubkey --in FILE`; `encrypt --pubkey FILE` →
  `encrypt --recipient URI` (the URI printed by `pubkey`).
- Library consumers via `PYTHONPATH` are unaffected; `import tessera_seal` is unchanged.
- Do NOT publish to PyPI yet — see the distribution-posture decision record.

## Security considerations

- No crypto-path changes; the CLI continues to delegate key custody to the plugin subprocess.
- `argon2-cffi` is now a declared install dependency, preserving the TSEAL-00040 fail-closed KDF posture for
  every `pip install` consumer (no silent PBKDF2 downgrade environment).
- `keygen` rejects unsupported `--suite` values with a nonzero exit (TSEAL-00039) — verified in the fresh venv.

## Test plan

Verified 2026-06-10 in a fresh venv (`python3 -m venv` + editable install of all three projects):

```bash
pip install -e tessera-seal/python
export TESSERA_SEAL_PASSPHRASE=...           # non-interactive keygen/decrypt
tessera-seal keygen  --out alice.tseal-key-v1.1
tessera-seal pubkey  --in alice.tseal-key-v1.1 > alice.uri
tessera-seal encrypt --recipient "$(cat alice.uri)" --in secret.bin --out secret.tseal
tessera-seal info    --in secret.tseal
tessera-seal decrypt --keyfile alice.tseal-key-v1.1 --in secret.tseal --out secret.out
cmp secret.bin secret.out                     # byte-identical round trip
echo hi | tessera-seal encrypt --recipient "$(cat alice.uri)" | tessera-seal decrypt --keyfile alice.tseal-key-v1.1
tessera-seal keygen --suite 0x06 --out h.key  # exits 2 with the v1.4 explanation
python3 tessera-seal/python/cli.py info --in secret.tseal   # from-checkout form
python3 -m pytest tessera-seal/python/test_tessera_seal.py  # suite unchanged, green
```

## Rollback

Delete `python/pyproject.toml`, `python/tessera_seal_cli.py`, `python/py.typed`, restore `python/cli.py` to its
pre-TSEAL-00046 single-file form (`git checkout` of the previous revision), and `pip uninstall tessera-seal`.
No schema, no migrations, no library-code changes.
