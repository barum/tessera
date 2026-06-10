# TSEAL-00040 — plugin keyfile: explicit, authenticated KDF block; fail-closed wrap

**Date:** 2026-06-10
**Scope:** `sec(...)` — security-relevant (passphrase-KDF selection for the key-on-disk wrap).
Remediation item TP-038 (P1) from the 2026-06-10 plan; also delivers TP-100 (plugin protocol
tests) early.
**Status:** released

## Summary

The reference plugin (`tessera-seal-plugin-file`) silently downgraded its passphrase KDF from
Argon2id to PBKDF2-HMAC-SHA-512 whenever `argon2-cffi` was not importable — without changing the
keyfile format identifier. Two keyfiles with identical headers could have different KDF strength,
and `unwrap` could not tell which KDF wrapped a given file (it re-ran the same environment-
dependent probe). The keyfile now carries an explicit, AEAD-authenticated 13-byte KDF block;
`wrap` fails closed without `argon2-cffi` unless the caller explicitly opts in; `unwrap` selects
the KDF from the file, never from the environment. A new pytest module pins the format and the
frame protocol.

## Wire / API changes

- **No envelope wire-format change.** The TesseraSeal envelope and all KAT vectors are untouched.
  The keyfile is plugin-protocol territory, explicitly outside the core wire spec.
- **Keyfile format (write):** still header line `tseal-key-v1.1`, but the base64url blob gains a
  trailing KDF block: `salt[16] || nonce[12] || pk[1568] || wrapped_sk[3168] || tag[16] ||
  kdf_id[1] || p0[4] || p1[4] || p2[4]` (big-endian).
  - `kdf_id 0x01` = Argon2id (`p0`=memory_kib, `p1`=time_cost, `p2`=parallelism)
  - `kdf_id 0x02` = PBKDF2-HMAC-SHA-512 (`p0`=iterations, `p1`=`p2`=0)
- **AAD binding:** the AES-256-GCM key-wrap AAD is now `header || kdf_block` for new files, so
  on-disk tampering with the KDF id/params fails the wrap tag. Legacy files keep their original
  AAD (`header` only).
- **Fail-closed wrap:** `_wrap_sk(..., allow_pbkdf2=False)` raises (and `keygen` exits non-zero)
  when `argon2-cffi` is missing, unless `allow_pbkdf2=True` / new CLI flag `--allow-pbkdf2` is
  passed. **No environment variable can enable the fallback.**
- **File-driven unwrap:** `_unwrap_sk` derives with exactly the KDF named in the file's KDF block.
  An Argon2id-wrapped file hard-fails when `argon2-cffi` is missing — never silently retried
  under PBKDF2.
- **Defensive parse caps:** forged KDF blocks are rejected at parse if they demand > 4 GiB
  Argon2id memory, > 1024 time_cost, > 64 lanes, or > 1e8 PBKDF2 iterations (resource-exhaustion
  guard), or carry an unknown `kdf_id`.
- **Backward compatibility:** legacy `tseal-key-v1` files and KDF-block-less `tseal-key-v1.1`
  files (distinguished by header + exact blob length) still unwrap via the legacy derive path
  (Argon2id preferred, warned PBKDF2 fallback — the pre-TSEAL-00040 behavior). New keys are
  always written with the KDF block.

## Code changes

- `tessera-seal/plugin/tessera_seal_plugin_file.py`: new `KdfParams` dataclass (encode/decode +
  validation caps), `_derive_argon2id` / `_derive_pbkdf2` / `_derive_kwrap_from_params` /
  `_derive_kwrap_legacy` split (the old probing `_derive_kwrap` is gone), `KeyFile.kdf` field +
  `KeyFile.aad()`, length-disambiguated v1.1 parse, fail-closed `_wrap_sk(allow_pbkdf2=...)`,
  `keygen --allow-pbkdf2` flag, updated module docstring.
- `tessera-seal/plugin/tessera-seal-plugin-protocol.md`: new "Keyfile KDF block (TSEAL-00040)"
  section documenting the layout, rules, caps, and back-compat.
- `tessera-seal/plugin/test_plugin_keyfile.py` (**new**, 30 tests): wrap/unwrap roundtrip under
  both KDFs, fail-closed wrap (incl. env-independence), file-driven KDF selection, Argon2id-file
  fail-closed unwrap, wrong passphrase, KDF tamper (param tweak → unwrap fail; id flip → parse
  reject), legacy v1 + v1.1 compat, truncated/extended blob rejection, forged-params rejection,
  embedded-pubkey URI path, and the frame protocol (roundtrip, clean EOF, truncated length
  prefix/body, zero-length, oversized declared length, oversized write, recipient URI parse
  failures). **This delivers TP-100 (plugin protocol tests) early.**

## Migration

- **Existing keyfiles:** no action required; they remain readable via the legacy path.
  Recommended: re-run `keygen` (with `argon2-cffi` installed) to produce a keyfile with the
  explicit KDF block.
- **Operators without `argon2-cffi`:** `keygen` now fails with a clear message. Either install
  `argon2-cffi` (recommended) or pass `--allow-pbkdf2` explicitly.
- **Older plugin builds** cannot parse new keyfiles (blob 13 bytes longer than they expect) —
  they fail loudly at parse, not silently with the wrong KDF.

## Test plan

- `cd tessera-seal/plugin && python3 -m pytest test_plugin_keyfile.py -v` → 30 passed (verified
  with and without `argon2-cffi`; without it, the 2 Argon2id-positive tests skip).
- `cd tessera-seal/python && python3 -m pytest test_tessera_seal.py -q` → 65 passed (unchanged).
- CLI smoke: `keygen --out f && pubkey --in f` → Argon2id KDF block embedded, URI printed.

## Rollback

Revert the two plugin files and delete the test module. Keyfiles written with the KDF block are
**not readable** by the reverted code (blob-length check fails loudly); re-wrap them with the old
code (`keygen` + same passphrase) before rolling back, or keep a forward-fixed plugin for reads.

## Security considerations

- Closes a silent-downgrade hole: KDF strength is now explicit in, and authenticated by, the
  file. No environment probe decides a security property anymore (wrap: explicit caller opt-in
  only; unwrap: file-driven only).
- Parse-time caps prevent a forged keyfile from driving memory/CPU exhaustion via attacker-chosen
  Argon2id/PBKDF2 cost parameters.
- The legacy read path intentionally preserves the old environment-dependent probe for old files
  only — deprecating it entirely would brick existing keyfiles; flagged for removal in a future
  keyfile format rev.

## Linked items

- TP-038 (remediation plan 2026-06-10), TP-100 (delivered early), TSEAL-00040.
