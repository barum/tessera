# 2026-06-13 — TSEAL-00030 — Hybrid suite 0x06 (X25519 + ML-KEM-1024) C port

**Type:** `sec(TSEAL-00030)` — adds a hybrid KEM construction to the canonical C reference.
**Scope:** `tessera-seal/c/` (library + tests), the C conformance runner, `hybrid_supported()`,
whitepaper §1/§5b/§12/§14, root + project `CLAUDE.md`. **No wire-format change** — suite `0x06`
is an already-allocated suite byte; this port makes the C reference *produce and consume* it
byte-identically to Python/Rust/Go rather than rejecting it.

## Summary

The hybrid suite `0x06` (X25519 + ML-KEM-1024 + AES-256-GCM + UtC commit, X-Wing-style combiner)
was a 3-way contract (Python ↔ Rust ↔ Go). This change ports it to the canonical **C** reference,
making it a **4-way byte-identical KAT contract**. The C port uses **OpenSSL 3.5+
`EVP_PKEY_X25519`** for the X25519 half — the same pinned OpenSSL that already supplies ML-KEM-1024,
so **no new dependency**. C's conformance PASS count rises **288 → 297** (+9: the three
`hybrid_*.json` files), verified by the cross-language harness consuming Python-generated hybrid
envelopes byte-for-byte.

This was the highest-leverage item on the v1.4 hybrid backlog: it completes the EU-regulator /
BSI-TR-02102 / ANSSI hybrid story for the canonical ABI and retires the "hybrid is really 3-of-8"
gap for the one non-hybrid language that already had a tessera-seal runner.

## Wire/API changes

- **No wire change.** Suite `0x06` envelopes are unchanged; C now interoperates with them.
- **New C ABI surface (additive — the v1.0/v1.1 non-hybrid ABI is byte-for-byte unchanged):**
  - `tessera_seal_pub_hybrid_t { uint8_t suite; uint8_t pk[1600]; }`,
    `tessera_seal_priv_hybrid_t { uint8_t suite; uint8_t sk[3200]; }` — **separate** structs (the
    existing `tessera_seal_pub_t`/`tessera_seal_priv_t` are untouched, preserving the fixed-size
    non-hybrid ABI).
  - `tessera_seal_generate_keypair_hybrid()`, `tessera_seal_generate_keypair_hybrid_from_seed(seed[96])`
    (64-byte ML-KEM seed `d‖z` via `OSSL_PKEY_PARAM_ML_KEM_SEED` + 32-byte X25519 scalar),
    `tessera_seal_encrypt_hybrid()`, `tessera_seal_decrypt_hybrid()`, `tessera_seal_zeroize_priv_hybrid()`,
    `tessera_seal_encrypt_hybrid_output_size()`.
  - Hybrid layout: pk = `ml_kem_pk(1568) ‖ x25519_pk(32)`; sk = `ml_kem_sk(3168) ‖ x25519_scalar(32)`;
    wire KEM_CT = `ml_kem_ct(1568) ‖ x25519_eph_pk(32)` (1600).
  - Combiner (frozen v1 wire tag, verbatim):
    `K_session = SHAKE-256("pqcrypt v1 hybrid combiner" ‖ ss_mlkem ‖ x_ss ‖ ml_kem_ct ‖ x_eph_pk, 32)`.
- **`tessera_seal_peek_header` is now suite-aware:** it accepts `0x06` as a known suite and requires
  `KEM_CT_LEN == 1600` for it (1568 for `0x01`/`0x02`), preserving the TSEAL-00049 exact-size pin
  per suite. Non-hybrid `tessera_seal_decrypt` still rejects a `0x06` header (`priv.suite` 0x01/0x02
  ≠ 0x06 → `BAD_KEY`).
- `hybrid_supported()` in `tools/conformance/run.sh` flips `c` to supported.

## Security considerations

- **All hybrid invariants preserved** and proven by the 9 green hybrid KATs (byte-identity with the
  Python reference): the X-Wing combiner order/label, the suite/key consistency checks
  (`pub.suite == 0x06` on encrypt; `priv.suite == header.suite` on decrypt, else `BAD_KEY`), the
  single `TESSERA_SEAL_E_DECRYPT_FAILED` for every auth-class failure, the synthetic-key timing pad
  on the decrypt failure path, the deterministic HKDF nonce (fresh `K_session` per envelope from a
  fresh ML-KEM Encaps + fresh X25519 ephemeral), and the 32-byte UtC commitment.
- **CSPRNG-only:** the X25519 ephemeral and keygen scalar use OpenSSL's OS-seeded DRBG
  (`RAND_bytes`), the same CSPRNG ML-KEM EVP uses internally. No userspace PRNG.
- **Supply chain:** X25519 = OpenSSL 3.5+ `EVP_PKEY_X25519` — no new dependency (same OpenSSL as
  ML-KEM). No "Kyber"/"Curve25519"/"ECDH" tokens in the public surface.
- All combiner-intermediate secrets are `OPENSSL_cleanse`d before free.

## Test plan (executed 2026-06-13, macOS arm64, OpenSSL 3.6.2)

| Check | Command | Result |
|-------|---------|--------|
| Cross-language gate | `TESSERA_CONFORMANCE_SKIP="cpython java cpp typescript" bash tools/conformance/run.sh` | **c 297 / 0 / 6** (288 std + 9 hybrid); python/go/rust 297; ALL GREEN |
| C unit tests | `cd tessera-seal/c && make test` | **41 pass, 0 fail** (was 32; +9 hybrid incl. roundtrip, KEM_CT_LEN==1600, AD-binding negative, X25519-half tamper → DECRYPT_FAILED, from-seed determinism, `kat_hybrid_decrypt_json`) |
| Vector freeze | `bash tools/scripts/check-vector-freeze.sh` | **OK** (no vector modified) |
| Whitepaper | `cd tessera-seal/latex && make` | 30 pages; §1/§5b/§12/§14 hybrid claims render |

## Migration guidance

None for existing callers. C consumers that need hybrid now have the `*_hybrid` entry points; the
non-hybrid API is unchanged. The reference plugin keyfile (`.tseal-key-v1.1`) still wraps non-hybrid
ML-KEM keys only — hybrid keyfile support remains separate plugin work.

## Rollback

Revert this commit: the hybrid C entry points and structs are additive; `peek_header` reverts to
rejecting `0x06`; `hybrid_supported()` reverts `c`; C's count returns to 288. No wire/vector state
to unwind (no vector was added or changed). Python/Rust/Go hybrid is unaffected.

## Linked items

- Backlog TSEAL-00030 (was "v1.4 hybrid C port"), unblocked by TESS-00006 (OpenSSL 3.5+ in CI/builds)
  and the OpenSSL EVP X25519 availability noted in the strategic backlog.
- Reference shape: `2026-05-21-pqcrypt-00028-hybrid-rust.md`, `2026-05-21-pqcrypt-00029-hybrid-go.md`.
- Remaining hybrid ports (C++/TS/Java/CPython, TSEAL-00031/32/33/34) each require their language to
  first gain a tessera-seal conformance runner.
