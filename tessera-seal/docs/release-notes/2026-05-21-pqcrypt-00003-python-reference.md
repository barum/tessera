# PQCK-00003 — PQCrypt Python reference + conformance vectors

**Date:** 2026-05-21
**Ticket:** PQCK-00003
**Type:** feat

## Summary

Ship the **readable canonical Python reference** for PQCrypt v1, the test suite that pins observable behaviour for every language port, the micro-bench (with first measurements on Apple M3 Max), and the deterministic conformance vector generator. The KAT vectors produced by this PR are the source-of-truth artifacts that Go, Rust, and C ports (PQCK-00006, 00007, 00005) will be tested against.

## Wire/API changes

This is the first running implementation of PQCrypt v1. The Python module surface is now the binding contract for downstream language ports:

### Module surface (`pqcrypt/python/pqcrypt.py`)

```python
# Constants
VARIANT_PQCRYPT = 0x04
SUITE_MLKEM1024_AESGCM = 0x01     # mandatory
SUITE_MLKEM1024_CHACHA = 0x02     # optional
HEADER_BYTES = 16
MLKEM1024_PK_BYTES = 1568
MLKEM1024_SK_BYTES = 3168
MLKEM1024_CT_BYTES = 1568
AEAD_NONCE_BYTES = 12
AEAD_TAG_BYTES = 16
COMMIT_BYTES = 32
MAX_KEM_CT_LEN = 4096
MAX_AD_LEN = 65_536
MAX_PLAINTEXT = 4 * 1024 * 1024 * 1024

# Errors
class PQCryptError(Exception): ...
class UnknownVariant(PQCryptError): ...
class UnknownSuite(PQCryptError): ...
class InvalidLength(PQCryptError): ...
class DecryptionError(PQCryptError): ...   # one class for ALL auth-class failures

# Keys
class PublicKey:  ...   # 1568-byte ML-KEM-1024 encapsulation key
class PrivateKey: ...   # 3168-byte ML-KEM-1024 decapsulation key

def generate_keypair(suite=SUITE_MLKEM1024_AESGCM) -> (PrivateKey, PublicKey)

# Encrypt / decrypt
def encrypt(plaintext, recipient_pub, *, suite=SUITE_MLKEM1024_AESGCM,
            associated_data=b"", sender_counter=None) -> bytes
def decrypt(envelope, recipient_priv, *, expected_ad) -> bytes

# Helpers
def peek_header(envelope) -> DecodedHeader      # structural, NOT auth
def validate(envelope) -> bool                  # structural, NOT auth
def validate_min_timestamp(envelope, min_ms) -> bool
def set_now_ms_for_testing(value)               # KAT-vector determinism only

# Sender context (internally locked, parallels PQID HLCGenerator)
class SenderContext: ...
```

### Wire-format invariants enforced by the reference

- 16-byte header `TS(6)‖VAR(1)=0x04‖SUITE(1)‖CTR(2)‖KEM_CT_LEN(2)‖AD_LEN(4)`, big-endian.
- Body order: `KEM_CT ‖ AD ‖ AEAD_NONCE(12) ‖ AEAD_CT ‖ AEAD_TAG(16) ‖ COMMIT(32)`.
- Deterministic AEAD nonce = `HKDF-SHA3-256-Expand(prk, "pqcrypt v1 aead n", 12)`.
- UtC commit = `HMAC-SHA3-256(K_commit, header ‖ KEM_CT ‖ AD ‖ AEAD_CT)` over a separately-derived `K_commit`.
- AEAD AAD = `header ‖ KEM_CT ‖ AD` (binds the entire envelope structure into the AEAD tag).
- The wire nonce is verified against the deterministic derivation on decrypt: a flip of any nonce byte ⇒ `DecryptionError`.
- Single `DecryptionError` for all authentication-class failures; structural errors (`UnknownVariant`, `UnknownSuite`, `InvalidLength`) are distinct because they don't leak per-bit secrets.
- Cross-suite key reuse is permitted (a keypair generated under suite 0x01 also works under 0x02 because the KEM is suite-independent).

### Files added

| File | Purpose |
|------|---------|
| `pqcrypt/python/pqcrypt.py` | 466 lines, readable canonical reference |
| `pqcrypt/python/test_pqcrypt.py` | 56-test suite covering all invariants |
| `pqcrypt/python/bench.py` | Micro-bench mirroring pqid/python/bench.py output format |
| `pqcrypt/python/requirements.txt` | `cryptography ≥ 46`, `kyber-py ≥ 1.0`, `pycryptodome ≥ 3.20` (deterministic DRBG) |
| `pqcrypt/conformance/scripts/generate.py` | KAT vector generator. Deterministic via `kyber-py.set_drbg_seed(48-byte seed)` and frozen clock. |
| `pqcrypt/conformance/vectors/decrypt.json` | 7 records — known envelopes → known plaintexts (both suites, various AD sizes) |
| `pqcrypt/conformance/vectors/peek_header.json` | 4 records — header parsing with deterministic 16-byte header bytes |
| `pqcrypt/conformance/vectors/invalid.json` | 25 records — variant byte rejection (9 cases), suite byte rejection (7 cases), truncation (3 cases), tamper detection (6 critical-position flips) |
| `pqcrypt/conformance/vectors/ad_binding.json` | 6 records — PQID-as-AD positive (2), cross-substitution negative (2), 1-bit flip (1), wrong-length AD (1) |
| `pqcrypt/conformance/vectors/commitment.json` | 3 records — UtC commit-tag KATs independent of AEAD |
| `pqcrypt/conformance/vectors/min_timestamp.json` | 4 records — `validate_min_timestamp` parity with pqid/pqhash |
| `pqcrypt/benchmarks/python.txt` | First reference numbers (Apple M3 Max, kyber-py 1.0 pure-Python) |

## Migration guidance

Not applicable — first running version. Downstream consumers (Go/Rust/C ports in PQCK-00005/00006/00007) MUST:

1. Vendor the documented ML-KEM-1024 library (per `pqcrypt/CLAUDE.md`).
2. Implement the wire format described in the whitepaper (`pqcrypt/latex/PQCrypt_Whitepaper.pdf`).
3. Verify byte-identical decryption of every record in `pqcrypt/conformance/vectors/*.json`.

The vectors are deterministic: re-running `python3 pqcrypt/conformance/scripts/generate.py` MUST produce byte-identical JSON files (validated in this PR). If a future change produces different vectors, that is a spec change and requires a release-notes entry.

## Test plan

```bash
cd pqcrypt/python
pip install -r requirements.txt
python3 -m pytest test_pqcrypt.py -v
```

**Result: 56/56 pass in 0.45s** (Apple M3 Max, Python 3.14.3).

Coverage by test class:

| Class | # tests | Asserts |
|-------|---------|---------|
| `TestConstants` | 5 | Wire constants match whitepaper §3 |
| `TestRoundTrip` | 8 | empty/short/1KB/64KB × {AES-GCM, ChaCha} |
| `TestEnvelopeStructure` | 4 | Header layout, length formula, validate() |
| `TestVariantRejection` | 10 | Bytes 0x00, 0x01, 0x02, 0x03, 0x05, 0x10, 0x7F, 0x80, 0xFE, 0xFF all rejected |
| `TestSuiteRejection` | 7 | Suites 0x00, 0x03, 0x04, 0x10, 0x7F, 0xFE, 0xFF all rejected |
| `TestADBinding` | 4 | Positive, 1-bit flip, empty, wrong-length |
| `TestTamper` | 6 | KEM_CT, AEAD_CT, AEAD_TAG, COMMIT, nonce, every header byte |
| `TestLengthLimits` | 3 | Header-truncate, body-truncate, oversized AD |
| `TestDeterminism` | 1 | Same (ts, counter) ⇒ same header bytes |
| `TestPeekAndValidate` | 2 | Header round-trip + min-timestamp |
| `TestSenderContext` | 2 | Monotonic counter, counter-wraps-to-next-ms |
| `TestCrossSuiteInterop` | 1 | One keypair, both suites |
| `TestKeyWrappers` | 3 | Bad-size pk/sk, unknown suite |

**KAT regeneration determinism:** verified by SHA-256 hashing `pqcrypt/conformance/vectors/*.json` across two consecutive `generate.py` invocations. All 6 files produce identical hashes.

## Rollback

Files added under `pqcrypt/python/`, `pqcrypt/conformance/scripts/`, `pqcrypt/conformance/vectors/`, and `pqcrypt/benchmarks/python.txt` may be removed wholesale. No other surface depends on them yet. The umbrella `CLAUDE.md`, project `CLAUDE.md`, whitepaper, and `common/c/` extractions (PQCK-00002) remain valid.

## Security considerations

- **OS CSPRNG only.** The Python reference defers to `kyber-py`'s internal randomness (which calls `os.urandom` in production) and `cryptography`'s AES-256-GCM (`os.urandom` for the on-wire IV when applicable). No userspace PRNG fallback. The KAT generator deterministically seeds the DRBG via `MLKem1024.set_drbg_seed(48-byte seed)` — this path is for vector generation **only** and must never be invoked in production.
- **Constant-time decrypt path.** The reference verifies AEAD tag, UtC commit, deterministic-nonce match, and AD equality in `hmac.compare_digest`-backed constant time. Even when ML-KEM `Decaps` raises (truncated KEM_CT), the synthetic-key AEAD verify still runs to keep timing flat. The structural error path (`UnknownVariant`, `UnknownSuite`, `InvalidLength`) is intentionally distinguishable because those errors do not depend on secret-correlated bytes.
- **No "Kyber" naming.** The vendor library exposes `ML_KEM_1024`; we alias it to `pqcrypt.MLKem1024` at import time, so no public surface carries the legacy "Kyber" token.
- **`PrivateKey` does not zeroize.** Python's memory model makes that promise hollow. Documented in the `PrivateKey` docstring; production deployments should keep long-term keys in HSM/SE/SoftHSM and only expose a Decaps oracle (the plugin-protocol path landing in PQCK-00008).
- **`pycryptodome` is a generator-only dependency.** It is required to make `kyber-py.set_drbg_seed()` work, which is required only for deterministic KAT generation. Production callers do not import it.
- **No side-channel claim beyond software timing.** Power-analysis, EM, DVFS, and prefetcher attacks remain out of scope per `pqcrypt/docs/side-channel-disclaimer.md`.

## Linked PRs / tickets

- **Depends on:** PQCK-00001 (scaffold + whitepaper), PQCK-00002 (common/c extractions; not used by Python but defines the binding semantics).
- **Unblocks:** PQCK-00004 (PQID/PQHash reject 0x04 — uses the same variant-byte allocation table), PQCK-00005 (PQCrypt C reference — mirrors this Python module's API and KDF schedule), PQCK-00006/00007 (Go/Rust ports — must consume the same KAT vectors).
- **References:** FIPS 203 (ML-KEM), RFC 5869 (HKDF), Bellare-Hoang 2022 (UtC commitment), `pqcrypt/latex/main.tex` whitepaper §3–§8.
