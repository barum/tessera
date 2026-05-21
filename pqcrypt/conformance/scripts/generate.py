"""
generate.py — Produce PQCrypt conformance vectors from the Python reference.

Run from the repo root:
    cd pqcrypt && python3 conformance/scripts/generate.py

Writes JSON vector files into pqcrypt/conformance/vectors/. Files are
committed verbatim; re-running this script on the same source must produce
byte-identical JSON. If it does not, that is a determinism bug — fix it
before merging.

Vector files:
  - decrypt.json           - known envelopes -> known plaintexts
                             (envelope is whatever the reference produced at
                              generation time; KEM randomness is captured)
  - peek_header.json       - header parsing, deterministic header bytes
  - invalid.json           - bad variant byte, bad suite byte, truncation
  - ad_binding.json        - PQID-as-AD positive / negative
  - commitment.json        - UtC commit-tag KATs independent of AEAD path
  - min_timestamp.json     - validate_min_timestamp helper

Schema (each file is a JSON array of records):
  {
    "name": "human-readable id, unique within file",
    "op":   "decrypt | peek_header | validate | validate_min_timestamp |
             utc_commit | invalid_decode",
    ...op-specific fields...
  }

Note: ML-KEM Encaps uses fresh randomness, so envelopes cannot be the
result of a deterministic re-encryption. Instead, this script captures
the envelope produced once at generation time and asserts that each
language's *decrypt* path reproduces the original plaintext from it.
The Python reference is the source of truth: vectors are accepted iff
every other language decrypts them identically.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Make the python/ reference importable.
HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parent.parent.parent  # pqcrypt/
sys.path.insert(0, str(PROJECT_ROOT / "python"))

import pqcrypt  # noqa: E402


VECTORS_DIR = PROJECT_ROOT / "conformance" / "vectors"

# Deterministic timestamp for header-stability vectors.
KAT_TS_MS = 1_700_000_000_000

# Deterministic ML-KEM-1024 entropy source for reproducible vectors. We use
# kyber-py's DRBG seeding so every regeneration produces byte-identical
# envelopes. If kyber-py is replaced, the replacement must offer the same
# deterministic mode or the vectors lose stability and must be re-pinned.
# 48 bytes — NIST AES-256-CTR-DRBG entropy input length per kyber-py.
_KAT_DRBG_SEED = bytes.fromhex(
    "000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000001"
)


def _kp_seed(index: int) -> bytes:
    """Deterministic 64-byte ML-KEM-1024 keypair seed for KAT record `index`."""
    out = bytearray(64)
    out[28:32] = index.to_bytes(4, "big")
    return bytes(out)


def _hybrid_seed(index: int) -> bytes:
    """Deterministic 96-byte hybrid keypair seed (64 ML-KEM || 32 X25519).

    The ML-KEM half follows the _kp_seed pattern (index biased to avoid
    collision with non-hybrid records); the X25519 half is just the index
    big-endian-encoded so different records yield different X25519 keys.
    """
    pq_seed = _kp_seed(900_000 + index)
    x_scalar = bytearray(32)
    x_scalar[28:32] = index.to_bytes(4, "big")
    return pq_seed + bytes(x_scalar)


def _reset_kat_drbg() -> None:
    """Re-seed the ML-KEM DRBG with the KAT seed. Call before each vector
    generation function so the function's output is independent of prior
    calls' randomness consumption."""
    pqcrypt.MLKem1024.set_drbg_seed(_KAT_DRBG_SEED)


def _freeze_kat_clock() -> None:
    """Freeze the timestamp source to KAT_TS_MS so the header bytes are
    stable across runs. (The ML-KEM DRBG is reseeded via _reset_kat_drbg
    independently.) Pair this call with set_now_ms_for_testing(None) in a
    finally-block at the caller."""
    pqcrypt.set_now_ms_for_testing(KAT_TS_MS)


def _hex(b: bytes) -> str:
    return b.hex()


def _write(path: Path, records: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(records, f, indent=2)
        f.write("\n")
    print(f"wrote {path.relative_to(PROJECT_ROOT)} ({len(records)} record(s))")


# ---------------------------------------------------------------------------


def make_decrypt_vectors():
    """
    A KAT pair: (private_key, envelope) -> plaintext.

    Each record carries the recipient private key (hex), the envelope (hex),
    the expected_ad, and the expected plaintext. The Python reference produced
    the envelope at generation time; every other language MUST decrypt the
    same envelope back to the same plaintext.
    """
    _reset_kat_drbg()
    records = []
    cases = [
        ("empty_aesgcm", b"", b"", pqcrypt.SUITE_MLKEM1024_AESGCM),
        ("short_aesgcm", b"hello world", b"", pqcrypt.SUITE_MLKEM1024_AESGCM),
        ("ad_aesgcm", b"with AD", b"pqid-like-41-byte-string-padded___........", pqcrypt.SUITE_MLKEM1024_AESGCM),
        ("medium_aesgcm", b"X" * 256, b"", pqcrypt.SUITE_MLKEM1024_AESGCM),
        ("empty_chacha", b"", b"", pqcrypt.SUITE_MLKEM1024_CHACHA),
        ("short_chacha", b"hello chacha", b"", pqcrypt.SUITE_MLKEM1024_CHACHA),
        ("ad_chacha", b"chacha + AD", b"pqid-like-41-byte-string-padded___........", pqcrypt.SUITE_MLKEM1024_CHACHA),
    ]
    for idx, (name, pt, ad, suite) in enumerate(cases):
        seed = _kp_seed(100 + idx)
        priv, pub = pqcrypt.generate_keypair_from_seed(seed, suite=suite)
        env = pqcrypt.encrypt(pt, pub, suite=suite, associated_data=ad)
        # Sanity: round-trip locally.
        assert pqcrypt.decrypt(env, priv, expected_ad=ad) == pt
        records.append(
            {
                "name": name,
                "op": "decrypt",
                "suite": suite,
                "private_key_seed_hex": _hex(seed),
                "private_key_hex": _hex(priv.to_bytes()),
                "envelope_hex": _hex(env),
                "expected_ad_hex": _hex(ad),
                "expected_plaintext_hex": _hex(pt),
            }
        )
    _write(VECTORS_DIR / "decrypt.json", records)


def make_peek_header_vectors():
    """
    Deterministic header bytes for a frozen (ts, counter) pair.

    The first 16 bytes of the envelope are deterministic given:
        ts, variant=0x04, suite, counter, kem_ct_len, ad_len.
    KEM_CT_LEN and AD_LEN depend on inputs the test selects; ML-KEM-1024
    ciphertext is always 1568 bytes for the v1 suites, so kem_ct_len is
    constant at 1568 here.
    """
    # Clock is frozen by main(); do not reset it here.
    _reset_kat_drbg()
    records = []
    for idx, (name, suite, counter, ad_len) in enumerate([
        ("aesgcm_ctr0_ad0", pqcrypt.SUITE_MLKEM1024_AESGCM, 0, 0),
        ("aesgcm_ctr7_ad41", pqcrypt.SUITE_MLKEM1024_AESGCM, 7, 41),
        ("chacha_ctr0_ad0", pqcrypt.SUITE_MLKEM1024_CHACHA, 0, 0),
        ("chacha_ctr0xFFFE_ad8", pqcrypt.SUITE_MLKEM1024_CHACHA, 0xFFFE, 8),
    ]):
        _, pub = pqcrypt.generate_keypair_from_seed(_kp_seed(400 + idx), suite=suite)
        env = pqcrypt.encrypt(
            b"x", pub, suite=suite, associated_data=b"A" * ad_len, sender_counter=counter
        )
        header_hex = _hex(env[: pqcrypt.HEADER_BYTES])
        records.append(
            {
                "name": name,
                "op": "peek_header",
                "header_hex": header_hex,
                "expected": {
                    "timestamp_ms": KAT_TS_MS,
                    "variant": 0x04,
                    "suite": suite,
                    "counter": counter,
                    "kem_ct_len": 1568,
                    "ad_len": ad_len,
                },
            }
        )
    _write(VECTORS_DIR / "peek_header.json", records)


def make_invalid_vectors():
    """
    Structural and authentication failure cases. Each record either:
      - Asserts a specific structural error class (UnknownVariant /
        UnknownSuite / InvalidLength) on peek_header(), or
      - Asserts DecryptionError on decrypt() with a captured private key.
    """
    records = []

    # 1. Header bytes representing each reserved/non-allocated variant.
    for variant in [0x00, 0x01, 0x02, 0x03, 0x05, 0x10, 0x7F, 0xFE, 0xFF]:
        # Construct a header with valid suite (0x01) but wrong variant.
        header = bytes(
            [
                0x00,  # ts msb
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                variant,
                0x01,  # suite
                0x00,
                0x00,  # ctr
                0x06,
                0x20,  # kem_ct_len = 1568
                0x00,
                0x00,
                0x00,
                0x00,  # ad_len = 0
            ]
        )
        records.append(
            {
                "name": f"variant_0x{variant:02x}_rejected",
                "op": "peek_header_should_fail",
                "envelope_hex": _hex(header + b"\x00" * 1568 + b"\x00" * 12 + b"\x00" * 16 + b"\x00" * 32),
                "error_kind": "UNKNOWN_VARIANT",
            }
        )

    # 2. Headers representing non-allocated suites (variant=0x04, suite invalid).
    for suite in [0x00, 0x03, 0x04, 0x10, 0x7F, 0xFE, 0xFF]:
        header = bytes(
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x04,    # variant (valid PQCrypt)
                suite,   # suite (invalid)
                0x00, 0x00,  # ctr
                0x06, 0x20,  # kem_ct_len = 1568
                0x00, 0x00, 0x00, 0x00,  # ad_len = 0
            ]
        )
        records.append(
            {
                "name": f"suite_0x{suite:02x}_rejected",
                "op": "peek_header_should_fail",
                "envelope_hex": _hex(header + b"\x00" * 1568 + b"\x00" * 12 + b"\x00" * 16 + b"\x00" * 32),
                "error_kind": "UNKNOWN_SUITE",
            }
        )

    # 3. Truncated envelopes.
    records.append(
        {
            "name": "empty",
            "op": "decrypt_should_fail",
            "envelope_hex": "",
            "error_kind": "INVALID_LEN",
        }
    )
    records.append(
        {
            "name": "header_only",
            "op": "decrypt_should_fail",
            "envelope_hex": "00" * pqcrypt.HEADER_BYTES,
            "error_kind": "UNKNOWN_VARIANT",
        }
    )
    records.append(
        {
            "name": "header_with_bad_variant_truncated",
            "op": "decrypt_should_fail",
            "envelope_hex": "00" * pqcrypt.HEADER_BYTES + "ff" * 100,
            "error_kind": "UNKNOWN_VARIANT",
        }
    )

    # 4. A captured well-formed envelope with one-bit flips in critical positions.
    _reset_kat_drbg()
    seed = _kp_seed(200)
    priv, pub = pqcrypt.generate_keypair_from_seed(seed)
    env = pqcrypt.encrypt(b"tamper", pub, associated_data=b"ad1")
    priv_seed_hex = _hex(seed)
    priv_hex = _hex(priv.to_bytes())
    # Positions whose flip MUST cause DecryptionError (not structural error):
    flip_targets = {
        "flip_kem_ct_byte500": pqcrypt.HEADER_BYTES + 500,
        "flip_ad_byte0": pqcrypt.HEADER_BYTES + 1568,
        "flip_nonce_byte0": pqcrypt.HEADER_BYTES + 1568 + 3,  # ad is 3 bytes
        "flip_aead_ct_first": pqcrypt.HEADER_BYTES + 1568 + 3 + 12,
        "flip_aead_tag_last": len(env) - 32 - 1,
        "flip_commit_last": len(env) - 1,
    }
    for name, idx in flip_targets.items():
        tampered = bytearray(env)
        tampered[idx] ^= 0x01
        records.append(
            {
                "name": name,
                "op": "decrypt_should_fail",
                "private_key_seed_hex": priv_seed_hex,
                "private_key_hex": priv_hex,
                "envelope_hex": _hex(bytes(tampered)),
                "expected_ad_hex": _hex(b"ad1"),
                "error_kind": "DECRYPT_FAILED",
            }
        )

    _write(VECTORS_DIR / "invalid.json", records)


def make_ad_binding_vectors():
    """
    Positive and negative cases for the canonical PQID-as-AD pattern.

    Each record carries (private_key, envelope, the AD it was encrypted with).
    Positive cases pass `expected_ad = bound_ad` and assert decrypt succeeds.
    Negative cases pass a different `expected_ad` and assert DecryptionError.
    """
    _reset_kat_drbg()
    records = []

    seed = _kp_seed(300)
    priv, pub = pqcrypt.generate_keypair_from_seed(seed)
    priv_seed_hex = _hex(seed)
    priv_hex = _hex(priv.to_bytes())
    # Simulate a 41-byte PQID.
    pqid_a = bytes(range(41))
    pqid_b = bytes(range(1, 42))  # differs in every byte

    env_a = pqcrypt.encrypt(b"payload-A", pub, associated_data=pqid_a)
    env_b = pqcrypt.encrypt(b"payload-B", pub, associated_data=pqid_b)

    def _record(name, op, env, ad, extra=None):
        r = {
            "name": name,
            "op": op,
            "private_key_seed_hex": priv_seed_hex,
            "private_key_hex": priv_hex,
            "envelope_hex": _hex(env),
            "expected_ad_hex": _hex(ad),
        }
        if extra:
            r.update(extra)
        return r

    records.append(_record("positive_pqid_a", "decrypt", env_a, pqid_a,
                           {"expected_plaintext_hex": _hex(b"payload-A")}))
    records.append(_record("positive_pqid_b", "decrypt", env_b, pqid_b,
                           {"expected_plaintext_hex": _hex(b"payload-B")}))
    records.append(_record("negative_a_with_b", "decrypt_should_fail", env_a, pqid_b,
                           {"error_kind": "DECRYPT_FAILED"}))
    records.append(_record("negative_b_with_a", "decrypt_should_fail", env_b, pqid_a,
                           {"error_kind": "DECRYPT_FAILED"}))
    pqid_a_flipped = bytearray(pqid_a)
    pqid_a_flipped[0] ^= 0x01
    records.append(_record("negative_a_one_bit_flip", "decrypt_should_fail",
                           env_a, bytes(pqid_a_flipped),
                           {"error_kind": "DECRYPT_FAILED"}))
    records.append(_record("negative_a_short_ad", "decrypt_should_fail",
                           env_a, pqid_a[:-1],
                           {"error_kind": "DECRYPT_FAILED"}))

    _write(VECTORS_DIR / "ad_binding.json", records)


def make_commitment_vectors():
    """
    UtC commit tag KATs: given (K_commit, header, kem_ct, ad, aead_ct),
    the COMMIT is uniquely determined as HMAC-SHA3-256 over the concatenation.

    This file pins the HMAC-SHA3-256 binding so language ports cannot
    silently substitute a different commitment scheme.
    """
    records = []
    cases = [
        ("zero_key_empty_msg", bytes(32), b"", b"", b"", b""),
        (
            "tiny_inputs",
            bytes(range(32)),
            b"hdr-16-byte-pqcryp",  # 18-byte stand-in for header
            b"kem-ct-stand-in",
            b"ad",
            b"ct",
        ),
        (
            "large_msg",
            bytes(reversed(range(32))),
            b"\x00" * 16,
            b"K" * 1568,
            b"D" * 41,
            b"C" * 1024,
        ),
    ]
    for name, k_commit, hdr, kem_ct, ad, ct in cases:
        commit = pqcrypt._utc_commit(k_commit, hdr, kem_ct, ad, ct)
        records.append(
            {
                "name": name,
                "op": "utc_commit",
                "k_commit_hex": _hex(k_commit),
                "header_hex": _hex(hdr),
                "kem_ct_hex": _hex(kem_ct),
                "ad_hex": _hex(ad),
                "aead_ct_hex": _hex(ct),
                "expected_commit_hex": _hex(commit),
            }
        )
    _write(VECTORS_DIR / "commitment.json", records)


def make_min_timestamp_vectors():
    """validate_min_timestamp parallels pqid/pqhash analogues."""
    _reset_kat_drbg()
    records = []
    _, pub = pqcrypt.generate_keypair_from_seed(_kp_seed(500))
    env = pqcrypt.encrypt(b"x", pub, sender_counter=0)
    for name, min_ms, expected in [
        ("min_lt_ts", KAT_TS_MS - 1, True),
        ("min_eq_ts", KAT_TS_MS, True),
        ("min_gt_ts", KAT_TS_MS + 1, False),
        ("min_far_future", KAT_TS_MS * 2, False),
    ]:
        records.append(
            {
                "name": name,
                "op": "validate_min_timestamp",
                "envelope_hex": _hex(env),
                "min_ms": min_ms,
                "expected": expected,
            }
        )
    _write(VECTORS_DIR / "min_timestamp.json", records)


def make_hybrid_decrypt_vectors():
    """KAT pairs for the v1.2 hybrid suite 0x06.

    Each record carries:
      - private_key_seed_hex: 96-byte hybrid seed (FIPS 203 64 || X25519 32)
      - private_key_hex:       3200-byte expanded form (ML-KEM-1024 sk || X25519 sk)
      - envelope_hex
      - expected_ad_hex, expected_plaintext_hex

    Languages that don't yet support suite 0x06 should skip this file.
    """
    _reset_kat_drbg()
    records = []
    cases = [
        ("hybrid_empty", b"", b""),
        ("hybrid_short", b"hello hybrid", b""),
        ("hybrid_with_ad", b"with AD", b"pqid-like-41-byte-string-padded___........"),
        ("hybrid_medium", b"X" * 256, b""),
    ]
    suite = pqcrypt.SUITE_HYBRID_X25519_MLKEM1024_AESGCM
    for idx, (name, pt, ad) in enumerate(cases):
        seed = _hybrid_seed(idx)
        priv, pub = pqcrypt.generate_keypair_from_seed(seed, suite=suite)
        env = pqcrypt.encrypt(pt, pub, suite=suite, associated_data=ad)
        assert pqcrypt.decrypt(env, priv, expected_ad=ad) == pt
        records.append({
            "name": name,
            "op": "decrypt",
            "suite": suite,
            "private_key_seed_hex": _hex(seed),
            "private_key_hex": _hex(priv.to_bytes()),
            "public_key_hex": _hex(pub.to_bytes()),
            "envelope_hex": _hex(env),
            "expected_ad_hex": _hex(ad),
            "expected_plaintext_hex": _hex(pt),
        })
    _write(VECTORS_DIR / "hybrid_decrypt.json", records)


def make_hybrid_ad_binding_vectors():
    """PQID-as-AD positive/negative for the hybrid suite."""
    _reset_kat_drbg()
    records = []
    suite = pqcrypt.SUITE_HYBRID_X25519_MLKEM1024_AESGCM
    seed = _hybrid_seed(100)
    priv, pub = pqcrypt.generate_keypair_from_seed(seed, suite=suite)
    seed_hex = _hex(seed)
    priv_hex = _hex(priv.to_bytes())
    pqid_a = bytes(range(41))
    pqid_b = bytes(range(1, 42))
    env_a = pqcrypt.encrypt(b"payload-A", pub, suite=suite, associated_data=pqid_a)
    env_b = pqcrypt.encrypt(b"payload-B", pub, suite=suite, associated_data=pqid_b)

    def _rec(name, op, env, ad, extra=None):
        r = {
            "name": name, "op": op, "suite": suite,
            "private_key_seed_hex": seed_hex,
            "private_key_hex": priv_hex,
            "envelope_hex": _hex(env),
            "expected_ad_hex": _hex(ad),
        }
        if extra:
            r.update(extra)
        return r

    records.append(_rec("hybrid_positive_a", "decrypt", env_a, pqid_a,
                        {"expected_plaintext_hex": _hex(b"payload-A")}))
    records.append(_rec("hybrid_positive_b", "decrypt", env_b, pqid_b,
                        {"expected_plaintext_hex": _hex(b"payload-B")}))
    records.append(_rec("hybrid_neg_a_with_b", "decrypt_should_fail", env_a, pqid_b,
                        {"error_kind": "DECRYPT_FAILED"}))
    records.append(_rec("hybrid_neg_flip_x25519_eph", "decrypt_should_fail",
                        bytes(bytearray(env_a)[:pqcrypt.HEADER_BYTES + pqcrypt.MLKEM1024_CT_BYTES + 5]
                              + bytes([env_a[pqcrypt.HEADER_BYTES + pqcrypt.MLKEM1024_CT_BYTES + 5] ^ 0x01])
                              + bytearray(env_a)[pqcrypt.HEADER_BYTES + pqcrypt.MLKEM1024_CT_BYTES + 6:]),
                        pqid_a, {"error_kind": "DECRYPT_FAILED"}))
    _write(VECTORS_DIR / "hybrid_ad_binding.json", records)


def make_hybrid_peek_header_vectors():
    """Hybrid header parsing — kem_ct_len should report 1600."""
    _reset_kat_drbg()
    records = []
    suite = pqcrypt.SUITE_HYBRID_X25519_MLKEM1024_AESGCM
    _, pub = pqcrypt.generate_keypair_from_seed(_hybrid_seed(200), suite=suite)
    env = pqcrypt.encrypt(b"x", pub, suite=suite, associated_data=b"", sender_counter=0)
    records.append({
        "name": "hybrid_ctr0_ad0",
        "op": "peek_header",
        "header_hex": _hex(env[:pqcrypt.HEADER_BYTES]),
        "expected": {
            "timestamp_ms": KAT_TS_MS,
            "variant": 0x04,
            "suite": suite,
            "counter": 0,
            "kem_ct_len": 1600,
            "ad_len": 0,
        },
    })
    _write(VECTORS_DIR / "hybrid_peek_header.json", records)


def main():
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    pqcrypt.set_now_ms_for_testing(KAT_TS_MS)
    try:
        make_decrypt_vectors()
        make_peek_header_vectors()
        make_invalid_vectors()
        make_ad_binding_vectors()
        make_commitment_vectors()
        make_min_timestamp_vectors()
        # v1.2 hybrid (PQCK-00021)
        make_hybrid_decrypt_vectors()
        make_hybrid_ad_binding_vectors()
        make_hybrid_peek_header_vectors()
    finally:
        pqcrypt.set_now_ms_for_testing(None)
    print(f"\nAll vectors written under {VECTORS_DIR}.")


if __name__ == "__main__":
    main()
