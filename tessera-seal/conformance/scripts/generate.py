"""
generate.py — Produce TesseraSeal conformance vectors from the Python reference.

Run from the repo root:
    cd tessera-seal && python3 conformance/scripts/generate.py

Writes JSON vector files into tessera-seal/conformance/vectors/. Files are
committed verbatim; re-running this script on the same source must produce
byte-identical JSON. If it does not, that is a determinism bug — fix it
before merging.

Vector files:
  - decrypt.json           - known envelopes -> known plaintexts
                             (envelope is whatever the reference produced at
                              generation time; KEM randomness is captured)
  - peek_header.json       - header parsing, deterministic header bytes
  - invalid.json           - bad variant byte, bad suite byte, truncation
  - ad_binding.json        - TesseraID-as-AD positive / negative
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

import argparse
import json
import os
import sys
from pathlib import Path

# Make the python/ reference importable.
HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parent.parent.parent  # tessera-seal/
sys.path.insert(0, str(PROJECT_ROOT / "python"))

import tessera_seal  # noqa: E402


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
    tessera_seal.MLKem1024.set_drbg_seed(_KAT_DRBG_SEED)


def _freeze_kat_clock() -> None:
    """Freeze the timestamp source to KAT_TS_MS so the header bytes are
    stable across runs. (The ML-KEM DRBG is reseeded via _reset_kat_drbg
    independently.) Pair this call with set_now_ms_for_testing(None) in a
    finally-block at the caller."""
    tessera_seal.set_now_ms_for_testing(KAT_TS_MS)


def _hex(b: bytes) -> str:
    return b.hex()


# TESS-00009 / TP-113: module-level write switch. False = dry run (default);
# main() flips it only when --write is passed, so an accidental invocation
# (or `--help`) can never silently rewrite frozen vectors.
_WRITE = False


def _write(path: Path, records: list) -> None:
    content = json.dumps(records, indent=2) + "\n"
    if path.exists():
        status = "unchanged" if path.read_text() == content else "WOULD CHANGE"
    else:
        status = "NEW FILE"
    rel = path.relative_to(PROJECT_ROOT)
    if _WRITE:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as f:
            f.write(content)
        print(f"wrote {rel} ({len(records)} record(s), was {status})")
    else:
        print(f"dry-run {rel} ({len(records)} record(s), {status})")


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
        ("empty_aesgcm", b"", b"", tessera_seal.SUITE_MLKEM1024_AESGCM),
        ("short_aesgcm", b"hello world", b"", tessera_seal.SUITE_MLKEM1024_AESGCM),
        ("ad_aesgcm", b"with AD", b"pqid-like-41-byte-string-padded___........", tessera_seal.SUITE_MLKEM1024_AESGCM),
        ("medium_aesgcm", b"X" * 256, b"", tessera_seal.SUITE_MLKEM1024_AESGCM),
        ("empty_chacha", b"", b"", tessera_seal.SUITE_MLKEM1024_CHACHA),
        ("short_chacha", b"hello chacha", b"", tessera_seal.SUITE_MLKEM1024_CHACHA),
        ("ad_chacha", b"chacha + AD", b"pqid-like-41-byte-string-padded___........", tessera_seal.SUITE_MLKEM1024_CHACHA),
        # TESS-00009 / TP-046 boundary KATs. APPENDED at the end of the list
        # so the DRBG draw order (and therefore every earlier record's bytes)
        # is unchanged — the committed records are frozen. The explicit
        # sender_counter values keep the module-level SenderContext state
        # untouched too (implicit-counter encrypts would shift the ctr field
        # of every later implicit envelope, mutating frozen records).
        #   - 64 KiB plaintext (vectors previously maxed out at 256 B).
        #   - AD at exactly the MAX_AD_LEN = 65_536 cap (previously <= 41 B).
        ("pt_64kib_aesgcm", bytes(range(256)) * 256, b"", tessera_seal.SUITE_MLKEM1024_AESGCM, 7),
        ("ad_max_65536_aesgcm", b"boundary: max-length AD", b"A" * tessera_seal.MAX_AD_LEN, tessera_seal.SUITE_MLKEM1024_AESGCM, 8),
    ]
    for idx, case in enumerate(cases):
        name, pt, ad, suite = case[:4]
        counter = case[4] if len(case) > 4 else None
        seed = _kp_seed(100 + idx)
        priv, pub = tessera_seal.generate_keypair_from_seed(seed, suite=suite)
        if counter is None:
            env = tessera_seal.encrypt(pt, pub, suite=suite, associated_data=ad)
        else:
            env = tessera_seal.encrypt(
                pt, pub, suite=suite, associated_data=ad, sender_counter=counter
            )
        # Sanity: round-trip locally.
        assert tessera_seal.decrypt(env, priv, expected_ad=ad) == pt
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
        ("aesgcm_ctr0_ad0", tessera_seal.SUITE_MLKEM1024_AESGCM, 0, 0),
        ("aesgcm_ctr7_ad41", tessera_seal.SUITE_MLKEM1024_AESGCM, 7, 41),
        ("chacha_ctr0_ad0", tessera_seal.SUITE_MLKEM1024_CHACHA, 0, 0),
        ("chacha_ctr0xFFFE_ad8", tessera_seal.SUITE_MLKEM1024_CHACHA, 0xFFFE, 8),
        # TESS-00009 / TP-046: counter saturated at the 16-bit maximum.
        # APPENDED at the end so earlier records' DRBG draw order is unchanged.
        ("aesgcm_ctr0xFFFF_ad0", tessera_seal.SUITE_MLKEM1024_AESGCM, 0xFFFF, 0),
    ]):
        _, pub = tessera_seal.generate_keypair_from_seed(_kp_seed(400 + idx), suite=suite)
        env = tessera_seal.encrypt(
            b"x", pub, suite=suite, associated_data=b"A" * ad_len, sender_counter=counter
        )
        header_hex = _hex(env[: tessera_seal.HEADER_BYTES])
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
    # 0x05 is the first reserved-future suite byte (boundary-adjacent to the
    # 0x01/0x02 allocations); every decoder MUST reject it as UNKNOWN_SUITE.
    # (0x06 is NOT listed here: it is the hybrid suite, accepted by hybrid-
    # capable languages, so it cannot be a universal-rejection vector.)
    for suite in [0x00, 0x03, 0x04, 0x05, 0x10, 0x7F, 0xFE, 0xFF]:
        header = bytes(
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x04,    # variant (valid TesseraSeal)
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
            "envelope_hex": "00" * tessera_seal.HEADER_BYTES,
            "error_kind": "UNKNOWN_VARIANT",
        }
    )
    records.append(
        {
            "name": "header_with_bad_variant_truncated",
            "op": "decrypt_should_fail",
            "envelope_hex": "00" * tessera_seal.HEADER_BYTES + "ff" * 100,
            "error_kind": "UNKNOWN_VARIANT",
        }
    )

    # 4. A captured well-formed envelope with one-bit flips in critical positions.
    _reset_kat_drbg()
    seed = _kp_seed(200)
    priv, pub = tessera_seal.generate_keypair_from_seed(seed)
    env = tessera_seal.encrypt(b"tamper", pub, associated_data=b"ad1")
    priv_seed_hex = _hex(seed)
    priv_hex = _hex(priv.to_bytes())
    # Positions whose flip MUST cause DecryptionError (not structural error):
    flip_targets = {
        "flip_kem_ct_byte500": tessera_seal.HEADER_BYTES + 500,
        "flip_ad_byte0": tessera_seal.HEADER_BYTES + 1568,
        "flip_nonce_byte0": tessera_seal.HEADER_BYTES + 1568 + 3,  # ad is 3 bytes
        "flip_aead_ct_first": tessera_seal.HEADER_BYTES + 1568 + 3 + 12,
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

    # 5. Suite/key consistency (whitepaper sec02/sec09, BAD_KEY). A well-formed
    # suite 0x02 (ChaCha) envelope decrypted with a private key TAGGED as suite
    # 0x01 must reject as BAD_KEY (structural), not auth-class. The key bytes
    # are valid for the envelope (same seed-derived ML-KEM-1024 key); ONLY the
    # suite tag mismatches the header, so the lone reason for rejection is the
    # suite/key-consistency check. Every port's runner tags the reconstructed
    # private key with the record's `suite` field, so the mismatch is exercised
    # uniformly. Go/Rust already enforced this; Python/C now enforce it too.
    _reset_kat_drbg()
    bk_seed = _kp_seed(250)
    bk_priv, bk_pub = tessera_seal.generate_keypair_from_seed(
        bk_seed, suite=tessera_seal.SUITE_MLKEM1024_CHACHA
    )
    bk_env = tessera_seal.encrypt(
        b"suite-key-mismatch", bk_pub,
        suite=tessera_seal.SUITE_MLKEM1024_CHACHA, associated_data=b"",
    )
    records.append(
        {
            "name": "bad_key_suite_mismatch",
            "op": "decrypt_should_fail",
            # Key tagged 0x01; the envelope header is 0x02 -> BAD_KEY.
            "suite": tessera_seal.SUITE_MLKEM1024_AESGCM,
            "private_key_seed_hex": _hex(bk_seed),
            "private_key_hex": _hex(bk_priv.to_bytes()),
            "envelope_hex": _hex(bk_env),
            "expected_ad_hex": "",
            "error_kind": "BAD_KEY",
        }
    )

    # 6. Truncation classes (TESS-00009 / TP-045). A well-formed envelope cut
    # short MUST fail the total-length-vs-declared-lengths check with the
    # INVALID_LEN class — never auth-class. The private key is included so
    # every runner exercises decrypt() (the truncated envelopes still carry a
    # perfectly valid 16-byte header, so a key-less record would degrade to a
    # peek_header call that succeeds). Cut points:
    #   - mid-KEM_CT          (700 bytes into the 1568-byte KEM ciphertext)
    #   - mid-AEAD_CT         (3 bytes into the AEAD ciphertext)
    #   - one byte short of the commit tag (empty-plaintext envelope, so the
    #     missing byte provably falls inside the 32-byte commit region)
    # All three land below HEADER + kem_ct_len + ad_len + NONCE + TAG + COMMIT.
    # Explicit sender_counter values: implicit-counter encrypts would advance
    # the module-level SenderContext and shift the ctr field of every later
    # implicit envelope (mutating frozen records downstream).
    _reset_kat_drbg()
    tr_seed = _kp_seed(260)
    tr_priv, tr_pub = tessera_seal.generate_keypair_from_seed(tr_seed)
    tr_ad = b"ad"
    tr_env = tessera_seal.encrypt(
        b"truncation-target", tr_pub, associated_data=tr_ad, sender_counter=0
    )
    e_seed = _kp_seed(261)
    e_priv, e_pub = tessera_seal.generate_keypair_from_seed(e_seed)
    e_ad = b"ad3"
    e_env = tessera_seal.encrypt(b"", e_pub, associated_data=e_ad, sender_counter=1)
    truncations = [
        ("trunc_mid_kem_ct", tr_seed, tr_priv, tr_ad,
         tr_env[: tessera_seal.HEADER_BYTES + 700]),
        ("trunc_mid_aead_ct", tr_seed, tr_priv, tr_ad,
         tr_env[: tessera_seal.HEADER_BYTES + tessera_seal.MLKEM1024_CT_BYTES
                + len(tr_ad) + tessera_seal.AEAD_NONCE_BYTES + 3]),
        ("trunc_one_byte_short_of_commit", e_seed, e_priv, e_ad, e_env[:-1]),
    ]
    for name, seed, priv, ad, env in truncations:
        # Pin the class against the Python reference at generation time.
        try:
            tessera_seal.decrypt(env, priv, expected_ad=ad)
            raise AssertionError(f"{name}: truncated envelope decrypted")
        except tessera_seal.InvalidLength:
            pass
        records.append(
            {
                "name": name,
                "op": "decrypt_should_fail",
                "private_key_seed_hex": _hex(seed),
                "private_key_hex": _hex(priv.to_bytes()),
                "envelope_hex": _hex(env),
                "expected_ad_hex": _hex(ad),
                "error_kind": "INVALID_LEN",
            }
        )

    # 7. Wrong KEM_CT_LEN under a structurally valid header (TESS-00009 /
    # TP-046). The header itself parses (4096 == MAX_KEM_CT_LEN, peek_header
    # succeeds) but declares more KEM ciphertext than the envelope carries,
    # so decrypt MUST reject with INVALID_LEN — uniformly in every port.
    _reset_kat_drbg()
    wk_seed = _kp_seed(262)
    wk_priv, wk_pub = tessera_seal.generate_keypair_from_seed(wk_seed)
    wk_env = bytearray(
        tessera_seal.encrypt(b"x", wk_pub, associated_data=b"", sender_counter=0)
    )
    wk_env[tessera_seal.KEM_CT_LEN_OFFSET : tessera_seal.KEM_CT_LEN_OFFSET + 2] = (
        tessera_seal.MAX_KEM_CT_LEN
    ).to_bytes(2, "big")
    wk_env = bytes(wk_env)
    assert tessera_seal.peek_header(wk_env).kem_ct_len == tessera_seal.MAX_KEM_CT_LEN
    try:
        tessera_seal.decrypt(wk_env, wk_priv, expected_ad=b"")
        raise AssertionError("wrong-kem_ct_len envelope decrypted")
    except tessera_seal.InvalidLength:
        pass
    records.append(
        {
            "name": "wrong_kem_ct_len_valid_header",
            "op": "decrypt_should_fail",
            "private_key_seed_hex": _hex(wk_seed),
            "private_key_hex": _hex(wk_priv.to_bytes()),
            "envelope_hex": _hex(wk_env),
            "expected_ad_hex": "",
            "error_kind": "INVALID_LEN",
        }
    )

    _write(VECTORS_DIR / "invalid.json", records)


def make_ad_binding_vectors():
    """
    Positive and negative cases for the canonical TesseraID-as-AD pattern.

    Each record carries (private_key, envelope, the AD it was encrypted with).
    Positive cases pass `expected_ad = bound_ad` and assert decrypt succeeds.
    Negative cases pass a different `expected_ad` and assert DecryptionError.
    """
    _reset_kat_drbg()
    records = []

    seed = _kp_seed(300)
    priv, pub = tessera_seal.generate_keypair_from_seed(seed)
    priv_seed_hex = _hex(seed)
    priv_hex = _hex(priv.to_bytes())
    # Simulate a 41-byte TesseraID.
    tessera_id_a = bytes(range(41))
    tessera_id_b = bytes(range(1, 42))  # differs in every byte

    env_a = tessera_seal.encrypt(b"payload-A", pub, associated_data=tessera_id_a)
    env_b = tessera_seal.encrypt(b"payload-B", pub, associated_data=tessera_id_b)

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

    records.append(_record("positive_pqid_a", "decrypt", env_a, tessera_id_a,
                           {"expected_plaintext_hex": _hex(b"payload-A")}))
    records.append(_record("positive_pqid_b", "decrypt", env_b, tessera_id_b,
                           {"expected_plaintext_hex": _hex(b"payload-B")}))
    records.append(_record("negative_a_with_b", "decrypt_should_fail", env_a, tessera_id_b,
                           {"error_kind": "DECRYPT_FAILED"}))
    records.append(_record("negative_b_with_a", "decrypt_should_fail", env_b, tessera_id_a,
                           {"error_kind": "DECRYPT_FAILED"}))
    tessera_id_a_flipped = bytearray(tessera_id_a)
    tessera_id_a_flipped[0] ^= 0x01
    records.append(_record("negative_a_one_bit_flip", "decrypt_should_fail",
                           env_a, bytes(tessera_id_a_flipped),
                           {"error_kind": "DECRYPT_FAILED"}))
    records.append(_record("negative_a_short_ad", "decrypt_should_fail",
                           env_a, tessera_id_a[:-1],
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
        commit = tessera_seal._utc_commit(k_commit, hdr, kem_ct, ad, ct)
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
    """validate_min_timestamp parallels tessera-id/tessera-hash analogues."""
    _reset_kat_drbg()
    records = []
    _, pub = tessera_seal.generate_keypair_from_seed(_kp_seed(500))
    env = tessera_seal.encrypt(b"x", pub, sender_counter=0)
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
    suite = tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM
    for idx, (name, pt, ad) in enumerate(cases):
        seed = _hybrid_seed(idx)
        priv, pub = tessera_seal.generate_keypair_from_seed(seed, suite=suite)
        env = tessera_seal.encrypt(pt, pub, suite=suite, associated_data=ad)
        assert tessera_seal.decrypt(env, priv, expected_ad=ad) == pt
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
    """TesseraID-as-AD positive/negative for the hybrid suite."""
    _reset_kat_drbg()
    records = []
    suite = tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM
    seed = _hybrid_seed(100)
    priv, pub = tessera_seal.generate_keypair_from_seed(seed, suite=suite)
    seed_hex = _hex(seed)
    priv_hex = _hex(priv.to_bytes())
    tessera_id_a = bytes(range(41))
    tessera_id_b = bytes(range(1, 42))
    env_a = tessera_seal.encrypt(b"payload-A", pub, suite=suite, associated_data=tessera_id_a)
    env_b = tessera_seal.encrypt(b"payload-B", pub, suite=suite, associated_data=tessera_id_b)

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

    records.append(_rec("hybrid_positive_a", "decrypt", env_a, tessera_id_a,
                        {"expected_plaintext_hex": _hex(b"payload-A")}))
    records.append(_rec("hybrid_positive_b", "decrypt", env_b, tessera_id_b,
                        {"expected_plaintext_hex": _hex(b"payload-B")}))
    records.append(_rec("hybrid_neg_a_with_b", "decrypt_should_fail", env_a, tessera_id_b,
                        {"error_kind": "DECRYPT_FAILED"}))
    records.append(_rec("hybrid_neg_flip_x25519_eph", "decrypt_should_fail",
                        bytes(bytearray(env_a)[:tessera_seal.HEADER_BYTES + tessera_seal.MLKEM1024_CT_BYTES + 5]
                              + bytes([env_a[tessera_seal.HEADER_BYTES + tessera_seal.MLKEM1024_CT_BYTES + 5] ^ 0x01])
                              + bytearray(env_a)[tessera_seal.HEADER_BYTES + tessera_seal.MLKEM1024_CT_BYTES + 6:]),
                        tessera_id_a, {"error_kind": "DECRYPT_FAILED"}))
    _write(VECTORS_DIR / "hybrid_ad_binding.json", records)


def make_hybrid_peek_header_vectors():
    """Hybrid header parsing — kem_ct_len should report 1600."""
    _reset_kat_drbg()
    records = []
    suite = tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM
    _, pub = tessera_seal.generate_keypair_from_seed(_hybrid_seed(200), suite=suite)
    env = tessera_seal.encrypt(b"x", pub, suite=suite, associated_data=b"", sender_counter=0)
    records.append({
        "name": "hybrid_ctr0_ad0",
        "op": "peek_header",
        "header_hex": _hex(env[:tessera_seal.HEADER_BYTES]),
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


def main(argv=None):
    global _WRITE
    parser = argparse.ArgumentParser(
        description=(
            "Regenerate the TesseraSeal conformance vectors from the Python "
            "reference. Default is a dry run that only reports what would "
            "change; pass --write to actually rewrite vectors/*.json. "
            "Committed vector records are FROZEN append-only — verify with "
            "tools/scripts/check-vector-freeze.sh after any --write. KNOWN "
            "non-reproducible files (pre-existing, tracked separately): "
            "ad_binding.json, hybrid_decrypt.json, hybrid_ad_binding.json "
            "regenerate with different bytes (hybrid X25519 ephemerals come "
            "from the OS CSPRNG, not the seeded DRBG) — do NOT commit "
            "rewrites of those three without re-pinning them deliberately."
        )
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="actually write the vector files (default: dry run, no writes)",
    )
    args = parser.parse_args(argv)
    _WRITE = args.write

    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    tessera_seal.set_now_ms_for_testing(KAT_TS_MS)
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
        tessera_seal.set_now_ms_for_testing(None)
    if _WRITE:
        print(f"\nAll vectors written under {VECTORS_DIR}.")
    else:
        print("\ndry run complete — re-run with --write to apply")


if __name__ == "__main__":
    main()
