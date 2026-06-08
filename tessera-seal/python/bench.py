"""
bench.py — TesseraSeal Python reference micro-benchmarks.

Output mirrors tessera-id/python/bench.py:
    <operation, left-aligned ~40 chars>  <ops/sec, right-aligned>  (<ns/op>)

Run:
    cd tessera-seal/python && python3 bench.py
"""
from __future__ import annotations

import os
import time

import tessera_seal


WARMUP = 200
ITERS_KEYGEN = 200
ITERS_ENC_1KB = 500
ITERS_DEC_1KB = 500
ITERS_ENC_1MB = 30
ITERS_DEC_1MB = 30
ITERS_PEEK = 100_000
ITERS_ENC_WITH_AD = 500


def _measure(label: str, iters: int, fn) -> None:
    # Warmup
    for _ in range(WARMUP):
        fn()
    t0 = time.perf_counter()
    for _ in range(iters):
        fn()
    elapsed = time.perf_counter() - t0
    ops_per_sec = iters / elapsed
    ns_per_op = (elapsed / iters) * 1e9
    print(f"{label:<40} {ops_per_sec:>14.0f} ops/sec   ({ns_per_op:>10.0f} ns/op)")


def main() -> None:
    print("TesseraSeal Python benchmarks (canonical reference, tessera_seal.py)")
    print("-" * 70)

    # Pre-create artifacts so each measurement is the operation under test.
    priv, pub = tessera_seal.generate_keypair()
    pt_1kb = os.urandom(1024)
    pt_1mb = os.urandom(1024 * 1024)
    tessera_id_ad = os.urandom(41)
    env_1kb = tessera_seal.encrypt(pt_1kb, pub)
    env_1mb = tessera_seal.encrypt(pt_1mb, pub)
    env_ad = tessera_seal.encrypt(pt_1kb, pub, associated_data=tessera_id_ad)

    _measure("keygen (ML-KEM-1024)", ITERS_KEYGEN, lambda: tessera_seal.generate_keypair())
    _measure("encrypt_1KB (AES-256-GCM)", ITERS_ENC_1KB, lambda: tessera_seal.encrypt(pt_1kb, pub))
    _measure("decrypt_1KB (AES-256-GCM)", ITERS_DEC_1KB, lambda: tessera_seal.decrypt(env_1kb, priv, expected_ad=b""))
    _measure("encrypt_1MB (AES-256-GCM)", ITERS_ENC_1MB, lambda: tessera_seal.encrypt(pt_1mb, pub))
    _measure("decrypt_1MB (AES-256-GCM)", ITERS_DEC_1MB, lambda: tessera_seal.decrypt(env_1mb, priv, expected_ad=b""))
    _measure("peek_header", ITERS_PEEK, lambda: tessera_seal.peek_header(env_1kb))
    _measure("encrypt_with_tessera_id_ad", ITERS_ENC_WITH_AD, lambda: tessera_seal.encrypt(pt_1kb, pub, associated_data=tessera_id_ad))

    # ChaCha suite, just to record the delta vs AES.
    priv_c = tessera_seal.PrivateKey(priv.to_bytes(), suite=tessera_seal.SUITE_MLKEM1024_CHACHA)
    pub_c = tessera_seal.PublicKey(pub.to_bytes(), suite=tessera_seal.SUITE_MLKEM1024_CHACHA)
    env_1kb_c = tessera_seal.encrypt(pt_1kb, pub_c, suite=tessera_seal.SUITE_MLKEM1024_CHACHA)
    _measure(
        "encrypt_1KB (ChaCha20-Poly1305)",
        ITERS_ENC_1KB,
        lambda: tessera_seal.encrypt(pt_1kb, pub_c, suite=tessera_seal.SUITE_MLKEM1024_CHACHA),
    )
    _measure(
        "decrypt_1KB (ChaCha20-Poly1305)",
        ITERS_DEC_1KB,
        lambda: tessera_seal.decrypt(env_1kb_c, priv_c, expected_ad=b""),
    )

    # Hybrid suite 0x06 (PQCK-00021): X25519 + ML-KEM-1024 + AES-256-GCM + UtC.
    # X25519 keygen + ECDH adds a measurable but small overhead on top of ML-KEM.
    priv_h, pub_h = tessera_seal.generate_keypair(suite=tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM)
    env_1kb_h = tessera_seal.encrypt(pt_1kb, pub_h, suite=tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM)
    _measure(
        "keygen (hybrid X25519+ML-KEM-1024)",
        ITERS_KEYGEN,
        lambda: tessera_seal.generate_keypair(suite=tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM),
    )
    _measure(
        "encrypt_1KB (hybrid suite 0x06)",
        ITERS_ENC_1KB,
        lambda: tessera_seal.encrypt(pt_1kb, pub_h, suite=tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM),
    )
    _measure(
        "decrypt_1KB (hybrid suite 0x06)",
        ITERS_DEC_1KB,
        lambda: tessera_seal.decrypt(env_1kb_h, priv_h, expected_ad=b""),
    )


if __name__ == "__main__":
    main()
