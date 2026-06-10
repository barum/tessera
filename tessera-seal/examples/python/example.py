#!/usr/bin/env python3
"""TesseraSeal basics: keygen, encrypt, decrypt with TesseraID-as-AD.

Run from the repo root:
    PYTHONPATH=tessera-id/python:tessera-seal/python \
        python3 tessera-seal/examples/python/example.py
"""
import tessera_id
import tessera_seal

priv, pub = tessera_seal.generate_keypair()          # suite 0x01 (ML-KEM-1024 + AES-256-GCM)
record_id = tessera_id.new_hlc()                     # 41-byte TesseraID bound as AD
envelope = tessera_seal.encrypt(b"the plaintext", pub, associated_data=record_id)
plaintext = tessera_seal.decrypt(envelope, priv, expected_ad=record_id)
assert plaintext == b"the plaintext"

hdr = tessera_seal.peek_header(envelope)             # structural only — NOT authenticated
print(f"suite=0x{hdr.suite:02x} kem_ct_len={hdr.kem_ct_len} ad_len={hdr.ad_len}")

try:  # rebinding the envelope to a different TesseraID fails closed
    tessera_seal.decrypt(envelope, priv, expected_ad=tessera_id.new_hlc())
    raise SystemExit("AD mismatch must not decrypt")
except tessera_seal.DecryptionError:
    print("AD mismatch rejected (fail closed)")
