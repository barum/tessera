#!/usr/bin/env python3
"""Interop, encrypt side: keypair from seed, encrypt with TesseraID-as-AD.

Emits four hex lines: keypair seed, AD (a TesseraID), envelope, plaintext.
The Go side (../go/interop) derives the same keypair from the seed,
decrypts the envelope under the same AD, and asserts the plaintext.
"""
import os

import tessera_id
import tessera_seal

seed = os.urandom(64)                                # FIPS 203 d || z
priv, pub = tessera_seal.generate_keypair_from_seed(seed)
record_id = tessera_id.new_hlc()
plaintext = b"sealed in Python, opened in Go"
envelope = tessera_seal.encrypt(plaintext, pub, associated_data=record_id)
assert tessera_seal.decrypt(envelope, priv, expected_ad=record_id) == plaintext

print(seed.hex())
print(record_id.hex())
print(envelope.hex())
print(plaintext.hex())
