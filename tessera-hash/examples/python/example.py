#!/usr/bin/env python3
"""TesseraHash basics: hash content, verify, decode.

Run from the repo root:
    PYTHONPATH=tessera-hash/python python3 tessera-hash/examples/python/example.py
"""
import tessera_hash

content = b"the bytes I want a stable content identifier for"

h = tessera_hash.Generator().new(content)    # 73-byte TesseraHash (variant 0x03)
assert tessera_hash.verify(h, content)       # constant-time tail check
assert not tessera_hash.verify(h, b"tampered content")

b64 = tessera_hash.encode_b64(h)             # 98 chars, canonical wire text
b32 = tessera_hash.encode_b32(h)             # 117 chars, human-typable Crockford
assert tessera_hash.decode_b64(b64) == h
assert tessera_hash.decode_b32(b32) == h

fields = tessera_hash.decode(h)
print(f"hash={b64}")
print(f"variant=0x{fields.variant:02x} ts_ms={fields.timestamp_ms} counter={fields.counter}")
