#!/usr/bin/env python3
"""TesseraID basics: generate, encode, decode, sort.

Run from the repo root:
    PYTHONPATH=tessera-id/python python3 tessera-id/examples/python/example.py
"""
import tessera_id

ids = [tessera_id.new() for _ in range(3)]   # 41-byte Standard (variant 0x01) IDs
assert ids == sorted(ids), "IDs sort by generation order (time-ordered)"

b64 = tessera_id.encode_b64(ids[0])          # 55 chars, canonical wire text
b32 = tessera_id.encode_b32(ids[0])          # 66 chars, human-typable Crockford
assert tessera_id.decode_b64(b64) == ids[0]
assert tessera_id.decode_b32(b32) == ids[0]

fields = tessera_id.decode(ids[0])
print(f"id={b64}")
print(f"variant=0x{fields.variant:02x} ts_ms={fields.timestamp_ms} counter={fields.counter}")

hlc = tessera_id.new_hlc()                   # HLC variant (0x02) for distributed causality
print(f"hlc={tessera_id.encode_b64(hlc)}")
