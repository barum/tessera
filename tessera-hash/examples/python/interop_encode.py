#!/usr/bin/env python3
"""Interop, encode side: hash a fixed content at a fixed (ts, counter).

The Go side (../go/interop) decodes the Crockford line, verifies the tail
against the same content, recomputes the hash at the same (ts, counter),
and asserts byte-identity.
"""
import tessera_hash

CONTENT = b"tessera-hash cross-language interop payload"
TS_MS = 1_750_000_000_000
COUNTER = 7

h = tessera_hash.hash_at(CONTENT, TS_MS, COUNTER)
print(tessera_hash.encode_b32(h))
