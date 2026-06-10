#!/usr/bin/env python3
"""Interop, encode side: emit one Standard TesseraID in both text forms.

The Go side (../go/interop) decodes both lines and asserts they carry the
same 41 bytes — wire output generated in one language MUST decode
byte-identically in every other.
"""
import tessera_id

raw = tessera_id.new()
print(tessera_id.encode_b64(raw))
print(tessera_id.encode_b32(raw))
