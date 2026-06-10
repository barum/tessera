# TesseraSeal interim chunking recipe (large payloads)

**Status: interim guidance.** TesseraSeal v1 is a deliberately single-shot envelope: one `encrypt()` call, one
plaintext ≤ 2³² bytes (4 GiB), no streaming API, and the reference CLI **buffers whole files in memory** for both
`encrypt` and `decrypt`. A native streaming envelope is a v2 work item; until it ships, this document is the
supported pattern for payloads that are too large to buffer (or that must be processed incrementally).

This recipe composes only shipped, normative v1 primitives — it introduces no new wire format. Every chunk is an
ordinary TesseraSeal envelope that any conforming implementation can decrypt.

## The pattern: envelope-per-chunk with position-binding AD

Split the plaintext into fixed-size chunks (e.g. 64 MiB) and seal each chunk as its own envelope, binding the
chunk's identity and position into the AEAD's associated data:

```
AD = TesseraID (41 bytes) || chunk_index (8 bytes, big-endian) || chunk_total (8 bytes, big-endian)
```

- **TesseraID** — one fresh 41-byte TesseraID for the whole file (the canonical TesseraID-as-AD routing pattern).
  All chunks of one file share it; chunks of different files can never be mixed.
- **chunk_index** — 0-based position of this chunk, 8-byte big-endian unsigned integer.
- **chunk_total** — total number of chunks in the file, 8-byte big-endian unsigned integer, identical in every
  chunk's AD.

The 57-byte AD is far below the 65 536-byte `AD_LEN` cap. Because AD is authenticated by the AEAD and bound into
the UtC commitment, any reorder, drop, duplicate, cross-file splice, or truncation attempt changes the AD the
receiver reconstructs and fails decryption with the single auth-class `DecryptionError`.

### Why this is safe under v1's guarantees

- **Fresh `K_session` per chunk.** Every `encrypt()` call performs its own ML-KEM-1024 encapsulation, so every
  chunk gets an independent session key. The deterministic AEAD nonce (HKDF-Expand from `K_session`) stays safe
  for exactly the reason it is safe for single envelopes: one key, one nonce, one message. Never try to reuse one
  envelope's key material across chunks.
- **`CTR` stays monotonic per sender.** Use a `SenderContext` (Python/Go/Rust/TS) or otherwise increment the
  16-bit header counter across chunks. The counter is provenance — uniqueness comes from the KEM — but monotonic
  counters preserve the same-sender ordering signal and match the spec's sender discipline.
- **chunk_total seals the length.** A truncated file is detectable without trusting the transport: the receiver
  knows from any single chunk how many chunks must exist.

## Sender procedure

1. Generate one TesseraID for the file (`tessera_id.new()` or `new_hlc()`).
2. Compute `chunk_total = ceil(file_size / chunk_size)` (use `chunk_total = 1` for an empty file and seal one
   empty chunk).
3. For each `chunk_index` in `0 .. chunk_total - 1`, with a single `SenderContext`:
   `envelope_i = encrypt(chunk_i, recipient_pub, ad = tessera_id || be64(chunk_index) || be64(chunk_total))`.
4. Store/transmit the envelopes plus the file's TesseraID (the AD is also readable from each envelope via
   `peek_ad()` — cleartext on wire, attacker-controlled until decrypt authenticates it).

```python
import struct
import tessera_id
import tessera_seal

CHUNK = 64 * 1024 * 1024
file_id = tessera_id.new()
chunks = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)] or [b""]
sender = tessera_seal.SenderContext()
envelopes = [
    sender.encrypt(chunk, pub, associated_data=file_id + struct.pack(">QQ", i, len(chunks)))
    for i, chunk in enumerate(chunks)
]
```

## Receiver procedure: verify-then-assemble

Never append plaintext to the output file before the chunk's envelope has authenticated. The safe order is:

1. Learn `tessera_id` and `chunk_total` from the first successfully **decrypted** chunk (peeked AD values are
   unauthenticated hints only).
2. For each expected `chunk_index`, decrypt with the reconstructed
   `expected_ad = tessera_id || be64(chunk_index) || be64(chunk_total)`. A chunk presented out of position fails
   here — the envelope's bound index disagrees with the expected one.
3. Reject the whole file if any chunk fails, is missing, or arrives twice with different bytes. Do not deliver
   partial plaintext to the application.
4. Assemble in index order only after all `chunk_total` chunks have authenticated (decrypt-to-temp-then-rename,
   or hold the plaintext chunks until the set is complete).

```python
plain = [None] * total
for env in envelopes:
    for idx in range(total):                       # or index envelopes externally
        try:
            ad = file_id + struct.pack(">QQ", idx, total)
            plain[idx] = tessera_seal.decrypt(env, priv, expected_ad=ad)
            break
        except tessera_seal.DecryptionError:
            continue
data = b"".join(plain)                             # only after every slot is filled
```

(In practice transports carry the index alongside the envelope — the loop above is the paranoid form; either way
the *authenticated* AD is what places a chunk, never the transport's claim.)

## What this recipe does NOT give you

- **No single commitment over the whole file.** Each chunk is individually key-committing, but there is no
  cross-chunk commitment tag. If you need one, hash the file (e.g. a TesseraHash) and verify it after assembly.
- **No constant-memory CLI today.** The reference `tessera-seal` CLI still buffers `--in`/stdin entirely; this
  recipe is a library-level pattern. CLI chunking support is backlog alongside v2 streaming.
- **No resumable/partial-read semantics.** Verify-then-assemble means the application sees all-or-nothing.

## Related reading

- [../README.md](../README.md) — CLI usage and the whole-file buffering note.
- [side-channel-disclaimer.md](side-channel-disclaimer.md) — timing posture, unchanged by chunking.
- [../CLAUDE.md](../CLAUDE.md) — hard invariants (deterministic nonce, single `DecryptionError` class,
  TesseraID-as-AD canonical pattern) that this recipe builds on.
