# tessera-seal/typescript

TypeScript reference implementation of TesseraSeal v1 (suites `0x01`/`0x02`; hybrid `0x06` is
v1.4 backlog, TSEAL-00032 — until it lands this port rejects `0x06` as `UnknownSuite`).

Authoritative spec: [../latex/](../latex/) and the built `../latex/TesseraSeal_Whitepaper.pdf`.
Authority order: whitepaper → `../python/tessera_seal.py` → `../c/tessera_seal.h` → this module.

Dependencies: [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) for
ML-KEM-1024, `@noble/ciphers` for AES-256-GCM + ChaCha20-Poly1305, `@noble/hashes` for
SHAKE-256 / HMAC-SHA3-256 / HKDF-SHA3-256.

## Build and test

```bash
cd tessera-seal/typescript
npm install
npm test        # tsc && node --test dist/test_tessera_seal.js
```

The test suite consumes the shared KAT vectors under `../conformance/vectors/`.

## Error taxonomy

All errors extend `TesseraSealError`. Structural errors are distinguishable; every
authentication-class failure collapses into the single `DecryptionError` (no
distinguishing oracle).

| Class | Kind | Thrown when |
|-------|------|-------------|
| `TesseraSealError` | base | Base class for every error below; also raised directly for malformed arguments (bad seed/key sizes). |
| `UnknownVariant` | structural | Header variant byte is not `0x04`. |
| `UnknownSuite` | structural | Suite byte is not an allocated suite (`0x01`, `0x02`). Includes hybrid `0x06` until the TSEAL-00032 port lands. |
| `InvalidLength` | structural | Truncated envelope, oversized AD/plaintext, header length fields out of range, timestamp overflow. |
| `BadKeyError` | structural | Suite/key consistency failure (whitepaper §2, §9 — `BAD_KEY`): `encrypt()` given a recipient public key whose `suite` tag does not match the requested suite, or `decrypt()` given a private key whose `suite` tag does not match the envelope header's suite. Checked **before any KEM/AEAD work**. Intentionally **not** a `DecryptionError` subclass — the check reads only the public suite byte, never secret-correlated bytes, so distinguishing it is safe. |
| `DecryptionError` | authentication | Every auth-class failure: bad AEAD tag, bad UtC commit tag, bad KEM ciphertext, AD mismatch, derived-nonce mismatch. One class, one code path, constant-time across causes. Never split this. |
