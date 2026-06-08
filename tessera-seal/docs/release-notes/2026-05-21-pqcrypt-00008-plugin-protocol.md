# PQCK-00008 — Plugin protocol + reference `pqcrypt-plugin-file`

**Date:** 2026-05-21
**Ticket:** PQCK-00008
**Type:** feat

## Summary

Implement the **PQCrypt plugin wire protocol** specified in whitepaper §11 and the operator-facing `pqcrypt/plugin/pqcrypt-plugin-protocol.md`. Ship the reference plugin **`pqcrypt-plugin-file`** which stores a passphrase-wrapped ML-KEM-1024 private key on disk under the `.pqck-key-v1` format (Argon2id + AES-256-GCM, with PBKDF2-HMAC-SHA-512 fallback).

The plugin protocol decouples key custody from the core wire spec: the PQCrypt library never sees long-term private keys directly; it invokes a plugin binary via `exec(2)` and exchanges length-prefixed binary frames over stdin/stdout. Future plugins for YubiKey, TPM, Secure Enclave, and FIDO2 can be added without touching the library.

## Wire/API changes

No wire-format change to PQCrypt envelopes. Two new artifacts:

### Frame protocol (`pqcrypt/plugin/protocol.py`)

Length-prefixed binary frames:
```
4 bytes  uint32 big-endian length (covers type byte + body)
1 byte   uint8  frame type
N bytes         body (length - 1 bytes)
```

Frame types (v1):

| Tag | Direction | Name | Body |
|-----|-----------|------|------|
| 0x01 | library→plugin | `RECIPIENT_STANZA` | plugin name + recipient payload |
| 0x02 | library→plugin | `WRAP_KEY` (reserved, not impl in v1) | per-envelope file-key to wrap |
| 0x03 | library→plugin | `UNWRAP_KEY` | 1568-byte ML-KEM-1024 ciphertext to decapsulate |
| 0x10 | plugin→library | `OK` | success payload (e.g., 32-byte shared secret) |
| 0x11 | plugin→library | `ERROR` | UTF-8 explanatory string |
| 0x1F | plugin→library | `DONE` | terminal (empty body) |

Max frame body: 16 MiB. Frame parser surfaces `ProtocolError` on truncation, length-prefix overflow, or unknown frame types.

### Recipient URI form

```
pqck1<plugin-name>1<base64url-payload>
```

Example: `pqck1file1AAAAAAAAAAAAAAAAAAAA...` (payload is plugin-defined; for `pqcrypt-plugin-file` it's the 1568-byte ML-KEM-1024 public key).

### Key file format (`.pqck-key-v1`)

Two-line ASCII file (mode 0600 on `keygen`):

```
pqck-key-v1
<base64url( salt[16] || nonce[12] || wrapped_sk[3168] || aead_tag[16] )>
```

Where `wrapped_sk = AES-256-GCM-Encrypt(K_wrap, nonce, sk, aad="pqck-key-v1")` and `K_wrap = Argon2id(passphrase, salt, m=64 MiB, t=3, p=1, 32 bytes)`.

If `argon2-cffi` is not installed, the reference plugin falls back to PBKDF2-HMAC-SHA-512 with 600 000 iterations and prints a stderr warning. Production deployments SHOULD install argon2-cffi.

### Reference plugin commands

```bash
pqcrypt-plugin-file keygen --out FILE     # prompt passphrase, generate + wrap key
pqcrypt-plugin-file pubkey --in FILE      # (placeholder; v1.1 adds pk-in-keyfile)
pqcrypt-plugin-file serve  --in FILE      # plugin-protocol loop on stdin/stdout
```

The library invokes the `serve` mode via `exec("pqcrypt-plugin-file", "serve", "--in", path)`.

### Files added

| File | Purpose |
|------|---------|
| `pqcrypt/plugin/protocol.py` | Frame read/write + recipient URI parse (~120 LoC) |
| `pqcrypt/plugin/pqcrypt_plugin_file.py` | Reference plugin (`keygen`, `pubkey`, `serve` subcommands) |

The previously-shipped `pqcrypt/plugin/pqcrypt-plugin-protocol.md` (PQCK-00001 scaffold) remains the operator-facing spec.

## Migration guidance

Not applicable — first plugin release. Plugin authors implement against `protocol.py` (Python) or port the frame protocol to their language; the wire protocol is what matters, not the helper library.

## Test plan

Five smoke tests, all PASS:

1. **Frame round-trip**: `write_frame(OK, "hello") → read_frame() → matches`.
2. **Recipient URI parse**: `RecipientId(plugin="file", payload=b"\x00\x01\x02").encode() → "pqck1file1AAEC"` → parses back.
3. **Key file serialize**: 4296-byte file produced by `keygen` from a 3168-byte sk; round-trips through `KeyFile.parse()`.
4. **Wrap/unwrap**: encrypt sk → decrypt sk → byte-identical.
5. **End-to-end serve mode**: library produces a PQCrypt envelope, extracts its 1568-byte `KEM_CT`, feeds it as an `UNWRAP_KEY` frame to a subprocess plugin server. Plugin reads frame, unwraps key file with passphrase, calls `MLKem1024.decaps(sk, kem_ct)`, returns 32-byte shared secret in an `OK` frame. The library's in-process decapsulation of the same `KEM_CT` produces the identical shared secret.

```bash
$ python3 -c "...run the 5 smoke tests..."
✓ frame round-trip
✓ recipient URI round-trip: pqck1file1AAEC
✓ key file serialized: 4296 bytes
✓ key wrap + unwrap round-trip
✓ plugin serve UNWRAP_KEY round-trip
ALL PLUGIN SMOKE TESTS PASS
```

## Rollback

`git rm pqcrypt/plugin/protocol.py pqcrypt/plugin/pqcrypt_plugin_file.py`. The `.gitignore` and other surfaces are unchanged. No library code depends on the plugin protocol yet; the library's in-process encrypt/decrypt path is unaffected.

## Security considerations

- **OS CSPRNG only** for salt + nonce (`secrets.token_bytes`).
- **Argon2id with whitepaper-specified parameters** (m=64 MiB, t=3, p=1). PBKDF2-HMAC-SHA-512 (600 k iterations) fallback is documented as a stopgap; production callers install `argon2-cffi`.
- **AES-256-GCM with AAD = "pqck-key-v1"** binds the key wrap to its format identifier; tampering with the header byte invalidates the tag.
- **Key file mode 0600** set by `keygen`.
- **Passphrase via getpass (no echo)** or `PQCRYPT_PASSPHRASE` env var.
- **Best-effort sk zeroize on plugin exit** (`bytearray` overwrite in a `finally` block). Python's memory model makes this hollow but it's better than nothing.
- **`WRAP_KEY` frame is reserved, not implemented in v1.** The library's in-process encrypt path uses the recipient public key directly without involving a plugin; `WRAP_KEY` is for future plugins that interpose on encrypt (e.g., to log every encryption to a hardware key).
- **Frame size cap of 16 MiB** protects against DoS via giant length-prefix.
- **Recipient URI parse rejects non-alphanumeric plugin names** (alphanumeric + `-` only).

## Known limitations (deferred to v1.1)

- `pubkey --in FILE` cannot currently re-derive the pk from sk; the v1 keyfile format does not store pk alongside sk. A v1.1 keyfile format adds a third field (`pk[1568]`) so `pubkey` becomes a clean read.
- `WRAP_KEY` not implemented in the reference plugin.
- Only the Python helper library is shipped; Go/Rust/C plugin-protocol helpers are deferred to v1.1+ (the wire protocol is portable; the helpers are convenience only).

## Linked PRs / tickets

- **Depends on:** PQCK-00001 (scaffold), PQCK-00003 (Python pqcrypt module).
- **Spec source:** whitepaper §11, `pqcrypt/plugin/pqcrypt-plugin-protocol.md`.
- **Unblocks:** community plugins for YubiKey, TPM, Secure Enclave, FIDO2; PQCK-00009 (conformance harness extension); future v1.1 work on the keyfile format.
