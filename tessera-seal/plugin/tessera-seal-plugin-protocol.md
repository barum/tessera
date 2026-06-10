# tessera-seal plugin protocol — v1 scaffold

> **Status:** scaffold (PQCK-00001). Full state machine, frame schemas, and error semantics land in PQCK-00008 alongside the reference `tessera-seal-plugin-file` implementation.

## Why a plugin protocol

TesseraSeal v1 deliberately does **not** specify a key-on-disk format in its core wire spec. Specifying one would mean choosing a passphrase KDF, wrapping cipher, version byte, and textual armor — each on a different aging clock than the wire format. The lesson from the age ecosystem (`age-plugin-yubikey`, `age-plugin-tpm`, `age-plugin-se`, `age-plugin-fido2`) is that key custody and key serialization belong to plugins.

TesseraSeal ships the protocol so plugin authors can build immediately, plus a reference plugin (`tessera-seal-plugin-file`) so the v1 spec is self-contained.

## Reference model

Modeled on the [C2SP age-plugin specification](https://github.com/C2SP/C2SP/blob/main/age-plugin.md). TesseraSeal's protocol diverges in two ways:

1. **Binary framing.** age-plugin uses an ASCII stanza grammar. TesseraSeal uses length-prefixed binary frames because TesseraSeal envelopes are themselves binary; an ASCII intermediate buys nothing.
2. **Per-envelope file-key wrap.** The library generates the per-envelope file-key (the ML-KEM-1024 ephemeral or session material) and asks the plugin to wrap it. The plugin owns the long-term private key; the library owns the envelope structure.

## Wire format (frame-level, v1 draft)

All values big-endian.

```
Frame:
  4 bytes  length      (uint32; total length including type byte but not this length field)
  1 byte   type        (frame type tag)
  N bytes  body        (length - 1 bytes)
```

### Frame types (v1)

| Type | Direction | Name | Body |
|------|-----------|------|------|
| `0x01` | library → plugin | `RECIPIENT_STANZA` | Plugin name (UTF-8, length-prefixed) + recipient identifier payload |
| `0x02` | library → plugin | `WRAP_KEY`         | 32-byte file-key to wrap |
| `0x03` | library → plugin | `UNWRAP_KEY`       | Wrapped file-key (variable length, plugin-defined) |
| `0x10` | plugin → library | `OK`               | Response payload (e.g., wrapped or unwrapped file-key) |
| `0x11` | plugin → library | `ERROR`            | UTF-8 explanatory string, length-prefixed |
| `0x1F` | plugin → library | `DONE`             | (empty) — terminal frame |

## Recipient identifier URI form

```
tseal1<plugin-name>1<base64url-payload>
```

- `tseal1` — fixed prefix marking a TesseraSeal v1 recipient identifier.
- `<plugin-name>` — short kebab-case identifier matching the plugin binary's `tessera-seal-plugin-<name>` filename.
- `1` — separator.
- `<base64url-payload>` — plugin-defined recipient material. For `tessera-seal-plugin-file`, this is a fingerprint of the ML-KEM-1024 public key.

Example: `tseal1file1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` (placeholder).

## Plugin discovery

The library invokes `tessera-seal-plugin-<name>` via `exec`, searching `$PATH`. The library is responsible for ensuring the plugin binary it invokes is trusted; TesseraSeal v1 does not specify a plugin-trust mechanism.

## Reference plugin: `tessera-seal-plugin-file`

Passphrase-wrapped private key on disk.

### Key generation

1. Generate an ML-KEM-1024 keypair (`pk`, `sk`).
2. Read a passphrase from the terminal (no echo) or from `$TESSERA_SEAL_PASSPHRASE`.
3. Derive a 32-byte symmetric key: `K_wrap = Argon2id(passphrase, salt=CSPRNG(16), m=64MiB, t=3, p=1, 32 bytes)`.
4. Wrap: `wrapped = AES-256-GCM-Encrypt(K_wrap, nonce=CSPRNG(12), plaintext=sk, aad=header || kdf_block)`.
5. Serialize (current write format, v1.1 + KDF block):
   ```
   tseal-key-v1.1
   <base64url(salt[16] || nonce[12] || pk[1568] || wrapped[3168] || tag[16] || kdf_block[13])>
   ```
   Two lines, trailing newline. File extension `.tseal-key`.

### Keyfile KDF block (TSEAL-00040)

The trailing 13-byte KDF block makes the passphrase-KDF choice **explicit and
authenticated** instead of environment-dependent:

```
kdf_block = kdf_id[1] || p0[4] || p1[4] || p2[4]      (big-endian)
  kdf_id 0x01 = Argon2id            (p0 = memory_kib, p1 = time_cost, p2 = parallelism)
  kdf_id 0x02 = PBKDF2-HMAC-SHA-512 (p0 = iterations, p1 = p2 = 0)
```

Rules:

- **Wrap fails closed.** If `argon2-cffi` is unavailable, `keygen` refuses to
  write a keyfile unless the caller explicitly opts in with `--allow-pbkdf2`
  (`allow_pbkdf2=True` in the API). No environment variable can enable the
  fallback — silent Argon2id→PBKDF2 downgrade is not possible.
- **Unwrap selects the KDF from the file, never from the environment.** A
  keyfile whose block names Argon2id hard-fails when `argon2-cffi` is missing;
  it is never silently retried under another KDF.
- The KDF block is bound into the AES-256-GCM AAD (`header || kdf_block`), so
  on-disk tampering with the KDF id or params fails the wrap tag.
- Parsers cap the block's cost parameters (≤ 4 GiB Argon2id memory, ≤ 1024
  time_cost, ≤ 64 lanes, ≤ 1e8 PBKDF2 iterations) so a forged keyfile cannot
  drive resource exhaustion.
- **Backward compatibility:** `tseal-key-v1` files and KDF-block-less
  `tseal-key-v1.1` files (distinguished by exact blob length) still unwrap via
  the legacy derive path (Argon2id preferred, warned PBKDF2 fallback). New
  keyfiles always carry the block.

### Key use (during encrypt / decrypt)

- On `WRAP_KEY`: the plugin computes a recipient-specific wrap of the per-envelope file-key under the ML-KEM-1024 public key (or, for symmetric-only test cases, under a derived key from the private key file). Returns the wrapped file-key in an `OK` frame.
- On `UNWRAP_KEY`: the plugin loads its private key file, prompts for the passphrase, derives `K_wrap`, unwraps the long-term `sk`, then unwraps the per-envelope file-key using `sk`. Returns the file-key in an `OK` frame.

The reference plugin is NOT part of the v1 normative wire format; only the **protocol** is. Other plugins (`tessera-seal-plugin-yubikey`, hypothetical) may wrap keys however they like.

## What this protocol does NOT cover

- Key custody (HSM, secure enclave, TPM): plugin author's job.
- Key rotation: a higher-level concern; envelopes are self-contained.
- Plugin trust attestation: TesseraSeal invokes whichever plugin binary the caller's `$PATH` resolves.
- Network plugins: in-scope, but the v1 reference plugin is local-only.

## Tracking

- **PQCK-00008** — full state machine + reference `tessera-seal-plugin-file` implementation.
- **PQCK-00011** — conformance vectors for the plugin protocol.
