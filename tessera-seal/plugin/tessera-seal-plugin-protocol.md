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
4. Wrap: `wrapped = AES-256-GCM-Encrypt(K_wrap, nonce=CSPRNG(12), plaintext=sk)`.
5. Serialize:
   ```
   tseal-key-v1
   <base64url(salt || nonce || wrapped || tag)>
   ```
   Two lines, trailing newline. File extension `.tseal-key`.

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
