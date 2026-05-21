# pqcrypt

**Pure post-quantum encryption envelope** with byte-identical polyglot reference implementations under the [pqtoolkit](../) monorepo.

PQCrypt is the third project in the pqtoolkit family, alongside [pqid](../pqid/) (post-quantum-era identifier) and [pqhash](../pqhash/) (SHAKE-256 content hash). It owns variant byte `0x04`.

## What it does

Wraps a plaintext into an envelope that **only the intended recipient's ML-KEM-1024 private key can open**, with:

- **One suite, no negotiation**: ML-KEM-1024 + AES-256-GCM + 32-byte UtC commitment tag + HKDF-SHA3-256.
- **Pure post-quantum**: no X25519 hybrid, no classical fallback. Residual risk acknowledged explicitly in the [whitepaper appendix](latex/sec14_appendices.tex).
- **Key-committing**: multi-recipient confusion attacks (the class age still has open) are closed by the UtC tag.
- **PQID-as-AD pattern**: bind a 41-byte PQID as the AEAD's associated data; envelopes fail closed if rebound to a different PQID.
- **Plugin protocol**: key-on-disk format lives in plugins (à la age), not in the core spec. Reference plugin `pqcrypt-plugin-file` ships in v1.

## v1 alpha status

Whitepaper LaTeX scaffold complete (this PR, PQCK-00001). Reference implementations follow:

| Language | Status | Tracking |
|----------|--------|----------|
| Python   | scaffold | PQCK-00003 |
| C        | scaffold | PQCK-00005 |
| Go       | scaffold | PQCK-00006 |
| Rust     | scaffold | PQCK-00007 |
| C++, TypeScript, Java, CPython ext | placeholders | v1.1+ |

## Wire format at a glance

```
Offset  Size  Field                                               AD?
0       6     TS         (timestamp_ms; provenance, not auth)     yes
6       1     VAR        (0x04 = PQCrypt v1)                      yes
7       1     SUITE      (0x01 = ML-KEM-1024 + AES-256-GCM + UtC) yes
8       2     CTR        (counter, monotonic per sender)          yes
10      2     KEM_CT_LEN (≤ 4096)                                   yes
12      4     AD_LEN     (≤ 65536)                                   yes
16      N     KEM_CT     (ML-KEM-1024 ciphertext = 1568 B for suite 0x01)
16+N    A     AD         (caller AD; the canonical pattern is a PQID)
16+N+A  12    AEAD_NONCE (derived from K_session via HKDF-Expand; deterministic)
…       M     AEAD_CT
…       16    AEAD_TAG   (128-bit AES-256-GCM tag)
…       32    COMMIT     (UtC commitment tag, HMAC-SHA3-256)
```

Full normative spec: [latex/sec03_wire_format.tex](latex/sec03_wire_format.tex).

## Read this first

- [latex/PQCrypt_Whitepaper.pdf](latex/PQCrypt_Whitepaper.pdf) — normative spec (built from LaTeX).
- [CLAUDE.md](CLAUDE.md) — project invariants for contributors.
- [docs/side-channel-disclaimer.md](docs/side-channel-disclaimer.md) — what v1 mitigates, what it does not.
- [docs/release-notes/CHANGELOG.md](docs/release-notes/CHANGELOG.md) — reverse-chronological release index.
- [plugin/pqcrypt-plugin-protocol.md](plugin/pqcrypt-plugin-protocol.md) — plugin wire protocol.

## Quick start (when ports land)

```python
import pqid, pqcrypt

priv, pub  = pqcrypt.generate_keypair(suite=pqcrypt.SUITE_MLKEM1024_AESGCM)
record_id  = pqid.new_hlc()
envelope   = pqcrypt.encrypt(b"hello", pub, associated_data=record_id)
plaintext  = pqcrypt.decrypt(envelope, priv, expected_ad=record_id)
assert plaintext == b"hello"
```

## License

Same as [the parent project](../LICENSE).
