# TesseraSeal v1 — Side-channel disclaimer

TesseraSeal v1 makes specific, narrow claims about what it defends against and what it does not. Read this before
deploying.

## What v1 mitigates

**Software-timing side channels.** TesseraSeal pins one verified, constant-time third-party ML-KEM-1024
implementation per language ([whitepaper §5](../latex/sec05_mlkem_binding.tex)); nothing cryptographic is vendored
into this repository except the Keccak/SHAKE-256 primitive (under `common/`). The pinned sources, matching the
authoritative table in [tessera-seal/CLAUDE.md](../CLAUDE.md):

| Language | ML-KEM-1024 source (pinned) | Notes |
|----------|------------------------------|-------|
| Python | `kyber-py ≥ 1.0` (NCC Group audit, Q2 2024) | Renamed to ML-KEM at the binding layer. Chosen for spec readability and KAT generation — the Python reference is the readable canonical source, **not a hardened production path**. |
| C | **OpenSSL 3.5+ `EVP_PKEY` ML-KEM** (encapsulate/decapsulate) | *Not* `mlkem-native` (named in an earlier revision of this document; never shipped). |
| Go | **stdlib `crypto/mlkem`** (Go 1.26+) | *Not* `filippo.io/mlkem` (named in an earlier revision; never shipped). |
| Rust | RustCrypto [`ml-kem` 0.3](https://github.com/RustCrypto/KEMs/tree/master/ml-kem) | `#![forbid(unsafe_code)]`. |
| C++ | wraps the C library | Inherits OpenSSL. |
| TypeScript | `@noble/post-quantum` | Constant-time documented; pure JS. |
| Java | SunJCE JEP 452 (JDK 24+) | *Not* BouncyCastle. |
| CPython ext | wraps the C reference | Inherits OpenSSL. |

X25519 sources for the hybrid suite `0x06` (hybrid-capable languages only): `x25519-dalek` 2 (Rust), stdlib
`crypto/ecdh` (Go), `cryptography` (Python).

AEAD tag and UtC commitment tag verification are constant-time `memcmp`-equivalents in every language. On
**authentication-class** failure paths (bad AEAD tag, bad commit tag, KEM implicit-reject, AD mismatch) the decrypt
routine runs the synthetic-key schedule — the HKDF derivations against a zero PRK, results discarded — as a timing
pad; the Python reference additionally executes a synthetic AEAD verify on the KEM-decaps-failure path.
**Structural** errors (invalid length, unknown variant/suite, BadKey suite mismatch) may return early: they are
caller errors, distinguishable by design, and their detection touches no per-key secret-correlated bytes
(whitepaper §9.2).

**Timing posture, honestly stated.** An automated timing-histogram script ships at
[`tools/scripts/timing-histogram.py`](../../tools/scripts/timing-histogram.py) (TSEAL-00048) and runs in the
manual `tessera-seal.yml` dispatch; it is **not yet a blocking PR gate**. It measures N good-vs-bad decrypt pairs
against the Python reference (warn > 50 ns / hard-fail > 500 ns on the median per-pair delta) and emits a JSON
artifact for cross-run trend tracking — on contended hosts single-run medians wander in the ±1 µs band, so read
the artifact as a trend point. The most recent **manual** measurement (Python reference, 2026-05-19, Apple M4 Max,
quiet host) observed a median good-vs-bad decrypt difference under 50 ns over 100,000 pairs — see
[security-audit-v1.2.md](security-audit-v1.2.md) open item #1 (the script addresses the automation half of that
item; promotion to a blocking CI gate remains open), and [`tessera-seal/benchmarks/`](../benchmarks/) for
per-language measurement environments. No timing dataset or timing assertion exists under `conformance/vectors/`
— the regression is a script, not a conformance vector.

The single `DecryptionError` (`TESSERA_SEAL_E_DECRYPT_FAILED`) class for every authentication-class failure (bad
AEAD tag, bad commit tag, bad KEM ciphertext, AD mismatch, unknown variant in a decrypted internal blob) prevents
distinguishing-oracle attacks at the API surface.

## What v1 does NOT mitigate

> **Constant-time is not constant-power.**

TesseraSeal v1 does not defend against any of the following classes of attack:

- **Power analysis (SPA/DPA).** PQShield demonstrated single-trace SPA recovery of ML-KEM secrets on Cortex-M4 with under 1000 traces ([PQShield 2024](https://pqshield.com/blog/power-side-channel-ml-kem)). SPA-CCA on unmasked ML-KEM with a single trace was demonstrated by Guo, Johansson, and Yang ([eprint 2024/2051](https://eprint.iacr.org/2024/2051)). Masked implementations exist (e.g. `mlkem-native`'s masking branch) but no library pinned by v1 enables masking.
- **Electromagnetic emanation (EM).** Same physical-access threat model as power analysis.
- **Frequency-scaling / DVFS side channels.** Hertzbleed ([Wang et al. 2022](https://www.hertzbleed.com/)) demonstrated that DVFS turns power-side-channels into remote timing attacks on x86. TesseraSeal v1 does not pin clock frequencies and does not defend against this class.
- **Memory-prefetcher side channels.** GoFetch ([Chen et al. 2024](https://gofetch.fail/)) demonstrated that the Apple M1–M3 DMP (data memory-dependent prefetcher) leaks secrets across nominally constant-time code. Affects all macOS/iOS-hosted callers without architectural mitigations.
- **Architectural exploits.** Spectre/Meltdown-class transient-execution attacks, Plundervolt-class voltage manipulation, Row Hammer-class memory attacks, and shared-cache attacks (Flush+Reload, Prime+Probe) are out of scope.
- **Implementation correctness in non-pinned libraries.** If you swap one of the pinned ML-KEM implementations for a different library, you take on whatever side-channel posture that library has. TesseraSeal makes no claim about non-pinned choices.

## Recommended posture by threat model

| Threat | Recommendation |
|--------|----------------|
| Network-only adversary on the same VPC / LAN | v1 is sufficient. |
| Network-only adversary with arbitrary path observation | v1 is sufficient. |
| Multi-tenant shared host (cloud VM neighbors) | v1 mitigates the AEAD timing and ML-KEM software-timing paths. Hertzbleed-class DVFS attacks are not mitigated; consider disabling Turbo / pinning frequency on the deploying host. |
| Co-located untrusted process (shared CPU cache) | Not recommended. Consider running TesseraSeal in an isolated VM, or wait for a future suite with masked ML-KEM. |
| Physical access (smart card, embedded device, hostile lab) | Not recommended for v1. Use masked ML-KEM (out of v1 scope) and hardware-isolated key custody. |

## The honest framing

TesseraSeal v1's primary defense is *cryptographic*: it ensures that an attacker who recovers your envelope from
the wire cannot decrypt it without your ML-KEM-1024 private key (and, for hybrid suite `0x06`, the X25519 long-term
scalar). v1 is appropriate for envelope-at-rest and envelope-in-transit scenarios where the threat model is
computational, not physical-access.

For physical-access threats, you need additional layers: hardware-isolated key custody (HSM, secure enclave),
constant-power cryptographic cores, and side-channel-aware ML-KEM implementations (which TesseraSeal may pin in a
future suite byte).

## Forward path

A future **suite byte** (drawn from the reserved-future suite range; `0x06` is taken by hybrid) is expected to pin
a masked ML-KEM-1024 implementation as mandatory for "high-assurance" deployments. The suite-byte allocation
discipline ([whitepaper appendix C](../latex/sec14_appendices.tex)) supports this without breaking v1 envelopes.

## References

- KyberSlash 1 & 2: <https://kyberslash.cr.yp.to/>
- PQShield power-side-channel disclosure: <https://pqshield.com/blog/power-side-channel-ml-kem>
- SPA-CCA on ML-KEM (Guo, Johansson, Yang): <https://eprint.iacr.org/2024/2051>
- Hertzbleed: <https://www.hertzbleed.com/>
- GoFetch: <https://gofetch.fail/>
- Intel DOIT guidance: <https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-operand-independent-timing-isa-guidance.html>
- TesseraSeal internal audit notes: [security-audit-v1.2.md](security-audit-v1.2.md)
