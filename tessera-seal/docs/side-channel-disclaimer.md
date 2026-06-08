# TesseraSeal v1 — Side-channel disclaimer

TesseraSeal v1 makes specific, narrow claims about what it defends against and what it does not. Read this before deploying.

## What v1 mitigates

**Software-timing side channels.** TesseraSeal vendors constant-time ML-KEM-1024 implementations per language ([whitepaper §5](../latex/sec05_mlkem_binding.tex)):

- C: [mlkem-native](https://github.com/pq-code-package/mlkem-native) (PQ Code Package, Cryspen — formally verified parts).
- Rust: [RustCrypto `ml-kem`](https://github.com/RustCrypto/KEMs/tree/master/ml-kem).
- Go: [`filippo.io/mlkem`](https://github.com/FiloSottile/mlkem768).
- Python: `cryptography ≥ 45` if ML-KEM lands, else `kyber-py ≥ 1.0` (renamed to ML-KEM at the binding layer).

AEAD tag and UtC commitment tag verification are constant-time `memcmp`-equivalents in every language. The decrypt path executes the AEAD verify even on structural failures (truncated input, bad header magic) using a synthetic key derived from a zero PRK, to keep timing flat. The conformance harness ships a 100 000-pair timing-histogram regression that asserts the median good-vs-bad difference is under 50 ns on reference hardware (Apple M3 Max @ 4.05 GHz P-core).

The single `DecryptionError` (`TESSERA_SEAL_E_DECRYPT_FAILED`) class for every authentication-class failure (bad AEAD tag, bad commit tag, bad KEM ciphertext, AD mismatch, unknown variant in a decrypted internal blob) prevents distinguishing-oracle attacks at the API surface.

## What v1 does NOT mitigate

> **Constant-time is not constant-power.**

TesseraSeal v1 does not defend against any of the following classes of attack:

- **Power analysis (SPA/DPA).** PQShield demonstrated single-trace SPA recovery of ML-KEM secrets on Cortex-M4 with under 1000 traces ([PQShield 2024](https://pqshield.com/blog/power-side-channel-ml-kem)). SPA-CCA on unmasked ML-KEM with a single trace was demonstrated by Guo, Johansson, and Yang ([eprint 2024/2051](https://eprint.iacr.org/2024/2051)). Masked implementations exist in `mlkem-native`'s masking branch but are not the v1 default.
- **Electromagnetic emanation (EM).** Same physical-access threat model as power analysis.
- **Frequency-scaling / DVFS side channels.** Hertzbleed ([Wang et al. 2022](https://www.hertzbleed.com/)) demonstrated that DVFS turns power-side-channels into remote timing attacks on x86. TesseraSeal v1 does not pin clock frequencies and does not defend against this class.
- **Memory-prefetcher side channels.** GoFetch ([Chen et al. 2024](https://gofetch.fail/)) demonstrated that the Apple M1–M3 DMP (data memory-dependent prefetcher) leaks secrets across nominally constant-time code. Affects all macOS/iOS-hosted callers without architectural mitigations.
- **Architectural exploits.** Spectre/Meltdown-class transient-execution attacks, Plundervolt-class voltage manipulation, Row Hammer-class memory attacks, and shared-cache attacks (Flush+Reload, Prime+Probe) are out of scope.
- **Implementation correctness in non-vendored libraries.** If you swap one of the vendored ML-KEM implementations for a different library, you take on whatever side-channel posture that library has. TesseraSeal makes no claim about non-vendored choices.

## Recommended posture by threat model

| Threat | Recommendation |
|--------|----------------|
| Network-only adversary on the same VPC / LAN | v1 is sufficient. |
| Network-only adversary with arbitrary path observation | v1 is sufficient. |
| Multi-tenant shared host (cloud VM neighbors) | v1 mitigates the AEAD timing and ML-KEM software-timing paths. Hertzbleed-class DVFS attacks are not mitigated; consider disabling Turbo / pinning frequency on the deploying host. |
| Co-located untrusted process (shared CPU cache) | Not recommended. Consider running TesseraSeal in an isolated VM, or wait for v2 / suite `0x05+` with masked ML-KEM. |
| Physical access (smart card, embedded device, hostile lab) | Not recommended for v1. Use masked ML-KEM (out of v1 scope) and hardware-isolated key custody. |

## The honest framing

TesseraSeal v1's primary defense is *cryptographic*: it ensures that an attacker who recovers your envelope from the wire cannot decrypt it without your ML-KEM-1024 private key. v1 is appropriate for envelope-at-rest and envelope-in-transit scenarios where the threat model is computational, not physical-access.

For physical-access threats, you need additional layers: hardware-isolated key custody (HSM, secure enclave), constant-power cryptographic cores, and side-channel-aware ML-KEM implementations (which TesseraSeal may pin in a future suite byte).

## Forward path

A future suite byte (likely `0x05` or beyond) is expected to pin a masked ML-KEM-1024 implementation as mandatory for "high-assurance" deployments. The variant-byte allocation discipline ([whitepaper appendix B](../latex/sec14_appendices.tex)) supports this without breaking v1 envelopes.

## References

- KyberSlash 1 & 2: <https://kyberslash.cr.yp.to/>
- PQShield power-side-channel disclosure: <https://pqshield.com/blog/power-side-channel-ml-kem>
- SPA-CCA on ML-KEM (Guo, Johansson, Yang): <https://eprint.iacr.org/2024/2051>
- Hertzbleed: <https://www.hertzbleed.com/>
- GoFetch: <https://gofetch.fail/>
- Intel DOIT guidance: <https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-operand-independent-timing-isa-guidance.html>
