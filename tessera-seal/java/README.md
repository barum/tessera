# tessera-seal/java

Java reference implementation of TesseraSeal v1.

**Status:** v1.1 placeholder.

Authoritative spec: [../latex/](../latex/) and the built `../latex/TesseraSeal_Whitepaper.pdf`.

Dependencies (planned): [BouncyCastle 1.79+](https://www.bouncycastle.org/releasenotes.html) — FIPS-certified ML-KEM (CMVP cert #4801). Side-channel posture for BC ML-KEM must be verified at port time per the security checklist; if BC's constant-time guarantees are insufficient, `liboqs-jni` is the fallback.
