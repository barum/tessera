# tessera-seal/java

Java reference implementation of TesseraSeal v1 (suites `0x01` ML-KEM-1024 + AES-256-GCM and
`0x02` ML-KEM-1024 + ChaCha20-Poly1305, each with the 32-byte UtC commitment tag). Hybrid suite
`0x06` is not ported yet (TSEAL-00033 backlog); it is rejected as `UnknownSuite`.

Authoritative spec: [../latex/](../latex/) and the built `../latex/TesseraSeal_Whitepaper.pdf`.

**Dependencies:** none. JDK 24+ stdlib only — `javax.crypto.KEM` ML-KEM-1024 (JEP 452, SunJCE),
AES/GCM and ChaCha20-Poly1305 ciphers, SHA3-256/SHAKE256 digests, HmacSHA3-256. No BouncyCastle.

## Build and test

```bash
cd tessera-seal/java
make build   # compile TesseraSeal.java into build/
make test    # compile + run TesseraSealTest (self-contained tests + KAT consumption)
```

## Install / consumption

The artifact is **publish-ready but not on Maven Central** — publication is gated on the name-clearance
decision ([docs/decisions/2026-06-10-name-clearance.md](../../docs/decisions/2026-06-10-name-clearance.md));
posture record: [docs/decisions/2026-06-10-distribution-posture.md](../../docs/decisions/2026-06-10-distribution-posture.md).
Build the jar locally from the Maven pom (TESS-00014; requires JDK 24+ for JEP 452 ML-KEM):

```bash
cd tessera-seal/java
mvn -q package -DskipTests           # → target/tessera-seal-1.3.1.jar
```

Consume it as a local jar (`--class-path target/tessera-seal-1.3.1.jar`), or install it into your local
repository for Maven/Gradle builds:

```bash
mvn -q install -DskipTests           # coordinates: com.tessera:tessera-seal:1.3.1
```

## Errors

All exceptions extend `TesseraSeal.TesseraSealError`:

- `UnknownVariant` / `UnknownSuite` / `InvalidLength` — structural header failures.
- `BadKey` — suite/key consistency failure (TSEAL-00038): `encrypt()` rejects when
  `pub.suite != requested suite`; `decrypt()` rejects when `priv.suite != header.suite`.
  Structural, raised before any KEM work; deliberately distinct from the auth class.
- `DecryptionError` — the single class for every authentication-class failure
  (bad AEAD tag, bad commit tag, bad KEM ciphertext, AD mismatch). No distinguishing oracle.
