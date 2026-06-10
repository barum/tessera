# tessera-hash/java

Java reference implementation of TesseraHash — the 73-byte SHAKE-256 content hash format (variant `0x03`).
The whitepaper at [../latex/](../latex/) is normative; the Python reference at
[../python/tessera_hash.py](../python/tessera_hash.py) is the readable canonical source.

SHAKE-256 comes from the shared Java Keccak in [../../common/java/](../../common/java/) (compiled in by
both the Makefile and the Maven build via `build-helper-maven-plugin` — never re-vendored inside this
project, per the umbrella supply-chain invariants). No third-party dependencies. JDK 17+.

## Build / test

```bash
cd tessera-hash/java
make build
make test
```

## Install / consumption

The artifact is **publish-ready but not on Maven Central** — publication is gated on the name-clearance
decision ([docs/decisions/2026-06-10-name-clearance.md](../../docs/decisions/2026-06-10-name-clearance.md));
posture record: [docs/decisions/2026-06-10-distribution-posture.md](../../docs/decisions/2026-06-10-distribution-posture.md).
Build the jar locally from the Maven pom (TESS-00014):

```bash
cd tessera-hash/java
mvn -q package -DskipTests           # → target/tessera-hash-1.3.1.jar
```

Consume it as a local jar (`--class-path target/tessera-hash-1.3.1.jar`), or install it into your local
repository for Maven/Gradle builds:

```bash
mvn -q install -DskipTests           # coordinates: com.tessera:tessera-hash:1.3.1
```
