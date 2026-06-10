# tessera-id/java

Java reference implementation of TesseraID — the 41-byte sortable identifier (Standard `0x01` + HLC `0x02`
variants). The whitepaper at [../latex/](../latex/) is normative; the Python reference at
[../python/tessera_id.py](../python/tessera_id.py) is the readable canonical source. Stdlib only
(`SecureRandom` for the 32-byte CSPRNG tail); no third-party dependencies. JDK 17+.

## Build / test / bench

```bash
cd tessera-id/java
make test     # raw-javac build + test runner (the historical path; still works)
make bench
```

## Install / consumption

The artifact is **publish-ready but not on Maven Central** — publication is gated on the name-clearance
decision ([docs/decisions/2026-06-10-name-clearance.md](../../docs/decisions/2026-06-10-name-clearance.md));
posture record: [docs/decisions/2026-06-10-distribution-posture.md](../../docs/decisions/2026-06-10-distribution-posture.md).
Build the jar locally from the Maven pom (TESS-00014):

```bash
cd tessera-id/java
mvn -q package -DskipTests           # → target/tessera-id-1.3.1.jar
```

Consume it as a local jar (`--class-path target/tessera-id-1.3.1.jar`), or install it into your local
repository for Maven/Gradle builds:

```bash
mvn -q install -DskipTests           # coordinates: com.tessera:tessera-id:1.3.1
```
