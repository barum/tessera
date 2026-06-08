# tessera-seal/benchmarks

One `.txt` file per language, refreshed when a performance-relevant change lands. Format mirrors `tessera-id/benchmarks/` exactly: left-aligned operation name (~40 chars), right-aligned ops/sec, ns/op in parentheses.

**Status:** placeholder (PQCK-00001). Bench output lands per-language as each port completes (PQCK-00003+).

## Operations measured per language

| Operation | Target |
|-----------|--------|
| `keygen` | ML-KEM-1024 keypair generation |
| `encrypt_1KB` | Encrypt 1 KiB plaintext under fresh recipient |
| `encrypt_1MB` | Encrypt 1 MiB plaintext under fresh recipient |
| `decrypt_1KB` | Decrypt the 1 KiB envelope |
| `decrypt_1MB` | Decrypt the 1 MiB envelope |
| `peek_header` | Parse header without authentication |
| `encrypt_with_tessera_id_ad` | Same as `encrypt_1KB` but with a 41-byte TesseraID as AD |

## Expected reference numbers (Zen 4, ML-KEM-1024 + AES-256-GCM)

| Op | Expected ops/sec | Derivation |
|----|------------------|------------|
| `keygen` | ~120,000 | ML-KEM-1024 keygen ~46,200 cycles ÷ 5.7 GHz boost |
| `encrypt_1KB` | ~80,000 | ML-KEM Encaps ~54,800 + HKDF + AES-GCM 1 KB at 9.7 GB/s |
| `encrypt_1MB` | ~5,500 | Dominated by AES-GCM throughput 9.7 GB/s |
| `decrypt_1KB` | ~95,000 | ML-KEM Decaps ~45,300 + HKDF + AES-GCM |
| `decrypt_1MB` | ~5,700 | Ditto |
| `peek_header` | ~100,000,000 | Pure parsing, no crypto |
| `encrypt_with_tessera_id_ad` | ~80,000 | Identical to `encrypt_1KB`; AD path is free |
