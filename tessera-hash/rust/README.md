# tessera-hash/rust

Rust reference implementation of TesseraHash — the 73-byte SHAKE-256 content hash format (variant `0x03`). The
whitepaper at `../latex/` is normative; the Python reference at `../python/tessera_hash.py` is the readable
canonical source.

## Install / consumption

The crate is **publish-ready but not yet published** — crates.io publication is gated on the name-clearance
decision ([docs/decisions/2026-06-10-name-clearance.md](../../docs/decisions/2026-06-10-name-clearance.md)).
Until then, consume it as a path or git dependency:

```toml
# Path dependency (vendored checkout)
[dependencies]
tessera-hash = { path = "../tessera/tessera-hash/rust" }

# Git dependency
[dependencies]
tessera-hash = { git = "https://github.com/barum/tessera", version = "1.3.1" }
```

The library target is `tessera_hash` (`use tessera_hash::...`). SHAKE-256 comes from the RustCrypto `sha3`
crate per the umbrella supply-chain pins; no re-vendored Keccak.

## Build / test

```bash
cd tessera-hash/rust
cargo build --release
cargo test --release
```

This crate is a member of the repo-root Cargo workspace; the shared `[profile.release]` lives in the root
`Cargo.toml`.
