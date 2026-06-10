# tessera-id/rust

Rust reference implementation of TesseraID — the 41-byte sortable identifier (Standard `0x01` + HLC `0x02`
variants). The whitepaper at `../latex/` is normative; the Python reference at `../python/tessera_id.py` is the
readable canonical source.

## Install / consumption

The crate is **publish-ready but not yet published** — crates.io publication is gated on the name-clearance
decision ([docs/decisions/2026-06-10-name-clearance.md](../../docs/decisions/2026-06-10-name-clearance.md)).
Until then, consume it as a path or git dependency:

```toml
# Path dependency (vendored checkout)
[dependencies]
tessera-id = { path = "../tessera/tessera-id/rust" }

# Git dependency
[dependencies]
tessera-id = { git = "https://github.com/barum/tessera", version = "1.3.1" }
```

The library target is `tessera_id` (`use tessera_id::...`). No `unsafe`, no FFI; randomness comes from the
`getrandom` crate (OS CSPRNG only, per the umbrella security invariants).

## Build / test / bench

```bash
cd tessera-id/rust
cargo build --release
cargo test --release
cargo run --release --bin bench
```

This crate is a member of the repo-root Cargo workspace; the shared `[profile.release]` lives in the root
`Cargo.toml`.
