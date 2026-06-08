# TESS-00001 — Full brand rename: PQToolkit → Tessera

**Date:** 2026-06-08
**Scope:** umbrella (TESS) — repo-wide brand rename across all 8 languages, docs,
whitepapers, skills, and CI. **No wire-format change**; all conformance vectors
are byte-identical and every language still passes.
**Status:** released

## Summary

The suite is renamed from **PQToolkit** to **Tessera**, and its three products
are renamed to drop the "post-quantum" branding from the two formats where it was
a label rather than a property (an identifier and a hash have no quantum threat
model; SHAKE-256 is no more "post-quantum" than SHA-256). The names now describe
what each component *is* — durable, over-provisioned, provenance-carrying
primitives — and "post-quantum" remains only in TesseraSeal's *description*, where
it is earned (ML-KEM-1024).

| Was | Now | What it is |
|-----|-----|------------|
| PQToolkit / pqtoolkit | **Tessera** | the umbrella suite |
| PQID / pqid | **TesseraID** / tessera-id | 41-byte sortable, coordination-free identifier |
| PQHash / pqhash | **TesseraHash** / tessera-hash | wide SHAKE-256 content-address hash |
| PQCrypt / pqcrypt | **TesseraSeal** / tessera-seal | ML-KEM-1024 + AES-256-GCM key-committing envelope |

## Wire / API changes

- **No core wire change.** Variant byte `0x04`, suite bytes `0x01/0x02/0x06`, all
  byte layouts, and every conformance vector are unchanged and byte-identical.
- **Frozen wire constants kept verbatim:** the TesseraSeal KDF/combiner
  domain-separation labels (`"pqcrypt v1 header"`, `"pqcrypt v1 hybrid combiner"`,
  etc.) are hashed *into* the envelope, so renaming them would change every
  envelope's bytes. They are frozen v1 wire tags and remain literal — the only
  place the token `pqcrypt` legitimately survives in code. Renaming them is a v2
  wire break, deliberately not done here.
- **Plugin layer (TesseraSeal) rebranded** (not core wire, not in conformance
  KATs): recipient URI `pqck1file1…` → `tseal1file1…`; keyfile `.pqck-key-v1.1` →
  `.tseal-key-v1.1`.
- **Env var:** `PQTK_CONFORMANCE_SKIP` → `TESSERA_CONFORMANCE_SKIP`.
- **Per-language identifiers** renamed idiomatically: Python modules
  `tessera_id`/`tessera_hash`/`tessera_seal`; Go packages
  `tesseraid`/`tesserahash`/`tesseraseal`; Rust crates `tessera-{id,hash,seal}`;
  Java packages `com.tessera.{id,hash,seal,common}`; C macros
  `TESSERA_ID_*`/`TESSERA_HASH_*`/`TESSERA_SEAL_*`; common C `pqtk_*`→`tessera_*`,
  `pqtk_header.h`→`tessera_header.h`; CPython ext `tessera_id_ext`.
- **Going-forward ticket prefixes:** `PQID-`→`TID-`, `PQHASH-`→`THASH-`,
  `PQCK-`→`TSEAL-`, `PQTK-`→`TESS-`. Historical release-note entries keep their
  original prefixes/filenames as a dated ledger.

## Code / docs / CI changes

- 3 project trees moved (`pqid`→`tessera-id`, etc.); ~79 files renamed; ~207
  files content-edited across 8 languages via a parallel rename workflow.
- Shared build glue reconciled: `go.work`, root `Cargo.toml` workspace, `common/c`
  (incl. `tessera_header.h`), `tools/conformance/run.sh`, `.gitignore`.
- Whitepapers rebuilt: `TesseraID_Whitepaper.pdf`, `TesseraHash_Whitepaper.pdf`,
  `TesseraSeal_Whitepaper.pdf`, umbrella `Tessera_Whitepaper.pdf`. Root published
  PDF is now `TesseraID_Whitepaper.pdf`.
- Skills renamed: `tessera-id-impl`, `tessera-hash-impl`, `tessera-seal-impl`,
  `tessera-conformance`, `tessera-security`.
- CI: `pqcrypt.yml` → `tessera-seal.yml`; paths/env/identifiers updated.
- A latent harness bug was fixed in passing: `run.sh` read the stale per-crate
  Rust target (`tools/conformance/rust/target/`) instead of the workspace target
  (`target/`); now points at the workspace output.

## Test plan

```
bash tools/conformance/run.sh
# Expect ALL LANGUAGES GREEN, byte-identical to pre-rename:
#   python 267, c 258, cpp 207, go 267, rust 267, typescript 207, java 207, cpython 207
TESSERA_CONFORMANCE_SKIP="cpp typescript java cpython" bash tools/conformance/run.sh   # alpha gate
# whitepapers: cd <project>/latex && make   (and ./latex for the umbrella)
```

Validated: full 8-language run green after the rename (0 fail), identical pass
counts to the pre-rename baseline — confirming the rename touched no wire bytes.

## Migrations / seeds / env / infra / flags

- **Env:** rename `PQTK_CONFORMANCE_SKIP` → `TESSERA_CONFORMANCE_SKIP` in any local
  scripts/CI overrides.
- **Consumers (none in-tree):** import paths / package names change per the table
  above; the on-the-wire format does not, so already-produced envelopes, IDs, and
  hashes remain valid and decode byte-identically.

## Operator runbook

Redeploy-only. No data migration (no wire change). The GitHub repository itself may
still be named `pqtoolkit` — renaming the remote repo is a separate manual step
outside this change.

## Rollback

Revert the rename commit. Because no wire bytes changed, rollback is purely a
source/name revert with no data implications.

## Linked

TESS-00001. Companion (frozen) context: the v1 wire tags remain `pqcrypt v1 …`.
