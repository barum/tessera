# Decision memo: OSS-Fuzz enrollment for Tessera (C + Rust fuzz targets)

- **Date:** 2026-06-10
- **Ticket:** TESS-00016 (TP-096)
- **Status:** PROPOSED — gated on name-clearance + first public publication
- **Owner:** Bahram Samani

## Summary

Tessera now has structured, coverage-guided fuzz targets for its parser-heavy
decode surfaces in three languages (TP-096):

- **Rust (cargo-fuzz / libFuzzer):** `tessera-seal/rust/fuzz` (`fuzz_decrypt`,
  `fuzz_peek_header`), `tessera-hash/rust/fuzz` (`fuzz_decode`),
  `tessera-id/rust/fuzz` (`fuzz_decode`).
- **C (libFuzzer + ASan):** `tessera-seal/c/fuzz_decrypt.c` over
  `tessera_seal_peek_header` / `tessera_seal_peek_ad` / `tessera_seal_decrypt`.
- **Go (native `go test -fuzz`):** `tessera-seal/go/fuzz_test.go`,
  `tessera-hash/go/fuzz_test.go`, `tessera-id/go/fuzz_test.go` (corpus grown).

[OSS-Fuzz](https://github.com/google/oss-fuzz) runs these continuously on
Google's infrastructure with sanitizers (ASan/UBSan/MSan), coverage tracking,
and automated regression bisection + private disclosure to maintainers. This
memo records **what enrollment requires** and **the proposed configuration**,
and **why it is gated** rather than submitted today.

## Why this is worth it

The very first 60-second local run of the C harness found a real
**heap out-of-bounds read** in the canonical C ABI's `tessera_seal_decrypt`
(attacker-controlled `KEM_CT_LEN` smaller than the ML-KEM-1024 ciphertext size
drives `mlkem_decaps` to read 1568 bytes past a short envelope — see
`docs/release-notes/2026-06-10-tess-00016-fuzzing.md`). A crypto-envelope
format with manual offset arithmetic over attacker-controlled length fields is
exactly the profile OSS-Fuzz exists to babysit; continuous fuzzing would have
caught that class of bug before any user did, and will catch the next one.

## What OSS-Fuzz enrollment requires

OSS-Fuzz accepts projects that are **(a) open source, (b) have a meaningful
user base or are critical to global infrastructure, and (c) provide a working
fuzzing build.** Concretely, a PR to `google/oss-fuzz` adds
`projects/tessera/` with:

1. **`project.yaml`** — metadata:
   - `homepage:` the public canonical repo URL (pending name-clearance, see
     gating).
   - `language:` one entry per fuzzing language. We need **both** `c++`
     (covers the C libFuzzer target) and `rust`. (OSS-Fuzz treats C and C++
     under the `c++` language toolchain.)
   - `primary_contact:` and `auto_ccs:` — a **monitored maintainer email** that
     can receive embargoed vulnerability reports. This must be an address the
     maintainer actually reads; OSS-Fuzz sends crash details there under a
     90-day disclosure deadline. (Tie this to the SECURITY.md reporting channel
     once TP-114 lands.)
   - `sanitizers:` `address`, `undefined` (and `memory` for the Rust targets,
     which build cleanly under MSan since there is no `unsafe`).
   - `fuzzing_engines:` `libfuzzer` (primary), optionally `afl`, `honggfuzz`.
   - `main_repo:` the git URL OSS-Fuzz clones each build.

2. **`Dockerfile`** — based on `gcr.io/oss-fuzz-base/base-builder` (C/C++) and
   pulling the Rust toolchain via `base-builder-rust`. Installs the one build
   prerequisite the C target needs that the base image lacks: **OpenSSL 3.5+**
   (for ML-KEM-1024 `EVP_PKEY`). The base image ships OpenSSL 3.0, which has no
   ML-KEM — so the Dockerfile must build OpenSSL ≥ 3.5 from source, exactly as
   `conformance.yml` already does for the C conformance leg. This is the single
   biggest enrollment task and is already a solved problem in our CI.

3. **`build.sh`** — compiles each target with `$CC/$CXX $CFLAGS` (OSS-Fuzz
   injects the sanitizer + `-fsanitize=fuzzer` flags) and copies the resulting
   fuzzer binaries to `$OUT`:
   - **C:** compile `tessera-seal/c/fuzz_decrypt.c` + `tessera_seal.c` +
     `common/c/hkdf_sha3.c` against the built OpenSSL, link `-lcrypto`, emit
     `$OUT/tessera_seal_fuzz_decrypt`. Our `tessera-seal/c/Makefile fuzz_decrypt`
     target is the local model for this.
   - **Rust:** `cargo fuzz build` in each of the three `*/rust/fuzz` crates,
     copy `fuzz/target/*/release/<target>` to `$OUT/`. The crates are already
     cargo-fuzz-shaped (`[package.metadata] cargo-fuzz = true`, standalone
     `[workspace]`, `libfuzzer-sys` targets under `fuzz_targets/`).
   - **Seed corpora:** zip the frozen KAT envelopes/hashes into
     `$OUT/<target>_seed_corpus.zip` so OSS-Fuzz starts from real wire
     artifacts (our Go/C harnesses already seed from
     `conformance/vectors/*.json`).

4. **(Optional) `<target>.options`** — per-target libFuzzer options
   (`max_len`, dictionaries). Low priority; the decoders are robust to default
   sizing.

## Proposed configuration

| Target | Source | Sanitizers | Seed corpus |
|--------|--------|-----------|-------------|
| `tessera_seal_fuzz_decrypt` | `tessera-seal/c/fuzz_decrypt.c` | ASan, UBSan | `tessera-seal/conformance/vectors/decrypt.json` envelopes |
| `tessera_seal_rs_fuzz_decrypt` | `tessera-seal/rust/fuzz/fuzz_targets/fuzz_decrypt.rs` | ASan, UBSan, MSan | seal KAT envelopes |
| `tessera_seal_rs_fuzz_peek_header` | `tessera-seal/rust/fuzz/fuzz_targets/fuzz_peek_header.rs` | ASan, UBSan, MSan | seal KAT envelopes |
| `tessera_hash_rs_fuzz_decode` | `tessera-hash/rust/fuzz/fuzz_targets/fuzz_decode.rs` | ASan, UBSan, MSan | hash KAT (binary + text) |
| `tessera_id_rs_fuzz_decode` | `tessera-id/rust/fuzz/fuzz_targets/fuzz_decode.rs` | ASan, UBSan, MSan | id KAT (binary + text) |

Go native fuzzing (`go test -fuzz`) is **not** an OSS-Fuzz target — OSS-Fuzz
does not run Go's built-in fuzzer for libraries of this shape, and our Go
targets already run in our own CI dispatch. They stay as first-party
regression fuzzers.

Start with the **C target only** for the first submission (highest value,
manual-offset arithmetic, already found a bug), then add the Rust targets in a
follow-up PR once the build is proven green on OSS-Fuzz infra.

## Why this is gated (not submitted today)

1. **Name clearance.** The project name "Tessera" collides with ConsenSys
   Tessera (see `docs/decisions/2026-06-10-name-clearance.md`). OSS-Fuzz's
   `projects/<name>/` directory and the `homepage`/`main_repo` URLs bake the
   public name and repo path in. Submitting before name clearance risks
   re-doing the enrollment under a new name and an awkward public rename.
2. **Public repository.** OSS-Fuzz requires a public `main_repo` it can clone
   each build. The repo is not yet published (see
   `docs/decisions/2026-06-10-distribution-posture.md`). Enrollment cannot
   precede first publication.
3. **Maintainer disclosure address.** `primary_contact` must be a monitored
   inbox under an embargo SLA. This should be the same channel as the
   forthcoming `SECURITY.md` coordinated-disclosure policy (TP-114); enroll
   only after that channel exists, so vulnerability reports land somewhere with
   a defined response process.
4. **User-base / criticality bar.** OSS-Fuzz prioritizes widely-used or
   infrastructure-critical projects. A pre-publication reference spec has no
   user base yet; the application is stronger after first external adopters.

## Recommendation

Hold enrollment until **(1) name clearance resolves, (2) the repo is public,
and (3) SECURITY.md + a monitored disclosure inbox exist (TP-114).** Keep the
fuzz targets green in first-party CI dispatch in the meantime; they already
provide the regression value locally. When the gates clear, open the
`projects/tessera/` PR starting with the C target, reusing the OpenSSL-3.5
build recipe already proven in `conformance.yml`.

## Action items (when ungated)

- [ ] Resolve name clearance (TP-115/-116 series) → final public name + repo URL.
- [ ] Publish the repository (distribution-posture decision).
- [ ] Land SECURITY.md + monitored disclosure inbox (TP-114).
- [ ] Fix the `KEM_CT_LEN` OOB read (TSEAL follow-up) **before** the C target
      goes to continuous fuzzing, so OSS-Fuzz doesn't open with a known crash.
- [ ] Open `google/oss-fuzz` PR: `project.yaml`, `Dockerfile` (OpenSSL 3.5
      from source), `build.sh` (C target), seed corpora.
- [ ] Follow-up PR: add the four Rust targets.
