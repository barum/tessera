# Tessera Remediation & Market Plan — 2026-06-10

Item-by-item implementation plan derived from the 2026-06-10 deep audit (60-agent workflow: 13 dimension audits,
5 market sweeps, adversarial verification of all 42 critical/high findings — zero refuted — plus completeness critic).
Each item is formatted for hand-off to the **epic-developer** skill.

**Fields:** `COUNTER_ID · PRIORITY · ORDER · TYPE · NAME` then `Deps / Status / Hand-off`.

- **PRIORITY:** P0 = emergency (data loss, broken ports, red gate); P1 = correctness / truthfulness / security;
  P2 = quality bar (packaging, testing, hygiene); P3 = strategic / market.
- **ORDER:** recommended execution sequence. Items in the same wave with no mutual deps are parallelizable.
- **TYPE:** repo commit types (`feat|fix|docs|refactor|chore|sec`).
- **STATUS:** `NOT-STARTED` or `DECISION-REQUIRED` (maintainer must choose direction before work starts).

**Global Definition of Done (applies to every code item, per CLAUDE.md):** `bash tools/conformance/run.sh` stays
green (alpha 4 + full 8 where applicable); KAT vectors regenerated from the Python reference and committed verbatim
when observable behavior changes; release-notes entry + CHANGELOG index line in the owning project; affected
CLAUDE.md / README / skill surfaces updated in the same PR (`updated:` timestamp refreshed); `sec(...)` tag +
"Security considerations" section when a security invariant is touched.

Ticket-prefix convention for spawned tickets: `TID-` (tessera-id), `THASH-` (tessera-hash), `TSEAL-` (tessera-seal),
`TESS-` (umbrella/repo/CI/docs).

---

## Wave 0 — Emergency (P0)

#### TP-001 · P0 · 1 · chore · restore-umbrella-release-notes
Deps: — · Status: DONE (2026-06-10)
Hand-off: The entire umbrella release-notes surface is deleted-uncommitted in the working tree (one staged, two
unstaged): `docs/release-notes/2026-06-08-pqtk-00012-toolkit-validation-and-doc-truthfulness.md`,
`docs/release-notes/2026-06-08-tess-00001-rename-to-tessera.md`, `docs/release-notes/CHANGELOG.md`. This is the only
canonical record of the PQToolkit→Tessera rename. Run `git restore --staged --worktree docs/release-notes/` and
verify `git status` is clean for that path. If relocation was intended, complete the move in one commit with the
index updated and a release-notes entry explaining the move. Acceptance: all three files present at HEAD or
deliberately relocated with rationale.

#### TP-002 · P0 · 2 · sec · fix-seal-cpython-suite-regression
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. The BadKey fix (4fce343) broke the TesseraSeal CPython extension: `py_decrypt` hardcodes
`priv.suite = TESSERA_SEAL_SUITE_MLKEM1024_AESGCM` (`tessera-seal/cpython/tessera_seal_ext.c:159`), so the C
library's new `priv->suite != h.suite` check (`tessera-seal/c/tessera_seal.c:650`) rejects every legitimate
suite-0x02 (ChaCha20-Poly1305) envelope with BAD_KEY; the ext's own test fails at runtime. Fix: peek the envelope
header (`tessera_seal_peek_header`) and set `priv.suite` from it, or add a suite parameter to `decrypt()`. Also add
a distinct `BadKey` exception class to the ext (`raise_status` currently maps E_BAD_KEY to base `TesseraSealError`,
tessera_seal_ext.c:42) and note the encrypt-side check is vacuous in the binding (ext.c:106). Acceptance:
`cpython/test_tessera_seal_ext.py` fully green in a clean temp build; suite-0x02 round-trip restored.

#### TP-003 · P0 · 3 · sec · port-badkey-check-typescript
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. TypeScript never received the normative suite/key-consistency check: `encrypt` never
compares `recipientPub.suite` to the requested suite and `decrypt` never compares `priv.suite` to `header.suite`
(`tessera-seal/typescript/tessera_seal.ts:337-345`, `:376-430`), so its KAT-consuming tests are red on
`bad_key_suite_mismatch`. Port the two-line checks mirroring `go/tessera_seal.go:625-627` and `:718-720`, add a
typed BadKey error class (structural, NOT auth-class — no oracle merge with DecryptionError), re-run `npm test`.
Acceptance: TS test suite green including the shared KAT; error taxonomy documented in the TS README.

#### TP-004 · P0 · 4 · sec · port-badkey-check-java
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. Same as TP-003 for Java: `TesseraSeal.java` encrypt (~line 581) and decrypt (~line 608)
never consult the suite fields both key types already carry; Java tests red on `bad_key_suite_mismatch`. Add the
checks before any KEM work, add a BadKey exception class, re-run `make test`. Also either scope the whitepaper's
unqualified normative sentence (sec02_threat_model.tex:10, sec09_failure_modes.tex) per-language or confirm all 8
ports now comply (after TP-002/003/004 only C++ remains — verify and fix or document). Acceptance: Java suite green;
whitepaper sentence true.

#### TP-005 · P0 · 5 · docs · backfill-tess-00002-4-release-notes
Deps: TP-001 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. TESS-00002 (badge repoint), TESS-00003 (tsconfig bundler), TESS-00004 (CI manual-only) shipped
with zero release-notes entries; the umbrella CHANGELOG index at HEAD ends at TESS-00001. Backfill three brief
entries (TESS-00004 especially must document how to manually dispatch conformance now and the cost rationale) and
update `docs/release-notes/CHANGELOG.md`. Acceptance: index lists all entries reverse-chronologically; repo's own
release-notes discipline rule satisfied.

#### TP-006 · P0 · 6 · chore · tessera-name-clearance-decision
Deps: — · Status: DECISION-RECORDED (2026-06-10) — memo done (docs/decisions/2026-06-10-name-clearance.md); registry reservations/registration pending
Hand-off: TESS ticket. "Tessera" collides in the exact crypto/security category — ConsenSys Tessera is an
established enterprise crypto/privacy product, and bare `tessera` names are already taken on npm, PyPI, and
crates.io. No clearance was recorded in the rename (c97338d). Before ANY registry publish or public launch:
(1) run a real clearance search (USPTO TESS + EUIPO, software/crypto classes); (2) reserve still-free hyphenated
names (`tessera-id`, `tessera-seal`, `tessera-hash`) on npm/PyPI/crates.io immediately as placeholders; (3) decide:
keep name with qualifier, or rename now while it costs little (the repo just paid for one rename — the receipt is
TESS-00001). Output: a recorded decision memo in docs/ + reserved registry names. Blocks TP-085..TP-094.

---

## Wave 1 — CI restoration (P0/P1)

#### TP-007 · P0 · 7 · fix · ci-c-leg-openssl-3.5
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket (CRITICAL — the blocking gate was red). The step named "Install OpenSSL 3.5+ (Ubuntu)"
(`.github/workflows/conformance.yml:43-44`) runs `apt-get install libssl-dev` which delivers OpenSSL 3.0.13 on
ubuntu-24.04 — no ML-KEM provider — so the C reference (`EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-1024", ...)`,
tessera_seal.c:199) fails all 9 positive TesseraSeal decrypt vectors with rc=-4 while negative vectors pass
accidentally. Fix: build/pin OpenSSL 3.5+ in the workflow (cached), or use a container image shipping 3.5+, or set
OPENSSL_PREFIX; add an explicit `openssl version` assertion step that fails fast below 3.5. Apply to every workflow
compiling the C seal reference (conformance.yml, tessera-seal.yml, c.yml). Acceptance: manual dispatch shows C leg
258/0.

#### TP-008 · P0 · 8 · sec · regenerate-npm-lockfiles-public-registry
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. All four committed `package-lock.json` files (tessera-id/typescript, tessera-hash/typescript,
tessera-seal/typescript, tools/conformance/typescript) resolve every dependency through a private corporate
Artifactory (`https://jfrogrepo24.jfrog.io/artifactory/api/npm/npm-virtual/...`) — public runners and consumers get
403 and an internal hostname is published. Regenerate all four against `https://registry.npmjs.org` (remove the
corporate .npmrc from the environment first), commit, and add a CI assertion that greps lockfiles for any
non-registry.npmjs.org `resolved` URL. Acceptance: `npm ci` succeeds on a GitHub runner; CI guard in place.

#### TP-009 · P1 · 9 · fix · ci-macos-timeout-portability
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Every macOS fuzz-smoke leg fails with exit 127 because GNU `timeout` does not exist on
macos-latest runners (rust.yml:30, c.yml:51, cpp.yml:51, java.yml:39, typescript.yml:41, cpython.yml:35,
python.yml:35). Replace `timeout 60 cmd` with a portable construct: `brew install coreutils` + `gtimeout`, or drop
the wall-clock cap in favor of the iteration-count argument the fuzz harnesses already accept. Acceptance: macOS
legs of all 7 workflows pass on manual dispatch.

#### TP-010 · P1 · 10 · fix · python-workflow-kyber-py-dep
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. python.yml never installs tessera-seal requirements but
`tools/conformance/python/python_runner.py:25` unconditionally imports `tessera_seal` → every leg of the canonical
Python workflow red. Fix both sides: add `pip install -r tessera-seal/python/requirements.txt` to python.yml AND
make python_runner.py import tessera_seal lazily (only when a seal vector dir is passed) so id/hash-only workflows
don't drag in crypto deps. Acceptance: python.yml green on dispatch.

#### TP-011 · P1 · 11 · fix · java-conformance-runner-stackoverflow
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. The Java conformance runner dies with `java.lang.StackOverflowError` on ubuntu (JDK 17 and
21 legs, run 27210721839) while consuming id/hash vectors — likely unbounded recursion in its JSON parsing.
Reproduce locally (`make build` in tools/conformance/java, run against vector dirs), fix the recursion (raise -Xss
only as stopgap), and treat the "java 207 0" doc claim as unverified until the runner completes in CI. Acceptance:
java.yml conformance step green on both JDK legs.

#### TP-012 · P1 · 12 · fix · latex-workflow-lmodern-and-coverage
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. latex.yml fails outright (`lmodern.sty not found`) and builds only 1 of the 4 whitepapers
CLAUDE.md:119 attributes to it (tessera-seal's is built by tessera-seal.yml; tessera-hash and the umbrella latex/
have no CI build). Add `lmodern` to the apt set, extend to a 4-leg matrix over {latex/, tessera-id/latex,
tessera-hash/latex, tessera-seal/latex}, upload all four PDFs as artifacts. Acceptance: clean dispatch run building
all four papers.

#### TP-013 · P0 · 13 · sec · restore-pr-gate-and-branch-protection
Deps: TP-007, TP-008, TP-009, TP-010, TP-011, TP-012 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. TESS-00004 made all 11 workflows `workflow_dispatch`-only AND main has no branch protection
(`gh api .../branches/main/protection` → 404): a wire-format or crypto regression can land on main with zero
automated verification, while CLAUDE.md still calls conformance.yml "the branch-protection gate". Recommended
posture: re-enable `on: pull_request` for conformance.yml only (the 4-language alpha step — one job, one runner,
<2 min warm), restore branch protection on main requiring that check, keep the expensive per-language matrices
manual or path-filtered. Decision needed: cost ceiling vs gate. If the maintainer declines, TP-019 must rewrite all
gate claims instead. Acceptance: either a live PR gate + protected main, or fully truthful docs.

#### TP-014 · P1 · 14 · fix · go-workflow-version-matrix
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. go.yml declares matrix go ["1.22","1.23"] but every go.mod has `go 1.26`, so GOTOOLCHAIN
auto-upgrade silently runs 1.26 on both legs — the matrix is fiction. Set the matrix to versions satisfying the
directive (e.g. ["1.26"]) or lower the go directive if older support is intended. Acceptance: matrix versions
actually execute.

#### TP-015 · P1 · 15 · sec · pin-actions-by-sha-and-permissions
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. `dtolnay/rust-toolchain@stable` (rust.yml:16, conformance.yml:32, tessera-seal.yml:65) is a
mutable third-party ref; no action anywhere is SHA-pinned; no workflow declares a `permissions:` block. Pin all
actions by full commit SHA with a version comment, add top-level `permissions: contents: read` to every workflow,
optionally add Dependabot/Renovate for action bumps. Acceptance: zero mutable third-party refs; least-privilege
permissions everywhere.

#### TP-016 · P1 · 16 · fix · python-floor-matrix-alignment
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. CLAUDE.md declares Python 3.9+ but no workflow tests 3.9 and matrices are inconsistent
(python.yml/cpython.yml: 3.10-3.12; tessera-seal.yml: 3.11-3.13). Either add 3.9 (id/hash only — seal deps may need
newer) or amend CLAUDE.md to the floor actually tested, and align matrices. Acceptance: documented floor == tested
floor.

#### TP-017 · P2 · 17 · chore · ci-dependency-caching
Deps: TP-013 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. No actions/cache or cache inputs anywhere despite cost being the stated reason CI was
disabled; setup-go warns on missing go.sum path. Add cache keys: setup-go `cache-dependency-path` at module go.sum
files, setup-node `cache: npm`, Swatinem/rust-cache, cached TeX Live or a TeX container. Then revisit the cost
rationale for manual-only CI. Acceptance: warm-cache run times documented; cost argument re-evaluated.

#### TP-018 · P1 · 18 · docs · readme-badges-strategy
Deps: TP-013 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. README.md:3-12 shows ten status badges pointing at manual-dispatch-only workflows on a repo
the public API can't even resolve — they permanently display the failing 2026-06-09 state. Either add a scheduled
(cron) trigger so badges reflect reality at low cost, or replace the badge row with a one-line note that CI is
manual + link to the latest run. Acceptance: no badge can show a stale/false state.

#### TP-019 · P1 · 19 · docs · claude-md-ci-truthfulness-rewrite
Deps: TP-013 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Root CLAUDE.md's CI quick reference is materially untruthful: calls conformance.yml "the
branch-protection gate" (manual-only since 9f70919), claims latex.yml builds three papers (builds one, broken),
presents local-run numbers as CI results, and conformance.yml:46's step name still says "v1.2". Rewrite the CI
section to match the (post-TP-013) reality, distinguish "verified locally" from "enforced in CI", fix the step
name. Also fix the same claims in `.claude/skills/tessera-conformance/SKILL.md:11` and refresh its `updated:`
timestamp. Acceptance: every CI claim in CLAUDE.md/skills verifiable against workflow files.

#### TP-020 · P1 · 20 · fix · harness-exit-code-and-count-enforcement
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. `tools/conformance/run.sh:161-174` counts PASS/FAIL by grepping runner stdout, never checks
exit status, never cross-checks pass+fail against the vector record count — a segfaulted, missing, or zero-test
runner contributes 0/0 and the harness still prints ALL LANGUAGES GREEN with exit 0. Capture the per-vector-file
runner exit code (nonzero with no FAIL lines = hard failure) and assert PASS+FAIL equals the effective (non-doc)
record count derived from the JSON. Acceptance: killing any runner mid-suite turns the run red; injected
undercount detected.

#### TP-021 · P1 · 21 · fix · harness-skip-visibility
Deps: TP-020 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Two silent-pass problems: (a) the CPython runner fake-passes hlc_overflow vectors
(`tools/conformance/cpython/conformance_runner.py:202-204` returns True "skipped — covered by C reference") so
cpython reports 207 PASS instead of 204 PASS / 3 SKIP; (b) 5 "doc" pseudo-records across vector files are silently
skipped by all runners. Emit explicit `SKIP <name>` lines for unexecutable/doc records and add a SKIP column to
run.sh's summary. Acceptance: per-language table shows PASS/FAIL/SKIP; no fake passes remain.

#### TP-022 · P1 · 22 · fix · seal-runners-assert-error-kind
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. The `error_kind` field in tessera-seal vectors is decorative — zero runners read it
(grep across python_runner.py, go/rust/c tessera_seal runners), so the BadKey-vs-auth-class distinction (normative)
is not actually verified by the harness. Teach all four seal runners to map their language's error taxonomy to the
error_kind enum and assert per record — at minimum BAD_KEY vs auth-class for `bad_key_suite_mismatch`. Acceptance:
deliberately mis-classifying an error in any reference flips the harness red.

#### TP-023 · P1 · 23 · docs · vector-freeze-append-only-policy
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Vectors are the cross-language compatibility contract, but the documented workflow
("regenerate from Python and commit") would let behavioral drift rewrite history green. Declare shipped vectors
frozen (regeneration may only append records or add files) in tools/conformance/ docs + CLAUDE.md, and add a cheap
CI/script check that existing record bytes are unchanged vs HEAD (4fce343 already followed this discipline —
codify it). Acceptance: mutating an existing record fails the check; appending passes.

#### TP-024 · P2 · 24 · chore · run-sh-hygiene-and-skip-var-errata
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. run.sh:16 uses only `set -o pipefail`, violating the repo's own `set -euo pipefail`
convention — add `set -u` plus a comment explaining the deliberate `-e` omission (or note the sanctioned exception
in CLAUDE.md). Make run.sh warn on skip tokens not in ALL_LANGS (unknown tokens currently no-op silently). Add a
one-line erratum to the pre-rename release note still referencing `PQTK_CONFORMANCE_SKIP`. Acceptance: convention
truthful; typo'd skip tokens visibly warned.

---

## Wave 2 — Cross-language correctness & KAT coverage (P1)

#### TP-025 · P1 · 25 · sec · tessera-id-generator-spin-alignment
Deps: — · Status: DONE (2026-06-10)
Hand-off: TID ticket. On counter exhaust after a clock regression the spec and C/C++/Java spin
`while now <= last_ts` (sec03_part2_spec.tex:68; c/tessera_id.c:115) but Python (the canonical reference!),
tessera_id_fast.py, Go, Rust, and TS spin `while now == ts` (python/tessera_id.py:137-139; go/tessera_id.go:120-124;
rust/src/lib.rs:325-329; typescript/tessera_id.ts:165-166) — the loop exits immediately during regression, last_ts
moves backward, and the emitted ID sorts before its predecessor, violating strict monotonicity. Change the spin
condition in all five diverging implementations to match the spec, add a clock-regression + counter-exhaust unit
test via the existing test-clock overrides, mirrored across languages. Per authority order the spec + C are right;
do NOT change the spec to match the outlier. Acceptance: new regression test green in all 8 languages.

#### TP-026 · P1 · 26 · sec · tessera-hash-generator-spin-alignment
Deps: TP-025 · Status: DONE (2026-06-10)
Hand-off: THASH ticket. Same defect class in tessera-hash: Python spins `while _now_ms() == ts`
(tessera_hash.py:148-151,157-160) while the other six languages spin on `<=` — Python can emit a regressed
timestamp after a backward clock jump. Change the Python spin to `while _now_ms() <= self._last_ts`, add the same
regression test as TP-025. Acceptance: behavior identical across all 7 tessera-hash implementations.

#### TP-027 · P1 · 27 · sec · tessera-id-cpython-variant-rejection
Deps: — · Status: DONE (2026-06-10)
Hand-off: TID ticket. The tessera-id CPython extension has NO unknown-variant rejection path: it never binds
`tessera_id_validate()` (c/tessera_id.c:350-356) and the C string decoders it wraps don't check the variant — a
0x03/0x00/0xFF buffer encodes, decodes, and round-trips silently (live-verified). The conformance runner masks this
by reimplementing the check in harness code (tools/conformance/cpython/conformance_runner.py:91-94), so the green
207 overstates the library. Bind validate() in the extension (raising TesseraIdError on unknown variant), make the
runner call the real library function (like the C runner does, conformance_runner.c:311), and add string-form
unknown-variant vectors so harness masking of this class becomes impossible. Acceptance: ext rejects unknown
variants through its public API; runner exercises the library, not itself.

#### TP-028 · P1 · 28 · sec · string-decode-variant-contract-id
Deps: TP-027 · Status: DONE (2026-06-10)
Hand-off: TID ticket. Unknown-variant rejection at string-decode level diverges across languages (and within
TypeScript): Rust/Java reject at string decode; others validate only in a separate step. Pin the contract in the
whitepaper (recommended: string decoders MUST validate the variant), align all 8 languages, add b64/crockford-form
unknown-variant records to invalid.json so the harness pins it forever. Acceptance: identical rejection behavior in
all 8 for both text forms, KAT-enforced.

#### TP-029 · P1 · 29 · sec · tessera-hash-text-decoder-variant-alignment
Deps: TP-028 · Status: DONE (2026-06-10)
Hand-off: THASH ticket. sec03 says every non-0x03 byte is rejected at decode, but: Python and C decode a 0x05
variant successfully via b64/crockford text forms; Go rejects in Crockford but accepts in Base64URL (internally
inconsistent); C++/Rust/TS/Java reject in both. The two canonical references are the permissive outliers. Align
Python/C/Go-b64 to reject (majority + spec wording), add wrong-variant b64/crockford records to
tessera_hash_invalid.json. Acceptance: KAT-pinned, all languages identical.

#### TP-030 · P1 · 30 · sec · suite-0x06-reject-coverage-non-hybrid
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. The normative "non-hybrid languages MUST reject suite 0x06 as UNKNOWN_SUITE" has ZERO test
or KAT coverage: 0x06 can't appear in shared invalid.json (hybrid languages accept it) and hybrid_*.json is skipped
for non-hybrid languages, so a non-hybrid port that mis-parsed 0x06 would pass everything. Add a per-language unit
test in C, C++, TypeScript, Java, CPython ext asserting decrypt/peek_header of a suite-0x06 envelope fails with
UNKNOWN_SUITE, or a language-conditional KAT record (`suite_0x06_rejected` consumed only when hybrid_supported is
false). Acceptance: the MUST is mechanically enforced in all five.

#### TP-031 · P1 · 31 · sec · sec9.2-synthetic-aead-must-resolution
Deps: — · Status: DONE (2026-06-10) — decided: §9.2 softened to implemented behavior
Hand-off: TSEAL ticket. Whitepaper §9.2 mandates "even on structural failure paths the decrypt routine MUST execute
the AEAD verify against a synthetic 32-byte key" — implemented by ZERO of eight ports (Python raises before AEAD
work on structural errors; C feeds a zeroed ss through the real path; Rust short-circuits one path; a C comment
falsely claims compliance), and per-language failure shapes differ so cross-language timing is not uniform. Decide:
(a) implement the synthetic AEAD verify uniformly on auth-class failure paths and define which structural errors
are exempt, or (b) soften §9.2 to describe implemented behavior. Either way fix the false C comment and align the
eight ports' failure-path shape. All failures are fail-closed today — this is timing-posture truthfulness, not an
auth break. Acceptance: spec text and all 8 implementations agree; documented in side-channel disclaimer.

#### TP-032 · P1 · 32 · feat · tessera-hash-java-generator-and-tests
Deps: — · Status: DONE (2026-06-10)
Hand-off: THASH ticket. Java ships only the stateless half (hashOnly/hashAt; no Generator class, no clock/counter
logic) yet the whitepaper marks Java complete; Java has zero unit tests and the documented `make test` target does
not exist (verified failure). Either implement the Java Generator mirroring the locked Go/Rust shape + add a test
target and tests, or downgrade Java's status in sec08 and tessera-hash/CLAUDE.md to "partial (codec + stateless
only)". Recommended: implement (the suite markets 8-language parity). Acceptance: `make test` exists and passes;
whitepaper status truthful.

#### TP-033 · P1 · 33 · fix · tessera-id-java-contract-alignment
Deps: — · Status: DONE (2026-06-10)
Hand-off: TID ticket. Java inverts two documented cross-language invariants: StandardGenerator is internally
`synchronized` by default (StandardGenerator.java:38) where the contract says NOT internally locked, and
HLCGenerator exposes a configurable `maxDriftMs` constructor where the bound is documented fixed at 60,000 hard
error. Also: observe() takes a raw 9-byte prefix instead of a decoded ID (loses validation other languages perform)
and the error name diverges (DriftExceededException vs HLCDriftError/ErrHLCDrift). Either align Java
(unsynchronized-by-default + synchronized wrapper; remove/package-private the drift constructor; add
nextObserving(TesseraId) overload; rename exception) or amend tessera-id/README.md:134-137's "across every
implementation" claims. Recommended: align Java. Coordinate with TP-034. Acceptance: README invariants true for
all languages.

#### TP-034 · P1 · 34 · sec · hlc-drift-configurability-decision
Deps: TP-033 · Status: DONE (2026-06-10) — decided: drift bound clamped at 60,000 ms, configurability removed (TID-00019/TID-00020)
Hand-off: TID ticket. The HLC drift bound is runtime-configurable in C/C++/Java (c/tessera_id.h:60 per-generator
max_drift_ms; cpp set_max_drift_ms; Java constructor) but a fixed constant in Python/Go/Rust/TS; the spec calls it
both normative and "configurable" in different places. Decide whether per-generator override is part of the
contract; either remove the setters/fields in C/C++/Java or document the override affordance in sec03 and fix the
quick-ref wording to distinguish normative default from local override. Security note: CLAUDE.md says relaxing the
bound defeats monotonicity — recommend removing configurability. Acceptance: one answer, spec + 8 languages + docs
agree.

#### TP-035 · P2 · 35 · refactor · error-taxonomy-alignment
Deps: — · Status: DONE (2026-06-10)
Hand-off: TID ticket. C++ and the CPython ext collapse everything into one generic error class
(cpp/tessera_id.hpp:393-397 unknown-variant/drift/padding all → TesseraIdError; cpython ext single class), and
tessera_id_fast.py doesn't raise the same exception types as tessera_id.py. Introduce typed error
subclasses/codes in C++ and the ext mirroring the C status enum; make tessera_id_fast.py raise tessera_id.py's
types. Also fix tessera-id/CLAUDE.md's claim that the ext "must match tessera_id_fast.py's API" (it wraps the C ABI
with a 9-byte observe — fix the sentence or the API, TP-033 overlap). Acceptance: documented taxonomy per language;
parity claims truthful.

#### TP-036 · P1 · 36 · fix · tessera-hash-hash-at-range-alignment
Deps: — · Status: DONE (2026-06-10)
Hand-off: THASH ticket. `hash_at` out-of-range timestamp handling diverges: C and Go silently mask to 48 bits
(tessera_hash.c:77; tessera_hash.go:112-114) while Python/C++/Rust/TS/Java raise. Make C return a status and Go
return an error for out-of-range timestamps, matching the Python reference; add an out-of-range hash_at negative
vector. Acceptance: KAT-pinned identical behavior.

#### TP-037 · P2 · 37 · docs · tessera-hash-locking-invariant-qualification
Deps: — · Status: DONE (2026-06-10)
Hand-off: THASH ticket. "Internally locked generator" is stated as a hard invariant (sec06:16, sec11:114) but the C
reference is explicitly caller-locked (tessera_hash.h:44-45 "exposes no synchronization"). Qualify the invariant:
"internally locked where the language has shared-memory threading; the C struct is caller-synchronized by
documented contract." Acceptance: spec matches header docs.

#### TP-038 · P1 · 38 · sec · plugin-kdf-silent-downgrade-fix
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. The plugin keyfile silently downgrades Argon2id→PBKDF2 when argon2-cffi is absent without
changing the file-format identifier (tessera_seal_plugin_file.py:88-112,70,201-208) — two keyfiles with the same
header can have different KDF strength, and unwrap can't tell. Either make argon2-cffi a hard dependency (fail
closed) or encode the KDF choice + params in the keyfile header/blob so unwrap selects deterministically.
Security-relevant: tag sec(...), add a keyfile-format note to the plugin protocol doc. Acceptance: no silent KDF
substitution possible; tests cover both paths.

#### TP-039 · P2 · 39 · sec · rust-seal-getrandom-swap
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. tessera-seal Rust reads /dev/urandom directly via std::fs::File (lib.rs:203-210) for ML-KEM
encaps randomness and X25519 ephemerals — CSPRNG-compliant but non-portable and inconsistent with tessera-id's
getrandom crate usage (tessera-id/rust/src/lib.rs:313). Switch fill_random to `getrandom::fill` (or OsRng via
rand_core, already a dependency). Also move serde/serde_json/hex/rand_core to dev-dependencies if only tests use
them, and extend the umbrella CLAUDE.md supply-chain table to name Rust's hash/AEAD crate sources. Acceptance: no
direct device reads; dep table truthful.

#### TP-040 · P2 · 40 · refactor · python-decrypt-aad-alignment
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. Python builds the decrypt AEAD AAD from `expected_ad` while all other ports build it from
the on-wire ad (tessera_seal.py:917 vs c:730-732, go:769-772, rust:635-638, TS/Java) — observably identical today,
structurally divergent. Align Python to verify with the on-wire ad (or document the deliberate difference in
porting notes). Also document Go's `ts:=0` sentinel quirk in the Go README. Acceptance: one documented AAD
construction across ports.

#### TP-041 · P2 · 41 · docs · seal-code-comment-hygiene-sweep
Deps: TP-002 · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. Sweep: (a) UnknownSuite docstring says "only 0x01, 0x02" though 0x06 is allocated
(tessera_seal.py:135); (b) C header comment h:131-136 contradicts the implementation on 0x06 handling (peek_header
actually rejects) and the h:26-29 suite table omits 0x06 — fix comment, add "rejected until TSEAL-00030" row;
(c) replace x^x timing pads with a fixed synthetic-buffer compare if length-mismatch flatness is intended;
(d) one-line erratum on renamed historical release notes. Acceptance: comments match code everywhere in seal.

#### TP-042 · P2 · 42 · refactor · tessera-hash-dead-last-tail-removal
Deps: — · Status: DONE (2026-06-10)
Hand-off: THASH ticket. Generator `last_tail` state is dead code in Python and C — same-ms branches are
behaviorally identical whether the tail matches or not — while the docstring claims a disambiguation role
(tessera_hash.py:113-121,143-160). Drop last_tail from both generators (or implement the intended distinction) and
fix the docstring. Acceptance: no dead state; docstring truthful; KATs unchanged.

#### TP-043 · P1 · 43 · chore · hlc-drift-conformance-vectors
Deps: TP-020 · Status: DONE (2026-06-10)
Hand-off: TID ticket. No HLC drift conformance vector exists and the runner can't express one (hlc_overflow.json
has only 3 effective records, no drift case). Add a drift-rejection vector class: peer l_msg = physical_time +
60_001 ms expecting a drift error, plus the boundary case at exactly +60_000 (must be accepted/rejected per spec
boundary semantics — pin which), and an `expects_error` pathway in every language's hlc_overflow handler.
Acceptance: drift bound KAT-enforced in all 8 languages.

#### TP-044 · P2 · 44 · chore · reserved-byte-vectors-id-hash
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. tessera-id invalid.json covers only variants 0x00/0x03/0x04/0xff; tessera-hash similar —
mid-range reserved bytes (0x05, 0x10, 0x7f, 0xfe) untested, unlike tessera-seal which covers them. Extend
build_invalid_vectors() in both generate scripts with boundary-adjacent and mid-range reserved bytes, regenerate,
commit. Acceptance: reserved-range rejection KAT-pinned for all three projects symmetrically.

#### TP-045 · P1 · 45 · chore · seal-truncation-vectors
Deps: TP-023 · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. The only INVALID_LEN vector is the empty envelope; no truncation case with a structurally
valid header exists. Add generator records taking the captured well-formed envelope (generate.py:294+) truncated
mid-kem_ct, mid-aead_ct, and one byte short of the commit tag, expecting INVALID_LEN-class rejection in all
seal-capable languages. Acceptance: truncation classes KAT-pinned (append-only per TP-023).

#### TP-046 · P2 · 46 · chore · seal-boundary-vectors
Deps: TP-023, TP-045 · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. Decrypt vectors max out at 256-byte plaintexts and ad_len ∈ {0,8,41}. On next regeneration
add: one large-plaintext decrypt KAT (e.g. 64 KiB), one max-ad_len envelope, a ctr=0xFFFF header, and a
wrong-kem_ct_len-with-valid-header rejection record. Acceptance: boundary surface KAT-covered.

---

## Wave 3 — Whitepaper / spec truthfulness (P1)

#### TP-047 · P1 · 47 · docs · regenerate-appendix-c-and-doc-vector-ci
Deps: — · Status: DONE (2026-06-10)
Hand-off: TID ticket. Whitepaper Appendix C's 12 "example TesseraIDs" are fabricated: 54 chars (must be 66), none
decodes, rows 3 and 10 share an identical 39-char "random" suffix (~2^-195), and the "first 14 characters
identical" claim is false (it's 12) — in the published PDF (sec14_appendices.tex:83-100, PDF p.39). Regenerate by
actually running the Python StandardGenerator in a tight loop within one ms, paste verbatim output, fix the prose,
rebuild the PDF. Then add a CI-checkable script that decodes every example string in all appendix sources
(extend to Appendix A and the DOCX examples) so fabricated examples become structurally impossible. Acceptance:
every example string in every spec decodes against the reference; CI check green.

#### TP-048 · P1 · 48 · docs · docx-pipeline-example-fix-and-status
Deps: TP-047 · Status: DONE (2026-06-10) — decided: DOCX pipeline declared non-normative
Hand-off: TID ticket. The DOCX whitepaper pipeline publishes a false cross-encoding example (wp_section2_why_spec.js:
338-341 — Crockford string neither matches the Base64URL bytes nor decodes), and the dual LaTeX+DOCX source
pipelines have no parity check. Fix the example from the reference implementation, then decide: declare the DOCX
non-normative/deprecated in tessera-id/CLAUDE.md, or build a shared data file both pipelines consume (vectors +
pad-bit prose). Recommended: declare LaTeX sole normative source. Acceptance: no false examples; pipeline status
recorded.

#### TP-049 · P1 · 49 · docs · strike-python-runner-fallback-claims
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. The phantom "Python runner fallback" survives in the normative whitepapers after the
0c95e38 honesty pass fixed only CLAUDE.md: tessera-seal sec12_conformance.tex:24 and :66, umbrella
sec06_conformance_and_ci.tex:58, tessera-hash sec08:23 — while run.sh:42-52 states verbatim "There is no
Python-runner fallback" (cpp/ts/java/cpython skip the seal vector dir entirely). Strike/rewrite all four passages,
rebuild all three PDFs, add a release-notes erratum. Acceptance: zero fallback claims anywhere; PDFs rebuilt.

#### TP-050 · P1 · 50 · sec · timing-histogram-phantom-and-disclaimer-fix
Deps: TP-031 · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. Two normative documents assert a shipped 100,000-pair timing-histogram regression that has
never existed (sec09_failure_modes.tex:32-41; docs/side-channel-disclaimer.md), contradicted by the repo's own
security-audit-v1.2.md (open items 1 and 7). The same disclaimer also names the wrong ML-KEM libraries: claims C
uses mlkem-native (actual: OpenSSL 3.5+ EVP) and Go uses filippo.io/mlkem (actual: stdlib crypto/mlkem); reference
hardware string disagrees across docs (M3 Max vs M4 Max). Rewrite §9.3 + the disclaimer to the truthful posture
(manual timing measurement, automated regression planned — see TP-150), regenerate the vendoring list from the
live CLAUDE.md table, note kyber-py is for spec readability/KAT generation not production hardening. Acceptance:
the most security-facing docs contain zero false claims.

#### TP-051 · P1 · 51 · docs · phantom-kat-files-in-specs
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. tessera-seal sec12:9 lists `encrypt_roundtrip.json` ("fixed-RNG-seed determinism") as
shipped vector inventory — file does not exist; umbrella sec06:16 lists `kyberslash_regression` as present, directly
contradicting the project paper's own honest "planned (backlog)" label (sec12:15). Either ship encrypt_roundtrip
vectors (the generator path is already specified in sec12:74) or relabel both as planned/backlog in the kyberslash
style; sync the umbrella table to the project paper. Acceptance: spec vector inventory == `ls conformance/vectors/`.

#### TP-052 · P1 · 52 · docs · tessera-hash-counter-overflow-prose-fix
Deps: TP-026 · Status: DONE (2026-06-10)
Hand-off: THASH ticket. The NORMATIVE wire-format section states counter overflow "bumps the timestamp by 1 ms and
resets the counter" claiming parity with TesseraID's Standard generator (sec03:23, sec06:18) — but every
implementation spins to the next real millisecond, and TesseraID's Standard generator also spins ("bump by 1" is
actually TesseraID's HLC rule — copy-paste error). A port implemented from this prose would diverge observably.
Correct sec03/sec06 to spin-to-next-ms semantics, rebuild the PDF, add a test note pinning overflow semantics.
Acceptance: prose matches all implementations + TesseraID's sibling description (sec03_part2_spec.tex:220).

#### TP-053 · P1 · 53 · docs · tessera-hash-ts-shake-source-truth
Deps: — · Status: DONE (2026-06-10)
Hand-off: THASH ticket. Three whitepaper places claim TypeScript sources SHAKE-256 from @noble/hashes with
"const-time documented" and "browser + Node" (sec04:27, sec08:43, sec10:59); the implementation actually uses
Node's OpenSSL-backed `node:crypto` + Buffer (tessera_hash.ts:10,159-162) — Node-only, different supply-chain
story. Decide: correct the three tables to "node:crypto (OpenSSL), Node 18+, Node-only", or switch the
implementation to @noble/hashes if browser support is intended (KAT re-run required). Either way the dependency
table is a pinned security invariant — keep it truthful. Acceptance: docs == code; KATs green.

#### TP-054 · P1 · 54 · docs · vendoring-claims-to-pins-sweep
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. The seal paper repeatedly claims it "vendors" constant-time ML-KEM/X25519 implementations
(sec02_threat_model.tex:8, sec10_side_channel…) — the repo vendors none of them (it pins third-party libraries;
only Keccak is vendored in common/). Replace vendoring language with "pins verified third-party implementations
per language" matching sec05's pin table; delete/rewrite the mlkem-native "retained as fallback" acknowledgment.
Acceptance: supply-chain description matches reality.

#### TP-055 · P1 · 55 · docs · stale-conformance-counts-in-pdfs
Deps: TP-013, TP-019 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Freshly rebuilt PDFs bake in stale counts and now-false CI claims: seal sec12:50-64 shows
265/256/265/265 (current: 267/258/267/267), sec12:70 + sec14:114 claim "required check for merging to main" / 1051
PASS; umbrella sec06 similar. Refresh count tables from an actual harness run, rephrase CI claims to the
post-TP-013 reality (or remove point-in-time counts in favor of "see harness output"). Rebuild all PDFs.
Acceptance: no number in a PDF contradicts a live run.

#### TP-056 · P1 · 56 · docs · id-paper-variant-registry-0x04
Deps: — · Status: DONE (2026-06-10)
Hand-off: TID ticket. The TesseraID paper's normative variant registry says "0x04–0xFE reserved for future"
(sec03_part2_spec.tex:48) while its own title page (main.tex:141) and appendix (sec14:139) allocate 0x04 =
TesseraSeal. Update sec03 to list 0x04 = TesseraSeal (allocated 2026, MUST reject) and 0x05–0xFE reserved-future,
matching the other three registries. Acceptance: all four papers show one registry.

#### TP-057 · P1 · 57 · docs · pad-guard-misstatements-cross-paper
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Two cross-paper pad-bit errors: (a) the TesseraID paper states a mathematically impossible
Base64URL pad split for TesseraHash ("final character carries 4 bits of value plus 4 bits of zero padding" — 8
bits in a 6-bit char, sec03_part2_spec.tex:206), contradicting the TesseraHash paper; (b) the umbrella paper claims
both projects "apply the same padding-bit guards" with TesseraHash's numbers for both (sec03_shared_namespace.tex:67
— actual: TesseraID 2/2, TesseraHash 4/1). Fix both; consider replacing duplicated TesseraHash normative prose in
the TesseraID paper with a non-normative pointer. Acceptance: pad-bit math correct and consistent in all papers.

#### TP-058 · P1 · 58 · docs · security-bounds-harmonization
Deps: — · Status: DONE (2026-06-10)
Hand-off: THASH ticket. Second-preimage bounds are stated three different ways: 2^256 in TL;DR + Python docstring
(sec01:20, tessera_hash.py:22) vs 2^512 in sec02/sec07/sec11 — and 2^512 itself overstates FIPS 202's
min(d, 256)-bit cap for SHAKE-256, contradicting the TesseraID paper's formulation. Restate everywhere as
min(2^d, 2^256) per FIPS 202 (classical) with the Grover column alongside; fix the Python docstring; align the
TesseraID sibling section. Acceptance: one defensible bound everywhere.

#### TP-059 · P1 · 59 · docs · bibliography-defects
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. references.bib defects: the load-bearing UtC citation `bellare2022commitment` points to
ePrint 2022/1260 which is `chan2022commit`'s ID (UtC is ePrint 2022/268); `bellare2024gcmsst` and another entry
share 2024/875; `len2021aead` should be 2020/1491; one suspect author list (Terrapin). Fix IDs, dedupe, verify
each cited entry resolves to the claimed paper, rebuild. Acceptance: every citation spot-checked and correct.

#### TP-060 · P1 · 60 · docs · umbrella-editorial-artifact
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Published umbrella roadmap contains a drafting artifact: "a hypothetical tesseraseal v2 at
variant 0x06--no wait, that's already taken" (sec08_roadmap.tex:55-57) — which also conflates suite bytes with
variant bytes. Rewrite (a v2 envelope takes a new VARIANT byte from 0x05–0xFE; 0x06 is a SUITE byte inside variant
0x04), and proofread the umbrella for similar residue before rebuild. Acceptance: clean prose; namespace
distinction correct.

#### TP-061 · P2 · 61 · docs · rfc2119-declarations
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Only the TesseraID paper declares RFC 2119 keyword meanings (sec03_part2_spec.tex:7); the
other three papers use MUST/SHOULD normatively with no declaration. Add the one-sentence BCP 14 (RFC 2119 +
RFC 8174) declaration to the conventions/front matter of tessera-hash, tessera-seal, and umbrella papers.
Acceptance: all four papers declare keyword semantics.

#### TP-062 · P2 · 62 · docs · tessera-hash-errata-sweep
Deps: — · Status: DONE (2026-06-10)
Hand-off: THASH ticket. Numeric/factual errata in one PR: timestamp range lower bound says 2017-10-09 but
1_700_000_000_000 ms = 2023-11-14 (sec03:19 — state the true field range [1970, ~10889] and separately note
MIN_TIMESTAMP_MS as the non-normative sanity gate, mirroring tessera-id sec03:84-86); "147" hex chars (should be
146); "33–38% shorter" recheck; "two orders of magnitude" recheck; "OS monotonic clock" wording. Also evaluate
migrating Go to stdlib crypto/sha3 so the supply-chain "stdlib" claim is exact (KAT-gated). Acceptance: every
number in the paper recomputed and correct.

#### TP-063 · P2 · 63 · docs · ticket-map-and-aegis-date-reconciliation
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. The whitepaper v1.4 backlog map conflicts with CLAUDE.md (C++ hybrid port omitted, numbers
shifted, TSEAL-00035 double-assigned to CI-histogram and the BadKey work; sec14_appendices.tex:99, sec08_roadmap)
and the AEGIS deferral is dated "November 2026" — a future date — in a May 2026 decision record (sec04_suites.tex:24,
sec14:55). Reconcile the ticket registry once (CLAUDE.md as source of truth, PQCK-NNNNN = historical, TSEAL-NNNNN =
continued numbering), add the C++ hybrid port, fix dates, normalize prefixes. Coordinate with TP-075. Acceptance:
one ticket registry, no future-dated history.

#### TP-064 · P1 · 64 · docs · crockford-guard-wording-fix
Deps: — · Status: DONE (2026-06-10)
Hand-off: TID ticket. Root CLAUDE.md invariant #4, tessera-id/CLAUDE.md, tessera-id/README.md:27,133, and Go
comments (go/tessera_id.go:357,409) all describe the Crockford guard as "top 2 bits of the 330-bit value must be
zero" — the whitepaper and all code actually check the final character's LOW 2 bits (stream-trailing pad bits).
Rewrite all five surfaces to the whitepaper wording. Acceptance: guard description identical and correct everywhere.

#### TP-065 · P1 · 65 · docs · benchmark-provenance-and-rerun
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. The whitepaper's "verified benchmark data" was measured in a Claude agent sandbox VM
(/home/claude path + generic KVM CPU string leak in checked-in outputs) and the captured artifacts were hand-edited
by the rename commit — provenance false by omission. Also: tessera-hash/benchmarks/ is empty while sec08:66,75
claims per-language benchmark files; tessera-seal/benchmarks/README.md says "placeholder" while populated. Re-run
all benchmarks on documented physical hardware (CPU SKU, governor, isolation) or amend methodology.md to disclose
the environment class; adopt the rule that captured outputs are never hand-edited (regenerate instead); fix the
two benchmark-dir status claims; add the missing tessera-hash bench (TP-103 overlap). Acceptance: every published
number has truthful provenance.

#### TP-066 · P2 · 66 · docs · common-header-consumption-claim
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. common/c/tessera_header.h:28-30 claims consumption by all three projects' C ports; only
tessera-seal includes it — tessera-id and tessera-hash re-define offsets locally. Either include it from
tessera-hash/c and tessera-id/c (defining project macros in terms of umbrella macros) or correct the comment and
the two whitepaper sentences repeating the claim. Acceptance: claim matches includes.

#### TP-067 · P2 · 67 · docs · tessera-hash-streaming-prose
Deps: — · Status: DONE (2026-06-10)
Hand-off: THASH ticket. sec04:42 describes streaming the sponge via "each language's incremental API", but every
public API is one-shot and the vendored common/ Keccak has no incremental absorb/squeeze. Either soften sec04 to
"one-shot today; streaming is backlog" or add an incremental API to common/ + per-language streaming entry points
with KAT coverage (large work — see TP-139 for the strategic variant). Recommended: soften now, link TP-139.
Acceptance: spec describes shipped behavior.

#### TP-068 · P2 · 68 · docs · umbrella-whitepaper-linking
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. latex/Tessera_Whitepaper.pdf is tracked but referenced by zero documentation. Link it from
README.md (umbrella whitepaper bullet under Projects), state its non-normative status relative to project papers in
CLAUDE.md, and ensure latex.yml builds it (TP-012). Acceptance: discoverable + status declared.

#### TP-069 · P3 · 69 · refactor · latex-macro-rename
Deps: — · Status: DEFERRED-TO-BACKLOG (2026-06-10) — cosmetic; not in strategic backlog
Hand-off: TESS ticket. Cosmetic: \pqcrypt/\pqid/\pqhash/\pqtoolkit macros remain in seal + umbrella LaTeX
(main.tex:104-107), rendering correctly to new names. Rename to \tseal/\tid/\thash/\tessera in a no-output-change
commit; verify by pdftotext diff. Leave frozen KDF labels and historical ticket IDs untouched. Acceptance: zero
rendered-output change.

---

## Wave 4 — Docs & DX (P1/P2)

#### TP-070 · P1 · 70 · feat · python-packaging-and-cli-entrypoint
Deps: TP-006 · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket (the single highest-leverage DX fix). The only documented CLI invocation
`python -m tessera_seal.cli` cannot work — tessera-seal/python/ is a flat module, not a package, with no
pyproject.toml; cli.py's docstring shows an installed `tessera-seal` command that has no entry point; README flag
names (`pubkey --keyfile`, encrypt flags) don't match cli.py's actual flags. Restructure tessera-seal/python into a
`tessera_seal/` package with cli as a submodule, add pyproject.toml (deps from requirements.txt, py.typed,
__version__, console_script `tessera-seal`), fix both READMEs' command examples to verified-working invocations,
fix the flag mismatches. Acceptance: `pip install -e .` then `tessera-seal keygen/pubkey/encrypt/decrypt/info` all
work exactly as documented; root README.md:56 verified.

#### TP-071 · P0 · 71 · sec · cli-reject-unsupported-suite-flag
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. `keygen --suite 0x06` is parsed and silently dropped (cli.py:300-302 registers, 106-110
never forwards; plugin keygen hardcodes default) — the docstring's hybrid example yields a pure-ML-KEM key while
the user believes they have X25519 defense-in-depth: a silent security-posture downgrade. Make cmd_keygen hard-error
on any suite it cannot honor ("hybrid keyfiles land in v1.4", nonzero exit) or remove the flag + docstring example
until TP-121+ land. Small, ships independently of TP-070. Acceptance: no silently-ignored security-relevant flag.

#### TP-072 · P1 · 72 · docs · tessera-hash-readme
Deps: — · Status: DONE (2026-06-10)
Hand-off: THASH ticket. tessera-hash has no project README.md at all (root README links only CLAUDE.md + PDF).
Create one mirroring tessera-id/README.md's shape: wire format, encodings, tree, authority order, quick start per
language, invariants. Link from root README's tessera-hash section. Acceptance: parity with sibling projects.

#### TP-073 · P1 · 73 · docs · stale-placeholder-status-sweep
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. tessera-seal/cpython/README.md says "Status: v2 placeholder. Lands once
tessera_seal_fast.py is stable" while the directory contains a 12.5K implemented v1.1 extension; the TS README has
a similar stale status; root README.md:89 repeats "(v2 placeholder)". Rewrite all three to actual v1.1 status
(wraps c/tessera_seal.c, suites 0x01/0x02, build via setup.py), consistent with the CLAUDE.md table. Acceptance:
no "placeholder" label on shipped code.

#### TP-074 · P2 · 74 · docs · broken-links-sweep
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. 20 broken relative markdown links, mostly rename fallout — 3 in project skills
(tessera-seal-impl/SKILL.md:100 → old tseal-00028/00029 filenames; tessera-hash/CLAUDE.md:39 → nonexistent file).
Fix the 3 skill links (+ refresh `updated:` timestamps) and CLAUDE.md:39; for historical release notes either
retarget links or add a header noting links predate the rename. Add a link-check script to CI (manual dispatch ok).
Acceptance: link checker green repo-wide.

#### TP-075 · P2 · 75 · docs · ticket-prefix-mapping
Deps: TP-063 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. The same tickets appear as PQCK-NNNNN and TSEAL-NNNNN in different docs, and root CLAUDE.md's
conventions omit TSEAL/THASH/TID prefixes. State the mapping once in tessera-seal/CLAUDE.md (PQCK = historical/
closed, TSEAL = same numbering continued), normalize forward-looking references to TSEAL-*, add the prefix table to
root CLAUDE.md conventions. Acceptance: one prefix story.

#### TP-076 · P2 · 76 · docs · stale-test-counts
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. tessera-seal/python/README.md:8,45 claims 56/56 tests, tessera-seal/README.md:22 claims
"62+"; actual pytest count is 65. Update or — better — drop exact counts in favor of "see pytest output" to end
the recurring drift. Acceptance: no stale counts.

#### TP-077 · P2 · 77 · docs · per-language-usage-examples
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. All "Quick start per language" sections contain only test/bench commands — zero library
usage code anywhere; no examples/ directory exists. Add a 5-10 line use-as-a-library snippet per language per
project (new→encode→decode for id/hash; keygen→encrypt→decrypt for seal) plus cross-language interop examples
("decode in lang A what lang B produced"), and an examples/ dir per project exercised by CI so snippets cannot rot.
Acceptance: every snippet executed by a CI step.

#### TP-078 · P1 · 78 · docs · seal-chunking-recipe-doc
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. No streaming story: single-shot API with 4 GiB cap, whole-file buffering in the CLI, no
large-payload guidance. Until TP-127 (v2 streaming), add a documented interim chunking recipe to tessera-seal/docs
+ whitepaper appendix: envelope-per-chunk, AD = TesseraID ‖ chunk_index ‖ total, counter monotonic; note the CLI's
whole-file buffering in --help and README. Acceptance: an adopter has a safe pattern for large files today.

#### TP-079 · P2 · 79 · refactor · tessera-hash-api-destutter
Deps: TP-006 · Status: DONE (2026-06-10)
Hand-off: THASH ticket. Go package `tesserahash` exports TesseraHashHashOnly/TesseraHashEncodeBase64URL/… (stutters
against Go style and sibling tessera-id conventions); TS similar; tessera-hash TS lacks the InvalidEncoding/
UnknownVariant error subclasses tessera-id TS has. De-stutter Go/TS exports (HashOnly, EncodeBase64URL, Decode),
add TS error subclasses. Breaking rename — do before any external publication (sequence with TP-085+). Acceptance:
API symmetry across projects.

#### TP-080 · P2 · 80 · feat · sender-context-c-cpp-java
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. SenderContext (counter management) exists in Python/Go/Rust/TS but not C/C++/Java; C++
silently defaults counter=0. Add `tessera_seal_sender_ctx_t` to the C API and surface in C++/Java, or explicitly
document in tessera_seal.h + C++/Java READMEs that CTR monotonicity is the caller's job and counter=0 is
acceptable (K_session uniqueness derives from the KEM). Recommended: add the context. Acceptance: parity or
documented divergence.

#### TP-081 · P3 · 81 · feat · peek-ad-helper
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. peek_header exposes ad_len but not the AD bytes in every language, despite AD being
cleartext-on-wire and the TesseraID-as-AD pattern being the canonical routing use case. Add peek_ad() alongside
peek_header() in all languages with the "unauthenticated — attacker-controlled until decrypt" doc warning, or
document the slicing recipe in the README's AD section. Acceptance: routing-before-decrypt has a first-class API.

#### TP-082 · P2 · 82 · docs · conformance-readme-fixes
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. tessera-id/conformance/README.md documents a nonexistent `tessera-id/conformance/run.sh`
(real harness: tools/conformance/run.sh); tessera-hash/conformance has no README and ships an empty stray runners/
directory. Fix the path, add tessera-hash/conformance/README.md documenting the tessera_hash_* op schema (or
declare the tessera-id README authoritative), `rmdir` the empty dir. Acceptance: conformance docs navigable and
truthful.

#### TP-083 · P2 · 83 · docs · conformance-skill-truthfulness
Deps: TP-019 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. `.claude/skills/tessera-conformance/SKILL.md:147` claims conformance.yml ignores
TESSERA_CONFORMANCE_SKIP (false — the workflow's alpha step uses it) and documents the wrong FAIL output format.
Rewrite to describe the real two-step CI shape (post-TP-013), fix the format example, refresh `updated:`.
Acceptance: skill executable as written.

#### TP-084 · P2 · 84 · feat · id-and-hash-clis
Deps: TP-070 · Status: DONE (2026-06-10)
Hand-off: TID+THASH ticket. No CLI exists for tessera-id or tessera-hash in any language. Add minimal Python CLIs
reusing the references: `tessera-id` (new / new-hlc / decode / encode --b32|--b64) and `tessera-hash`
(hash / verify / decode), packaged via the TP-070 pattern. (The unified killer-CLI binary is TP-131; this is the
minimal ergonomic floor.) Acceptance: documented commands work post-install.

---

## Wave 5 — Packaging & distribution (P2; gated on TP-006/TP-085)

#### TP-085 · P2 · 85 · chore · distribution-posture-decision
Deps: TP-006 · Status: DECISION-RECORDED (2026-06-10) — see docs/decisions/2026-06-10-distribution-posture.md
Hand-off: TESS ticket. Nothing is published anywhere (verified: crates.io/npm/PyPI 404; zero git tags; no publish
workflow; github.com/barum/tessera not publicly resolvable). Decide explicitly: (a) publish canonical artifacts
(at minimum Python ref + Rust crate + npm package) with tag-driven automation, or (b) document "vendoring-only, no
published artifacts" in the root README. Everything in TP-086..TP-094 keys off this. Acceptance: recorded decision;
README states the posture.

#### TP-086 · P2 · 86 · chore · version-coherence-and-tags
Deps: TP-085 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Manifests disagree (Cargo.tomls 0.1.0; package.jsons/setup.pys 1.0.0; release notes v1.3);
zero git tags despite v1.0–v1.3 release notes; no SemVer/stability policy. Pick one version source of truth per
project aligned to release notes (e.g. 1.3.x), propagate into every manifest + a __version__/VERSION constant per
language, tag milestones retroactively (tessera-seal/v1.3 at its commit; tessera/v2026.06.08 at the rename), tag
future releases in the release-notes workflow, add a short versioning-policy doc (wire-format version vs impl
version). Acceptance: one version story, tags exist.

#### TP-087 · P2 · 87 · chore · rust-crate-metadata
Deps: TP-085, TP-006 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. All three crates lack license/description/repository/readme metadata (cargo package warns;
unpublishable). Add `license = "Apache-2.0"`, description, repository, readme, keywords to each (or
`publish = false` if vendoring-only), move [profile.release] to the workspace root. Acceptance: `cargo package`
clean per crate.

#### TP-088 · P2 · 88 · chore · npm-package-metadata
Deps: TP-085, TP-006 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. npm packages point main/types at gitignored dist/, lack license/description/repository/
files/exports, no prepare script — not installable from git, not publishable. Add the metadata + exports map,
add a `prepare` script so git installs build dist/ (or commit dist/ on release), or set `"private": true`
explicitly if not publishing. Acceptance: `npm pack` produces a working tarball (or explicit private).

#### TP-089 · P2 · 89 · fix · go-module-paths-fetchable
Deps: TP-085, TP-006 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Module paths are unfetchable bare names (`module tesseraid` / `tesserahash` / `tesseraseal`)
and tessera-hash carries a `replace tesseraid => ../../tessera-id/go` directive that is ignored when consumed as a
dependency — structural consumption blocker. Rename to repo-rooted form (github.com/<org>/<repo>/tessera-id/go …),
drop the replace in favor of real module path + version, keep go.work for local dev. One-time breaking rename —
do before first tag. Acceptance: `go get` works from a public checkout (or paths documented as placeholder pending
TP-006).

#### TP-090 · P2 · 90 · chore · java-maven-packaging
Deps: TP-085 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Java has raw-javac Makefiles only — no pom.xml/Gradle, no jar target, no coordinates. Add a
minimal Maven pom per Java tree (com.tessera groupId, version per TP-086, jar packaging, toolchain/release pins).
Publishing can stay deferred; the artifact should exist. Acceptance: `mvn package` produces jars; Makefiles keep
working or delegate.

#### TP-091 · P2 · 91 · chore · c-cpp-install-targets
Deps: TP-085 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. C/C++ have no install target, no pkg-config, no CMake — consumption is undocumented
multi-directory source copying (project headers + common/). Add an `install` target + .pc file (or CMakeLists
producing static/INTERFACE targets) installing tessera_*.h + common/ headers + static libs; document the minimal
vendoring file set per project README. Acceptance: a downstream C program can build against an installed prefix.

#### TP-092 · P2 · 92 · chore · cpython-wheel-pipeline
Deps: TP-085 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. CPython extensions can't ship: setup.py sources reach outside the package dir
(`../c/tessera_id.c`, `../../common/c/...`), no pyproject metadata, no cibuildwheel, versions stuck at 1.0.0. If
shipping: restructure with a src layout that vendors/copies the needed C files at sdist time, move metadata to
pyproject.toml, add a cibuildwheel workflow. If not: mark explicitly build-from-checkout in their READMEs.
Acceptance: wheels build on 3 OSes, or posture documented.

#### TP-093 · P2 · 93 · feat · release-publish-workflow-with-provenance
Deps: TP-086, TP-087, TP-088, TP-089, TP-090, TP-013 · Status: PARTIAL (2026-06-10) — release.yml drafted; publishing gated on TP-006/TP-085
Hand-off: TESS ticket. No release/tag/publish automation exists. Add a tag-triggered workflow that: runs the full
conformance gate, builds all four whitepapers, builds artifacts per language, publishes via trusted publishing
with provenance (PyPI attestations, npm SLSA-L3 default, crates.io trusted publishing), signs binaries
(sigstore/Sigsum like age), attaches checksummed artifacts to a GitHub Release. Day-one provenance is a
differentiator incumbents retrofitted slowly. Acceptance: one tag produces signed, attested artifacts end-to-end.

#### TP-094 · P2 · 94 · chore · spdx-license-propagation
Deps: — · Status: PARTIAL (2026-06-10) — manifest license metadata done; per-file SPDX headers deferred
Hand-off: TESS ticket. Apache-2.0 exists only at repo root; no license field in any Cargo.toml/package.json/
setup.py; no SPDX headers; README never names the license. Add SPDX license fields to every manifest,
SPDX-License-Identifier headers to source files (scriptable), and a license line in README. Acceptance: every
artifact self-describes its license.

---

## Wave 6 — Testing depth & supply chain (P2)

#### TP-095 · P2 · 95 · chore · property-based-testing
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Zero property-based testing in any of 8 languages (verified by dependency greps). Start with
hypothesis on the canonical Python references: decode∘encode identity over full field domains; byte-sort ≅
(ts, counter, random) lexicographic order; HLC merge idempotence/monotonicity; seal encrypt∘decrypt identity with
random suites/AD/lengths; non-canonical text forms always rejected. Then proptest (Rust) and go-fuzz-derived
properties as a second tier. Acceptance: property suites in CI dispatch; at least Python landed.

#### TP-096 · P2 · 96 · sec · decoder-fuzzing-seal-hash-ossfuzz
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL+THASH ticket. Coverage-guided fuzzing exists only for tessera-id Go decoders; tessera-seal — the
one format with a variable-length attacker-controlled layout (KEM_CT_LEN/AD_LEN driving offset arithmetic in C) —
has no fuzz harness in any language; tessera-hash none; tessera-id/rust/fuzz/ is an empty leftover dir. Add:
cargo-fuzz target on seal decrypt/peek_header, `go test -fuzz` on seal Decode/Decrypt, libFuzzer harness for the C
reference (canonical ABI, manual offset math), mirror for tessera-hash decoders. Then enroll the C targets in
OSS-Fuzz. Acceptance: fuzzers run clean for an agreed budget; OSS-Fuzz application submitted.

#### TP-097 · P3 · 97 · feat · differential-fuzzing-oracle
Deps: TP-096 · Status: DONE (2026-06-10) — differential oracle landed
Hand-off: TESS ticket (strategic — also market move). Build a cryptofuzz-style differential fuzzer on top of the
existing 8 conformance runners: random structured inputs → all languages → assert identical accept/reject +
identical bytes. No other greenfield format project has 8 first-party implementations to diff; this converts the
polyglot matrix into a unique correctness asset and a marketing artifact. Acceptance: differ runs in CI dispatch;
divergences it finds become KAT records (per TP-023 append-only).

#### TP-098 · P2 · 98 · chore · concurrency-tests-and-race-detector
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Only two concurrency tests exist repo-wide; the HLC locking contract is untested; Go race
detector never used in CI. Add an HLC-under-threads test (N threads, one generator: global uniqueness, per-thread
monotonicity, drift behavior) to Python/Go/Rust/Java; switch CI Go steps to `go test -race`. Acceptance: race-clean
runs; HLC contract enforced by tests in 4+ languages.

#### TP-099 · P2 · 99 · chore · hash-ts-java-unit-tests
Deps: TP-032 · Status: DONE (2026-06-10)
Hand-off: THASH ticket. tessera-hash TS and Java have zero unit tests; documented commands fail (`npm test` —
missing script; `make test` — no target). Port the Python negative tests (variant rejection, non-canonical encoding
rejection, cross-decode rejection) to TS (node:test) and Java; wire test scripts/targets; fix the CLAUDE.md build
table. Rust tests/ dir is also empty — add inline-module coverage check. Acceptance: documented test commands
exist and pass in all languages.

#### TP-100 · P2 · 100 · chore · plugin-protocol-tests
Deps: TP-038 · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. ~18.5 KB of plugin/keyfile code has zero tests. Add a pytest module: keyfile wrap/unwrap
roundtrip, v1.0-format compat decrypt, wrong-passphrase failure, embedded-pubkey query path, frame protocol
encode/decode with truncated/oversized frames, KDF-path coverage per TP-038. Acceptance: plugin covered; failure
modes pinned.

#### TP-101 · P2 · 101 · chore · fuzz-loop-honesty
Deps: TP-096 · Status: DONE (2026-06-10)
Hand-off: TID ticket. 7 of 8 tessera-id "fuzz" harnesses are fixed-seed deterministic loops replaying identical
inputs every run (e.g. python/fuzz/fuzz_decode.py:118 SEED='20260519'). Seed from time/commit SHA in CI (log the
seed for reproduction), treat Go native fuzz as the real tier and grow its corpus (currently 1 file), rename the
fixed loops "regression replay" so docs stop overstating. Acceptance: no harness labeled fuzz replays a constant.

#### TP-102 · P2 · 102 · chore · coverage-measurement
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. No coverage tooling in any language. Add pytest-cov to the three Python reference suites
(cheapest, highest value), cargo llvm-cov and `go test -coverprofile` to the manual CI dispatch; publish numbers
in the conformance summary; don't gate initially. Acceptance: coverage visible per language.

#### TP-103 · P2 · 103 · chore · benchmark-regression-and-hash-bench
Deps: TP-065 · Status: PARTIAL (2026-06-10) — benches re-run + tessera-hash bench added; no CI regression gate
Hand-off: TESS ticket. Benchmarks: tessera-id well-documented; tessera-seal populated but labeled placeholder;
tessera-hash absent; nothing regression-gated. Delete the placeholder line, add a minimal tessera-hash bench
(hash_only + encode throughput), and if perf is a selling point add a tolerance-banded comparison step to CI
dispatch. Acceptance: three projects have reproducible benchmarks with methodology.

#### TP-104 · P1 · 104 · sec · lockfiles-and-exact-pins
Deps: TP-008 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Supply-chain gaps: no Cargo.lock committed for seal; TS deps caret-ranged (@noble ^0.5 etc.);
Python requirement floors not exact pins. Commit Cargo.lock + TS lockfiles, gate CI on `--locked` /
`npm ci --frozen-lockfile` installs, convert crypto deps to exact pins bumped only via reviewed PRs. Acceptance:
reproducible dependency resolution everywhere.

#### TP-105 · P2 · 105 · chore · ts-unused-curves-dep
Deps: TP-104 · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. tessera-seal TS ships @noble/curves ^2.2.0 as a production dependency with zero imports
(reserved for the future hybrid port). Remove until TP-123 wires it in, then pin exactly. Acceptance: prod deps ==
consumed deps.

#### TP-106 · P2 · 106 · sec · plugin-passphrase-channel-hardening
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. The plugin reads the keyfile passphrase from an environment variable
(tessera_seal_plugin_file.py:218-221). Restrict the env path to CI/test, document the leak surface (process
listing, /proc/environ, crash dumps), prefer interactive getpass or an fd/agent-based channel for production.
Acceptance: documented + default-safe.

#### TP-107 · P2 · 107 · chore · seal-ext-test-harness-resilience
Deps: TP-002 · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. test_tessera_seal_ext.py aborts on first error (decrypt call outside try/except kills
main() before ~20 remaining checks + both KAT loops) — one regression hides all others. Wrap roundtrip/decrypt
assertions in the same count-and-continue pattern the KAT loops use. Acceptance: a single failure yields a full
report.

---

## Wave 7 — Repo hygiene (P2)

#### TP-108 · P2 · 108 · chore · vscode-and-gitignore
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. `.vscode/` is untracked-and-unignored (limbo); its settings.json pins typescript.tsdk with a
real rationale. Decide: commit it (it encodes a cross-tool compatibility decision) or add `.vscode/` to .gitignore.
Either way add `.venv/` and `.env` to .gitignore. Acceptance: clean `git status`.

#### TP-109 · P2 · 109 · chore · dedupe-tracked-pdfs
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Byte-identical duplicate PDFs tracked in all four latex/ dirs (main.pdf == *_Whitepaper.pdf,
md5-verified). Add `*/latex/main.pdf` + `/latex/main.pdf` to .gitignore, `git rm --cached` the four main.pdf
copies, keep only named *_Whitepaper.pdf artifacts, and state the per-project PDF tracking policy in CLAUDE.md
(currently only TesseraID's PDF is policy-mandated). Acceptance: one tracked PDF per paper; policy written.

#### TP-110 · P2 · 110 · chore · git-history-and-identity
Deps: — · Status: DECISION-RECORDED (2026-06-10) — no history rewrite
Hand-off: TESS ticket. History debt: largest feature landing arrived as non-conventional commits "v4"/"pqencrypt"
(2,877+ insertions); ~10 MB dead Go binaries + ~6 MB PDF revisions permanently in history; merge commits despite
squash policy; 49/50 commits authored under the employer email (bahrams@jfrog.com) on a personal repo. Actions:
document the v4/pqencrypt content in seal release notes for traceability; add a commit-msg lint hook; set
repo-local user.email to the personal address + add .mailmap; decide whether a pre-1.0 git-filter-repo pass
dropping the three runner blobs (~35% clone shrink) is acceptable — single-maintainer repo, but published main.
Acceptance: decision recorded; hooks in place; identity unified going forward.

#### TP-111 · P2 · 111 · chore · orphan-dirs-cleanup
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Empty orphan dirs: common/cpp (CLAUDE.md implies C++ Keccak should live there — reword the
common/ bullet instead), tessera-id/rust/fuzz, tessera-hash/rust/tests, tessera-hash/benchmarks,
tessera-hash/conformance/runners, others. rmdir them (or populate per TP-096/TP-099/TP-103), fix the CLAUDE.md
wording. Acceptance: no empty tracked dirs; docs match layout.

#### TP-112 · P2 · 112 · chore · branches-and-gofmt
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Two stale fully-merged local branches (feat/pqhash-v1, …) — delete. Five Go files fail
gofmt (tessera-id/go/tessera_id.go, tessera-seal/go/tessera_seal.go + bench_test.go, others) — run gofmt -w and
add a `gofmt -l` check step to go.yml. Acceptance: clean branch list; format-checked CI.

#### TP-113 · P2 · 113 · chore · generator-script-and-c-warnings
Deps: — · Status: DONE (2026-06-10)
Hand-off: TID ticket. conformance/scripts/generate.py has no argparse — running it with `--help` regenerates all
vector files (silent side effect; byte-identical today by luck/discipline). Add argparse with an explicit
`--write` flag. Also size the C alphabet array initializers ([33]/[65]) to silence compiler warnings. Coordinate
with TP-023 (freeze check makes accidental regeneration harmless). Acceptance: no side-effectful --help; clean
C build.

---

## Wave 8 — Governance, legal, security posture (P1, parallelizable from day 1)

#### TP-114 · P1 · 114 · sec · security-md-and-cvd
Deps: — · Status: DONE (2026-06-10)
Hand-off: TESS ticket. No SECURITY.md or coordinated-disclosure policy in a security-focused crypto repo — an
OpenSSF Scorecard zero and the cheapest unfixed credibility gap. Add SECURITY.md: private reporting channel
(enable GitHub private vulnerability reporting), supported scope (which suites/languages/versions), disclosure
SLA, embargo process. Acceptance: GitHub security tab functional; policy published.

#### TP-115 · P1 · 115 · chore · copyright-notice-and-ip-carveout
Deps: — · Status: DECISION-RECORDED (2026-06-10) — employer carve-out OPEN; see docs/decisions/2026-06-10-ip-provenance.md
Hand-off: TESS ticket. No copyright owner is named anywhere; all development under an employer email; AI
co-authorship on security-critical commits; the spec claims multi-decade ambitions. Name the copyright owner
(NOTICE file + README line + LICENSE appendix), obtain or document an employer IP carve-out/acknowledgment BEFORE
publication, switch commit identity (TP-110). Maintainer decision + possibly employer conversation required.
Acceptance: provenance answerable in writing.

#### TP-116 · P1 · 116 · chore · export-control-notice
Deps: — · Status: BLOCKED-EXTERNAL (2026-06-10) — README notice + docs/export-control.md done; BIS notification email is a maintainer action at go-public
Hand-off: TESS ticket. The repo ships working ML-KEM-1024/AES-256-GCM/ChaCha20/X25519 source in 8 languages —
textbook ECCN 5D002. The publicly-available exemption (15 CFR 734.3(b)(3) via 742.15(b)/740.13(e)) requires a
one-time email notification to BIS (crypto@bis.doc.gov) + NSA ENC coordinator with the repo URL at/before public
availability. Add an export-notice section to the root README (ECCN 5D002, publicly-available source per EAR
742.15(b), notification reference) and send the email when the repo goes public; keep the sent notice on file.
Acceptance: notice in README; notification sent/filed.

#### TP-117 · P2 · 117 · docs · contributing-coc-citation
Deps: TP-114 · Status: DONE (2026-06-10)
Hand-off: TESS ticket. Missing standard OSS docs: CONTRIBUTING.md (distill CLAUDE.md's conventions: branch/PR/
ticket format, conformance gate expectations, lockstep-port rule), CODE_OF_CONDUCT.md, CITATION.cff for the
whitepapers. Acceptance: all three present and linked from README.

#### TP-118 · P2 · 118 · chore · openssf-scorecard-and-badge
Deps: TP-114, TP-015, TP-013 · Status: PARTIAL (2026-06-10) — scorecard workflow added; badge/publish need a public repo
Hand-off: TESS ticket. Run OpenSSF Scorecard in CI (manual dispatch initially), work the top deductions (most are
covered by TP-013/015/093/114), pursue the OpenSSF Best Practices badge. Acceptance: scorecard step running;
badge application submitted.

#### TP-119 · P3 · 119 · feat · c2sp-spec-submission
Deps: TP-049, TP-055, TP-115 · Status: PARTIAL (2026-06-10) — plan written (docs/decisions/2026-06-10-c2sp-submission-plan.md); submission gated on TP-006/TP-085/TP-115
Hand-off: TESS ticket (strategic governance). Submit the TesseraSeal envelope spec + the shared variant-byte
registry to C2SP (the maintainer-driven venue hosting age's spec, Wycheproof, CCTV): versioned freeze a third
party can cite, instant "not just my repo" legitimacy, no consensus process. Requires whitepaper truthfulness
items done first. Acceptance: C2SP PR opened; spec text extracted into standalone versioned form.

---

## Wave 9 — Strategic / market (P3) — close the gap, then surpass

#### TP-120 · P3 · 120 · docs · policy-profiles-cnsa-vs-eu
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. Regulators split: CNSA 2.0 matches PQ-only ML-KEM-1024 (suites 0x01/0x02); BSI TR-02102-1
(2026-01) and ANSSI mandate/prefer hybrid (suite 0x06). Ship named "policy profiles" as documentation +
conformance gates: CNSA-2.0 profile and EU profile — turning the PQ-only-vs-hybrid split from a liability into a
selectable feature. One page + a conformance tag per profile. Acceptance: an adopter can name their regulator and
get a suite prescription.

#### TP-121 · P3 · 121 · feat · hybrid-0x06-c-port
Deps: TP-007 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TSEAL ticket (existing backlog TSEAL-00030, now unblocked: OpenSSL 3.5+ — the pinned C dependency —
already exposes X25519 EVP, zero new deps). Port hybrid suite 0x06 to C per the skill playbook: new
pub/priv hybrid structs + dedicated entry points preserving the v1.0/v1.1 ABI byte-for-byte, flip
hybrid_supported() c=true, consume hybrid_*.json KATs byte-identically. EU-regulator order: C first. Acceptance:
c reports 267/0 (258+9 hybrid).

#### TP-122 · P3 · 122 · feat · hybrid-0x06-java-port
Deps: TP-121 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TSEAL ticket (backlog TSEAL-00032): SunJCE XDH (JEP 339) for X25519 + JEP 452 ML-KEM, flip
hybrid_supported(), KATs byte-identical. Acceptance: java hybrid KATs green.

#### TP-123 · P3 · 123 · feat · hybrid-0x06-typescript-port
Deps: TP-122, TP-105 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TSEAL ticket (backlog TSEAL-00031): @noble/curves X25519, re-add the dep pinned exactly, flip
hybrid_supported(), KATs byte-identical. Acceptance: ts hybrid KATs green.

#### TP-124 · P3 · 124 · feat · hybrid-0x06-cpp-cpython-ports
Deps: TP-121, TP-002 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TSEAL ticket (backlog: C++ wraps the C lib — the ticket the whitepaper map omitted, see TP-063; CPython
ext mirrors via the C reference). Flip both hybrid_supported() entries, KATs byte-identical. Completes the 8/8
hybrid matrix — retire the "really 4+4" honesty gap. Acceptance: full-8 run shows hybrid in every language.

#### TP-125 · P3 · 125 · feat · ascii-armor
Deps: — · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TSEAL ticket. Binary-only blocks the secrets-in-git/config-file use case that built age's user base
(sops). Spec + implement an armored text encoding for envelopes (header/footer lines + base64 body, fixed width),
polyglot with KATs, CLI `--armor`. Days of work, large adoption unlock. Acceptance: armored round-trip in alpha-4
languages + KAT records.

#### TP-126 · P3 · 126 · feat · v2-multi-recipient-committing-spec
Deps: TP-119 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TSEAL ticket (the leapfrog thesis). The wire format carries exactly one KEM_CT — "encrypt to team /
me+backup" is impossible, and it's the workflow that drives age/sops adoption. Design TesseraSeal v2 (new VARIANT
byte from 0x05–0xFE, per TP-060's namespace correction): N recipient stanzas, per-recipient KEM_CT + committing
wrap of K_session, preserving single-DecryptionError oracle discipline and per-recipient UtC commitment. Verified
market gap as of 2026-06: nobody anywhere ships a multi-recipient PQ envelope with commitment — age's
multi-recipient ambiguity from non-committing AEAD is its documented open weakness. Spec-first: whitepaper section
→ Python ref → lockstep ports → KATs. Acceptance: v2 spec published with vectors; Python+Rust+Go reference.

#### TP-127 · P3 · 127 · feat · v2-streaming-committing-aead
Deps: TP-126 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TSEAL ticket. Single one-shot AES-256-GCM means whole-file buffering, no seek, no pipes (age STREAM,
Tink streaming AEAD, AWS ESDK framing all have this). Design committing chunked/streaming mode for v2 (STREAM-style
nonce-counter chained chunks, per-chunk commitment or chained commit, 4 GiB cap removed), spec-first with KATs;
supersedes the TP-078 interim recipe. Acceptance: v2 streams with commitment; CLI handles >RAM files.

#### TP-128 · P3 · 128 · feat · tessera-sign-mldsa-spec
Deps: TP-119 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TESS ticket (new project). Pre-spec "TesseraSign": ML-DSA-87 detached-signature envelope under a new
variant byte, same polyglot-KAT discipline. CNSA 2.0's binding 2025–2027 milestones are signing-centric and every
pinned library already ships ML-DSA (OpenSSL 3.5+, JDK 24+, RustCrypto, @noble). Completes the suite story: one
Keccak family across ID+hash+seal+sign ("one primitive to audit" — FIPS/CMMC pitch). Acceptance: whitepaper +
Python reference + variant-byte allocation + vectors.

#### TP-129 · P3 · 129 · docs · hqc-contingency-reservation
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. NIST's backup KEM (HQC) is slipping toward 2027 final; Tessera has no written ML-KEM-failure
plan. Reserve and document a suite byte for ML-KEM+HQC (or HQC-only) in the whitepaper's reserved-future table with
"allocated upon FIPS finalization (~2027)" language. One paragraph converts a structural-break scenario from
existential threat to planned migration. Acceptance: reservation in all relevant registries/papers.

#### TP-130 · P3 · 130 · feat · age-plugin-tessera-and-sops
Deps: TP-070, TP-006 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TSEAL ticket (ride the ecosystem). Ship `age-plugin-tessera` exposing pure ML-KEM-1024 committing
recipients through age's plugin protocol (which the existing plugin design already imitates), then a sops
keysource PR. Pitch: "age gives you hybrid-768 without commitment; the plugin gives you CNSA-aligned 1024 WITH
commitment." Acceptance: age encrypt/decrypt round-trip through the plugin; sops integration demo.

#### TP-131 · P3 · 131 · feat · unified-tessera-cli
Deps: TP-070, TP-084, TP-125, TP-006 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TESS ticket (the killer-CLI vehicle — multihash had IPFS, age had sops, WireGuard had the kernel). One
static binary `tessera` (Go or Rust): seal/unseal files age-style with TesseraID-as-AD, id new/decode, hash
sum/verify/convert. Publish to Homebrew/crates/registries (per TP-085), signed per TP-093. Acceptance: brew install
→ seal a file in under a minute.

#### TP-132 · P3 · 132 · feat · postgres-extension-tesseraid
Deps: TP-006 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TID ticket (highest-leverage ID adoption move; Postgres 18's uuidv7() proves DB-native generation is the
lever). Build a `tesseraid` Postgres extension: native type with btree opclass, server-side generators (standard +
HLC), timestamp-extraction function, casts to/from both text forms. Acceptance: CREATE EXTENSION; PK usage demo;
index-behavior benchmark vs uuid (feeds TP-133).

#### TP-133 · P3 · 133 · docs · capability-id-repositioning-and-benchmark
Deps: — · Status: DONE (2026-06-10) — doc repositioning shipped; storage benchmark deferred
Hand-off: TID ticket. Reposition from "post-quantum ID" (weak: Grover largely irrelevant to online guessing) to
"sortable capability ID" — the gap RFC 9562 itself documents (UUIDs disclaimed for security use; v7's 74 bits
guessable given timestamp; TesseraID is the only sortable format at capability-token strength) — plus the HLC
clock-rigor story. Publish the honest storage benchmark: 41B vs 16B at 10^8–10^9 rows on Postgres/InnoDB incl.
secondary-index multiplication, with a decision table for when 2.5x is worth it. Includes a "TesseraID for UUIDv7
users" migration/coexistence note. Acceptance: README/whitepaper repositioned; benchmark published with raw data.

#### TP-134 · P3 · 134 · feat · uuidv8-compat-profile
Deps: TP-133 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TID ticket. Define a documented, lossy down-mapping of TesseraID → UUIDv8 (keep 48-bit ts + top 62 random
bits) so systems store 41 bytes but expose a uuid-typed view to legacy schemas/ORMs/JOINs. Spec section + reference
helpers in Python/Go/Rust + vectors. Acceptance: round-trip-documented profile with KATs.

#### TP-135 · P3 · 135 · feat · typeid-style-prefix-layer
Deps: TP-133 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TID ticket. Adopt TypeID's DX lesson: spec an optional `prefix_` + Crockford text form (prefix excluded
from the wire format — zero wire cost). Buys the most-loved ergonomic feature in the ID space and invites the
TypeID community to treat TesseraID as an upgrade path. Acceptance: spec'd text grammar + parser support in
reference languages + vectors.

#### TP-136 · P3 · 136 · feat · masked-timestamp-variant
Deps: TP-133 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TID ticket. TesseraID fixes UUIDv7's entropy criticism but inherits its timestamp-leak criticism
(cleartext 48-bit creation time = cross-system correlation). Allocate a new variant byte for a masked-timestamp
mode (Brooker-style `unix_ts_ms XOR H(key, ts >> N)`: locally sortable within a 2^N-ms window, leak-free
globally). Leapfrogs the critique before UUIDv7 does. Spec-first; new variant = whitepaper + registry update
(security-relevant). Acceptance: variant spec'd + reference impl + vectors.

#### TP-137 · P3 · 137 · docs · hlc-interop-mappings
Deps: — · Status: DONE (2026-06-10)
Hand-off: TID ticket. The HLC variant has no interop story with systems that actually use HLCs (CockroachDB, Mongo
cluster time, YugabyteDB, Dart crdt, uhlc-rs/Zenoh). Publish mappings (field correspondence, drift-bound
translation, merge semantics) + one CRDT-framework integration example. Owns the niche no portable format
occupies. Acceptance: published mapping doc + working example.

#### TP-138 · P3 · 138 · feat · multicodec-and-sigstore-bridges
Deps: TP-006 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: THASH ticket. Two permissionless integrations: (1) register a multicodec code (one PR to
multiformats/multicodec) + ship a lossless tessera-hash↔multihash/CIDv1 converter — TesseraHash content becomes
IPFS-pinnable, turning the biggest competitor into a transport layer; (2) propose `tesseraHash` as an in-toto
DigestSet algorithm name + ship a cosign-compatible attestation example — instant supply-chain relevance.
Acceptance: registration merged; converters + example in repo.

#### TP-139 · P3 · 139 · feat · hash-streaming-merkle-variant
Deps: TP-067 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: THASH ticket. Close the streaming gap on Tessera's own terms: allocate a future variant for a
SHAKE-256-based tree/chunked mode (Sakura/K12-style or fixed-chunk Merkle over SHAKE-256) so verified
streaming/range verification exists without abandoning single-primitive discipline. Disqualifying gap today for
large artifacts vs BLAKE3/bao and CID DAGs. Acceptance: variant spec + reference impl + vectors.

#### TP-140 · P3 · 140 · feat · evidence-manifest-flagship
Deps: TP-138, TP-131 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TESS ticket (the anchor application — RFC 6920's failure shows formats without a flagship deployment go
nowhere). Build an "evidence manifest" reference product for the legal/regulated-archive niche: TesseraHash
digests + RFC 3161/Roughtime timestamps + a Merkle transparency log; CLI verbs in TP-131's binary. The niche
treats timestamping + log as table stakes and values no-downgrade + canonicality. Acceptance: end-to-end demo:
ingest → manifest → timestamp → log → verify.

#### TP-141 · P3 · 141 · feat · tessera-vectors-standalone
Deps: TP-023 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TESS ticket (make the harness the product — Wycheproof model). Publish "tessera-vectors" as a standalone
versioned artifact (vectors + schema + runner protocol doc) and contribute the negative-vector suite
(reserved-byte rejection, BadKey mismatch, malformed envelopes) to CCTV. Third-party implementers get a self-serve
test kit; doubles as the recruiting tool for TP-142. Acceptance: standalone repo/package published; CCTV PR opened.

#### TP-142 · P3 · 142 · chore · independent-implementer-recruitment
Deps: TP-141, TP-119 · Status: BLOCKED-EXTERNAL (2026-06-10) — needs public repo + willing third party; see docs/strategic-backlog.md
Hand-off: TESS ticket. All interop claims are self-attested (one author, 8 implementations). Recruit one
independent implementer (different author, different repo) for any single Tessera format and feature their
implementation as the interop proof — the age/rage dynamic. Acceptance: one external implementation passing the
vector suite, featured in README.

#### TP-143 · P3 · 143 · sec · third-party-audit
Deps: TP-031, TP-050, TP-114, TP-115 · Status: BLOCKED-EXTERNAL (2026-06-10) — needs funding + firm; see docs/strategic-backlog.md
Hand-off: TESS ticket. No third-party audit exists (internal security-audit-v1.2.md only). Commission a scoped
audit of the Python+C TesseraSeal references (~$50k anchor; noble/libsodium playbook: OpenSats/Sovereign Tech
Fund-style grants or single corporate sponsor), publish verbatim. One audit converts self-asserted invariants into
citable assurance. Honesty debt (TP-031/050) must be burned down first or the auditor finds it for you.
Acceptance: published report; findings triaged into this plan's format.

#### TP-144 · P3 · 144 · sec · machine-checked-composition-proof
Deps: — · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TSEAL ticket. Commission or DIY a machine-checked protocol argument for the TesseraSeal composition
(Tamarin or hax/F* model of KEM + HKDF + AEAD + UtC commit): cheaper than a code audit, 2026 differentiation
(even liboqs has only primitive-level proofs). State precisely what is and isn't proven. Acceptance: model +
proof artifacts in repo; whitepaper security section cites them.

#### TP-145 · P3 · 145 · docs · hpke-pq-comparison-and-decision-records
Deps: TP-120 · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. Three decision-record docs: (1) a one-page "TesseraSeal vs HPKE-PQ" leading with key
commitment (HPKE's documented gap), oracle discipline, fixed polyglot wire — positioned before HPKE-PQ's RFC
lands; (2) a whitepaper subsection justifying the ML-KEM-1024 combiner divergence from X-Wing/768-ecosystem (CNSA
parameter alignment; frozen "pqcrypt v1 hybrid combiner" label); (3) record the AEGIS permanent-deferral decision
(draft-18, no RFC; UtC is AES-GCM-specific) so it stops resurfacing. Acceptance: reviewers' first three questions
pre-answered in writing.

#### TP-146 · P3 · 146 · chore · mlkemtest-cross-generation
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. Conformance vectors are generated solely via kyber-py's DRBG path. Use Go 1.26's official
`crypto/mlkem/mlkemtest` derandomized Encapsulate1024 as a second independent KAT source to cross-check vector
generation — hardens against single-source generator bugs. Acceptance: cross-generation script + CI dispatch step
comparing both sources byte-identically.

#### TP-147 · P3 · 147 · docs · fips-deployment-note
Deps: — · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket. Add the FIPS-mode deployment paragraph: the C port inherits OpenSSL's FIPS 140-3 module
once 3.5.4 validation completes (expected 2026-2027); kyber-py is unvalidated (spec-readability/KAT role);
per-language validation posture table. Costs a paragraph, unlocks federal/regulated procurement conversations
ahead of the 2027 CNSA acquisition gate. Acceptance: note in seal docs + whitepaper.

#### TP-148 · P3 · 148 · docs · ietf-independent-submissions
Deps: TP-119, TP-133 · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TESS ticket. Pursue lightweight standards artifacts: an Independent-Submission Internet-Draft for the
TesseraID wire format + variant registry (the ULID lesson: informal specs decay and get displaced by RFCs), and a
short I-D for TesseraHash framed as a strict "verification profile" (one algorithm, one length, one encoding,
mandatory reject — WireGuard's no-agility precedent). C2SP (TP-119) first; IETF I-Ds second. Acceptance: drafts
submitted to the Independent Stream.

#### TP-149 · P3 · 149 · feat · rust-aes-intrinsics
Deps: — · Status: DEFERRED-TO-BACKLOG (2026-06-10) — see docs/strategic-backlog.md
Hand-off: TSEAL ticket (existing backlog TSEAL-00027/00034). AES-NI/ARMv8 intrinsics for the Rust port's 1 MiB
throughput gap: needs aes-gcm 0.11 or nightly target_feature cfg (aes-gcm 0.10's `aes` feature alone does NOT
enable ARMv8 intrinsics on stable). Behavior-identical optimization; KATs must stay green. Acceptance: benchmark
delta published; no wire change.

#### TP-150 · P3 · 150 · feat · ci-timing-histogram-automation
Deps: TP-050, TP-013 · Status: DONE (2026-06-10)
Hand-off: TSEAL ticket (existing backlog TSEAL-00035 — and the item that makes the TP-050 phantom TRUE instead of
deleted). Automate the timing-histogram regression: N-pair good/bad decrypt timing comparison with a median-delta
assertion, run on a dispatch/scheduled cadence (noisy shared runners → generous threshold + trend tracking, not
hard gate initially). Once shipped, restore the (now-truthful) claim to §9.3 and the side-channel disclaimer.
Acceptance: automated run produces histogram artifact + assertion; docs updated to match shipped reality.

---

## Dependency-critical path (summary)

1. **TP-001 → TP-005** (working tree + ledger) — minutes, do first.
2. **TP-002/003/004 + TP-071** (broken ports + silent CLI downgrade) — the regression cluster.
3. **TP-007..TP-012 → TP-013** (CI repair → re-gate) — unblocks everything that claims "verified".
4. **TP-020..TP-023** (harness enforcement + vector freeze) — makes all later green claims trustworthy.
5. **TP-025..TP-046** (correctness + KAT coverage) — burns down the spec-divergence debt.
6. **TP-047..TP-068** (whitepaper truthfulness) — required before TP-119/TP-143 (external scrutiny).
7. **TP-006 → TP-085 → TP-086..TP-094** (name → posture → packaging) — the adoption gate.
8. **TP-114..TP-118** (governance) — parallel from day 1; cheap credibility.
9. **Wave 9** — strategic differentiation, sequenced after the foundation holds.
