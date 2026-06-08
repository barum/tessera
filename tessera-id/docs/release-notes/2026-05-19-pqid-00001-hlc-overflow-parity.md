# PQID-00001 — Fix Go and Rust HLC counter-overflow parity

## Summary

Go and Rust HLC generators silently wrapped the 16-bit counter at
`MAX_COUNTER` instead of bumping logical time, in the same-ms peer-merge
branches. Aligned with the Python and C reference: stage the counter in a
wider integer, then do an unconditional post-check.

## Code changes

- `pqid/go/pqid.go` — replace per-branch `cMsg + 1` (which silently wraps
  uint16) and the special-case overflow guard with a `uint32 cWide`
  staging variable and an unconditional `if cWide > maxCounter` post-check.
  Also fixes a previously-latent edge: the no-observe path used
  `if lOld > pt` (missing the equality case); changed to `if lOld >= pt`
  to match Python.
- `pqid/rust/src/lib.rs` — same change in Rust: drop the three
  `wrapping_add(1)` calls in favour of `u32::from(...) + 1` staging,
  remove the special-case guard, do the unconditional `if c_wide > MAX`
  check. Also fixes the analogous `l_old > pt` → `l_old >= pt` no-observe
  equality case.

## Schema / migrations / seeds / env vars / infra / flags

None — algorithmic fix. The fix only changes behavior at counter-overflow
edge cases; existing well-behaved generators are unaffected.

## Operator runbook

Redeploy-only. Existing HLC streams that never hit the overflow edge are
bit-identical to before.

## Test plan

```
bash pqid/conformance/run.sh
```

Expect 8/8 languages green at 75/75. Specifically, every vector in
`pqid/conformance/vectors/hlc_overflow.json` must PASS on Go and Rust
(they failed `observe_l_msg_eq_l_new_c_msg_max` before this fix).

Plus per-language test suites:

  - `cd pqid/go && go test ./...`
  - `cd pqid/rust && cargo test --release`

## Rollback

`git revert <hash>`. Note that reverting only this commit while keeping
PQID-00003 will reintroduce a known regression detected by the harness.

## Linked PRs / tickets

PQID-00001. Depends on PQID-00003.
