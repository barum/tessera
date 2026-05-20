# PQID-00011 + PQID-00015 — Comment cleanups (Python counter + Go Crockford)

## Summary

Two cosmetic, comment-only changes bundled in a single release entry.

- **PQID-00011** — Python `StandardGenerator.new` had a comment that
  claimed the random counter step makes the counter "opaque to outside
  observers." That's overclaiming: a 4-bit step in {1..16} is trivially
  observable. Rewritten to state what the step actually does (defense
  in depth + smoother overflow distribution) and to point to the
  randomized initial offset on each new ms + the 256-bit random tail as
  the real sources of unlinkability.
- **PQID-00015** — Go `EncodeCrockford` had a paragraph-long apologetic
  comment to the author. Replaced with a single concise line stating
  the bit budget (328 → 330 with 2 pad bits, MSB-first).

## Code changes

- `pqid/python/pqid.py` — rewrite the two block comments around
  `StandardGenerator.new`'s same-ms and new-ms branches.
- `pqid/go/pqid.go` — replace the 6-line "we laid bits MSB-first... EXCEPT..."
  block with a 3-line factual comment.

No algorithmic change. Python tests and conformance harness pass.

## Schema / migrations / seeds / env vars / infra / flags

None.

## Test plan

- `python3 pqid/python/test_pqid.py` — 11/11.
- `bash pqid/conformance/run.sh` — 8/8 languages × 75 vectors green.

## Rollback

`git revert <hash>`.

## Linked PRs / tickets

PQID-00011, PQID-00015.
