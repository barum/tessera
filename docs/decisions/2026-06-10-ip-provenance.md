# Decision record: IP provenance and copyright ownership (TP-115)

**Date:** 2026-06-10
**Status:** OPEN — maintainer action required before public publication
**Owner:** Bahram Samani

## Context

The 2026-06-10 audit found that no copyright owner was named anywhere in the repository, while the
specifications explicitly aim to be long-lived normative documents ("intended to outlive any individual
deployment"). Provenance facts on file:

- 49 of 50 commits are authored under an employer email identity (`bahrams@jfrog.com`); 1 commit under a
  personal address via the GitHub web UI.
- Security-relevant commits carry AI co-authorship trailers (Claude), consistent with the development process.
- `LICENSE` is Apache-2.0 at the repo root, but until 2026-06-10 no `NOTICE` file, no per-manifest license
  fields, and no copyright line existed.

## What was done on 2026-06-10

- `NOTICE` created naming **Bahram Samani** as the draft copyright holder, with an explicit pre-publication
  caveat that employer confirmation is pending.
- Repo-local git identity switched to the personal address going forward, with a `.mailmap` unifying the two
  historical identities (see TP-110).

## Open questions the maintainer must close before publication

1. **Employer claim.** Was any of this work performed within the scope of employment or using employer
   resources such that the employer (JFrog) could assert ownership? Obtain either a written carve-out /
   acknowledgment, or a personal-project confirmation consistent with the employment agreement, and record
   the outcome here.
2. **Copyright line.** Confirm the final form: personal name, a legal entity, or joint. Update `NOTICE`,
   README copyright line, and per-manifest license metadata (TP-094) accordingly.
3. **AI co-authorship.** Decide whether to keep the Co-Authored-By trailers as-is (they are factual) and note
   that under current USCO guidance the human author/maintainer claims copyright in the curated, directed
   work product.

## Decision

Pending maintainer action. This file is the single place to record the outcome; do not publish artifacts
(registries, signed releases) until items 1-2 are closed.
