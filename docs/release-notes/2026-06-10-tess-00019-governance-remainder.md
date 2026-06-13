# TESS-00019 — Governance remainder: OpenSSF Scorecard workflow, C2SP submission plan, strategic backlog, plan status sweep

- **Date:** 2026-06-10
- **Type:** chore/docs (umbrella)
- **Remediation items:** TP-118 (partial — workflow shipped, badge gated), TP-119 (prep — plan
  recorded, submission gated), strategic-backlog memos for TP-121..128/130..132/134..136/138..144/
  148..149, and the final status sweep of
  [docs/remediation-plan-2026-06-10.md](../remediation-plan-2026-06-10.md).

## Summary

Final remediation wave: closes out the 2026-06-10 plan's bookkeeping. Adds a weekly OpenSSF
Scorecard workflow (SHA-pinned, least-privilege, `publish_results: false` until the repo is
public), records the C2SP submission plan for the TesseraSeal envelope v1 spec + shared
variant-byte registry, captures all 23 deferred strategic items in a per-item backlog with
readiness/first-step/blocker, and updates every one of the plan's 150 `Status:` fields to ground
truth (116 DONE, 4 DECISION-RECORDED, 5 PARTIAL, 22 DEFERRED-TO-BACKLOG, 3 BLOCKED-EXTERNAL).

## Code changes

- **NEW** [.github/workflows/scorecard.yml](../../.github/workflows/scorecard.yml) — OpenSSF
  Scorecard analysis. Triggers: weekly cron (Mondays 05:30 UTC) + `workflow_dispatch`. Top-level
  `permissions: contents: read`; job-scoped `security-events: write` (SARIF upload) and
  `id-token: write` (Scorecard's OIDC publish path) per the Scorecard docs. All four actions pinned
  by full commit SHA (`ossf/scorecard-action` v2.4.3, `actions/checkout` v4.3.1,
  `actions/upload-artifact` v4.6.2, `github/codeql-action/upload-sarif` v3.36.2).
  `publish_results: false` and the code-scanning upload step is `continue-on-error` — both flip
  when the repo goes public (TP-006/TP-085). SARIF kept 30 days as a run artifact either way.
- **NEW** [docs/decisions/2026-06-10-c2sp-submission-plan.md](../decisions/2026-06-10-c2sp-submission-plan.md)
  — TP-119 prep: what C2SP requires, proposed scope (TesseraSeal envelope v1 + variant-byte
  registry appendix), met/unmet prerequisite checklist, and the exact `tessera-seal/latex/` →
  Markdown extraction outline. Submission gated on TP-006/TP-085/TP-115.
- **NEW** [docs/strategic-backlog.md](../strategic-backlog.md) — one section per deferred Wave 9
  item (TP-121..128, 130..132, 134..136, 138..144, 148, 149): current readiness, first concrete
  step, blocking dependency. Notable: hybrid C port TP-121 is now UNBLOCKED (OpenSSL 3.5+ exposes
  X25519 EVP; playbook in `.claude/skills/tessera-seal-impl/SKILL.md`).
- **UPDATED** [docs/remediation-plan-2026-06-10.md](../remediation-plan-2026-06-10.md) — `Status:`
  field lines only, all 150 items, dated tokens.

## Wire/API changes

None. No source, vector, spec, or packaging surface touched — workflow + docs only. Conformance
vectors untouched (freeze check trivially passes).

## Migration guidance

- **Operators:** `scorecard.yml` is the second workflow with an automatic trigger (alongside
  `conformance.yml`'s PR/push gate) — it is scheduled-only and never blocks PRs. Root CLAUDE.md's
  "only workflow that runs automatically" sentence in the CI quick reference needs the one-word
  reconciliation ("plus the weekly Scorecard schedule") — flagged to the index/CLAUDE.md owner.
- **When the repo goes public:** flip `publish_results: true` in scorecard.yml, remove
  `continue-on-error` from the code-scanning upload, add the Scorecard badge to README.md, and
  start working the top deductions; then execute the C2SP plan's §5 next steps.
- The umbrella `docs/release-notes/CHANGELOG.md` index line for this entry is orchestrator-owned.

## Test plan

Run (all verified green on this change):

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/scorecard.yml'))"
actionlint .github/workflows/scorecard.yml
bash tools/scripts/check-md-links.sh docs
grep -c 'Status: DONE (2026-06-10)' docs/remediation-plan-2026-06-10.md          # 116
grep -c 'Status: DEFERRED-TO-BACKLOG (2026-06-10)' docs/remediation-plan-2026-06-10.md  # 22
grep -cE 'Status: (NOT-STARTED|DECISION-REQUIRED)' docs/remediation-plan-2026-06-10.md  # 0
```

First live verification: manually dispatch `scorecard` from the Actions tab and confirm the
`scorecard-sarif` artifact appears.

## Security considerations

The new workflow grants no write access to repo contents: elevated scopes (`security-events`,
`id-token`) are job-scoped exactly per Scorecard's documentation, all actions are SHA-pinned
(repo convention since TESS-00006/TP-015), and `persist-credentials: false` is set on checkout.
No results leave the repo while `publish_results: false`.

## Rollback

Delete the three new files and `git revert` the plan's status-line commit. No state, schema, or
artifact depends on them; removing scorecard.yml simply stops the weekly run.

## Linked tickets

- TESS-00019 (this entry) — remediation plan TP-118 (partial), TP-119 (prep), strategic backlog,
  status sweep.
- Builds on: TESS-00006 (CI restoration / SHA pinning), TESS-00008 (governance baseline: SECURITY.md,
  decision memos), TESS-00010/TSEAL-00045/THASH-00007/TID-00021 (whitepaper truthfulness — the
  C2SP prerequisite), TESS-00014 (packaging metadata).
