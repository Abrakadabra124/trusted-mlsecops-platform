# Private CI channel implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development or
> superpowers:executing-plans task-by-task. Parent owns integration and native CI.

**Goal:** Verify a bounded private encrypted handoff across actual hosted jobs.

**Architecture:** Exact public source commit mirrored to a private execution
repository. Actual execution identity, repository-scoped token, temporary AES
secret, independent producer output pins, owned artifact deletion/readback.

**Tech Stack:** Existing Python 3.12.15, cryptography 50.0.2, GitHub Actions,
fixed action commits, existing qualification and coverage tools.

**Spec:** [Private CI channel prerequisite](../specs/2026-11-20-private-ci-channel-design.md).

## Global constraints

No local infrastructure, external models, paid resources, private public uploads,
source identity impersonation, changed proposal windows or reduced acceptance.
Preserve root worktree AGENTS.md/GOAL.md user changes. R1 remains open.

## Review focus

- Public visibility or repository rename/recreation must refuse before upload.
- Execution identity must not masquerade as the original public repository.
- Modified envelope with a new digest must still fail authenticated decryption.
- Cleanup must never delete another run's artifact or treat API failure as absence.
- Cancellation/failure must preserve bounded retention and an actionable runbook.

### Task 1: Explicit execution identity

Files: `mlsecops/ci_transfer.py`, `scripts/ci_transfer_qualification.py`,
`docs/operations/ci-transfer.md`. Existing candidate adapters remain unchanged
until the actual candidate cross-job integration, outside this canary slice.

- [x] Pin a failing test accepting only the two exact execution repository names
  and rejecting cross-repository context substitution, foreign names and case drift.
- [x] Implement one explicit allowlist while preserving true run owner and the
  existing closed context schema. Keep the public source identity distinct in docs.
- [x] Run the 37 core tests and individual module coverage: 102/102 statements,
  42/42 branches. The five candidate adapters retain the original restriction.
- [x] Obtain scoped review: APPROVE, no P1/P2; core committed as `f8582c1`.

### Task 2: Private canary transport and hosted proof

Files: `scripts/ci_private_channel.py`, its qualification tests,
`.github/workflows/private-channel.yml`, operations/evidence documentation.

- [x] Write failure-first tests for repo/source/run guard, key and context errors,
  bounded local input and owned artifact deletion, including API error/foreign run.
- [x] Implement fixed canary producer/receiver with ordinary AES APIs and closed
  outcome projection; fixed artifact name and size; no model or release claims.
- [x] Prepare pinned producer/receiver/cleanup jobs, private-only and dispatch-only,
  short timeouts, no cache, exact artifact ID, one-day fallback retention.
- [x] Run tests: 55 core/channel, 60 adjacent bridge/validation/frozen, no skips.
  Core 102/102 statements and 42/42 branches; driver 177/178 and 23/24.
  Ruff/docs/static checks passed; scoped reviewer independently repeated 55 tests,
  confirmed coverage and approved. Publish public source before exact mirroring.
- [x] Verify private metadata and hard zero-spend prerequisite, provision one
  temporary AES secret, execute once, inspect every job and deletion readback.
- [x] Delete temporary secret, verify absence, publish only closed observations
  and runbook. Record native refusal honestly and fix before a justified retry.

Native outcome: [932c2a4 /44681708741](../../evidence/private-ci-channel-2026-11-20.md),
all three jobs success, 7 crypto refusals, 1 artifact deleted, independent readback
0 artifacts, temporary secret absent. Full candidate transport remains below.

### Remaining full R1 dependencies

Use the verified private channel for actual frozen candidate and original primary
materials, provision exact consumer image/source, parallel gates on one candidate,
retain primary evidence, finish image remediation and independent M22 review,
run M18 last and reproduce from clean checkout. None is waived by this plan.
