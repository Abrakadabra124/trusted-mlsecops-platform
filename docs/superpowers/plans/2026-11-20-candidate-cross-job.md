# Original candidate cross-job implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development or
> superpowers:executing-plans. Independent tasks have disjoint write scopes.

**Goal:** Deliver one original frozen candidate to independent hosted consumers
with the exact image, external original trust identity and private primary evidence.

**Architecture:** Public standard hosted runners satisfy the unchanged Kubernetes
resource profile. Source-only image transfer precedes private inputs. A separate
private repository holds encrypted assets and authenticated producer control data;
publisher and reader credentials are repository-scoped and separate.

**Tech Stack:** Existing Python/cryptography/Docker, GitHub Actions and REST APIs.

**Spec:** [Candidate cross-job design](../specs/2026-11-20-candidate-cross-job-design.md).

## Global constraints

Preserve all M01-M23 criteria, timing windows and source/image pins. No local
infrastructure, external models, paid usage, broad personal CI token, private
public artifacts, unrelated infrastructure changes or foundation repo edits.
Preserve root AGENTS.md/GOAL.md user changes. Minimum quota reserve 25%.

## Review focus

- Private runner capacity must not be confused with the successful AES canary.
- Never transfer a generated new root instead of the original frozen trust key.
- Reject foreign image/config/source, archive tampering and oversized downloads.
- Keep producer packet owner distinct from the consumer's cleanup resources.
- A failed or cancelled job must not leave unbounded private storage or destroy
  the only retained primary evidence needed for final independent replay.

### Task 1: Original trust provisioning

Files: `mlsecops/bootstrap.py`, `scripts/bootstrap_trust_qualification.py`,
`docs/operations/bootstrap-trust.md`.

- [x] Write failing tests for invalid/mismatched key, dirty/unowned existing state,
  key replacement on retry and interruption before final registry publication.
- [x] Add `initialize(root, state, *, trust_key_path=None)` using the ordinary
  bounded private-key reader. Existing callers remain unchanged. A fresh state
  uses supplied Ed25519 trust bytes from the beginning; existing state may only
  accept the same identity and must never rotate or overwrite it.
- [x] Verify actual signatures/public registry, unchanged adjacent roles, default
  bootstrap idempotency, explicit failure and per-module 95% coverage. Review.
  Windows component/regression checks passed (78 methods, 4 POSIX-only skips);
  parent source review completed. Native POSIX tests passed in run 44775977421,
  within 130 Linux tests without skips. Actual campaign secret delivery is Task 4.

### Task 2: Exact source-only image handoff

Files: `scripts/ci_source_image.py`, its qualification tests,
`.github/workflows/source-image-transfer.yml`, operations/evidence documentation.

- [x] Pin negative tests for foreign source/image, recipe/context drift, archive
  size/hash, unexpected entries and failed load/cleanup ownership.
- [x] Implement bounded export/import of only the freshly built public source-only
  worker. Fix caps before native measurements; any over-cap result refuses and
  reports actual sizes without automatically enlarging storage limits.
- [x] Verify cross-job image ID/source labels and ordinary worker compatibility
  on fresh public hosted runners. Retain no model/key/private input in this path.
- [x] Review, execute, verify exact artifact cleanup and publish safe evidence.
  Source 8b9b24d / run 44775977421: all three jobs success, 173 seconds,
  compressed image 129.63 MiB, exact-ID 404 plus accessible empty run listing.
  [Evidence](../../evidence/source-image-transfer-2026-11-20.md).

### Task 3: Private asset adapter and access

Files: a bounded private release-asset adapter and qualification tests, private
store runbook, next workflow integration.

- [ ] Fix the exact repository/ID, run namespace, closed authority record, asset
  count/size/lifetime caps, authenticated publisher/reader API contracts and
  cancellation-safe cleanup. Write failure-first tests and implement the adapter.
- [ ] Review code and a concrete least-privilege credential setup before requesting
  any user credential action. Never put personal tokens in chat/logs/arguments.
- [ ] Validate live transport using the new scoped credentials only after they
  exist; do not reinterpret existing private canary as proof of this adapter.

The closed producer signature, bounded release adapter, two access roles and controlled
Linux readback passed 272 tests at e48a7db. The operator verified both empty
GitHub environments allow only the exact campaign branch. Durable interruption
recovery, issued credentials and actual private transport are still pending.
[Qualification evidence](../../evidence/candidate-cross-job-2026-11-20.md).

### Task 4: Actual frozen candidate and consumers

- [ ] Separate existing producer freeze/seal from consumers, without changing
  ordinary acceptance readers. Preserve original producer owner and enforce
  independent consumer cleanup ownership.
- [ ] Bind exact image and original trust, candidate/validation/upstream packets.
  Run full M11/M12 and M13/M14/M15 using the same candidate, then retain/replay
  original primary evidence privately after owned resource cleanup.
- [ ] Integrate all remaining original gates, image remediation and independent
  M22 results, run M18 last, reproduce from clean checkout, publish final R1 only
  if the full original acceptance is proven.
