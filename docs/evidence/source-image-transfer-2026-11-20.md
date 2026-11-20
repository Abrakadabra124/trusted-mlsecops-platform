# Exact source image transfer between hosted jobs

Week 13, T21. The prerequisite is verified on source
[`8b9b24d1b64f04e47d6148e17962a6fc31702c23`](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/8b9b24d1b64f04e47d6148e17962a6fc31702c23),
[run 44775977421](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44775977421),
attempt 1, branch `qualify/source-image-transfer`, 2026-11-20. All three jobs
completed successfully. This transfers the public source-only worker image;
it does not transfer a frozen candidate or accept M18/R1.

## Required property and implementation

The same candidate must use the same image in later independent jobs. Rebuilding
the Dockerfile is not evidence that the new configuration digest matches the
producer. The [core](../../scripts/ci_source_image.py) builds once from an immutable
Git archive containing only the committed allowlist and exact reviewed recipe.
Ignored runtime, models, data and keys are excluded. A changed recipe or a
source/context fingerprint mismatch refuses before publication.

The [driver](../../scripts/ci_source_image_native.py) checks clean source, actual
repository/run/attempt/workflow/job and public/nonfork identity through GitHub API.
The [workflow](../../.github/workflows/source-image-transfer.yml) transfers a
single compressed archive. Its receipt comes independently from producer job
outputs, not from the downloaded file. Receiver checks compressed and raw sizes
and hashes, archive entries, config ID, revision and source fingerprint before
running the ordinary worker CLI with no network, non-root user, read-only root,
dropped capabilities and bounded CPU/memory/PIDs.

This profile explicitly requires Linux Docker classic `overlay2`; containerd
manifest/index IDs are not interchangeable with the platform's config IDs.
Both native endpoints passed the backend guard. It does not claim compatibility
with unsupported image stores or bit-for-bit reproducibility of a rebuild.

## Actual native result

| Check | Observed result |
| --- | --- |
| Producer | success, 111 seconds |
| Receiver, fresh hosted runner | success, 43 seconds |
| Remote artifact cleanup, third hosted runner | success, 13 seconds |
| First job start to last job finish | 173 seconds, including scheduling gaps |
| Linux preflight | 130 tests, 15.241 seconds, no failures or skips |
| Per-module native coverage | Both statement and branch thresholds >=95% passed for core, driver and bootstrap |
| Compressed image | 135,930,716 bytes, 129.63 MiB, below fixed 384 MiB cap |
| Raw Docker archive | 427,607,040 bytes, 407.80 MiB, below fixed 2 GiB cap |
| Actions ZIP, including transport overhead | 135,930,854 bytes |
| Artifact ID | `14650132011` |
| Artifact cleanup | 1 deleted; independent authenticated listing returned 0 |
| Independent exact-ID readback | GET returned HTTP 404; the run artifact list remained accessible and empty |

Public image receipt, not an ML model/candidate identity:

```text
image_id: sha256:f79ad84b7946d71a3946ae0554de4a71384e362a151253af7438217a800d126b
source_fingerprint: d22665930ec69eb39765a871dca8eb00eeab2ee691a8acd7278e8485c1b8c874
archive_sha256: f9727d64f677e39ef21a877ef4fc45353826215e791a9a0230e5f123c9e61ad8
tar_sha256: fa2cc74c742b5d16a13cf3a6b1057ac77528de2e8d2b0803690def15a9d66be3
```

Six closed projections reported pass: image preparation, producer cleanup
(`files_removed=4`), artifact precheck, image receipt, idempotent receiver cleanup
(`files_removed=0` after receiver's internal cleanup), and remote deletion
(`artifacts_deleted=1`). Every projection retained `release_ready=false`.
Receiver's successful return requires the probe absence readback and owned local
cleanup. The final separate cleanup job deletes the remote artifact by verified ID.

No model, private key, dataset, candidate packet, raw primary evidence or billing
details were uploaded. This run needed no repository secret. Only the public
source-only archive was stored temporarily. The account's existing hard zero
spend limit was preserved; the post-run billing UI still displayed zero billable
Actions usage. That is a UI observation, not an invoice or future quota reservation.

## Component tests and review

The parent independently ran the integrated seven-module preflight on Windows:
130 tests in 41.610 seconds, 126 passed and 4 POSIX-only skips. Those four tests
then executed successfully in the native Linux preflight. Local measured coverage:

| Module | Statements | Branches |
| --- | --- | --- |
| `mlsecops.bootstrap` | 73/73 | 26/26 |
| `scripts.ci_source_image` | 244/244 | 30/30 |
| `scripts.ci_source_image_native` | 174/174 | 30/30 |

There were no coverage exclusions. Native execution enforced each 95% threshold
separately; exact native percentages were not exported. Adjacent API transport
tests passed 18/18 in the implementation worktree. Parent whole-tree Ruff checks
and documentation validation passed. YAML uniqueness, fixed actions/permissions,
nine shell blocks and two embedded Python blocks were checked; only the new
workflow matches the qualification push branch.

An internal reviewer independently examined the core and driver, reproduced
concrete ownership failures, and approved the corrected paths. Corrections had
failing regression cases before the fixes:

- A pre-existing CID file could select an unrelated container for deletion.
  Receiver now checks its externally owned workspace and exact initial entries
  before any Docker invocation.
- Allowed filenames alone did not prove ownership. Each job now has an exclusive
  external `RUNNER_TEMP` owner record; cleanup compares the expected owner and
  preserves its marker until other files are removed.
- Docker `--rm` conflicted with explicit helper cleanup. The helper now owns
  removal, followed by final-state inspection on success and failure.
- Empty/invalid CID after interrupted creation used to prevent absence readback.
  The exact owner-bound name remains the readback fallback; invalid CID still
  refuses. This does not authorize deleting an arbitrary container by name.
- Git's Windows line-ending conversion changed archive bytes. Archive creation
  pins conversion settings; the source fingerprint requirement was not weakened.

These are controlled defects found before the native run, not claimed production
incidents. Internal code review is not the independent human M22 challenge review.

## Remaining R1 work

[Runbook and recovery playbook](../operations/source-image-transfer.md),
[original trust bootstrap](../operations/bootstrap-trust.md), and
[cross-job implementation plan](../superpowers/plans/2026-11-20-candidate-cross-job.md)
describe the implementation and next steps. Original trust provisioning passed
real signing/identity and POSIX component tests; delivery of a real original
trust secret between campaign jobs is still pending.

Private candidate/validation/upstream packets and consumer primary evidence still
need a bounded private store, scoped credentials and a protected producer authority
record. Consumer evidence upload must not silently grant rewrite authority over
producer expectations. All gates must use one original candidate, preserve its
time windows, and run M18 last. Image findings, full runtime coverage and independent
human M22 challenges (0/2) remain open. No final R1 release was created.
