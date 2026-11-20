# Private original-candidate serving driver

T21 implementation of the parent-approved wiring contract. Scope: the original
producer, three private M13 transport envelopes, one new owned consumer SQL,
ordinary M13/M14/M15 gates and two Lifecycle transitions, verified cleanup,
private primary retention, context deletion and independent historical replay.
This component is not M18 acceptance or a new proposal authority.

Native validation on exact `422accf7` is now recorded in
[run 44662206137 evidence](../evidence/serving-consumer-native-2026-11-20.md):
M13 514, M14 153, M15 188, cleanup 4/4, retention and independent replay after
consumer context deletion. The implementation/qualification notes below describe
the original increment; this same-job result does not establish cross-job delivery
or full same-candidate M18/R1 acceptance.

## Local implementation plan

1. Write orchestration negatives first: authority/pin forwarding, foreign inputs,
   actual freshness, owned SQL, transition order, independent failure cleanup,
   retained primary/context lifetime, output and environment privacy.
2. Reuse existing readers and ownership helpers without changing them. Snapshot
   and restore gate environment; keep GITHUB_OUTPUT and fd 1/2 private. Preserve
   exact original report pins, source identity and stopped producer SQL pin.
3. Measure statements and branches separately for the new driver; run Ruff,
   format and documentation checks, then commit only these three new files.

## Hosted caller interface and prerequisites

The parent workflow owns runner provisioning and scheduling. The following are
hosted commands, not instructions to launch local infrastructure:

```sh
python -B -m scripts.ci_serving_native
python -B -m scripts.ci_serving_native cleanup
```

The Python boundary is `execute(root, cleanup=False)`. It returns the closed public
projection; the CLI emits that projection and returns 0 only on component success.
The lower-level `run(root, producer, progress)` assumes the caller has installed
the same private-output and environment boundaries; ordinary callers use execute.

Required: an exclusively owned Linux GitHub-hosted runner, `GITHUB_ACTIONS=true`,
`RUNNER_ENVIRONMENT=github-hosted`, repository/run ID/attempt/job environment,
clean exact checkout, and the existing `trusted-mlsecops:dev` image resolving to
the pinned source image ID. There is no image rebuild, candidate replacement,
parallel cluster use or cross-job transport here.

`root/.runtime` must contain the original producer workspace, working owned SQL,
the exact completed M02/M03/M07 reports and their original primary files, original
trust private key `keys/trust.pem`, and producer cluster recovery witness. The
driver calls existing `ci_producer_cluster.cleanup` before opening the proposal
window. An existing proposal report or a nonempty `release-proposals` refuses a
second proposal. The original trust key is copied only by the approved candidate
materializer; no signing trust root is regenerated.

## Execution and private files

1. Verify hosted/source/owner guards and producer cluster cleanup. Run the ordinary
   proposal qualification once, freeze its original files, and use the frozen
   reader's exact candidate/source/image identity as authority.
2. Seal candidate, upstream receipts and validation with existing helpers, all
   phase M13. Read only the signed manifest's validation descriptor through the
   producer publisher client. Keep the one ephemeral AES (Advanced Encryption
   Standard) key in process memory; transport context and ciphertext/manifest pins
   remain separate trusted caller arguments, never artifact-derived authority.
3. Stop producer SQL and record its stopped-state pin privately. Materialize the
   candidate and attach upstream reports/CAS (content-addressed storage). Keep
   both contexts open until cleanup and primary retention finish.
4. Explicitly call `storage_pki.initialize(state)` for new consumer SQL TLS
   (Transport Layer Security) credentials. This is separate from the original
   release trust root. Begin Lifecycle, bootstrap SQL at 15440, verify distinct
   workspace/container and exact storage pin, then import candidate and validation
   once through their approved owned-target importers. No imports run after M13.
5. Create the existing serving retention receipt, start M13, and run ordinary
   `acceptance.report(gate, "local-cpu", root, state=state)` for M13/M14/M15.
   Require the matching gate, status pass and integer exit code 0. Preserve exact
   JSON report/admission pins. Between gates use only Lifecycle M13 and M14
   transitions; consumer SQL stays live with the same pin.
6. Verify all four Lifecycle cleanup results while contexts still exist, check
   the unchanged producer stopped pin, and call `ci_serving_retention.retain`.
   After both contexts exit and the consumer path is gone, independently replay
   the exported archive with the original external arguments. Recheck source and
   producer stopped pin. Do not use the older M23-dependent aggregate join.

Private durable driver files live under `.runtime/ci-serving-native`: failed or
successful original M13/M14/M15 reports, `producer-offline.json`,
`retention-private.json` with independent replay arguments/index pin, and the
bounded `retained` archive. Lifecycle witnesses remain separately under
`.runtime/ci-serving-recovery`. Keys and envelopes are not serialized by this
driver. The existing candidate exporter may retain its private plaintext archive;
all transfer artifacts and metadata remain private.

Dependency output, Python stderr/stdout and inherited child fd 1/2 use existing
`ci_consumer_native.private_output`, with actions `serving-run`/`serving-cleanup`.
`GITHUB_OUTPUT` points at
`.runtime/evidence/ci-serving-native-github-output.private`. No workflow artifacts
or public job outputs carry these files. The complete process environment is
snapshotted and restored, including newly introduced gate pins. Each gate receives
the exact original proposal/demo pins; M14/M15 also receive raw keys/trust file
hashes, not freshly signed registry identities.

Public output has only `status`, fixed `stage`, fixed M13/M14/M15 `gate_counts`,
and `cleanup_counts={required:4, verified:0..4}`. Counts alone do not establish
native acceptance. No source/image/container IDs, pins, receipts, envelopes,
exception text or logs are emitted. A private-output close/restore error still
returns fail, even if gate and resource operations completed.

## Failure and recovery

All original transport, proposal, source approval and policy deadlines remain.
After bootstrap and before every gate the driver reuses current-time frozen
checks and transport-context windows, then calls serving retention preflight
with its unchanged 600-second minimum immediately before the gate. The trio may
not fit the original 1800-second proposal window; that is refusal, not renewal.
Historical replay grants no operational window or release authority.

A gate or inner operation error attempts cleanup before contexts exit. An outer
handler retries durable ownership cleanup on entry/exit errors and after consumer
files are gone. The original exception/stage survives cleanup failure. Before
Lifecycle.begin, missing witnesses remain unverified; no resources are adopted.
Producer SQL is stopped on an earlier failure, or its previously captured stopped
pin is checked without stopping/restarting it again. The parent still needs its
always-cleanup for producer failures before driver guards/prerequisites succeed.

The cleanup CLI gets run owner and exact current source/image independently,
loads the existing Lifecycle, and verifies its separate producer offline record.
Missing/foreign witnesses, changed owner/source or incomplete absence fail. Do not
reset records, refresh IDs, delete by name, repeat a proposal, or rerun imports to
repair ambiguity. Preserve private evidence and escalate to the runner owner.
SQL cleanup retains the approved stop-only contract; the disposable hosted runner
owns eventual container/volume/network disposal. Partial imports may have written
the new owned SQL before a later rejection; cleanup is not transactional rollback.

Rollback removes the new workflow caller integration; existing production modules
and legacy gate contracts are unchanged. The later native trio result above
does not establish private cross-job handoff or full same-candidate M18 acceptance.

## Qualification

Use pinned Python 3.12.15 and the repository lock. These commands run offline
qualification fixtures only, not infrastructure. The combined preflight order is:

```powershell
uv sync --locked --no-build --python 3.12.15
uv run --locked python -B -W error -m unittest scripts.ci_serving_native_qualification scripts.ci_serving_recovery_qualification scripts.ci_serving_retention_qualification scripts.serving_campaign_qualification
```

The driver suite uses strict boundary fixtures, real file I/O, original driver
control flow and real private FD capture. It blocks subprocess/network entry
points. Existing transfer/SQL-import cryptographic qualifications run separately;
the combined suite also exercises the real lifecycle and signed retention readers.
Fixtures patch actual imported helper objects, not only `sys.modules` aliases.
Verified locally with Python 3.12.15: 20 driver tests passed, including 25 injected
failure boundaries through the same pipeline. The ordered combined preflight
passed 73 tests in 227.402 seconds. Branch-enabled coverage measured each
production module separately, with no excluded lines:

| Module | Statements | Branches |
| --- | --- | --- |
| `ci_serving_native` | 225/225 (100%) | 24/24 (100%) |
| `ci_serving_recovery` | 202/202 (100%) | 14/14 (100%) |
| `ci_serving_retention` | 166/166 (100%) | 32/32 (100%) |
| `serving_campaign` | 93/93 (100%) | 12/12 (100%) |

The initial driver absence and the original-pin/inner-cleanup regressions were
observed RED before implementation/fixes. A controlled actual-time check rejects
1200.01 against original expiry 1800 through the existing conservative clock.
Module entry, cleanup after context deletion, primary exception preservation,
partial cleanup, private output exit failure and complete environment restoration
are exercised. Full Ruff check and format-check passed (1137 files); docs check
passed (1197 files, 394 Markdown documents, 2798 local links).

These are controlled local qualifications and author self-review, not independent
review or a hosted M13/M14/M15 run. No Docker/WSL/Kubernetes/SQL/native CI process,
network request, external model, workflow change, publication or push was used
in that author's qualification.

## Parent integration and hosted playbook

Parent repeated the same 73 tests on Python 3.12.15: pass in 220.251 seconds,
with the four per-module statements/branches results above. Separate driver
review approved exact author commit `7e4840d9fcba8ad98c086e17572380d649f9b1ca`.
Workflow review and static checks confirmed 14 ordered steps, 12 valid Bash
blocks and five parsed Python blocks. This is not a hosted trio result.

The [workflow](../../.github/workflows/serving-consumer.yml) uses a public
standard disposable `ubuntu-24.04` runner. It prepares the pinned CPU image,
producer cluster and SQL, runs original M01/M02/M07, verifies producer cluster
cleanup, then calls this driver. Two independent `always()` steps stop source
SQL and invoke this driver's recorded consumer cleanup. It publishes no
artifacts or candidate pins; dependency output and GITHUB_OUTPUT stay private.

From the reviewed source commit in a clean checkout, the existing repository
owner can start the scoped workflow without altering main:

```powershell
git status --short
git rev-parse HEAD
git push origin HEAD:refs/heads/qualify/original-serving-consumer-native
gh run list --repo Abrakadabra124/trusted-mlsecops-platform --branch qualify/original-serving-consumer-native --workflow serving-consumer.yml
```

Require an empty status, then verify the run's exact `headSha`. Do not force-push
over a different attempt or repeat dispatch after an observer timeout. Read
the same run again; the [consumer observation runbook](ci-consumer-native.md) explains this case.
Accept only terminal success with the driver's final `stage=complete`, all three
gate counts, cleanup `required=4, verified=4`, successful separate cleanup CLI,
and verified source SQL shutdown. A missing/skipped/failed step remains refusal.
Record exact source, run/job, durations and the closed projection; keep raw logs,
pins and primary archives private. The 60-minute job limit and original
1800-second proposal/600-second phase requirements remain unchanged.

No successful native trio, private transport between jobs, M18 acceptance or
R1 release is claimed by this prepared workflow. Retained files survive consumer
deletion on the runner; a separate private lifecycle is still needed to preserve
them after runner disposal.
