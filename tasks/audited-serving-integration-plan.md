# Mandatory serving audit and coherent campaign lifecycle

Current checkpoint: d66b12a primary43155788888 passed real HTTP configuration
roundtrip (54.987612s incompatible policy, 56.628996s restored ONNX), retained
Deployment/outbox and complete owned cleanup. Security43155788165 passed993 test
executions and25/37/17/46native assertions. M11 on the same source failed at the
progress parser after12m51s, with owned cleanup confirmed. A finite startup
refusal producer/parser mismatch was reproduced and corrected; the underlying
native startup failure is still unknown and needs a new run. Next increment reuses the existing HTTP owner for audit
readback, refuses another serving audit Job and verifies orphaned Pod absence.
Its controlled campaign starts HTTP before audit outage/restart proof; bootstrap
before first actual admission, shared probe handoff and mandatory heartbeat remain
open. See [source-bound evidence](../docs/evidence/serving-handoff-2026-11-12.md#проверенная-смена-конфигурации-наd66b12a).

Неделя11/T29, continuation of audited-kubernetes-promotion-plan.md. Baseline
c4b6cdc documents runtime4aeece4; scoped promotion/outage recovery is verified,
full M23/R1 remains open. Existing authorization permits implementation and hosted
disposable validation without another approval round. No local infrastructure,
external models, paid services or relaxation of acceptance thresholds.

## Verified integration defects

1. `scripts.kube_serving_native.prepare` calls actual promotion refusal before any
   audit profile exists. `kube_candidate_native.qualify(prepared=None)` repeats
   this ordering. Mandatory `kube_promotion.invoke` now correctly refuses that state.
2. Serving/privacy derive HTTP config from promotion schema by dropping only
   schema_version, leaving security_audit_config. `serving_http.configured`
   correctly rejects this unknown field. Serving needs its own identity_audit_file,
   producer identity and durable outbox, not promoter signing material.
3. Controlled, candidate, privacy and load paths currently choose authorities at
   different stages. A persistent trust observer must retain one explicit initial
   root and full signed history across policy changes and root rotations.
4. `kube_security_events.validate(initial_root=...)` currently compares promotion
   current root directly with audit initial root. This is valid before rotation;
   it cannot prove a rotated root. A signed transition chain must bridge them.
5. Registry currently requires heartbeat from trust only. Serving heartbeat must
   belong to the real HTTP lifecycle before it becomes mandatory. A stand-in
   daemon or test-generated heartbeat would misrepresent serving availability.
6. Reusing ml-serving for observer and serving shares namespace/service-account
   network identity but must not share signing keys/outbox mounts. Current single
   PVC and four-Secret quota cannot silently grow. Specify bounded resources and
   verify actual access, memory and CPU with fresh M13/M14.
7. The ordinary HTTP lifespan calls engine.activate once at startup. Its maintenance
   loop checks an already activated generation; it is not an existing release reload
   API. Do not claim automatic first activation after a new SQL selection.

## Intended execution order

One operator campaign owns the trust authority and audit materials. After model
storage and trust storage exist, it creates the initial signed trust state and
audited collector/observer. It starts the actual serving HTTP process with a
separate serving event identity and durable state before approving a model.
Its security heartbeat means HTTP identity handling is alive; it does not claim
that a model is Ready or that predictions are allowed. Initial prediction requests
must still fail without an authorized selection.

After selection the operator performs a verified replacement of the serving Pod,
retaining the service identity and durable outbox. The existing startup reader
activates only the authorized bundle. Readiness gates traffic until verification;
replacement must remain within the heartbeat loss budget or refuse new promotion.
Activation, revocation and rollback remain bound to exact artifacts.
Serving identity failures deliver signed events or fail closed;
they cannot delegate signing to trainer, inference worker or promoter. Collector
outage must deny new promotion while the ML observation path remains measurable.

Trust rotation uses the existing dual-signed package. Observer receives an explicit
operator update retaining the original initial root, journal pin, event history and
heartbeat counter. New immutable configuration must have recorded UID/content pins;
unknown, interrupted or substituted updates remain refused. Do not delete history,
mint a replacement epoch or weaken heartbeat requirements to obtain a green run.

## Implementation and evidence tasks

- [ ] Add failing contracts for preparation ordering, shared campaign authority,
  exact serving config fields, required serving identity and worker exclusion.
- [ ] Refactor preparation/callers to establish one campaign authority before actual
  refusal; preserve actual release_assurance_required and controlled vs actual labels.
- [ ] Provision serving role credentials and separate durable outbox with explicit
  namespace/PVC/Secret quotas. Test lost state, incorrect role, pin, Pod mutation,
  no adoption and no automatic reinitialization.
- [ ] Wire real HTTP identity child/heartbeat and service lifecycle before promotion.
  Assert no model before admission, valid inference after admission, no forged
  readiness from security heartbeat, controlled serving Pod replacement with retained
  identity/outbox, actual denial delivery and recovery.
- [ ] Implement explicit observer rotation configuration transition and current-root
  verification against signed history. Verify old-root refusal, missing package,
  retained journal/counter, owned Pod replacement and interrupted update behavior.
- [ ] Update controlled/actual/privacy/load/monitoring callers coherently, preserving
  qualification permits as qualifications, never actual release authorization.
- [ ] Run fresh M13/M14 and required M23 source/outage/durability scenarios on the
  deployed profile, retain raw logs privately and sanitized evidence publicly.
- [ ] Clean checkout reproduction, exact source/image/policy binding, runbook,
  terminal CI and verified owned cleanup before publishing acceptance claims.

## Metrics and stop conditions

All original gate thresholds in docs/acceptance.md remain mandatory. No extra
percentage-of-completion claim follows from this plan. Require fresh audit on every
release, unchanged combined object+selection snapshot for initially unavailable
audit, exact original-event recovery, monotonic counters across replacement,
delivery <=60s and telemetry loss detection <=120s. Existing atomic-commit limits
and partial immutable artifacts after a mid-flight outage remain explicit.

The prior observer45s qualification timeout is still unexplained: diagnostic-only
4156d41 passed with unchanged runtime. Preserve that history, collect bounded
evidence if it recurs and prove a causal fix before calling it resolved.

This plan does not remove M10 actual admission, full M19, M22 independent human
challenges, M16 canary/rollback, M17 restore, image findings or shutdown debt.
M18 remains LAST and must accept every required gate on one candidate.

## Implementation ledger

2026-11-12 explicit serving configuration transition, currently local-only:
`kube_security_events.validate(authority_root=...)` already accepts roots proven
by the signed observer rotation history. This establishes continuity, while the
model Reader still checks the current SQL root. Therefore an old suspended HTTP
configuration can be verified after observer rotation without bypassing integrity.
The NEW target configuration additionally requires the observer's CURRENT verified
root, the same environment, credential paths, serving identity and worker image.

The coordinator consumes a verified suspension ticket, checks old HTTP/worker/Job
absence, persists a change intent, deletes only the pinned ConfigMap UID and
resourceVersion, confirms disappearance, then creates a new immutable ConfigMap.
Deployment UID, signing/TLS credentials and PVC/outbox remain owned and unchanged.
An intent invalidates the original ticket before deletion begins; failed/uncertain
deletion or creation remains suspended and cannot resume by recomputing that ticket.
Only full new-config validation clears the intent and returns a rebound ticket.
Exact no-op configuration requests are idempotent. Interrupted-transition recovery
still needs an explicit operator procedure; no blind reset/adoption is introduced.

Negative-first local91tests pass,139/139statements and46/46branches of the
coordinator covered. Next native proof must switch the actual HTTP process to an
incompatible policy config (real503/no worker), return to the original admitted
config (real ONNX), retain independent identity receipts and heartbeat, and verify
old/new ConfigMap and Pod UIDs plus unchanged model ledger. This proof is pending;
bootstrap-before-actual, all-caller handoff and mandatory serving heartbeat remain
required. No new full-M23 or R1 acceptance is claimed.

Persistent Deployment increment: service configuration, UID/resourceVersion-bound
scale-to-zero, verified old process cleanup, then single-replica
replacement, separate service.token, exec readiness/liveness probes and in-place
HTTP readback are implemented and verified on88e7c0a/Kubernetes43119250736:
19promotion+12audit+4/4/10/4HTTP checks, replacement28.737285s, heartbeat2->3,
retained outbox and independently matched identity receipt, all owned cleanup.
Security43119182873success774Linux0skips; clean153tests/1Windows skip.
[Evidence](../docs/evidence/persistent-http-2026-11-12.md). No quota increase,
second HTTP server, new public listener or registry heartbeat bypass is added.
Registry still requires trust only until all campaign/caller paths own the actual
HTTP lifecycle. Do not close mandatory serving heartbeat or full M23 on this proof.
Security outbox persists on security-serving; ordinary HTTP request journal remains
per-Pod in private tmpfs, an explicit retention limitation. Initializers never
inherit application health probes. Replacement retains the same immutable config,
Secret and durable outbox; expected selected release is verified by the reader.

2026-11-12: initial campaign authority wiring implemented, native verification pending.
Reuse existing pinned operator `keys/trust.pem` / trusted-keys.json, validate the
key/public binding and never create a missing authority key. `initialize_campaign`
installs the existing separate trust schema and creates a signed unapproved-campaign
seed only when there is no signed current document. Existing policy is never reset.
Collector/observer bootstrap follows this authority preparation, before actual refusal.
Controlled promotion, ordinary serving, privacy and standalone candidate callers now
reuse this authority. Qualification permits retain separate keys and purposes.

Negative-first tests cover pin mismatch, missing key, hosted-only guard, seed versus
existing policy, foreign authority refusal before update/audit, and coherent privacy
handoff key. Local38promotion/serving tests plus39privacy/load/candidate tests pass.
An initial Windows short/full-path assertion was corrected using canonical paths.
The HTTP exact-field/mandatory identity integration and observer root-rotation update
remain open; this authority wiring alone cannot make those native paths accepted.

00b7c39 hosted proof: Kubernetes43107249594success13promotion+10audit assertions;
security43107221066success753Linux0skips+25/37/15/46native. Freshlocked checkout
77tests/0skips. Same runtime fingerprint; actual candidate refused, full R1 open.
Two added caller regressions verify incomplete audit stops serving/candidate before
actual refusal. Added native repeated initialize_campaign compares root/version/
signed envelope after a working policy exists; its next run must confirm no reset.

The d4e1e86 run now confirms this idempotence assertion: Kubernetes43108656911
success14promotion+10audit, owned SQL/cluster cleanup success. Security43108621949
success755Linux0skips and25/37/15/46native. Fresh checkout79tests0skips was verified.

Serving integration increment: fourth role now has dedicated TLS/signing files,
identity-audit.json and security-serving PVC. Operator selects by namespace+claim
name and rejects swapped/missing volumes without repair. ml-serving quota permits
exactly two PVCs/five Secrets, with no CPU/memory increase. No duplicate network
policy is created for the shared namespace/service account. Service digest binds
workspace/environment/role, independently of model and image replacement.

Ordinary serving/privacy configuration now validates promotion schema2, drops its
schema/admission fields, adds only the serving identity config, and deep-copies
context. Ordinary serving Jobs require the identity config and validated audit
profile before creation, mount only serving audit credentials, and leave candidate
qualification Jobs unchanged. Real serving_http.configured is exercised by unit
tests with the converted config. Local127tests-Werror pass with one Linux-only skip.
New native checks read actual serving outbox from two owned Jobs, compare pins,
separate volume identity and0700/0600 permissions; hosted verification is pending.

Still required: uninterrupted actual HTTP lifecycle before/after release, mandatory
registry heartbeat, independent collector receipts for deployed HTTP denial,
candidate/load/monitoring integration, observer rotation transition, fresh M13/M14
and the original full R1 gates. No checkbox claiming those outcomes is closed here.

6f04191 hosted proof is now verified: Kubernetes43111654007success14promotion+
12audit assertions and owned cleanup; security43111626192success762Linux0skips+
25/37/15/46native. Fresh checkout127tests/1Windows skip; Linux executes it.
This proves the fourth role's actual persistent state, not HTTP lifecycle.

Next implemented composition (native result pending): existing primary promotion
campaign provisions serving API permissions and invokes the ordinary CLI before
approval, after selection, and after artifact revocation. Same image/config/authority,
separate inference worker, unchanged model/promotion snapshot, exact model/bundle
binding and ONNX parity use the existing verifier. A fresh identity.denied is
matched to the independent collector receipt; old events, changed pin and missing
or altered receipt fail. No fake Engine or directly fabricated producer event is
used in this deployed path. The three Jobs are sequential; continuous_lifecycle
remains explicitly false. Mandatory persistent HTTP/heartbeat, observer rotation,
candidate/privacy/load/monitoring, M13/M14 and full R1 remain open.

d86d3de hosted composition accepted: Kubernetes43113676523success18promotion+
12audit plus13before/22active/14revoked HTTP checks. Golden error7.583384781240099e-08,
one fresh identity.denied matched to independent collector receipt; each owned CLI,
worker and final SQL/cluster cleanup verified. Actual candidate remains refused
release_assurance_required. Security43113651515success763Linux0skip+25/37/15/46native;
clean locked128tests1Windows skip. Continuous lifecycle and all remaining requirements
above are unchanged, no M18 or full R1 acceptance follows from this composition.

2026-11-12 observer rotation increment prepared: full anchored signed history,
immutable public ConfigMap, serialized UID/resourceVersion-bound replacement,
unchanged producer keys/PVC/pin and signed-event prefix, current-container first
source success plus independent collector counter. Interrupted transition keeps
ready=false; automatic recovery remains open. Local123tests/1Windows skip pass.
Hosted primary campaign adds real rotation/old-root refusal/exact-event receipt,
pending live evidence. Mandatory serving heartbeat and all caller transitions
remain open; this increment does not close M11/M23/M18 or R1.

e7ec709 hosted43125706293 success:19promotion+12audit+10observer cases,
rotation9.8959s/heartbeat14->15, exact revocation receipt, old-root refusal,
unchanged model ledger and cleanup verified. Security43125649611 failed coverage
and recurring45s source recovery timeout. Coverage gap corrected by signed-state
negative tests; new modules now have separate >=95% per-module CI guard. Timeout
cause remains unknown; read-only failure diagnostics added, thresholds unchanged.
See [evidence](../docs/evidence/observer-rotation-2026-11-12.md); no full gate closure.

Followup4f726f5 security43127559794 terminal success:842Linux test executions,
zero skips;25/37/15/46native cases; new per-module coverage gates passed.
Runtime fingerprint unchanged from e7ec709; clean checkout133tests7.930s1Windows
skip. Recurring timeout cause remains unexplained despite this successful replay.

Next caller increment implemented locally: ordinary rotation now updates the
owned observer before old/new-root HTTP checks; candidate rotation updates it
after the measured live PRIMARY refusal/recovery and before the independent
MODEL_REVOCATION peer. Failed observer transition preserves committed PRIMARY,
does not rotate peer, and cannot report success.14coordinator tests,100% statements
and branches for both modules. Hosted M11 caller proof pending; no broader closure.

aa276b2 hosted M11 43130494941 terminal failure: ordinary rotation reached the
next live-trust-outage stage, then response-contract failed. Candidate transition
not accepted. Source SQL/cluster cleanup passed; backup/recovery skipped.
Security43130462337 passed856Linux/0skip and25/37/15/46native cases. Root cause
is unknown; finite response-failure categories added for the next bounded replay,
without changing accepted responses, deadlines or interpreting429 as trust refusal.

5486596 hosted M11 43132977638 terminal success:146cases,701Linux executions/0skip,
ordinary observer11.688843s/HB16->17 and candidate10.732460s/HB25->26, retained
outbox and cleanup. Three primary hashes and trace/signer metrics independently
reconciled. Security43132975200 passed856Linux/0skip. Clean72tests/0skip.
[Evidence](../docs/evidence/m11-observer-callers-2026-11-12.md). Previous response
contract and45s observer failures remain unexplained; success is not causal repair.
Next mandatory step remains coherent serving lifecycle/heartbeat across callers,
fresh M13/M14 and full M23; actual admission/M18/R1 remain open.

## Next implementation: explicit transfer of the serving identity

The permanent Deployment and qualification CLI already run the real serving
HTTP implementation. They must never write the same audit state concurrently.
Use an explicit operator transfer: validate owned Deployment/config/identity;
persist a suspended marker and unique ticket; scale1->0; verify old HTTP and
worker removal; run the qualification HTTP owner; verify its Job/worker cleanup;
then restore the original Deployment with the same config, keys and PVC.
An altered/stale ticket, unknown Job, failed cleanup or interrupted replacement
must keep the marker unready and prohibit a second owner. A failed test may return
ownership only after cleanup is independently confirmed; it still fails the gate.

This preserves existing real-process expiry/fault/privacy tests, including their
SIGSTOP-based trust-read anchor, without applying SIGSTOP to the permanent
Deployment's liveness-probed process. It does not claim one uninterrupted PID
across qualification runs. Heartbeats must always originate in whichever real
HTTP process currently owns the identity. Collector readback and retained state
must prove handovers before enabling the mandatory registry flag.

Required followup in this same integration: explicit configuration changes between
actual/controlled contexts, bootstrap before first admission attempt, transfer in
the shared native invoke path, measured heartbeat continuity and cleanup, and
fresh M11/M13/M14/M23. The existing globally optional serving heartbeat is not
considered solved until these callers and the registry requirement are coherent.

Operator transfer is now implemented and wired into the primary controlled
promotion campaign. Local verification:59 tests/0skips with warnings as errors;
the new coordinator covers45/45 statements and6/6 branches.11 of those tests
reject incomplete return evidence (stale heartbeat, changed Pod/identity/permissions,
missing independent receipt, failed actual probe). Hosted execution is pending.
The report uses `single_owner_lifecycle`, not uninterrupted process continuity.
Interrupted transfer recovery and the global caller/registry integration remain
open; this checkpoint does not accept M23 or R1.

Readback review found a missing ownership condition: absent Jobs do not prove
their asynchronously deleted Pods are gone. A negative test reproduced the
incorrect resume, then the coordinator was changed to wait for empty Pod
inventories in both serving namespaces. Missing inventories and orphaned Pods
block the next owner. Local coordinator coverage is now59/59 statements and12/12
branches;33 focused tests pass. Fresh hosted confirmation remains required.

Security run43139535579 on6d202b5 failed45s observer recovery after collector
restart (outbox2events/1receipt, collector1/1,3 failed checks). Configuration,
signed SQL history and producer state were readable afterward; cause remains
unknown. Finite child exit categories were added without changing scheduling,
acceptance deadlines or journal locking. This is diagnosis, not causal repair.

Candidate/load/monitoring/privacy applications now attach the existing serving
Observer to their actual HTTP lifespan. Native invoke validates the audit profile
and mounts only serving identity/state for these callers; PRIMARY and independent
MODEL_REVOCATION authority scopes stay distinct. Local combined165 tests/4 Linux
skips pass, including owned real-loopback helper lifecycle and missing-identity
refusals. Hosted caller proof and mandatory registry/shared handoff integration
remain pending. No new metrics series or acceptance threshold were introduced.

86a6327 primary43141312875 failed during handoff because the newly added empty-Pod
condition also counted the legitimate trust observer in ml-serving. SQL/cluster
cleanup succeeded. The corrected inventory excludes only the independently
validated observer UID/spec/container instance, never a label/name match; orphaned
HTTP/worker Pods still block handoff. Native invoke now checks the probe slot and
waits for Pod cleanup after Job deletion. Local coordinator85/85 statements and
26/26 branches; hosted verification of this correction is pending.
