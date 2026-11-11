# Mandatory serving audit and coherent campaign lifecycle

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

Persistent Deployment increment: service configuration, UID/resourceVersion-bound
scale-to-zero, verified old process cleanup, then single-replica
replacement, separate service.token, exec readiness/liveness probes and in-place
HTTP readback are implemented. Native verification is pending. No quota increase,
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
