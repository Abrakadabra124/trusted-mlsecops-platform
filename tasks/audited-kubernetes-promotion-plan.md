# Audited Kubernetes promotion implementation plan

> Executor: superpowers:executing-plans inline, negative-first; без внешних моделей
> и повторных согласований в пределах ранее разрешённой цели.

**Goal:** исправить schema mismatch и соединить реальный promoter Pod с обязательным аудитом.
**Architecture:** bounded direct mTLS, private persistent collector/outboxes,
existing trust observer, existing promoter verifier. No unaudited fallback.
**Spec:** [ADR0066](../docs/decisions/0066-audited-kubernetes-promotion.md),
[M23](../docs/acceptance.md#m23), [R1 delivery](../docs/r1-delivery.md).
**Tech Stack:** locked Python3.12.15/ssl/uvicorn/cryptography, existing Kubernetes/Cilium.

## Global constraints

Не запускать/менять локальные Docker/WSL/Kubernetes/SQL. Hosted infrastructure only.
Не менять thresholds/roles/keys/epoch, AGENTS/GOAL или enterprise repository.
МTLS1.3; signed events/receipts; wire deadline2s; fixed routes and response bounds.
Новая security logic >=95% statements/branches и обязательные negative scenarios.

## Review focus

Downgrade/schema confusion; handshake exceeding total deadline; credentials sent
before server authentication; wrong-role secret mounts; missing state mistaken
for a request to initialize. Test these at the owning task, retain failures.

## Task 1: authenticated bounded transport

Files: mlsecops/security_event_tls.py, security_event_delivery.py,
security_event_admission.py, security_event_server.py;
scripts/security_event_tls_qualification.py and hosted TLS collector probe.
Consumes existing exchange/Emitter/Configured/Collector. Produces explicit client
schema2, admission schema3 and collector schema2, with unchanged legacy loopback.

- [x] RED real TLS wrong CA/name/missing client certificate; no bearer before handshake.
- [x] GREEN TLS material validation/context/connect, bounded exchange and collector bind.
- [x] Verify schemas, total deadline, private failure, fresh challenge/receipt over TLS.
- [x] Hosted real collector/source restart/outage; per-module coverage and cleanup.
  [ae7b687 /43095023099 success](../docs/evidence/audit-tls-2026-11-12.md).

## Task 2: owned Kubernetes audit profile and schema2 promoter

Files: mlsecops/kube_security_events.py and resource/provisioning helpers,
kube_promotion.py; relevant qualification and native scripts/workflows.
Consumes task1 transport and security_trust_service. Produces bootstrap/validate,
durable audited promoter mounts/config, correct schema2 validation.

- [x] RED existing schema mismatch plus required fixed audit path/private mounts.
- [x] RED/GREEN scoped role resources and explicit fresh-volume provisioning.
  This is a building block; bootstrap and native deployment below remain required.
- [x] Implement owned CA/secret/journal provisioning and validated Service address;
  collector+trust observer lifecycle, narrow Cilium rules, separate role state.
  Code and pure contracts pass; native deployment is not yet accepted.
- [ ] Connect existing promoter bootstrap/CLI and update caller fixtures coherently.
- [ ] Native actual refusal, controlled positive, collector outage/no-write, recovery,
  Pod restart durability, wrong worker access and owned cleanup.

## Task 3: evidence, operations and publication

- [ ] Fresh clean checkout, scoped regression, source/image pins and terminal CI.
- [ ] Runbook diagnosis/recovery/rollback; public evidence with failure history.
- [ ] Publish/verify remote, retain full M23/R1 remaining criteria and next integration.

## Ledger

Baseline db25bbb. Previous observer final docs CI43089077612 both jobs success.
Existing kube promotion pure test fails unexpected_fields; schema1->controller
schema rejection, schema2->kube rejection reproduced without network/SQL.
Preflight interfaces: TLS profile version differs from signed event/registry
schema; never reinterpret event envelopes as transport config. Persistent state
and mount design must keep outbox lock independent of observer config-directory lock.

Task1 in progress: real TLS negative tests RED before module/schema implementation.
Current local56tests4.991s-Werror/3Linux skips. TLS52statements6branches100%,
server47statements10branches100%, delivery>=95% branches locally; durable outbox
coverage needs its existing Linux tests. Windows reset/aborted connection after
expected client rejection was reproduced with finite exception type and stopped
thread; only negative listener cases accept that transport termination.
Actual Linux TLS collector test and hosted source regressions still pending.

Task1 correction ae7b687: initial43093814194 contracts failed on Linux BrokenPipeError
in negative test listener; native job succeeded. Failure and partial-HTTP assertion
correction retained in [runbook](../docs/operations/audit-tls.md). Run43095023099
has passed every contracts step including actual TLS collector and coverage;
terminal run/native status must still be observed before accepting the increment.

Task2 first building blocks: kube_security_resources creates fixed role Secrets,
three namespace-separated Retain PVC requests, narrow Cilium TLS routes, private
copied files and single-replica/Recreate runtime specifications. security_event_provision
only initializes /audit/state as an explicit operator action, reopens committed state,
rejects existing/incomplete directories and emits public pins, never credentials.
Local13tests/1Linux skip, both modules100% statements/branches. Actual Linux filesystem
and cluster deployment remain separate checks. No adapter schema change yet.

Next integration order: owned audit PKI/registry -> reserve resource UIDs and ServiceIP
-> fresh-PVC provisioning Jobs/readback/pins -> immutable role Secrets -> collector
and SELECT-only observer -> validate ownership/PV identity -> schema2 promoter mount
and all caller fixtures -> hosted restart/outage/worker boundary proof.
Do not add bootstrap init to runtime pods or recover a lost marker by adopting resources.

Task2 implementation2026-11-12: dedicated P256 TLS CA, fixed SAN/purposes,
Ed25519 signed registry with all six producer roles, private file pins, no rekey/adoption.
Operator bootstrap reserves resource UIDs, validates ServiceIPv4 and PV binding/spec,
provisions three journals through separate Jobs, verifies their public pins and cleanup,
then creates immutable role Secrets and collector/observer Deployments. Actual Pod
ancestry/spec/image and private environment boundaries are checked before promotion.
Adapter now requires schema2 and /security/audit.json; it refuses missing/changed
audit profile before creating a Job or initializing the promotion ledger.

Local44tests/1Linux skip, per-module coverage: provision43/43statements8/8branches,
resources70/70+16/16, materials120/120+26/26, operator201/203+68/70,
promotion140/141+41/42. Full hosted proof is pending. Harness imports were checked;
initial wrong helper import and test fixture attribute collision were corrected locally.

Prepared native proof uses actual scoped Pods, fresh mTLS challenge, a temporary
owned Cilium ingress denial, actual promoter refusal/no SQL change, original pending
event recovery, collector/observer Pod replacement and worker TCP/mount refusal.
It is connected to kubernetes-promotion.yml but has not yet produced accepted evidence.
Repeated API observations of old TLS run43095023099 still report in_progress despite
successful steps; log download502 is not a successful final run. New integration
was held until a terminal status. Final success is now verified and both logs read:
624Linux executions/0skips, per-module coverage >=95%, native25+37+15+46assertions.
The existing branch can now publish the next integration without cancelling that run.

Remaining caller integration is explicit: serving/privacy/load prepare currently
performs actual candidate refusal before its controlled audit bootstrap. This ordering,
serving identity profile and trust-rotation configuration need the fresh M13/M14
integration; do not mark that path accepted by the promotion-only native proof.

Prepublication regression: 85 executions with `-W error`, one POSIX-only skip on
Windows; 13 promotion adapter tests pass separately. An existing CLI test used
`run_module` after importing its module and failed on RuntimeWarning in strict
mode. It now uses `run_path` against the actual module file; argument rejection
and private stderr assertions remain unchanged. Ruff and local documentation
links pass. This does not replace the required hosted filesystem/cluster proof.
