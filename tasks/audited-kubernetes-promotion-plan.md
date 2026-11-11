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
- [ ] Verify schemas, total deadline, private failure, fresh challenge/receipt over TLS.
- [ ] Hosted real collector/source restart/outage; per-module coverage and cleanup.

## Task 2: owned Kubernetes audit profile and schema2 promoter

Files: mlsecops/kube_security_events.py and resource/provisioning helpers,
kube_promotion.py; relevant qualification and native scripts/workflows.
Consumes task1 transport and security_trust_service. Produces bootstrap/validate,
durable audited promoter mounts/config, correct schema2 validation.

- [ ] RED existing schema mismatch plus required fixed audit path/private mounts.
- [ ] Implement owned CA/secret/journal provisioning and validated Service address;
  collector+trust observer lifecycle, narrow Cilium rules, separate role state.
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
