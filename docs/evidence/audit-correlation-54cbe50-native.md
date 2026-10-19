# ADR 0046: native proof для 54cbe50

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [Краткое evidence](audit-correlation-2026-10-19.md), [ADR](../decisions/0046-private-audit-correlation.md), [RB-65/PB-39](../operations/audit-correlation-troubleshooting.md).

## Привязка

Проверенный код: [54cbe5028ad0e042f23cfc96ada18a64b543704f](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/54cbe5028ad0e042f23cfc96ada18a64b543704f). Все 10 workflows завершились на этом SHA, attempt 1: **6 success / 4 failure**. Наблюдатель подтвердил terminal matrix 2026-10-19T20:22:58.3160078Z. Повторных запусков этого increment не было. Последующая публикация этого документа - docs-only, не новый runtime test.

- Actual candidate: source_dirty=false, 81 уникальный pass case, release_ready=false. Finished 2026-10-19T20:17:50.709930+00:00.
- Serving image: `sha256:66fadcc36da096b96504c6db6d02fac5e439344654e8b4b93a4806cdd40e513d`.
- Source fingerprint: `df0476a4aa6aaf451a2d5a3e3de1fc86bce4c29a63bb21cf6bbe581fff06ad12`.
- Canonical full candidate report SHA-256: `e2b53feddfe39fa739d33d247cd0a0cd9e6f399fa9d38d282a09144d1221bd20`.
- Canonical controlled-release report SHA-256: `cfe1ccd6de33a5192cb5cc982391fbdee6a475d6e8f8186b5e4849e72e918a83`.
- Исходные пользовательские изменения AGENTS.md/GOAL.md не включены в публикацию. Локальные Docker/WSL/SQL не изменялись; native инфраструктура только disposable CI.
- Отдельные workflows строят собственные образы. Одинаковый commit не доказывает byte-identical image builds или единую M18 release-приёмку.

## Linux contracts и coverage

Storage [job 118280288643](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39316806682/job/118280288643):

- Новая correlation suite: **64 tests / 0 skips, 8.953 s**, pass.
- Public export/snapshot suite: **47 tests / 0 skips, 0.941 s**, pass.
- Максимальные context v2 JSONL records: release 1539 / qualification 1366 bytes при лимите 2048. Лимит не увеличен.
- Exact public schema и HTTP JSON не расширены. Canary probe проверяет новые nested source/run/evaluation значения; old context v1 не проходит correlation proof.
- Два regression tests после review запрещают mutable __deepcopy__ reference и prefix retention, скрывающий целиком legacy requests. Fresh campaign начинается с sequence=1; structural exporter по-прежнему может отдельно экспортировать suffix с честной семантикой.

| Модуль | Statements | Miss | Branch exits | Partial | Mixed Cover |
| --- | ---: | ---: | ---: | ---: | ---: |
| audit_lineage | 30 | 0 | 4 | 0 | 100% |
| serving_context | 52 | 0 | 8 | 0 | 100% |
| audit_event | 44 | 0 | 22 | 0 | 100% |
| audit_correlation_probe | 70 | 0 | 28 | 0 | 100% |
| audit_export_probe | 47 | 0 | 20 | 0 | 100% |
| audit_export | 96 | 1 | 40 | 1 | 99% |
| audit_snapshot | 130 | 0 | 50 | 1 | 99% |

100% для первых пяти модулей здесь означает отсутствие missed statements и branch exits. 99% exporter/snapshot - mixed coverage, не 99% branches: отдельно 39/40 и 49/50. Их прежние thresholds 95/95 не ослаблены. __main__ exporter проверяется реальными дочерними CLI, но не покрывается parent coverage.

## Наблюдавшаяся корреляция

| Window | Events | Correlated requests | Completed HTTP 200 | Failed after intent | Without context |
| --- | ---: | ---: | ---: | ---: | ---: |
| Actual candidate qualification | 332 | 58 | 58 | 0 | 25 |
| Controlled signed release | 56 | 8 | 8 | 0 | 6 |

Actual candidate использует неизменённый signed proposal и отдельный permit. Controlled release использует отдельно подписанные test roots/gate fixtures и 40 native cases; это **не** approval реального candidate. Presence context описывает намерение, completed_200 включает readiness, завершённый send не доказывает client receipt. Отказы после intent и aborted проверены controlled negative tests, но в этих двух native окнах failed_after_intent=0; не выдавать unit fault injection за наблюдавшийся production-инцидент.

Public actual window: 83 completed / 0 aborted / 0 unresolved requests, predict 78 / ready 5. Candidate contexts 58 / none 25 / release 0. Source counts и summary повторно сопоставлены локально; private graph не публикуется.

Смежные actual-candidate проверки: privacy 12 requests / 36 durable events / 3 owned files, 69 approved metric series, no ambient telemetry; audit pair accepted=durable=8. Golden 3 rows, maximum_error=0; stopped-worker denial 2.0148764150000034 s. Outage: 44 observations, last 200 59.70993375799998 s, first 503 59.761820236000005 s; assessment повторно вычислен из полного trace и совпал. Paused SQL denial 10.002015057999984 s, signed-expiry denial 6.684234716999981 s; оба с ACTIVE libpq query, unfinished read и fenced generation. Post-expiry HTTP 503 и renewal/recovery подтверждены. Это один lab trace, не универсальный SLA.

## Все terminal workflows

| Workflow | Run / job | Attempt | Conclusion |
| --- | --- | ---: | --- |
| [Frozen evasion and domain guard](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39316806650) | 39316806650 / 118280288296 | 1 | failure |
| [Paired robust training research](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39316806628) | 39316806628 / 118280288351 | 1 | failure |
| [Frozen poisoning research matrix](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39316806644) | 39316806644 / 118280289990 | 1 | failure |
| [Worker and storage image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39316806654) | 39316806654 / 118280288921 | 1 | failure |
| [Storage role and TLS qualification](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39316806682) | 39316806682 / 118280288643 | 1 | success |
| [Developer runtime qualification](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39316806617) | 39316806617 / 118280289418 | 1 | success |
| [Intake evidence contracts](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39316806614) | 39316806614 / 118280288211 | 1 | success |
| [Documentation integrity](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39316806632) | 39316806632 / 118280290518 | 1 | success |
| [MLflow tracking compatibility and private service](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39316806601) | 39316806601 / 118280287839 | 1 | success |
| [Kubernetes isolation qualification](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39316806627) | 39316806627 / 118280288267 | 1 | success |

## Смежные gates этого SHA

| Gate | Cases | Status / exit | Finished UTC |
| --- | ---: | --- | --- |
| M03 | 431 | pass / 0 | 2026-10-19T20:11:32.184860+00:00 |
| M07 | 97 | pass / 0 | 2026-10-19T20:12:54.057988+00:00 |
| M06 | 18 | pass / 0 | 2026-10-19T20:16:06.934705+00:00 |
| M20 | 725 | pass / 0 | 2026-10-19T20:20:40.746137+00:00 |
| M21 | 122 | pass / 0 | 2026-10-19T20:22:30.451036+00:00 |

Controller bootstrap: 139 scoped cases, observed 2026-10-19T20:16:31.293045+00:00, publisher/scorer dumpable=0 и core_limits=[0,0]. Controller image `sha256:84300db02778b8cfbb841e7b79cdcc97cb3dc374c20e6d373d11aeb4ad96de40`.

M07 прошёл с первой попытки, но это **не исправление** прежнего connection rejection: [f0d0542 first attempt](audit-export-f0d0542-native.md) и неизвестная причина остаются reliability debt. Ни thresholds, ни SQL concurrency limits не ослаблялись.

## Сохранённые release blockers

Image audit реально выполнил scan и проверил SBOM всех четырёх images, не был skipped. Числа относятся к severity findings данного scan, не к уникальным CVE:

| Image profile | Critical | High | SBOM valid / scan executed / exit |
| --- | ---: | ---: | --- |
| worker | 0 | 56 | true / true / 2 |
| storage | 9 | 132 | true / true / 2 |
| worker-candidate | 0 | 55 | true / true / 2 |
| storage-candidate | 1 | 85 | true / true / 2 |

Poisoning: execution complete, 35 trainings, 10 violating / 0 inconclusive / 25 nonviolating scenarios; итог fail. Evasion: recall_drop=0.07183673469387755 > maximum 0.05. Paired candidate также не прошёл:

| Seed | Recall drop | Threshold | Status |
| --- | ---: | ---: | --- |
| known-73041 | 0.052244897959183675 | 0.05 | fail |
| new-73043 | 0.06224066390041494 | 0.05 | fail |
| new-73047 | 0.06143344709897611 | 0.05 | fail |

Эти четыре workflow failures блокируют release и не переклассифицированы в pass из-за успешного serving/correlation. Полные M13/T16/R1, all-output acceptance и более ранние незакрытые задачи сохраняются.

## Полный очищенный actual-candidate report

Это synthetic lab report из stdout завершённого native job, не raw worker/HTTP logs и не приватные audit events. Числовые JSON lexemes сохранены; SHA вычислен Python canonical serializer.

```json
{
  "campaign_id": "bf18e02986b64577b59cc58281129b99",
  "candidate_reference": "480d8974510782932f291e5e241ab6705a7ce81a4796525d41d7b3ed3b09275c",
  "cases": [
    "original-signed-proposal-bound",
    "actual-release-remains-denied-without-assurance",
    "qualification-permit-is-not-release-approval",
    "source-candidate-loaded-without-resigning",
    "one-shot-reference-same-model",
    "unsigned-permit-never-ready",
    "unsigned-permit-never-predicts",
    "http-ready-after-actual-ONNX-load",
    "http-golden-CPU-consistency",
    "http-running-digest-bound",
    "http-mixed-score-and-abstain",
    "persistent-worker-reused",
    "http-missing-auth-401",
    "http-invalid-422-redacted",
    "http-oversized-413",
    "client-errors-do-not-disable-model",
    "independent-client-burst-boundary",
    "client-quota-refill-recovers",
    "client-admission-accounting",
    "primary-client-remains-available",
    "foreign-client-identity-401",
    "native-malformed-model-never-ready",
    "stopped-worker-inference-503",
    "deadline-removes-only-owned-worker",
    "failed-worker-readiness-503",
    "explicit-verified-reload-recovers",
    "context-candidate-not-release-selection",
    "context-ready-generation-bound",
    "context-prediction-generation-bound",
    "context-private-references-not-public",
    "context-public-shape-unchanged",
    "audit-http-pair-accepted",
    "audit-http-pair-durable",
    "http-422-empty-body",
    "http-422-unknown-version",
    "http-422-boolean-version",
    "http-422-unknown-feature",
    "http-422-missing-feature",
    "http-422-boolean-feature",
    "http-422-empty-batch",
    "http-422-over-100-rows",
    "http-422-nan",
    "http-422-infinity",
    "http-422-negative-infinity",
    "http-100-row-boundary",
    "http-real-lock-pressure-429",
    "http-remains-ready-after-invalid-and-overload",
    "trust-outage-cold-start-not-ready",
    "trust-outage-cold-start-no-ML",
    "trust-outage-expired-readiness-503",
    "trust-outage-owned-worker-cleaned",
    "trust-restart-no-implicit-activation",
    "trust-recovery-fresh-read-and-golden",
    "trust-outage-HTTP-deadline-and-no-extension",
    "paused-query-baseline-golden",
    "paused-established-query-HTTP-denial-before-completion",
    "paused-query-fenced-readiness",
    "paused-query-owned-worker-cleaned",
    "late-trust-read-cannot-reactivate",
    "paused-query-explicit-fresh-recovery",
    "near-expiry-paused-query-baseline-golden",
    "near-expiry-short-policy-limits-before-approval",
    "near-expiry-paused-established-query-HTTP-denial-before-completion",
    "near-expiry-paused-query-fenced-readiness",
    "near-expiry-client-denial-before-signed-expiry",
    "near-expiry-paused-query-post-expiry-denial",
    "near-expiry-paused-query-owned-worker-cleaned",
    "near-expiry-late-trust-read-cannot-reactivate",
    "near-expiry-renewed-trust-still-requires-activation",
    "near-expiry-paused-query-explicit-fresh-recovery",
    "privacy-http-input-and-output-matrix",
    "privacy-owned-audit-input-absent",
    "privacy-native-telemetry-disabled",
    "privacy-approved-metrics-cardinality",
    "actual-candidate-revocation-http-503",
    "actual-candidate-revocation-readiness-503",
    "closed-audit-private-primary-material-correlation",
    "closed-audit-public-export-schema-counters-and-canaries",
    "closed-audit-export-not-release-approval",
    "qualification-authority-and-private-key-removed",
    "source-cas-budget-envelopes-and-checkout-unchanged"
  ],
  "evaluation_reference": "6b311e760f67c1169b5f0936932b47b0f44329c0f410000c0cc01259a7a02931",
  "finished_at": "2026-10-19T20:17:50.709930+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f",
  "proposal_reference": "61f793148f9e84bba160c57fd0e015e8c5827da070491b71f155fdbd92484ca8",
  "qualification_permit_sha256": "764f71eb23848bfde6b142828417232750f21266047bef54b7d6cb90fb4694be",
  "reference_response_sha256": "8fb0800fef439821722025ec5bbc3f35b1346645b25c202b7fab41dfed77851e",
  "release_ready": false,
  "runtime": {
    "client_quota": {
      "admitted_deltas": [
        2,
        2,
        4
      ],
      "boundary_statuses": [
        422,
        429,
        422,
        429
      ],
      "refill_statuses": [
        200,
        200
      ],
      "release_ready": false,
      "status": "pass",
      "window_seconds": 0.005644383000003472
    },
    "golden_rows": 3,
    "http_audit": {
      "accepted_delta": 8,
      "durable_delta": 8,
      "release_ready": false,
      "scope": "actual-candidate-http-audit-pair-not-full-M13",
      "status": "pass"
    },
    "http_correlation": {
      "completed_200": 58,
      "correlated_requests": 58,
      "events": 332,
      "failed_after_intent": 0,
      "release_ready": false,
      "schema_version": 1,
      "scope": "candidate-qualification-private-correlation-not-full-M13",
      "status": "pass",
      "without_context": 25
    },
    "http_expiring_query": {
      "approval_deadline": 1094.8518829345703,
      "denial": {
        "active_observed": {
          "monotonic": 578.900898706,
          "wall": 1792441060.049015
        },
        "connected_read_entered": true,
        "finished_monotonic": 585.493497674,
        "finished_wall": 1792441066.641615,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 578.809262957,
        "started_wall": 1792441059.9573793
      },
      "expected_trust": {
        "document_sha256": "deac3d9ab7767c139084cd4fa230ca51ce0ca36cf366ea0fcd3fd6a0e871261e",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 585.7423839569092,
        "document_sha256": "deac3d9ab7767c139084cd4fa230ca51ce0ca36cf366ea0fcd3fd6a0e871261e",
        "monotonic": 578.752458938,
        "sequence": 51,
        "version": 2,
        "wall": 1792441059.9005754
      },
      "policy_expires_at": 1792441067,
      "policy_expiry_monotonic": 585.851883649826,
      "post_expiry": {
        "finished_monotonic": 585.903428062,
        "finished_wall": 1792441067.0515447,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 585.901997784,
        "started_wall": 1792441067.0501137
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 647.769456031,
        "document_sha256": "a1289c486f84b4a2b8a90e96b46a42818e50317a3b85c67d4f145a5c2c8825df",
        "monotonic": 587.779565295,
        "sequence": 56,
        "version": 3,
        "wall": 1792441068.9276822
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "a1289c486f84b4a2b8a90e96b46a42818e50317a3b85c67d4f145a5c2c8825df",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 566.946605874,
          "wall": 1792441048.094722
        },
        "connected_read_entered": true,
        "finished_monotonic": 576.85687349,
        "finished_wall": 1792441058.0049906,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 566.854858432,
        "started_wall": 1792441048.0029747
      },
      "last_verified": {
        "deadline": 626.788496376,
        "document_sha256": "2f2bcb749aaeecddd409601499e33654cd6adca2daf15184a59ead5505eb84c3",
        "monotonic": 566.79880403,
        "sequence": 43,
        "version": 1,
        "wall": 1792441047.9469206
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 638.152170493,
        "document_sha256": "2f2bcb749aaeecddd409601499e33654cd6adca2daf15184a59ead5505eb84c3",
        "monotonic": 578.163347155,
        "sequence": 49,
        "version": 1,
        "wall": 1792441059.3114638
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "http_privacy": {
      "ambient_signals_used": false,
      "approved_metric_series": 69,
      "audit_events_confirmed": 36,
      "audit_files_scanned": 3,
      "release_ready": false,
      "request_cases": 12,
      "scope": "existing-serving-output-privacy-not-full-M13",
      "status": "pass"
    },
    "http_trust_outage": {
      "assessment": {
        "failures": [
        ],
        "first_503_seconds": 59.761820236000005,
        "last_200_seconds": 59.70993375799998,
        "observations": 44,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "5609c93440a98d4c96ae2b10a3d822eb6655a899e7294eb0bba533e4407b430f",
        "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f"
      },
      "last_verified": {
        "deadline": 565.241549871,
        "document_sha256": "2f2bcb749aaeecddd409601499e33654cd6adca2daf15184a59ead5505eb84c3",
        "monotonic": 505.251588249,
        "sequence": 36,
        "version": 1,
        "wall": 1792440986.399705
      },
      "records": [
        {
          "finished_monotonic": 505.754617915,
          "finished_wall": 1792440986.9027348,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 505.733609112,
          "started_wall": 1792440986.8817258,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 507.776593397,
          "finished_wall": 1792440988.9247108,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 507.754763927,
          "started_wall": 1792440988.9028804,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.798330672,
          "finished_wall": 1792440990.9464478,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 509.776744729,
          "started_wall": 1792440990.9248614,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 511.819683939,
          "finished_wall": 1792440992.9678009,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 511.798484472,
          "started_wall": 1792440992.9466012,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 513.841464953,
          "finished_wall": 1792440994.989582,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 513.819819369,
          "started_wall": 1792440994.967936,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 515.86512131,
          "finished_wall": 1792440997.0132382,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 515.841607298,
          "started_wall": 1792440996.989724,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 517.887030339,
          "finished_wall": 1792440999.0351472,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 517.865271696,
          "started_wall": 1792440999.0133884,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 519.908606636,
          "finished_wall": 1792441001.0567236,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 519.887165218,
          "started_wall": 1792441001.035282,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 521.930483123,
          "finished_wall": 1792441003.0786002,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 521.908746821,
          "started_wall": 1792441003.0568635,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 523.95194052,
          "finished_wall": 1792441005.1000576,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 523.930639073,
          "started_wall": 1792441005.0787559,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 525.973524852,
          "finished_wall": 1792441007.1216419,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 525.952096684,
          "started_wall": 1792441007.1002133,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 527.995528742,
          "finished_wall": 1792441009.1436458,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 527.973677993,
          "started_wall": 1792441009.1217945,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 530.016911008,
          "finished_wall": 1792441011.165028,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 529.995668478,
          "started_wall": 1792441011.1437852,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 532.038443174,
          "finished_wall": 1792441013.1865602,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 532.017048878,
          "started_wall": 1792441013.1651657,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 534.060538219,
          "finished_wall": 1792441015.208655,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 534.038580518,
          "started_wall": 1792441015.1866972,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 536.082558495,
          "finished_wall": 1792441017.2306755,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 536.060682125,
          "started_wall": 1792441017.2087986,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 538.104949695,
          "finished_wall": 1792441019.2530668,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 538.082693366,
          "started_wall": 1792441019.2308102,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 540.127476162,
          "finished_wall": 1792441021.2755933,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 540.105085387,
          "started_wall": 1792441021.2532022,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 542.148951869,
          "finished_wall": 1792441023.2970688,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 542.127614346,
          "started_wall": 1792441023.2757308,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 544.170877728,
          "finished_wall": 1792441025.3189948,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 544.149075236,
          "started_wall": 1792441025.2971919,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 546.193069205,
          "finished_wall": 1792441027.341186,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 546.17101596,
          "started_wall": 1792441027.3191326,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 548.214936819,
          "finished_wall": 1792441029.3630538,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 548.193210028,
          "started_wall": 1792441029.3413265,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 550.236744215,
          "finished_wall": 1792441031.3848612,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 550.215079902,
          "started_wall": 1792441031.3631966,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 552.259788986,
          "finished_wall": 1792441033.407906,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 552.236895471,
          "started_wall": 1792441033.3850121,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.281375529,
          "finished_wall": 1792441035.4294925,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 554.259929835,
          "started_wall": 1792441035.4080465,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 556.303097845,
          "finished_wall": 1792441037.4512148,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 556.281535275,
          "started_wall": 1792441037.429652,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 558.324821561,
          "finished_wall": 1792441039.4729385,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 558.303247589,
          "started_wall": 1792441039.4513643,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 560.346665858,
          "finished_wall": 1792441041.4947827,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 560.324969345,
          "started_wall": 1792441041.4730859,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 562.368051222,
          "finished_wall": 1792441043.516168,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 562.346810302,
          "started_wall": 1792441043.4949272,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 564.390375629,
          "finished_wall": 1792441045.5384927,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 564.368178001,
          "started_wall": 1792441045.5162947,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 564.461672085,
          "finished_wall": 1792441045.609789,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 564.440506819,
          "started_wall": 1792441045.5886235,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 564.532457163,
          "finished_wall": 1792441045.6805742,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 564.511803025,
          "started_wall": 1792441045.6599195,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 564.603866482,
          "finished_wall": 1792441045.7519834,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 564.582555373,
          "started_wall": 1792441045.7306721,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 564.675578524,
          "finished_wall": 1792441045.8236957,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 564.653996107,
          "started_wall": 1792441045.8021128,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 564.746916859,
          "finished_wall": 1792441045.8950338,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 564.725712218,
          "started_wall": 1792441045.873829,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 564.818534617,
          "finished_wall": 1792441045.9666517,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 564.79704821,
          "started_wall": 1792441045.945165,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 564.889310938,
          "finished_wall": 1792441046.0374281,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 564.868675804,
          "started_wall": 1792441046.0167925,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 564.961522007,
          "finished_wall": 1792441046.1096392,
          "http_status": 200,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 564.939452478,
          "started_wall": 1792441046.0875692,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 565.013408485,
          "finished_wall": 1792441046.1615255,
          "http_status": 503,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 565.011651044,
          "started_wall": 1792441046.1597679,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 565.065058147,
          "finished_wall": 1792441046.2131753,
          "http_status": 503,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 565.063500722,
          "started_wall": 1792441046.2116175,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 565.116424821,
          "finished_wall": 1792441046.2645416,
          "http_status": 503,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 565.115137971,
          "started_wall": 1792441046.263255,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 565.167591945,
          "finished_wall": 1792441046.3157089,
          "http_status": 503,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 565.166512934,
          "started_wall": 1792441046.3146296,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 565.218695174,
          "finished_wall": 1792441046.3668122,
          "http_status": 503,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 565.217680193,
          "started_wall": 1792441046.3657968,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 565.269729384,
          "finished_wall": 1792441046.4178462,
          "http_status": 503,
          "lease_deadline": 565.241549871,
          "response_valid": true,
          "started_monotonic": 565.268784915,
          "started_wall": 1792441046.4169016,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 626.7489585,
        "document_sha256": "2f2bcb749aaeecddd409601499e33654cd6adca2daf15184a59ead5505eb84c3",
        "monotonic": 566.759722999,
        "sequence": 41,
        "version": 1,
        "wall": 1792441047.9078398
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0.0,
    "public_audit_window": {
      "context_kinds": {
        "candidate-qualification": 58,
        "none": 25,
        "release-selection": 0
      },
      "events": 332,
      "release_ready": false,
      "requests": {
        "aborted": 0,
        "completed": 83,
        "unresolved": 0
      },
      "routes": {
        "predict": 78,
        "ready": 5
      },
      "schema_version": 1,
      "scope": "serving-audit-public-window-not-full-M13",
      "status": "pass"
    },
    "stopped_worker_denial_seconds": 2.0148764150000034
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:66fadcc36da096b96504c6db6d02fac5e439344654e8b4b93a4806cdd40e513d",
    "source_fingerprint": "df0476a4aa6aaf451a2d5a3e3de1fc86bce4c29a63bb21cf6bbe581fff06ad12",
    "source_revision": "54cbe5028ad0e042f23cfc96ada18a64b543704f"
  },
  "source_dirty": false,
  "started_at": "2026-10-19T20:16:13.560872+00:00",
  "status": "pass",
  "subject_sha256": "5609c93440a98d4c96ae2b10a3d822eb6655a899e7294eb0bba533e4407b430f"
}
```

## Полный controlled-release report

```json
{
  "campaign_id": "d2ece684d9be4e258e8b0158f98f57bd",
  "cases": 40,
  "finished_at": "2026-10-19T20:15:57.407650+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "All-pass gate reports are controlled contract fixtures, not actual ML acceptance",
    "HTTP/ONNX execution only when an explicit worker image is supplied; not actual ML acceptance",
    "Current source ML security failures remain blocking"
  ],
  "release_ready": false,
  "runtime": {
    "client_quota": {
      "admitted_deltas": [
        2,
        2,
        4
      ],
      "boundary_statuses": [
        422,
        429,
        422,
        429
      ],
      "refill_statuses": [
        200,
        200
      ],
      "release_ready": false,
      "status": "pass",
      "window_seconds": 0.005713094999975965
    },
    "golden_rows": 3,
    "http_correlation": {
      "completed_200": 8,
      "correlated_requests": 8,
      "events": 56,
      "failed_after_intent": 0,
      "release_ready": false,
      "schema_version": 1,
      "scope": "release-selection-private-correlation-not-full-M13",
      "status": "pass",
      "without_context": 6
    },
    "maximum_error": 5.960464477539063e-08,
    "stopped_worker_denial_seconds": 2.0258930539999938
  },
  "schema_version": 1,
  "scope": "serving-HTTP-ONNX-TLS-controlled-fixture-not-full-M12",
  "source_dirty": false,
  "source_fingerprint": "df0476a4aa6aaf451a2d5a3e3de1fc86bce4c29a63bb21cf6bbe581fff06ad12",
  "source_revision": "54cbe5028ad0e042f23cfc96ada18a64b543704f",
  "started_at": "2026-10-19T20:15:37.864956+00:00",
  "status": "pass"
}
```

