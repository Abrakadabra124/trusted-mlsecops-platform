# T16: native primary audit evidence a7a09c8

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0049](../decisions/0049-private-audit-evidence.md), [RED/GREEN/review](audit-evidence-2026-10-20.md), [RB-68/PB-42](../operations/audit-evidence-troubleshooting.md).

## Проверенный результат

- Code SHA: [a7a09c87fd299620e4753ec76c971ab80df16623](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/a7a09c87fd299620e4753ec76c971ab80df16623).
- Native [Storage job](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316658/job/118712556919), attempt 1, success. Candidate interval: 2026-10-20T15:27:47.981484+00:00 -> 2026-10-20T15:29:25.995746+00:00.
- 85 уникальных candidate cases, включая retained packet, fresh receipt admission и parent reverify после child exit/source journal cleanup. Это проверенный компонент, не full M13, M12 или release approval.
- Image: `sha256:a45751b03aeca1572c29192a041543b46e32447f86ae1e8fbd2a029e8aa883f9`; source fingerprint: `35d6bf3594ad182f128a49cb068718379c0f066ed9e1a891f80f02da0ef24c01`.
- Private packet SHA-256: `4f7ff8fdbfcaeb63e783fe2ad5f7e49a5428df189d4dbe592482fd1b7e5a455c`. Сам packet не публикуется: содержит приватные identifiers и primary bytes, хранится только до teardown disposable VM.
- Independent HTTP ledger: **107 responses**; closed audit: **336 events / 84 completed / 0 aborted / 0 unresolved**; **58 correlated / 26 without context**, failed-after-intent=0. Разница 23 - responses без audit admission, допустимые только по проверенным правилам 401/404/429/503. Это не 23 потерянных journal records. Exact ID/route/status/admission соответствие проверяет parent по retained packet, а не по арифметике summary.
- HTTP-аудит: predict 79, ready 5. Counts зависят от числа наблюдений timed outage; предыдущие 340/85 в b0df48e не являются нормативом для нового запуска. Проверяются фактические primary bytes и обязательные нижние границы, не равенство прошлому run.
- Full-lifecycle output observer: 6 canaries, native stderr=0, all nested captures sealed. Privacy probe: 12 requests / 36 durable events / 3 audit files / 69 approved metric series. Ни эти probes, ни packet не доказывают покрытие ещё не подключённых service logs.
- Отдельный controlled release fixture: 40 cases, иной scope. Его нельзя автоматически объединить с actual-candidate campaign в полную M13-приёмку.

## Linux contracts и regression

| Проверка | Фактический результат |
| --- | --- |
| Fresh private receipt checker | 14 tests, 0 skips, 100% |
| Full-lifecycle observer + parent crypto | 26 tests, 0 skips; observer 100%, parent 99% |
| Packet verifier / HTTP ledger / retain probe | 20 tests, 0 skips; каждый модуль 100% statements/branches |
| Public export + snapshot + packet native IO | 56 tests, 0 skips; export 99%, snapshot 99%, export probe 100% |
| Independent private lineage/correlation | 64 tests, 0 skips, 100% scoped modules |

Native IO suite включает реальный owned loopback: закрыть HTTP и journal, сохранить packet, удалить source temporary directory, заново загрузить packet и пересчитать результат. В том же наборе проверены exclusive creation/nooverwrite, 0700/0600, symlink/hardlink отказ, short-write/fsync failure и readback. Controlled fault injection не доказывает физический power-loss recovery.

M03 **431 cases pass**, M07 **97 pass**, M06 **18 pass**, M20 **725 pass**, M21 **122 pass** на этом SHA в своих CI jobs. Это отдельные synthetic-profile gates, не M18 acceptance всего release. Старый intermittent M07 connection rejection остаётся reliability debt с неустановленной причиной; один новый pass не считается его исправлением.

## Полная terminal CI-матрица

Все 10 workflows завершены; **6 success / 4 failure**, каждый attempt 1. Нет rerun, cancelled или скрытого skipped workflow. Успешные завершающие cleanup steps не меняют failed conclusion основного workflow.

| Workflow | Conclusion | Attempt | Job |
| --- | --- | --- | --- |
| [Developer runtime qualification](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316637) | success | 1 | [118712556492](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316637/job/118712556492) |
| [Documentation integrity](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316613) | success | 1 | [118712562416](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316613/job/118712562416) |
| [Frozen evasion and domain guard](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316675) | failure | 1 | [118712558080](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316675/job/118712558080) |
| [Frozen poisoning research matrix](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316646) | failure | 1 | [118712558035](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316646/job/118712558035) |
| [Intake evidence contracts](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447322722) | success | 1 | [118712578661](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447322722/job/118712578661) |
| [Kubernetes isolation qualification](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316656) | success | 1 | [118712556260](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316656/job/118712556260) |
| [MLflow tracking compatibility and private service](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447319779) | success | 1 | [118712568358](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447319779/job/118712568358) |
| [Paired robust training research](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447319650) | failure | 1 | [118712568527](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447319650/job/118712568527) |
| [Storage role and TLS qualification](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316658) | success | 1 | [118712556919](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316658/job/118712556919) |
| [Worker and storage image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316663) | failure | 1 | [118712559080](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39447316663/job/118712559080) |

## Сохраняющиеся release blockers

- Image audit: все четыре scanner execution завершены, exit code 2. Baseline worker: 0 Critical / 56 High; storage: 9 / 132. Candidate worker: 0 / 55; candidate storage: 1 / 85. Это реальные policy failures, не отсутствие scanner. Compatibility pass не разрешает adoption небезопасного image.
- Poisoning matrix: execution complete, 35 trainings, 10 violating / 0 inconclusive / 25 nonviolating scenarios. Full M08 inconclusive; failed robustness findings сохраняются.
- Evasion: execution complete, recall drop **0.07183673469387755 > 0.05**, fail.
- Paired robust candidate: recall drops **0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611**, каждый выше 0.05. Не принят как исправление исходной модели.
- Full M13 остаётся inconclusive: production configured()/audit_path lifecycle и 429/503 privacy matrix, real service-log coverage, exact actual/controlled subject composition, отдельная strict public gate projection.
- Full T16/R1/M18 не завершены. Production retention/encryption/backup, multi-node HA и независимость администратора не доказаны.

## Полный synthetic candidate receipt

Ниже сохранён exact report из native stdout с форматированием без изменения numeric lexemes. Это вручную проверенный synthetic qualification artifact, не универсальная public-safe schema для пользовательских данных. Private packet, HTTP IDs, journal records, credentials и private keys сюда не включены. Campaign/subject digests и timestamps относятся только к этому disposable lab run.

<details>
<summary>85 cases и полный native receipt</summary>

```json
{
  "campaign_id": "b7f19968c85a4375beb5cdb1dc6b6747",
  "candidate_reference": "ce949d409b721f346b28cdd96d1b2bccace4ea9c3c9d80ff106959442a00a4de",
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
    "closed-audit-primary-packet-retained",
    "closed-audit-public-export-schema-counters-and-canaries",
    "closed-audit-export-not-release-approval",
    "qualification-authority-and-private-key-removed",
    "source-cas-budget-envelopes-and-checkout-unchanged",
    "full-lifecycle-output-privacy",
    "current-private-receipt-admitted",
    "closed-audit-primary-packet-reverified"
  ],
  "evaluation_reference": "cc5735a3fa1f947ad047fc9e3e45a43ecd2a58ec4c161b81a4760c3a3c4f7415",
  "finished_at": "2026-10-20T15:29:25.995746+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f",
  "proposal_reference": "d818ca014ba9e24ec37c0757143f956066d1d1fa0fd90d37770e6bb83259874f",
  "qualification_permit_sha256": "982fe440d949564d4f0c7d377567ec72ce33af9060eabf92616d9d6d8f61598e",
  "reference_response_sha256": "3c1299b9260845ebfa1520c3df34a04c44af4cd9906437728fef422576ed00d1",
  "release_ready": false,
  "runtime": {
    "audit_evidence": {
      "correlation": {
        "completed_200": 58,
        "correlated_requests": 58,
        "events": 336,
        "failed_after_intent": 0,
        "release_ready": false,
        "schema_version": 1,
        "scope": "candidate-qualification-private-correlation-not-full-M13",
        "status": "pass",
        "without_context": 26
      },
      "observed_responses": 107,
      "packet_sha256": "4f7ff8fdbfcaeb63e783fe2ad5f7e49a5428df189d4dbe592482fd1b7e5a455c",
      "public": {
        "context_kinds": {
          "candidate-qualification": 58,
          "none": 26,
          "release-selection": 0
        },
        "events": 336,
        "release_ready": false,
        "requests": {
          "aborted": 0,
          "completed": 84,
          "unresolved": 0
        },
        "routes": {
          "predict": 79,
          "ready": 5
        },
        "schema_version": 1,
        "scope": "serving-audit-public-window-not-full-M13",
        "status": "pass"
      },
      "release_ready": false,
      "schema_version": 1,
      "scope": "private-primary-audit-packet-not-full-M13",
      "status": "pass"
    },
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
      "window_seconds": 0.0056390019999525975
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
      "events": 336,
      "failed_after_intent": 0,
      "release_ready": false,
      "schema_version": 1,
      "scope": "candidate-qualification-private-correlation-not-full-M13",
      "status": "pass",
      "without_context": 26
    },
    "http_expiring_query": {
      "approval_deadline": 1193.710593700409,
      "denial": {
        "active_observed": {
          "monotonic": 678.746625203,
          "wall": 1792510155.036031
        },
        "connected_read_entered": true,
        "finished_monotonic": 685.313271128,
        "finished_wall": 1792510161.6026778,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 678.639488651,
        "started_wall": 1792510154.9288945
      },
      "expected_trust": {
        "document_sha256": "14671c38fb7a3f0499ad79accaa25f270c4d3d24dfd40d727a38d39619f68305",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 685.5611107349396,
        "document_sha256": "14671c38fb7a3f0499ad79accaa25f270c4d3d24dfd40d727a38d39619f68305",
        "monotonic": 678.572200104,
        "sequence": 51,
        "version": 2,
        "wall": 1792510154.8616061
      },
      "policy_expires_at": 1792510162,
      "policy_expiry_monotonic": 685.7105939388275,
      "post_expiry": {
        "finished_monotonic": 685.762201799,
        "finished_wall": 1792510162.051607,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 685.760696507,
        "started_wall": 1792510162.050102
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 747.744350106,
        "document_sha256": "af6d7157c2425fbbf57b6f4d644ca26395f7ef6cabd0fff280284698ffc68c53",
        "monotonic": 687.754605537,
        "sequence": 56,
        "version": 3,
        "wall": 1792510164.0440116
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "af6d7157c2425fbbf57b6f4d644ca26395f7ef6cabd0fff280284698ffc68c53",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 666.606968718,
          "wall": 1792510142.8963742
        },
        "connected_read_entered": true,
        "finished_monotonic": 676.507799277,
        "finished_wall": 1792510152.7972057,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 666.505142805,
        "started_wall": 1792510142.7945487
      },
      "last_verified": {
        "deadline": 726.427949874,
        "document_sha256": "4f03d9f1a5b13fa74f8f9f807b56eaee0de54fbb0a211d72b56070a700a40ee9",
        "monotonic": 666.439783467,
        "sequence": 43,
        "version": 1,
        "wall": 1792510142.7291894
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 737.902569442,
        "document_sha256": "4f03d9f1a5b13fa74f8f9f807b56eaee0de54fbb0a211d72b56070a700a40ee9",
        "monotonic": 677.914249461,
        "sequence": 49,
        "version": 1,
        "wall": 1792510154.2036555
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
        "failures": [],
        "first_503_seconds": 59.77417316899994,
        "last_200_seconds": 59.721988572999976,
        "observations": 44,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "3cdf864b118290a9cd0af00b6f78ac633665f23ee2538cea81b45bed36443ab2",
        "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f"
      },
      "last_verified": {
        "deadline": 664.810508775,
        "document_sha256": "4f03d9f1a5b13fa74f8f9f807b56eaee0de54fbb0a211d72b56070a700a40ee9",
        "monotonic": 604.820793887,
        "sequence": 36,
        "version": 1,
        "wall": 1792510081.1101997
      },
      "records": [
        {
          "finished_monotonic": 605.335367437,
          "finished_wall": 1792510081.6247742,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 605.313785626,
          "started_wall": 1792510081.6031919,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 607.3571056,
          "finished_wall": 1792510083.646512,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 607.335485597,
          "started_wall": 1792510083.6248918,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 609.378761711,
          "finished_wall": 1792510085.6681683,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 609.357261091,
          "started_wall": 1792510085.6466672,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 611.400237765,
          "finished_wall": 1792510087.6896443,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 611.378901661,
          "started_wall": 1792510087.6683078,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 613.421618679,
          "finished_wall": 1792510089.7110252,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 613.400379035,
          "started_wall": 1792510089.689785,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 615.443482876,
          "finished_wall": 1792510091.7328894,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 615.421769177,
          "started_wall": 1792510091.7111752,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 617.464745348,
          "finished_wall": 1792510093.7541516,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 617.443634114,
          "started_wall": 1792510093.73304,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 619.486060341,
          "finished_wall": 1792510095.775467,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 619.464896479,
          "started_wall": 1792510095.7543025,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 621.507841711,
          "finished_wall": 1792510097.7972484,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 621.486203764,
          "started_wall": 1792510097.77561,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 623.529210128,
          "finished_wall": 1792510099.8186166,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 623.507985404,
          "started_wall": 1792510099.7973917,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 625.551594284,
          "finished_wall": 1792510101.841001,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 625.529355395,
          "started_wall": 1792510101.8187616,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 627.573746101,
          "finished_wall": 1792510103.8631527,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 627.551754983,
          "started_wall": 1792510103.841161,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 629.595661995,
          "finished_wall": 1792510105.8850687,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 629.573883726,
          "started_wall": 1792510105.8632898,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 631.617247889,
          "finished_wall": 1792510107.9066541,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 631.595803664,
          "started_wall": 1792510107.8852098,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 633.639307389,
          "finished_wall": 1792510109.928714,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 633.617380832,
          "started_wall": 1792510109.906787,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 635.661179248,
          "finished_wall": 1792510111.9505858,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 635.639454967,
          "started_wall": 1792510111.9288611,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 637.682856262,
          "finished_wall": 1792510113.9722626,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 637.6613198,
          "started_wall": 1792510113.9507258,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 639.704772331,
          "finished_wall": 1792510115.9941788,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 639.683003836,
          "started_wall": 1792510115.97241,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 641.726232018,
          "finished_wall": 1792510118.0156384,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 641.70489089,
          "started_wall": 1792510117.994297,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 643.747981685,
          "finished_wall": 1792510120.0373883,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 643.726374938,
          "started_wall": 1792510120.0157812,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 645.771142779,
          "finished_wall": 1792510122.0605497,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 645.748151211,
          "started_wall": 1792510122.0375574,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 647.792839884,
          "finished_wall": 1792510124.0822463,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 647.771287759,
          "started_wall": 1792510124.0606937,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.814579308,
          "finished_wall": 1792510126.1039855,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 649.792983401,
          "started_wall": 1792510126.0823896,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 651.837861332,
          "finished_wall": 1792510128.1272678,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 651.814751914,
          "started_wall": 1792510128.104158,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 653.860275756,
          "finished_wall": 1792510130.1496825,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 653.838026345,
          "started_wall": 1792510130.1274323,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 655.884100735,
          "finished_wall": 1792510132.1735077,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 655.860433976,
          "started_wall": 1792510132.14984,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 657.905760088,
          "finished_wall": 1792510134.1951668,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 657.884259895,
          "started_wall": 1792510134.173666,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 659.927349418,
          "finished_wall": 1792510136.2167556,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 659.905901901,
          "started_wall": 1792510136.195308,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 661.948873158,
          "finished_wall": 1792510138.2382796,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 661.927487136,
          "started_wall": 1792510138.2168932,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 663.970076679,
          "finished_wall": 1792510140.259483,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 663.949026375,
          "started_wall": 1792510140.2384324,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.041704398,
          "finished_wall": 1792510140.3311112,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.020189535,
          "started_wall": 1792510140.3095956,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.113294517,
          "finished_wall": 1792510140.402701,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.091851037,
          "started_wall": 1792510140.3812573,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.185418993,
          "finished_wall": 1792510140.4748254,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.163396362,
          "started_wall": 1792510140.4528027,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.256622209,
          "finished_wall": 1792510140.5460286,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.235558439,
          "started_wall": 1792510140.5249646,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.328059132,
          "finished_wall": 1792510140.6174655,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.306760343,
          "started_wall": 1792510140.5961664,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.399997561,
          "finished_wall": 1792510140.689404,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.378169514,
          "started_wall": 1792510140.6675756,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.471254687,
          "finished_wall": 1792510140.760661,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.450129313,
          "started_wall": 1792510140.7395353,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.54278246,
          "finished_wall": 1792510140.832189,
          "http_status": 200,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.521363406,
          "started_wall": 1792510140.8107693,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.594967056,
          "finished_wall": 1792510140.8843734,
          "http_status": 503,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.592895586,
          "started_wall": 1792510140.8823018,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.646742509,
          "finished_wall": 1792510140.936149,
          "http_status": 503,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.645042433,
          "started_wall": 1792510140.9344487,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.698263466,
          "finished_wall": 1792510140.9876697,
          "http_status": 503,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.696830159,
          "started_wall": 1792510140.986236,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.74977741,
          "finished_wall": 1792510141.0391839,
          "http_status": 503,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.748362046,
          "started_wall": 1792510141.0377681,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.801312032,
          "finished_wall": 1792510141.0907185,
          "http_status": 503,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.799871151,
          "started_wall": 1792510141.0892773,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 664.852740226,
          "finished_wall": 1792510141.1421466,
          "http_status": 503,
          "lease_deadline": 664.810508775,
          "response_valid": true,
          "started_monotonic": 664.851404631,
          "started_wall": 1792510141.1408105,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 726.386709551,
        "document_sha256": "4f03d9f1a5b13fa74f8f9f807b56eaee0de54fbb0a211d72b56070a700a40ee9",
        "monotonic": 666.398411457,
        "sequence": 41,
        "version": 1,
        "wall": 1792510142.6878176
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0.0,
    "output_privacy": {
      "canary_count": 6,
      "fd_lifecycle_complete": true,
      "native_stderr_bytes": 0,
      "release_ready": false,
      "schema_version": 1,
      "scope": "serving-lifecycle-output-privacy-not-full-M13",
      "status": "pass",
      "stderr_characters": 0,
      "stdout_characters": 18519
    },
    "public_audit_window": {
      "context_kinds": {
        "candidate-qualification": 58,
        "none": 26,
        "release-selection": 0
      },
      "events": 336,
      "release_ready": false,
      "requests": {
        "aborted": 0,
        "completed": 84,
        "unresolved": 0
      },
      "routes": {
        "predict": 79,
        "ready": 5
      },
      "schema_version": 1,
      "scope": "serving-audit-public-window-not-full-M13",
      "status": "pass"
    },
    "stopped_worker_denial_seconds": 2.0148556319999216
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:a45751b03aeca1572c29192a041543b46e32447f86ae1e8fbd2a029e8aa883f9",
    "source_fingerprint": "35d6bf3594ad182f128a49cb068718379c0f066ed9e1a891f80f02da0ef24c01",
    "source_revision": "a7a09c87fd299620e4753ec76c971ab80df16623"
  },
  "source_dirty": false,
  "started_at": "2026-10-20T15:27:47.981484+00:00",
  "status": "pass",
  "subject_sha256": "3cdf864b118290a9cd0af00b6f78ac633665f23ee2538cea81b45bed36443ab2"
}
```

</details>
