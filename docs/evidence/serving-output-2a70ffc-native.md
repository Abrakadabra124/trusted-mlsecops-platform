# Serving lifecycle output: native 2a70ffc

Дата: 2026-10-20. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit».
[ADR 0047](../decisions/0047-serving-output-observation.md), [история RED/исправлений](serving-output-2026-10-19.md), [RB-66/PB-40](../operations/serving-output-troubleshooting.md), [карта каналов](../privacy-output-map.md).

## Привязка и статус

- Code commit: 2a70ffc0be6d49751ae5fa023be0c384048f9de3, source_dirty=false.
- [Storage workflow](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39430911567), job 118655429156, attempt 1, success. Actual candidate: 82 unique cases, status=pass, release_ready=false, full_M12=inconclusive.
- Source fingerprint: 1da59db725a969c8149b07936c40b1cce76da9b6adc362f3835ffe7f37c82783.
- Serving image: sha256:a97ff6c37f87a4f9e16636f0fc3f491adb93afd9ad10b674c8737e9fc2f70965.
- Actual campaign: 2026-10-20T13:38:12.590890+00:00 -> 2026-10-20T13:39:49.862273+00:00.
- Actual report canonical SHA-256: 83bbb49a289dda49cba5ae9bb0dfa826ce93352c46ab8d62d2b8897702571905.
- Controlled report canonical SHA-256: b02adb6b43b97dc8226b7e48f6de1a7f64c837961b55aa729f91fb421ca1826b.
- Full reports ниже сохранены без округления numeric values. Хеши вычислены через project canonical()/digest(), не по Markdown и не по JSON pretty-print bytes.

Новый observer подтвердил empty native stderr, полное завершение child и 6 private canaries. Python capture: stdout 18213 characters, stderr 0; содержимое capture не опубликовано. Late handler внутри HTTP, atexit, strict whitespace, mutation после serialization и import-boundary negative controls проверены отдельно. Это serving qualification scope, не универсальная защита всех host outputs и не full M13.

## Проверки Linux

- Output/native suites: 19 methods, 0 failures/skips, 5.707 s. Output probe 45 statements / 12 branches, 100%; native CLI 63 statements / 12 branches, mixed 97%, непокрыт standalone __main__.
- Privacy/candidate/output suites: 38 methods, 0 failures/skips, 10.091 s. Privacy probe 200 statements / 90 branches, 100%.
- Controller/lifecycle/transport: 83 methods, 0 failures/skips, 19.595 s. Correlation 64 / 9.002 s; closed export 47 / 0.961 s. Suites пересекаются; не суммировать их как уникальные tests.
- Actual privacy: 12 requests, 36 confirmed durable events, 3 audit files, 69 approved metric samples, ambient signals disabled. Audit pair 8 accepted / 8 durable.
- Actual private correlation: 336 events / 58 correlated HTTP 200 / 26 without context / 0 failed after intent.
- Public window: 336 events / 84 completed / 0 aborted / 0 unresolved, predict 79 / ready 5; candidate contexts 58 / none 26 / release 0. Дополнительный запрос относительно прежней campaign не переписывается в исторические 332 events: counters берутся из текущего отчёта.
- Controlled release: 40 cases; 56 events / 8 correlated HTTP 200 / 6 without context. Отдельные test roots/approval не являются одобрением actual candidate.
- Actual golden parity: 3 rows, maximum error 0; stopped worker denial 2.016079119999972 s.
- Outage: 43 observations; last HTTP 200 59.73918313900003 s, first HTTP 503 59.790949458 s. Полный assess(anchor, records) независимо пересчитан из опубликованного report и совпал с assessment.
- Paused SQL и signed-policy expiry: HTTP 503 при active незавершённом read, generation fenced; post-expiry 503 и recovery после renewal подтверждены полными записями.

## Границы

release_ready остаётся false. Failed image/poisoning/evasion/paired gates не обходятся qualification permit. M13 aggregation пока не подключена; общий T16/R1 не завершён. Forced-stop Docker cleanup на shared/local host не доказан: этот wrapper только disposable hosted CI, timeout/cancellation не разрешает pass и требует disposal job. Native success не устраняет прежний unexplained M07 first-attempt reliability debt.

## Полная CI matrix и сохраняющиеся blockers

Наблюдение завершено 2026-10-20T13:44:35.572Z: все 10 workflows terminal для одного code SHA, **6 success / 4 failure**, все attempt 1. Исправленный код не является rerun первого ff3f25f: история первого отказа и его отдельная matrix сохранены в [журнале](serving-output-2026-10-19.md).

| Workflow | Run | Job | Conclusion | Attempt |
| --- | --- | --- | --- | --- |
| Developer runtime qualification | [39430911790](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39430911790) | 118655430038 | success | 1 |
| Documentation integrity | [39430911312](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39430911312) | 118655427750 | success | 1 |
| Frozen evasion and domain guard | [39430912089](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39430912089) | 118655431230 | failure | 1 |
| Frozen poisoning research matrix | [39430911427](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39430911427) | 118655428476 | failure | 1 |
| Intake evidence contracts | [39430911674](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39430911674) | 118655429111 | success | 1 |
| Kubernetes isolation qualification | [39430911659](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39430911659) | 118655429854 | success | 1 |
| MLflow tracking compatibility and private service | [39430911653](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39430911653) | 118655428626 | success | 1 |
| Paired robust training research | [39430911632](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39430911632) | 118655429887 | failure | 1 |
| Storage role and TLS qualification | [39430911567](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39430911567) | 118655429156 | success | 1 |
| Worker and storage image audit | [39430911999](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39430911999) | 118655430648 | failure | 1 |

Текущие executable gates прочитаны из полных JSON logs и привязаны к 2a70ffc0be6d49751ae5fa023be0c384048f9de3:

| Gate | Status | Cases | Finished UTC |
| --- | --- | --- | --- |
| M03 | pass | 431 | 2026-10-20T13:33:19.419785+00:00 |
| M06 | pass | 18 | 2026-10-20T13:37:22.374149+00:00 |
| M07 | pass | 97 | 2026-10-20T13:34:43.009150+00:00 |
| M20 | pass | 725 | 2026-10-20T13:41:59.158680+00:00 |
| M21 | pass | 122 | 2026-10-20T13:43:50.173765+00:00 |

Current image audit реально выполнил scan всех четырёх images, SBOM validated=true, scan_executed=true, scanner exit=2. Severity matches: baseline worker 0 Critical / 56 High; baseline storage 9 / 132; candidate worker 0 / 55; candidate storage 1 / 85. Это findings scanner, не доказательство exploitability каждого match; policy по-прежнему блокирует adoption/release.

Poisoning: 35 training runs, 10 violating / 0 inconclusive / 25 nonviolating scenarios. Evasion recall drop 0.07183673469387755 при maximum 0.05. Paired candidate drops: 0.052244897959183675, 0.06224066390041494, 0.06143344709897611 на трёх frozen probes, все выше 0.05. Эти failures содержат реальные завершённые measurements, не skipped commands. Upstream ML policy и benchmark не менялись.

## Полный actual-candidate report

```json
{
  "campaign_id": "cb75a49040b145918b52f06305beb9f5",
  "candidate_reference": "18082a89f0a9c955798ec6920d9cc3612302966b6f64036d781b5729af87e27a",
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
    "source-cas-budget-envelopes-and-checkout-unchanged",
    "full-lifecycle-output-privacy"
  ],
  "evaluation_reference": "5df3162c43e8dc30bba097bada323d2dcef3e4541997d00729702015d9f4543e",
  "finished_at": "2026-10-20T13:39:49.862273+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f",
  "proposal_reference": "2771bbd86828dc6fd8236f11dde9853966d9aa448c56d92b81411fa85200676c",
  "qualification_permit_sha256": "8526e95723363f2eafc2b7a4bec990a13928e5ba7666fae00ec0e1a53a92b9cd",
  "reference_response_sha256": "73d33095617852d431062f970e6fb40365fb983a10b00ce2db7329703dcdfc24",
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
      "window_seconds": 0.005944762000012815
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
      "approval_deadline": 1179.1940295696259,
      "denial": {
        "active_observed": {
          "monotonic": 663.546890881,
          "wall": 1792503579.3528607
        },
        "connected_read_entered": true,
        "finished_monotonic": 669.132114741,
        "finished_wall": 1792503584.9380856,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 663.450330185,
        "started_wall": 1792503579.2563
      },
      "expected_trust": {
        "document_sha256": "e821b2506a009ad06cfc1a6bc0e31d951f2fded12321ee32ac772b4cfe0e9920",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 669.380542755127,
        "document_sha256": "e821b2506a009ad06cfc1a6bc0e31d951f2fded12321ee32ac772b4cfe0e9920",
        "monotonic": 663.39124086,
        "sequence": 51,
        "version": 2,
        "wall": 1792503579.1972108
      },
      "policy_expires_at": 1792503586,
      "policy_expiry_monotonic": 670.194030046463,
      "post_expiry": {
        "finished_monotonic": 670.245662512,
        "finished_wall": 1792503586.051632,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 670.244155007,
        "started_wall": 1792503586.050125
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 732.148539257,
        "document_sha256": "06a97fd170c38985c8dfb80e829318a7b6308965f435498622b0849e7ecd3e15",
        "monotonic": 672.159119788,
        "sequence": 56,
        "version": 3,
        "wall": 1792503587.9650898
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "06a97fd170c38985c8dfb80e829318a7b6308965f435498622b0849e7ecd3e15",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 651.55666511,
          "wall": 1792503567.3626347
        },
        "connected_read_entered": true,
        "finished_monotonic": 661.466811362,
        "finished_wall": 1792503577.272782,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 651.464627388,
        "started_wall": 1792503567.2705972
      },
      "last_verified": {
        "deadline": 711.396876447,
        "document_sha256": "e197849b5410d8a3a435a2777d6fc4ec6e175e20ddaf132f93cc8a7cd97ff210",
        "monotonic": 651.407385345,
        "sequence": 43,
        "version": 1,
        "wall": 1792503567.2133555
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 722.773803137,
        "document_sha256": "e197849b5410d8a3a435a2777d6fc4ec6e175e20ddaf132f93cc8a7cd97ff210",
        "monotonic": 662.78460827,
        "sequence": 49,
        "version": 1,
        "wall": 1792503578.5905783
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
        "first_503_seconds": 59.790949458,
        "last_200_seconds": 59.73918313900003,
        "observations": 43,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "d77a2267ff70b451ca9006b9596711637cb8f4a024906bc68852bd4a76d3f7b0",
        "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f"
      },
      "last_verified": {
        "deadline": 649.857196525,
        "document_sha256": "e197849b5410d8a3a435a2777d6fc4ec6e175e20ddaf132f93cc8a7cd97ff210",
        "monotonic": 589.868428722,
        "sequence": 36,
        "version": 1,
        "wall": 1792503505.6743987
      },
      "records": [
        {
          "finished_monotonic": 590.39538846,
          "finished_wall": 1792503506.2013593,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 590.373479052,
          "started_wall": 1792503506.179449,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 592.417864087,
          "finished_wall": 1792503508.2238345,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 592.395555477,
          "started_wall": 1792503508.2015254,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 594.440583258,
          "finished_wall": 1792503510.2465541,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 594.418060901,
          "started_wall": 1792503510.224031,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 596.462467415,
          "finished_wall": 1792503512.268438,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 596.440751377,
          "started_wall": 1792503512.2467215,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 598.484564316,
          "finished_wall": 1792503514.290535,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 598.462616739,
          "started_wall": 1792503514.2685866,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 600.506668175,
          "finished_wall": 1792503516.3126388,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 600.484705784,
          "started_wall": 1792503516.2906759,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 602.528405395,
          "finished_wall": 1792503518.3343759,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 602.506814285,
          "started_wall": 1792503518.3127844,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 604.549904267,
          "finished_wall": 1792503520.3558748,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 604.528544519,
          "started_wall": 1792503520.3345146,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 606.571817487,
          "finished_wall": 1792503522.3777878,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 606.550043673,
          "started_wall": 1792503522.3560138,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 608.594162942,
          "finished_wall": 1792503524.4001336,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 608.571960482,
          "started_wall": 1792503524.3779304,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 610.615967602,
          "finished_wall": 1792503526.4219387,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 610.594323299,
          "started_wall": 1792503526.4002934,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 612.638388197,
          "finished_wall": 1792503528.4443588,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 612.616126206,
          "started_wall": 1792503528.4220965,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 614.659991627,
          "finished_wall": 1792503530.4659622,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 614.638532968,
          "started_wall": 1792503530.444503,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 616.681585155,
          "finished_wall": 1792503532.4875555,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 616.660153952,
          "started_wall": 1792503532.466124,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 618.703270691,
          "finished_wall": 1792503534.509241,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 618.681728665,
          "started_wall": 1792503534.4876988,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 620.724978042,
          "finished_wall": 1792503536.5309486,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 620.703440637,
          "started_wall": 1792503536.5094109,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 622.747348268,
          "finished_wall": 1792503538.5533192,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 622.725161013,
          "started_wall": 1792503538.531131,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 624.771040352,
          "finished_wall": 1792503540.5770109,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 624.747498325,
          "started_wall": 1792503540.5534685,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 626.793061286,
          "finished_wall": 1792503542.5990322,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 626.771204812,
          "started_wall": 1792503542.5771751,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 628.81511881,
          "finished_wall": 1792503544.6210892,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 628.793210435,
          "started_wall": 1792503544.5991805,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 630.837579401,
          "finished_wall": 1792503546.64355,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 630.815265433,
          "started_wall": 1792503546.6212354,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 632.860295838,
          "finished_wall": 1792503548.6662664,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 632.83773485,
          "started_wall": 1792503548.643705,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 634.882301725,
          "finished_wall": 1792503550.6882722,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 634.860440178,
          "started_wall": 1792503550.6664102,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 636.904178084,
          "finished_wall": 1792503552.7101486,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 636.882431718,
          "started_wall": 1792503552.688402,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 638.926380621,
          "finished_wall": 1792503554.7323513,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 638.904314399,
          "started_wall": 1792503554.7102845,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 640.948281724,
          "finished_wall": 1792503556.7542522,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 640.926516076,
          "started_wall": 1792503556.7324862,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 642.969534282,
          "finished_wall": 1792503558.7755046,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 642.948400159,
          "started_wall": 1792503558.7543702,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 644.99064195,
          "finished_wall": 1792503560.7966123,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 644.969663569,
          "started_wall": 1792503560.7756336,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 647.012217412,
          "finished_wall": 1792503562.8181877,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 646.990777862,
          "started_wall": 1792503562.796748,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.033893838,
          "finished_wall": 1792503564.8398643,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.012379945,
          "started_wall": 1792503564.81835,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.105595588,
          "finished_wall": 1792503564.911566,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.084044726,
          "started_wall": 1792503564.890015,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.177577592,
          "finished_wall": 1792503564.983548,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.155738962,
          "started_wall": 1792503564.961709,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.250073909,
          "finished_wall": 1792503565.0560446,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.227719743,
          "started_wall": 1792503565.0336897,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.321357351,
          "finished_wall": 1792503565.1273277,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.300203757,
          "started_wall": 1792503565.106174,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.392582564,
          "finished_wall": 1792503565.198553,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.371465428,
          "started_wall": 1792503565.1774356,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.464430736,
          "finished_wall": 1792503565.2704012,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.442723883,
          "started_wall": 1792503565.248694,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.536197216,
          "finished_wall": 1792503565.3421679,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.514589348,
          "started_wall": 1792503565.3205593,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.607611861,
          "finished_wall": 1792503565.4135823,
          "http_status": 200,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.58634621,
          "started_wall": 1792503565.3923163,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.65937818,
          "finished_wall": 1792503565.4653487,
          "http_status": 503,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.657755895,
          "started_wall": 1792503565.463726,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.711125996,
          "finished_wall": 1792503565.5170965,
          "http_status": 503,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.709487889,
          "started_wall": 1792503565.515458,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.762451818,
          "finished_wall": 1792503565.568422,
          "http_status": 503,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.761217623,
          "started_wall": 1792503565.5671878,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.813783791,
          "finished_wall": 1792503565.6197543,
          "http_status": 503,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.812542653,
          "started_wall": 1792503565.6185126,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 649.864932845,
          "finished_wall": 1792503565.6709032,
          "http_status": 503,
          "lease_deadline": 649.857196525,
          "response_valid": true,
          "started_monotonic": 649.863869387,
          "started_wall": 1792503565.6698396,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 711.358200164,
        "document_sha256": "e197849b5410d8a3a435a2777d6fc4ec6e175e20ddaf132f93cc8a7cd97ff210",
        "monotonic": 651.368393033,
        "sequence": 41,
        "version": 1,
        "wall": 1792503567.1743631
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
      "stdout_characters": 18213
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
    "stopped_worker_denial_seconds": 2.016079119999972
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:a97ff6c37f87a4f9e16636f0fc3f491adb93afd9ad10b674c8737e9fc2f70965",
    "source_fingerprint": "1da59db725a969c8149b07936c40b1cce76da9b6adc362f3835ffe7f37c82783",
    "source_revision": "2a70ffc0be6d49751ae5fa023be0c384048f9de3"
  },
  "source_dirty": false,
  "started_at": "2026-10-20T13:38:12.590890+00:00",
  "status": "pass",
  "subject_sha256": "d77a2267ff70b451ca9006b9596711637cb8f4a024906bc68852bd4a76d3f7b0"
}
```

## Полный controlled-release report

```json
{
  "campaign_id": "7db1a4c0548b4edf9c02d14849f7b86f",
  "cases": 40,
  "finished_at": "2026-10-20T13:37:55.300161+00:00",
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
      "window_seconds": 0.006571765999979107
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
    "stopped_worker_denial_seconds": 2.028421299999991
  },
  "schema_version": 1,
  "scope": "serving-HTTP-ONNX-TLS-controlled-fixture-not-full-M12",
  "source_dirty": false,
  "source_fingerprint": "1da59db725a969c8149b07936c40b1cce76da9b6adc362f3835ffe7f37c82783",
  "source_revision": "2a70ffc0be6d49751ae5fa023be0c384048f9de3",
  "started_at": "2026-10-20T13:37:35.226947+00:00",
  "status": "pass"
}
```
