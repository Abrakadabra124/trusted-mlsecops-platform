# T16: fresh private receipt, native b0df48e

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Дата: 2026-10-20.
**Native increment verified; полный M13/T16/R1 не принят.**
[ADR 0048](../decisions/0048-privacy-acceptance.md), [local RED/coverage/review](privacy-evidence-2026-10-20.md), [RB-67/PB-41](../operations/privacy-evidence-troubleshooting.md).

## Источник и границы

- Code commit: [b0df48eaff1eceab087a6d4957df4e685d93a014](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/b0df48eaff1eceab087a6d4957df4e685d93a014).
- Clean source fingerprint: `75525082be610731f763ca935b01c9c563b53204653169a757ad48c42e338038`.
- Actual serving image: `sha256:87631fdacd06afba63ad797aa224cd68f73f05349bb0047dc80ffd7b43f41726`.
- Actual campaign: `2e098d31c4cd46d08d82d9358364c3a2`; 2026-10-20T14:31:45.369238+00:00 -> 2026-10-20T14:33:22.680471+00:00.
- [Storage job 118682909190](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39438815747/job/118682909190), ubuntu-24.04 disposable GitHub-hosted VM, attempt 1, terminal success.
- Локальные Docker/WSL/Kubernetes/SQL не запускались. Native результат получен существующим CI workflow, а не Windows mock.
- Все публикуемые материалы здесь относятся только к synthetic lab. Полный native receipt содержит private-graph references; его нельзя считать безопасным public export настоящих данных.

## Проверенный результат

Parent заново загрузил primary signed proposal через serving storage client, выполнил existing signature/material/source/image/expiry verification до запуска child, а затем проверил fresh byte-bound receipt после полного FD exit и повторной source проверки. **83 уникальных case IDs**, включая ровно один parent-only `current-private-receipt-admitted`. `release_ready=false`, `full_M12=inconclusive`.

Linux contracts: **14 privacy-evidence methods / 0 skips / 0.035 s**, 89 statements / 34 branches / **100%**. Output/native suites: **22 methods / 0 skips / 7.796 s**, existing output probe 100%, parent 98% (не исполнен только `__main__`). Privacy HTTP suite 38 methods / 0 skips / 9.816 s; correlation 64 / 0 skips / 8.929 s. Полные логи job не содержат skipped test outcome.

| Наблюдение | Результат |
| --- | --- |
| Private audit | 340 events, 58 correlated HTTP 200, 27 without context, failed-after-intent 0 |
| Public closed window | 85 completed, 0 aborted, 0 unresolved; predict 80, ready 5; release-selection 0 |
| Privacy matrix | 12 requests, 36 durable events, 3 owned files, 69 approved metric series, ambient signals false |
| Output observer | 6 canaries, complete child FD lifecycle, native stderr 0 bytes; Python stdout 18440 chars, stderr 0 |
| Audit pair | accepted 8 / durable 8 |
| Per-client quota | 422/429/422/429; refill 200/200; admitted deltas 2/2/4 |
| Golden inference | 3 rows, maximum error 0 |
| Stopped worker | verified HTTP denial after 2.015444953000042 s |
| Trust outage | 44 observations; last 200 at 59.683576571 s, first 503 at 59.74195423699996 s |
| Paused / expired SQL read | 503 while query active and unfinished, generation fenced; post-expiry 503, recovery verified |

Outage assessment независимо пересчитан из опубликованных anchor/records через существующий `assess` и совпал с report. Количество requests выросло с 84 в предыдущем increment до 85 из-за наблюдаемого polling; checker не фиксирует исторический итог, а проверяет равенства и минимумы непересекающихся фаз.

Post-run consistency check сопоставил source/proposal/subject/model с отдельно опубликованным upstream proposal receipt и повторил schema/accounting validation. Candidate/evaluation refs для этого дополнительного локального прогона взяты из native report, поэтому сам по себе он **не доказывает независимость пяти bindings**. Первичная проверка всех пяти выполнялась parent в native CI и отдельно проверена real-signature negative tests.

Canonical SHA-256 полного actual report: `55fbde41df1370aeff1f817959d3d8d4af0cb0dfe0693fd4d0fe873ecc532390`.
Canonical SHA-256 controlled receipt: `48124752f8eb0e753445d507759e352a49f8bc215b0aabfd7ad0df20f1ae436b`.
Digest вычислен Python `canonical(decode(...))`; JSON ниже сохраняет числовые lexemes исходного receipt.

## Все terminal CI outcomes

Наблюдение всех десяти terminal workflows завершено 2026-10-20T14:39:15.9035958Z. **6 success / 4 failure, все attempt 1**, rerun/cancel не выполнялись.

| Workflow | Run / job | Attempt | Conclusion |
| --- | --- | --- | --- |
| Developer runtime qualification | [39438815736](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39438815736/job/118682903099) | 1 | success |
| Documentation integrity | [39438815408](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39438815408/job/118682901263) | 1 | success |
| Frozen evasion and domain guard | [39438815821](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39438815821/job/118682903990) | 1 | failure |
| Frozen poisoning research matrix | [39438815582](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39438815582/job/118682902264) | 1 | failure |
| Intake evidence contracts | [39438815652](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39438815652/job/118682901936) | 1 | success |
| Kubernetes isolation qualification | [39438815497](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39438815497/job/118682901140) | 1 | success |
| MLflow tracking compatibility and private service | [39438815734](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39438815734/job/118682902568) | 1 | success |
| Paired robust training research | [39438815639](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39438815639/job/118682902481) | 1 | failure |
| Storage role and TLS qualification | [39438815747](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39438815747/job/118682909190) | 1 | success |
| Worker and storage image audit | [39438815575](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39438815575/job/118682902707) | 1 | failure |

Current-SHA regression: M03 **431** pass, M07 **97** pass, M06 **18** pass, M20 **725** pass, M21 **122** pass, scoped controller **139** pass. Это отдельные gates/components, не общий M18 release. Finish UTC: M03 14:26:58.852842; M07 14:28:20.221243; M06 14:31:30.164154; M20 14:36:45.617241; M21 14:38:46.525553.

### Отказы, которые не скрыты

- Image audit: все четыре SBOM и scans реально выполнены, scanner exit 2. Worker 0 Critical / 56 High; storage 9 / 132; worker candidate 0 / 55; storage candidate 1 / 85. Совместимость candidate image не разрешает adoption при этих failures.
- Poisoning: 35 trainings (30 poisoned + 5 controls), 10 violating / 25 nonviolating / 0 inconclusive. Thresholds не изменялись.
- Evasion: recall drop 0.07183673469387755 при maximum 0.05.
- Paired robust candidate: drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611, каждый выше 0.05.
- Исторический intermittent M07 connection failure из f0d0542 остаётся reliability debt. Успех текущего запуска не устанавливает и не устраняет его причину.

## Что ещё не доказано

M13 dispatch остаётся inconclusive, что проверено executable contract test. Обязательны exact retained private audit snapshots с HTTP linkage, privacy production configuration/lifecycle включая 429/503, реальные service-log observations, корректная composition actual/controlled subjects и отдельная strict public projection. Старый controlled production Reader receipt имеет другой model subject и не является actual approval.

Hosted environment guard не является attestation. Forced-stop nested Docker cleanup на shared/local host не квалифицирована. Не заявляются differential privacy, устранение membership inference, production readiness или полная privacy на основе согласованных counters.

## Полный actual candidate report

```json
{
  "campaign_id": "2e098d31c4cd46d08d82d9358364c3a2",
  "candidate_reference": "52b7c70847f04ea488e2d5fb78f3f149e956cbf9727ea0082f31cbd31953cd24",
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
    "full-lifecycle-output-privacy",
    "current-private-receipt-admitted"
  ],
  "evaluation_reference": "fa1e8501be0b50b2d24831fbc1dae7dfb4cfb0c552adf016c89b32871613d4e8",
  "finished_at": "2026-10-20T14:33:22.680471+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f",
  "proposal_reference": "0b9d8c67c9ec02ff0dfe3fff587f697a3313ec0adc489a48bda23cd31e0324cc",
  "qualification_permit_sha256": "1da344815043082921f23c4255edb559302285067f7ee795a35faed3f4161207",
  "reference_response_sha256": "2dc021df8f3a3a994256f4b6ff39b532c5d97b87b5dc1d156ca574822cbf86b8",
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
      "window_seconds": 0.005695371999991039
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
      "events": 340,
      "failed_after_intent": 0,
      "release_ready": false,
      "schema_version": 1,
      "scope": "candidate-qualification-private-correlation-not-full-M13",
      "status": "pass",
      "without_context": 27
    },
    "http_expiring_query": {
      "approval_deadline": 1109.06711935997,
      "denial": {
        "active_observed": {
          "monotonic": 593.624942061,
          "wall": 1792506791.557822
        },
        "connected_read_entered": true,
        "finished_monotonic": 600.219370084,
        "finished_wall": 1792506798.1522508,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 593.53831103,
        "started_wall": 1792506791.4711914
      },
      "expected_trust": {
        "document_sha256": "d63e8d29ca51b77a8040f1804d5a294c67cc82ae1e34c39e3524da86df4451cb",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 600.4682283401489,
        "document_sha256": "d63e8d29ca51b77a8040f1804d5a294c67cc82ae1e34c39e3524da86df4451cb",
        "monotonic": 593.479252564,
        "sequence": 51,
        "version": 2,
        "wall": 1792506791.412133
      },
      "policy_expires_at": 1792506799,
      "policy_expiry_monotonic": 601.0671195983887,
      "post_expiry": {
        "finished_monotonic": 601.118630167,
        "finished_wall": 1792506799.0515103,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 601.117228631,
        "started_wall": 1792506799.0501087
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 662.954178875,
        "document_sha256": "0d94234e9182139274f122900cbd890b85b324577cac25324efd350562d6ef54",
        "monotonic": 602.964176639,
        "sequence": 56,
        "version": 3,
        "wall": 1792506800.897057
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "0d94234e9182139274f122900cbd890b85b324577cac25324efd350562d6ef54",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 581.672059678,
          "wall": 1792506779.6049397
        },
        "connected_read_entered": true,
        "finished_monotonic": 591.588063951,
        "finished_wall": 1792506789.5209453,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 581.5854294,
        "started_wall": 1792506779.5183094
      },
      "last_verified": {
        "deadline": 641.519783191,
        "document_sha256": "655be736c929431b9924ab5c223dc56b7e071bd957683235bf53a4e4abca5fc8",
        "monotonic": 581.529629887,
        "sequence": 43,
        "version": 1,
        "wall": 1792506779.4625103
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 652.873672522,
        "document_sha256": "655be736c929431b9924ab5c223dc56b7e071bd957683235bf53a4e4abca5fc8",
        "monotonic": 592.884596288,
        "sequence": 49,
        "version": 1,
        "wall": 1792506790.8174765
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
        "first_503_seconds": 59.74195423699996,
        "last_200_seconds": 59.683576571,
        "observations": 44,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "c27838b188cfa9362babdbc5c8c8ce52a4a59ee608b8def6901a570e57d2241c",
        "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f"
      },
      "last_verified": {
        "deadline": 580.020909813,
        "document_sha256": "655be736c929431b9924ab5c223dc56b7e071bd957683235bf53a4e4abca5fc8",
        "monotonic": 520.030479766,
        "sequence": 36,
        "version": 1,
        "wall": 1792506717.96336
      },
      "records": [
        {
          "finished_monotonic": 520.507563919,
          "finished_wall": 1792506718.4404447,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 520.486095484,
          "started_wall": 1792506718.4189758,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 522.529166308,
          "finished_wall": 1792506720.4620473,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 522.507705389,
          "started_wall": 1792506720.4405856,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 524.550792415,
          "finished_wall": 1792506722.483673,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 524.529307043,
          "started_wall": 1792506722.4621875,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 526.573129269,
          "finished_wall": 1792506724.50601,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 526.550923518,
          "started_wall": 1792506724.483804,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 528.595998049,
          "finished_wall": 1792506726.528879,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 528.573277654,
          "started_wall": 1792506726.506158,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 530.617769812,
          "finished_wall": 1792506728.5506504,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 530.5961692,
          "started_wall": 1792506728.5290496,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 532.63919359,
          "finished_wall": 1792506730.5720742,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 532.617890236,
          "started_wall": 1792506730.5507708,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 534.661297892,
          "finished_wall": 1792506732.5941787,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 534.639326902,
          "started_wall": 1792506732.5722075,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 536.683549858,
          "finished_wall": 1792506734.6164305,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 536.661434016,
          "started_wall": 1792506734.5943143,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 538.705785311,
          "finished_wall": 1792506736.638666,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 538.683653841,
          "started_wall": 1792506736.6165342,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 540.727179341,
          "finished_wall": 1792506738.66006,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 540.705915959,
          "started_wall": 1792506738.6387963,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 542.748949802,
          "finished_wall": 1792506740.6818306,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 542.727281628,
          "started_wall": 1792506740.660162,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 544.770553004,
          "finished_wall": 1792506742.7034338,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 544.749096122,
          "started_wall": 1792506742.6819766,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 546.792356394,
          "finished_wall": 1792506744.7252371,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 546.770709007,
          "started_wall": 1792506744.7035894,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 548.814730875,
          "finished_wall": 1792506746.7476113,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 548.792490547,
          "started_wall": 1792506746.725371,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 550.836540924,
          "finished_wall": 1792506748.7694218,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 550.814863948,
          "started_wall": 1792506748.7477443,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 552.858569782,
          "finished_wall": 1792506750.7914507,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 552.836677585,
          "started_wall": 1792506750.769558,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.88140859,
          "finished_wall": 1792506752.814289,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 554.858706151,
          "started_wall": 1792506752.7915866,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 556.903390965,
          "finished_wall": 1792506754.8362715,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 556.881549222,
          "started_wall": 1792506754.8144298,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 558.924882643,
          "finished_wall": 1792506756.8577635,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 558.903514163,
          "started_wall": 1792506756.8363945,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 560.946676923,
          "finished_wall": 1792506758.8795576,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 560.92502849,
          "started_wall": 1792506758.8579087,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 562.968325606,
          "finished_wall": 1792506760.9012063,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 562.94681562,
          "started_wall": 1792506760.879696,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 564.990411369,
          "finished_wall": 1792506762.9232922,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 564.968472755,
          "started_wall": 1792506762.9013531,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 567.012001066,
          "finished_wall": 1792506764.9448817,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 566.990542317,
          "started_wall": 1792506764.9234228,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 569.033747539,
          "finished_wall": 1792506766.9666283,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 569.012180138,
          "started_wall": 1792506766.9450605,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 571.055489997,
          "finished_wall": 1792506768.9883707,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 571.033896787,
          "started_wall": 1792506768.966777,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 573.078945607,
          "finished_wall": 1792506771.0118268,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 573.055670668,
          "started_wall": 1792506770.988551,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 575.101146613,
          "finished_wall": 1792506773.0340278,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 575.079143588,
          "started_wall": 1792506773.0120242,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 577.12325628,
          "finished_wall": 1792506775.0561368,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 577.101283609,
          "started_wall": 1792506775.034164,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.145039334,
          "finished_wall": 1792506777.07792,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.123402244,
          "started_wall": 1792506777.0562825,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.215810616,
          "finished_wall": 1792506777.1486912,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.195174222,
          "started_wall": 1792506777.1280546,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.286246492,
          "finished_wall": 1792506777.219127,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.265945694,
          "started_wall": 1792506777.198826,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.357417573,
          "finished_wall": 1792506777.2902982,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.33638127,
          "started_wall": 1792506777.2692616,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.428599381,
          "finished_wall": 1792506777.36148,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.407555537,
          "started_wall": 1792506777.340436,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.500674557,
          "finished_wall": 1792506777.4335554,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.478756842,
          "started_wall": 1792506777.4116373,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.572294393,
          "finished_wall": 1792506777.5051754,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.550813803,
          "started_wall": 1792506777.483694,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.642835819,
          "finished_wall": 1792506777.5757165,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.622421658,
          "started_wall": 1792506777.555302,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.714056337,
          "finished_wall": 1792506777.6469371,
          "http_status": 200,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.692965974,
          "started_wall": 1792506777.6258464,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.772434003,
          "finished_wall": 1792506777.7053146,
          "http_status": 503,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.764205517,
          "started_wall": 1792506777.6970859,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.828099591,
          "finished_wall": 1792506777.7609801,
          "http_status": 503,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.825888975,
          "started_wall": 1792506777.7587695,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.879477955,
          "finished_wall": 1792506777.8123586,
          "http_status": 503,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.878217943,
          "started_wall": 1792506777.8110983,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.930939774,
          "finished_wall": 1792506777.8638203,
          "http_status": 503,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.929563897,
          "started_wall": 1792506777.8624444,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.982208956,
          "finished_wall": 1792506777.9150896,
          "http_status": 503,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 579.981028412,
          "started_wall": 1792506777.9139087,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 580.03336225,
          "finished_wall": 1792506777.9662428,
          "http_status": 503,
          "lease_deadline": 580.020909813,
          "response_valid": true,
          "started_monotonic": 580.032293616,
          "started_wall": 1792506777.965174,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 641.481405376,
        "document_sha256": "655be736c929431b9924ab5c223dc56b7e071bd957683235bf53a4e4abca5fc8",
        "monotonic": 581.491383903,
        "sequence": 41,
        "version": 1,
        "wall": 1792506779.4242642
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
      "stdout_characters": 18440
    },
    "public_audit_window": {
      "context_kinds": {
        "candidate-qualification": 58,
        "none": 27,
        "release-selection": 0
      },
      "events": 340,
      "release_ready": false,
      "requests": {
        "aborted": 0,
        "completed": 85,
        "unresolved": 0
      },
      "routes": {
        "predict": 80,
        "ready": 5
      },
      "schema_version": 1,
      "scope": "serving-audit-public-window-not-full-M13",
      "status": "pass"
    },
    "stopped_worker_denial_seconds": 2.015444953000042
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:87631fdacd06afba63ad797aa224cd68f73f05349bb0047dc80ffd7b43f41726",
    "source_fingerprint": "75525082be610731f763ca935b01c9c563b53204653169a757ad48c42e338038",
    "source_revision": "b0df48eaff1eceab087a6d4957df4e685d93a014"
  },
  "source_dirty": false,
  "started_at": "2026-10-20T14:31:45.369238+00:00",
  "status": "pass",
  "subject_sha256": "c27838b188cfa9362babdbc5c8c8ce52a4a59ee608b8def6901a570e57d2241c"
}
```

## Upstream proposal receipt

Это опубликованный metadata receipt, не сам private signed package. Его signature verification выполняется при storage load/bind в parent, а не путём доверия этому JSON.

```json
{
  "campaign_id": "e9a9ae90861a4e3fa587ba8157f2ca53",
  "cases": 12,
  "documents": 9,
  "finished_at": "2026-10-20T14:27:08.063511+00:00",
  "full_M10": "inconclusive",
  "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f",
  "objects": 20,
  "policy_sha256": "cbd80b1497db20f0403f8eff370ed83233832a731c2568dff9c4551539bb113b",
  "proposal_reference": "0b9d8c67c9ec02ff0dfe3fff587f697a3313ec0adc489a48bda23cd31e0324cc",
  "release_ready": false,
  "runner_digest": "1be5ade67d79b1830c969e4687d76bdc5e93dbb675f749d43a02f3d1aa31cebb",
  "scope": "release-proposal-and-authorization-denial-not-full-M10",
  "source": {
    "image_id": "sha256:87631fdacd06afba63ad797aa224cd68f73f05349bb0047dc80ffd7b43f41726",
    "source_fingerprint": "75525082be610731f763ca935b01c9c563b53204653169a757ad48c42e338038",
    "source_revision": "b0df48eaff1eceab087a6d4957df4e685d93a014"
  },
  "source_dirty": false,
  "started_at": "2026-10-20T14:27:06.536176+00:00",
  "status": "pass",
  "subject_sha256": "c27838b188cfa9362babdbc5c8c8ce52a4a59ee608b8def6901a570e57d2241c"
}
```

## Controlled production-reader receipt

Полный опубликованный stdout receipt отдельной controlled campaign. Existing CLI заменяет список cases числом 40; это не сохранённые case IDs и не независимое доказательство полноты M13. Private state report содержит список, но он не был извлечён и не выдаётся за опубликованный здесь. Controlled fixture не разрешает actual release.

```json
{
  "campaign_id": "6b670ec9afa64f0f9451cce9c1905bb5",
  "cases": 40,
  "finished_at": "2026-10-20T14:31:28.012228+00:00",
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
      "window_seconds": 0.005361660000005486
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
    "stopped_worker_denial_seconds": 2.024868475000005
  },
  "schema_version": 1,
  "scope": "serving-HTTP-ONNX-TLS-controlled-fixture-not-full-M12",
  "source_dirty": false,
  "source_fingerprint": "75525082be610731f763ca935b01c9c563b53204653169a757ad48c42e338038",
  "source_revision": "b0df48eaff1eceab087a6d4957df4e685d93a014",
  "started_at": "2026-10-20T14:31:08.667987+00:00",
  "status": "pass"
}
```

