# T16 public audit export: native f0d0542

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Проверяемый code commit: [`f0d054275ae095ec90c4eb41b323d7533d2b17db`](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/f0d054275ae095ec90c4eb41b323d7533d2b17db). [Общий evidence](audit-export-2026-10-19.md), [ADR 0045](../decisions/0045-public-audit-export.md), [RB-64/PB-38](../operations/audit-export-troubleshooting.md).

## Итог и provenance

- Все **10 workflows terminal** на 2026-10-19T19:38:09Z: **6 success / 4 failure** по последним attempts. Storage attempt 2; первая попытка failed, не удалена и разобрана ниже. Это 10 workflows, не утверждение о 10 успешных запусках.
- Source fingerprint: `cc8f80a19f5cea70e0fb8b563dcb2516ce587c9127445f10b0caa6287cd2fab2`.
- Serving image: `sha256:12df49e8c6d8b1a7301343f4a8966c8f6f456cee6798f5a9be6c7cf328148492`; controller image: `sha256:fa0e3f0d49b8434b42f76806e61b406f5b3a2f8b99d9a062cca52b43324da597`. Отдельные builds одного source fingerprint, не обещание bit-identical images.
- Candidate завершён 2026-10-19T19:36:25.198922+00:00, **80 уникальных cases pass**, source_dirty=false, release_ready=false.
- Canonical SHA-256 полного candidate report: `9fe4434e3acde1cf45cad897457e42894890b1e3465dfe8242a87b826f505d7b`. JSON ниже сохраняет исходные числовые значения; hash пересчитан Python canonical serializer.
- M03 **431**, M07 **97**, M06 **18**, M20 **725**, M21 **122** cases pass. M20 finished 2026-10-19T19:34:48.932753+00:00; M21 finished 2026-10-19T19:37:06.815869+00:00. Отдельные gates/fixtures, не единая R1-приёмка.
- Полные M13/T16/R1, all-output privacy и private source/run/report/approval/release/request correlation остаются открытыми.

## Native компонент

Новый suite **46 tests / 0 skips** прошёл дважды: attempt 1 за **0.860 s**, attempt 2 за **0.920 s**. Это реальные Linux owned filesystem/CLI/loopback checks, не Windows mocks вместо native. Guard readback выполнялся в отдельном child; parent runner не менял свои kernel limits.

| Модуль | Statements | Missing | Branch exits | Partial | Mixed Cover |
| --- | ---: | ---: | ---: | ---: | ---: |
| mlsecops.audit_export | 96 | 1 | 40 | 1 | 99% |
| mlsecops.audit_snapshot | 130 | 0 | 50 | 1 | 99% |
| scripts.audit_export_probe | 46 | 0 | 20 | 0 | 100% |

Пороги CI **95/95/100** сохранены. Mixed Cover не называется отдельным branch percentage: snapshot покрывает 49/50 branch exits, exporter 39/40 в parent coverage; вызов `__main__` проверен fresh subprocess tests вне parent coverage. Дополнительно прошли **18 process-privacy** tests за 4.822 s и **70 controller/lifecycle** за 13.915 s, оба без skips. Actual publisher/scorer: dumpable=0 и core_limits=[0,0], observed 2026-10-19T19:29:58.628805+00:00.

## Реальный public export

Закрытый журнал candidate HTTP fixture прошёл production CLI, independent schema/accounting/canary comparison и повторное чтение source bytes без изменений. Всего **332 события**, **83 completed requests**, **0 aborted**, **0 unresolved**; routes predict=78/ready=5. Observed contexts candidate-qualification=57/none=26/release-selection=0. Это фиксированные агрегаты, не утверждение о 83 успешных inference или release approval.

```json
{
  "context_kinds": {
    "candidate-qualification": 57,
    "none": 26,
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
}
```

Новые finite cases: `closed-audit-public-export-schema-counters-and-canaries`, `closed-audit-export-not-release-approval`. В public export нет private JSONL, request/principal IDs и context hashes. Внешний synthetic qualification report ниже сохраняет свои ранее разрешённые artifact/provenance references и связывает test с code/image; его схема отличается от public export. Это не экспорт всех platform logs и не full M13; отсутствие чувствительных значений во всех outputs этим increment не заявлено.

Смежная регрессия: audit accepted/durable 8/8; privacy 12 requests, 36 durable events, 3 owned files, 69 approved metrics, ambient_signals_used=false. Golden 3 rows, maximum_error=0.0. Worker stop denial 2.0171734059999835 s. Outage 43 observations, first503=59.745807242999945 s; assessment повторно пересчитан из observations и совпал. Paused SQL denial 10.002468288000046 s, expiry denial 5.667662783999958 s; оба HTTP503 при ACTIVE/pending query и fenced generation. Это component budgets, не общий production SLO.

## Полная CI matrix

| Workflow | Attempt | Conclusion | Job ID |
| --- | ---: | --- | ---: |
| [Developer runtime qualification](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39310191078/attempts/1) | 1 | success | 118257450073 |
| [Documentation integrity](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39310191124/attempts/1) | 1 | success | 118257462037 |
| [Frozen evasion and domain guard](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39310191405/attempts/1) | 1 | failure | 118257450097 |
| [Frozen poisoning research matrix](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39310190983/attempts/1) | 1 | failure | 118257448580 |
| [Intake evidence contracts](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39310190947/attempts/1) | 1 | success | 118257449959 |
| [Kubernetes isolation qualification](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39310191063/attempts/1) | 1 | success | 118257449142 |
| [MLflow tracking compatibility and private service](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39310191079/attempts/1) | 1 | success | 118257449503 |
| [Paired robust training research](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39310190955/attempts/1) | 1 | failure | 118257448863 |
| [Storage role and TLS qualification](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39310191396/attempts/2) | 2 | success | 118260451815 |
| [Worker and storage image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39310190977/attempts/1) | 1 | failure | 118257449212 |

## Сохранённый failure первой попытки Storage

[Attempt 1](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39310191396/attempts/1), job **118257450533**: exporter suite и M03 прошли, затем M07 failed. Из 32 concurrent holdout attempts: claimed slots 2..32, один `storage_connection_rejected`, invalid_receipts=0. Actual-candidate step был skipped, поэтому первая попытка не доказывает end-to-end export.

Сделан **один** диагностический rerun только Storage на том же immutable SHA. [Attempt 2](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39310191396/attempts/2), job **118260451815**, прошёл M07 и candidate. Код, бюджеты/пороги и assertions не менялись. Root cause первого connection rejection **не установлен**; ранее известный M07 reliability debt не закрыт. Retry pass не объявляется исправлением или доказательством надёжности.

```json
{
  "artifact_hashes": {
  },
  "cases": [
  ],
  "diagnostics": {
    "holdout_concurrency": {
      "attempts": 32,
      "claimed_slots": [
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        21,
        22,
        23,
        24,
        25,
        26,
        27,
        28,
        29,
        30,
        31,
        32
      ],
      "complete": true,
      "diagnostic_only": true,
      "invalid_receipts": 0,
      "rejection_codes": {
        "storage_connection_rejected": 1
      },
      "schema_version": 1
    }
  },
  "exit_code": 1,
  "finished_at": "2026-10-19T19:24:49.811762+00:00",
  "gate": "M07",
  "input_digests": {
    "source_fingerprint": "cc8f80a19f5cea70e0fb8b563dcb2516ce587c9127445f10b0caa6287cd2fab2"
  },
  "metrics": {
  },
  "policy_digest": "9a78ff344304e12e52c54652d8750aae69038e2a1ae2fb2c375a752e67fedb24",
  "profile": "local-cpu",
  "redaction_version": 1,
  "residual_risks": [
    "holdout_qualification_failed:concurrent-over-budget-denied"
  ],
  "schema_version": 1,
  "source_revision": "f0d054275ae095ec90c4eb41b323d7533d2b17db",
  "started_at": "2026-10-19T19:24:05.029526+00:00",
  "status": "fail"
}
```

## Подтверждённые release blockers

Image audit действительно выполнил scan и валидацию SBOM для всех четырёх images; каждый scanner_exit_code=2, security status fail:

| Image | Critical | High | Exit |
| --- | ---: | ---: | ---: |
| worker | 0 | 56 | 2 |
| storage | 9 | 132 | 2 |
| worker-candidate | 0 | 55 | 2 |
| storage-candidate | 1 | 85 | 2 |

Poisoning matrix: execution complete, **10 violating / 0 inconclusive / 25 nonviolating**. Evasion recall_drop **0.07183673469387755 > 0.05**. Paired candidate: **0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 > 0.05** для known-73041/new-73043/new-73047. Все ML research reports completed, но fail; adoption/release_ready не разрешены.

## Полный candidate report

Это очищенный synthetic qualification report из CI, не private source journal.

```json
{
  "campaign_id": "5713d69dd0554a58a5263c37d43f1532",
  "candidate_reference": "0623aacdce0f75b2f76b72549b89b04759c1b07e56f911b90fd1205da27ea6db",
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
    "closed-audit-public-export-schema-counters-and-canaries",
    "closed-audit-export-not-release-approval",
    "qualification-authority-and-private-key-removed",
    "source-cas-budget-envelopes-and-checkout-unchanged"
  ],
  "evaluation_reference": "ba1c94aca5e2d87f1c3514461aa1c6e2ff298e284eb1b726dd891fa3773fd65b",
  "finished_at": "2026-10-19T19:36:25.198922+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f",
  "proposal_reference": "a3456ee7193080f3302118661ba3886f2a7a00f801d759fc57d17daaba99c396",
  "qualification_permit_sha256": "16acbdbe5a576743fae6ff817890414c5c9b4db310b10ac2851f34ffd08919c8",
  "reference_response_sha256": "8ff20572fe7771cb45c25641d44c9cb3ee93f56810c5eb875c5c407c9b8f0e1e",
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
      "window_seconds": 0.0065423119999650226
    },
    "golden_rows": 3,
    "http_audit": {
      "accepted_delta": 8,
      "durable_delta": 8,
      "release_ready": false,
      "scope": "actual-candidate-http-audit-pair-not-full-M13",
      "status": "pass"
    },
    "http_expiring_query": {
      "approval_deadline": 1114.1757023334503,
      "denial": {
        "active_observed": {
          "monotonic": 599.558460514,
          "wall": 1792438574.3827577
        },
        "connected_read_entered": true,
        "finished_monotonic": 605.108818425,
        "finished_wall": 1792438579.9331164,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 599.441155641,
        "started_wall": 1792438574.2654529
      },
      "expected_trust": {
        "document_sha256": "ce973df65206524f8d29de0fcb0305338824b2da2d962dc1540d3d989c35e487",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 605.3571047782898,
        "document_sha256": "ce973df65206524f8d29de0fcb0305338824b2da2d962dc1540d3d989c35e487",
        "monotonic": 599.369769594,
        "sequence": 51,
        "version": 2,
        "wall": 1792438574.194067
      },
      "policy_expires_at": 1792438581,
      "policy_expiry_monotonic": 606.1757025718689,
      "post_expiry": {
        "finished_monotonic": 606.227241868,
        "finished_wall": 1792438581.0515392,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 606.225838771,
        "started_wall": 1792438581.0501354
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 668.378444092,
        "document_sha256": "f9ddca7ad635c4682029e8797221a02e4c7b759e8f30e87983c8db3c2fa1dc9d",
        "monotonic": 608.391322202,
        "sequence": 58,
        "version": 3,
        "wall": 1792438583.2156193
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "f9ddca7ad635c4682029e8797221a02e4c7b759e8f30e87983c8db3c2fa1dc9d",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 587.30449789,
          "wall": 1792438562.128795
        },
        "connected_read_entered": true,
        "finished_monotonic": 597.1843076,
        "finished_wall": 1792438572.0086057,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 587.181839312,
        "started_wall": 1792438562.0061367
      },
      "last_verified": {
        "deadline": 647.098434413,
        "document_sha256": "d5863ebf6b1195f6ec01f5cfd15cd71847dd1a3c6e22cfab644172f9d2552273",
        "monotonic": 587.110254922,
        "sequence": 43,
        "version": 1,
        "wall": 1792438561.934552
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 658.660447292,
        "document_sha256": "d5863ebf6b1195f6ec01f5cfd15cd71847dd1a3c6e22cfab644172f9d2552273",
        "monotonic": 598.673484051,
        "sequence": 49,
        "version": 1,
        "wall": 1792438573.4977813
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
        "first_503_seconds": 59.745807242999945,
        "last_200_seconds": 59.69359711699997,
        "observations": 43,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "c269ef17cdaf0a0b7ded174a273b7544132ba298233292e844ab73e691076bf4",
        "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f"
      },
      "last_verified": {
        "deadline": 585.378552405,
        "document_sha256": "d5863ebf6b1195f6ec01f5cfd15cd71847dd1a3c6e22cfab644172f9d2552273",
        "monotonic": 525.390449284,
        "sequence": 36,
        "version": 1,
        "wall": 1792438500.2147467
      },
      "records": [
        {
          "finished_monotonic": 525.921259852,
          "finished_wall": 1792438500.7455578,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 525.899963142,
          "started_wall": 1792438500.7242606,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 527.943583243,
          "finished_wall": 1792438502.7678812,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 527.921453397,
          "started_wall": 1792438502.7457507,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 529.966168504,
          "finished_wall": 1792438504.7904663,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 529.943781129,
          "started_wall": 1792438504.7680783,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 531.989225518,
          "finished_wall": 1792438506.8135238,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 531.966337653,
          "started_wall": 1792438506.790635,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 534.011597467,
          "finished_wall": 1792438508.835895,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 533.989399684,
          "started_wall": 1792438508.813697,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 536.033890519,
          "finished_wall": 1792438510.8581884,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 536.011753169,
          "started_wall": 1792438510.8360507,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 538.056727602,
          "finished_wall": 1792438512.8810256,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 538.034058835,
          "started_wall": 1792438512.8583562,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 540.078962154,
          "finished_wall": 1792438514.90326,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 540.056916225,
          "started_wall": 1792438514.8812137,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 542.101447,
          "finished_wall": 1792438516.925745,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 542.079121632,
          "started_wall": 1792438516.903419,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 544.123186294,
          "finished_wall": 1792438518.9474845,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 544.101592815,
          "started_wall": 1792438518.9258902,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 546.146252175,
          "finished_wall": 1792438520.97055,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 546.12335762,
          "started_wall": 1792438520.947655,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 548.168352515,
          "finished_wall": 1792438522.9926503,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 548.146429045,
          "started_wall": 1792438522.9707265,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 550.191205544,
          "finished_wall": 1792438525.0155034,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 550.168483691,
          "started_wall": 1792438524.9927812,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 552.21343275,
          "finished_wall": 1792438527.0377305,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 552.19139618,
          "started_wall": 1792438527.0156934,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.235652162,
          "finished_wall": 1792438529.05995,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 554.213622034,
          "started_wall": 1792438529.0379195,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 556.258258789,
          "finished_wall": 1792438531.0825567,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 556.235821755,
          "started_wall": 1792438531.0601192,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 558.280912035,
          "finished_wall": 1792438533.1052098,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 558.258448262,
          "started_wall": 1792438533.0827456,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 560.303068267,
          "finished_wall": 1792438535.127366,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 560.281079969,
          "started_wall": 1792438535.1053772,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 562.324545788,
          "finished_wall": 1792438537.1488435,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 562.303211893,
          "started_wall": 1792438537.1275094,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 564.347426085,
          "finished_wall": 1792438539.171724,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 564.324731072,
          "started_wall": 1792438539.1490285,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 566.370421694,
          "finished_wall": 1792438541.1947196,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 566.347607854,
          "started_wall": 1792438541.1719053,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 568.39291342,
          "finished_wall": 1792438543.2172112,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 568.370609407,
          "started_wall": 1792438543.194907,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 570.415441402,
          "finished_wall": 1792438545.2397392,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 570.393099368,
          "started_wall": 1792438545.2173967,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 572.437720731,
          "finished_wall": 1792438547.2620182,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 572.415596959,
          "started_wall": 1792438547.2398944,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 574.460624987,
          "finished_wall": 1792438549.284923,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 574.437905058,
          "started_wall": 1792438549.2622023,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 576.483189683,
          "finished_wall": 1792438551.3074875,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 576.460772005,
          "started_wall": 1792438551.2850692,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 578.506411388,
          "finished_wall": 1792438553.3307092,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 578.483373558,
          "started_wall": 1792438553.307671,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 580.529599876,
          "finished_wall": 1792438555.3538978,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 580.506568446,
          "started_wall": 1792438555.3308659,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 582.551700223,
          "finished_wall": 1792438557.3759983,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 582.529793864,
          "started_wall": 1792438557.3540912,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 584.574369628,
          "finished_wall": 1792438559.3986676,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 584.551895122,
          "started_wall": 1792438559.3761926,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 584.646630559,
          "finished_wall": 1792438559.4709284,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 584.624544345,
          "started_wall": 1792438559.4488418,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 584.71995156,
          "finished_wall": 1792438559.5442495,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 584.696751797,
          "started_wall": 1792438559.5210493,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 584.793161625,
          "finished_wall": 1792438559.6174595,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 584.770082396,
          "started_wall": 1792438559.5943797,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 584.865601108,
          "finished_wall": 1792438559.689899,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 584.843283665,
          "started_wall": 1792438559.667581,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 584.938238599,
          "finished_wall": 1792438559.7625365,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 584.915773201,
          "started_wall": 1792438559.7400706,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.011170828,
          "finished_wall": 1792438559.8354685,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 584.988357784,
          "started_wall": 1792438559.8126552,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.084046401,
          "finished_wall": 1792438559.9083443,
          "http_status": 200,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 585.061298258,
          "started_wall": 1792438559.8855956,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.136256527,
          "finished_wall": 1792438559.9605546,
          "http_status": 503,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 585.134174973,
          "started_wall": 1792438559.9584725,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.188066214,
          "finished_wall": 1792438560.0123641,
          "http_status": 503,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 585.186360804,
          "started_wall": 1792438560.0106583,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.240103561,
          "finished_wall": 1792438560.0644016,
          "http_status": 503,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 585.238203432,
          "started_wall": 1792438560.062501,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.291830464,
          "finished_wall": 1792438560.1161284,
          "http_status": 503,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 585.290242595,
          "started_wall": 1792438560.11454,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.343575519,
          "finished_wall": 1792438560.1678736,
          "http_status": 503,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 585.341930223,
          "started_wall": 1792438560.1662273,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.395403808,
          "finished_wall": 1792438560.2197018,
          "http_status": 503,
          "lease_deadline": 585.378552405,
          "response_valid": true,
          "started_monotonic": 585.393670498,
          "started_wall": 1792438560.217968,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 647.054537356,
        "document_sha256": "d5863ebf6b1195f6ec01f5cfd15cd71847dd1a3c6e22cfab644172f9d2552273",
        "monotonic": 587.066754489,
        "sequence": 41,
        "version": 1,
        "wall": 1792438561.8910518
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0.0,
    "public_audit_window": {
      "context_kinds": {
        "candidate-qualification": 57,
        "none": 26,
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
    "stopped_worker_denial_seconds": 2.0171734059999835
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:12df49e8c6d8b1a7301343f4a8966c8f6f456cee6798f5a9be6c7cf328148492",
    "source_fingerprint": "cc8f80a19f5cea70e0fb8b563dcb2516ce587c9127445f10b0caa6287cd2fab2",
    "source_revision": "f0d054275ae095ec90c4eb41b323d7533d2b17db"
  },
  "source_dirty": false,
  "started_at": "2026-10-19T19:34:46.371603+00:00",
  "status": "pass",
  "subject_sha256": "c269ef17cdaf0a0b7ded174a273b7544132ba298233292e844ab73e691076bf4"
}
```
