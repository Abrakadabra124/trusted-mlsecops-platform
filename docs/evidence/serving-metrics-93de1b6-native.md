# Native serving metrics qualification 93de1b6

Источник: [Storage run 39294934944](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294934944), job 118204871271, attempt 1, success. Code commit `93de1b6af0abdbe3072579b2c48c0ac35db4c176`. Это повторная native проверка после явной source-lock correction, не rerun прежнего SHA. [Итог и matrix](serving-metrics-2026-10-19.md); [failed attempt](serving-metrics-4c86fcb-native.md) сохранён.

## Metrics gate

Canonical candidate report SHA-256: `b70bb8eb3100e390a1656e4c23cc5fa4b50d666d62437de7fcaa87ef0e7b17f6`. Python повторно проверил digest, exact source revision, unique case count, approved schema count и пересчёт outage assessment из records. Эта проверка не является повторным запуском native workloads.

35 tests / 0 skips, 3.692 s; collector 115 statements / 30 branches / 100%, independent probe 69 statements / 36 branches / 100%. Existing privacy probe + candidate harness: 25 tests / 0 skips, 4.045 s, 181 statements / 84 branches / 100%. HTTP audit 48 tests / 0 skips, 4.632 s; serving regressions 81 tests / 0 skips, 15.799 s; client access 32 tests / 0 skips, 2.043 s. Worker privacy 13 tests / 0 skips, 0.363 s; guard 100%. Все проверки выполнены в disposable Linux CI, не на локальной инфраструктуре.

## Kernel regression receipt

```json
{
  "abort_signal": 6,
  "core_dumped": false,
  "core_limits": [
    0,
    0
  ],
  "dumpable": 0,
  "owned_files": 0,
  "release_ready": false,
  "scope": "worker-kernel-privacy-component-not-full-M13",
  "status": "pass"
}
```

## Actual candidate report

78 unique cases, включая privacy-approved-metrics-cardinality. source_dirty=false, release_ready=false. Approved metrics 69; 12 privacy requests / 36 confirmed audit events / 3 owned audit files; ambient telemetry не использована. Qualification permission не является release approval. Числовые JSON lexemes сохранены, менялся только whitespace. Private credentials, raw journals, canaries и model bytes не публикуются.

```json
{
  "campaign_id": "45e3a0e4f863445896494e2e721b6726",
  "candidate_reference": "966941f392364c94e8fe235618df2ed14ada35747c494b2faa3fe363fef68442",
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
    "qualification-authority-and-private-key-removed",
    "source-cas-budget-envelopes-and-checkout-unchanged"
  ],
  "evaluation_reference": "94829ba42985124795612e0bd29a930d783ac8bef9964c1e1992817ea8ad0895",
  "finished_at": "2026-10-19T17:40:49.618741+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f",
  "proposal_reference": "ab5328607fba18a2c9fa2880681f8bd0799572ef0a18a3488313eeb95b067d4d",
  "qualification_permit_sha256": "e6bf04454cda135cc7e847b9e5dc6c6c0e7594e330fd93aa07199a6298588356",
  "reference_response_sha256": "750a32de5e3a1852c186b80dac2582870835c266adc29d0d3d72afd8ce4c8c98",
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
      "window_seconds": 0.005873137999969913
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
      "approval_deadline": 1114.8437631130219,
      "denial": {
        "active_observed": {
          "monotonic": 599.189512327,
          "wall": 1792431639.3457487
        },
        "connected_read_entered": true,
        "finished_monotonic": 604.782464197,
        "finished_wall": 1792431644.9387014,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 599.098047256,
        "started_wall": 1792431639.2542837
      },
      "expected_trust": {
        "document_sha256": "de2d6984fc44a764ddf7088953e857d6767f3dcb9487f6279bfa30298bdf1604",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 605.0307250022888,
        "document_sha256": "de2d6984fc44a764ddf7088953e857d6767f3dcb9487f6279bfa30298bdf1604",
        "monotonic": 599.040858135,
        "sequence": 51,
        "version": 2,
        "wall": 1792431639.1970947
      },
      "policy_expires_at": 1792431646,
      "policy_expiry_monotonic": 605.8437633514404,
      "post_expiry": {
        "finished_monotonic": 605.895486074,
        "finished_wall": 1792431646.0517225,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 605.893884062,
        "started_wall": 1792431646.05012
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 667.74398057,
        "document_sha256": "d174a359d9ed23ef249ff0c444d98eed97e1004e8f92baa428750a38261992d3",
        "monotonic": 607.754673297,
        "sequence": 56,
        "version": 3,
        "wall": 1792431647.91091
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "d174a359d9ed23ef249ff0c444d98eed97e1004e8f92baa428750a38261992d3",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 587.256227632,
          "wall": 1792431627.412464
        },
        "connected_read_entered": true,
        "finished_monotonic": 597.16755812,
        "finished_wall": 1792431637.323796,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 587.164536239,
        "started_wall": 1792431627.3207724
      },
      "last_verified": {
        "deadline": 647.097267197,
        "document_sha256": "af5de3e935b429604b29fd39047e9267f8e523938608d666d5f36125bfcc80d6",
        "monotonic": 587.107146677,
        "sequence": 43,
        "version": 1,
        "wall": 1792431627.2633834
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 658.44422397,
        "document_sha256": "af5de3e935b429604b29fd39047e9267f8e523938608d666d5f36125bfcc80d6",
        "monotonic": 598.453898173,
        "sequence": 49,
        "version": 1,
        "wall": 1792431638.6101348
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
        "first_503_seconds": 59.74158933000001,
        "last_200_seconds": 59.68971473700003,
        "observations": 44,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "f6742158968039d1ce003cd883dd95cf487041b4b8632db390b133a0eac89042",
        "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f"
      },
      "last_verified": {
        "deadline": 585.58199044,
        "document_sha256": "af5de3e935b429604b29fd39047e9267f8e523938608d666d5f36125bfcc80d6",
        "monotonic": 525.591889447,
        "sequence": 36,
        "version": 1,
        "wall": 1792431565.748126
      },
      "records": [
        {
          "finished_monotonic": 526.075426524,
          "finished_wall": 1792431566.231664,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 526.053959372,
          "started_wall": 1792431566.210196,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 528.097343474,
          "finished_wall": 1792431568.2535803,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 528.075599122,
          "started_wall": 1792431568.2318356,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 530.119125973,
          "finished_wall": 1792431570.2753627,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 530.097485488,
          "started_wall": 1792431570.2537222,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 532.140661741,
          "finished_wall": 1792431572.2968986,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 532.119264233,
          "started_wall": 1792431572.2755008,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 534.162232189,
          "finished_wall": 1792431574.318469,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 534.140801267,
          "started_wall": 1792431574.2970376,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 536.183760879,
          "finished_wall": 1792431576.3399978,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 536.162372796,
          "started_wall": 1792431576.3186095,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 538.205784383,
          "finished_wall": 1792431578.3620214,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 538.183899043,
          "started_wall": 1792431578.3401356,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 540.227258653,
          "finished_wall": 1792431580.3834956,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 540.205928919,
          "started_wall": 1792431580.3621655,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 542.249446106,
          "finished_wall": 1792431582.405683,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 542.22738135,
          "started_wall": 1792431582.383618,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 544.271380406,
          "finished_wall": 1792431584.4276173,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 544.249585013,
          "started_wall": 1792431584.4058218,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 546.293280914,
          "finished_wall": 1792431586.4495177,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 546.27152241,
          "started_wall": 1792431586.4277592,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 548.315035156,
          "finished_wall": 1792431588.4712722,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 548.293424493,
          "started_wall": 1792431588.4496613,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 550.337206173,
          "finished_wall": 1792431590.493443,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 550.315163894,
          "started_wall": 1792431590.4714005,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 552.359055737,
          "finished_wall": 1792431592.5152926,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 552.337351168,
          "started_wall": 1792431592.4935877,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.380727745,
          "finished_wall": 1792431594.536965,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 554.359219002,
          "started_wall": 1792431594.5154555,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 556.403179186,
          "finished_wall": 1792431596.559416,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 556.3808726,
          "started_wall": 1792431596.5371091,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 558.425502533,
          "finished_wall": 1792431598.5817394,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 558.403320299,
          "started_wall": 1792431598.559557,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 560.447630299,
          "finished_wall": 1792431600.603867,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 560.425643743,
          "started_wall": 1792431600.5818803,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 562.469766696,
          "finished_wall": 1792431602.6260035,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 562.447767575,
          "started_wall": 1792431602.6040041,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 564.491568909,
          "finished_wall": 1792431604.6478057,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 564.469902282,
          "started_wall": 1792431604.626139,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 566.513383606,
          "finished_wall": 1792431606.6696205,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 566.491713583,
          "started_wall": 1792431606.6479502,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 568.534775652,
          "finished_wall": 1792431608.6910126,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 568.513520534,
          "started_wall": 1792431608.6697571,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 570.556194219,
          "finished_wall": 1792431610.7124312,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 570.534916147,
          "started_wall": 1792431610.6911526,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 572.578086211,
          "finished_wall": 1792431612.7343233,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 572.556330029,
          "started_wall": 1792431612.7125666,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 574.600195618,
          "finished_wall": 1792431614.7564323,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 574.578228989,
          "started_wall": 1792431614.7344656,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 576.62228207,
          "finished_wall": 1792431616.7785192,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 576.600334946,
          "started_wall": 1792431616.7565715,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 578.644890488,
          "finished_wall": 1792431618.8011274,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 578.622429485,
          "started_wall": 1792431618.778666,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 580.667159244,
          "finished_wall": 1792431620.8233964,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 580.645038245,
          "started_wall": 1792431620.8012748,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 582.68915034,
          "finished_wall": 1792431622.8453872,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 582.667268085,
          "started_wall": 1792431622.8235047,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 584.711509895,
          "finished_wall": 1792431624.8677468,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 584.689291704,
          "started_wall": 1792431624.8455284,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 584.782415339,
          "finished_wall": 1792431624.9386523,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 584.761649269,
          "started_wall": 1792431624.917886,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 584.853091196,
          "finished_wall": 1792431625.0093281,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 584.83255151,
          "started_wall": 1792431624.9887881,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 584.924331535,
          "finished_wall": 1792431625.0805686,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 584.903249175,
          "started_wall": 1792431625.0594857,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 584.995581373,
          "finished_wall": 1792431625.1518183,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 584.974466871,
          "started_wall": 1792431625.1307034,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.066362104,
          "finished_wall": 1792431625.2225993,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 585.045710227,
          "started_wall": 1792431625.201947,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.138220298,
          "finished_wall": 1792431625.2944574,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 585.116472293,
          "started_wall": 1792431625.272709,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.210310024,
          "finished_wall": 1792431625.3665469,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 585.188343321,
          "started_wall": 1792431625.34458,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.281604184,
          "finished_wall": 1792431625.4378412,
          "http_status": 200,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 585.26043969,
          "started_wall": 1792431625.4166763,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.333478777,
          "finished_wall": 1792431625.4897158,
          "http_status": 503,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 585.331750391,
          "started_wall": 1792431625.487987,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.385327172,
          "finished_wall": 1792431625.5415642,
          "http_status": 503,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 585.383585049,
          "started_wall": 1792431625.5398216,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.436631131,
          "finished_wall": 1792431625.592868,
          "http_status": 503,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 585.435412896,
          "started_wall": 1792431625.5916495,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.48789211,
          "finished_wall": 1792431625.644129,
          "http_status": 503,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 585.486722295,
          "started_wall": 1792431625.6429589,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.539061528,
          "finished_wall": 1792431625.6952982,
          "http_status": 503,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 585.537980238,
          "started_wall": 1792431625.694217,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.590077228,
          "finished_wall": 1792431625.7463143,
          "http_status": 503,
          "lease_deadline": 585.58199044,
          "response_valid": true,
          "started_monotonic": 585.589142202,
          "started_wall": 1792431625.7453787,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 647.058471795,
        "document_sha256": "af5de3e935b429604b29fd39047e9267f8e523938608d666d5f36125bfcc80d6",
        "monotonic": 587.068662328,
        "sequence": 41,
        "version": 1,
        "wall": 1792431627.2248988
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0.0,
    "stopped_worker_denial_seconds": 2.0154915780000238
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:327d592c3ddfe67575da95e799acaa188a8e3a8e60242c1952bfe18176f518ba",
    "source_fingerprint": "30fbd2ef30fb192ca941fedb35916f66413091d50a656cd525706aafbc9b192a",
    "source_revision": "93de1b6af0abdbe3072579b2c48c0ac35db4c176"
  },
  "source_dirty": false,
  "started_at": "2026-10-19T17:39:12.833373+00:00",
  "status": "pass",
  "subject_sha256": "f6742158968039d1ce003cd883dd95cf487041b4b8632db390b133a0eac89042"
}
```
