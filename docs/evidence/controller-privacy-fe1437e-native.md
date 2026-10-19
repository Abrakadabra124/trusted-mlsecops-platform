# T16: native receipt fe1437e

Code commit `fe1437e887e15053a3b03a72e892b517da166e76`. [Storage CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39301863940), job 118228836159, attempt 1. [Общий отчёт и ограничения](controller-privacy-2026-10-19.md).

## Kernel receipt

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

## Actual publisher/scorer process readback

[Kubernetes CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39301863911), job 118228835821, attempt 1. Extract из scoped-controller report (139 cases); M20 total 725, M21 total 122. Это snapshot процессов с реальными scoped identities, не повторный enforcement внутри observer.

```json
{
  "scope": "actual-controller-process-privacy-readback-not-full-M13",
  "source_revision": "fe1437e887e15053a3b03a72e892b517da166e76",
  "observed_at": "2026-10-19T18:31:04.154224+00:00",
  "status": "pass",
  "source_fingerprint": "5bec6983e846be6b993ae5ac430deb5e32af142c90b67792c96ea1c82bfaf530",
  "image_id": "sha256:c72f4a36ba22e272e2edb951bf9656fe2a15a5837548d2b364d33bd55a3ecf68",
  "process_privacy": {
    "publisher": {
      "core_limits": [
        0,
        0
      ],
      "dumpable": 0
    },
    "scorer": {
      "core_limits": [
        0,
        0
      ],
      "dumpable": 0
    }
  },
  "cases": [
    {
      "id": "publisher:kernel-privacy-readback",
      "status": "pass"
    },
    {
      "id": "scorer:kernel-privacy-readback",
      "status": "pass"
    }
  ],
  "release_ready": false
}
```

## Actual candidate report

Не release approval: synthetic qualification, source_dirty=false, release_ready=false. Numeric lexemes сохранены из CI JSON; это очищенный report, не raw job log. Все 78 case names и outage observations сохранены для независимого пересчёта.

```json
{
  "campaign_id": "0a183eb1cd564999a84e70d86a2a0f54",
  "candidate_reference": "4cfff909a470fe163370a8e054bfef2fa6912f6a2ebdb15547e36d508c6b39cc",
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
  "evaluation_reference": "6adedc0c81b65b23b2617fce5dd6bad95e92ebf7de740bcc5bce56bfc79d3899",
  "finished_at": "2026-10-19T18:31:17.749140+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634",
  "proposal_reference": "ce283d145a0eea4fbeb8dc4a088102d5f13795a05002f3cb28825dab907ca062",
  "qualification_permit_sha256": "178795c84753dd1974ff8705f6e6a5485ac5046ff550ea495ecbe87a06f439e9",
  "reference_response_sha256": "b2a9d21d5516c8271a90647143eb1314ba97607e39bfc22938c07d9059400056",
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
      "window_seconds": 0.006078228999967905
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
      "approval_deadline": 1161.33052110672,
      "denial": {
        "active_observed": {
          "monotonic": 646.508414007,
          "wall": 1792434667.1778917
        },
        "connected_read_entered": true,
        "finished_monotonic": 652.07938097,
        "finished_wall": 1792434672.74886,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 646.401437808,
        "started_wall": 1792434667.0709152
      },
      "expected_trust": {
        "document_sha256": "5438d25d52b8119d6522919290a18693f94eafda48086c0ca9cfe79f19cb2975",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 652.3274703025818,
        "document_sha256": "5438d25d52b8119d6522919290a18693f94eafda48086c0ca9cfe79f19cb2975",
        "monotonic": 646.339353231,
        "sequence": 51,
        "version": 2,
        "wall": 1792434667.0088315
      },
      "policy_expires_at": 1792434674,
      "policy_expiry_monotonic": 653.3305218219757,
      "post_expiry": {
        "finished_monotonic": 653.382550041,
        "finished_wall": 1792434674.052028,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 653.380659198,
        "started_wall": 1792434674.0501351
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 715.323108469,
        "document_sha256": "c9a6d4ec3c7f4025d54cbbefbf19f7546688a7957810183ba768dde69beeffc0",
        "monotonic": 655.334137463,
        "sequence": 56,
        "version": 3,
        "wall": 1792434676.0036159
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "c9a6d4ec3c7f4025d54cbbefbf19f7546688a7957810183ba768dde69beeffc0",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 634.44551874,
          "wall": 1792434655.1149962
        },
        "connected_read_entered": true,
        "finished_monotonic": 644.346402163,
        "finished_wall": 1792434665.0158813,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 634.343541022,
        "started_wall": 1792434655.0130184
      },
      "last_verified": {
        "deadline": 694.266037021,
        "document_sha256": "9c33dba22e700e3c44cc29e60e3d37c3fc5be1952cdaa332922834d0366e7da9",
        "monotonic": 634.277944751,
        "sequence": 43,
        "version": 1,
        "wall": 1792434654.947423
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 705.72116618,
        "document_sha256": "9c33dba22e700e3c44cc29e60e3d37c3fc5be1952cdaa332922834d0366e7da9",
        "monotonic": 645.733258279,
        "sequence": 49,
        "version": 1,
        "wall": 1792434666.4027367
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
        "first_503_seconds": 59.74956517600003,
        "last_200_seconds": 59.694110722000005,
        "observations": 43,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "ca163ce95b8953f7b66d65a9b9e81b3d1663dc6a3c6a663fb483a848a1a22b0e",
        "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634"
      },
      "last_verified": {
        "deadline": 632.646474624,
        "document_sha256": "9c33dba22e700e3c44cc29e60e3d37c3fc5be1952cdaa332922834d0366e7da9",
        "monotonic": 572.65839927,
        "sequence": 36,
        "version": 1,
        "wall": 1792434593.3278773
      },
      "records": [
        {
          "finished_monotonic": 573.164867529,
          "finished_wall": 1792434593.8343465,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 573.142972932,
          "started_wall": 1792434593.8124511,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 575.187910398,
          "finished_wall": 1792434595.8573892,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 575.165052713,
          "started_wall": 1792434595.834531,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 577.211076888,
          "finished_wall": 1792434597.8805556,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 577.188077661,
          "started_wall": 1792434597.8575559,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 579.233633261,
          "finished_wall": 1792434599.9031122,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 579.211257112,
          "started_wall": 1792434599.8807354,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 581.2565829,
          "finished_wall": 1792434601.9260619,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 581.233814979,
          "started_wall": 1792434601.9032931,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 583.281302954,
          "finished_wall": 1792434603.9507816,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 583.256764553,
          "started_wall": 1792434603.9262428,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 585.304325239,
          "finished_wall": 1792434605.973804,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 585.281462451,
          "started_wall": 1792434605.9509406,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 587.327548953,
          "finished_wall": 1792434607.997028,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 587.304470182,
          "started_wall": 1792434607.9739485,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 589.350505016,
          "finished_wall": 1792434610.0199842,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 589.327724853,
          "started_wall": 1792434609.997203,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 591.374384603,
          "finished_wall": 1792434612.0438633,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 591.350683955,
          "started_wall": 1792434612.0201623,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 593.397179583,
          "finished_wall": 1792434614.0666585,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 593.374562519,
          "started_wall": 1792434614.044041,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 595.421464427,
          "finished_wall": 1792434616.0909436,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 595.397356473,
          "started_wall": 1792434616.0668347,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 597.444657838,
          "finished_wall": 1792434618.1141365,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 597.421652325,
          "started_wall": 1792434618.0911307,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 599.466771107,
          "finished_wall": 1792434620.1362498,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 599.444845056,
          "started_wall": 1792434620.1143231,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 601.490425187,
          "finished_wall": 1792434622.159904,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 601.467048958,
          "started_wall": 1792434622.136527,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 603.513624044,
          "finished_wall": 1792434624.183103,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 603.490583758,
          "started_wall": 1792434624.1600618,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 605.536445275,
          "finished_wall": 1792434626.205924,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 605.513988967,
          "started_wall": 1792434626.1834671,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 607.560176645,
          "finished_wall": 1792434628.2296553,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 607.536622698,
          "started_wall": 1792434628.206101,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 609.584192298,
          "finished_wall": 1792434630.253671,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 609.560369352,
          "started_wall": 1792434630.2298477,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 611.607674315,
          "finished_wall": 1792434632.2771533,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 611.584376331,
          "started_wall": 1792434632.2538545,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 613.634592951,
          "finished_wall": 1792434634.304072,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 613.607860445,
          "started_wall": 1792434634.2773385,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 615.65724447,
          "finished_wall": 1792434636.3267233,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 615.634770873,
          "started_wall": 1792434636.304249,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 617.678986363,
          "finished_wall": 1792434638.3484652,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 617.657425516,
          "started_wall": 1792434638.3269038,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 619.701352647,
          "finished_wall": 1792434640.3708313,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 619.679182009,
          "started_wall": 1792434640.3486602,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 621.723597608,
          "finished_wall": 1792434642.3930767,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 621.701521369,
          "started_wall": 1792434642.3709996,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 623.74674341,
          "finished_wall": 1792434644.416222,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 623.723775921,
          "started_wall": 1792434644.393254,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 625.769585487,
          "finished_wall": 1792434646.4390643,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 625.746909491,
          "started_wall": 1792434646.4163878,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 627.794467482,
          "finished_wall": 1792434648.4639463,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 627.769766743,
          "started_wall": 1792434648.439245,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 629.818239905,
          "finished_wall": 1792434650.4877188,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 629.794638047,
          "started_wall": 1792434650.4641163,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 631.841115069,
          "finished_wall": 1792434652.5105941,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 631.818426806,
          "started_wall": 1792434652.487905,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 631.913957153,
          "finished_wall": 1792434652.5834358,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 631.891281828,
          "started_wall": 1792434652.56076,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 631.987519614,
          "finished_wall": 1792434652.6569986,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 631.964116403,
          "started_wall": 1792434652.6335945,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 632.061088794,
          "finished_wall": 1792434652.7305677,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 632.0376809,
          "started_wall": 1792434652.7071593,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 632.134628457,
          "finished_wall": 1792434652.8041072,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 632.111293641,
          "started_wall": 1792434652.7807717,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 632.207235498,
          "finished_wall": 1792434652.876714,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 632.184779555,
          "started_wall": 1792434652.8542578,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 632.280214686,
          "finished_wall": 1792434652.9496934,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 632.2575579,
          "started_wall": 1792434652.927036,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 632.352509992,
          "finished_wall": 1792434653.0219886,
          "http_status": 200,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 632.330392177,
          "started_wall": 1792434652.9998705,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 632.407964446,
          "finished_wall": 1792434653.0774436,
          "http_status": 503,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 632.40294257,
          "started_wall": 1792434653.0724208,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 632.459965971,
          "finished_wall": 1792434653.129445,
          "http_status": 503,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 632.458084045,
          "started_wall": 1792434653.1275623,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 632.512619335,
          "finished_wall": 1792434653.1820984,
          "http_status": 503,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 632.510044488,
          "started_wall": 1792434653.1795228,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 632.564553829,
          "finished_wall": 1792434653.2340326,
          "http_status": 503,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 632.562773553,
          "started_wall": 1792434653.232252,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 632.616315709,
          "finished_wall": 1792434653.2857945,
          "http_status": 503,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 632.614659145,
          "started_wall": 1792434653.2841375,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 632.668115492,
          "finished_wall": 1792434653.3375945,
          "http_status": 503,
          "lease_deadline": 632.646474624,
          "response_valid": true,
          "started_monotonic": 632.666418198,
          "started_wall": 1792434653.3358965,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 694.221664376,
        "document_sha256": "9c33dba22e700e3c44cc29e60e3d37c3fc5be1952cdaa332922834d0366e7da9",
        "monotonic": 634.233154644,
        "sequence": 41,
        "version": 1,
        "wall": 1792434654.902633
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0.0,
    "stopped_worker_denial_seconds": 2.0182932449999953
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:11dda816c7297be4fa28886ae1cabdaf0e1beefc9457f96096c9f96f6e0c6b8b",
    "source_fingerprint": "5bec6983e846be6b993ae5ac430deb5e32af142c90b67792c96ea1c82bfaf530",
    "source_revision": "fe1437e887e15053a3b03a72e892b517da166e76"
  },
  "source_dirty": false,
  "started_at": "2026-10-19T18:29:40.078331+00:00",
  "status": "pass",
  "subject_sha256": "ca163ce95b8953f7b66d65a9b9e81b3d1663dc6a3c6a663fb483a848a1a22b0e"
}
```
