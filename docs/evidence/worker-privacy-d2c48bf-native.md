# Native worker privacy qualification d2c48bf

Источник: [Storage run 39287256202](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39287256202), job 118177665632, attempt 1. Code commit `d2c48bf03ce6f669fd990538f01d47b82380f06c`. Это повторная native проверка после исправления scanner fault-injection target; production worker code не менялся относительно af7253e. [Итог, CI matrix и ограничения](worker-privacy-2026-10-19.md). Private journals, canaries, credentials, model bytes и raw logs не опубликованы.

## Worker kernel receipt

Disposable Linux subprocess и собственный child; baseline dumpability проверяется assertion. Только атрибуты своего процесса, без host core_pattern или baseline core dump.

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

## Actual candidate regression

77 unique cases, release_ready=false. Qualification permission не является release approval. Числовые значения исходного JSON сохранены, изменён только whitespace.

```json
{
  "campaign_id": "5c81c9a388e343aaae070f328e975917",
  "candidate_reference": "5844df44508918786d04d65799feeded1b9bb9744373be6d9dfeba8879e53921",
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
    "actual-candidate-revocation-http-503",
    "actual-candidate-revocation-readiness-503",
    "qualification-authority-and-private-key-removed",
    "source-cas-budget-envelopes-and-checkout-unchanged"
  ],
  "evaluation_reference": "8483e7455d1c62a7e1b4d2072b0c7d3edcf6cf2abfe59b75b8ebe449d11a4af6",
  "finished_at": "2026-10-19T16:46:45.912175+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634",
  "proposal_reference": "1a570894af465e8d7d0a3dd5d3c9b8a8504850ba3ffcab6ae58105206f50bb2a",
  "qualification_permit_sha256": "287c854010832fabb6c17f08632ae8bbb3f2ac3d77d1dbcf4964f81ff8be335f",
  "reference_response_sha256": "556c3aa6cef7b53b4297e80325e798c5cbf791efee01f317ecd919c4db4a9fbb",
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
      "window_seconds": 0.0035576459999902
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
      "approval_deadline": 956.4953668117523,
      "denial": {
        "active_observed": {
          "monotonic": 438.70454081,
          "wall": 1792428396.209173
        },
        "connected_read_entered": true,
        "finished_monotonic": 444.323321459,
        "finished_wall": 1792428401.8279548,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 438.628563884,
        "started_wall": 1792428396.1331964
      },
      "expected_trust": {
        "document_sha256": "5b912983eb3898769e69bd681789da7dbfa83aa36e105043f74ad2559d76c437",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 444.57250714302063,
        "document_sha256": "5b912983eb3898769e69bd681789da7dbfa83aa36e105043f74ad2559d76c437",
        "monotonic": 438.579736054,
        "sequence": 51,
        "version": 2,
        "wall": 1792428396.0843687
      },
      "policy_expires_at": 1792428403,
      "policy_expiry_monotonic": 445.4953672885895,
      "post_expiry": {
        "finished_monotonic": 445.546882498,
        "finished_wall": 1792428403.051515,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 445.545454292,
        "started_wall": 1792428403.0500863
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 506.935451242,
        "document_sha256": "bda475ff73358c8d70a9c2a3b29040e456f44c03cfae5e3e929a075bab09a0b2",
        "monotonic": 446.943240035,
        "sequence": 56,
        "version": 3,
        "wall": 1792428404.4478729
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "bda475ff73358c8d70a9c2a3b29040e456f44c03cfae5e3e929a075bab09a0b2",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 427.194888695,
          "wall": 1792428384.6995213
        },
        "connected_read_entered": true,
        "finished_monotonic": 437.120286483,
        "finished_wall": 1792428394.62492,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 427.118309607,
        "started_wall": 1792428384.622942
      },
      "last_verified": {
        "deadline": 487.061307,
        "document_sha256": "07884a2aefecf5fb29b6a5454944b619d5513fa001d39bb98d068d36f8ad130d",
        "monotonic": 427.068808891,
        "sequence": 43,
        "version": 1,
        "wall": 1792428384.5734415
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 498.120803772,
        "document_sha256": "07884a2aefecf5fb29b6a5454944b619d5513fa001d39bb98d068d36f8ad130d",
        "monotonic": 438.128650682,
        "sequence": 49,
        "version": 1,
        "wall": 1792428395.6332834
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "http_privacy": {
      "ambient_signals_used": false,
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
        "first_503_seconds": 59.763940434000006,
        "last_200_seconds": 59.71223654400001,
        "observations": 46,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "b82c160c6236bf7daacfd7625f7d26f6a2179fec36aa6b43a111772285db9063",
        "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634"
      },
      "last_verified": {
        "deadline": 425.903187629,
        "document_sha256": "07884a2aefecf5fb29b6a5454944b619d5513fa001d39bb98d068d36f8ad130d",
        "monotonic": 365.910844006,
        "sequence": 36,
        "version": 1,
        "wall": 1792428323.4154768
      },
      "records": [
        {
          "finished_monotonic": 366.390077052,
          "finished_wall": 1792428323.89471,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 366.371939314,
          "started_wall": 1792428323.876572,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 368.408312996,
          "finished_wall": 1792428325.9129462,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 368.390184381,
          "started_wall": 1792428325.894817,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 370.426118045,
          "finished_wall": 1792428327.930751,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 370.408421888,
          "started_wall": 1792428327.9130545,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 372.443804306,
          "finished_wall": 1792428329.9484372,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 372.426214683,
          "started_wall": 1792428329.9308472,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 374.461525811,
          "finished_wall": 1792428331.9661586,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 374.443928426,
          "started_wall": 1792428331.948561,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 376.479382638,
          "finished_wall": 1792428333.9840157,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 376.461648789,
          "started_wall": 1792428333.9662814,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 378.497362378,
          "finished_wall": 1792428336.0019953,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 378.479502392,
          "started_wall": 1792428335.984135,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 380.515350754,
          "finished_wall": 1792428338.0199835,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 380.497460254,
          "started_wall": 1792428338.0020928,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 382.533711479,
          "finished_wall": 1792428340.0383446,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 382.515494358,
          "started_wall": 1792428340.020127,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 384.551581598,
          "finished_wall": 1792428342.0562148,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 384.533858797,
          "started_wall": 1792428342.0384915,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 386.56943564,
          "finished_wall": 1792428344.0740685,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 386.551692532,
          "started_wall": 1792428344.0563252,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 388.587284851,
          "finished_wall": 1792428346.0919178,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 388.569582264,
          "started_wall": 1792428346.074215,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 390.605310904,
          "finished_wall": 1792428348.1099439,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 390.587426876,
          "started_wall": 1792428348.0920594,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 392.623397448,
          "finished_wall": 1792428350.1280305,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 392.605463446,
          "started_wall": 1792428350.1100962,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 394.641325448,
          "finished_wall": 1792428352.1459584,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 394.623515452,
          "started_wall": 1792428352.1281483,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 396.659197148,
          "finished_wall": 1792428354.16383,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 396.64144616,
          "started_wall": 1792428354.1460788,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 398.677042522,
          "finished_wall": 1792428356.1816752,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 398.659296492,
          "started_wall": 1792428356.163929,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 400.694680796,
          "finished_wall": 1792428358.1993136,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 400.677165969,
          "started_wall": 1792428358.1817985,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 402.712624618,
          "finished_wall": 1792428360.2172575,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 402.694773269,
          "started_wall": 1792428360.199406,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 404.730858195,
          "finished_wall": 1792428362.235491,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 404.712729845,
          "started_wall": 1792428362.2173624,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 406.748865187,
          "finished_wall": 1792428364.2534983,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 406.730972837,
          "started_wall": 1792428364.2356055,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 408.766897307,
          "finished_wall": 1792428366.2715302,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 408.748988072,
          "started_wall": 1792428366.2536206,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 410.785438198,
          "finished_wall": 1792428368.2900712,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 410.767022255,
          "started_wall": 1792428368.2716548,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 412.803382662,
          "finished_wall": 1792428370.3080153,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 412.785558131,
          "started_wall": 1792428370.290191,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 414.821190764,
          "finished_wall": 1792428372.3258238,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 414.803495724,
          "started_wall": 1792428372.3081284,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 416.839274797,
          "finished_wall": 1792428374.3439078,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 416.821292931,
          "started_wall": 1792428374.3259254,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 418.857402998,
          "finished_wall": 1792428376.362036,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 418.839408964,
          "started_wall": 1792428376.3440416,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 420.875783405,
          "finished_wall": 1792428378.3804164,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 420.857569582,
          "started_wall": 1792428378.3622022,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 422.923847706,
          "finished_wall": 1792428380.4284809,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 422.87593064,
          "started_wall": 1792428380.3805633,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 424.941755919,
          "finished_wall": 1792428382.446389,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 424.923968051,
          "started_wall": 1792428382.4286005,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.010252086,
          "finished_wall": 1792428382.514885,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 424.99190802,
          "started_wall": 1792428382.4965408,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.077905348,
          "finished_wall": 1792428382.5825381,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.060367072,
          "started_wall": 1792428382.5649993,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.145972365,
          "finished_wall": 1792428382.6506052,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.1280181,
          "started_wall": 1792428382.6326509,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.214249105,
          "finished_wall": 1792428382.718882,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.196121632,
          "started_wall": 1792428382.700754,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.282204487,
          "finished_wall": 1792428382.7868376,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.264362219,
          "started_wall": 1792428382.7689948,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.350462098,
          "finished_wall": 1792428382.8550954,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.332341114,
          "started_wall": 1792428382.8369737,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.41887445,
          "finished_wall": 1792428382.9235075,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.400612677,
          "started_wall": 1792428382.905245,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.486742211,
          "finished_wall": 1792428382.9913752,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.468994393,
          "started_wall": 1792428382.9736269,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.55494435,
          "finished_wall": 1792428383.059577,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.53688656,
          "started_wall": 1792428383.0415192,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.62308055,
          "finished_wall": 1792428383.1277134,
          "http_status": 200,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.605061328,
          "started_wall": 1792428383.109694,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.67478444,
          "finished_wall": 1792428383.1794174,
          "http_status": 503,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.673182867,
          "started_wall": 1792428383.1778152,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.726390066,
          "finished_wall": 1792428383.2310228,
          "http_status": 503,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.724925636,
          "started_wall": 1792428383.2295582,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.777604459,
          "finished_wall": 1792428383.2822375,
          "http_status": 503,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.776466625,
          "started_wall": 1792428383.2810993,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.828706323,
          "finished_wall": 1792428383.3333392,
          "http_status": 503,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.827690851,
          "started_wall": 1792428383.3323236,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.879925112,
          "finished_wall": 1792428383.384558,
          "http_status": 503,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.878804965,
          "started_wall": 1792428383.3834374,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 425.931121578,
          "finished_wall": 1792428383.4357545,
          "http_status": 503,
          "lease_deadline": 425.903187629,
          "response_valid": true,
          "started_monotonic": 425.929999077,
          "started_wall": 1792428383.4346316,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 487.029733938,
        "document_sha256": "07884a2aefecf5fb29b6a5454944b619d5513fa001d39bb98d068d36f8ad130d",
        "monotonic": 427.037675043,
        "sequence": 41,
        "version": 1,
        "wall": 1792428384.5423076
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0.0,
    "stopped_worker_denial_seconds": 2.011746403000018
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:13cfa0ab458cc21c334c1d673aaa2b3c0863489d4e1e687780edd281b68ed7f3",
    "source_fingerprint": "aa9ffa0a6216e7f870370cf1e552bd626fc1971e7670726436f307da504d3916",
    "source_revision": "d2c48bf03ce6f669fd990538f01d47b82380f06c"
  },
  "source_dirty": false,
  "started_at": "2026-10-19T16:45:12.580739+00:00",
  "status": "pass",
  "subject_sha256": "b82c160c6236bf7daacfd7625f7d26f6a2179fec36aa6b43a111772285db9063"
}
```
