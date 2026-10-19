# Native worker privacy qualification af7253e

Источник: [Storage run 39283688533](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39283688533), job 118163593269, attempt 1. Code commit `af7253e91a6709800b9d9e1e7febf0f34cd2e427`. Kernel receipt и полный sanitized actual-candidate report сохранены из job logs; итоговая CI matrix и ограничения приведены в [evidence](worker-privacy-2026-10-19.md). Private journals, canaries, credentials, model bytes и raw logs не опубликованы.

## Worker kernel receipt

Отдельный disposable Linux subprocess: baseline dumpability 1 проверяется assertion, затем readback 0 и soft/hard core [0,0]. Child завершён SIGABRT; wait status не содержит core flag. Это не проверка privileged host или controller memory policy.

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

77 unique cases, без новых фиктивных release approvals. Qualification permission не является разрешением выпуска. Report сохраняет числовые значения исходного JSON; только whitespace изменён.

```json
{
  "campaign_id": "cca9a0f5444b438b98b45e5586da872e",
  "candidate_reference": "c160ccbe866d8fbabac8e4aa1fbd5d08352a12aabc7c2416306143616ea90b57",
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
  "evaluation_reference": "7de341a31fd85fabfa7d693a446ef0d8d1a72cc3aa421985630c5d6e6e98f260",
  "finished_at": "2026-10-19T16:21:12.184010+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634",
  "proposal_reference": "607bc1464322afee42002276c9dbd1681706eba67acddc71941bfbfb3a4f4376",
  "qualification_permit_sha256": "4946f014eef97a7202c0435778a389fe8ae918b31c29d5aa084ba9667b9d2f08",
  "reference_response_sha256": "f7e56b09e8754f8a2230cf4a39c06e5c0bac4946277eb251bac3e1559be74194",
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
      "window_seconds": 0.00553302700001268
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
      "approval_deadline": 1025.3110558986664,
      "denial": {
        "active_observed": {
          "monotonic": 509.348274255,
          "wall": 1792426862.0372179
        },
        "connected_read_entered": true,
        "finished_monotonic": 515.956942013,
        "finished_wall": 1792426868.6458864,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 509.267071565,
        "started_wall": 1792426861.956015
      },
      "expected_trust": {
        "document_sha256": "0767eeda129150b6fbad18e574a53e524e91a77ce302001d2e8e942a6eeefc5e",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 516.2054147720337,
        "document_sha256": "0767eeda129150b6fbad18e574a53e524e91a77ce302001d2e8e942a6eeefc5e",
        "monotonic": 509.214350901,
        "sequence": 51,
        "version": 2,
        "wall": 1792426861.9032948
      },
      "policy_expires_at": 1792426869,
      "policy_expiry_monotonic": 516.311056137085,
      "post_expiry": {
        "finished_monotonic": 516.362606036,
        "finished_wall": 1792426869.0515497,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 516.361127285,
        "started_wall": 1792426869.0500708
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 578.068134086,
        "document_sha256": "9b9eca6b197957078fa16ba90167373d458bb3c39c473227cac677d9b2356aad",
        "monotonic": 518.077716855,
        "sequence": 56,
        "version": 3,
        "wall": 1792426870.7666607
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "9b9eca6b197957078fa16ba90167373d458bb3c39c473227cac677d9b2356aad",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 497.560110466,
          "wall": 1792426850.249054
        },
        "connected_read_entered": true,
        "finished_monotonic": 507.481220168,
        "finished_wall": 1792426860.1701648,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 497.478721594,
        "started_wall": 1792426850.1676652
      },
      "last_verified": {
        "deadline": 557.417103275,
        "document_sha256": "3862cf23eca86fdb7f0cb01ac74762e5fe0383d41de074ee91234a8ffb164b9a",
        "monotonic": 497.426470706,
        "sequence": 43,
        "version": 1,
        "wall": 1792426850.1154146
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 568.6817322429999,
        "document_sha256": "3862cf23eca86fdb7f0cb01ac74762e5fe0383d41de074ee91234a8ffb164b9a",
        "monotonic": 508.691509877,
        "sequence": 49,
        "version": 1,
        "wall": 1792426861.3804536
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
        "first_503_seconds": 59.747452987999964,
        "last_200_seconds": 59.69493474699999,
        "observations": 44,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "2b7cc3387f9027ff2ac1658309b03f42f10c47fef7e50e2ce70de0c90c5134f9",
        "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634"
      },
      "last_verified": {
        "deadline": 495.993470133,
        "document_sha256": "3862cf23eca86fdb7f0cb01ac74762e5fe0383d41de074ee91234a8ffb164b9a",
        "monotonic": 436.003450503,
        "sequence": 36,
        "version": 1,
        "wall": 1792426788.6923943
      },
      "records": [
        {
          "finished_monotonic": 436.458899704,
          "finished_wall": 1792426789.147844,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 436.436852503,
          "started_wall": 1792426789.1257963,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 438.481332057,
          "finished_wall": 1792426791.1702764,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 438.459138516,
          "started_wall": 1792426791.1480823,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 440.504078424,
          "finished_wall": 1792426793.1930227,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 440.481591592,
          "started_wall": 1792426793.1705353,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 442.526741001,
          "finished_wall": 1792426795.2156851,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 442.504184206,
          "started_wall": 1792426795.1931279,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 444.550081536,
          "finished_wall": 1792426797.2390258,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 444.527125906,
          "started_wall": 1792426797.2160697,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 446.572747898,
          "finished_wall": 1792426799.261692,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 446.550188777,
          "started_wall": 1792426799.2391326,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 448.594945648,
          "finished_wall": 1792426801.28389,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 448.572863471,
          "started_wall": 1792426801.2618074,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 450.617627196,
          "finished_wall": 1792426803.3065715,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 450.595044155,
          "started_wall": 1792426803.283988,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 452.640273927,
          "finished_wall": 1792426805.3292181,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 452.617732887,
          "started_wall": 1792426805.3066766,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 454.661369692,
          "finished_wall": 1792426807.350314,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 454.640381878,
          "started_wall": 1792426807.3293257,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 456.683901208,
          "finished_wall": 1792426809.3728456,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 456.661511914,
          "started_wall": 1792426809.3504558,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 458.706459317,
          "finished_wall": 1792426811.3954036,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 458.684029673,
          "started_wall": 1792426811.3729737,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 460.728829496,
          "finished_wall": 1792426813.4177737,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 460.706572706,
          "started_wall": 1792426813.3955164,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 462.751684858,
          "finished_wall": 1792426815.4406292,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 462.729164306,
          "started_wall": 1792426815.4181082,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 464.774240993,
          "finished_wall": 1792426817.463185,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 464.751915646,
          "started_wall": 1792426817.4408593,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 466.797144964,
          "finished_wall": 1792426819.4860892,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 466.774448011,
          "started_wall": 1792426819.4633918,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 468.820212376,
          "finished_wall": 1792426821.5091567,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 468.797303311,
          "started_wall": 1792426821.486247,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 470.842278068,
          "finished_wall": 1792426823.5312223,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 470.8203682,
          "started_wall": 1792426823.509312,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 472.865515183,
          "finished_wall": 1792426825.5544593,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 472.84251509,
          "started_wall": 1792426825.5314589,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 474.888666632,
          "finished_wall": 1792426827.5776107,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 474.86563484,
          "started_wall": 1792426827.5545788,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 476.911693695,
          "finished_wall": 1792426829.600638,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 476.888808606,
          "started_wall": 1792426829.5777524,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 478.934468398,
          "finished_wall": 1792426831.6234124,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 478.91183084,
          "started_wall": 1792426831.6007748,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 480.958194119,
          "finished_wall": 1792426833.6471384,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 480.934713031,
          "started_wall": 1792426833.623657,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 482.981025015,
          "finished_wall": 1792426835.6699693,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 482.958345172,
          "started_wall": 1792426835.647289,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 485.003539712,
          "finished_wall": 1792426837.692484,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 484.981183495,
          "started_wall": 1792426837.6701274,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 487.027648416,
          "finished_wall": 1792426839.7165926,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 487.003842156,
          "started_wall": 1792426839.692786,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 489.05115188,
          "finished_wall": 1792426841.740096,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 489.027760448,
          "started_wall": 1792426841.7167044,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 491.073665917,
          "finished_wall": 1792426843.7626102,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 491.051271538,
          "started_wall": 1792426843.7402153,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 493.095554355,
          "finished_wall": 1792426845.7844987,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 493.073901486,
          "started_wall": 1792426845.7628453,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.11885265,
          "finished_wall": 1792426847.807797,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.095696825,
          "started_wall": 1792426847.7846406,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.191125371,
          "finished_wall": 1792426847.8800697,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.168960585,
          "started_wall": 1792426847.8579044,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.263034398,
          "finished_wall": 1792426847.9519784,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.241253959,
          "started_wall": 1792426847.9301977,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.335869265,
          "finished_wall": 1792426848.0248137,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.313150599,
          "started_wall": 1792426848.0020943,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.408086076,
          "finished_wall": 1792426848.0970304,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.386021654,
          "started_wall": 1792426848.0749655,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.480860097,
          "finished_wall": 1792426848.1698043,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.45824409,
          "started_wall": 1792426848.147188,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.553303775,
          "finished_wall": 1792426848.2422478,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.530984147,
          "started_wall": 1792426848.219928,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.625738494,
          "finished_wall": 1792426848.314683,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.603518522,
          "started_wall": 1792426848.2924623,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.69838525,
          "finished_wall": 1792426848.3873293,
          "http_status": 200,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.675851902,
          "started_wall": 1792426848.3647957,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.750903491,
          "finished_wall": 1792426848.439848,
          "http_status": 503,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.748708047,
          "started_wall": 1792426848.4376519,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.80253756,
          "finished_wall": 1792426848.4914818,
          "http_status": 503,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.800994301,
          "started_wall": 1792426848.4899383,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.853863509,
          "finished_wall": 1792426848.5428078,
          "http_status": 503,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.852621547,
          "started_wall": 1792426848.5415654,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.905300104,
          "finished_wall": 1792426848.5942442,
          "http_status": 503,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.90402341,
          "started_wall": 1792426848.5929673,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.956831246,
          "finished_wall": 1792426848.6457753,
          "http_status": 503,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 495.955428275,
          "started_wall": 1792426848.6443722,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 496.008347478,
          "finished_wall": 1792426848.6972916,
          "http_status": 503,
          "lease_deadline": 495.993470133,
          "response_valid": true,
          "started_monotonic": 496.006949403,
          "started_wall": 1792426848.6958933,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 557.380737511,
        "document_sha256": "3862cf23eca86fdb7f0cb01ac74762e5fe0383d41de074ee91234a8ffb164b9a",
        "monotonic": 497.389580555,
        "sequence": 41,
        "version": 1,
        "wall": 1792426850.0785244
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0.0,
    "stopped_worker_denial_seconds": 2.0138136269999904
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:4ee6e46110f48213a77e7c9c32fc44f1c6051576789f60990a06041b446687c5",
    "source_fingerprint": "aa9ffa0a6216e7f870370cf1e552bd626fc1971e7670726436f307da504d3916",
    "source_revision": "af7253e91a6709800b9d9e1e7febf0f34cd2e427"
  },
  "source_dirty": false,
  "started_at": "2026-10-19T16:19:36.502472+00:00",
  "status": "pass",
  "subject_sha256": "2b7cc3387f9027ff2ac1658309b03f42f10c47fef7e50e2ce70de0c90c5134f9"
}
```
