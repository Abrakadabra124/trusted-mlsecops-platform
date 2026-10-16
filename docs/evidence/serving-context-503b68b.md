# Actual-candidate native report: 503b68b, attempt 2

Полный очищенный JSON report, прочитанный из [Storage CI attempt 2](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124426/attempts/2), job `117113836984`. Code commit `503b68bbde0fb619132a0e1d797b0173ec55d3f5`; 72 cases pass, source_dirty=false, release_ready=false. Это qualification, не production release approval. [Контекст и неудачные попытки](serving-context-2026-10-16.md).

```json
{
  "campaign_id": "80e96787fd4b4745b260893e277e525d",
  "candidate_reference": "6f0dd75af78fe837358f39d11132f58cab5a554ef954fbb8822522d51c975477",
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
    "actual-candidate-revocation-http-503",
    "actual-candidate-revocation-readiness-503",
    "qualification-authority-and-private-key-removed",
    "source-cas-budget-envelopes-and-checkout-unchanged"
  ],
  "evaluation_reference": "d63d7e7d04a8fd14066e94ead669dd161384f6a374312458983e9e346ec578e9",
  "finished_at": "2026-10-16T17:57:41.271415+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f",
  "proposal_reference": "32c0485d78f57bd82912eec7d04a4b165d4267537b19de28cf601ff5f3a97888",
  "qualification_permit_sha256": "9c9dcb921f9159bd5b89c4a542c676482aa3572b0443eb22ecb7a07b61a445e3",
  "reference_response_sha256": "521a642f7ec497a348c37a4592114a24b6df1a7453669154e9e8a174befe2b03",
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
      "window_seconds": 0.0036860969999565896
    },
    "golden_rows": 3,
    "http_expiring_query": {
      "approval_deadline": 1084.8765215873718,
      "denial": {
        "active_observed": {
          "monotonic": 568.97022533,
          "wall": 1792173451.0937033
        },
        "connected_read_entered": true,
        "finished_monotonic": 575.582048223,
        "finished_wall": 1792173457.7055268,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 568.883763049,
        "started_wall": 1792173451.0072408
      },
      "expected_trust": {
        "document_sha256": "92851af205652569eac3faec6c55c4f223eb7e34365b0f5a1d349608df0583bb",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 575.8307526111603,
        "document_sha256": "92851af205652569eac3faec6c55c4f223eb7e34365b0f5a1d349608df0583bb",
        "monotonic": 568.840442474,
        "sequence": 51,
        "version": 2,
        "wall": 1792173450.9639204
      },
      "policy_expires_at": 1792173458,
      "policy_expiry_monotonic": 575.876522064209,
      "post_expiry": {
        "finished_monotonic": 575.928036277,
        "finished_wall": 1792173458.0515141,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 575.926632444,
        "started_wall": 1792173458.0501099
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 637.734872038,
        "document_sha256": "6b1a03c9962d7eb40a98e7ba8be0e2c9138fea2cb7938723b6e9cb2a95dd96c2",
        "monotonic": 577.745438696,
        "sequence": 56,
        "version": 3,
        "wall": 1792173459.8689167
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "6b1a03c9962d7eb40a98e7ba8be0e2c9138fea2cb7938723b6e9cb2a95dd96c2",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 557.080080116,
          "wall": 1792173439.203558
        },
        "connected_read_entered": true,
        "finished_monotonic": 566.995155047,
        "finished_wall": 1792173449.1186337,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 556.99361035,
        "started_wall": 1792173439.1170883
      },
      "last_verified": {
        "deadline": 616.939340784,
        "document_sha256": "68bbd37c957976a9d446e75cebe132986ab9b5ca6fa656a97efaaef9fe93613a",
        "monotonic": 556.94934535,
        "sequence": 43,
        "version": 1,
        "wall": 1792173439.0728233
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 628.260439547,
        "document_sha256": "68bbd37c957976a9d446e75cebe132986ab9b5ca6fa656a97efaaef9fe93613a",
        "monotonic": 568.270532264,
        "sequence": 49,
        "version": 1,
        "wall": 1792173450.39401
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "http_trust_outage": {
      "assessment": {
        "failures": [],
        "first_503_seconds": 59.74186084600001,
        "last_200_seconds": 59.68224226999996,
        "observations": 52,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "6decef6c065b950160789d7be46c4c9da2a30010d23fc0198f78df72ac08444e",
        "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f"
      },
      "last_verified": {
        "deadline": 555.457894301,
        "document_sha256": "68bbd37c957976a9d446e75cebe132986ab9b5ca6fa656a97efaaef9fe93613a",
        "monotonic": 495.467450578,
        "sequence": 36,
        "version": 1,
        "wall": 1792173377.5909286
      },
      "records": [
        {
          "finished_monotonic": 495.889197947,
          "finished_wall": 1792173378.0126762,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 495.879259351,
          "started_wall": 1792173378.0027375,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 497.899604358,
          "finished_wall": 1792173380.0230827,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 497.889352205,
          "started_wall": 1792173380.0128303,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 499.909665661,
          "finished_wall": 1792173382.033144,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 499.899711288,
          "started_wall": 1792173382.0231893,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 501.919819985,
          "finished_wall": 1792173384.0432982,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 501.909818489,
          "started_wall": 1792173384.0332966,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 503.930861373,
          "finished_wall": 1792173386.0543396,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 503.919950664,
          "started_wall": 1792173386.0434287,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 505.941596757,
          "finished_wall": 1792173388.065075,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 505.930997686,
          "started_wall": 1792173388.0544758,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 507.952187804,
          "finished_wall": 1792173390.0756662,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 507.941736452,
          "started_wall": 1792173390.0652144,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.962939084,
          "finished_wall": 1792173392.0864174,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 509.952322981,
          "started_wall": 1792173392.0758011,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 511.97409787,
          "finished_wall": 1792173394.0975761,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 511.963093012,
          "started_wall": 1792173394.086571,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 513.984776399,
          "finished_wall": 1792173396.1082547,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 513.974219377,
          "started_wall": 1792173396.0976975,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 515.994992388,
          "finished_wall": 1792173398.1184707,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 515.984914582,
          "started_wall": 1792173398.1083927,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 518.005465335,
          "finished_wall": 1792173400.1289437,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 517.995155873,
          "started_wall": 1792173400.118634,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 520.015927803,
          "finished_wall": 1792173402.1394064,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 520.005586309,
          "started_wall": 1792173402.1290646,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 522.025949304,
          "finished_wall": 1792173404.1494277,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 522.016070725,
          "started_wall": 1792173404.1395488,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 524.036160739,
          "finished_wall": 1792173406.1596391,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 524.026085184,
          "started_wall": 1792173406.149563,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 526.04669514,
          "finished_wall": 1792173408.1701734,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 526.036295766,
          "started_wall": 1792173408.1597736,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 528.057472091,
          "finished_wall": 1792173410.1809506,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 528.046832706,
          "started_wall": 1792173410.1703107,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 530.06833874,
          "finished_wall": 1792173412.191817,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 530.057605758,
          "started_wall": 1792173412.1810837,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 532.079144599,
          "finished_wall": 1792173414.202623,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 532.06850785,
          "started_wall": 1792173414.1919858,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 534.089981862,
          "finished_wall": 1792173416.2134602,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 534.079250978,
          "started_wall": 1792173416.202729,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 536.101276639,
          "finished_wall": 1792173418.224755,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 536.090144377,
          "started_wall": 1792173418.2136223,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 538.111834033,
          "finished_wall": 1792173420.2353125,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 538.101413268,
          "started_wall": 1792173420.2248912,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 540.122122568,
          "finished_wall": 1792173422.2456007,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 540.111975192,
          "started_wall": 1792173422.2354531,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 542.132876233,
          "finished_wall": 1792173424.2563546,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 542.122227961,
          "started_wall": 1792173424.245706,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 544.143228678,
          "finished_wall": 1792173426.266707,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 544.133012376,
          "started_wall": 1792173426.2564905,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 546.153458135,
          "finished_wall": 1792173428.2769365,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 546.14336159,
          "started_wall": 1792173428.2668395,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 548.163810119,
          "finished_wall": 1792173430.2872887,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 548.153605059,
          "started_wall": 1792173430.2770832,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 550.174321513,
          "finished_wall": 1792173432.2977998,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 550.163948009,
          "started_wall": 1792173432.287426,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 552.184455194,
          "finished_wall": 1792173434.3079338,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 552.174457612,
          "started_wall": 1792173434.2979357,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.195386332,
          "finished_wall": 1792173436.3188646,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.184592307,
          "started_wall": 1792173436.3080704,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.255366344,
          "finished_wall": 1792173436.3788447,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.245509995,
          "started_wall": 1792173436.3689883,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.315214868,
          "finished_wall": 1792173436.438693,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.305499104,
          "started_wall": 1792173436.4289773,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.374002732,
          "finished_wall": 1792173436.497481,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.365304849,
          "started_wall": 1792173436.488783,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.433787581,
          "finished_wall": 1792173436.557266,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.424157769,
          "started_wall": 1792173436.5476358,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.493960336,
          "finished_wall": 1792173436.6174388,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.483922635,
          "started_wall": 1792173436.6074007,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.553947193,
          "finished_wall": 1792173436.6774256,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.54409763,
          "started_wall": 1792173436.6675756,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.613874195,
          "finished_wall": 1792173436.7373524,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.604079285,
          "started_wall": 1792173436.7275574,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.672926375,
          "finished_wall": 1792173436.7964048,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.663990378,
          "started_wall": 1792173436.7874684,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.732904773,
          "finished_wall": 1792173436.8563833,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.723018234,
          "started_wall": 1792173436.8464963,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.792523255,
          "finished_wall": 1792173436.9160016,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.783002848,
          "started_wall": 1792173436.9064808,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.851904081,
          "finished_wall": 1792173436.9753823,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.842635488,
          "started_wall": 1792173436.9661136,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.911731387,
          "finished_wall": 1792173437.0352097,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.902002289,
          "started_wall": 1792173437.0254805,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 554.971709269,
          "finished_wall": 1792173437.0951874,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 554.961830093,
          "started_wall": 1792173437.085308,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 555.031255937,
          "finished_wall": 1792173437.1547344,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 555.0218047,
          "started_wall": 1792173437.1452827,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 555.090488934,
          "finished_wall": 1792173437.2139673,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 555.081354894,
          "started_wall": 1792173437.204833,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 555.149692848,
          "finished_wall": 1792173437.2731712,
          "http_status": 200,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 555.140582593,
          "started_wall": 1792173437.2640607,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 555.209311424,
          "finished_wall": 1792173437.3327897,
          "http_status": 503,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 555.199819218,
          "started_wall": 1792173437.3232973,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 555.262263975,
          "finished_wall": 1792173437.3857424,
          "http_status": 503,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 555.259697735,
          "started_wall": 1792173437.3831756,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 555.31358287,
          "finished_wall": 1792173437.437061,
          "http_status": 503,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 555.312362662,
          "started_wall": 1792173437.4358408,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 555.364919028,
          "finished_wall": 1792173437.4883976,
          "http_status": 503,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 555.363671809,
          "started_wall": 1792173437.4871497,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 555.416318416,
          "finished_wall": 1792173437.5397968,
          "http_status": 503,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 555.415015082,
          "started_wall": 1792173437.5384932,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 555.467611895,
          "finished_wall": 1792173437.5910902,
          "http_status": 503,
          "lease_deadline": 555.457894301,
          "response_valid": true,
          "started_monotonic": 555.466410433,
          "started_wall": 1792173437.5898886,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 616.91039377,
        "document_sha256": "68bbd37c957976a9d446e75cebe132986ab9b5ca6fa656a97efaaef9fe93613a",
        "monotonic": 556.919943833,
        "sequence": 41,
        "version": 1,
        "wall": 1792173439.043422
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0,
    "stopped_worker_denial_seconds": 2.014195480000012
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:abcb339a52ccce3e3790118c51d60654ffcc814634a616f1bda4ff06728d1665",
    "source_fingerprint": "ba76619b9a6231b2d120ed117b711e3b0413bbe849fac6c593a6f75e82a98bbc",
    "source_revision": "503b68bbde0fb619132a0e1d797b0173ec55d3f5"
  },
  "source_dirty": false,
  "started_at": "2026-10-16T17:56:05.129154+00:00",
  "status": "pass",
  "subject_sha256": "6decef6c065b950160789d7be46c4c9da2a30010d23fc0198f78df72ac08444e"
}
```
