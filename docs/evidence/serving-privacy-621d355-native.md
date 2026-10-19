# Native serving privacy qualification 621d355

Источник: [Storage run 39276391635](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39276391635), job 118141671532, attempt 1. Полный sanitized actual-candidate report: 77 unique cases; private journal, canaries и credentials не опубликованы. Scope существующих serving outputs, не полный M13/R1. [Итог и ограничения](serving-privacy-2026-10-19.md).

```json
{
  "campaign_id": "4bc192cfad0e415b8bea2b9b4dd2f59d",
  "candidate_reference": "0aea144544f26a2f4ba753fb34f00a92e0e461a4e00aa83d1810b6832f8ad25c",
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
  "evaluation_reference": "b03219b6561173137e9d944c061f02254e6b84bbc6a7145f64d8e498c8e90d8a",
  "finished_at": "2026-10-19T15:23:58.372600+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634",
  "proposal_reference": "db8c31b0ce2494c48d727f0593e3de955df243c47211401cdef7434ec1ed2dd8",
  "qualification_permit_sha256": "23ac0ddea6145620e53a729f0df34ae8a5f708967897a5cba1a0b2f175234a55",
  "reference_response_sha256": "e1d14e42feb0dfd84b0229c50f759783bbd7b9b2c8c44a3e595e6abc8ef7e8b1",
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
      "window_seconds": 0.005949041999997462
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
      "approval_deadline": 1032.5927217006683,
      "denial": {
        "active_observed": {
          "monotonic": 516.493604648,
          "wall": 1792423427.9008825
        },
        "connected_read_entered": true,
        "finished_monotonic": 523.093255618,
        "finished_wall": 1792423434.5005345,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 516.407086796,
        "started_wall": 1792423427.8143647
      },
      "expected_trust": {
        "document_sha256": "e1b0cc614159c7664cd0f5c712a8679994543f10d8ab4cf98a636a8a0b82da8b",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 523.3403415679932,
        "document_sha256": "e1b0cc614159c7664cd0f5c712a8679994543f10d8ab4cf98a636a8a0b82da8b",
        "monotonic": 516.350699557,
        "sequence": 51,
        "version": 2,
        "wall": 1792423427.7579775
      },
      "policy_expires_at": 1792423435,
      "policy_expiry_monotonic": 523.5927221775055,
      "post_expiry": {
        "finished_monotonic": 523.644480845,
        "finished_wall": 1792423435.0517588,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 523.64292652,
        "started_wall": 1792423435.0502036
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 585.445390408,
        "document_sha256": "375be2dd701d0906fd451fa76de0d257b9b92eb5959f96b1399594f7156a01ff",
        "monotonic": 525.455469972,
        "sequence": 56,
        "version": 3,
        "wall": 1792423436.862748
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "375be2dd701d0906fd451fa76de0d257b9b92eb5959f96b1399594f7156a01ff",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 504.618786423,
          "wall": 1792423416.0260642
        },
        "connected_read_entered": true,
        "finished_monotonic": 514.519780322,
        "finished_wall": 1792423425.927059,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 504.517096906,
        "started_wall": 1792423415.9243748
      },
      "last_verified": {
        "deadline": 564.4516258890001,
        "document_sha256": "aaa836b77db5650950126c9a42021ab3254f40aac99c4b42bb9cfe3d46056da1",
        "monotonic": 504.461966028,
        "sequence": 43,
        "version": 1,
        "wall": 1792423415.869244
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 575.79442791,
        "document_sha256": "aaa836b77db5650950126c9a42021ab3254f40aac99c4b42bb9cfe3d46056da1",
        "monotonic": 515.804783353,
        "sequence": 49,
        "version": 1,
        "wall": 1792423427.2120614
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
        "first_503_seconds": 59.788612656,
        "last_200_seconds": 59.73589904299996,
        "observations": 43,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "aa215f573183214966db49da7f261e543b160b4d7f535f5514c8c0b8c950d88d",
        "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634"
      },
      "last_verified": {
        "deadline": 502.99055274,
        "document_sha256": "aaa836b77db5650950126c9a42021ab3254f40aac99c4b42bb9cfe3d46056da1",
        "monotonic": 443.000665527,
        "sequence": 36,
        "version": 1,
        "wall": 1792423354.4079437
      },
      "records": [
        {
          "finished_monotonic": 443.483527673,
          "finished_wall": 1792423354.8908062,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 443.460669656,
          "started_wall": 1792423354.8679478,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 445.506622107,
          "finished_wall": 1792423356.9139009,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 445.483690992,
          "started_wall": 1792423356.8909688,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 447.530711538,
          "finished_wall": 1792423358.9379902,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 447.506792832,
          "started_wall": 1792423358.914071,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 449.554427116,
          "finished_wall": 1792423360.9617057,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 449.530888454,
          "started_wall": 1792423360.9381666,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 451.577937099,
          "finished_wall": 1792423362.9852161,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 451.554644933,
          "started_wall": 1792423362.9619231,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 453.601380685,
          "finished_wall": 1792423365.0086594,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 453.578060586,
          "started_wall": 1792423364.9853387,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 455.624724792,
          "finished_wall": 1792423367.0320034,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 455.601529636,
          "started_wall": 1792423367.0088077,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 457.648531547,
          "finished_wall": 1792423369.0558102,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 457.624848664,
          "started_wall": 1792423369.0321267,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 459.67162726,
          "finished_wall": 1792423371.0789058,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 459.648724688,
          "started_wall": 1792423371.0560029,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 461.695413445,
          "finished_wall": 1792423373.1026921,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 461.671822784,
          "started_wall": 1792423373.0791008,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 463.718347241,
          "finished_wall": 1792423375.1256258,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 463.695545672,
          "started_wall": 1792423375.102824,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 465.742030986,
          "finished_wall": 1792423377.1493094,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 465.718519181,
          "started_wall": 1792423377.1257973,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 467.765026632,
          "finished_wall": 1792423379.172305,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 467.742165045,
          "started_wall": 1792423379.1494431,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 469.787408623,
          "finished_wall": 1792423381.1946871,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 469.765154451,
          "started_wall": 1792423381.1724327,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 471.810975017,
          "finished_wall": 1792423383.2182539,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 471.787537756,
          "started_wall": 1792423383.1948156,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 473.834296247,
          "finished_wall": 1792423385.241575,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 473.811196068,
          "started_wall": 1792423385.2184741,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 475.856758865,
          "finished_wall": 1792423387.2640374,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 475.834422574,
          "started_wall": 1792423387.2417006,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 477.879629423,
          "finished_wall": 1792423389.286908,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 477.856887222,
          "started_wall": 1792423389.2641654,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 479.902899814,
          "finished_wall": 1792423391.3101783,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 479.879897626,
          "started_wall": 1792423391.2871757,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 481.926372145,
          "finished_wall": 1792423393.3336506,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 481.903111972,
          "started_wall": 1792423393.31039,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 483.949552117,
          "finished_wall": 1792423395.3568308,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 483.926500947,
          "started_wall": 1792423395.333779,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 485.972577633,
          "finished_wall": 1792423397.379856,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 485.949699866,
          "started_wall": 1792423397.356978,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 487.995528687,
          "finished_wall": 1792423399.4028072,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 487.972697089,
          "started_wall": 1792423399.379975,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 490.01887351,
          "finished_wall": 1792423401.4261522,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 489.995702745,
          "started_wall": 1792423401.4029808,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 492.041839799,
          "finished_wall": 1792423403.4491184,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 492.019040628,
          "started_wall": 1792423403.426319,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 494.064816208,
          "finished_wall": 1792423405.4720948,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 494.041966065,
          "started_wall": 1792423405.4492443,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 496.087201347,
          "finished_wall": 1792423407.49448,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 496.065092437,
          "started_wall": 1792423407.4723706,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 498.11076935,
          "finished_wall": 1792423409.518048,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 498.087325606,
          "started_wall": 1792423409.4946039,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 500.133055898,
          "finished_wall": 1792423411.5403342,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 500.110904165,
          "started_wall": 1792423411.5181825,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.156778211,
          "finished_wall": 1792423413.5640569,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.13321451,
          "started_wall": 1792423413.5404925,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.228559893,
          "finished_wall": 1792423413.6358385,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.206893885,
          "started_wall": 1792423413.6141722,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.300851701,
          "finished_wall": 1792423413.7081304,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.278745063,
          "started_wall": 1792423413.6860232,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.373618845,
          "finished_wall": 1792423413.7808974,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.351029671,
          "started_wall": 1792423413.758308,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.445423301,
          "finished_wall": 1792423413.852702,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.423732554,
          "started_wall": 1792423413.8310108,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.517522387,
          "finished_wall": 1792423413.924801,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.495653756,
          "started_wall": 1792423413.902932,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.59048093,
          "finished_wall": 1792423413.9977598,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.567653477,
          "started_wall": 1792423413.9749317,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.66391137,
          "finished_wall": 1792423414.0711896,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.640626702,
          "started_wall": 1792423414.0479047,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.73656457,
          "finished_wall": 1792423414.1438434,
          "http_status": 200,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.714061899,
          "started_wall": 1792423414.1213403,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.789278183,
          "finished_wall": 1792423414.1965568,
          "http_status": 503,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.786801908,
          "started_wall": 1792423414.19408,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.841117936,
          "finished_wall": 1792423414.2483966,
          "http_status": 503,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.839372697,
          "started_wall": 1792423414.246651,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.892513618,
          "finished_wall": 1792423414.299792,
          "http_status": 503,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.891204499,
          "started_wall": 1792423414.2984827,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.943910278,
          "finished_wall": 1792423414.351189,
          "http_status": 503,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.942637984,
          "started_wall": 1792423414.3499162,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 502.995520488,
          "finished_wall": 1792423414.4027991,
          "http_status": 503,
          "lease_deadline": 502.99055274,
          "response_valid": true,
          "started_monotonic": 502.994046758,
          "started_wall": 1792423414.4013247,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 564.410750608,
        "document_sha256": "aaa836b77db5650950126c9a42021ab3254f40aac99c4b42bb9cfe3d46056da1",
        "monotonic": 504.420390588,
        "sequence": 41,
        "version": 1,
        "wall": 1792423415.8276687
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0.0,
    "stopped_worker_denial_seconds": 2.014582000999951
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:9661a1bc0891fdb54bee4cf952e8c14834b0771e4244a01633c479e813b9f6d9",
    "source_fingerprint": "f89b7b371d241bd5e6a0dfd9716e8ec071d0efe607e734dfddf7ff5d6029ecc7",
    "source_revision": "621d3550495220199087a64ed31067e9ac67952f"
  },
  "source_dirty": false,
  "started_at": "2026-10-19T15:22:21.912248+00:00",
  "status": "pass",
  "subject_sha256": "aa215f573183214966db49da7f261e543b160b4d7f535f5514c8c0b8c950d88d"
}
```
