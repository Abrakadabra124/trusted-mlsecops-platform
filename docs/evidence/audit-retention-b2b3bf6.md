# Audit retention increment: native serving regression b2b3bf6

Полный sanitized actual-candidate regression report. [Storage CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38928710730), job `117066845457`, clean code `b2b3bf65b7b740318c5f5d0086fa380a14b834b1`. [Evidence и ограничения](audit-retention-2026-10-16.md).

Это регрессия существующего HTTP serving после добавления opt-in retained audit backend. Журнал ещё не подключён к HTTP: данный report не доказывает audit correlation или полный M13. Native storage contracts подтверждены отдельными 51 tests в том же CI job. Qualification permission не является release approval; image/ML failures сохраняют блокировку выпуска.

```json
{
  "campaign_id": "7c11f550be1c4c75b70ec795bb3161e1",
  "candidate_reference": "8f4f9898b8b11465d9e0fea775bb25780aefe5515a1fc9e71a6da1caa85a1423",
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
  "evaluation_reference": "e24b1a50a11bedadd3cc974dc50387aa7d93d09822d1ae12882394bbc12400c9",
  "finished_at": "2026-10-16T16:09:02.139836+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634",
  "proposal_reference": "c7b98d7a3bf69c48760c1b6c48d776d2c3bad29888b7bf2b539bd923f8c54f10",
  "qualification_permit_sha256": "cf42b888372e12b048f2fac297b81afdd3189fae7b376e2266726565894fe11e",
  "reference_response_sha256": "009990cbd9607052d9fa4ea461b48c647da5d8da30cfeaa3f4f69542c9ee6f86",
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
      "window_seconds": 0.0029482709999797407
    },
    "golden_rows": 3,
    "http_expiring_query": {
      "approval_deadline": 1006.6826059818268,
      "denial": {
        "active_observed": {
          "monotonic": 488.494315085,
          "wall": 1792166931.8117082
        },
        "connected_read_entered": true,
        "finished_monotonic": 495.124037976,
        "finished_wall": 1792166938.441432,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 488.418231196,
        "started_wall": 1792166931.7356246
      },
      "expected_trust": {
        "document_sha256": "f5a5a765c1f5e70c0a0d9f12121cc82cd6e39e8366632674a39eae3c5708e6bb",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 495.37318992614746,
        "document_sha256": "f5a5a765c1f5e70c0a0d9f12121cc82cd6e39e8366632674a39eae3c5708e6bb",
        "monotonic": 488.381405532,
        "sequence": 43,
        "version": 2,
        "wall": 1792166931.698799
      },
      "policy_expires_at": 1792166939,
      "policy_expiry_monotonic": 495.6826066970825,
      "post_expiry": {
        "finished_monotonic": 495.734079846,
        "finished_wall": 1792166939.051473,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 495.732711716,
        "started_wall": 1792166939.0501041
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 557.202409339,
        "document_sha256": "b021abdd3bbb66a7852a523d9998f4dcca2e9afb626480e2e690dca4dfad39c9",
        "monotonic": 497.211162933,
        "sequence": 48,
        "version": 3,
        "wall": 1792166940.5285563
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "b021abdd3bbb66a7852a523d9998f4dcca2e9afb626480e2e690dca4dfad39c9",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 476.938661766,
          "wall": 1792166920.2560549
        },
        "connected_read_entered": true,
        "finished_monotonic": 486.859336469,
        "finished_wall": 1792166930.1767306,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 476.857554807,
        "started_wall": 1792166920.1749475
      },
      "last_verified": {
        "deadline": 536.812117208,
        "document_sha256": "a6ab46608fb48ac05e632c6ff0a479d9e8879554802fecf629ab1a919661eadd",
        "monotonic": 476.820716201,
        "sequence": 35,
        "version": 1,
        "wall": 1792166920.1381094
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 547.916766534,
        "document_sha256": "a6ab46608fb48ac05e632c6ff0a479d9e8879554802fecf629ab1a919661eadd",
        "monotonic": 487.925403198,
        "sequence": 41,
        "version": 1,
        "wall": 1792166931.2427967
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "http_trust_outage": {
      "assessment": {
        "failures": [],
        "first_503_seconds": 59.761295787999984,
        "last_200_seconds": 59.709320177999984,
        "observations": 54,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "d0b3b3bee051d06501be5bde2e3e14f3577c3fa7d876869591018d3206d9e858",
        "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634"
      },
      "last_verified": {
        "deadline": 475.637019238,
        "document_sha256": "a6ab46608fb48ac05e632c6ff0a479d9e8879554802fecf629ab1a919661eadd",
        "monotonic": 415.645449922,
        "sequence": 28,
        "version": 1,
        "wall": 1792166858.9628432
      },
      "records": [
        {
          "finished_monotonic": 416.0622304,
          "finished_wall": 1792166859.3796241,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 416.054568596,
          "started_wall": 1792166859.3719618,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 418.070408442,
          "finished_wall": 1792166861.3878021,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 418.062372004,
          "started_wall": 1792166861.3797653,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 420.078263516,
          "finished_wall": 1792166863.3956573,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 420.070525349,
          "started_wall": 1792166863.3879187,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 422.086605807,
          "finished_wall": 1792166865.4039996,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 422.07843212,
          "started_wall": 1792166865.3958254,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 424.09468475,
          "finished_wall": 1792166867.4120784,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 424.08672683,
          "started_wall": 1792166867.40412,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 426.102642965,
          "finished_wall": 1792166869.4200366,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 426.09478048,
          "started_wall": 1792166869.4121735,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 428.110340661,
          "finished_wall": 1792166871.4277344,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 428.102757528,
          "started_wall": 1792166871.4201508,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 430.118047947,
          "finished_wall": 1792166873.4354417,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 430.110444174,
          "started_wall": 1792166873.4278374,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 432.126839993,
          "finished_wall": 1792166875.4442337,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 432.118165198,
          "started_wall": 1792166875.4355583,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 434.134479828,
          "finished_wall": 1792166877.4518733,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 434.126952519,
          "started_wall": 1792166877.444346,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 436.142511812,
          "finished_wall": 1792166879.4599056,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 436.134597618,
          "started_wall": 1792166879.451991,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 438.150627242,
          "finished_wall": 1792166881.468021,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 438.142636803,
          "started_wall": 1792166881.4600298,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 440.159088646,
          "finished_wall": 1792166883.4764824,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 440.150757781,
          "started_wall": 1792166883.4681509,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 442.167756065,
          "finished_wall": 1792166885.4851496,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 442.159228314,
          "started_wall": 1792166885.4766214,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 444.175837759,
          "finished_wall": 1792166887.4932313,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 444.167871919,
          "started_wall": 1792166887.4852653,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 446.184191219,
          "finished_wall": 1792166889.501585,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 446.176033848,
          "started_wall": 1792166889.4934273,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 448.192205341,
          "finished_wall": 1792166891.509599,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 448.184356007,
          "started_wall": 1792166891.5017493,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 450.200096216,
          "finished_wall": 1792166893.51749,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 450.19231246,
          "started_wall": 1792166893.5097058,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 452.208617739,
          "finished_wall": 1792166895.5260115,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 452.200216699,
          "started_wall": 1792166895.51761,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 454.216879202,
          "finished_wall": 1792166897.5342727,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 454.208766427,
          "started_wall": 1792166897.5261595,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 456.224673486,
          "finished_wall": 1792166899.5420673,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 456.216983853,
          "started_wall": 1792166899.5343769,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 458.2325198,
          "finished_wall": 1792166901.5499136,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 458.224818281,
          "started_wall": 1792166901.5422115,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 460.240551284,
          "finished_wall": 1792166903.557945,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 460.232666037,
          "started_wall": 1792166903.550059,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 462.248313362,
          "finished_wall": 1792166905.565707,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 462.24066329,
          "started_wall": 1792166905.5580564,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 464.256281512,
          "finished_wall": 1792166907.5736752,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 464.248471669,
          "started_wall": 1792166907.565865,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 466.263883465,
          "finished_wall": 1792166909.5812771,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 466.256446604,
          "started_wall": 1792166909.5738397,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 468.271995675,
          "finished_wall": 1792166911.5893893,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 468.264030104,
          "started_wall": 1792166911.581423,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 470.279838668,
          "finished_wall": 1792166913.597232,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 470.27213945,
          "started_wall": 1792166913.5895326,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 472.287731716,
          "finished_wall": 1792166915.6051254,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 472.279995972,
          "started_wall": 1792166915.597389,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 474.295614558,
          "finished_wall": 1792166917.613008,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.287831444,
          "started_wall": 1792166917.6052244,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 474.353643335,
          "finished_wall": 1792166917.671037,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.345763104,
          "started_wall": 1792166917.6631563,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 474.411815719,
          "finished_wall": 1792166917.7292094,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.403771069,
          "started_wall": 1792166917.7211642,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 474.469667698,
          "finished_wall": 1792166917.7870612,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.461979207,
          "started_wall": 1792166917.7793725,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 474.527575051,
          "finished_wall": 1792166917.8449688,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.519822353,
          "started_wall": 1792166917.8372154,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 474.586111406,
          "finished_wall": 1792166917.903505,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.577731358,
          "started_wall": 1792166917.8951242,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 474.644347596,
          "finished_wall": 1792166917.9617412,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.636256656,
          "started_wall": 1792166917.9536498,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 474.702932113,
          "finished_wall": 1792166918.020326,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.694500878,
          "started_wall": 1792166918.011894,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 474.761399083,
          "finished_wall": 1792166918.0787928,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.753094119,
          "started_wall": 1792166918.0704873,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 474.819824149,
          "finished_wall": 1792166918.1372178,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.811534628,
          "started_wall": 1792166918.1289277,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 474.877996012,
          "finished_wall": 1792166918.1953897,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.869971232,
          "started_wall": 1792166918.1873643,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 474.936540008,
          "finished_wall": 1792166918.2539337,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.928135033,
          "started_wall": 1792166918.2455282,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.003890026,
          "finished_wall": 1792166918.3212836,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 474.986636224,
          "started_wall": 1792166918.3040297,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.062991495,
          "finished_wall": 1792166918.3803854,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 475.053990168,
          "started_wall": 1792166918.3713832,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.121424653,
          "finished_wall": 1792166918.4388185,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 475.11317321,
          "started_wall": 1792166918.4305663,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.180084775,
          "finished_wall": 1792166918.4974785,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 475.171605728,
          "started_wall": 1792166918.488999,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.238326513,
          "finished_wall": 1792166918.55572,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 475.230251538,
          "started_wall": 1792166918.5476446,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.296942318,
          "finished_wall": 1792166918.614336,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 475.288469991,
          "started_wall": 1792166918.605863,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.3547701,
          "finished_wall": 1792166918.6721637,
          "http_status": 200,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 475.347060608,
          "started_wall": 1792166918.6644537,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.40674571,
          "finished_wall": 1792166918.7241392,
          "http_status": 503,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 475.40492171,
          "started_wall": 1792166918.7223148,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.45830573,
          "finished_wall": 1792166918.7756996,
          "http_status": 503,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 475.45683143,
          "started_wall": 1792166918.7742248,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.509761503,
          "finished_wall": 1792166918.8271554,
          "http_status": 503,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 475.508399613,
          "started_wall": 1792166918.8257928,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.561158747,
          "finished_wall": 1792166918.8785524,
          "http_status": 503,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 475.559895877,
          "started_wall": 1792166918.877289,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.61253534,
          "finished_wall": 1792166918.929929,
          "http_status": 503,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 475.611308204,
          "started_wall": 1792166918.9287014,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.663822618,
          "finished_wall": 1792166918.9812162,
          "http_status": 503,
          "lease_deadline": 475.637019238,
          "response_valid": true,
          "started_monotonic": 475.662635833,
          "started_wall": 1792166918.9800289,
          "trust_sequence": 28
        }
      ],
      "recovery_verified": {
        "deadline": 536.7890689149999,
        "document_sha256": "a6ab46608fb48ac05e632c6ff0a479d9e8879554802fecf629ab1a919661eadd",
        "monotonic": 476.797415717,
        "sequence": 33,
        "version": 1,
        "wall": 1792166920.114809
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0,
    "stopped_worker_denial_seconds": 2.013518621000003
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:faf7129cd5e77d916a4f39c7b3fcd349cf61f77071199ec475ff53515b3baf51",
    "source_fingerprint": "9eac6f96db4e55438097b792903abee05ae8f3cc10369a8789129a1eef16de18",
    "source_revision": "b2b3bf65b7b740318c5f5d0086fa380a14b834b1"
  },
  "source_dirty": false,
  "started_at": "2026-10-16T16:07:27.875915+00:00",
  "status": "pass",
  "subject_sha256": "d0b3b3bee051d06501be5bde2e3e14f3577c3fa7d876869591018d3206d9e858"
}
```
