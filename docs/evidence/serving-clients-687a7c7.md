# Serving clients: native report 687a7c7

Полный sanitized actual-candidate qualification report, не release approval. [Storage run](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38788512971), job `116606666991`; exact clean code `687a7c7644898a0a844283b30b8aecf39defffed`. [Результаты и ограничения](serving-clients-2026-10-15.md). Исправленный polling не меняет production rate limits, trust deadline или assessment policy. Исторический [failed trace f273fd5](serving-clients-f273fd5-failure.md) сохраняется отдельно.

```json
{
  "campaign_id": "3e36eb51a226466db64700353509f989",
  "candidate_reference": "00bbc75177f17453c48833d6d1940b5d0d814942255fd8cc6b56ede18691e643",
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
  "evaluation_reference": "8d03bb848b594d27d6b1b5056a86c9ed410e722ca1789df1dd5ca94e8ac95c0d",
  "finished_at": "2026-10-15T18:54:13.800649+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634",
  "proposal_reference": "7eec890f582e434d8050fa4cd34a3f530d8a58f351b95d47cfd8b20b3d2c3147",
  "qualification_permit_sha256": "66370b283cc837607239c1cd8b8f2a6e0771cb3b424a25fb4060bbec4d2427f7",
  "reference_response_sha256": "d0bc51821ef6a9aee7467e433ed3709849b9f8b3450d78679d737a858e4c5294",
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
      "window_seconds": 0.0029598520000035933
    },
    "golden_rows": 3,
    "http_expiring_query": {
      "approval_deadline": 940.8401546478271,
      "denial": {
        "active_observed": {
          "monotonic": 423.594358109,
          "wall": 1792090443.7542026
        },
        "connected_read_entered": true,
        "finished_monotonic": 430.224848029,
        "finished_wall": 1792090450.3846939,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 423.518170793,
        "started_wall": 1792090443.6780155
      },
      "expected_trust": {
        "document_sha256": "929ce9d297a2e80e80c5f8c440abfd4b0ff0249fab0a519a457331cba188eed9",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 430.47321343421936,
        "document_sha256": "929ce9d297a2e80e80c5f8c440abfd4b0ff0249fab0a519a457331cba188eed9",
        "monotonic": 423.482236946,
        "sequence": 43,
        "version": 2,
        "wall": 1792090443.6420817
      },
      "policy_expires_at": 1792090451,
      "policy_expiry_monotonic": 430.8401551246643,
      "post_expiry": {
        "finished_monotonic": 430.891762863,
        "finished_wall": 1792090451.0516076,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 430.890286898,
        "started_wall": 1792090451.0501304
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 492.354259375,
        "document_sha256": "195d88542d881bd1c530df0db470ca6bce35faae7cb27e886ba24813ec5fcb2f",
        "monotonic": 432.361559342,
        "sequence": 48,
        "version": 3,
        "wall": 1792090452.5214043
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "195d88542d881bd1c530df0db470ca6bce35faae7cb27e886ba24813ec5fcb2f",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 412.085977955,
          "wall": 1792090432.2458224
        },
        "connected_read_entered": true,
        "finished_monotonic": 422.002518196,
        "finished_wall": 1792090442.162364,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 411.999749815,
        "started_wall": 1792090432.159594
      },
      "last_verified": {
        "deadline": 471.955277454,
        "document_sha256": "f2ea6485844a7b010dbe2b21936dd1b0a386ccbbb66ce1f99b349cc4cd39ea49",
        "monotonic": 411.963156957,
        "sequence": 35,
        "version": 1,
        "wall": 1792090432.1230018
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 483.034826208,
        "document_sha256": "f2ea6485844a7b010dbe2b21936dd1b0a386ccbbb66ce1f99b349cc4cd39ea49",
        "monotonic": 423.04367697,
        "sequence": 41,
        "version": 1,
        "wall": 1792090443.2035217
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "http_trust_outage": {
      "assessment": {
        "failures": [],
        "first_503_seconds": 59.777709752999954,
        "last_200_seconds": 59.725950308999984,
        "observations": 54,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "f820e6a03dc2c62cc262251da987518d2ed844e081ec5e54af48565bdeaa7634",
        "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634"
      },
      "last_verified": {
        "deadline": 410.719152705,
        "document_sha256": "f2ea6485844a7b010dbe2b21936dd1b0a386ccbbb66ce1f99b349cc4cd39ea49",
        "monotonic": 350.727164607,
        "sequence": 28,
        "version": 1,
        "wall": 1792090370.8870096
      },
      "records": [
        {
          "finished_monotonic": 351.158528385,
          "finished_wall": 1792090371.3183737,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 351.149942789,
          "started_wall": 1792090371.3097878,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 353.166819989,
          "finished_wall": 1792090373.3266652,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 353.15870716,
          "started_wall": 1792090373.318552,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 355.175383463,
          "finished_wall": 1792090375.3352287,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 355.166932075,
          "started_wall": 1792090375.3267767,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 357.184157229,
          "finished_wall": 1792090377.3440025,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 357.175542574,
          "started_wall": 1792090377.3353875,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 359.194189427,
          "finished_wall": 1792090379.354035,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 359.184325599,
          "started_wall": 1792090379.3441706,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 361.202377484,
          "finished_wall": 1792090381.3622227,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 361.194316388,
          "started_wall": 1792090381.3541615,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 363.210622635,
          "finished_wall": 1792090383.370468,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 363.202510022,
          "started_wall": 1792090383.362355,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 365.218918269,
          "finished_wall": 1792090385.3787634,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 365.210780608,
          "started_wall": 1792090385.3706255,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 367.227661165,
          "finished_wall": 1792090387.3875065,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 367.219082547,
          "started_wall": 1792090387.3789275,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 369.23564475,
          "finished_wall": 1792090389.39549,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 369.227830731,
          "started_wall": 1792090389.3876758,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 371.243768479,
          "finished_wall": 1792090391.4036138,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 371.235775719,
          "started_wall": 1792090391.3956206,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 373.252078777,
          "finished_wall": 1792090393.411924,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 373.243934062,
          "started_wall": 1792090393.403779,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 375.260657536,
          "finished_wall": 1792090395.420503,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 375.252233272,
          "started_wall": 1792090395.4120781,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 377.269073564,
          "finished_wall": 1792090397.4289188,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 377.260819763,
          "started_wall": 1792090397.4206645,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 379.276999696,
          "finished_wall": 1792090399.4368448,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 379.269239844,
          "started_wall": 1792090399.4290848,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 381.285226988,
          "finished_wall": 1792090401.4450722,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 381.27717211,
          "started_wall": 1792090401.4370172,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 383.2933955,
          "finished_wall": 1792090403.4532409,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 383.285388125,
          "started_wall": 1792090403.4452329,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 385.301362133,
          "finished_wall": 1792090405.4612076,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 385.293564189,
          "started_wall": 1792090405.453409,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 387.309735729,
          "finished_wall": 1792090407.4695811,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 387.301514554,
          "started_wall": 1792090407.4613593,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 389.31823202,
          "finished_wall": 1792090409.4780774,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 389.30990143,
          "started_wall": 1792090409.4697464,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 391.326331683,
          "finished_wall": 1792090411.4861767,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 391.31840308,
          "started_wall": 1792090411.478248,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 393.334501205,
          "finished_wall": 1792090413.4943464,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 393.326448088,
          "started_wall": 1792090413.486293,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 395.342642025,
          "finished_wall": 1792090415.5024872,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 395.334623782,
          "started_wall": 1792090415.4944687,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 397.354764048,
          "finished_wall": 1792090417.514609,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 397.342760013,
          "started_wall": 1792090417.5026047,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 399.363251073,
          "finished_wall": 1792090419.5230963,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 399.354917562,
          "started_wall": 1792090419.5147622,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 401.371618709,
          "finished_wall": 1792090421.5314639,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 401.363390408,
          "started_wall": 1792090421.5232353,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 403.37968838,
          "finished_wall": 1792090423.5395336,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 403.371737306,
          "started_wall": 1792090423.5315819,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 405.387894444,
          "finished_wall": 1792090425.5477397,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 405.37980098,
          "started_wall": 1792090425.5396457,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 407.396523899,
          "finished_wall": 1792090427.5563693,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 407.388027435,
          "started_wall": 1792090427.5478723,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 409.404338748,
          "finished_wall": 1792090429.564184,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 409.396630463,
          "started_wall": 1792090429.5564754,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 409.462562192,
          "finished_wall": 1792090429.6224074,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 409.454456001,
          "started_wall": 1792090429.6143007,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 409.52123691,
          "finished_wall": 1792090429.681082,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 409.512676981,
          "started_wall": 1792090429.6725218,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 409.579256124,
          "finished_wall": 1792090429.7391014,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 409.571352109,
          "started_wall": 1792090429.7311969,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 409.637445257,
          "finished_wall": 1792090429.7972906,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 409.629357002,
          "started_wall": 1792090429.789202,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 409.695281414,
          "finished_wall": 1792090429.8551266,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 409.687578122,
          "started_wall": 1792090429.847423,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 409.75340673,
          "finished_wall": 1792090429.913252,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 409.745410584,
          "started_wall": 1792090429.9052553,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 409.811180112,
          "finished_wall": 1792090429.9710255,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 409.803503601,
          "started_wall": 1792090429.9633484,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 409.869240119,
          "finished_wall": 1792090430.0290854,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 409.861340009,
          "started_wall": 1792090430.0211844,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 409.927616825,
          "finished_wall": 1792090430.0874622,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 409.919405073,
          "started_wall": 1792090430.0792499,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 409.98538522,
          "finished_wall": 1792090430.1452303,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 409.977735619,
          "started_wall": 1792090430.1375804,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.043298414,
          "finished_wall": 1792090430.2031438,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.035550385,
          "started_wall": 1792090430.195395,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.101319522,
          "finished_wall": 1792090430.2611644,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.093458081,
          "started_wall": 1792090430.2533028,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.159376163,
          "finished_wall": 1792090430.3192215,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.151427039,
          "started_wall": 1792090430.3112717,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.220873127,
          "finished_wall": 1792090430.3807182,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.209993382,
          "started_wall": 1792090430.3698382,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.278916889,
          "finished_wall": 1792090430.4387622,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.270992733,
          "started_wall": 1792090430.4308374,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.337018549,
          "finished_wall": 1792090430.496864,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.329029514,
          "started_wall": 1792090430.4888742,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.395263645,
          "finished_wall": 1792090430.5551088,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.387178445,
          "started_wall": 1792090430.547023,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.453114916,
          "finished_wall": 1792090430.61296,
          "http_status": 200,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.445381899,
          "started_wall": 1792090430.6052268,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.50487436,
          "finished_wall": 1792090430.6647196,
          "http_status": 503,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.503232308,
          "started_wall": 1792090430.663077,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.556372607,
          "finished_wall": 1792090430.716218,
          "http_status": 503,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.554928035,
          "started_wall": 1792090430.714773,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.607694964,
          "finished_wall": 1792090430.76754,
          "http_status": 503,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.60645756,
          "started_wall": 1792090430.7663023,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.65904403,
          "finished_wall": 1792090430.8188891,
          "http_status": 503,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.657785165,
          "started_wall": 1792090430.81763,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.710347338,
          "finished_wall": 1792090430.8701923,
          "http_status": 503,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.709151468,
          "started_wall": 1792090430.8689964,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 410.761663035,
          "finished_wall": 1792090430.921508,
          "http_status": 503,
          "lease_deadline": 410.719152705,
          "response_valid": true,
          "started_monotonic": 410.760447364,
          "started_wall": 1792090430.9202921,
          "trust_sequence": 28
        }
      ],
      "recovery_verified": {
        "deadline": 471.932693464,
        "document_sha256": "f2ea6485844a7b010dbe2b21936dd1b0a386ccbbb66ce1f99b349cc4cd39ea49",
        "monotonic": 411.940712534,
        "sequence": 33,
        "version": 1,
        "wall": 1792090432.1005576
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0,
    "stopped_worker_denial_seconds": 2.012246224000023
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:1ba4f7245e7518ad3966bafd6a527111b6bbeca3456949d586afbe8c2eb20e7d",
    "source_fingerprint": "6d7c5bdf7d60297c6b95c01117cd10fbd4b5df31a1efefa8e9ca3f57393e91c1",
    "source_revision": "687a7c7644898a0a844283b30b8aecf39defffed"
  },
  "source_dirty": false,
  "started_at": "2026-10-15T18:52:39.761346+00:00",
  "status": "pass",
  "subject_sha256": "f820e6a03dc2c62cc262251da987518d2ed844e081ec5e54af48565bdeaa7634"
}
```
