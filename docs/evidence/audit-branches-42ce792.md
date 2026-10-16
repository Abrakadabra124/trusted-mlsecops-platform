# Audit branch coverage increment: native serving regression 42ce792

Полный sanitized actual-candidate regression report. [Storage CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38933422730), job `117082827528`, clean code `42ce7928d3518dd656c4b314e6861bc922ba29cf`. [Evidence и ограничения](audit-branches-2026-10-16.md).

Это регрессия существующего serving, не ещё не реализованная HTTP audit integration. В том же CI job отдельные suites проверили 61 audit contract и 10 contracts branch checker. Production audit modules не изменены; release_ready=false и failed image/ML gates продолжают блокировать выпуск.

```json
{
  "campaign_id": "7457b344227f4ce889849adc610aafb6",
  "candidate_reference": "2e360e42a6a5733017721368e3e75bae68e5a371aff81ca127e71724caa8345e",
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
  "evaluation_reference": "967b85bfca03a482bdee8ec4266fa56457fde6b4152a9079464b803c40590634",
  "finished_at": "2026-10-16T16:45:59.939969+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634",
  "proposal_reference": "84a42aa66df192f284db288d7853e9541198e62d2a9135ead537055c24231109",
  "qualification_permit_sha256": "38210ded9b0c2b3d2e08627b24265c9b7b2c5fe0ddf46f22b49f69b4a9ebdefe",
  "reference_response_sha256": "9c3bd6ee24b0ed397bf000577776eab5f55de9be82c89d986a9ae611346e3a9e",
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
      "window_seconds": 0.0033358640000074047
    },
    "golden_rows": 3,
    "http_expiring_query": {
      "approval_deadline": 1053.3342061042786,
      "denial": {
        "active_observed": {
          "monotonic": 538.755109038,
          "wall": 1792169149.4209023
        },
        "connected_read_entered": true,
        "finished_monotonic": 544.320425527,
        "finished_wall": 1792169154.98622,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 538.61793674,
        "started_wall": 1792169149.28373
      },
      "expected_trust": {
        "document_sha256": "e890cc88e4b881970910c543d803cd57561ab5b3b55e1b148cfd1f08182166c2",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 544.5696654319763,
        "document_sha256": "e890cc88e4b881970910c543d803cd57561ab5b3b55e1b148cfd1f08182166c2",
        "monotonic": 538.578797322,
        "sequence": 43,
        "version": 2,
        "wall": 1792169149.2445908
      },
      "policy_expires_at": 1792169156,
      "policy_expiry_monotonic": 545.3342065811157,
      "post_expiry": {
        "finished_monotonic": 545.385608744,
        "finished_wall": 1792169156.051402,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 545.384332362,
        "started_wall": 1792169156.0501246
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 607.270783818,
        "document_sha256": "8d57db7ef3416ba8701f7c7d8cf6f4240bfcea5ccc5ba13c24eaade7e7d774cd",
        "monotonic": 547.279146745,
        "sequence": 48,
        "version": 3,
        "wall": 1792169157.9449403
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "8d57db7ef3416ba8701f7c7d8cf6f4240bfcea5ccc5ba13c24eaade7e7d774cd",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 526.999687925,
          "wall": 1792169137.6654809
        },
        "connected_read_entered": true,
        "finished_monotonic": 536.920328938,
        "finished_wall": 1792169147.5861232,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 526.918523261,
        "started_wall": 1792169137.5843165
      },
      "last_verified": {
        "deadline": 586.869522014,
        "document_sha256": "8c999a155ddda89c34b6f7e440a21f9b48dbe15a041fdb4b1df2b3a7732065bd",
        "monotonic": 526.878584048,
        "sequence": 35,
        "version": 1,
        "wall": 1792169137.5443776
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 598.079207102,
        "document_sha256": "8c999a155ddda89c34b6f7e440a21f9b48dbe15a041fdb4b1df2b3a7732065bd",
        "monotonic": 538.088314294,
        "sequence": 41,
        "version": 1,
        "wall": 1792169148.7541077
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "http_trust_outage": {
      "assessment": {
        "failures": [],
        "first_503_seconds": 59.75580964300002,
        "last_200_seconds": 59.704083619000016,
        "observations": 53,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "5e3c90b118789f17c16f43a3a6ac3becbf3f135895d182b43e3e0131ced2d159",
        "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634"
      },
      "last_verified": {
        "deadline": 524.977829507,
        "document_sha256": "8c999a155ddda89c34b6f7e440a21f9b48dbe15a041fdb4b1df2b3a7732065bd",
        "monotonic": 464.986992169,
        "sequence": 28,
        "version": 1,
        "wall": 1792169075.6527858
      },
      "records": [
        {
          "finished_monotonic": 465.438470265,
          "finished_wall": 1792169076.104264,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 465.430110493,
          "started_wall": 1792169076.0959036,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 467.447056547,
          "finished_wall": 1792169078.1128502,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 467.438595094,
          "started_wall": 1792169078.1043887,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 469.455905205,
          "finished_wall": 1792169080.121699,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 469.447181073,
          "started_wall": 1792169080.1129746,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 471.464201275,
          "finished_wall": 1792169082.129995,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 471.456022952,
          "started_wall": 1792169082.1218166,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 473.472786312,
          "finished_wall": 1792169084.1385803,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 473.464313553,
          "started_wall": 1792169084.1301072,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 475.481565957,
          "finished_wall": 1792169086.1473598,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 475.472899981,
          "started_wall": 1792169086.1386933,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 477.490056275,
          "finished_wall": 1792169088.15585,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 477.481691366,
          "started_wall": 1792169088.147485,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 479.498601475,
          "finished_wall": 1792169090.1643953,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 479.490207974,
          "started_wall": 1792169090.1560016,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 481.508150683,
          "finished_wall": 1792169092.1739442,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 481.498726413,
          "started_wall": 1792169092.16452,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 483.516958031,
          "finished_wall": 1792169094.1827517,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 483.508288269,
          "started_wall": 1792169094.1740818,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 485.525372899,
          "finished_wall": 1792169096.1911666,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 485.517080597,
          "started_wall": 1792169096.1828742,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 487.533939163,
          "finished_wall": 1792169098.1997328,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 487.525513753,
          "started_wall": 1792169098.1913073,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 489.543069573,
          "finished_wall": 1792169100.2088635,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 489.534087258,
          "started_wall": 1792169100.1998806,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 491.551681504,
          "finished_wall": 1792169102.2174754,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 491.543234323,
          "started_wall": 1792169102.2090278,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 493.560895964,
          "finished_wall": 1792169104.2266898,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 493.551846741,
          "started_wall": 1792169104.2176402,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 495.570740674,
          "finished_wall": 1792169106.2365346,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 495.561025653,
          "started_wall": 1792169106.226819,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 497.579391174,
          "finished_wall": 1792169108.2451851,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 497.570866748,
          "started_wall": 1792169108.2366602,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 499.588256643,
          "finished_wall": 1792169110.2540503,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 499.579536187,
          "started_wall": 1792169110.2453296,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 501.596915041,
          "finished_wall": 1792169112.2627087,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 501.588384416,
          "started_wall": 1792169112.2541778,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 503.606212172,
          "finished_wall": 1792169114.272006,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 503.597059214,
          "started_wall": 1792169114.2628527,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 505.615052525,
          "finished_wall": 1792169116.2808464,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 505.606320241,
          "started_wall": 1792169116.2721136,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 507.623818851,
          "finished_wall": 1792169118.2896125,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 507.615188097,
          "started_wall": 1792169118.2809815,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 509.632553232,
          "finished_wall": 1792169120.298347,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 509.623948226,
          "started_wall": 1792169120.2897418,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 511.641447932,
          "finished_wall": 1792169122.3072417,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 511.632678493,
          "started_wall": 1792169122.298472,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 513.650410202,
          "finished_wall": 1792169124.316204,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 513.641582766,
          "started_wall": 1792169124.3073764,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 515.659025249,
          "finished_wall": 1792169126.3248188,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 515.650571118,
          "started_wall": 1792169126.3163645,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 517.667928595,
          "finished_wall": 1792169128.3337224,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 517.659159005,
          "started_wall": 1792169128.3249526,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 519.676890499,
          "finished_wall": 1792169130.3426845,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 519.668091705,
          "started_wall": 1792169130.3338852,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 521.685649232,
          "finished_wall": 1792169132.351443,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 521.677043425,
          "started_wall": 1792169132.342837,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 523.694423409,
          "finished_wall": 1792169134.360217,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 523.685814268,
          "started_wall": 1792169134.3516078,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 523.753036375,
          "finished_wall": 1792169134.4188302,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 523.744552058,
          "started_wall": 1792169134.4103456,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 523.811539498,
          "finished_wall": 1792169134.4773333,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 523.803160998,
          "started_wall": 1792169134.4689543,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 523.870227956,
          "finished_wall": 1792169134.5360222,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 523.86169042,
          "started_wall": 1792169134.527484,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 523.928730066,
          "finished_wall": 1792169134.594524,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 523.920358055,
          "started_wall": 1792169134.5861516,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 523.987744467,
          "finished_wall": 1792169134.653538,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 523.978869511,
          "started_wall": 1792169134.644663,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.046247781,
          "finished_wall": 1792169134.7120416,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.037869842,
          "started_wall": 1792169134.7036633,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.104482166,
          "finished_wall": 1792169134.7702758,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.096363841,
          "started_wall": 1792169134.7621572,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.162898491,
          "finished_wall": 1792169134.8286922,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.154633369,
          "started_wall": 1792169134.8204267,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.221497985,
          "finished_wall": 1792169134.887292,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.213036752,
          "started_wall": 1792169134.8788302,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.280329846,
          "finished_wall": 1792169134.9461238,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.271620846,
          "started_wall": 1792169134.9374144,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.33875271,
          "finished_wall": 1792169135.0045464,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.3304817,
          "started_wall": 1792169134.9962752,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.397234923,
          "finished_wall": 1792169135.0630288,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.388875982,
          "started_wall": 1792169135.0546696,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.456193721,
          "finished_wall": 1792169135.1219873,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.44737555,
          "started_wall": 1792169135.1131692,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.514824402,
          "finished_wall": 1792169135.1806183,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.506324131,
          "started_wall": 1792169135.1721177,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.573375376,
          "finished_wall": 1792169135.2391691,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.564960302,
          "started_wall": 1792169135.230754,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.631915953,
          "finished_wall": 1792169135.29771,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.623470163,
          "started_wall": 1792169135.2892637,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.691075788,
          "finished_wall": 1792169135.3568695,
          "http_status": 200,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.682081066,
          "started_wall": 1792169135.3478746,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.742801812,
          "finished_wall": 1792169135.4085958,
          "http_status": 503,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.741217293,
          "started_wall": 1792169135.4070108,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.794489993,
          "finished_wall": 1792169135.460284,
          "http_status": 503,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.792888178,
          "started_wall": 1792169135.4586816,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.845931177,
          "finished_wall": 1792169135.511725,
          "http_status": 503,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.844582368,
          "started_wall": 1792169135.510376,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.89773587,
          "finished_wall": 1792169135.5635297,
          "http_status": 503,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.896475291,
          "started_wall": 1792169135.5622687,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 524.949035873,
          "finished_wall": 1792169135.6148295,
          "http_status": 503,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.947827953,
          "started_wall": 1792169135.6136212,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 525.000285972,
          "finished_wall": 1792169135.6660798,
          "http_status": 503,
          "lease_deadline": 524.977829507,
          "response_valid": true,
          "started_monotonic": 524.999142577,
          "started_wall": 1792169135.6649363,
          "trust_sequence": 28
        }
      ],
      "recovery_verified": {
        "deadline": 586.775377169,
        "document_sha256": "8c999a155ddda89c34b6f7e440a21f9b48dbe15a041fdb4b1df2b3a7732065bd",
        "monotonic": 526.784137726,
        "sequence": 33,
        "version": 1,
        "wall": 1792169137.4499314
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0,
    "stopped_worker_denial_seconds": 2.0134107729999755
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:d1c1f26657cf9de5845711204608951d499782f1139b3cb3cc3b18bc5d1e1528",
    "source_fingerprint": "9eac6f96db4e55438097b792903abee05ae8f3cc10369a8789129a1eef16de18",
    "source_revision": "42ce7928d3518dd656c4b314e6861bc922ba29cf"
  },
  "source_dirty": false,
  "started_at": "2026-10-16T16:44:20.316084+00:00",
  "status": "pass",
  "subject_sha256": "5e3c90b118789f17c16f43a3a6ac3becbf3f135895d182b43e3e0131ced2d159"
}
```
