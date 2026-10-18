# Native serving regression для audit admission 01ec902

Источник: [Storage run 39129029564](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39129029564), job 117680175876, attempt 1. Это полный sanitized candidate report с 72 cases, не HTTP audit acceptance. [Итог](audit-admission-2026-10-18.md).

```json
{
  "campaign_id": "c49c3a607e2a4320bbaf2f7b4221edd8",
  "candidate_reference": "36aa23c34430ddd4e8cb0d95e6d4d3ce44915e7bcf13e859ee4fa07e9335b1b6",
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
  "evaluation_reference": "9bd10bbc0771ec628844d4610de76ba48e20ba61bd7183ee43962fbffc06141d",
  "finished_at": "2026-10-18T12:59:47.376939+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f",
  "proposal_reference": "d372adc1619a37234ddaec6f185a0aa4242212d0086e8484f6a35dedf430c749",
  "qualification_permit_sha256": "74109c3bf448fa50db9bd6fd52dea7abea1b2c660c2848fb6a91bce8d656f073",
  "reference_response_sha256": "eae050bb4e42663fd42b28b40968b365c846a1c209d6c1e7c61598e10feb0536",
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
      "window_seconds": 0.004173817999969742
    },
    "golden_rows": 3,
    "http_expiring_query": {
      "approval_deadline": 1039.14213347435,
      "denial": {
        "active_observed": {
          "monotonic": 524.007442545,
          "wall": 1792328376.8653088
        },
        "connected_read_entered": true,
        "finished_monotonic": 530.607908924,
        "finished_wall": 1792328383.4657762,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 523.915734969,
        "started_wall": 1792328376.773601
      },
      "expected_trust": {
        "document_sha256": "98b52070ae8dac7cf5b9047b90fe7e0d654050e9403820a1f2bd5a9ec32fdb83",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 530.8570780754089,
        "document_sha256": "98b52070ae8dac7cf5b9047b90fe7e0d654050e9403820a1f2bd5a9ec32fdb83",
        "monotonic": 523.868123977,
        "sequence": 51,
        "version": 2,
        "wall": 1792328376.7259903
      },
      "policy_expires_at": 1792328384,
      "policy_expiry_monotonic": 531.1421337127686,
      "post_expiry": {
        "finished_monotonic": 531.193794889,
        "finished_wall": 1792328384.0516613,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 531.192253693,
        "started_wall": 1792328384.0501196
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 593.074367864,
        "document_sha256": "a7347b64c7dc874dc38a4b85db8470cb1dd56a9d2982697e680bc0cc37d6ff3a",
        "monotonic": 533.084657006,
        "sequence": 56,
        "version": 3,
        "wall": 1792328385.9425235
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "a7347b64c7dc874dc38a4b85db8470cb1dd56a9d2982697e680bc0cc37d6ff3a",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 512.058917501,
          "wall": 1792328364.9167836
        },
        "connected_read_entered": true,
        "finished_monotonic": 521.959200413,
        "finished_wall": 1792328374.8170671,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 511.957224796,
        "started_wall": 1792328364.815091
      },
      "last_verified": {
        "deadline": 571.895757885,
        "document_sha256": "0baf5743c28886bed7f583c50295a802b17d3ddac416774abd1241924fe2647e",
        "monotonic": 511.907191725,
        "sequence": 43,
        "version": 1,
        "wall": 1792328364.765058
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 583.262687811,
        "document_sha256": "0baf5743c28886bed7f583c50295a802b17d3ddac416774abd1241924fe2647e",
        "monotonic": 523.273299587,
        "sequence": 49,
        "version": 1,
        "wall": 1792328376.131166
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "http_trust_outage": {
      "assessment": {
        "failures": [],
        "first_503_seconds": 59.745691566999994,
        "last_200_seconds": 59.69393537399998,
        "observations": 51,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "5701b5cb960d521fe2effefc8da1a6ad16c2b92f33a42bc127960c78750ae404",
        "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f"
      },
      "last_verified": {
        "deadline": 510.361780749,
        "document_sha256": "0baf5743c28886bed7f583c50295a802b17d3ddac416774abd1241924fe2647e",
        "monotonic": 450.37303393,
        "sequence": 36,
        "version": 1,
        "wall": 1792328303.2309003
      },
      "records": [
        {
          "finished_monotonic": 450.818511984,
          "finished_wall": 1792328303.676379,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 450.807638616,
          "started_wall": 1792328303.6655047,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 452.82942848,
          "finished_wall": 1792328305.6872952,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 452.818633804,
          "started_wall": 1792328305.6765003,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 454.841193316,
          "finished_wall": 1792328307.6990602,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 454.829620545,
          "started_wall": 1792328307.687487,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 456.852544777,
          "finished_wall": 1792328309.7104115,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 456.841343971,
          "started_wall": 1792328309.6992104,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 458.865759757,
          "finished_wall": 1792328311.7236266,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 458.852716446,
          "started_wall": 1792328311.7105827,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 460.876820093,
          "finished_wall": 1792328313.734687,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 460.86591545,
          "started_wall": 1792328313.7237818,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 462.888721375,
          "finished_wall": 1792328315.7465882,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 462.876999571,
          "started_wall": 1792328315.734866,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 464.907478651,
          "finished_wall": 1792328317.7653456,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 464.889288516,
          "started_wall": 1792328317.747155,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 466.918862589,
          "finished_wall": 1792328319.7767293,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 466.907627574,
          "started_wall": 1792328319.765494,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 468.930784097,
          "finished_wall": 1792328321.788651,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 468.919021038,
          "started_wall": 1792328321.7768877,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 470.941938182,
          "finished_wall": 1792328323.799805,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 470.930961935,
          "started_wall": 1792328323.7888284,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 472.953232849,
          "finished_wall": 1792328325.8110995,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 472.94210611,
          "started_wall": 1792328325.7999725,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 474.964949254,
          "finished_wall": 1792328327.822816,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 474.953427078,
          "started_wall": 1792328327.8112934,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 476.976901521,
          "finished_wall": 1792328329.8347683,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 476.965116335,
          "started_wall": 1792328329.8229825,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 478.988540717,
          "finished_wall": 1792328331.8464074,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 478.977054246,
          "started_wall": 1792328331.8349206,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 481.000493796,
          "finished_wall": 1792328333.8583608,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 480.988696767,
          "started_wall": 1792328333.846563,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 483.011608559,
          "finished_wall": 1792328335.8694754,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 483.000639049,
          "started_wall": 1792328335.8585055,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 485.02260744,
          "finished_wall": 1792328337.8804743,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 485.011769533,
          "started_wall": 1792328337.869636,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 487.034572921,
          "finished_wall": 1792328339.8924398,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 487.022754037,
          "started_wall": 1792328339.8806205,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 489.046537308,
          "finished_wall": 1792328341.9044042,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 489.034730037,
          "started_wall": 1792328341.8925965,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 491.058116489,
          "finished_wall": 1792328343.9159834,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 491.046683384,
          "started_wall": 1792328343.9045498,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 493.069515362,
          "finished_wall": 1792328345.9273822,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 493.058262588,
          "started_wall": 1792328345.916129,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.081245869,
          "finished_wall": 1792328347.9391127,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 495.069667048,
          "started_wall": 1792328347.9275336,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 497.092701938,
          "finished_wall": 1792328349.9505687,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 497.081395533,
          "started_wall": 1792328349.939262,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 499.103607176,
          "finished_wall": 1792328351.9614737,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 499.092839794,
          "started_wall": 1792328351.9507062,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 501.115138625,
          "finished_wall": 1792328353.9730055,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 501.103764401,
          "started_wall": 1792328353.961631,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 503.12612198,
          "finished_wall": 1792328355.9839888,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 503.11528866,
          "started_wall": 1792328355.973155,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 505.137375527,
          "finished_wall": 1792328357.9952424,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 505.126277856,
          "started_wall": 1792328357.9841444,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 507.14832988,
          "finished_wall": 1792328360.0061967,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 507.137513943,
          "started_wall": 1792328359.9953804,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.159237753,
          "finished_wall": 1792328362.0171046,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.148471698,
          "started_wall": 1792328362.0063381,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.219529454,
          "finished_wall": 1792328362.0773962,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.209380526,
          "started_wall": 1792328362.067247,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.280348707,
          "finished_wall": 1792328362.1382155,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.269667218,
          "started_wall": 1792328362.1275337,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.341632645,
          "finished_wall": 1792328362.1994994,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.33048457,
          "started_wall": 1792328362.1883507,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.402087358,
          "finished_wall": 1792328362.2599542,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.391774937,
          "started_wall": 1792328362.2496414,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.461886263,
          "finished_wall": 1792328362.319753,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.452179166,
          "started_wall": 1792328362.3100457,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.522170591,
          "finished_wall": 1792328362.3800373,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.511983642,
          "started_wall": 1792328362.3698502,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.582653909,
          "finished_wall": 1792328362.4405208,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.572269572,
          "started_wall": 1792328362.430136,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.64348345,
          "finished_wall": 1792328362.5013502,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.632753953,
          "started_wall": 1792328362.4906204,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.703632876,
          "finished_wall": 1792328362.5614996,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.693621075,
          "started_wall": 1792328362.5514874,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.763494608,
          "finished_wall": 1792328362.6213615,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.753729463,
          "started_wall": 1792328362.611596,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.824800294,
          "finished_wall": 1792328362.682667,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.813595902,
          "started_wall": 1792328362.671462,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.885543042,
          "finished_wall": 1792328362.7434096,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.87490517,
          "started_wall": 1792328362.7327716,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 509.946439812,
          "finished_wall": 1792328362.8043065,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.93565144,
          "started_wall": 1792328362.7935178,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 510.006584679,
          "finished_wall": 1792328362.8644514,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 509.996546787,
          "started_wall": 1792328362.8544133,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 510.066969304,
          "finished_wall": 1792328362.9248362,
          "http_status": 200,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 510.056684724,
          "started_wall": 1792328362.9145513,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 510.118725497,
          "finished_wall": 1792328362.976592,
          "http_status": 503,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 510.117158914,
          "started_wall": 1792328362.9750254,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 510.170576047,
          "finished_wall": 1792328363.0284429,
          "http_status": 503,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 510.168844056,
          "started_wall": 1792328363.0267105,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 510.221923149,
          "finished_wall": 1792328363.0797899,
          "http_status": 503,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 510.220666322,
          "started_wall": 1792328363.078533,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 510.273229527,
          "finished_wall": 1792328363.1310964,
          "http_status": 503,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 510.272011272,
          "started_wall": 1792328363.1298778,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 510.324490357,
          "finished_wall": 1792328363.182357,
          "http_status": 503,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 510.323318358,
          "started_wall": 1792328363.1811848,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 510.375734227,
          "finished_wall": 1792328363.233601,
          "http_status": 503,
          "lease_deadline": 510.361780749,
          "response_valid": true,
          "started_monotonic": 510.374581384,
          "started_wall": 1792328363.2324479,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 571.8651096149999,
        "document_sha256": "0baf5743c28886bed7f583c50295a802b17d3ddac416774abd1241924fe2647e",
        "monotonic": 511.876332565,
        "sequence": 41,
        "version": 1,
        "wall": 1792328364.734199
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0,
    "stopped_worker_denial_seconds": 2.0187897810000095
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:9bcfa72f1169556fa2b94a3f3851a5e1d82c65c79cfccc1d3fe20bae1241f216",
    "source_fingerprint": "877bdb7cf3b9030130b8cd0bb2ef55d9636c9a0660a717cf203bebd5b605514d",
    "source_revision": "01ec9021cfa8e5a356ca6361ac9b94f0e0744562"
  },
  "source_dirty": false,
  "started_at": "2026-10-18T12:58:10.119967+00:00",
  "status": "pass",
  "subject_sha256": "5701b5cb960d521fe2effefc8da1a6ad16c2b92f33a42bc127960c78750ae404"
}
```
