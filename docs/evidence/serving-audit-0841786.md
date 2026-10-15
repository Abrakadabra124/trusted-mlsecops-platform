# Audit core increment: native serving regression 0841786

Полный sanitized actual-candidate regression report. [Storage CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38794232968), job `116626318445`, clean code `08417867ff324e43264ebb41ebc27d3d79fb46a5`. [Evidence и ограничения](serving-audit-2026-10-15.md).

Это повторная проверка существующего HTTP serving после добавления отдельного audit core. Сам журнал ещё не подключён к HTTP: этот report не доказывает audit correlation, retention или полный M13. Qualification permission не является release approval; image/ML failures остаются блокирующими.

```json
{
  "campaign_id": "def48727685d4edf984c4943bce59a84",
  "candidate_reference": "43e7c643c9c9ebc3ea1cc9896179ff9fa73b7e37b23f4f11dcda142babd02904",
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
  "evaluation_reference": "32bc4df7cdf59f9e9d6c5df14175f94640f081cb349a8d2357acf84b0d7004a6",
  "finished_at": "2026-10-15T19:38:30.019333+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634",
  "proposal_reference": "1bd684a316e7de95c6f2fea3317e3074f7d19e08511a14e139ecf54802cab89d",
  "qualification_permit_sha256": "6aaf26d3202744cdbda6e0044dc56b714cb420224230a4f2164ebbe6750ff5a2",
  "reference_response_sha256": "9a66d6cc4f38dcb74cc4f8fedf01e978b8ae63b8ec71ab66d2339b65a412aacb",
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
      "window_seconds": 0.003538591999927121
    },
    "golden_rows": 3,
    "http_expiring_query": {
      "approval_deadline": 1248.4319787025452,
      "denial": {
        "active_observed": {
          "monotonic": 736.246388401,
          "wall": 1792093096.8144085
        },
        "connected_read_entered": true,
        "finished_monotonic": 741.77715969,
        "finished_wall": 1792093102.3451807,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 736.073411461,
        "started_wall": 1792093096.6414318
      },
      "expected_trust": {
        "document_sha256": "fb2c0ff0f03ac5b90e17d1c425265b8c76bf2caec993b20ffb5b22f0e39d0eb3",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 742.0255672931671,
        "document_sha256": "fb2c0ff0f03ac5b90e17d1c425265b8c76bf2caec993b20ffb5b22f0e39d0eb3",
        "monotonic": 736.033849086,
        "sequence": 43,
        "version": 2,
        "wall": 1792093096.6018698
      },
      "policy_expires_at": 1792093103,
      "policy_expiry_monotonic": 742.4319791793823,
      "post_expiry": {
        "finished_monotonic": 742.483334731,
        "finished_wall": 1792093103.0513544,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 742.482028205,
        "started_wall": 1792093103.0500484
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 805.345153832,
        "document_sha256": "9af702cdd1f13a71715493072b605165ad24329989d1745193f6ffbba5903781",
        "monotonic": 745.353503984,
        "sequence": 48,
        "version": 3,
        "wall": 1792093105.9215248
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "9af702cdd1f13a71715493072b605165ad24329989d1745193f6ffbba5903781",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 723.351991983,
          "wall": 1792093083.9200122
        },
        "connected_read_entered": true,
        "finished_monotonic": 733.161919333,
        "finished_wall": 1792093093.7299407,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 723.158737618,
        "started_wall": 1792093083.726758
      },
      "last_verified": {
        "deadline": 783.102361881,
        "document_sha256": "b11a1f317a93ba721453d3970b6708414e3ba42644f5982ebfb160cab9455566",
        "monotonic": 723.112126113,
        "sequence": 35,
        "version": 1,
        "wall": 1792093083.6801467
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 794.847961457,
        "document_sha256": "b11a1f317a93ba721453d3970b6708414e3ba42644f5982ebfb160cab9455566",
        "monotonic": 734.856458668,
        "sequence": 41,
        "version": 1,
        "wall": 1792093095.4244792
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "http_trust_outage": {
      "assessment": {
        "failures": [],
        "first_503_seconds": 59.777426016999925,
        "last_200_seconds": 59.726164267999934,
        "observations": 43,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "6bc0a4ec8fa778dc095ff575ccdbf7e1f26b854cb92c30a4f610a45f8bab1e76",
        "model_sha256": "b463c227c89352bd5ce8f7a43a00542b11d41dd348e16dfd9df52a30fdc9c634"
      },
      "last_verified": {
        "deadline": 721.249084294,
        "document_sha256": "b11a1f317a93ba721453d3970b6708414e3ba42644f5982ebfb160cab9455566",
        "monotonic": 661.258040075,
        "sequence": 28,
        "version": 1,
        "wall": 1792093021.8260603
      },
      "records": [
        {
          "finished_monotonic": 662.290293017,
          "finished_wall": 1792093022.858314,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 662.281474934,
          "started_wall": 1792093022.8494956,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 664.302318995,
          "finished_wall": 1792093024.87034,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 664.291264752,
          "started_wall": 1792093024.8592854,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 666.311820931,
          "finished_wall": 1792093026.8798418,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 666.302439276,
          "started_wall": 1792093026.8704598,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 668.32126108,
          "finished_wall": 1792093028.889282,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 668.311939582,
          "started_wall": 1792093028.87996,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 670.331502651,
          "finished_wall": 1792093030.8995235,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 670.321373783,
          "started_wall": 1792093030.8893945,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 672.340859346,
          "finished_wall": 1792093032.9088802,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 672.331613195,
          "started_wall": 1792093032.899634,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 674.350778327,
          "finished_wall": 1792093034.9187992,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 674.34097921,
          "started_wall": 1792093034.909,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 676.359677505,
          "finished_wall": 1792093036.9276984,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 676.350902303,
          "started_wall": 1792093036.918923,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 678.368962147,
          "finished_wall": 1792093038.936983,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 678.359795991,
          "started_wall": 1792093038.9278166,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 680.378370695,
          "finished_wall": 1792093040.9463916,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 680.369117601,
          "started_wall": 1792093040.937138,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 682.388024593,
          "finished_wall": 1792093042.9560456,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 682.378536119,
          "started_wall": 1792093042.9465566,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 684.39717763,
          "finished_wall": 1792093044.9651985,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 684.388141062,
          "started_wall": 1792093044.9561617,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 686.406907547,
          "finished_wall": 1792093046.9749286,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 686.397304671,
          "started_wall": 1792093046.9653254,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 688.416207733,
          "finished_wall": 1792093048.9842286,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 688.407033553,
          "started_wall": 1792093048.975054,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 690.42595872,
          "finished_wall": 1792093050.9939802,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 690.416330241,
          "started_wall": 1792093050.984351,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 692.435904249,
          "finished_wall": 1792093053.003925,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 692.426073641,
          "started_wall": 1792093052.9940944,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 694.445436416,
          "finished_wall": 1792093055.0134573,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 694.436018448,
          "started_wall": 1792093055.004039,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 696.455435155,
          "finished_wall": 1792093057.023456,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 696.445550844,
          "started_wall": 1792093057.0135715,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 698.465352355,
          "finished_wall": 1792093059.0333734,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 698.455549535,
          "started_wall": 1792093059.02357,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 700.475663996,
          "finished_wall": 1792093061.043685,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 700.465454068,
          "started_wall": 1792093061.0334744,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 702.484556452,
          "finished_wall": 1792093063.0525775,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 702.475781775,
          "started_wall": 1792093063.0438023,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 704.494818313,
          "finished_wall": 1792093065.0628393,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 704.484674144,
          "started_wall": 1792093065.0526946,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 706.503752335,
          "finished_wall": 1792093067.0717733,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 706.494937748,
          "started_wall": 1792093067.0629582,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 708.519483307,
          "finished_wall": 1792093069.0875041,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 708.504103252,
          "started_wall": 1792093069.072124,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 710.53156152,
          "finished_wall": 1792093071.0995824,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 710.519604367,
          "started_wall": 1792093071.087625,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 712.54078521,
          "finished_wall": 1792093073.1088064,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 712.531732044,
          "started_wall": 1792093073.0997527,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 714.549625634,
          "finished_wall": 1792093075.1176467,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 714.540897158,
          "started_wall": 1792093075.1089177,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 716.559070859,
          "finished_wall": 1792093077.127092,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 716.549776507,
          "started_wall": 1792093077.1177971,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 718.568474797,
          "finished_wall": 1792093079.1364958,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 718.55919168,
          "started_wall": 1792093079.1272123,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 720.578217811,
          "finished_wall": 1792093081.1462388,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 720.568585279,
          "started_wall": 1792093081.136606,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 720.636794946,
          "finished_wall": 1792093081.2048159,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 720.628320317,
          "started_wall": 1792093081.196341,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 720.694875673,
          "finished_wall": 1792093081.2628965,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 720.686895683,
          "started_wall": 1792093081.2549164,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 720.752778407,
          "finished_wall": 1792093081.3207994,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 720.744967723,
          "started_wall": 1792093081.3129885,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 720.810185931,
          "finished_wall": 1792093081.378207,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 720.80287111,
          "started_wall": 1792093081.3708918,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 720.867400567,
          "finished_wall": 1792093081.4354215,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 720.860277332,
          "started_wall": 1792093081.4282978,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 720.926427379,
          "finished_wall": 1792093081.4944484,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 720.917500104,
          "started_wall": 1792093081.4855206,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 720.984204343,
          "finished_wall": 1792093081.5522254,
          "http_status": 200,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 720.976522077,
          "started_wall": 1792093081.5445428,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 721.035466092,
          "finished_wall": 1792093081.603487,
          "http_status": 503,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 721.034297427,
          "started_wall": 1792093081.602318,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 721.086493717,
          "finished_wall": 1792093081.6545148,
          "http_status": 503,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 721.085551535,
          "started_wall": 1792093081.653572,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 721.138755923,
          "finished_wall": 1792093081.7067769,
          "http_status": 503,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 721.137729123,
          "started_wall": 1792093081.7057498,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 721.190142207,
          "finished_wall": 1792093081.7581632,
          "http_status": 503,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 721.188842387,
          "started_wall": 1792093081.7568629,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 721.24132787,
          "finished_wall": 1792093081.8093488,
          "http_status": 503,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 721.24036215,
          "started_wall": 1792093081.8083827,
          "trust_sequence": 28
        },
        {
          "finished_monotonic": 721.29217162,
          "finished_wall": 1792093081.8601925,
          "http_status": 503,
          "lease_deadline": 721.249084294,
          "response_valid": true,
          "started_monotonic": 721.291407032,
          "started_wall": 1792093081.8594277,
          "trust_sequence": 28
        }
      ],
      "recovery_verified": {
        "deadline": 783.07690292,
        "document_sha256": "b11a1f317a93ba721453d3970b6708414e3ba42644f5982ebfb160cab9455566",
        "monotonic": 723.085423639,
        "sequence": 33,
        "version": 1,
        "wall": 1792093083.6534429
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0,
    "stopped_worker_denial_seconds": 2.0131380199999285
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:58677cc0527df166ee8830c3bf5b2571c4c4234b35355b88d850e4237ea16b8e",
    "source_fingerprint": "083ed073ad75764fa290c4db6b4e797cec82c209ee9327e202e9bf5b23a8a19d",
    "source_revision": "08417867ff324e43264ebb41ebc27d3d79fb46a5"
  },
  "source_dirty": false,
  "started_at": "2026-10-15T19:36:44.716186+00:00",
  "status": "pass",
  "subject_sha256": "6bc0a4ec8fa778dc095ff575ccdbf7e1f26b854cb92c30a4f610a45f8bab1e76"
}
```

