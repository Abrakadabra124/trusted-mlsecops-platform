# Native serving deadline: ed87e97

Code commit: `ed87e975e03a76c1529cf442a140a508fc4cddd4`.

Canonical report SHA-256: `6b4be2bc0a1df2f70ace939858ff821700f5785804854d2ca68e73db0b245222`. Outage assessment пересчитан из всех 137 observations; paused-query delay пересчитан из monotonic timestamps.

[Storage CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38774146548), job `116557300727`, completed/success. Полный sanitized candidate report, включая оба timestamped traces; не raw log. Это synthetic qualification, не разрешение выпуска. [Разбор и ограничения](serving-deadline-2026-10-15.md).

```json
{
  "campaign_id": "6a581a24d7ba49d0bca4294e527330ba",
  "candidate_reference": "e48ea0557de33eba8cff8e553d6824f68994b4006f2fbfc5c62272a0b0a4a9f0",
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
    "actual-candidate-revocation-http-503",
    "actual-candidate-revocation-readiness-503",
    "qualification-authority-and-private-key-removed",
    "source-cas-budget-envelopes-and-checkout-unchanged"
  ],
  "evaluation_reference": "08db337c1b86def2703538db850a3a8987daf50e79c6ab2bf8321cc005ce428c",
  "finished_at": "2026-10-15T17:11:28.500946+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f",
  "proposal_reference": "c4eb67ab7a9852c5cb71147d06509ceeb7088ae8d17d08735043a000ce38b2db",
  "qualification_permit_sha256": "b11e6cf37acbec40a7882bc5ef9f5f08a37d3a4c43e4eda932afe6d7ff6995d6",
  "reference_response_sha256": "de5309bfe6ff8f7220fe23748085ed7247a5982c8145cc93a31d7c775cf14f2f",
  "release_ready": false,
  "runtime": {
    "golden_rows": 3,
    "http_paused_query": {
      "denial": {
        "connected_read_entered": true,
        "finished_monotonic": 513.591866348,
        "finished_wall": 1792084285.651542,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 503.589516034,
        "started_wall": 1792084275.6491904
      },
      "last_verified": {
        "deadline": 563.5299435730001,
        "document_sha256": "371e2d5900c3007172d4c17c610c5ebae824ed82b3ca5f3ef8b5afb211a3a2b4",
        "monotonic": 503.542728476,
        "sequence": 29,
        "version": 1,
        "wall": 1792084275.6024032
      },
      "recovery_verified": {
        "deadline": 574.895299848,
        "document_sha256": "371e2d5900c3007172d4c17c610c5ebae824ed82b3ca5f3ef8b5afb211a3a2b4",
        "monotonic": 514.906710555,
        "sequence": 35,
        "version": 1,
        "wall": 1792084286.9663851
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "http_trust_outage": {
      "assessment": {
        "failures": [],
        "first_503_seconds": 59.74807846099998,
        "last_200_seconds": 59.740031386,
        "observations": 137,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "9ed3e08c258678ce8f3e3666c54001af6de71d0b9bb4c80b101af02e8d7a8f95",
        "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f"
      },
      "last_verified": {
        "deadline": 501.976536783,
        "document_sha256": "371e2d5900c3007172d4c17c610c5ebae824ed82b3ca5f3ef8b5afb211a3a2b4",
        "monotonic": 441.986612496,
        "sequence": 22,
        "version": 1,
        "wall": 1792084214.046287
      },
      "records": [
        {
          "finished_monotonic": 442.419170429,
          "finished_wall": 1792084214.4788454,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 442.408913049,
          "started_wall": 1792084214.4685879,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 444.429904057,
          "finished_wall": 1792084216.489579,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 444.419327578,
          "started_wall": 1792084216.479002,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 446.440679017,
          "finished_wall": 1792084218.500354,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 446.43005038,
          "started_wall": 1792084218.4897249,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 448.451232229,
          "finished_wall": 1792084220.5109072,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 448.44081599,
          "started_wall": 1792084220.5004904,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 450.462078925,
          "finished_wall": 1792084222.5217538,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 450.451369722,
          "started_wall": 1792084222.5110443,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 452.473276231,
          "finished_wall": 1792084224.532951,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 452.462219183,
          "started_wall": 1792084224.521894,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 454.484142341,
          "finished_wall": 1792084226.5438173,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 454.47342681,
          "started_wall": 1792084226.5331016,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 456.495482958,
          "finished_wall": 1792084228.5551577,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 456.484290325,
          "started_wall": 1792084228.5439649,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 458.506671781,
          "finished_wall": 1792084230.5663466,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 458.495650526,
          "started_wall": 1792084230.5553253,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 460.517198544,
          "finished_wall": 1792084232.5768735,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 460.506818897,
          "started_wall": 1792084232.5664935,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 462.527627911,
          "finished_wall": 1792084234.587303,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 462.517346572,
          "started_wall": 1792084234.5770211,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 464.538067417,
          "finished_wall": 1792084236.5977423,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 464.527773807,
          "started_wall": 1792084236.5874476,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 466.549102156,
          "finished_wall": 1792084238.608777,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 466.538236171,
          "started_wall": 1792084238.597911,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 468.559424098,
          "finished_wall": 1792084240.619099,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 468.549263756,
          "started_wall": 1792084240.6089385,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 470.570911599,
          "finished_wall": 1792084242.6305866,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 470.559598345,
          "started_wall": 1792084242.619273,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 472.582123831,
          "finished_wall": 1792084244.6417987,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 472.571078662,
          "started_wall": 1792084244.6307533,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 474.592582531,
          "finished_wall": 1792084246.6522574,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 474.582280032,
          "started_wall": 1792084246.6419547,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 476.603203245,
          "finished_wall": 1792084248.6628783,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 476.592768776,
          "started_wall": 1792084248.6524434,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 478.614732963,
          "finished_wall": 1792084250.674408,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 478.603383093,
          "started_wall": 1792084250.6630576,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 480.625339137,
          "finished_wall": 1792084252.685014,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 480.614885033,
          "started_wall": 1792084252.6745598,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 482.63653826,
          "finished_wall": 1792084254.6962132,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 482.625510771,
          "started_wall": 1792084254.6851852,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 484.64719325,
          "finished_wall": 1792084256.7068682,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 484.636701544,
          "started_wall": 1792084256.696376,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 486.658116035,
          "finished_wall": 1792084258.717791,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 486.647353602,
          "started_wall": 1792084258.7070282,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 488.668440421,
          "finished_wall": 1792084260.728115,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 488.658257633,
          "started_wall": 1792084260.7179322,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 490.679731705,
          "finished_wall": 1792084262.7394066,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 490.66859824,
          "started_wall": 1792084262.728273,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 492.691445998,
          "finished_wall": 1792084264.7511208,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 492.679904576,
          "started_wall": 1792084264.7395792,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 494.702548007,
          "finished_wall": 1792084266.7622228,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 494.691609862,
          "started_wall": 1792084266.7512844,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 496.71345473,
          "finished_wall": 1792084268.7731297,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 496.702729413,
          "started_wall": 1792084268.7624042,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 498.723767653,
          "finished_wall": 1792084270.7834425,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 498.713631043,
          "started_wall": 1792084270.7733057,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.734435305,
          "finished_wall": 1792084272.7941103,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.723944973,
          "started_wall": 1792084272.7836196,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.749430637,
          "finished_wall": 1792084272.8091056,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.73952483,
          "started_wall": 1792084272.7991996,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.763898821,
          "finished_wall": 1792084272.8235738,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.754520322,
          "started_wall": 1792084272.814195,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.778500956,
          "finished_wall": 1792084272.8381758,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.76899603,
          "started_wall": 1792084272.8286707,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.793312825,
          "finished_wall": 1792084272.8529878,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.78359007,
          "started_wall": 1792084272.8432648,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.807964417,
          "finished_wall": 1792084272.8676395,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.798401237,
          "started_wall": 1792084272.8580759,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.822942617,
          "finished_wall": 1792084272.8826177,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.81302092,
          "started_wall": 1792084272.8726954,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.838246076,
          "finished_wall": 1792084272.897921,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.8280205,
          "started_wall": 1792084272.887695,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.853260443,
          "finished_wall": 1792084272.9129357,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.843336382,
          "started_wall": 1792084272.903011,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.868289939,
          "finished_wall": 1792084272.927965,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.858356991,
          "started_wall": 1792084272.9180317,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.883444299,
          "finished_wall": 1792084272.943119,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.873381728,
          "started_wall": 1792084272.9330564,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.897960503,
          "finished_wall": 1792084272.9576354,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.888538452,
          "started_wall": 1792084272.948213,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.912792138,
          "finished_wall": 1792084272.972467,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.903027305,
          "started_wall": 1792084272.9627018,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.927815382,
          "finished_wall": 1792084272.9874904,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.917879729,
          "started_wall": 1792084272.9775543,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.942248701,
          "finished_wall": 1792084273.0019236,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.932903644,
          "started_wall": 1792084272.9925783,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.957538404,
          "finished_wall": 1792084273.017213,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.947337685,
          "started_wall": 1792084273.0070124,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.972747777,
          "finished_wall": 1792084273.0324225,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.962625775,
          "started_wall": 1792084273.0223005,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 500.98726358,
          "finished_wall": 1792084273.0469384,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.977833063,
          "started_wall": 1792084273.0375078,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.002567611,
          "finished_wall": 1792084273.0622425,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 500.992352835,
          "started_wall": 1792084273.0520275,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.017082703,
          "finished_wall": 1792084273.0767574,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.007665601,
          "started_wall": 1792084273.0673404,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.031896184,
          "finished_wall": 1792084273.091571,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.022170844,
          "started_wall": 1792084273.0818455,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.046400996,
          "finished_wall": 1792084273.106076,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.036984927,
          "started_wall": 1792084273.0966594,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.060715784,
          "finished_wall": 1792084273.120391,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.051487666,
          "started_wall": 1792084273.1111624,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.074963715,
          "finished_wall": 1792084273.1346385,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.065807422,
          "started_wall": 1792084273.125482,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.089976329,
          "finished_wall": 1792084273.1496513,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.080016731,
          "started_wall": 1792084273.1396914,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.105028367,
          "finished_wall": 1792084273.1647031,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.095021571,
          "started_wall": 1792084273.1546962,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.119391555,
          "finished_wall": 1792084273.1790664,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.110130235,
          "started_wall": 1792084273.1698048,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.13399355,
          "finished_wall": 1792084273.1936684,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.124482091,
          "started_wall": 1792084273.1841567,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.149422564,
          "finished_wall": 1792084273.2090974,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.139129101,
          "started_wall": 1792084273.1988037,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.164702649,
          "finished_wall": 1792084273.2243776,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.154514824,
          "started_wall": 1792084273.2141895,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.179545996,
          "finished_wall": 1792084273.239221,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.169797624,
          "started_wall": 1792084273.2294722,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.195110394,
          "finished_wall": 1792084273.2547853,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.184641041,
          "started_wall": 1792084273.2443154,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.210582729,
          "finished_wall": 1792084273.2702577,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.200204718,
          "started_wall": 1792084273.2598794,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.225750264,
          "finished_wall": 1792084273.2854252,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.215673947,
          "started_wall": 1792084273.2753484,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.240717213,
          "finished_wall": 1792084273.3003922,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.230842804,
          "started_wall": 1792084273.2905176,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.255654165,
          "finished_wall": 1792084273.315329,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.245807569,
          "started_wall": 1792084273.3054821,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.270884236,
          "finished_wall": 1792084273.3305593,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.260745783,
          "started_wall": 1792084273.3204203,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.286274508,
          "finished_wall": 1792084273.3459494,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.275976847,
          "started_wall": 1792084273.3356516,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.301808489,
          "finished_wall": 1792084273.3614836,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.291365986,
          "started_wall": 1792084273.3510406,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.316561577,
          "finished_wall": 1792084273.3762364,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.306904015,
          "started_wall": 1792084273.3665786,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.331846401,
          "finished_wall": 1792084273.3915212,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.32165538,
          "started_wall": 1792084273.38133,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.347001262,
          "finished_wall": 1792084273.4066763,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.336939432,
          "started_wall": 1792084273.3966138,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.361919359,
          "finished_wall": 1792084273.4215944,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.352127535,
          "started_wall": 1792084273.411802,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.377307316,
          "finished_wall": 1792084273.4369822,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.367025735,
          "started_wall": 1792084273.4267004,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.39313108,
          "finished_wall": 1792084273.452806,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.382400077,
          "started_wall": 1792084273.4420745,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.408988186,
          "finished_wall": 1792084273.468663,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.398227277,
          "started_wall": 1792084273.4579017,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.424656829,
          "finished_wall": 1792084273.4843318,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.41413081,
          "started_wall": 1792084273.4738057,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.440188073,
          "finished_wall": 1792084273.4998631,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.42975476,
          "started_wall": 1792084273.4894295,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.455971732,
          "finished_wall": 1792084273.5156467,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.44528417,
          "started_wall": 1792084273.5049586,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.472206886,
          "finished_wall": 1792084273.5318818,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.461135095,
          "started_wall": 1792084273.5208097,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.487718054,
          "finished_wall": 1792084273.547393,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.477304486,
          "started_wall": 1792084273.5369792,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.502845944,
          "finished_wall": 1792084273.5625207,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.492814722,
          "started_wall": 1792084273.5524895,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.518563199,
          "finished_wall": 1792084273.5782382,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.50794165,
          "started_wall": 1792084273.5676162,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.53341952,
          "finished_wall": 1792084273.5930946,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.523661559,
          "started_wall": 1792084273.583336,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.548463433,
          "finished_wall": 1792084273.6081383,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.538516729,
          "started_wall": 1792084273.5981913,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.563716868,
          "finished_wall": 1792084273.6233916,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.553556213,
          "started_wall": 1792084273.613231,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.579145381,
          "finished_wall": 1792084273.6388204,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.568819086,
          "started_wall": 1792084273.6284938,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.593866421,
          "finished_wall": 1792084273.6535413,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.584243823,
          "started_wall": 1792084273.6439183,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.608818271,
          "finished_wall": 1792084273.6684933,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.598961677,
          "started_wall": 1792084273.6586363,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.623682856,
          "finished_wall": 1792084273.6833577,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.613909039,
          "started_wall": 1792084273.6735835,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.638423551,
          "finished_wall": 1792084273.6980984,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.628780185,
          "started_wall": 1792084273.6884549,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.653442086,
          "finished_wall": 1792084273.713117,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.64351008,
          "started_wall": 1792084273.7031846,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.668379069,
          "finished_wall": 1792084273.728054,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.658537171,
          "started_wall": 1792084273.718212,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.683305111,
          "finished_wall": 1792084273.74298,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.673464035,
          "started_wall": 1792084273.7331388,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.697699467,
          "finished_wall": 1792084273.7573745,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.688390187,
          "started_wall": 1792084273.7480648,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.711756871,
          "finished_wall": 1792084273.7714317,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.702784984,
          "started_wall": 1792084273.7624598,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.726643882,
          "finished_wall": 1792084273.7863188,
          "http_status": 200,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.716845915,
          "started_wall": 1792084273.7765205,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.734690957,
          "finished_wall": 1792084273.794366,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.731737174,
          "started_wall": 1792084273.7914116,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.741258251,
          "finished_wall": 1792084273.8009334,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.739755433,
          "started_wall": 1792084273.79943,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.748760841,
          "finished_wall": 1792084273.8084362,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.746418758,
          "started_wall": 1792084273.8060932,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.755440559,
          "finished_wall": 1792084273.8151155,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.753865569,
          "started_wall": 1792084273.81354,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.762121901,
          "finished_wall": 1792084273.8217971,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.760521488,
          "started_wall": 1792084273.8201962,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.769048833,
          "finished_wall": 1792084273.8287241,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.767240049,
          "started_wall": 1792084273.8269148,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.776076573,
          "finished_wall": 1792084273.835752,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.774147634,
          "started_wall": 1792084273.8338223,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.782838173,
          "finished_wall": 1792084273.8425133,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.781164916,
          "started_wall": 1792084273.8408396,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.789705886,
          "finished_wall": 1792084273.8493812,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.787943367,
          "started_wall": 1792084273.847618,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.796273895,
          "finished_wall": 1792084273.8559487,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.794803248,
          "started_wall": 1792084273.8544776,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.802770601,
          "finished_wall": 1792084273.8624456,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.801366175,
          "started_wall": 1792084273.8610406,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.809423286,
          "finished_wall": 1792084273.8690982,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.807860281,
          "started_wall": 1792084273.8675349,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.815890301,
          "finished_wall": 1792084273.8755653,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.814519634,
          "started_wall": 1792084273.8741941,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.822424663,
          "finished_wall": 1792084273.8820996,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.82097649,
          "started_wall": 1792084273.8806512,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.829094448,
          "finished_wall": 1792084273.8887696,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.827516262,
          "started_wall": 1792084273.8871908,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.835232046,
          "finished_wall": 1792084273.894907,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.834174194,
          "started_wall": 1792084273.893849,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.841209604,
          "finished_wall": 1792084273.9008844,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.840308406,
          "started_wall": 1792084273.8999832,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.8472819,
          "finished_wall": 1792084273.906957,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.846284662,
          "started_wall": 1792084273.9059594,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.853223971,
          "finished_wall": 1792084273.912899,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.852355374,
          "started_wall": 1792084273.91203,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.859145014,
          "finished_wall": 1792084273.91882,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.858297346,
          "started_wall": 1792084273.9179718,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.865065976,
          "finished_wall": 1792084273.9247408,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.864219751,
          "started_wall": 1792084273.9238942,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.870980416,
          "finished_wall": 1792084273.9306552,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.870139711,
          "started_wall": 1792084273.9298143,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.876795249,
          "finished_wall": 1792084273.93647,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.87602158,
          "started_wall": 1792084273.9356961,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.882706133,
          "finished_wall": 1792084273.9423811,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.881868704,
          "started_wall": 1792084273.9415433,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.888676888,
          "finished_wall": 1792084273.9483519,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.887778705,
          "started_wall": 1792084273.9474535,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.894548107,
          "finished_wall": 1792084273.954223,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.893749561,
          "started_wall": 1792084273.9534242,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.900530915,
          "finished_wall": 1792084273.9602058,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.89962069,
          "started_wall": 1792084273.9592953,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.906458469,
          "finished_wall": 1792084273.9661334,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.90560459,
          "started_wall": 1792084273.9652793,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.912368601,
          "finished_wall": 1792084273.9720438,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.911530361,
          "started_wall": 1792084273.9712052,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.918304642,
          "finished_wall": 1792084273.9779794,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.917441715,
          "started_wall": 1792084273.9771163,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.924177464,
          "finished_wall": 1792084273.9838524,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.923377665,
          "started_wall": 1792084273.9830523,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.930136447,
          "finished_wall": 1792084273.9898112,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.929250187,
          "started_wall": 1792084273.988925,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.93606843,
          "finished_wall": 1792084273.9957433,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.93520892,
          "started_wall": 1792084273.9948835,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.941901878,
          "finished_wall": 1792084274.0015767,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.941142175,
          "started_wall": 1792084274.0008168,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.947814094,
          "finished_wall": 1792084274.007489,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.946975322,
          "started_wall": 1792084274.00665,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.953679271,
          "finished_wall": 1792084274.0133543,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.952886476,
          "started_wall": 1792084274.012561,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.959596667,
          "finished_wall": 1792084274.0192716,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.958751634,
          "started_wall": 1792084274.0184264,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.965516507,
          "finished_wall": 1792084274.0251913,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.964669761,
          "started_wall": 1792084274.0243442,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.971437248,
          "finished_wall": 1792084274.0311122,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.970588238,
          "started_wall": 1792084274.0302627,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.977328104,
          "finished_wall": 1792084274.037003,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.976507958,
          "started_wall": 1792084274.0361826,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 501.983221405,
          "finished_wall": 1792084274.0428963,
          "http_status": 503,
          "lease_deadline": 501.976536783,
          "response_valid": true,
          "started_monotonic": 501.982399936,
          "started_wall": 1792084274.0420747,
          "trust_sequence": 22
        }
      ],
      "recovery_verified": {
        "deadline": 563.4995316029999,
        "document_sha256": "371e2d5900c3007172d4c17c610c5ebae824ed82b3ca5f3ef8b5afb211a3a2b4",
        "monotonic": 503.510580371,
        "sequence": 27,
        "version": 1,
        "wall": 1792084275.5702548
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0,
    "stopped_worker_denial_seconds": 2.015382125999963
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:1480c39bc063468b87121e2695a3faef01580762f223803b733fb0a73b035eb6",
    "source_fingerprint": "fef6e6505f3836daa47a56c77bfd36619aa59c13adb63f3e64d699e4c2c514dd",
    "source_revision": "ed87e975e03a76c1529cf442a140a508fc4cddd4"
  },
  "source_dirty": false,
  "started_at": "2026-10-15T17:10:02.559988+00:00",
  "status": "pass",
  "subject_sha256": "9ed3e08c258678ce8f3e3666c54001af6de71d0b9bb4c80b101af02e8d7a8f95"
}
```

