# Native HTTP audit qualification 281e902

Источник: [Storage run 39165939564](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39165939564), job 117788771210, attempt 1. Полный sanitized actual-candidate report: 74 cases, private journal не опубликован. Это HTTP audit component, не all-output M13 acceptance. [Итог и ограничения](serving-http-audit-2026-10-18.md).

```json
{
  "campaign_id": "714d0d3761864100a34745e0bfaee58c",
  "candidate_reference": "112b572719b46d641ec681e0926df6cea1b92ebd83c7bb3eec5a37f97732de85",
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
    "actual-candidate-revocation-http-503",
    "actual-candidate-revocation-readiness-503",
    "qualification-authority-and-private-key-removed",
    "source-cas-budget-envelopes-and-checkout-unchanged"
  ],
  "evaluation_reference": "d0d9c940e81d4fe760f508d1c804759a73597dd4f4c7261843095a03e2c5d656",
  "finished_at": "2026-10-18T21:09:39.405618+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f",
  "proposal_reference": "5122c559a4161582ace713e9963c09d5c19b6a12f9d61ed74bfd5e3873d3d4ba",
  "qualification_permit_sha256": "1c759a6dc849b1883976e0343c861110f2cb68f76fd6d8427d8ccf233f419af2",
  "reference_response_sha256": "62f90a1651e614aef66ea554fceffa4ef9e18d41a9c0bde3b0c5af2f000ea203",
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
      "window_seconds": 0.005972538000037275
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
      "approval_deadline": 1033.7544648647308,
      "denial": {
        "active_observed": {
          "monotonic": 518.267531134,
          "wall": 1792357769.5130658
        },
        "connected_read_entered": true,
        "finished_monotonic": 523.853272183,
        "finished_wall": 1792357775.0988076,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 518.16945136,
        "started_wall": 1792357769.414986
      },
      "expected_trust": {
        "document_sha256": "a7fc146778cb12046ebcb7525cf2415b5b9e87edec21f32e23b84945c1df1bb5",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 524.1022093296051,
        "document_sha256": "a7fc146778cb12046ebcb7525cf2415b5b9e87edec21f32e23b84945c1df1bb5",
        "monotonic": 518.112222742,
        "sequence": 51,
        "version": 2,
        "wall": 1792357769.3577578
      },
      "policy_expires_at": 1792357776,
      "policy_expiry_monotonic": 524.7544648647308,
      "post_expiry": {
        "finished_monotonic": 524.805845923,
        "finished_wall": 1792357776.0513806,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 524.804508076,
        "started_wall": 1792357776.0500424
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 586.631781046,
        "document_sha256": "b420bf7da53978c612e971090047e0cbe1101b873694950d1f85570f9115d1cf",
        "monotonic": 526.641495902,
        "sequence": 56,
        "version": 3,
        "wall": 1792357777.8870308
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "b420bf7da53978c612e971090047e0cbe1101b873694950d1f85570f9115d1cf",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 506.324899032,
          "wall": 1792357757.5704334
        },
        "connected_read_entered": true,
        "finished_monotonic": 516.230635119,
        "finished_wall": 1792357767.4761705,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 506.22734074,
        "started_wall": 1792357757.4728754
      },
      "last_verified": {
        "deadline": 566.1630396769999,
        "document_sha256": "4788fbbea1385529a35f3af1729cbcfc3924f9ca698ca7528a4ec781c6ec130e",
        "monotonic": 506.172915755,
        "sequence": 43,
        "version": 1,
        "wall": 1792357757.4184506
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 577.5117609,
        "document_sha256": "4788fbbea1385529a35f3af1729cbcfc3924f9ca698ca7528a4ec781c6ec130e",
        "monotonic": 517.521458124,
        "sequence": 49,
        "version": 1,
        "wall": 1792357768.766993
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "http_trust_outage": {
      "assessment": {
        "failures": [],
        "first_503_seconds": 59.752797617,
        "last_200_seconds": 59.70135330399995,
        "observations": 44,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "8ed28814542346c0b3036f812878396a24577cedfc66f84a13f4bbe1bb9746c0",
        "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f"
      },
      "last_verified": {
        "deadline": 504.653148464,
        "document_sha256": "4788fbbea1385529a35f3af1729cbcfc3924f9ca698ca7528a4ec781c6ec130e",
        "monotonic": 444.662791575,
        "sequence": 36,
        "version": 1,
        "wall": 1792357695.9083264
      },
      "records": [
        {
          "finished_monotonic": 445.156362767,
          "finished_wall": 1792357696.401898,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 445.135238963,
          "started_wall": 1792357696.3807738,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 447.178228498,
          "finished_wall": 1792357698.4237638,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 447.156519837,
          "started_wall": 1792357698.4020545,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 449.200619316,
          "finished_wall": 1792357700.4461546,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 449.178379208,
          "started_wall": 1792357700.4239142,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 451.222678253,
          "finished_wall": 1792357702.4682136,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 451.20075518,
          "started_wall": 1792357702.4462903,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 453.244571852,
          "finished_wall": 1792357704.490107,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 453.222811423,
          "started_wall": 1792357704.4683464,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 455.266935512,
          "finished_wall": 1792357706.5124707,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 455.244708208,
          "started_wall": 1792357706.490243,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 457.288520353,
          "finished_wall": 1792357708.5340557,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 457.267069844,
          "started_wall": 1792357708.5126047,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 459.309877345,
          "finished_wall": 1792357710.5554125,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 459.288656027,
          "started_wall": 1792357710.534191,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 461.332217874,
          "finished_wall": 1792357712.577753,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 461.310026518,
          "started_wall": 1792357712.5555615,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 463.354319135,
          "finished_wall": 1792357714.5998542,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 463.332359333,
          "started_wall": 1792357714.5778942,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 465.376118041,
          "finished_wall": 1792357716.6216533,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 465.354457429,
          "started_wall": 1792357716.5999923,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 467.398606485,
          "finished_wall": 1792357718.644142,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 467.376258248,
          "started_wall": 1792357718.621793,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 469.420810652,
          "finished_wall": 1792357720.666346,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 469.398745646,
          "started_wall": 1792357720.6442807,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 471.442493522,
          "finished_wall": 1792357722.6880286,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 471.420953007,
          "started_wall": 1792357722.6664882,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 473.464433925,
          "finished_wall": 1792357724.709969,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 473.442634845,
          "started_wall": 1792357724.6881697,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 475.486395599,
          "finished_wall": 1792357726.731931,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 475.464568315,
          "started_wall": 1792357726.7101033,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 477.509377176,
          "finished_wall": 1792357728.7549126,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 477.48652334,
          "started_wall": 1792357728.7320583,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 479.531253504,
          "finished_wall": 1792357730.7767887,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 479.509536503,
          "started_wall": 1792357730.7550714,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 481.553252367,
          "finished_wall": 1792357732.7987876,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 481.531394538,
          "started_wall": 1792357732.7769296,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 483.57505241,
          "finished_wall": 1792357734.8205879,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 483.55340273,
          "started_wall": 1792357734.7989376,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 485.596688229,
          "finished_wall": 1792357736.8422236,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 485.575181356,
          "started_wall": 1792357736.8207164,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 487.618496473,
          "finished_wall": 1792357738.8640318,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 487.596844291,
          "started_wall": 1792357738.842379,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 489.640494029,
          "finished_wall": 1792357740.8860292,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 489.61863674,
          "started_wall": 1792357740.8641717,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 491.662708126,
          "finished_wall": 1792357742.9082434,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 491.640636886,
          "started_wall": 1792357742.8861718,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 493.684490055,
          "finished_wall": 1792357744.930025,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 493.662846298,
          "started_wall": 1792357744.9083812,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 495.706859166,
          "finished_wall": 1792357746.9523942,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 495.684629391,
          "started_wall": 1792357746.9301643,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 497.728841512,
          "finished_wall": 1792357748.9743767,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 497.707002396,
          "started_wall": 1792357748.9525373,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 499.750276232,
          "finished_wall": 1792357750.9958112,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 499.728978679,
          "started_wall": 1792357750.9745138,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 501.772324521,
          "finished_wall": 1792357753.01786,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 501.750410092,
          "started_wall": 1792357752.995945,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 503.794125175,
          "finished_wall": 1792357755.0396602,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 503.772462588,
          "started_wall": 1792357755.0179975,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 503.866492745,
          "finished_wall": 1792357755.112028,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 503.844271953,
          "started_wall": 1792357755.0898068,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 503.937854602,
          "finished_wall": 1792357755.1833897,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 503.916629947,
          "started_wall": 1792357755.162165,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 504.009359885,
          "finished_wall": 1792357755.2548952,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 503.987986511,
          "started_wall": 1792357755.2335215,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 504.079887317,
          "finished_wall": 1792357755.3254225,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 504.059459916,
          "started_wall": 1792357755.3049948,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 504.150839795,
          "finished_wall": 1792357755.396375,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 504.129989409,
          "started_wall": 1792357755.3755243,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 504.222158891,
          "finished_wall": 1792357755.467694,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 504.200943693,
          "started_wall": 1792357755.4464786,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 504.293193814,
          "finished_wall": 1792357755.538729,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 504.272257517,
          "started_wall": 1792357755.5177925,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 504.364144879,
          "finished_wall": 1792357755.6096802,
          "http_status": 200,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 504.343289535,
          "started_wall": 1792357755.5888245,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 504.415589192,
          "finished_wall": 1792357755.6611245,
          "http_status": 503,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 504.414241353,
          "started_wall": 1792357755.6597762,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 504.467415644,
          "finished_wall": 1792357755.7129507,
          "http_status": 503,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 504.465699758,
          "started_wall": 1792357755.7112346,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 504.518737594,
          "finished_wall": 1792357755.764273,
          "http_status": 503,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 504.517505836,
          "started_wall": 1792357755.7630408,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 504.56988273,
          "finished_wall": 1792357755.8154178,
          "http_status": 503,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 504.568829737,
          "started_wall": 1792357755.8143647,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 504.621114954,
          "finished_wall": 1792357755.86665,
          "http_status": 503,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 504.61997122,
          "started_wall": 1792357755.865506,
          "trust_sequence": 36
        },
        {
          "finished_monotonic": 504.672214517,
          "finished_wall": 1792357755.9177496,
          "http_status": 503,
          "lease_deadline": 504.653148464,
          "response_valid": true,
          "started_monotonic": 504.671209093,
          "started_wall": 1792357755.916744,
          "trust_sequence": 36
        }
      ],
      "recovery_verified": {
        "deadline": 566.123462033,
        "document_sha256": "4788fbbea1385529a35f3af1729cbcfc3924f9ca698ca7528a4ec781c6ec130e",
        "monotonic": 506.133849242,
        "sequence": 41,
        "version": 1,
        "wall": 1792357757.379384
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0.0,
    "stopped_worker_denial_seconds": 2.016759057999991
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:024a93eefb810821d54b33a1ed264736baee1daa315179e51f34fa1dd34bac4c",
    "source_fingerprint": "1f10698960fc441afecf5efd72ccd2d81505f66ff9aeb3fbdaa7fdfc81f6c234",
    "source_revision": "281e902a888348d1f39e6bad56026cde1e14897d"
  },
  "source_dirty": false,
  "started_at": "2026-10-18T21:08:03.264239+00:00",
  "status": "pass",
  "subject_sha256": "8ed28814542346c0b3036f812878396a24577cedfc66f84a13f4bbe1bb9746c0"
}
```
