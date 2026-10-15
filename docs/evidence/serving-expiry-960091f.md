# Native signed-policy expiry: 960091f

Code commit: `960091f23a68a124a05648fb980c7d9c2db523d4`.

Canonical report SHA-256: `314cad1dd093b0301508a2750c14d5f5e8d4f4d51b457a7510dc0b26f99f4ba7`. Из сохранённого report повторно проверены 140 outage observations, оба ACTIVE timestamps, expiry/receipt и renewal/readback binding. Использованы те же strict assessors и дополнительные assertions, не независимый runtime повтор.

[Storage CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38779625543), job `116576139028`, completed/success. Полный sanitized candidate report: stopped-authority, paused-query и signed-policy-expiry traces, без raw logs или payloads. [Разбор и ограничения](serving-expiry-2026-10-15.md). Qualification не разрешает release.

```json
{
  "campaign_id": "028fd5c47a5145698e7db951e83b2d93",
  "candidate_reference": "8dda1f0c41ce108c7f20a19e9942151d0bd95bd95323d621e88d186e13d0c952",
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
  "evaluation_reference": "1f8e5535100d3a31c1c2c9ac103666539ba3b027eaf41dc235461996c93f153d",
  "finished_at": "2026-10-15T17:50:59.459521+00:00",
  "full_M12": "inconclusive",
  "limitations": [
    "Qualification permission is not release approval; failed gates remain blocking",
    "Golden consistency uses another ONNX worker, not independent sklearn parity",
    "Production Reader acceptance, privacy/audit and load acceptance remain separate"
  ],
  "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f",
  "proposal_reference": "ec2ea07276aa58d315afd486fdf8cc171cca5d88c016759d0df88751e356c9e1",
  "qualification_permit_sha256": "d9fd012715a057f4bf321e5cd1787d070dc9367291de68f70b79ca7fe19accfb",
  "reference_response_sha256": "2e972b356069dbee3f3e9e443246d8e3d4ab6a38002883b174dc00b59ecc581f",
  "release_ready": false,
  "runtime": {
    "golden_rows": 3,
    "http_expiring_query": {
      "approval_deadline": 1135.0270874500275,
      "denial": {
        "active_observed": {
          "monotonic": 618.017026505,
          "wall": 1792086648.9899387
        },
        "connected_read_entered": true,
        "finished_monotonic": 624.619762057,
        "finished_wall": 1792086655.592675,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 617.924771601,
        "started_wall": 1792086648.8976834
      },
      "expected_trust": {
        "document_sha256": "f0a2074b765637a82ea433a78ef5f7f4d18bb9c0e1b4c0edccddc96d6029f00f",
        "reused": false,
        "version": 2
      },
      "last_verified": {
        "deadline": 624.868332862854,
        "document_sha256": "f0a2074b765637a82ea433a78ef5f7f4d18bb9c0e1b4c0edccddc96d6029f00f",
        "monotonic": 617.879278764,
        "sequence": 37,
        "version": 2,
        "wall": 1792086648.852191
      },
      "policy_expires_at": 1792086656,
      "policy_expiry_monotonic": 625.027087688446,
      "post_expiry": {
        "finished_monotonic": 625.07863572,
        "finished_wall": 1792086656.0515473,
        "http_status": 503,
        "query_active": true,
        "query_finished": false,
        "response_valid": true,
        "started_monotonic": 625.077212473,
        "started_wall": 1792086656.050124
      },
      "profile": "signed-policy-expiry",
      "recovery_verified": {
        "deadline": 686.94138945,
        "document_sha256": "bebd20751b1b420f31096f3894dcb138d52b454018a824641108f90326b477e3",
        "monotonic": 626.951604451,
        "sequence": 42,
        "version": 3,
        "wall": 1792086657.924517
      },
      "release_ready": false,
      "renewal_receipt": {
        "document_sha256": "bebd20751b1b420f31096f3894dcb138d52b454018a824641108f90326b477e3",
        "reused": false,
        "version": 3
      },
      "schema_version": 1,
      "status": "pass"
    },
    "http_paused_query": {
      "denial": {
        "active_observed": {
          "monotonic": 606.055436823,
          "wall": 1792086637.028349
        },
        "connected_read_entered": true,
        "finished_monotonic": 615.960730044,
        "finished_wall": 1792086646.933643,
        "generation_fenced": true,
        "http_status": 503,
        "libpq_query_active_at_denial": true,
        "read_finished_at_denial": false,
        "response_valid": true,
        "started_monotonic": 605.958748079,
        "started_wall": 1792086636.93166
      },
      "last_verified": {
        "deadline": 665.902303218,
        "document_sha256": "3b48de65feb3a45748c7aa5dbb32f99f9b619c0f56b25bd2e5241fd70c1ded36",
        "monotonic": 605.913308054,
        "sequence": 29,
        "version": 1,
        "wall": 1792086636.8862202
      },
      "profile": "request-deadline",
      "recovery_verified": {
        "deadline": 677.279972126,
        "document_sha256": "3b48de65feb3a45748c7aa5dbb32f99f9b619c0f56b25bd2e5241fd70c1ded36",
        "monotonic": 617.289924675,
        "sequence": 35,
        "version": 1,
        "wall": 1792086648.262837
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "http_trust_outage": {
      "assessment": {
        "failures": [],
        "first_503_seconds": 59.740655876999995,
        "last_200_seconds": 59.729039984999986,
        "observations": 140,
        "release_ready": false,
        "scope": "http-trust-outage-component-not-full-M11",
        "status": "pass"
      },
      "identity": {
        "bundle_sha256": "01558a74b596cac10184f3d4aef4f8471afa3ecd4f08ae4395bd960bb25dcc62",
        "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f"
      },
      "last_verified": {
        "deadline": 604.385316876,
        "document_sha256": "3b48de65feb3a45748c7aa5dbb32f99f9b619c0f56b25bd2e5241fd70c1ded36",
        "monotonic": 544.395973756,
        "sequence": 22,
        "version": 1,
        "wall": 1792086575.368886
      },
      "records": [
        {
          "finished_monotonic": 544.826080284,
          "finished_wall": 1792086575.798993,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 544.815172201,
          "started_wall": 1792086575.7880845,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 546.836456331,
          "finished_wall": 1792086577.809369,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 546.82624292,
          "started_wall": 1792086577.7991552,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 548.846818527,
          "finished_wall": 1792086579.8197312,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 548.836618785,
          "started_wall": 1792086579.8095312,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 550.857447806,
          "finished_wall": 1792086581.8303607,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 550.846962603,
          "started_wall": 1792086581.8198748,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 552.867925694,
          "finished_wall": 1792086583.8408384,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 552.857605587,
          "started_wall": 1792086583.830518,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 554.878857614,
          "finished_wall": 1792086585.8517704,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 554.868099266,
          "started_wall": 1792086585.8410115,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 556.889363631,
          "finished_wall": 1792086587.8622766,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 556.87900027,
          "started_wall": 1792086587.8519127,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 558.900414981,
          "finished_wall": 1792086589.8733277,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 558.889470919,
          "started_wall": 1792086589.8623834,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 560.910672047,
          "finished_wall": 1792086591.883585,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 560.9005215,
          "started_wall": 1792086591.8734338,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 562.921045117,
          "finished_wall": 1792086593.8939579,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 562.91081383,
          "started_wall": 1792086593.8837261,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 564.93231572,
          "finished_wall": 1792086595.9052286,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 564.92120122,
          "started_wall": 1792086595.8941135,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 566.943394607,
          "finished_wall": 1792086597.9163072,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 566.932510569,
          "started_wall": 1792086597.905423,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 568.954170166,
          "finished_wall": 1792086599.9270828,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 568.943534633,
          "started_wall": 1792086599.916447,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 570.964765335,
          "finished_wall": 1792086601.937678,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 570.954314221,
          "started_wall": 1792086601.9272265,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 572.976577324,
          "finished_wall": 1792086603.94949,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 572.964988343,
          "started_wall": 1792086603.9379008,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 574.987033109,
          "finished_wall": 1792086605.959946,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 574.97672564,
          "started_wall": 1792086605.949638,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 576.997319465,
          "finished_wall": 1792086607.9702322,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 576.98715169,
          "started_wall": 1792086607.960064,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 579.008199393,
          "finished_wall": 1792086609.981112,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 578.997466166,
          "started_wall": 1792086609.9703784,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 581.018472004,
          "finished_wall": 1792086611.9913845,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 581.008328349,
          "started_wall": 1792086611.9812405,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 583.028559648,
          "finished_wall": 1792086614.0014722,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 583.018609656,
          "started_wall": 1792086613.991522,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 585.038860974,
          "finished_wall": 1792086616.0117736,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 585.028722338,
          "started_wall": 1792086616.0016346,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 587.049726141,
          "finished_wall": 1792086618.0226388,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 587.0390198,
          "started_wall": 1792086618.0119321,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 589.060890544,
          "finished_wall": 1792086620.0338032,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 589.04987419,
          "started_wall": 1792086620.0227866,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 591.07139357,
          "finished_wall": 1792086622.0443063,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 591.061038805,
          "started_wall": 1792086622.0339513,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 593.082588783,
          "finished_wall": 1792086624.0555015,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 593.071555236,
          "started_wall": 1792086624.0444674,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 595.09340045,
          "finished_wall": 1792086626.0663133,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 595.082733087,
          "started_wall": 1792086626.0556455,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 597.105092054,
          "finished_wall": 1792086628.0780048,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 597.093595187,
          "started_wall": 1792086628.0665076,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 599.115765248,
          "finished_wall": 1792086630.088678,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 599.105274577,
          "started_wall": 1792086630.078187,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 601.126532853,
          "finished_wall": 1792086632.0994456,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 601.11595042,
          "started_wall": 1792086632.0888627,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.13735402,
          "finished_wall": 1792086634.1102667,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.126685164,
          "started_wall": 1792086634.0995975,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.151660122,
          "finished_wall": 1792086634.124573,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.142445202,
          "started_wall": 1792086634.1153576,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.166143867,
          "finished_wall": 1792086634.1390567,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.156749531,
          "started_wall": 1792086634.129662,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.181466442,
          "finished_wall": 1792086634.154379,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.171235951,
          "started_wall": 1792086634.144148,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.196375294,
          "finished_wall": 1792086634.169288,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.186554077,
          "started_wall": 1792086634.1594665,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.21069423,
          "finished_wall": 1792086634.1836069,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.201459403,
          "started_wall": 1792086634.174372,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.224788836,
          "finished_wall": 1792086634.1977015,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.21577872,
          "started_wall": 1792086634.188691,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.239484138,
          "finished_wall": 1792086634.2123969,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.229879427,
          "started_wall": 1792086634.2027917,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.254106473,
          "finished_wall": 1792086634.227019,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.244568336,
          "started_wall": 1792086634.2174807,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.268792357,
          "finished_wall": 1792086634.241705,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.259190922,
          "started_wall": 1792086634.232103,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.282884397,
          "finished_wall": 1792086634.255797,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.273878359,
          "started_wall": 1792086634.2467906,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.297399752,
          "finished_wall": 1792086634.2703125,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.287976862,
          "started_wall": 1792086634.260889,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.311741992,
          "finished_wall": 1792086634.2846546,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.30248886,
          "started_wall": 1792086634.275401,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.325634589,
          "finished_wall": 1792086634.2985473,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.316824537,
          "started_wall": 1792086634.289737,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.339781433,
          "finished_wall": 1792086634.312694,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.330718257,
          "started_wall": 1792086634.3036306,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.353976607,
          "finished_wall": 1792086634.3268893,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.344865692,
          "started_wall": 1792086634.317778,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.368551393,
          "finished_wall": 1792086634.341464,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.359023496,
          "started_wall": 1792086634.3319356,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.383522281,
          "finished_wall": 1792086634.356435,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.373642344,
          "started_wall": 1792086634.3465545,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.398535258,
          "finished_wall": 1792086634.3714478,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.388607822,
          "started_wall": 1792086634.36152,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.413030357,
          "finished_wall": 1792086634.385943,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.403620368,
          "started_wall": 1792086634.3765328,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.427472088,
          "finished_wall": 1792086634.4003847,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.418121714,
          "started_wall": 1792086634.3910341,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.441875346,
          "finished_wall": 1792086634.414788,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.432559637,
          "started_wall": 1792086634.405472,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.456232598,
          "finished_wall": 1792086634.4291453,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.446960512,
          "started_wall": 1792086634.4198728,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.470444057,
          "finished_wall": 1792086634.4433568,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.461318745,
          "started_wall": 1792086634.434231,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.485334699,
          "finished_wall": 1792086634.4582474,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.475531607,
          "started_wall": 1792086634.448444,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.499852061,
          "finished_wall": 1792086634.4727647,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.490430565,
          "started_wall": 1792086634.463343,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.513959608,
          "finished_wall": 1792086634.4868724,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.504938479,
          "started_wall": 1792086634.477851,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.527950723,
          "finished_wall": 1792086634.5008633,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.519025106,
          "started_wall": 1792086634.4919376,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.543275449,
          "finished_wall": 1792086634.5161881,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.533039656,
          "started_wall": 1792086634.505952,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.557952221,
          "finished_wall": 1792086634.530865,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.548362298,
          "started_wall": 1792086634.5212746,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.572082297,
          "finished_wall": 1792086634.544995,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.563017318,
          "started_wall": 1792086634.5359297,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.586156317,
          "finished_wall": 1792086634.559069,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.577167141,
          "started_wall": 1792086634.5500796,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.600626712,
          "finished_wall": 1792086634.5735393,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.591242545,
          "started_wall": 1792086634.5641549,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.614620683,
          "finished_wall": 1792086634.5875332,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.605709883,
          "started_wall": 1792086634.578622,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.62870898,
          "finished_wall": 1792086634.6016214,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.619708473,
          "started_wall": 1792086634.5926208,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.643615052,
          "finished_wall": 1792086634.6165276,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.633794026,
          "started_wall": 1792086634.6067064,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.657711545,
          "finished_wall": 1792086634.6306243,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.648699215,
          "started_wall": 1792086634.6216116,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.671899599,
          "finished_wall": 1792086634.6448123,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.662795779,
          "started_wall": 1792086634.635708,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.685957139,
          "finished_wall": 1792086634.6588697,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.676990225,
          "started_wall": 1792086634.6499026,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.70022819,
          "finished_wall": 1792086634.6731408,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.691018751,
          "started_wall": 1792086634.6639311,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.715245169,
          "finished_wall": 1792086634.6881578,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.705316181,
          "started_wall": 1792086634.6782284,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.730083804,
          "finished_wall": 1792086634.7029965,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.720340734,
          "started_wall": 1792086634.693253,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.744424926,
          "finished_wall": 1792086634.7173376,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.735167366,
          "started_wall": 1792086634.7080796,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.758721925,
          "finished_wall": 1792086634.7316344,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.74951453,
          "started_wall": 1792086634.722427,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.773024735,
          "finished_wall": 1792086634.7459373,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.763808453,
          "started_wall": 1792086634.7367208,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.786875667,
          "finished_wall": 1792086634.7597883,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.778127183,
          "started_wall": 1792086634.7510395,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.801603622,
          "finished_wall": 1792086634.774516,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.791960312,
          "started_wall": 1792086634.7648728,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.816519131,
          "finished_wall": 1792086634.7894318,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.806692054,
          "started_wall": 1792086634.7796044,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.831758798,
          "finished_wall": 1792086634.8046715,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.821608244,
          "started_wall": 1792086634.7945206,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.845926675,
          "finished_wall": 1792086634.8188393,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.836842851,
          "started_wall": 1792086634.809755,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.860602394,
          "finished_wall": 1792086634.833515,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.851018352,
          "started_wall": 1792086634.8239307,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.875458341,
          "finished_wall": 1792086634.848371,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.865687169,
          "started_wall": 1792086634.8385994,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.889678766,
          "finished_wall": 1792086634.8625915,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.880547564,
          "started_wall": 1792086634.85346,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.904434496,
          "finished_wall": 1792086634.877347,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.894763471,
          "started_wall": 1792086634.867676,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.919489176,
          "finished_wall": 1792086634.8924043,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.909520873,
          "started_wall": 1792086634.8824332,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.934464497,
          "finished_wall": 1792086634.9073772,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.924586404,
          "started_wall": 1792086634.8974988,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.950705,
          "finished_wall": 1792086634.9236178,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.939560623,
          "started_wall": 1792086634.9124732,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.966049784,
          "finished_wall": 1792086634.9389625,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.955802879,
          "started_wall": 1792086634.9287152,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.980448534,
          "finished_wall": 1792086634.953361,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.971143365,
          "started_wall": 1792086634.9440558,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 603.994470207,
          "finished_wall": 1792086634.9673827,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.985534421,
          "started_wall": 1792086634.9584467,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.008820095,
          "finished_wall": 1792086634.9817328,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 603.999555863,
          "started_wall": 1792086634.9724681,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.022877763,
          "finished_wall": 1792086634.9957902,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.013910119,
          "started_wall": 1792086634.9868224,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.037332728,
          "finished_wall": 1792086635.0102453,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.027965643,
          "started_wall": 1792086635.000878,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.051932195,
          "finished_wall": 1792086635.024845,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.042415579,
          "started_wall": 1792086635.015328,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.066721387,
          "finished_wall": 1792086635.039634,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.057024884,
          "started_wall": 1792086635.0299373,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.08067388,
          "finished_wall": 1792086635.0535865,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.071809678,
          "started_wall": 1792086635.044722,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.09469426,
          "finished_wall": 1792086635.0676067,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.085760087,
          "started_wall": 1792086635.0586724,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.10869208,
          "finished_wall": 1792086635.0816047,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.099780147,
          "started_wall": 1792086635.0726924,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.125013741,
          "finished_wall": 1792086635.0979264,
          "http_status": 200,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.113793496,
          "started_wall": 1792086635.086706,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.136629633,
          "finished_wall": 1792086635.1095424,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.130129234,
          "started_wall": 1792086635.1030416,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.146135197,
          "finished_wall": 1792086635.1190479,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.144975542,
          "started_wall": 1792086635.1178877,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.152539063,
          "finished_wall": 1792086635.1254518,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.151252934,
          "started_wall": 1792086635.1241653,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.159064161,
          "finished_wall": 1792086635.1319766,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.157628426,
          "started_wall": 1792086635.1305408,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.165491821,
          "finished_wall": 1792086635.1384044,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.164164061,
          "started_wall": 1792086635.1370764,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.17211317,
          "finished_wall": 1792086635.1450257,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.170563191,
          "started_wall": 1792086635.1434755,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.179106471,
          "finished_wall": 1792086635.1520193,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.177219913,
          "started_wall": 1792086635.1501322,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.185924145,
          "finished_wall": 1792086635.1588368,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.184218246,
          "started_wall": 1792086635.1571305,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.191944792,
          "finished_wall": 1792086635.1648574,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.191050024,
          "started_wall": 1792086635.1639624,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.19809652,
          "finished_wall": 1792086635.1710093,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.197055064,
          "started_wall": 1792086635.1699674,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.204324033,
          "finished_wall": 1792086635.1772368,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.203206918,
          "started_wall": 1792086635.1761193,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.21069673,
          "finished_wall": 1792086635.1836092,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.209418215,
          "started_wall": 1792086635.1823306,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.217031221,
          "finished_wall": 1792086635.1899443,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.21578288,
          "started_wall": 1792086635.1886952,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.22322776,
          "finished_wall": 1792086635.1961405,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.22214514,
          "started_wall": 1792086635.1950574,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.229473627,
          "finished_wall": 1792086635.2023864,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.228349845,
          "started_wall": 1792086635.201262,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.235786915,
          "finished_wall": 1792086635.2086997,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.234559023,
          "started_wall": 1792086635.2074714,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.241771628,
          "finished_wall": 1792086635.2146842,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.240869616,
          "started_wall": 1792086635.213782,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.247705855,
          "finished_wall": 1792086635.2206185,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.24684441,
          "started_wall": 1792086635.2197568,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.253608513,
          "finished_wall": 1792086635.226521,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.252782364,
          "started_wall": 1792086635.2256947,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.259497356,
          "finished_wall": 1792086635.23241,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.258680204,
          "started_wall": 1792086635.2315924,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.26538722,
          "finished_wall": 1792086635.2382998,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.264568846,
          "started_wall": 1792086635.237481,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.271242069,
          "finished_wall": 1792086635.2441547,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.27045876,
          "started_wall": 1792086635.243371,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.277099943,
          "finished_wall": 1792086635.2500124,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.276313178,
          "started_wall": 1792086635.2492254,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.282927491,
          "finished_wall": 1792086635.25584,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.282170482,
          "started_wall": 1792086635.2550828,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.288769065,
          "finished_wall": 1792086635.2616816,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.287997638,
          "started_wall": 1792086635.26091,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.294596592,
          "finished_wall": 1792086635.2675092,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.293840264,
          "started_wall": 1792086635.2667525,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.300463123,
          "finished_wall": 1792086635.2733757,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.29966696,
          "started_wall": 1792086635.2725794,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.306650405,
          "finished_wall": 1792086635.279563,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.305535415,
          "started_wall": 1792086635.2784479,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.312650837,
          "finished_wall": 1792086635.2855635,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.311722937,
          "started_wall": 1792086635.2846353,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.318569516,
          "finished_wall": 1792086635.2914822,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.317722327,
          "started_wall": 1792086635.2906349,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.324465511,
          "finished_wall": 1792086635.297378,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.323640674,
          "started_wall": 1792086635.296553,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.330326271,
          "finished_wall": 1792086635.3032389,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.329537151,
          "started_wall": 1792086635.3024495,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.336169929,
          "finished_wall": 1792086635.3090823,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.33539721,
          "started_wall": 1792086635.3083096,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.341968241,
          "finished_wall": 1792086635.3148808,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.341240437,
          "started_wall": 1792086635.3141527,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.347795008,
          "finished_wall": 1792086635.3207076,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.347018241,
          "started_wall": 1792086635.3199306,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.354028797,
          "finished_wall": 1792086635.3269415,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.352872739,
          "started_wall": 1792086635.3257852,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.360284397,
          "finished_wall": 1792086635.333197,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.359124192,
          "started_wall": 1792086635.3320365,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.366241368,
          "finished_wall": 1792086635.339154,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.365359394,
          "started_wall": 1792086635.3382719,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.372180224,
          "finished_wall": 1792086635.3450928,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.371312887,
          "started_wall": 1792086635.3442252,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.378073314,
          "finished_wall": 1792086635.350986,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.377252195,
          "started_wall": 1792086635.3501644,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.383906582,
          "finished_wall": 1792086635.3568192,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.383144263,
          "started_wall": 1792086635.3560567,
          "trust_sequence": 22
        },
        {
          "finished_monotonic": 604.389696369,
          "finished_wall": 1792086635.362609,
          "http_status": 503,
          "lease_deadline": 604.385316876,
          "response_valid": true,
          "started_monotonic": 604.38897701,
          "started_wall": 1792086635.3618894,
          "trust_sequence": 22
        }
      ],
      "recovery_verified": {
        "deadline": 665.871799504,
        "document_sha256": "3b48de65feb3a45748c7aa5dbb32f99f9b619c0f56b25bd2e5241fd70c1ded36",
        "monotonic": 605.882662742,
        "sequence": 27,
        "version": 1,
        "wall": 1792086636.855575
      },
      "release_ready": false,
      "schema_version": 1,
      "status": "pass"
    },
    "maximum_error": 0,
    "stopped_worker_denial_seconds": 2.0154235969999945
  },
  "schema_version": 1,
  "scope": "actual-candidate-serving-qualification-not-release-approval",
  "source": {
    "image_id": "sha256:675a34f2db1818b539940d5693c1d7a2716e2f8ec327061e0f0c9b80a5b77f0a",
    "source_fingerprint": "fef6e6505f3836daa47a56c77bfd36619aa59c13adb63f3e64d699e4c2c514dd",
    "source_revision": "960091f23a68a124a05648fb980c7d9c2db523d4"
  },
  "source_dirty": false,
  "started_at": "2026-10-15T17:49:23.607120+00:00",
  "status": "pass",
  "subject_sha256": "01558a74b596cac10184f3d4aef4f8471afa3ecd4f08ae4395bd960bb25dcc62"
}
```

