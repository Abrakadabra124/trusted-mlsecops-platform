# Native monitoring with epoch admission: public projection

Source: `361b7dd084dbc2dc05d66da86558abfdcaee825d`. [Run42327687810](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42327687810).

Bounded hosted output only. Private primary packets, claims and credentials are excluded.
This fresh-campaign observation does not itself simulate a candidate process crash; separate Linux process tests are described in [evidence](monitoring-restart-2026-11-07.md).
Full M15/R1 remain open.

## Composed component

```json
{
  "binding_sha256": "4e476d30c7f977d84d077a807170dbc761701865adedd044ce4af1a076e4d084",
  "campaign": "79bdc1b189684a878545be2e71909333",
  "candidate_reference": "fd370f9ca87118c66348b04c295b6a15b27e2641694e86067d165e1fb5e13487",
  "feedback_quarantine": {
    "direct_database_denials": 15,
    "packet_sha256": "59245837ba23ea6ce6263d8419c7afe314e3d112a0ab3995f7cec4a345b46750",
    "promotion_unchanged": true,
    "protected_tables_unchanged": true,
    "quarantine_rows_added": 1,
    "record_sha256": "aae5c58036cd96e585125a45adfdbccc52dba6cb9c484a8ff5a1293e747b067e",
    "release_ready": false,
    "retry_unchanged": true,
    "schema_version": 1,
    "status": "pass",
    "submitted_records": 10,
    "training_eligible": false,
    "verified_labels": false
  },
  "finished_at": "2026-11-07T02:13:25.107816+00:00",
  "full_M15": "inconclusive",
  "model_sha256": "fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46",
  "native": {
    "clean_windows": 10,
    "delivered_alerts": 3,
    "elapsed_seconds": 26.243217,
    "full_M15": "inconclusive",
    "max_delivery_seconds": 0.471294143,
    "model_sha256": "fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46",
    "observations": 12000,
    "operator_retained_reverified": {
      "clean_windows": 10,
      "delivered_alerts": 3,
      "full_M15": "inconclusive",
      "max_delivery_seconds": 0.471294143,
      "observations": 12000,
      "packet_sha256": "64c3d7fd20e55efa8a28e2817a3f11c250bcec6ee082a3a691f2469f16549075",
      "reference_sha256": "bbb73319859f60154533d8a47a507931a88d761e497659d21701b57092d3b7b4",
      "release_ready": false,
      "schema_version": 1,
      "shift_windows": 2,
      "status": "pass"
    },
    "packet_sha256": "64c3d7fd20e55efa8a28e2817a3f11c250bcec6ee082a3a691f2469f16549075",
    "reference_sha256": "bbb73319859f60154533d8a47a507931a88d761e497659d21701b57092d3b7b4",
    "release_ready": false,
    "schema_version": 1,
    "scope": "actual-candidate-monitoring-observation",
    "shift_windows": 2,
    "status": "pass",
    "subject_sha256": "4379bde100d1334ff118bd5f9ebd11948e4e46c2e08e1cd4efd0fd437d9840ba",
    "worker_cleanup_verified": true
  },
  "proposal_reference": "dec67ad556c547731b19371e4cfe889d84472f00ad3970da4222e16e8fe607d6",
  "qualification_permit_sha256": "8612d4495dbf63b8f55646dfc15925adaed469b20a884d8c7eb11cf4bb0534eb",
  "release_ready": false,
  "schema_version": 1,
  "scope": "actual-candidate-monitoring-observation",
  "source": {
    "image_id": "sha256:24358884b722eaf8ef1532ba71a02fa3f4611c8a381fd44d5c5e6486b16a1770",
    "source_fingerprint": "d6a9a8b029037553a636429b962d06cceb5dad7f62ce9137633004f68b8c6c0b",
    "source_revision": "361b7dd084dbc2dc05d66da86558abfdcaee825d"
  },
  "source_dirty": false,
  "started_at": "2026-11-07T02:12:39.681488+00:00",
  "status": "pass",
  "subject_sha256": "4379bde100d1334ff118bd5f9ebd11948e4e46c2e08e1cd4efd0fd437d9840ba"
}
```

## Primary reconciliation after owned cleanup

```json
{
  "clean_windows": 10,
  "delivered_alerts": 3,
  "feedback_quarantine": {
    "direct_database_denials": 15,
    "packet_sha256": "59245837ba23ea6ce6263d8419c7afe314e3d112a0ab3995f7cec4a345b46750",
    "promotion_unchanged": true,
    "protected_tables_unchanged": true,
    "quarantine_rows_added": 1,
    "record_sha256": "aae5c58036cd96e585125a45adfdbccc52dba6cb9c484a8ff5a1293e747b067e",
    "release_ready": false,
    "retry_unchanged": true,
    "schema_version": 1,
    "status": "pass",
    "submitted_records": 10,
    "training_eligible": false,
    "verified_labels": false
  },
  "full_M15": "inconclusive",
  "max_delivery_seconds": 0.471294143,
  "observations": 12000,
  "packet_sha256": "64c3d7fd20e55efa8a28e2817a3f11c250bcec6ee082a3a691f2469f16549075",
  "post_cleanup_reverified": true,
  "reference_sha256": "bbb73319859f60154533d8a47a507931a88d761e497659d21701b57092d3b7b4",
  "release_ready": false,
  "schema_version": 1,
  "shift_windows": 2,
  "status": "pass"
}
```
