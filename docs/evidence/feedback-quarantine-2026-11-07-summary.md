# Native feedback quarantine: bounded public projection

Source: `9162a2fe512be18537598a7f413543e15af3947a`. [Run 42325145874](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42325145874).

This is the public projection emitted by the hosted runner, not the private primary packet.
Claims, request payloads, credentials and signing keys are excluded. Full M15/R1 remain open.

## Composed component

```json
{
  "binding_sha256": "33be765e80a5051b5c82215c3d30839971d16e7ead29a44bc3883346cb10bed5",
  "campaign": "ef264665c8ba481496a57b9e16755d16",
  "candidate_reference": "5f4548547c3d738fbc105cc41cccd35441677286ed088a56fdcbcb4df74fd31e",
  "feedback_quarantine": {
    "direct_database_denials": 15,
    "packet_sha256": "badfd15fb2e0b4eee34b0954c06c1cac01312a71cd48be020223ed79b4a48c8e",
    "promotion_unchanged": true,
    "protected_tables_unchanged": true,
    "quarantine_rows_added": 1,
    "record_sha256": "630ac74560ecc6f25bfbfdf21452fbd17905b855c5feb3050ad6f613ab99e563",
    "release_ready": false,
    "retry_unchanged": true,
    "schema_version": 1,
    "status": "pass",
    "submitted_records": 10,
    "training_eligible": false,
    "verified_labels": false
  },
  "finished_at": "2026-11-07T01:42:44.548492+00:00",
  "full_M15": "inconclusive",
  "model_sha256": "fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46",
  "native": {
    "clean_windows": 10,
    "delivered_alerts": 3,
    "elapsed_seconds": 23.029503,
    "full_M15": "inconclusive",
    "max_delivery_seconds": 0.398394584,
    "model_sha256": "fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46",
    "observations": 12000,
    "operator_retained_reverified": {
      "clean_windows": 10,
      "delivered_alerts": 3,
      "full_M15": "inconclusive",
      "max_delivery_seconds": 0.398394584,
      "observations": 12000,
      "packet_sha256": "f8a26f56331477a718eedc293a8591d0b6a9f9b2d13d19177df98d06eaac03e4",
      "reference_sha256": "2740c9f3259578a11c80b801558b4acd168bd6ed5559ca85a9d2f338f6d5ca3a",
      "release_ready": false,
      "schema_version": 1,
      "shift_windows": 2,
      "status": "pass"
    },
    "packet_sha256": "f8a26f56331477a718eedc293a8591d0b6a9f9b2d13d19177df98d06eaac03e4",
    "reference_sha256": "2740c9f3259578a11c80b801558b4acd168bd6ed5559ca85a9d2f338f6d5ca3a",
    "release_ready": false,
    "schema_version": 1,
    "scope": "actual-candidate-monitoring-observation",
    "shift_windows": 2,
    "status": "pass",
    "subject_sha256": "cb3f3feb2139c25a1b7dc83684b66a9dccbc86de64cead6fe1bdc61d880bc86b",
    "worker_cleanup_verified": true
  },
  "proposal_reference": "381ebb7fe092271b2ac8d5a6391e1cfd37ed98851e4f7558274d9beec3ec09eb",
  "qualification_permit_sha256": "c2cfab6904954e2f5f5c207e0f9e26a6a567652c96b1fdaecae043fbea8b5c47",
  "release_ready": false,
  "schema_version": 1,
  "scope": "actual-candidate-monitoring-observation",
  "source": {
    "image_id": "sha256:ce456f0459372d87d88eb4d9d2ee53da06c785604fc96010ab01ebce2d6a7759",
    "source_fingerprint": "4441bb1cec402f634bf4f85e0cf9852be3338845a3fafd836ac232aa3d17cad5",
    "source_revision": "9162a2fe512be18537598a7f413543e15af3947a"
  },
  "source_dirty": false,
  "started_at": "2026-11-07T01:42:05.356107+00:00",
  "status": "pass",
  "subject_sha256": "cb3f3feb2139c25a1b7dc83684b66a9dccbc86de64cead6fe1bdc61d880bc86b"
}
```

## Recomputed after owned infrastructure cleanup

```json
{
  "clean_windows": 10,
  "delivered_alerts": 3,
  "feedback_quarantine": {
    "direct_database_denials": 15,
    "packet_sha256": "badfd15fb2e0b4eee34b0954c06c1cac01312a71cd48be020223ed79b4a48c8e",
    "promotion_unchanged": true,
    "protected_tables_unchanged": true,
    "quarantine_rows_added": 1,
    "record_sha256": "630ac74560ecc6f25bfbfdf21452fbd17905b855c5feb3050ad6f613ab99e563",
    "release_ready": false,
    "retry_unchanged": true,
    "schema_version": 1,
    "status": "pass",
    "submitted_records": 10,
    "training_eligible": false,
    "verified_labels": false
  },
  "full_M15": "inconclusive",
  "max_delivery_seconds": 0.398394584,
  "observations": 12000,
  "packet_sha256": "f8a26f56331477a718eedc293a8591d0b6a9f9b2d13d19177df98d06eaac03e4",
  "post_cleanup_reverified": true,
  "reference_sha256": "2740c9f3259578a11c80b801558b4acd168bd6ed5559ca85a9d2f338f6d5ca3a",
  "release_ready": false,
  "schema_version": 1,
  "shift_windows": 2,
  "status": "pass"
}
```

