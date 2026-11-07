# Публичная проекция M15 observation

Это ограниченная проекция проверенного CI output, не M15 acceptance и не raw packet.
Полный контекст и ограничения: [evidence](monitoring-native-2026-11-07.md).

```json
{
  "schema_version": 1,
  "evidence_kind": "component-observation",
  "native_workflow_run": 42322768934,
  "native_workflow_job": 128250962479,
  "contracts_workflow_run": 42322768944,
  "observation": {
    "binding_sha256": "db22ecc08528953b9eb8eba144a45faac4d45ccfbc18bef42558878ae08867cc",
    "campaign": "ccabe595ae1944e4bb36d51071d838a1",
    "candidate_reference": "9f00fab366e68760e26d2b52c4f9014ff170940d6565c259cd29d46201cf443f",
    "finished_at": "2026-11-07T01:16:59.018341+00:00",
    "full_M15": "inconclusive",
    "model_sha256": "fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46",
    "native": {
      "clean_windows": 10,
      "delivered_alerts": 3,
      "elapsed_seconds": 23.100061,
      "full_M15": "inconclusive",
      "max_delivery_seconds": 0.368848423,
      "model_sha256": "fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46",
      "observations": 12000,
      "operator_retained_reverified": {
        "clean_windows": 10,
        "delivered_alerts": 3,
        "full_M15": "inconclusive",
        "max_delivery_seconds": 0.368848423,
        "observations": 12000,
        "packet_sha256": "5043b3f57c115c81156b1754c0d6ad8a7854c5b9a1438589b736abc78a3b2530",
        "reference_sha256": "23746f54f7e86258b94cb38fb02d428d16cea12ca19178e5ca5120c2ee1e2b3c",
        "release_ready": false,
        "schema_version": 1,
        "shift_windows": 2,
        "status": "pass"
      },
      "packet_sha256": "5043b3f57c115c81156b1754c0d6ad8a7854c5b9a1438589b736abc78a3b2530",
      "reference_sha256": "23746f54f7e86258b94cb38fb02d428d16cea12ca19178e5ca5120c2ee1e2b3c",
      "release_ready": false,
      "schema_version": 1,
      "scope": "actual-candidate-monitoring-observation",
      "shift_windows": 2,
      "status": "pass",
      "subject_sha256": "5b919ab00bee4ba953d6c9239e52dff4b2c3bb558b0c4a7f01bac5bdefb74ad9",
      "worker_cleanup_verified": true
    },
    "proposal_reference": "3363831a57c0dc27c2dc026a69fa2d0744a06e70f45ecc62ec078a4168c57fc3",
    "qualification_permit_sha256": "4980914b838c6c395d0ea01569765c27e9ad74e91a071fb17633c4d0b6caaef4",
    "release_ready": false,
    "schema_version": 1,
    "scope": "actual-candidate-monitoring-observation",
    "source": {
      "image_id": "sha256:b5256720e37eb20eef5232b0461bd278588041230a41dcda4543735d4566fa52",
      "source_fingerprint": "6108c39835667e940a2e3ced8dd6fb4b2290c853e8b03e5ef2e704d62d22ef9e",
      "source_revision": "acb5b18d8d45b5d329a8794ff49c9503800afc49"
    },
    "source_dirty": false,
    "started_at": "2026-11-07T01:16:19.271581+00:00",
    "status": "pass",
    "subject_sha256": "5b919ab00bee4ba953d6c9239e52dff4b2c3bb558b0c4a7f01bac5bdefb74ad9"
  },
  "post_cleanup": {
    "clean_windows": 10,
    "delivered_alerts": 3,
    "full_M15": "inconclusive",
    "max_delivery_seconds": 0.368848423,
    "observations": 12000,
    "packet_sha256": "5043b3f57c115c81156b1754c0d6ad8a7854c5b9a1438589b736abc78a3b2530",
    "post_cleanup_reverified": true,
    "reference_sha256": "23746f54f7e86258b94cb38fb02d428d16cea12ca19178e5ca5120c2ee1e2b3c",
    "release_ready": false,
    "schema_version": 1,
    "shift_windows": 2,
    "status": "pass"
  }
}
```

