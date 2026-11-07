# T18 dashboard: finite acceptance summary

Synthetic CPU scope. Private packets, keys and raw logs excluded.

```json
{
  "clean_checkout_skips": 0,
  "clean_checkout_tests": 37,
  "contracts_linux_executions_with_repeats": 350,
  "contracts_linux_skips": 0,
  "dashboard_and_probe_branches": 26,
  "dashboard_and_probe_coverage_percent": 100,
  "dashboard_and_probe_statements": 55,
  "dashboard_tests": 21,
  "full_R1": "incomplete",
  "gates": [
    {
      "artifact_hashes": {
        "controlled_contracts": "3338508a18c2e9f2c313c4b5421d50427ddab4afc9e85d5afdfd5eefe5a3dd5d",
        "method_materials": "2e5ec68176bead96026c0397215a07c5014d941cea1eef0be3708021dbcf5fd1"
      },
      "cluster_absent_at": "2026-11-07T05:38:05Z",
      "gate": "M15",
      "input_digests": {
        "candidate_reference": "20cdd2980c6a8640547b6901ca572a4362bb1e0c48d6c8739e94bfc39b37f1ed",
        "image_id": "sha256:389b6dd35334721863d44eb8b98c7475281d1105ab6a7a74e13776b91d33cde8",
        "model_sha256": "fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46",
        "proposal_reference": "318f47a2b2705203fb2f447c44e99f81402e74349b9cae50bc518698914cc9c2",
        "qualification_permit_sha256": "15721b6070efd2c4c27fdc34e1fba88c2394928151073bf7fbd995461bc67011",
        "source_fingerprint": "64d583ff1773f1e993765b040bd446e71296870c63b42c9a56f2867e524f291f",
        "source_revision": "6fa4d9690cef2a3a051f31f5a43f708c85b431af",
        "subject_sha256": "afe985543118532271d2828eac44eca59a4e3ee35d0f06d6252fecd1d0de0f77"
      },
      "metrics": {
        "checks": 188,
        "clean_windows": 10,
        "delivered_alerts": 3,
        "feedback": {
          "direct_database_denials": 15,
          "promotion_unchanged": true,
          "protected_tables_unchanged": true,
          "quarantine_rows_added": 1,
          "retry_unchanged": true,
          "submitted_records": 10,
          "training_eligible": false,
          "verified_labels": false
        },
        "max_delivery_seconds": 0.374568635,
        "observations": 12000,
        "shift_windows": 2
      },
      "policy_digest": "9a78ff344304e12e52c54652d8750aae69038e2a1ae2fb2c375a752e67fedb24",
      "post_cleanup_verified_at": "2026-11-07T05:38:08Z",
      "primary_sha256": "4c1761eeb46b7dc4e27f938c82ca9485ddbdf15b9c44263c99aeb64b0465d3cb",
      "release_ready": false,
      "run_url": "https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42343109962",
      "source_dirty": false,
      "source_revision": "6fa4d9690cef2a3a051f31f5a43f708c85b431af",
      "sql_stopped_at": "2026-11-07T05:38:02Z",
      "status": "pass"
    },
    {
      "artifact_hashes": {
        "controlled_contracts": "fdbea5c4c08b46ab5b08f32799d5e51599b1ab8a7382e696ea304dbeaa9838b4",
        "method_materials": "2e5ec68176bead96026c0397215a07c5014d941cea1eef0be3708021dbcf5fd1"
      },
      "cluster_absent_at": "2026-11-07T05:39:00Z",
      "gate": "M13",
      "input_digests": {
        "candidate_reference": "b7b569cf42c4b588c6c99aaf9b3ee3b04cd44f00e389b835446195e96a53ee71",
        "evaluation_reference": "4e83611e758555d1273a80b5c6f005e2699e5bc6e409c8c12b37121139c2a96d",
        "image_id": "sha256:c61088cd53189318b6cc8403b5a6233a1f6498d313f7ca036b0fdf9ee7bff601",
        "model_sha256": "fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46",
        "proposal_reference": "11763773e7134f764b3b3ea243427350d3b08a4a9149cb6970dc0d3615e19378",
        "source_fingerprint": "64d583ff1773f1e993765b040bd446e71296870c63b42c9a56f2867e524f291f",
        "source_revision": "6fa4d9690cef2a3a051f31f5a43f708c85b431af",
        "subject_sha256": "376c26445e6db2de6a407b2e96379664f075c55f395f3f879e2bb8ec7b414181"
      },
      "metrics": {
        "audit_events": 108,
        "checks": 512,
        "closed_service_windows": 5,
        "controlled_cli_checks": 22,
        "controlled_cli_fenced_requests": 2,
        "controlled_cli_independent_admission_observed": false,
        "controlled_cli_matrix_requests": 12,
        "controlled_cli_metric_series": 69,
        "controlled_cli_output_bytes": 0,
        "controlled_cli_quota_requests": 6,
        "controlled_cli_retained_snapshot_reverified": true,
        "controlled_cli_service_log_windows": 2,
        "correlated_requests": 18,
        "detected_service_leak_controls": 5,
        "feedback_privacy": {
          "detected_service_leak_controls": 1,
          "direct_database_denials": 15,
          "promotion_unchanged": true,
          "protected_tables_unchanged": true,
          "quarantine_rows_added": 1,
          "rejected_commands": 8,
          "rejections_unchanged": true,
          "release_ready": false,
          "retained_reverified": true,
          "retry_unchanged": true,
          "schema_version": 1,
          "scope": "actual-feedback-cli-privacy-not-full-M13",
          "source_service_windows": 1,
          "status": "pass",
          "submitted_records": 1,
          "successful_commands": 3
        },
        "input_canaries": 9,
        "metric_series": 69,
        "monitoring_observations": 1014,
        "monitoring_privacy": {
          "ambient_signals_used": false,
          "audit_events_confirmed": 40,
          "dashboard_requests": 9,
          "label_accepted": 1,
          "label_retry_accepted": 0,
          "metric_series": 69,
          "observations_added": 1000,
          "operator_requests": 18,
          "prediction_requests": 10,
          "quota_accepted": 7,
          "quota_limited": 13,
          "quota_recovered": true,
          "quota_requests": 20,
          "rejected_labels_or_framing": 9,
          "release_ready": false,
          "schema_version": 1,
          "scope": "operator-monitoring-privacy-component-not-full-M13",
          "status": "pass",
          "unauthorized_requests": 4
        },
        "native_stderr_bytes": 0,
        "observed_http_responses": 35,
        "post_cleanup_primary_reverified": true,
        "privacy_durable_events": 36,
        "privacy_requests": 12,
        "retained_packet_reverified": true,
        "retained_service_packets_reverified": 5,
        "service_log_windows": 2,
        "source_feedback_service_windows": 1,
        "worker_cleanup": true,
        "worker_terminal_stream": true
      },
      "policy_digest": "9a78ff344304e12e52c54652d8750aae69038e2a1ae2fb2c375a752e67fedb24",
      "post_cleanup_verified_at": "2026-11-07T05:39:01Z",
      "primary_sha256": "3ef71b6651b2acdcd957648428aef7b9177cb3c93161e8510e339d52e10b8d28",
      "release_ready": false,
      "run_url": "https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42343123664",
      "source_dirty": false,
      "source_revision": "6fa4d9690cef2a3a051f31f5a43f708c85b431af",
      "sql_stopped_at": "2026-11-07T05:38:55Z",
      "status": "pass"
    }
  ],
  "node_hosted": "22.23.4",
  "node_local": "24.19.0",
  "same_release_candidate_across_gates": false,
  "scope": "T18 synthetic dashboard and separate fresh M13/M15 campaigns, not M18/R1"
}
```
