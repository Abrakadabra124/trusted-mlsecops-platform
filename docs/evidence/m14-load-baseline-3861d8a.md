# Первичная публичная проекция M14, source 3861d8a

Один baseline run42266248228, job128058809744. Это точный JSON aggregate
из CI, без raw latency packets и credentials. Измерение завершено,
normal-load profile fail, полный M14 inconclusive. [Разбор](m14-load-baseline-2026-11-06.md).

```json
{
  "candidate_reference": "145b1777e555b67e9573dffed32fc4e61d2fd160033d5a764c386508fbf5a762",
  "finished_at": "2026-11-06T18:02:32.537950+00:00",
  "full_M14": "inconclusive",
  "model_sha256": "fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46",
  "native": {
    "elapsed_seconds": 152.790536,
    "full_M14": "inconclusive",
    "golden": {
      "absolute_score_tolerance": 0.000001,
      "bundle_sha256": "fb005977634a397c90b32bd2130a8b63b737f4cfc6cbb860ed00508376383a17",
      "model_sha256": "fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46",
      "payload_sha256": "9851917c540e6a9167ff7e3958aa502be676280bc8accc9f473213b4b1ee5e15",
      "rows_per_request": 1
    },
    "measurement": {
      "checks": {
        "5xx_below_0_1_percent": true,
        "all_clients_measured": true,
        "all_clients_warmed_up": true,
        "at_least_1000_correct_predictions": true,
        "at_least_1000_requests": true,
        "full_observation_window": true,
        "latency_targets": false,
        "no_timeouts_transport_or_quota_denials": false,
        "no_unexpected_non5xx_http_errors": true,
        "no_wrong_predictions": true,
        "not_capped": true
      },
      "elapsed_ns": 130208818564,
      "measured": {
        "attempts": 115059,
        "clients": {
          "0": 3590,
          "1": 13316,
          "2": 7935,
          "3": 12681,
          "4": 7757,
          "5": 14246,
          "6": 13525,
          "7": 9345,
          "8": 18133,
          "9": 14531
        },
        "latency_histogram_le_ms": {
          "1": 2332,
          "5": 111809,
          "10": 112368,
          "20": 112377,
          "50": 112377,
          "100": 112383,
          "200": 112383,
          "500": 115055,
          "1000": 115059,
          "2000": 115059
        },
        "latency_ms": {
          "max": 516.102259,
          "min": 0.595679,
          "p50": 1.802661,
          "p95": 3.72016,
          "p99": 359.145001
        },
        "outcomes": {
          "http_error": 0,
          "limited": 112383,
          "mismatch": 0,
          "ok": 2676,
          "timeout": 0,
          "transport": 0
        },
        "rps": 958.825,
        "statuses": {
          "200": 2676,
          "429": 112383
        },
        "success_latency_ms": {
          "max": 516.102259,
          "min": 237.279269,
          "p50": 351.085663,
          "p95": 442.318578,
          "p99": 476.04575
        },
        "successes": 2676,
        "successful_rps": 22.3,
        "unexpected_5xx": 0
      },
      "profile": {
        "clients": 10,
        "connections": "one-per-request",
        "max_attempts": 200000,
        "measurement_seconds": 120,
        "model": "closed-loop",
        "percentiles": "nearest-rank",
        "request_timeout_seconds": 2,
        "warmup_seconds": 10
      },
      "profile_met": false,
      "release_ready": false,
      "schema_version": 1,
      "scope": "client-measurement-only",
      "warmup": {
        "attempts": 10508,
        "clients": {
          "0": 186,
          "1": 169,
          "2": 166,
          "3": 2018,
          "4": 168,
          "5": 700,
          "6": 2202,
          "7": 793,
          "8": 3650,
          "9": 456
        },
        "latency_histogram_le_ms": {
          "1": 409,
          "5": 10229,
          "10": 10255,
          "20": 10255,
          "50": 10255,
          "100": 10257,
          "200": 10259,
          "500": 10508,
          "1000": 10508,
          "2000": 10508
        },
        "latency_ms": {
          "max": 429.82536,
          "min": 0.631012,
          "p50": 1.637156,
          "p95": 3.444298,
          "p99": 317.188955
        },
        "outcomes": {
          "http_error": 0,
          "limited": 10255,
          "mismatch": 0,
          "ok": 253,
          "timeout": 0,
          "transport": 0
        },
        "rps": 1050.8,
        "statuses": {
          "200": 253,
          "429": 10255
        },
        "success_latency_ms": {
          "max": 429.82536,
          "min": 59.432481,
          "p50": 306.865553,
          "p95": 399.558347,
          "p99": 424.066924
        },
        "successes": 253,
        "successful_rps": 25.3,
        "unexpected_5xx": 0
      }
    },
    "model_sha256": "fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46",
    "operator": {
      "compute": {
        "controller_resources": {
          "limits": {
            "cpu": "2",
            "ephemeral-storage": "64Mi",
            "memory": "1Gi"
          },
          "requests": {
            "cpu": "100m",
            "ephemeral-storage": "64Mi",
            "memory": "256Mi"
          }
        },
        "node_capacity": {
          "cpu": "4",
          "memory": "16367516Ki"
        },
        "node_info": {
          "architecture": "amd64",
          "containerRuntimeVersion": "containerd://2.3.4",
          "kernelVersion": "7.0.0-1017-azure",
          "kubeletVersion": "v1.36.4",
          "operatingSystem": "linux"
        },
        "worker_resources": {
          "limits": {
            "cpu": "1",
            "ephemeral-storage": "64Mi",
            "memory": "1Gi"
          },
          "requests": {
            "cpu": "100m",
            "memory": "1Gi"
          }
        }
      },
      "resources": {
        "controller": {
          "average_cpu_cores": 1.319076504,
          "clock_uncertainty_ns": 1146,
          "cpu_core_seconds": 164.884563,
          "cpu_observed_seconds": 125,
          "max_sample_gap_seconds": 19,
          "max_sampled_rss_bytes": 198156288,
          "max_sampled_usage_bytes": 228827136,
          "max_sampled_working_set_bytes": 228798464,
          "requested_window_seconds": 120,
          "samples": 42,
          "source": "kubelet-summary-container",
          "true_peak_memory_measured": false
        },
        "worker": {
          "average_cpu_cores": 0.01928233064516129,
          "clock_uncertainty_ns": 1146,
          "cpu_core_seconds": 2.391009,
          "cpu_observed_seconds": 124,
          "max_sample_gap_seconds": 17,
          "max_sampled_rss_bytes": 40628224,
          "max_sampled_usage_bytes": 41799680,
          "max_sampled_working_set_bytes": 41787392,
          "requested_window_seconds": 120,
          "samples": 42,
          "source": "kubelet-summary-container",
          "true_peak_memory_measured": false
        }
      },
      "summary_sha256": "e716b47acc53132bc717e188930cb01c93d20586802ce6e1d6e4c50b4c354f90"
    },
    "operator_retained_reverified": true,
    "overload": {
      "attempts": 40,
      "correct": 8,
      "elapsed_ns": 272124118,
      "errors": 0,
      "limited": 32,
      "profile_met": true,
      "recovered": true
    },
    "profile_met": false,
    "release_ready": false,
    "scope": "actual-candidate-load-observation",
    "status": "pass",
    "subject_sha256": "fb005977634a397c90b32bd2130a8b63b737f4cfc6cbb860ed00508376383a17",
    "worker_cleanup_verified": true
  },
  "proposal_reference": "9bf329bfb4bbaa990a49d174f12df41c7e988ed6f26ee1d5d7b1379d6c12508e",
  "qualification_permit_sha256": "6c5c81e7217ef2fa4108e98cec6849d559d98573bf6d70b46e39e96a99fc35d0",
  "release_ready": false,
  "schema_version": 1,
  "scope": "actual-candidate-load-baseline",
  "source": {
    "image_id": "sha256:0f58a8b6d943d9a905dfe61c167a5c6476b7c6b9649ed690d3c04b5d8840a43d",
    "source_fingerprint": "023b433e8719df938bd59359ca1a92dc18622a9c2caa5f4975a29ef3015851d4",
    "source_revision": "3861d8a0522394ea6121eb7b0d6e15a58095b9c9"
  },
  "source_dirty": false,
  "started_at": "2026-11-06T17:59:07.405929+00:00",
  "status": "fail",
  "subject_sha256": "fb005977634a397c90b32bd2130a8b63b737f4cfc6cbb860ed00508376383a17"
}
```
