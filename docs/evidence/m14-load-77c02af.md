# M14 baseline 77c02af: первичный публичный отчёт

Один запуск, профиль отклонён по p95. Не M14 acceptance и не R1.
Canonical SHA-256: `e872b4da4bf206c4a125abffb53d4145a5a8edbd28548b859dcaaed14becbb3a`.
[Run 42279037992](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42279037992), job128102833804.

```json
{
  "candidate_reference": "77ac15b778e726a5d80cf8ffb52fee387aceed49f331ef91d300ab584a09a39e",
  "finished_at": "2026-11-06T19:28:28.722242+00:00",
  "full_M14": "inconclusive",
  "model_sha256": "fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46",
  "native": {
    "diagnostics": {
      "audit": {
        "accepted": 28040,
        "budget_bytes": 536870912,
        "capacity": 64,
        "closed": false,
        "durable": 28040,
        "durable_bytes": 30328174,
        "failed": false,
        "healthy": true,
        "held_bytes": 0,
        "held_slots": 0,
        "pending": 0,
        "reservations": 0,
        "reserved_bytes": 30328174,
        "unconfirmed": 0
      },
      "limited": {
        "normal": {
          "client_limited": 0,
          "overloaded": 0,
          "unrecognized": 0
        },
        "overload": {
          "client_limited": 0,
          "overloaded": 30,
          "unrecognized": 0
        },
        "recovery": {
          "client_limited": 0,
          "overloaded": 0,
          "unrecognized": 0
        }
      },
      "scope": "probe-internal-diagnostics-not-independent",
      "timings": {
        "engine_hold": {
          "count": 7013,
          "failed": 0,
          "max_ns": 62634307,
          "total_ns": 129317021241
        },
        "engine_wait": {
          "count": 7013,
          "failed": 0,
          "max_ns": 594445045,
          "total_ns": 911169255694
        },
        "predict_total": {
          "count": 7009,
          "failed": 0,
          "max_ns": 616648894,
          "total_ns": 1040193007272
        },
        "reader_check": {
          "count": 14026,
          "failed": 0,
          "max_ns": 42965045,
          "total_ns": 94938462052
        },
        "trust_read": {
          "count": 14026,
          "failed": 0,
          "max_ns": 41910628,
          "total_ns": 74897943371
        },
        "worker_ping": {
          "count": 7013,
          "failed": 0,
          "max_ns": 18258146,
          "total_ns": 14647291492
        },
        "worker_predict": {
          "count": 7009,
          "failed": 0,
          "max_ns": 23428156,
          "total_ns": 19023078123
        }
      },
      "window": "warmup-measurement-overload-recovery"
    },
    "elapsed_seconds": 151.266549,
    "full_M14": "inconclusive",
    "golden": {
      "absolute_score_tolerance": 1e-06,
      "bundle_sha256": "b6872a5179f6e4a017d7f9c3da710ac983d3b82b0fe05b7e531bce62c398ad04",
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
        "no_timeouts_transport_or_quota_denials": true,
        "no_unexpected_non5xx_http_errors": true,
        "no_wrong_predictions": true,
        "not_capped": true
      },
      "elapsed_ns": 130166512347,
      "measured": {
        "attempts": 6455,
        "clients": {
          "0": 659,
          "1": 658,
          "2": 645,
          "3": 643,
          "4": 634,
          "5": 649,
          "6": 640,
          "7": 645,
          "8": 651,
          "9": 631
        },
        "latency_histogram_le_ms": {
          "1": 0,
          "10": 0,
          "100": 499,
          "1000": 6455,
          "20": 0,
          "200": 4683,
          "2000": 6455,
          "5": 0,
          "50": 10,
          "500": 6438
        },
        "latency_ms": {
          "max": 661.31618,
          "min": 44.624565,
          "p50": 175.449878,
          "p95": 341.144841,
          "p99": 375.87118
        },
        "outcomes": {
          "http_error": 0,
          "limited": 0,
          "mismatch": 0,
          "ok": 6455,
          "timeout": 0,
          "transport": 0
        },
        "rps": 53.791666666666664,
        "statuses": {
          "200": 6455
        },
        "success_latency_ms": {
          "max": 661.31618,
          "min": 44.624565,
          "p50": 175.449878,
          "p95": 341.144841,
          "p99": 375.87118
        },
        "successes": 6455,
        "successful_rps": 53.791666666666664,
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
        "attempts": 543,
        "clients": {
          "0": 53,
          "1": 55,
          "2": 52,
          "3": 55,
          "4": 53,
          "5": 54,
          "6": 55,
          "7": 58,
          "8": 57,
          "9": 51
        },
        "latency_histogram_le_ms": {
          "1": 0,
          "10": 0,
          "100": 53,
          "1000": 543,
          "20": 0,
          "200": 403,
          "2000": 543,
          "5": 0,
          "50": 2,
          "500": 542
        },
        "latency_ms": {
          "max": 518.340157,
          "min": 40.76581,
          "p50": 175.166662,
          "p95": 342.483188,
          "p99": 375.841645
        },
        "outcomes": {
          "http_error": 0,
          "limited": 0,
          "mismatch": 0,
          "ok": 543,
          "timeout": 0,
          "transport": 0
        },
        "rps": 54.3,
        "statuses": {
          "200": 543
        },
        "success_latency_ms": {
          "max": 518.340157,
          "min": 40.76581,
          "p50": 175.166662,
          "p95": 342.483188,
          "p99": 375.841645
        },
        "successes": 543,
        "successful_rps": 54.3,
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
        "kubelet_housekeeping_interval_seconds": 5,
        "node_capacity": {
          "cpu": "4",
          "memory": "16366512Ki"
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
      "diagnostics_sha256": "08102c2b2ebe91ccd08e19aa1c7d1e4aa2912c48b1a6e7089b812235415751c3",
      "resources": {
        "controller": {
          "average_cpu_cores": 0.9308292076923077,
          "average_cpu_cores_bounds": [
            0.9237236412213741,
            0.9380449379844962
          ],
          "clock_uncertainty_ns": 720,
          "cpu_core_seconds": 121.007797,
          "cpu_observed_seconds": 130.0,
          "cpu_observed_seconds_bounds": [
            129.0,
            131.0
          ],
          "max_sample_gap_seconds": 11.0,
          "max_sampled_rss_bytes": 148054016,
          "max_sampled_usage_bytes": 183779328,
          "max_sampled_working_set_bytes": 183750656,
          "requested_window_seconds": 120.0,
          "samples": 40,
          "source": "kubelet-summary-container",
          "timestamp_resolution_seconds": 1.0,
          "true_peak_memory_measured": false
        },
        "worker": {
          "average_cpu_cores": 0.049970359375,
          "average_cpu_cores_bounds": [
            0.049582992248062015,
            0.05036382677165354
          ],
          "clock_uncertainty_ns": 720,
          "cpu_core_seconds": 6.396206,
          "cpu_observed_seconds": 128.0,
          "cpu_observed_seconds_bounds": [
            127.0,
            129.0
          ],
          "max_sample_gap_seconds": 11.0,
          "max_sampled_rss_bytes": 40620032,
          "max_sampled_usage_bytes": 41799680,
          "max_sampled_working_set_bytes": 41787392,
          "requested_window_seconds": 120.0,
          "samples": 40,
          "source": "kubelet-summary-container",
          "timestamp_resolution_seconds": 1.0,
          "true_peak_memory_measured": false
        }
      },
      "summary_sha256": "d78dde4df7e591d436284c8eedb1269f7f31086a808a5ea257550f8cd708ffbd"
    },
    "operator_retained_reverified": true,
    "overload": {
      "attempts": 40,
      "correct": 10,
      "elapsed_ns": 240468278,
      "errors": 0,
      "limited": 30,
      "profile_met": true,
      "recovered": true
    },
    "profile_met": false,
    "release_ready": false,
    "scope": "actual-candidate-load-observation",
    "status": "pass",
    "subject_sha256": "b6872a5179f6e4a017d7f9c3da710ac983d3b82b0fe05b7e531bce62c398ad04",
    "worker_cleanup_verified": true
  },
  "proposal_reference": "8feb0460ad0e569ac71fefe41b6b5de059c4a4dcd7f4a2b3452b3bea71f1fdba",
  "qualification_permit_sha256": "3956a015bb70ec1f2a8c894c0333b9005db4b2126b26b956ac9a1e8e5be20608",
  "release_ready": false,
  "schema_version": 1,
  "scope": "actual-candidate-load-baseline",
  "source": {
    "image_id": "sha256:25937b610d1f85c2c2942412d2a4283725a0041ea68b056b9e1d0903cb30165a",
    "source_fingerprint": "3488105dee665ee5837a4fb57b1a3c8d858d14363b68c6f5619f383d170a75dd",
    "source_revision": "77c02af33cdd3ab8ca9f3c9d7955a663d39757cc"
  },
  "source_dirty": false,
  "started_at": "2026-11-06T19:24:53.941710+00:00",
  "status": "fail",
  "subject_sha256": "b6872a5179f6e4a017d7f9c3da710ac983d3b82b0fe05b7e531bce62c398ad04"
}
```
