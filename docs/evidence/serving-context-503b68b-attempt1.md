# M07 failed attempt 1 at 503b68b

Очищенный original M07 report из [Storage attempt 1](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38942124426/attempts/1), job `117112099518`. Serving step не выполнялся. 31 конкурентное выделение slots и один storage_connection_rejected не доказывают ожидаемый holdout_budget_exhausted: gate корректно fail. Конкретная причина отказа соединения этим bounded report не установлена. Запрошен один повтор того же commit в новом disposable runner без изменения кода, политики и порогов. Возможный success повтора не отменяет этот факт и не доказывает исправление причины.

```json
{
  "artifact_hashes": {},
  "cases": [],
  "diagnostics": {
    "holdout_concurrency": {
      "attempts": 32,
      "claimed_slots": [
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        21,
        22,
        23,
        24,
        25,
        26,
        27,
        28,
        29,
        30,
        31,
        32
      ],
      "complete": true,
      "diagnostic_only": true,
      "invalid_receipts": 0,
      "rejection_codes": {
        "storage_connection_rejected": 1
      },
      "schema_version": 1
    }
  },
  "exit_code": 1,
  "finished_at": "2026-10-16T17:47:55.244548+00:00",
  "gate": "M07",
  "input_digests": {
    "source_fingerprint": "ba76619b9a6231b2d120ed117b711e3b0413bbe849fac6c593a6f75e82a98bbc"
  },
  "metrics": {},
  "policy_digest": "9a78ff344304e12e52c54652d8750aae69038e2a1ae2fb2c375a752e67fedb24",
  "profile": "local-cpu",
  "redaction_version": 1,
  "residual_risks": [
    "holdout_qualification_failed:concurrent-over-budget-denied"
  ],
  "schema_version": 1,
  "source_revision": "503b68bbde0fb619132a0e1d797b0173ec55d3f5",
  "started_at": "2026-10-16T17:47:26.500149+00:00",
  "status": "fail"
}
```
