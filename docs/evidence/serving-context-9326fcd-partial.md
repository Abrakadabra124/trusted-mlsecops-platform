# Failed native attempt 9326fcd: selected evidence

Это выбранные очищенные excerpts, не полный gate report и не pass. [Storage run](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38939866993), job `117104507602`, commit `9326fcde917c92a4a34aa06c2a21b8720a55e47f`. Пять context cases прошли, но fault injection не выбрал новый predict_result path. SQL не был остановлен: entered=false, ACTIVE отсутствует, HTTP 200. Qualification корректно отказала; нельзя выдать это за проверку deadline при остановленном SQL.

```json
{
  "context_cases": [
    {
      "case": "context-candidate-not-release-selection",
      "status": "pass"
    },
    {
      "case": "context-ready-generation-bound",
      "status": "pass"
    },
    {
      "case": "context-prediction-generation-bound",
      "status": "pass"
    },
    {
      "case": "context-private-references-not-public",
      "status": "pass"
    },
    {
      "case": "context-public-shape-unchanged",
      "status": "pass"
    }
  ],
  "http_paused_query": {
    "denial": {
      "active_observed": null,
      "connected_read_entered": false,
      "finished_monotonic": 509.894684387,
      "finished_wall": 1792172156.2675605,
      "generation_fenced": false,
      "http_status": 200,
      "libpq_query_active_at_denial": false,
      "read_finished_at_denial": false,
      "response_valid": true,
      "started_monotonic": 509.866715022,
      "started_wall": 1792172156.2395902
    },
    "last_verified": {
      "deadline": 569.80696122,
      "document_sha256": "c2bb2d517e3fa8ba6273a4f379d746cc9edb58fc33e46b27116e8559d5b52146",
      "monotonic": 509.818263657,
      "sequence": 43,
      "version": 1,
      "wall": 1792172156.191139
    },
    "profile": "request-deadline",
    "release_ready": false,
    "schema_version": 1,
    "status": "inconclusive"
  }
}
```

