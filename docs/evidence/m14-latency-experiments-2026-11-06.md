# M14: диагностика latency и ресурсных отказов, 2026-11-06

Статус: частичные hosted-наблюдения. Нагрузочная и ресурсная приёмка не пройдены,
`release_ready=false`, полный R1 не завершён. Эти данные дополняют
[первый baseline](m14-load-baseline-2026-11-06.md), а не заменяют отсутствующее
доказательство успешного M14. Метод и ограничения: [ADR 0056](../decisions/0056-load-measurement-profile.md),
действия при отказе: [ранбук](../operations/load-profile.md).

## Измерения

| Source | Correct / 120 s | Successful RPS | Successful p95 / p99, ms | Measured 429 | Причина отказа ресурсов |
| --- | ---: | ---: | --- | ---: | --- |
| `2806a12` | 1540 | 12.833 | 726.907 / 767.181 | 57124 | Разные значения внутри одной секундной метки |
| `98da2b8` | 3146 | 26.217 | 347.711 / 370.745 | 66333 | CPU worker: верхняя граница gap 21 s > 20 s |

Оба опыта: 10 s warmup + 120 s measurement, 10 закрытых клиентских циклов,
новое TCP-соединение на каждый запрос, восемь общих admission slots, прежние
client rate/burst/in-flight и проверки trust/audit. Timeouts, transport errors,
неверные predictions и 5xx равны нулю. Быстрые 429 не скрываются за низким p95
общего распределения; успешные ответы оцениваются отдельно.

`98da2b8` повторно использует одно SQL-соединение на Engine, перечитывая trust
на каждом вызове. Средний trust read снизился с 32.169 до 13.751 ms; среднее
удержание engine lock - с 76.812 до 37.613 ms. Внутренние времена относятся
ко всем фазам и включают вложенные вызовы, их нельзя складывать. Это диагностика
внутри probe, не независимый измеритель. Разные hosted runners и всего два опыта
не позволяют обещать стабильный коэффициент ускорения.

## Проверка источника и очистка

- [2806a12, run 42270925535](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42270925535): SQL stopped/readback 18:34:02 UTC, cluster absence 18:34:05 UTC.
- [98da2b8, run 42273530278](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42273530278): Linux 75 + 109 tests, без пропусков; SQL stopped/readback 18:51:20 UTC, cluster absence 18:51:29 UTC.
- Чистый remote checkout `98da2b8`: 184 Windows tests без пропусков, 7.987 s, import path и чистое Git-дерево проверены. Использовано существующее locked venv Python 3.12.15; три файла зависимостей не изменились. Это не создание нового venv и не локальный инфраструктурный прогон.
- Новый `trust_session.py`: controlled coverage 53/53 statements, 16/16 branches. Проверены reuse/expiry, credential changes, закрытый socket, query failure без скрытого retry, явный shutdown при ошибке worker cleanup и отзыв по новому подписанному документу в том же соединении.

Raw logs и полные пакеты остаются приватными. Ниже только уже опубликованные
конечные диагностические проекции из job logs. Они не содержат inputs, токенов,
закрытых ключей или текстов исключений. SHA-256 рассчитан от canonical JSON без LF,
с целыми timestamps без преобразования через floating point. Квитанция полной
ресурсной проверки в этих опытах не выдана. Новые M11/M13 и итоговый gate на одном
candidate обязательны перед утверждением R1.

## Проекция 2806a12

Canonical SHA-256: `4ee1301a1054fe9222cb80463b4b278b110b4dd6167318dcab547a17cef78b43`.

```json
{
  "container": "controller",
  "diagnostics": {
    "limited": {
      "normal": {
        "client_limited": 39625,
        "overloaded": 22330,
        "unrecognized": 0
      },
      "overload": {
        "client_limited": 0,
        "overloaded": 32,
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
        "count": 1692,
        "failed": 0,
        "max_ns": 172532385,
        "total_ns": 129966058799
      },
      "engine_wait": {
        "count": 1692,
        "failed": 0,
        "max_ns": 699402527,
        "total_ns": 879651629737
      },
      "predict_total": {
        "count": 1688,
        "failed": 0,
        "max_ns": 779209263,
        "total_ns": 1007012941319
      },
      "reader_check": {
        "count": 3384,
        "failed": 0,
        "max_ns": 114560508,
        "total_ns": 117584951751
      },
      "trust_read": {
        "count": 3384,
        "failed": 0,
        "max_ns": 112936870,
        "total_ns": 108860401499
      },
      "worker_ping": {
        "count": 1692,
        "failed": 0,
        "max_ns": 16294860,
        "total_ns": 5789371530
      },
      "worker_predict": {
        "count": 1688,
        "failed": 0,
        "max_ns": 17901467,
        "total_ns": 6405960130
      }
    },
    "window": "warmup-measurement-overload-recovery"
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
    "elapsed_ns": 130355853475,
    "measured": {
      "attempts": 58664,
      "clients": {
        "0": 8886,
        "1": 4635,
        "2": 3924,
        "3": 2808,
        "4": 6401,
        "5": 5567,
        "6": 7571,
        "7": 8585,
        "8": 5659,
        "9": 4628
      },
      "latency_histogram_le_ms": {
        "1": 0,
        "10": 56996,
        "100": 57124,
        "1000": 58664,
        "20": 57121,
        "200": 57124,
        "2000": 58664,
        "5": 48496,
        "50": 57122,
        "500": 57127
      },
      "latency_ms": {
        "max": 803.060772,
        "min": 1.157784,
        "p50": 3.544822,
        "p95": 7.110715,
        "p99": 643.982657
      },
      "outcomes": {
        "http_error": 0,
        "limited": 57124,
        "mismatch": 0,
        "ok": 1540,
        "timeout": 0,
        "transport": 0
      },
      "rps": 488.8666666666667,
      "statuses": {
        "200": 1540,
        "429": 57124
      },
      "success_latency_ms": {
        "max": 803.060772,
        "min": 412.566361,
        "p50": 613.932595,
        "p95": 726.906921,
        "p99": 767.181234
      },
      "successes": 1540,
      "successful_rps": 12.833333333333334,
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
      "attempts": 4970,
      "clients": {
        "0": 1392,
        "1": 766,
        "2": 182,
        "3": 181,
        "4": 485,
        "5": 155,
        "6": 185,
        "7": 200,
        "8": 220,
        "9": 1204
      },
      "latency_histogram_le_ms": {
        "1": 0,
        "10": 4817,
        "100": 4832,
        "1000": 4970,
        "20": 4830,
        "200": 4833,
        "2000": 4970,
        "5": 4187,
        "50": 4831,
        "500": 4838
      },
      "latency_ms": {
        "max": 736.61958,
        "min": 1.264945,
        "p50": 3.479796,
        "p95": 7.193529,
        "p99": 631.683508
      },
      "outcomes": {
        "http_error": 0,
        "limited": 4831,
        "mismatch": 0,
        "ok": 139,
        "timeout": 0,
        "transport": 0
      },
      "rps": 497.0,
      "statuses": {
        "200": 139,
        "429": 4831
      },
      "success_latency_ms": {
        "max": 736.61958,
        "min": 88.31117,
        "p50": 590.601918,
        "p95": 718.261789,
        "p99": 729.625905
      },
      "successes": 139,
      "successful_rps": 13.9,
      "unexpected_5xx": 0
    }
  },
  "release_ready": false,
  "samples": [
    {
      "cpu_at_ns": 1793989903000000000,
      "cpu_core_ns": 15571353000,
      "identity_sha256": "e2d78158d01d3d7c776d661adff771b3c48c73e7c15685d9dc506416d3484daf",
      "memory_at_ns": 1793989903000000000,
      "observed_ns": 1793989903057677612,
      "rss_bytes": 144793600,
      "started_ns": 1793989886000000000,
      "usage_bytes": 150790144,
      "working_set_bytes": 150761472
    },
    {
      "cpu_at_ns": 1793989903000000000,
      "cpu_core_ns": 15649023000,
      "identity_sha256": "e2d78158d01d3d7c776d661adff771b3c48c73e7c15685d9dc506416d3484daf",
      "memory_at_ns": 1793989903000000000,
      "observed_ns": 1793989907188098370,
      "rss_bytes": 144814080,
      "started_ns": 1793989886000000000,
      "usage_bytes": 150949888,
      "working_set_bytes": 150921216
    }
  ],
  "scope": "load-resource-rejection-diagnostic",
  "status": "fail"
}
```

## Проекция 98da2b8

Canonical SHA-256: `925abf969796d7c05233b4b92d776d7f57a275497723984b8b02a1b07631e744`.

```json
{
  "container": "worker",
  "detail": {
    "field": "cpu_at_ns",
    "gap_upper_bound_ns": 21000000000
  },
  "diagnostics": {
    "limited": {
      "normal": {
        "client_limited": 49605,
        "overloaded": 22322,
        "unrecognized": 0
      },
      "overload": {
        "client_limited": 0,
        "overloaded": 32,
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
        "count": 3428,
        "failed": 0,
        "max_ns": 108845861,
        "total_ns": 128935689999
      },
      "engine_wait": {
        "count": 3428,
        "failed": 0,
        "max_ns": 356924170,
        "total_ns": 849535486565
      },
      "predict_total": {
        "count": 3424,
        "failed": 0,
        "max_ns": 393928838,
        "total_ns": 977587407325
      },
      "reader_check": {
        "count": 6856,
        "failed": 0,
        "max_ns": 89048099,
        "total_ns": 108003145460
      },
      "trust_read": {
        "count": 6856,
        "failed": 0,
        "max_ns": 87092212,
        "total_ns": 94276398869
      },
      "worker_ping": {
        "count": 3428,
        "failed": 0,
        "max_ns": 30927021,
        "total_ns": 9650711505
      },
      "worker_predict": {
        "count": 3424,
        "failed": 0,
        "max_ns": 12257249,
        "total_ns": 10994131265
      }
    },
    "window": "warmup-measurement-overload-recovery"
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
    "elapsed_ns": 130109035524,
    "measured": {
      "attempts": 69479,
      "clients": {
        "0": 5989,
        "1": 6440,
        "2": 4209,
        "3": 6018,
        "4": 10571,
        "5": 6090,
        "6": 6874,
        "7": 8761,
        "8": 8392,
        "9": 6135
      },
      "latency_histogram_le_ms": {
        "1": 15,
        "10": 66312,
        "100": 66333,
        "1000": 69479,
        "20": 66329,
        "200": 66336,
        "2000": 69479,
        "5": 62858,
        "50": 66329,
        "500": 69479
      },
      "latency_ms": {
        "max": 412.813149,
        "min": 0.811493,
        "p50": 3.079362,
        "p95": 6.919608,
        "p99": 319.869055
      },
      "outcomes": {
        "http_error": 0,
        "limited": 66333,
        "mismatch": 0,
        "ok": 3146,
        "timeout": 0,
        "transport": 0
      },
      "rps": 578.9916666666667,
      "statuses": {
        "200": 3146,
        "429": 66333
      },
      "success_latency_ms": {
        "max": 412.813149,
        "min": 115.630503,
        "p50": 301.873764,
        "p95": 347.710507,
        "p99": 370.745398
      },
      "successes": 3146,
      "successful_rps": 26.216666666666665,
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
      "attempts": 5863,
      "clients": {
        "0": 574,
        "1": 1007,
        "2": 211,
        "3": 204,
        "4": 402,
        "5": 1276,
        "6": 1440,
        "7": 196,
        "8": 341,
        "9": 212
      },
      "latency_histogram_le_ms": {
        "1": 1,
        "10": 5592,
        "100": 5596,
        "1000": 5863,
        "20": 5594,
        "200": 5598,
        "2000": 5863,
        "5": 5334,
        "50": 5594,
        "500": 5863
      },
      "latency_ms": {
        "max": 360.18666,
        "min": 0.988088,
        "p50": 3.046626,
        "p95": 6.837469,
        "p99": 321.246905
      },
      "outcomes": {
        "http_error": 0,
        "limited": 5594,
        "mismatch": 0,
        "ok": 269,
        "timeout": 0,
        "transport": 0
      },
      "rps": 586.3,
      "statuses": {
        "200": 269,
        "429": 5594
      },
      "success_latency_ms": {
        "max": 360.18666,
        "min": 56.127598,
        "p50": 302.857196,
        "p95": 342.819075,
        "p99": 354.07105
      },
      "successes": 269,
      "successful_rps": 26.9,
      "unexpected_5xx": 0
    }
  },
  "release_ready": false,
  "scope": "load-resource-rejection-diagnostic",
  "status": "fail"
}
```

## Десять admission slots, 7ddb7a4

[Run 42275122970](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42275122970)
не прошёл. Linux 75 + 130 tests, без пропусков. Прогрев: 571 корректный ответ,
ошибок и 429 нет. Measurement: 3304 корректных ответа, 40778 client-limited
и 12398 ответов 503, общий overload равен нулю. p95 успешных ответов 348.545 ms,
p99 384.957 ms. Ресурсная проверка отклонила CPU controller gap с верхней
границей 21 s. SQL stopped/readback 19:01:51 UTC, cluster absence 19:01:54 UTC.
Следующая диагностика снимает конечное состояние audit journal; предположение
о заполнении его бюджета 16 MiB пока не подтверждено. Не следует приписывать
все 503 конкретной причине без этой проверки. Увеличение admission capacity
не завершило M14.

Canonical SHA-256: `bfc1bd4875ad53e97319f18d02a5a013cac3419234770fb7b306c75cfb272abf`.

```json
{
  "container": "controller",
  "detail": {
    "field": "cpu_at_ns",
    "gap_upper_bound_ns": 21000000000
  },
  "diagnostics": {
    "limited": {
      "normal": {
        "client_limited": 40778,
        "overloaded": 0,
        "unrecognized": 0
      },
      "overload": {
        "client_limited": 28,
        "overloaded": 0,
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
        "count": 3880,
        "failed": 0,
        "max_ns": 92545553,
        "total_ns": 69971020342
      },
      "engine_wait": {
        "count": 3880,
        "failed": 0,
        "max_ns": 610412910,
        "total_ns": 490538944246
      },
      "predict_total": {
        "count": 3876,
        "failed": 0,
        "max_ns": 628992908,
        "total_ns": 560360080005
      },
      "reader_check": {
        "count": 7760,
        "failed": 0,
        "max_ns": 70851470,
        "total_ns": 54164195636
      },
      "trust_read": {
        "count": 7760,
        "failed": 0,
        "max_ns": 68477536,
        "total_ns": 43507946245
      },
      "worker_ping": {
        "count": 3880,
        "failed": 0,
        "max_ns": 8947011,
        "total_ns": 6502779124
      },
      "worker_predict": {
        "count": 3876,
        "failed": 0,
        "max_ns": 13218669,
        "total_ns": 9038035011
      }
    },
    "window": "warmup-measurement-overload-recovery"
  },
  "measurement": {
    "checks": {
      "5xx_below_0_1_percent": false,
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
    "elapsed_ns": 130005016744,
    "measured": {
      "attempts": 56480,
      "clients": {
        "0": 5646,
        "1": 5633,
        "2": 5647,
        "3": 5663,
        "4": 5641,
        "5": 5629,
        "6": 5693,
        "7": 5647,
        "8": 5650,
        "9": 5631
      },
      "latency_histogram_le_ms": {
        "1": 0,
        "10": 24832,
        "100": 53452,
        "1000": 56480,
        "20": 53139,
        "200": 55512,
        "2000": 56480,
        "5": 74,
        "50": 53178,
        "500": 56468
      },
      "latency_ms": {
        "max": 671.780507,
        "min": 1.145725,
        "p50": 10.285491,
        "p95": 152.182955,
        "p99": 216.075206
      },
      "outcomes": {
        "http_error": 12398,
        "limited": 40778,
        "mismatch": 0,
        "ok": 3304,
        "timeout": 0,
        "transport": 0
      },
      "rps": 470.6666666666667,
      "statuses": {
        "200": 3304,
        "429": 40778,
        "503": 12398
      },
      "success_latency_ms": {
        "max": 671.780507,
        "min": 44.910295,
        "p50": 162.052487,
        "p95": 348.54475,
        "p99": 384.957208
      },
      "successes": 3304,
      "successful_rps": 27.533333333333335,
      "unexpected_5xx": 12398
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
      "attempts": 571,
      "clients": {
        "0": 55,
        "1": 55,
        "2": 58,
        "3": 61,
        "4": 54,
        "5": 61,
        "6": 54,
        "7": 59,
        "8": 59,
        "9": 55
      },
      "latency_histogram_le_ms": {
        "1": 0,
        "10": 0,
        "100": 41,
        "1000": 571,
        "20": 0,
        "200": 428,
        "2000": 571,
        "5": 0,
        "50": 2,
        "500": 568
      },
      "latency_ms": {
        "max": 513.565039,
        "min": 40.985238,
        "p50": 160.489055,
        "p95": 333.481358,
        "p99": 382.019506
      },
      "outcomes": {
        "http_error": 0,
        "limited": 0,
        "mismatch": 0,
        "ok": 571,
        "timeout": 0,
        "transport": 0
      },
      "rps": 57.1,
      "statuses": {
        "200": 571
      },
      "success_latency_ms": {
        "max": 513.565039,
        "min": 40.985238,
        "p50": 160.489055,
        "p95": 333.481358,
        "p99": 382.019506
      },
      "successes": 571,
      "successful_rps": 57.1,
      "unexpected_5xx": 0
    }
  },
  "release_ready": false,
  "scope": "load-resource-rejection-diagnostic",
  "status": "fail"
}
```
