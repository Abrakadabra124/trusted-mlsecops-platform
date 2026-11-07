# M14: нагрузка с работающим monitoring

Неделя 10 - Нагрузка и ML monitoring, T18. Проверен commit
`cab2cad335b512cd06baf95ac4411d5465b4be82`.
[M14 run 42331530833](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42331530833),
job `128278929977`: **success; M14 pass, 153 cases = 146 controlled methods +
7 aggregate criteria**. Это приёмка synthetic CPU-профиля с monitoring,
не production release и не завершение M15/M18/R1.

## Что изменилось

Обычный configured Runtime, evaluator и локальный подписывающий receipt sink
теперь обязательны в load probe. Reference построен из validation split того же
подписанного candidate через isolated worker. Создаются новые ключи и приватный
реестр эпох; повторное использование epoch не разрешается. Monitoring не выдаёт
release approval и не запускает обучение.

Start packet фиксирует reference digest, epoch/campaign, sink public key и state
identity. Finish packet связывает bounded state и signed receipt tail с теми же
значениями. Host заново считает успешные responses, проверяет активность
collector, очереди, подписи и сроки доставки. Fresh M14 требует эту проверку;
прежний отчёт с выключенным monitoring не удовлетворяет новому gate.

Collector и sink работают в controller Pod, поэтому их расходы входят в
независимые container CPU/RAM samples. Профиль нагрузки не изменён: 10 s прогрева,
120 s измерения, 10 closed-loop clients, новый TCP connection на запрос,
одна pinned golden строка, request timeout 2 s, cap 200000 attempts.

## Наблюдаемые результаты

| Метрика measurement window | Результат | Критерий |
|---|---:|---:|
| Попытки / корректные ответы | 12958 / 12958 | >=1000 |
| Throughput | 107.983333 requests/s | измеренное значение |
| p50 | 81.589065 ms | измеренное значение |
| p95 | 128.355589 ms | <=200 ms |
| p99 | 139.386008 ms | <=500 ms |
| Maximum | 215.745032 ms | измеренное значение |
| 429 / 5xx / timeout / transport / wrong | 0 / 0 / 0 / 0 / 0 | без скрытых ошибок |

Warmup: 1112/1112 correct. Отдельный overload: 40 attempts, 10 correct,
30 bounded 429, 0 errors, 151.869654 ms; recovery=true. Overload не входит в
normal percentiles. Все десять клиентов участвовали в обоих основных окнах.

Monitoring: **14082 observations**: 1 initial, 1112 warmup, 12958 measurement,
10 overload и 1 recovery. Проверены 14 evaluated windows, 26 delivered
signed receipts, 0 evicted windows, healthy/observing и пустые pending queues.
Каждый retained receipt прошёл проверку подписи и доставки менее 120 s.
Одинаковая golden строка намеренно отличается от validation distribution,
поэтому drift warnings ожидаемы. Это не измерение false-positive rate.

Независимый operator получил по 41 sample для controller и worker; maximum
upper-bound sampling gap 11 s, requested window 120 s. Controller average CPU
1.039840111 cores, maximum sampled usage 222351360 bytes, RSS 155648000 bytes.
Worker average CPU 0.065974609 cores, usage 41791488 bytes, RSS 40615936 bytes.
Limits: controller 2 CPU / 1 GiB, worker 1 CPU / 1 GiB. Sampled memory не является
true peak; сравнение с отдельным прежним run не доказывает точную цену monitoring.

## Ошибки, исправление и завершение

Первый `188c8fd` /42330214255 остановился до инфраструктуры: fixture ожидал drift
после одного окна. Test исправлен на два достаточных окна без изменения порогов.
Затем `9e361a0` /42330627959 дошёл до shutdown и отказал с
`audit_shutdown_pending`; SQL/cluster cleanup прошёл, M14 остался fail.

В `cab2cad` clean close сохраняет чтение и проверку identity/size/SHA-256 каждого
retained segment, inventory/lease и fsync manifest. Исключён повторный JSON-разбор
bytes, уже проверенных при write или load. Восстановление по-прежнему разбирает
все sequences. Односекундный timeout не увеличен. Контрольный CPU-only замер и
отрицательные сценарии описаны в [ранбуке](../operations/load-profile.md).
Этот успешный run подтверждает shutdown данного опыта; он не закрывает все
исторические проявления R1-B08 и не даёт гарантии при зависшем диске.

Перед shutdown audit snapshot: accepted=56328, durable=56327, pending=1,
unconfirmed=0, reservations=0, healthy=true. Это промежуточный снимок.
Далее обычный lifespan успешно закрыл monitoring, worker и audit writer;
worker absence подтверждён. Source SQL stopped/readback в 03:01:51 UTC,
cluster absence в 03:01:56 UTC, повторная проверка primary после обеих очисток
успешно завершена в 03:01:57 UTC 2026-11-07.

## Проверка доказательств

CI заново проверил три operator packets и шесть candidate artifacts после
owned cleanup; после SQL/cluster cleanup повторил проверку offline. Локальная
независимая сверка Git archive проверила 171 runtime blob и 478 method/material
blobs, policy digest, 146 method IDs, 7 aggregate criteria, source/candidate и
measurement/monitoring bindings. Локально raw request packets не скачивались.

| Привязка | SHA-256 / значение |
|---|---|
| Source fingerprint | `c408daaf966c70bc54767defaef0835130ecae5dacf563469b2cf4b9dd9414d8` |
| Image | `sha256:17e5b42b06e5220a4edc2219950f217c203cbd40cc4ec4f7e10f748f1f61c2d2` |
| Model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Subject | `7cb2482acc524600cc12d405d48b6064ada66ed510bd391f1be2681d7e9bd2e6` |
| Monitoring reference | `891bad650842f0fd3462fd51a027ad5cad59fd72a3006d5251388b2f807c3b49` |
| Monitoring proof | `810f5858ed083233b3a72680a709a98dc1fb34d1ba67ed581be7ab09341c8d5e` |
| Private observation | `de01a7575068b412d4962cadf893ec7acff2a357640225617162806f5d399c6c` |
| Public M14 primary | `ec1c0e98355e87b03c13856a1ff336bd9c79fa30b9c7a3e1382cfa2632088278` |
| Public baseline | `611452c8145cbcf315c01c67cfdadae9a2a2cec113b5edb39f3f9f86c8075b54` |

Linux preflight: 118 + 136 + 126 + 8 executions, 0 skips; fresh gate отдельно
выполнил 146 methods. Повторные executions не суммируются как уникальные tests.
12 measured modules: 975/976 statements, 296/298 branches, каждый отдельно >=95%.
`load_monitoring`: 98 statements/22 branches 100%; `audit_retention`:
267/102 100%; `load_gate` и `load_contracts`: 147/20 и 26/4 100%.

Чистый Windows checkout `cab2cad`, новая locked venv Python 3.12.15:
138 tests за 10.609 s, 39 POSIX skips. Это воспроизведение portable subset;
Linux filesystem и инфраструктуру оно не заменяет. Локальные Docker/WSL/SQL/K8s
не запускались.

## Воспроизведение и следующий этап

Для pure tests нужен Git и uv 0.12.23. Выполнить в отдельном чистом checkout:

```sh
git clone https://github.com/Abrakadabra124/trusted-mlsecops-platform.git mlsecops-reproduce
cd mlsecops-reproduce
git checkout cab2cad335b512cd06baf95ac4411d5465b4be82
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.load_monitoring_qualification scripts.load_probe_qualification scripts.kube_load_operator_qualification scripts.load_gate_qualification scripts.audit_retention_qualification scripts.serving_audit_qualification scripts.audit_admission_qualification scripts.audit_snapshot_qualification
```

Полная команда M14 и prerequisites находятся в
[ранбуке](../operations/load-profile.md) и
[workflow](../../.github/workflows/kubernetes-load.yml). Полный опыт выполнять
только в разрешённом disposable hosted CI, проверив `head_sha`, terminal success
и все cleanup steps. Новый run получает новые campaign, keys и receipts;
совпадение случайных идентификаторов не является критерием воспроизводимости.

На том же source [M15 contracts 42331530771](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42331530771)
прошли 142 + 77 + 52 Linux tests/0 skips;
[M15 native 42331530755](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42331530755)
прошёл 12000 observations, 10 clean + 2 shift windows, 3 receipts
(max delivery 0.484450753 s), feedback quarantine и 15 SQL denials, cleanup и
post-cleanup replay. Это отдельный candidate-bound опыт, не общий M18 на одном
candidate. Полные M15/R1 открыты: fresh privacy M13 с monitoring, общая M15
acceptance, остальные обязательные gates; independent M22 остаётся 0/2.
