# M14: первый полный нагрузочный baseline, 2026-11-06

Статус: **измерение завершено, профиль нагрузки не пройден**.
Это baseline actual candidate, не принятый M14 и не завершённый R1.
Workflow корректно завершился с failure из-за `profile_met=false`;
`release_ready=false`, `full_M14=inconclusive`.

## Источник и первичные доказательства

- Source: `3861d8a0522394ea6121eb7b0d6e15a58095b9c9`, dirty=false.
- [Native run 42266248228](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42266248228),
  job `128058809744`.
- [Первичный публичный JSON](m14-load-baseline-3861d8a.md).
  Canonical SHA-256: `251f97a17298a8b9d1d8db20b4dceb1f77cf7d98d5c375cd4c99c44de8d3cdbb`.
- Source fingerprint: `023b433e8719df938bd59359ca1a92dc18622a9c2caa5f4975a29ef3015851d4`.
- Image: `sha256:0f58a8b6d943d9a905dfe61c167a5c6476b7c6b9649ed690d3c04b5d8840a43d`.
- Model: `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`.
- Полные candidate/proposal/subject/permit digests находятся в JSON. Ключи,
  credentials, тела запросов и сырые latency records туда не включены.

Два публичных вывода одного report в job log совпали; это один опыт, не два.
Клиентский summary повторно вычислен оператором из приватных записей, его
canonical digest `e716b47acc53132bc717e188930cb01c93d20586802ce6e1d6e4c50b4c354f90`
совпадает с receipt. После выхода probe оператор повторно прочитал сохранённые
packets и проверил отсутствие owned worker Job/Pod.

## Что выполнилось

Подготовка pinned image и disposable cluster -> реальные source data/candidate ->
независимые reference predictions -> подписанный qualification permit ->
production HTTP application с отдельным ONNX worker -> нагрузка ->
отдельная перегрузка -> golden recovery -> проверка retained evidence -> cleanup.

Обычный promotion actual candidate остаётся запрещён без полного assurance.
Qualification permit имеет ограниченный срок и не заменяет release approval.

Профиль: 10 concurrent closed-loop clients, 10 секунд прогрева, 120 секунд
измерения, одна frozen golden row на запрос, отдельное TCP-соединение на каждый
запрос, абсолютный timeout 2 секунды. Все десять identities присутствуют в обоих
окнах. Cap 200000 попыток не достигнут; фактическое полное время клиента
130.208818564 секунды включает завершение tail requests.

## Результат измерения

| Показатель за 120 секунд | Значение |
| --- | ---: |
| Все попытки | 115059 |
| Корректные ответы 200 | 2676 |
| Ответы 429 | 112383 |
| Доля 429 | 97.6742% |
| Все attempts/s | 958.825 |
| Корректные predictions/s | 22.3 |
| Timeout / transport / неверный ответ / 5xx | 0 / 0 / 0 / 0 |
| p95 всех ответов | 3.720160 ms |
| p99 всех ответов | 359.145001 ms |
| p95 успешных ответов | 442.318578 ms |
| p99 успешных ответов | 476.045750 ms |
| Максимальная задержка | 516.102259 ms |

Быстрые отказы составляют большую часть распределения и скрывают задержки
успешных predictions. Поэтому проверяются оба распределения. Target p95 <=200 ms
для успешных ответов нарушен; наличие 429 нарушает normal-load contract.
Timeout/error не исключались из статистики. 1000 корректных predictions,
правильные digests и полное окно сами по себе не дают pass.

Отдельный burst: 40 попыток, 8 корректных ответов, 32 ограничения, 0 ошибок,
272.124118 ms. После refill получен корректный golden response.
Overload profile выполнен; он не исправляет провал обычного нагрузочного профиля.

## Наблюдение ресурсов

Наблюдатель использовал Kubelet Summary API, проверяя UID/spec/image и нулевые
перезапуски. Получено по 42 samples на контейнер. Неопределённость привязки clocks
1146 ns; она учтена в границах окна.

| Контейнер | Средние CPU cores | CPU observation | Max sampled RSS | Max sampled usage |
| --- | ---: | ---: | ---: | ---: |
| Controller/probe | 1.319076504 | 125 s | 198156288 bytes | 228827136 bytes |
| ONNX worker | 0.019282331 | 124 s | 40628224 bytes | 41799680 bytes |

Максимальный промежуток samples: controller 19 s, worker 17 s при лимите 20 s.
CPU observation шире заданных 120 s из-за дискретности samples; обе длительности
указаны явно. RAM является максимумом наблюдавшихся samples, не истинным пиком.

Hosted node: AMD64, 4 CPU, memory capacity 16367516 KiB, Linux,
Kubernetes v1.36.4, containerd 2.3.4. Controller limit 2 CPU/1 GiB,
worker limit 1 CPU/1 GiB. Полные requests/limits и kernel version есть в JSON.
Controller включает load generator и операторские exec reads, поэтому эти
значения не отделяют чистую стоимость приложения от инструмента измерения.
Низкая загрузка ONNX worker не устанавливает конкретную причину задержки.

## Проверки и воспроизведение

На том же source CI выполнил 60 новых/смежных tests за 1.864 s и 49 regression
tests за 0.259 s, без skips. Для каждого из восьми новых модулей отдельно
выполнены >=95% statements и >=95% branches. Частичные значения:
measurement 110/111 statements, 37/38 branches; probe 118/118, 27/28.
Остальные шесть модулей имеют 100% по обоим показателям.

В отдельном checkout из GitHub, detached на exact source, выполнен locked sync
Python 3.12.15 и все 60 controlled tests: pass, 0 skips, 2.638 s, git tree clean.
Использовано окружение ранее созданного fresh checkout; три dependency descriptors
не изменились. Это воспроизведение кода и controlled tests на Windows.
Native Kubernetes нагрузка проверена указанным hosted run, локальная
инфраструктура не запускалась.

[Runbook](../operations/load-profile.md) содержит команды, разбор отказа и
исправленные ошибки подготовки. Для hosted повторения нужен checkout exact source
с неизменённым lockfile; запускать workflow на ref, разрешающемся в этот commit.
Новый commit имеет другой source binding и является новым опытом.

## Очистка и ограничения

Source SQL stop с readback завершён 18:02:33 UTC, удаление owned cluster с
проверкой отсутствия 18:02:37 UTC. Worker/probe cleanup и retained readback
подтверждены до удаления кластера. Чужие ресурсы не затрагивались.

Приватные packets сохранялись и проверялись на CI runner; этот workflow не
обеспечивает их постоянное внешнее хранение. Публичный JSON содержит агрегаты.
Loopback closed-loop нагрузка не измеряет внешний ingress/TLS и не моделирует
независимый входящий поток. Синтетическая модель не доказывает бизнес-utility.

Следующий шаг: измерить внутренние задержки controller/worker exchange и
admission, затем исправлять один подтверждённый bottleneck за раз с тем же
payload/compute profile, сохранёнными trust/audit/quota checks и сравнением
до/после. M14, последующие CP4/CP5, independent M22 и полный R1 остаются открыты.
