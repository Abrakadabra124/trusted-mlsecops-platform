# ADR 0056: фиксированный клиентский профиль M14

Дата: 2026-11-06. Статус: принято для метода измерения; native M14 ещё не принят.

## Требование

[M14](../acceptance.md#m14) сохраняет 10 секунд прогрева, 120 секунд измерения,
10 concurrent clients, одну строку в запросе, не менее 1000 измеренных запросов,
p95 <= 200 ms, p99 <= 500 ms, неожиданные 5xx < 0.1%. Нужны CPU/RAM,
правильный digest, ограниченный overload и воспроизводимый compute profile.
Пропущенные timeout/error не должны улучшать распределение latency.

## Решение

[Измеритель](../../mlsecops/load_measurement.py) использует десять asyncio tasks
как десять закрытых циклов: каждый клиент начинает следующий запрос после
завершения предыдущего. Начало общего окна фиксируется monotonic clock.
Классификация warmup/measurement определяется временем начала запроса;
ответ на запрос, начатый до конца окна, учитывается с полной задержкой.
Генератор завершает начатые запросы, а отмена задачи отменяет дочерние tasks.

Каждый запрос создаёт новое loopback TCP-соединение. Latency включает соединение,
отправку, полный ответ и проверку содержимого. Это явно зафиксированная стоимость
профиля; результат не выдаётся за latency с keep-alive или внешним ingress/TLS.
Стандартный asyncio HTTP-клиент для этого конкретного endpoint принимает только
ограниченный ответ с единственным Content-Length. Он не реализует универсальный
HTTP SDK, redirects, chunked/compressed responses или произвольные адреса.
Абсолютный бюджет запроса 2 секунды действует на весь обмен, включая чтение body.

Для десяти identities используется существующий Access, без изменения его
границ. Общий лимит HTTP-приложения в восемь slots сохраняется до первого
измерения. Из наличия этого лимита следует риск 429 при десяти клиентах;
точное влияние пока не измерено. Нельзя выдавать такую гипотезу за результат benchmark.

[Golden contract](../../mlsecops/load_golden.py) фиксирует первую строку независимого
reference inference и её score до нагрузки. Каждый 200-ответ обязан иметь
точные model/bundle SHA-256, schema version, одну prediction и конечный score
в [0, 1] с абсолютной погрешностью <= 1e-6. Неверный ответ даже в прогреве
делает результат неприемлемым. Бизнес-utility синтетической модели этим не доказывается.

В приватных записях клиента остаются только номер клиента, относительные
start/end timestamps, HTTP status и конечный outcome. Body, token, request ID
и exception text туда не попадают. До 200000 попыток вместе с прогревом;
достижение лимита останавливает новые запросы и не позволяет получить pass.

Отчёт содержит отдельные warmup/measurement счётчики, все outcomes,
RPS и successful RPS, min/p50/p95/p99/max по nearest-rank, кумулятивную
гистограмму и отдельные quantiles успешных ответов. Проверка требует также
1000 корректных predictions, наличия всех десяти клиентов в обоих окнах,
полного времени наблюдения, отсутствия timeout/transport/429 в измерении и
неожиданных non-5xx HTTP errors. Это консервативные дополнительные проверки
benchmark, не смягчение исходных порогов M14. Intentional negatives/overload
будут отдельным опытом и не смешиваются с нормальной нагрузкой.

## Границы и следующий шаг

Сейчас реализованы primitives и controlled tests, а не полный native runner.
`profile_met` означает только выполнение клиентских проверок на переданных
наблюдениях. Отчёт явно имеет `scope=client-measurement-only` и
`release_ready=false`; это не M14 acceptance и не разрешение promotion.

Native интеграция должна связать actual candidate/permit/source/image с этим
измерением, сохранить исходные записи, повторно вычислить report и проверить
cleanup. CPU/RAM должны включать раздельные controller/probe и ONNX-worker
containers. Выбранный источник для следующего шага - операторское чтение
[Kubelet Summary API](https://kubernetes.io/docs/reference/kubelet-api/stats.v1alpha1/)
через [API server proxy](https://kubernetes.io/docs/reference/instrumentation/node-metrics/).
[Чистый parser](../../scripts/load_resources.py) уже проверяет exact node/PodRef/container,
наличие CPU/memory полей, timestamps без потери наносекунд, возраст sample <=30 s,
неизменный startTime/identity, монотонность CPU counters и согласованность cached
samples. Окно ровно 120 s должно быть охвачено с обеих сторон; промежуток между
samples <=20 s, максимум 256 наблюдений. При missing/reset/gap он отказывает,
не заменяет значения нулём. CPU core-seconds и average cores считаются между
реально наблюдавшимися границами, их длительность указана отдельно от 120 s.
Memory выводится как максимум наблюдавшихся usage/working-set/RSS bytes.

Это пока controlled parser, а не проверенная native реализация. Оператору ещё
нужно независимо подтвердить UID/image/restart перед каждым чтением, связать
samples с private start/end handshake и ограничить размер/частоту запросов.
Максимум sampled RAM нельзя называть истинным peak RSS. Дополнительные права
для model worker не требуются.

Closed-loop нагрузка не моделирует независимый поток входящих запросов и
может уменьшать RPS при замедлении сервиса. Результат обязательно указывает
эту модель; искусственно исправленные percentiles не подменяют реальные данные.
Перед оптимизацией сохраняется исходный benchmark; изменения сравниваются
на том же профиле с проверками trust, audit, quotas и cleanup.

## Проверка

Controlled tests проверяют потерю запросов, таймауты, malformed/truncated HTTP,
границу прогрева, tail, cap, cancellation, неправильные digest/score/schema,
точные latency/error thresholds и отказ при неполном окне.
[CI](../../.github/workflows/load-contracts.yml) требует >=95% statements и
branches отдельно для каждого нового модуля. Фактические результаты CI и
native нагрузки публикуются отдельно после проверки, не выводятся из наличия YAML.

Первый компонентный результат: [measurement/golden contracts 41127b1](../evidence/m14-measurement-2026-11-06.md).
