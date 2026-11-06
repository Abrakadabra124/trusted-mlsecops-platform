# ADR 0056: фиксированный клиентский профиль M14

Дата: 2026-11-06. Статус: принято для метода измерения; native M14 ещё не принят.

Первый [полный baseline 3861d8a](../evidence/m14-load-baseline-2026-11-06.md)
завершил измерение и cleanup, но не прошёл normal-load contract. Описанная ниже
исходная гипотеза о 429 теперь дополнена измерениями; конкретные внутренние
bottlenecks ещё требуют локализации.

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
границ. Первые измерения сохранили общий лимит в восемь slots. При десяти
клиентах он неизбежно вызывает overload; повторные быстрые попытки также
расходуют per-client quota. Диагностика `98da2b8` различила 22322 общих отказа
и 49605 client-limited за прогрев и измерение. Следующий эксперимент устанавливает
фиксированные десять общих slots, соответствующие нормальному профилю M14.
Это ограниченная ёмкость, не неограниченная очередь; Engine lock timeout,
client rate/burst/in-flight, response deadline и audit reservations сохраняются.
Проверка stalled audit удерживает десять запросов, требует отказа одиннадцатого
и доступности `/livez` при Uvicorn limit 16. Это уточняет прежнее значение 8
в ADR 0031/0035/0040, не переписывая результаты старых экспериментов.

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

Реализованы primitives, controlled tests и native baseline runner; первый
полный нагрузочный запуск на actual candidate проверен в указанном evidence.
`profile_met` означает только выполнение клиентских проверок на переданных
наблюдениях. Отчёт явно имеет `scope=client-measurement-only` и
`release_ready=false`; это не M14 acceptance и не разрешение promotion.

Native интеграция связала actual candidate/permit/source/image с измерением,
сохранила исходные записи на CI runner, повторно вычислила report и проверила
cleanup. CPU/RAM включают раздельные controller/probe и ONNX-worker
containers. Источник - операторское чтение
[Kubelet Summary API](https://kubernetes.io/docs/reference/kubelet-api/stats.v1alpha1/)
через [API server proxy](https://kubernetes.io/docs/reference/instrumentation/node-metrics/).
[Чистый parser](../../scripts/load_resources.py) уже проверяет exact node/PodRef/container,
наличие CPU/memory полей, возраст sample <=30 s, неизменный startTime/identity
и монотонность CPU counters. Окно ровно 120 s должно быть охвачено с обеих сторон;
промежуток между samples <=20 s, максимум 256 наблюдений. При missing/reset/gap он отказывает,
не заменяет значения нулём. CPU core-seconds и average cores считаются между
реально наблюдавшимися границами, их длительность указана отдельно от 120 s.
Memory выводится как максимум наблюдавшихся usage/working-set/RSS bytes.

Уточнение формата: [CPUStats/MemoryStats Kubernetes 1.36.4](https://github.com/kubernetes/kubernetes/blob/v1.36.4/staging/src/k8s.io/kubelet/pkg/apis/stats/v1alpha1/types.go)
используют `metav1.Time`, чей [JSON encoder](https://github.com/kubernetes/apimachinery/blob/v0.36.4/pkg/apis/meta/v1/time.go)
отбрасывает дробную часть секунды. Поэтому одинаковая метка допускает разные
снимки внутри секунды; отрицательная дельта CPU всё равно запрещена. Parser
сохраняет входные цифры, но не приписывает источнику наносекундную точность.
Ранний sample принимается только если вся его секундная корзина предшествует
началу окна с учётом clock uncertainty. К максимальному gap прибавляется 1 s;
порог 20 s остаётся прежним. CPU duration и average cores имеют отдельные
консервативные нижнюю и верхнюю границы, номинальная оценка явно приблизительна.
Исторический baseline `3861d8a` использовал прежнюю точечную интерпретацию;
его CPU duration и gap не подтверждают скорректированную ресурсную проверку.

Native оператор теперь связывает parser с проверками UID/image/restart перед
каждым чтением и private start/end handshake. Этот путь проверен
на controlled API fixtures и в опубликованном hosted baseline.
Максимум sampled RAM нельзя называть истинным peak RSS. Дополнительные права
для model worker не требуются.

Closed-loop нагрузка не моделирует независимый поток входящих запросов и
может уменьшать RPS при замедлении сервиса. Результат обязательно указывает
эту модель; искусственно исправленные percentiles не подменяют реальные данные.
Перед оптимизацией сохраняется исходный benchmark; изменения сравниваются
на том же профиле с проверками trust, audit, quotas и cleanup.

Первое измеренное узкое место в диагностике `2806a12` - trust reads:
108.860 s из 129.966 s удержания engine lock во всех фазах. Для проверки
гипотезы о стоимости handshake добавлена [сессия](../../mlsecops/trust_session.py)
из одного соединения на Engine с пределом повторного использования 5 s,
повторной проверкой credential files и явным cleanup. Каждый вызов по-прежнему
читает свежий trust document. Новые зависимости и общий глобальный пул не нужны.
[Psycopg connection lifecycle](https://www.psycopg.org/psycopg3/docs/api/connections.html)
и [autocommit](https://www.psycopg.org/psycopg3/docs/basic/transactions.html)
определяют закрытие и отсутствие idle transaction. В нагрузочном candidate и
production configured HTTP entrypoint применяется один механизм; старые
одноразовые диагностические reader paths сохраняют соединение на каждый read.
Проверки M11/M13 на новой реализации и полный acceptance остаются обязательными.

## Проверка

Эксперимент порядка выполнения после `df7ff2f`: 6929/6929 корректных measured
ответов, ноль 429/5xx/timeout/mismatch, но p95=313.890 ms. Среднее удержание
Engine lock 17.141 ms во всех фазах; суммарное ожидание 910.812 s, максимум
589.690 ms. Это основание проверить влияние очереди, а не доказательство
единственной причины latency. Credential parameters тоже стоят 43.109 s,
но их проверки в этом эксперименте не меняются.

HTTP execution теперь ожидает штатный `asyncio.Lock` до запуска `to_thread`.
[Python 3.12 гарантирует порядок ожидающих asyncio tasks](https://docs.python.org/3.12/library/asyncio-sync.html#asyncio.Lock),
а [порядок ожидающих threading.Lock не определён](https://docs.python.org/3.12/library/threading.html#lock-objects).
Queue wait ограничен меньшим из 1 s и remaining response budget; по timeout
применяется прежний `serving_busy` / HTTP 429. Внешние десять admission slots
ограничивают одновременно исполняющиеся и ожидающие requests. Engine lock,
trust reads до/после inference, worker protocol и audit остаются прежними.

Owned task сохраняется в pending до завершения, поэтому client cancellation
не освобождает slot у ещё работающего backend. После получения очереди budget
и generation проверяются ещё раз до executor. Lock освобождается в finally.
При измерении `engine_wait` теперь отражает только внутренний mutex; время
новой HTTP очереди полностью входит в независимую client-side latency.
Controlled checks подтверждают порядок, timeout без executor, expired generation,
сохранение ownership и доступность следующего запроса после отказа.
Ускорение и полный M14 подтверждаются только новым native запуском.

После [измерения 506a762](../evidence/m14-fifo-2026-11-06.md) устранена повторная
проверка TLS-файлов перед входом в managed Session. `trust_authority.read`
передаёт ответственность доверенному factory `Session.connection`; это внутренняя
зависимость кода, не поле HTTP/CLI. Session на КАЖДОМ использовании выполняет
полный `connection_materials`, проверку serving/promoter role, host pin и
fingerprint четырёх файлов. Ошибка теперь попадает внутрь ownership boundary
и закрывает прежнее соединение до SQL. Для обычного fresh-connect пути внешний
role preflight сохранён. Новые внешние factories обязаны соблюдать тот же контракт.
Документы доверия, подписи, версии и отзыв по-прежнему читаются и проверяются
для каждого запроса; response cache не появился. Ускорение требует нового native run.

Следующий шаг после p95=211.132398 ms на `91039fd`: одна bounded read каждого
из четырёх TLS/client files на проверку. `connection_materials` валидирует
settings/certificates и возвращает параметры с SHA-256 тех же прочитанных байтов.
`connection_parameters` сохраняет прежний интерфейс; Session использует оба
результата без повторного чтения. Fingerprints не кешируются, проверка после
нового connect и на каждом reuse сохранена. Лимит settings 65536 bytes теперь
применяется также к обычному fresh-connect пути (ранее этот предел уже был
обязателен для Session). Private key bytes не возвращаются вызывающему коду.
Diagnostic row `client_parameters` теперь измеряет весь `connection_materials`,
включая fingerprints; прежняя строка измеряла только validation parameters.
Это изменение состава timing, а не самостоятельное доказательство ускорения.

Controlled tests проверяют потерю запросов, таймауты, malformed/truncated HTTP,
границу прогрева, tail, cap, cancellation, неправильные digest/score/schema,
точные latency/error thresholds и отказ при неполном окне.
[CI](../../.github/workflows/load-contracts.yml) требует >=95% statements и
branches отдельно для каждого нового модуля. Фактические результаты CI и
native нагрузки публикуются отдельно после проверки, не выводятся из наличия YAML.

Первый компонентный результат: [measurement/golden contracts 41127b1](../evidence/m14-measurement-2026-11-06.md).
Первый профиль, выполнивший все client/resource/overload predicates:
[5f6fb84](../evidence/m14-load-pass-5f6fb84.md). Он не заменяет общую композицию.

## Fresh acceptance

`load_gate` соединяет текущий inventory controlled methods с новым actual-candidate
опытом. Ни skips, ни старый baseline не разрешают pass. Operator receipt включает
SHA-256 исходных start/finish/resource packets; после owned cleanup gate проверяет
их байты и повторяет summary/resource расчёт, а также проверяет хеши четырёх
candidate artifacts. Source/image, method materials и primary не меняются между
началом и завершением. Отчёт использует существующий `acceptance --gate M14`
с теми же fail/inconclusive правилами, что M11-M13. Native acceptance этого
нового пути ещё требуется; M18 остаётся последним и проверяет общий release.
