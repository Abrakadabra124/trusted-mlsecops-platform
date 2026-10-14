# ADR 0031: Постоянный изолированный ONNX worker и loopback API

Дата: 2026-10-14. Статус: реализация, native CI ещё не подтверждён. Scope: T15 component. M12/M13/M14/R1 не закрыты.

## Требование и решение

После [ADR 0030](0030-current-release-reader.md) контроллер умеет получить проверенные immutable bytes, но это не runtime load. ONNX Runtime исполняет ONNX-граф; даже файл модели может потреблять чрезмерные ресурсы. Поэтому parsing, structural inspection и inference выполняются в отдельном процессе контейнера, а не рядом с SQL credentials.

`Worker` создаёт постоянный контейнер по точному image digest и сверяет Docker inspect с запросом: non-root 65532, network=none, read-only root, без host mounts/ports/devices/signing keys/client certificates, all capabilities dropped, no-new-privileges, 1 GiB RAM/swap total, 2 CPU, 64 PIDs, 32 MiB noexec/nosuid tmpfs. Docker logs отключены. Local Docker controller/daemon/host остаются доверенными и привилегированными; этот вариант не выдаётся за scoped Kubernetes serving или production isolation.

Модель передаётся через stdin ровно один раз. Worker сверяет hash exact bytes, применяет существующий strict `linear-onnx-v2` scanner и создаёт один CPU InferenceSession из тех же bytes. Load acknowledgment включает session ID, model digest, request digest, scanner result и установленную ONNX Runtime version. Worker не выбирает модель по имени, пути или URL. Модель ограничена 8 MiB; transport load frame 12 MiB. Это ограничение текущего маленького linear profile, не поддержка произвольных моделей.

Далее используются canonical JSON frames с newline, максимум 64 KiB. Каждый predict/ping имеет новый случайный request ID, session ID и model digest. Prediction reply связывается с canonical request hash, row IDs/order/count и finite scores `[0,1]`. EOF, malformed/oversized/partial response, mismatch и timeout закрывают session. Fixed-schema replies не являются hardware attestation и не доказывают отсутствие всех runtime vulnerabilities.

## Ресурсы и lifecycle

Parent pipe transport использует единственный daemon IO thread и очереди ёмкостью один элемент. Deadline охватывает запись в stdin и чтение bounded response: 30 s для initial load, 2 s для predict/ping. Поздний reply не может стать ответом следующему запросу: после timeout session терминальна. Cleanup работает только по полному ID собственного созданного контейнера и подтверждает его отсутствие. При неудаче сохраняется handle для повторной cleanup, а serving остаётся unready.

В worker установлен 120 s alarm на каждую операцию/ожидание stdin. Engine выполняет heartbeat каждые 30 s; остановка parent не должна оставлять обычный idle worker навсегда. Alarm не объявляется защитой от произвольного уже скомпрометированного native runtime; внешние Docker resource limits и cleanup остаются обязательными.

`Engine` активирует model только после Reader.load, Docker config readback, verified worker acknowledgment, ping и повторного Reader.check. Перед каждым prediction проверяет текущий release/trust и worker, после вычисления повторяет Reader.check. При смене head/revoke/expiry ответ отбрасывается, worker закрывается. Даже полностью abstain batch требует живой доверенной session. Ошибка reload не восстанавливает старую модель автоматически. Bad client input отклоняется до lifecycle mutation.

## HTTP contract

FastAPI управляет startup/shutdown через lifespan; Uvicorn CLI слушает только `127.0.0.1`. `POST /v1/predict` принимает schema version 1 и именованные `instances` по шести полям feature contract. Любой extra key, NaN/Inf, boolean вместо числа, другая version, >100 строк или URL/file reference запрещены. Выход использует существующие `decision=score|abstain`, model/bundle digests и новый server request ID. Score является advisory, не приказом автоматически выпускать release.

Actual body bytes считаются при streaming read до накопления сверх 64 KiB; проверяются Content-Length и отсутствие content encoding. Body read ограничен 5 s. Не используется автоматическая неограниченная JSON body загрузка framework. Ответы: 401 без bearer token, 413 oversized, 422 invalid schema/body, 429 overload, 503 no trusted model. Детали исключений, body и raw features в ответы не включаются. Access logs и forwarded proxy headers отключены.

API требует один локальный случайный 256-bit bearer token из отдельного файла. На POSIX secret file должен иметь permissions без group/other access. Windows ACL здесь не проверяются автоматически. `/livez` не требует token и не означает readiness; `/readyz` требует token и проверяет действующий runtime. OpenAPI/docs endpoints отключены. Это single-client lab authentication, не полноценный identity provider, multi-client quotas или M13 audit trail.

Одновременно admitted максимум восемь HTTP операций, Engine ожидает свою lock максимум 1 s. Cancellation запроса **не освобождает slot**, пока реально выполняющийся inference thread не завершится. Это исправлено regression test: отменённый asyncio wrapper не останавливает underlying thread. Перегрузка не создаёт неограниченную очередь. Targets M14 ещё не измерены; 2 s worker deadline не равен 2 s HTTP latency, поскольку существуют SQL/trust checks и cleanup.

## Qualification не заменяет release acceptance

Native runner расширяет изолированную fixture ADR 0030 настоящей сгенерированной ONNX-моделью, pinned serving image и настоящим loopback HTTP. Остальные assurance reports/lineage остаются **controlled contract fixtures** с одноразовыми test roots. Их нельзя использовать для продвижения настоящего candidate или как all-pass M01-M23 evidence. Весь report сохраняет `release_ready=false`, `full_M12=inconclusive`. Ready=true внутри fixture API означает только завершённый verified runtime load в этой тестовой authority.

Настоящий production-like admission по-прежнему требует все gates. Текущие failed image/poisoning/evasion/robustness gates не обходятся startup flag или отдельным insecure route. Для полной приёмки нужны candidate-bound квалификационные reports, M12 runner без подмены остальной acceptance, HTTP trust-outage deadline trace, privacy/audit, benchmark, root rotation/rollback и scoped serving controller. Нельзя разрешить circular dependency «M12 требует approved model, approval требует M12» фиктивным отчётом; qualification environment и final release approval должны оставаться отдельными фазами.

## Источники и доказательства

- [ONNX Runtime overview/security guidance](https://onnxruntime.ai/docs/): модель может потреблять чрезмерные ресурсы; проверка и безопасная тестовая среда необходимы. Проверено 2026-10-14.
- [ONNX Runtime Python API](https://onnxruntime.ai/docs/api/python/api_summary.html): поддержка serialized model bytes; проект использует bytes, не повторное чтение пути.
- [FastAPI lifespan](https://fastapi.tiangolo.com/advanced/events/): единый startup/shutdown lifecycle.
- [Starlette request streaming](https://www.starlette.io/requests/): чтение body chunks без предварительного накопления всего тела; ограничения размера добавлены проектом.
- [API и запуск](../serving-api.md), [PB-25/RB-48/RB-49](../operations/serving-troubleshooting.md), [evidence](../evidence/serving-api-2026-10-14.md).
