# RB-66 / PB-40: наблюдение полного serving lifecycle

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0047](../decisions/0047-serving-output-observation.md), [карта каналов](../privacy-output-map.md), [evidence](../evidence/serving-output-2026-10-19.md).

## Назначение и владелец

Observer закрывает пробел между Python redirects и actual stdout/stderr FDs дочернего qualification-процесса. Он не запускает production, не выдаёт release approval и не заменяет полный M13. Ответственный - владелец disposable GitHub-hosted CI job; security reviewer подключается при canary/schema mismatch.

Новый wrapper поддерживает только существующий ubuntu-24.04 hosted workflow с explicit confirmation. На local/shared/self-hosted host не запускать и не подделывать environment guard. Guard не является криптографическим доказательством hosted VM. Pure unit tests разрешены локально, Docker/WSL/SQL для них не нужны.

## RB-66: диагностика

2026-10-23: Storage `fa053bc` ([40004068900](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40004068900)) и новый end-to-end `72071df` ([40007993642](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40007993642)) отказали в child observer; отдельный `af472f3` прошёл. Это воспроизведённая нестабильность, но не установленная причина. Повторять неизменённый код ради green запрещено. Для следующего изменённого прогона parent при `Rejected` читает bounded fault traces своей текущей campaign и выводит `scope=serving-failure-diagnostic-not-acceptance`: только enum статусы, известные outage причины, ограниченное время первого 503, HTTP 200/503 и фиксированные boolean признаки paused query. Missing/malformed/oversized trace даёт unavailable; raw exception, stdout/stderr, features, URLs, campaign/model hashes и credentials не выводятся. Диагностический итог всегда fail; исходное исключение повторно поднимается, approval не создаётся. Эти поля локализуют проблему, но не служат подписанным acceptance evidence и не подтверждают cleanup после forced stop.

| Симптом | Причина/граница | Действие |
| --- | --- | --- |
| serving_output_rejected, child nonzero | Guard, ownership, source, capture, native operation или schema отказ | Сверить commit/job/step и постоянный код; не печатать raw captured stderr/exception или private state. |
| worker_output_noncanonical | Лишние bytes, включая whitespace, до/после JSON | Не обрезать вывод и не отключать strict mode. Найти producer через controlled child negative tests. |
| serving_output_late_write | Сохранённый capture получил запись после seal, например cached logging handler в atexit | Late payload отбрасывается, внешний FD2 получает constant marker. Pass запрещён даже после успешного HTTP shutdown. |
| serving_output_canary | Synthetic private input обнаружен в capture/report | Сохранить только статус и scoped test reproduction. Не публиковать canary, credential, raw capture или контаминированный report. |
| serving_output_capture_incomplete | Overflow или input observer не был вызван | Не считать пустой capture доказательством privacy. Проверить реальный запуск 12 input cases и bounded callback. |
| source_changed / source_dirty | Evidence не принадлежит одному immutable checkout/image | Не подменять expected digest и не делать reset пользовательских файлов. Требуется новый clean checkout/job. |
| Timeout/cancellation/cleanup failure | Внешний process-group stop не доказывает остановку nested Docker/attach и удаления authority key directory | Native cleanup остаётся unconfirmed, итог inconclusive/nonzero. Завершить disposable job, не продолжать ML/release/upload private state; повтор только в новом hosted VM. |

После forced stop recovery owner - disposable job/VM lifecycle, не успешный worker_transport.cleanup. Родитель не выполняет global prune и не удаляет ресурсы по непроверенным prefix. Shared/local использование требует отдельного ownership inventory, recovery receipts и native fault tests; оно пока запрещено для этого wrapper. Успешный native путь по-прежнему сам проверяет removal owned authority/containers до возврата.

## PB-40: последовательность

1. Локально выполнить только pure contracts:

```bash
uv run --locked python -m unittest scripts.serving_output_qualification scripts.serving_output_native_qualification
uv run --locked python -m unittest scripts.serving_privacy_qualification scripts.candidate_serving_native_qualification scripts.worker_transport_privacy_qualification scripts.transport_owner_qualification
uv run --locked python scripts/check_docs.py
```

2. В clean hosted Storage workflow после штатного bootstrap и прежних gates выполняется:

```bash
uv run --locked python -m scripts.serving_output_native --state .runtime --confirm-disposable
```

Это команда CI, не инструкция запускать её на локальной существующей инфраструктуре. Не запускать hidden --child вручную: его observation=inconclusive и он не наблюдает собственные внешние FDs.

3. Parent проверяет privacy guard/runner profile/workspace owner, заменяет старый owned evidence/candidate-serving.json на inconclusive, закрепляет source/image, запускает фиксированный child через bounded transport.
4. Child lazy-imports candidate qualification внутри captures, получает exact input needles callback, завершает HTTP/journal/export/correlation, seals captures и проверяет сериализованный report. Campaign report.json не публикуется из child.
5. Parent ждёт полного child exit, проверяет canonical wire и нулевой FD stderr, schema/source/required component summaries; повторно проверяет checkout/image и только затем пишет final evidence. В report появляется один case full-lifecycle-output-privacy.
6. Проверить конечное состояние и exact SHA/CI evidence. status=pass требует output_privacy.fd_lifecycle_complete=true, canary_count=6, native_stderr_bytes=0 и прежние privacy/correlation/export statuses=pass. release_ready остаётся false. Пустой stderr без этих условий не является успешным результатом.

## Проверка и rollback

PB-40 verified на [native 2a70ffc](../evidence/serving-output-2a70ffc-native.md): 82 cases, output observation pass после child exit, stderr=0, 6 canaries; Linux 19 output / 38 privacy methods без skips, probes 100%. Первый failed import run и оба RED privacy bypass сохранены в [истории](../evidence/serving-output-2026-10-19.md). Это не проверка forced-stop восстановления Docker resources и не полная M13-приёмка.

Negative tests должны обнаруживать os.write, cached logger до redirect, handler внутри redirect с поздним atexit, inherited subprocess, незаметный JSON whitespace, overflow и отсутствие observer. Legacy capture mode остаётся совместимым; strict mode включён явно только у нового observer.

Rollback означает отключить новый CI wrapper обычным reviewed изменением и вернуть прежний component command, явно сняв full-lifecycle observation claim. Не изменять сохранённые reports, не переименовывать inconclusive в pass. Старый report на диске после ошибки guard/ownership не относится к новому запуску и не должен быть переиспользован acceptance runner.

## Встреченные проблемы

1. Python redirects не видят direct FD/subprocess output: добавлен внешний bounded observer.
2. Cached handler мог писать в уже проверенный Capture на atexit: RED воспроизведение, затем atomic seal и constant FD2 failure marker.
3. Existing qualify сохранял pass до privacy scan: child использует publish_report=False, final evidence принадлежит parent.
4. JSON decode скрывал лишний whitespace: strict mode сравнивает raw bytes с canonical JSON плюс один newline до освобождения capture.
5. SIGKILL не охватывает Docker daemon resources и новый attach session: это не выдано за исправленный native recovery. Wrapper ограничен disposable hosted CI, forced stop остаётся inconclusive и требует job disposal. Local/shared support остаётся отдельной обязательной задачей перед переносом туда.
6. Вложенные HTTP captures раньше оставались открытыми после проверки. Cached handler писал credential после exercise или в atexit, а outer observer ошибочно принимал report: оба RED-сценария дали Rejected not raised. Все три вложенных capture теперь используют общий LifecycleCapture и ExitStack seal перед scan, включая exception/cancellation. Проверка использует реальный exercise в owned Python child; clean control проходит, оба late-write режима дают ровно constant marker на FD2 и отказ parent, без публикации credential.
7. Report проверялся как сериализованный snapshot, но producer возвращал исходный mutable dict. Изменение объекта между scan и публикацией обходило проверку: deterministic RED подтвердил расхождение. Теперь result восстанавливается только из проверенных bytes, а не копируется из изменяемого объекта после scan. Регрессия проверяет сохранение exact snapshot и отсутствие private needle в принятом report.
8. Первый Linux CI остановился на synthetic HTTP fixture: top-level import engine_fixture ненужно загружал ONNX Runtime и его native PCI warning. Не добавлять warning allowlist в observer и не подавлять FD2. engine_fixture перенесён в два использующих его теста; отдельный owned-child test запрещает импорт onnxruntime при загрузке simulated HTTP fixture. Исторический failed CI и проверка исправления сохраняются в evidence.

