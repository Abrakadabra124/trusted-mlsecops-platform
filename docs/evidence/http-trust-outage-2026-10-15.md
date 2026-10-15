# HTTP trust outage: qualification component

## Scope и критерий

Продолжение actual-candidate qualification после `cdea4236`. Исходные proposal/model bytes не меняются. Отдельная disposable authority останавливается только после проверки ownership. Измеряется первый полученный клиентом HTTP 503 <=60 s от последней успешной verified policy read; после deadline ML-ответы запрещены. Задержка cleanup/HTTP не вычитается. Нарушение остаётся fail, даже при успешном recovery.

Это component evidence, не полная M11/M12 приёмка и не release approval. Production Reader, root rotation, rollback authorization, privacy/audit и общая M18 acceptance остаются обязательствами. Синтетика не подтверждает business utility.

## Метод

- Diagnostic `ObservedLease` наследует настоящий `trust.Lease`. Записывает успешные verified reads, не продлевает lease и не авторизует inference. Неуспешный refresh не создаёт новый anchor.
- Под Engine lock выполняются fresh check и stop собственного authority container. Сохраняются Unix UTC и monotonic timestamps, исходный deadline, policy hash/version и sequence. HTTP responses сверяются по model/bundle binding и golden scores; raw features, tokens и ответы модели в trace не сохраняются.
- Offline cold start должен вернуть 503. Работающий endpoint опрашивается до двух отказов, включая запрос после deadline; максимум 512 observations. Неупорядоченные/нечисловые timestamps отклоняются, неизвестный status, изменившийся lease, неверный ответ и поздний отказ не дают pass.
- В `finally` сверяется identity и запускается только прежняя authority. API остаётся unavailable до explicit activation, fresh verified read и golden replay с прежними digests. Неподтверждённое ownership запрещает restart.
- Клиентский trace проверяет конкретные запросы, не доказывает отсутствие любого возможного ответа между ними. Before/after trust contracts проверяются отдельно. Controlled clock tests не являются realtime measurements.

## Проверки этой ревизии

Новая outage suite: 11 methods, 92% Python branch-aware coverage. Покрыты expiry/refresh в Lease, malformed/late trace negatives, ownership changes, stop/body failure и simulated delayed cleanup. При artificial cleanup delay 0.3 s отчёт сохраняет fail после успешного recovery. Docker локально не запускался.

Объединённая adjacent suite: 140 methods pass за 13.718 s. Ruff lint/format проходят; documentation check: 354 files, 127 Markdown documents, 930 local links. Последний same-model bounded static review не нашёл новых конкретных defects; это не независимый аудит всей платформы.

Same-model scoped review нашёл два дефекта, воспроизведённых до исправления: recovery ошибочно принимал корректный HTTP 503; полный bootstrap требовал свободного места до попытки restart. Теперь recovery требует 200, а restart использует проверенный full container ID и bounded SQL readiness без повторной миграции. Дополнительный regression запрещает брать cached fallback за fresh-read anchor перед outage. Эти дефекты обнаружены в разработке, не являются production incident.

## Native failure на `2905e70`

[Storage CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38762343820), job `116516614545`: completed/failure, 7m36s. Источник `2905e70f015b5e51a1ac07b9543d276e2ac09255`, clean checkout. [Полный очищенный trace](http-trust-outage-2905e70.md) сохраняет 117 HTTP observations, policy hash/version, timestamps и recovery. Первый 503: **60.082361397 s**, допустимо <=60. Failure не округляется до pass. Последний 200: 59.984064734 s, до исходного deadline; все сохранённые responses имеют корректные digests/golden scores, lease sequence/deadline во время outage не менялись.

Offline cold start, readiness после expiry, удаление собственного worker, отсутствие auto-reactivation и fresh-read/golden recovery прошли. Anchor sequence 22, recovery sequence 27; signed document тот же. Model `09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f`, bundle `f67c9753e853fac6a963b513be4c47750f6f989c92cde1536ddea95174913d19`. После deadline failure runner не дошёл до последующего revoke и final source readback; эти cases для данной ревизии не заявляются.

До нового slice прошли M03 431, M07 97, journal 108, recovery 36, trust component 45, Reader 18 и прежний fixture HTTP 34. Эти успехи не заменяют failed endpoint measurement. Новая причина воспроизведена controlled test: HTTP denial ожидал synchronous worker cleanup. [ADR 0033](../decisions/0033-serving-retirement.md) отделяет немедленную invalidation от retained asynchronous cleanup. Исправленный runtime требует нового CI, старое evidence остаётся failure.

### Terminal CI matrix `2905e70`: 5 success / 5 failure

| Workflow | Result |
|---|---|
| [Storage](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38762343820) | failure: новый HTTP deadline 60.082361397 s |
| [Developer](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38762343768) | success: 3 обучения, probability difference 0, ONNX parity 2.086162567138672e-7 |
| [Tracking](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38762343912) | success: M06 18 |
| [Kubernetes](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38762343782) | success: M20 723, M21 122; M21 finished 2026-10-15T15:55:36.761445 UTC |
| [Intake](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38762343775) | success |
| [Docs](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38762344027) | success |
| [Image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38762343959) | failure: worker 0 Critical/56 High, storage 9 Critical/131 High; candidates 0/55 и 1/85 |
| [Poisoning](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38762343944) | failure: 10 violations, 0 inconclusive |
| [Evasion](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38762343799) | failure: recall drop 0.07183673469387755 >0.05, primary reconciliation pass |
| [Paired research](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38762343849) | failure: candidate drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 >0.05 |

Image audit действительно выполнил четыре scans и подтвердил SBOM, scanner exit 2. CI jobs имеют собственные image IDs; эта таблица не является release-bound M18 aggregate. Порог устойчивости и image findings не исключены из приёмки.

## Runtime correction после failure

Новые failure-first regressions покрывают blocked cleanup, thread-start error и retained handle retry. Scoped reviewers дополнительно воспроизвели ту же задержку внутри `Worker.send` и `Channel.exchange`; теперь runtime errors достигают Engine до process wait/Docker cleanup. Отдельные реальные методы Channel/Worker и Worker/Engine с controlled process/command проверены без Docker; startup cleanup не удалён. Предыдущая adjacent suite 144 methods pass за 13.751 s и serving suite 54/94% относятся к исправлению до последнего transport regression. Итоговые тесты и новый native CI фиксируются отдельно.

Финальная локальная проверка correction: **146 adjacent methods pass за 13.548 s**, **56 serving methods / 94% combined coverage** (565 statements, 168 branches). Ruff lint/format и docs check проходят. Старое native failure не переписывается на основании этих тестов; требуется новый clean-checkout запуск.

## Воспроизведение

[PB-26/RB-52](../operations/candidate-serving-troubleshooting.md), [storage workflow](../../.github/workflows/storage.yml). Приватный campaign trace: `.runtime/serving-qualifications/<campaign>/http-outage.json`; общий report: `.runtime/evidence/candidate-serving.json`. При failure общий inconclusive не должен скрывать отдельный измеренный fail trace. Санитизированный trace печатается до выхода; сырой CI log не публикуется в репозитории.
