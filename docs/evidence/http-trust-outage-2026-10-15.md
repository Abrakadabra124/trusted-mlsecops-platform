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

Native clean-checkout CI новой ревизии ещё требуется. Прежние 39 cases на `0a47b7b` не выдаются за новую HTTP outage проверку. Измерения и CI links добавляются только после terminal results.

## Воспроизведение

[PB-26/RB-52](../operations/candidate-serving-troubleshooting.md), [storage workflow](../../.github/workflows/storage.yml). Приватный campaign trace: `.runtime/serving-qualifications/<campaign>/http-outage.json`; общий report: `.runtime/evidence/candidate-serving.json`. При failure общий inconclusive не должен скрывать отдельный измеренный fail trace. Санитизированный trace печатается до выхода; сырой CI log не публикуется в репозитории.
