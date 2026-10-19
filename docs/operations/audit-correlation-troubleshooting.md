# RB-65 / PB-39: приватная корреляция source-to-request

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0046](../decisions/0046-private-audit-correlation.md), [evidence](../evidence/audit-correlation-2026-10-19.md).

Проверено в disposable Linux CI на [54cbe50](../evidence/audit-correlation-54cbe50-native.md): 64 contracts без skips, 100% focused coverage, actual 81 cases и controlled release 40 cases. Оба post-close correlation callbacks прошли. Полный M13 и production rollback не считаются принятыми.

## Что делает проверка

Внутренний context v2 связывает входные bytes и разрешение на источник, dataset envelope, training metadata, evaluation envelope, модель и release authorization либо qualification permit с конкретным запросом. Эти ссылки остаются в приватном журнале. Public export сохраняет прежние фиксированные счётчики. Run здесь - content-addressed metadata выполнения, не имя pipeline и не выдуманный MLflow ID.

Probe независимо получает ожидаемые значения из primary signed/package materials, не из production helper или самого audit event. Он работает только внутри уже проверенного reader campaign. Это не standalone authorization verifier, не способ повторно одобрить истёкший release и не доказательство защиты от администратора хоста или скомпрометированных доверенных signing keys.

## Prerequisites и ответственные

Владелец serving instance подтверждает ownership и успешный stop/Journal.close. Security reviewer разбирает mismatch подписанных материалов и журналов. Для native qualification нужен disposable Linux CI с существующим bootstrap. Локальные Docker, WSL, SQL и соседняя enterprise-платформа этим playbook не затрагиваются. Работающие production-процессы и активные spool не использовать для проб.

Expected context нельзя брать из HTTP input, редактируемого audit event или самостоятельно составлять из похожих hex-строк. Production Reader сначала проверяет весь package, roles, signatures, reports, approval, trust и current head. CandidateReader проверяет отдельный qualification permit; его наличие не превращает failed gates в разрешение release.

## RB-65: диагностика

| Симптом | Значение | Безопасное действие |
| --- | --- | --- |
| audit_correlation_context_required | Legacy context v1 | Старое окно допускает structural export, но не полный correlation pass. Сохранить его как историческое evidence; создать новое v2 окно обычным reviewed rollout. Не дописывать lineage задним числом. |
| audit_event_invalid / context_mismatch | Неизвестная схема, mixed contexts, неверная ссылка или authority | Сверить точную таблицу payload/envelope в ADR. Не заменять hash ради зелёного результата. Сохранить private источники, проверить тот же commit/campaign и ownership. |
| material_digest / source_binding | Изменились bytes либо связь signed lineage с quarantine_object | Остановить публикацию pass. Повторно проверить подписанные первичные материалы штатным verifier; неизвестную причину эскалировать. |
| authority_binding | Не тот selection/proposal, subject или authorization | Сравнивать release и qualification отдельно. Никогда не подписывать фиктивный approval для actual candidate. |
| window_unresolved | Retention suffix или незавершённый request | Не превращать inconclusive в pass. Требуется новое полное согласованное окно; недостающие события не синтезировать. |
| window_start | Исчезли целые начальные запросы fresh campaign | Даже полностью завершённые оставшиеся requests не доказывают целый прогон. Нужен first sequence=1; public structural export может отдельно читать suffix, но correlation pass запрещён. |
| no_completed_context | Нет ни одного подтверждённого HTTP 200 с v2 chain | Probe не доказывает рабочий успешный путь. Проверить отдельные serving failures, не ослаблять условие. |
| source_changed / ошибка lease | Источник изменился, занят или не закрыт | Следовать [RB-64](audit-export-troubleshooting.md). Не удалять чужую lease, не переписывать manifest и не выполнять global prune. |

HTTP response_completed означает завершение ASGI send, не получение ответа клиентом. Context на intent означает выбранную модель, но не успешное предсказание. failed_after_intent включает aborted и переход intent 200 -> HTTP 503; without_context обозначает запросы до выбора модели. completed_200 включает predict и readiness, поэтому не является счётчиком inference.

Source approval разрешает source/purpose/owner до expiry, но не закрепляет bytes. source_sha256 берётся из signed curator lineage. Serving не читает отдельный intake source-snapshot envelope. Это ограничение сохраняется явно.

## PB-39: воспроизводимая проверка

1. Установить точный checkout и отсутствие незаявленных изменений: git status, commit и locked dependencies. Не выполнять destructive reset. Пользовательские AGENTS/GOAL не включать в commit реализации.
2. Запустить pure contracts без инфраструктуры:

```bash
uv run --locked python -m unittest scripts.audit_correlation_qualification scripts.audit_correlation_probe_qualification scripts.serving_context_qualification scripts.audit_event_qualification scripts.release_reader_qualification scripts.candidate_serving_reader_qualification
uv run --locked python -m unittest scripts.audit_export_probe_qualification scripts.candidate_serving_native_qualification scripts.release_reader_native_qualification
uv run --locked python scripts/check_docs.py
```

3. Native доказательство получать в workflow Storage role and TLS qualification из clean checkout. Его текущая последовательность выполняет bootstrap, primary material verification, отдельный controlled signed release, затем actual candidate. Post-close callbacks проверяют v2 events и неизменность source snapshots. Не запускать native-команды вручную на существующей локальной инфраструктуре.
4. Проверить в evidence конкретного SHA: source_dirty=false, конечный статус workflow, оба http_correlation summary, exact schema/counts, отсутствие private refs в public export и release_ready=false. Успешные unit tests не заменяют этот шаг.
5. Записать все terminal workflows, включая image/ML failures и failed attempts. M07 connection rejection при повторе не считать исправленным без причины и regression test.
6. Публиковать только фиксированный summary после privacy review. Полный spool, private identifiers, keys и raw logs не копировать в Git. Модель и отчёты разных campaigns не смешивать.

Повторная проверка неизменного закрытого окна даёт те же счётчики; read_closed создаёт временную owned lease, но не меняет payload/manifest и не запускает retention. Не существует новой команды автоматического repair.

## Rollback и конечное состояние

Новый parser читает v1 и v2, но старый бинарь может отвергать v2. Rollback выполнять штатным stop/close и новым отдельным spool, сохранив исходный приватный v2 журнал; читать его совместимым reviewed exporter. Не понижать schema_version вручную и не удалять lineage ради старого reader. Recovery production rollout пока не квалифицирован.

Конечное состояние: verified context соответствует одному загруженному поколению; негативные подмены запрещены; закрытый источник не изменён; публичный summary не содержит новых ссылок; failed/inconclusive gates сохранены. Это компонент T16, не полная M13/R1 приёмка.

## Проблемы реализации и их проверка

- Design review обнаружил путаницу source approval и конкретных bytes. Добавлено отдельное source_sha256; контрольный test сверяет его с первичной signed lineage.
- Payload digest и signed envelope digest имеют одинаковый формат SHA-256, но разные значения. Negative tests подставляют реальные dataset_id, lineage_id, approval envelope и evaluation payload вместо требуемых объектов: probe отказывает.
- В первом unit-прогоне тестовый source_revision уже состоял из символов f, поэтому подмена тем же значением не могла вызвать отказ. Исправлена генерация гарантированно отличающегося валидного hash; пороги не менялись.
- При разработке probe ошибочно искал evaluation в reports, а CAS хранит его в evaluations. Исправлен namespace; сравнение с реальными подписанными fixture materials теперь проходит.
- Двойной class fixture setup перезаписывал общий temporary owner. Используется один общий setup/teardown; ResourceWarning устранён в повторном прогоне.
- Same-model review выявил, что asdict перед type-check позволяет пользовательскому __deepcopy__ скрыть mutable reference. RED test подтвердил обход; проверяются прямые поля через fields/getattr до копирования.
- Review выявил false pass после retention целых начальных запросов. RED test удалил legacy request 1-4, оставив v2 5-8. Probe теперь требует first sequence=1 для отдельного fresh campaign; structural exporter не менялся.

