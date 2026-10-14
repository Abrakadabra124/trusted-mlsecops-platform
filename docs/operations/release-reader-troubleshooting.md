# PB-24 / RB-46 / RB-47: Проверенный текущий release

Область: `mlsecops.release_reader`, переход от SQL selection к immutable model handoff. Это не инструкция для уже работающего HTTP endpoint: такого endpoint этот increment не добавляет. Ответственный: platform owner совместно с release approver; при подозрении на подмену подключить security owner.

## PB-24: Воспроизвести component qualification

Prerequisites: Python 3.12, locked environment, checkout проекта. Первые команды не меняют SQL state; создают только локальный coverage output. Запускать из корня repository:

```powershell
git status --short
git rev-parse HEAD
uv run --locked coverage run --data-file=.coverage-release-reader --source=mlsecops.release_reader -m unittest scripts.release_reader_qualification
uv run --locked coverage report --data-file=.coverage-release-reader --fail-under=100
uv run --locked python -m unittest scripts.release_reader_native_qualification
```

Проверять exit code каждой команды, а не только последней. Coverage 100% относится к ветвям Python reader в controlled tests; не доказывает SQL engine correctness, HTTP contract или изоляцию ONNX execution. Positive fixture содержит тестовые отчёты, не результаты настоящих acceptance gates.

### Native этап с изменениями

Только отдельный disposable CI/согласованный test workspace. Нужны существующий owned source state после storage bootstrap, собранный текущий storage image и свободные loopback ports 15444/15445. Не запускать на единственной рабочей копии БД и не перезапускать Docker/WSL ради диагностики. Read-only prerequisites:

```powershell
docker info --format '{{.ServerVersion}}'
git status --porcelain
```

Изменяющая команда после проверки owned test state:

```powershell
uv run --locked python -m scripts.release_reader_native --state .runtime --confirm-disposable
```

Runner требует clean checkout, создаёт `.runtime/evidence/reader-<campaign>-models` и `reader-<campaign>-trust`, отдельные container/network/volume/CA и случайные test roots. Проводит настоящий promotion/reader путь только для generated contract fixture. Проверяет отсутствие writes со стороны reader, revoke, sequence floor, serving identity и SQL selection без assurance. В конце удаляет только созданные owned ресурсы и сверяет source CAS ledger/checkout. Не запускает inference, не меняет принятую модель, не создаёт all-pass evidence для реального candidate.

Ожидаемый итог: sanitized report `.runtime/evidence/release-reader-qualification.json`, scope `release-reader-real-TLS-SQL-controlled-signed-fixture-not-M12`, status pass, `release_ready=false`, `full_M12=inconclusive`. Нет модели, ключей, raw feature payload или driver diagnostics в публичном выводе. При fail сохранить report и проверить CI step с фиксированными case labels. Не публиковать raw logs/state. Подтверждение завершения - terminal CI и итоговый report, не сам факт успешной загрузки workflow.

Если bootstrap оборвался до подтверждения ownership или ownership изменился, автоматическое удаление не продолжается. Не делать global prune и не удалять вычисленный путь вслепую. Сверить absolute child path, workspace marker, container ID и принадлежность volume/network; очистку частично созданных ресурсов согласовать отдельно. Нативная recovery такой частичной инициализации этим тестом не квалифицирована.

## RB-46: Selection есть, но reader не отдаёт модель

**Симптом:** `serving_head_missing`, `release_invalid_integer`, `serving_authorization_binding`, `release_assurance_required`, gate/signature/integrity rejection. Влияние: current handoff не появляется; ML response нельзя разрешать. Empty head имеет sequence=0 и закономерно отклоняется как отсутствие выбранного release.

1. Read-only: зафиксировать commit, role/environment и точный безопасный error code. Не копировать credentials/полный SQL exception в incident record.
2. Проверить, что выбрана роль serving, а не promoter/publisher. SQL grants не заменяют cryptographic authorization.
3. Сверить внешние root/policy/image/sequence pins с утверждённой конфигурацией. Не брать «правильный» ключ из отвергнутого bundle и не понижать floor.
4. Разделить случаи: отсутствующий proposal/CAS material; неверный digest/canonical document; отсутствующая independent assurance/approval; реальный failed gate; revoked key/ancestor; неверные часы. Для trust использовать [RB-44/RB-45](trust-troubleshooting.md).
5. При missing assurance/failed gate возвращаться к независимой оценке и release approval. Ручной SQL selection не исправляет причину. Тестовые all-pass fixtures запрещено переносить в настоящий release.
6. При corruption остановить продвижение данного candidate, сохранить безопасные metadata и поднять incident. Восстановление только из проверенной копии по [promotion recovery](promotion-recovery-troubleshooting.md), затем проверить актуальный trust отдельно. Не перезаписывать объект под старым digest.

**Критерий восстановления:** один и тот же разрешённый release повторно проходит signatures/material/authorization/online-trust checks, возвращает ожидаемые bytes/digest и current check. Для user-facing readiness дополнительно нужен sandbox runtime handshake и endpoint tests, которых этот компонент не выполняет. Если фактический gate продолжает fail, безопасное состояние - отказ, а не принудительная готовность.

**Rollback/эскалация:** не откатывать SQL head вручную и не стирать revocation. Ошибка policy/root/sequence требует release/security owner. Нельзя объявить устранённой проблему, просто перезапустив процесс и потеряв in-memory high-water mark.

## RB-47: Гонка head, истёкший handoff или временный outage

**Симптом:** `serving_head_changed`, `serving_sequence_replay`, `serving_release_expired`, `serving_release_not_current`, `serving_clock_skew`, `serving_head_unavailable`. Это может быть ожидаемый concurrent promotion, истечение approval или сбой инфраструктуры; не обязательно атака.

1. Read-only: сравнить environment/sequence/reference до и после операции, состояние времени и доступность owned SQL endpoint. Не сохранять raw features или полное содержимое модельных материалов.
2. При legitimate new head выполнить полный новый `Reader.load()` в контролируемом integration path. Не подменять field reference у старого handoff. Ошибка загрузки очищает current; прежний объект больше не разрешён.
3. После успешного reload прежний объект также нельзя использовать: equality bytes не означает identity текущего handoff. Будущий runtime manager должен атомарно связать worker session с новым handoff, а затем проверять его до/после inference.
4. При trust transport outage только уже подтверждённый handoff может использовать остаток исходного lease. Новый load требует online read. Повторный timeout не даёт новые 60 s. Неверный документ, revoke или expiry запрещают доступ сразу.
5. Model DB outage отличается от trust outage: свежая head check не проходит, reader отказывает без cached-head fallback. После восстановления требуется полный load, актуальные pins и проверка конечного состояния.
6. Clock rollback/skew не исправлять увеличением TTL. Проверить синхронизацию часов; восстановление времени и новый доверенный read выполнять после диагностики. Exact operational clock repair зависит от host, команды изменения времени здесь намеренно отсутствуют.

**Проверка исправления:** positive controlled checks плюс повтор точного negative сценария. `test_expiry_during_final_trust_refresh_is_not_missed` отдельно проверяет, что срок approval нельзя проскочить за время последнего trust request. Межсервисная атомарность не заявляется; HTTP before/after-inference negative tests остаются обязательными.

## Что встретилось при реализации

- Controlled tests обнаружили несовместимость frozen handoff scope (`frozenset`) с существующим lease validator. Исправлено преобразование в поддерживаемые immutable tuples на границе `check`, без ослабления валидации lease.
- Проверка expiry перенесена после завершающего trust refresh, чтобы время этого запроса не скрывало истечение model approval. Добавлен delayed-refresh regression.
- Первый delayed-refresh test задерживал ответ на весь 1800 s approval window и получал более ранний корректный `trust_lease_expired`, а не ожидаемую ошибку release. Fixture исправлена: approval подписан на 30 s, задержка остаётся внутри 60 s lease. Это исправление точности теста, не ослабление защиты и не реальный production incident.
- На Windows temporary directory использовал короткое имя `ABRAKA~1`, а безопасный resolver возвращал полный путь. Test comparison исправлено через `.resolve()` с обеих сторон. Ownership/path validation не отключалась; проверяется путь, а не текстовое совпадение двух alias одного каталога.
- [Evidence](../evidence/release-reader-2026-10-14.md) отделяет local tests, native CI и оставшийся runtime/API этап.
