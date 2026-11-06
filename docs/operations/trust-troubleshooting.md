# PB-23 / RB-44 / RB-45: актуальное доверие, отзыв и outage

Владелец: trust-owner; инфраструктуру authority обслуживает platform-owner. Scope: synthetic local CPU, [ADR 0029](../decisions/0029-online-trust.md). Инструкции не разрешают выпуск при failed/inconclusive ML gates. Отдельная authority не является production KMS или HA-сервисом.

## Отказ model backup для authority

`trust_authority_backup_forbidden` означает, что обычный или extended model backup получил trust workspace либо не смог однозначно подтвердить отсутствие `ml_trust`. Это ожидаемый запрет. Не создавать в authority таблицы `ml_promotion`, не удалять `ml_trust`, не менять ожидаемый результат на любой SQL error и не отключать guard ради зелёного теста. Model backup не является способом восстановления актуального trust policy или отмены отзывов.

Диагностика начинается с source revision, ownership marker и назначения переданного state. Проверка в `storage_backup.create` выполняется после ownership validation и до model migration lookup; только точный ответ `f` разрешает дальнейшие проверки. Transaction-level guard в `storage_snapshot` остаётся действующим. Если предполагалось резервировать model storage, оператор должен заново подтвердить правильный owned workspace, сохранив отказ и исходную authority неизменными. Не запускать destructive recovery по одному generic failure.

Regression: в run `42232406810` после успешных M03/M07 extended backup в trust qualification дошёл до отсутствующей promotion migration раньше явного scope refusal. `b60eb93` исправляет этот порядок. Failure-first тесты подтверждают запрет обоих вариантов до export и сохранение пути model storage; полный hosted повтор указан в [CI evidence](../evidence/ci-regression-2026-11-06.md#успешное-повторение-storage). Проверка без инфраструктуры:

```powershell
uv run --locked python -m unittest scripts.trust_native_qualification
```

В текущей цели native-проверки разрешены только в disposable GitHub-hosted CI. После изменения нужно подтвердить оба `model-backup-excludes-authority` cases, остальные trust/revocation/outage cases и cleanup. Успех одного отказа не закрывает M11, M17 или R1. При несовпадении причины оставить failure, сохранить приватный журнал и последний fixed case label, эскалировать platform-owner; не публиковать raw driver errors или ключи.

## Что это за компоненты

### Отказ coverage после добавления Session

Симптом: storage CI `42298587187` на source `2df0220` завершил 42 contract tests
успешно, но остановился на обязательном `fail-under=100`: в
`trust_authority.py` не проверялся переход `16 -> 27`, когда передана доверенная
фабрика соединений. Это пробел тестового набора authority, а не доказанный отказ
живого TLS-соединения. SQL cleanup того запуска завершился успешно.

Диагностика без запуска инфраструктуры:

```powershell
uv run --locked coverage run --data-file=.runtime/evidence/.coverage-trust --source=mlsecops.trust,mlsecops.trust_authority -m unittest scripts.trust_qualification scripts.trust_authority_qualification scripts.trust_root_store_qualification scripts.kube_trust_qualification
uv run --locked coverage report --data-file=.runtime/evidence/.coverage-trust --fail-under=100
```

Исправление добавляет проверку передачи host pin владельцу соединения, проверки
подписи/root/digest после чтения и отсутствия fallback transport при отказе
фабрики. Проверки свежих TLS credentials остаются обязанностью `Session` при
каждом использовании. Порог покрытия и runtime-код не меняются. Локальный повтор
на Windows: 45 tests, 0 skips, 259 statements и 102 branches полностью покрыты.
Hosted повтор storage необходим отдельно; этот результат не закрывает M18/R1.
Если причина отказа иная, сохранить private coverage report и точную revision,
передать platform-owner; не отключать branch coverage или проверки доверия.

PostgreSQL хранит текущую версию signed trust policy отдельно от model storage. Mutual TLS проверяет сертификаты обеих сторон; клиент требует TLS 1.3 и verify-full, а serving/promoter могут только читать policy. Подпись Ed25519 связывает документ с отдельно закреплённым root key.

Lease - ограниченный срок действия последней online проверки, максимум 60 секунд от начала SQL-запроса. Monotonic clock измеряет длительность без продления при переводе системных часов; wall/server clocks дополнительно ограничивают expiry. Это разрешение проверить конкретный набор материалов, а не автоматическая активация модели.

## PB-23: подготовить отдельную authority

Начать с read-only: проверить revision, рабочие Git changes, наличие Docker Engine, свободный loopback port 15444 и выбранный путь. Не запускать Docker/WSL reset, prune или изменение существующей БД. В текущей Windows-сессии Docker Engine отсутствует по named pipe; это ограничение среды, не причина ослаблять TLS или тесты.

Следующие команды **создают отдельные** workspace, container, volume, network, CA и ключи. Не использовать каталог model storage или существующую рабочую authority для новой установки.

```powershell
uv run --locked python -m mlsecops.bootstrap --state .runtime/trust-authority
uv run --locked python -m mlsecops.storage_bootstrap --state .runtime/trust-authority --port 15444
$trustRoot = (Get-Content .runtime/trust-authority/trusted-keys.json | ConvertFrom-Json).trust
uv run --locked python -m mlsecops.trust_authority install --state .runtime/trust-authority --root-public $trustRoot --confirm-authority
```

Bootstrap root принадлежит оператору этого нового lab state. Consumer получает public root, environment и minimum version по независимому доверенному каналу, не из скачанного model backup. Private signing key не копировать в serving/predictor, Git или CI artifacts. SQL client certificate является credential доступа к authority, а не ключом подписи ML release.

Проверка текущего номера без изменений:

```powershell
uv run --locked python -m mlsecops.trust_authority show --state .runtime/trust-authority
```

До первого update version=null. Show не проверяет допуск конкретной модели, не заменяет TLS consumer read и всегда возвращает release_ready=false. Для записи нужен реальный digest разрешённой promotion policy; placeholder ниже заменить **проверенным** SHA-256, не alias или результатом controlled all-pass fixture.

```powershell
uv run --locked python -m mlsecops.trust_authority update --state .runtime/trust-authority --policy PROMOTION_POLICY_SHA256 --key .runtime/trust-authority/keys/trust.pem --lifetime 3600 --confirm-authority
```

Update подписывает новую версию и сохраняет все предыдущие отзывы. Его повтор создаёт следующую версию намеренно. Publish одного и того же сохранённого signed document идемпотентен, пока он текущий и не expired:

```powershell
uv run --locked python -m mlsecops.trust_authority publish --state .runtime/trust-authority --document SIGNED_POLICY_JSON --confirm-authority
```

Для отзыва добавить к update `--revoke-artifact SHA256` или `--revoke-key PUBLIC_KEY_SHA256`. Key ID - SHA-256 декодированных 32 bytes Ed25519 public key, не private key и не хеш строки base64. Артефакт задаётся по content digest: model, dataset ID/manifest, runtime, policy или другой проверяемый ancestor. Подмена имени не отменяет отзыв. Не отзывать root для обычной ротации: root revocation намеренно останавливает все leases этой authority, а новый root требует отдельной процедуры.

Успех записи доказывается immutable document readback; `show` должен показать ожидаемую version/reference. Consumer должен заново получить policy по TLS и отклонить отозванный subject, сохранив независимые subject branches. Signature-only offline verification не доказывает, что это последняя версия.

## RB-44: недоступность authority, expiry или часы

1. Сохранить sanitized error code, revision, version/digest и timestamp. Не публиковать SQL connection strings, клиентские ключи, raw driver errors или запросы пользователя.
2. При trust_service_unavailable проверить существующий owned container/порт, сертификаты, время и доступность authority. Не создавать новую authority автоматически по тому же адресу. Ошибка сети не означает, что policy разрешает модель.
3. Новый consumer без online read не начинает ML-работу. Старый может использовать прежнюю разрешённую policy только до исходного deadline; не переписывать timestamp и не выдавать новый lease из кеша. Promotion требует успешный fresh read и при outage не выполняется.
4. trust_clock_invalid означает обратный ход wall/monotonic либо расхождение более 2 s с первоначальным clock anchor. Процесс намеренно сохраняет отказ. Проверить синхронизацию времени, затем перезапустить consumer с новой online проверкой, а не отключать guard. Server clock skew >2 s также отклоняется.
5. trust_lease_expired, expired approval или expired policy не лечатся ручным продлением поля. Владелец выпускает новую подписанную policy после проверки актуального состояния; release approval имеет отдельный срок.
6. После восстановления соединения проверить актуальную version, сохранность revocations и отрицательный запрос к отозванному материалу. Перезапуск БД или клиента сам по себе не является доказательством восстановления доверия.

## RB-45: conflicting update, replay или отмена отзыва

1. trust_version_replay, trust_update_conflict_or_unrevocation и trust_configuration_conflict требуют сверить внешний root/environment/minimum-version pin с текущей authority. Не снижать minimum version ради запуска старой модели.
2. Конкурентные updates сериализуются SQL transaction lock. Один конфликтующий документ выигрывает; другой отвергается. Прочитать текущий документ и повторно согласовать новый update с объединением действующих отзывов. Не выполнять DELETE/TRUNCATE и не редактировать version вручную.
3. После потери ответа publish мог уже закоммититься. Проверить immutable reference/current version и использовать тот же signed document для retry; не считать timeout автоматическим rollback.
4. trust_artifact_revoked / trust_key_revoked блокируют соответствующую модель и её проверяемые зависимости. Независимая ветвь допускается только при собственной полной авторизации. Root revocation остаётся блокирующим даже после очистки lease cache.
5. Если отказ случился после promotion commit, journal может содержать запись. SDK не возвращает activation; не активировать её по факту существования row. Нужны current trust, полная release verification и последующая serving acceptance.
6. Model backup v1/v2 намеренно не архивирует trust authority. Попытка backup её workspace отвергается до dump. При потере authority не восстанавливать доверие из старого model snapshot; оставить ML недоступным и эскалировать trust-owner. Полный root-rotation/authority-DR протокол ещё не реализован.

## Проверки и встреченные дефекты

```powershell
uv run --locked python -m unittest scripts.trust_qualification scripts.trust_authority_qualification scripts.trust_native_qualification scripts.promotion_qualification
```

Native runner требует отдельный disposable state и доступный Docker. Он создаёт собственную дочернюю authority, не меняет model storage, останавливает **собственный** container для реального 60-second outage и удаляет только проверенные owned resources. Не запускать на рабочем state только ради диагностики.

На `214cc3c` в clean-checkout CI прошли 45 native checks, source_dirty=false. Первый отказ после последнего успешного read: 59.992019191 s. Все fingerprints и точный scope приведены в evidence; это SDK/SQL client, не готовый HTTP endpoint.

```powershell
uv run --locked python -m scripts.trust_native --state .runtime --confirm-disposable
```

Ревью выявило два дефекта разработки: очистка кеша теряла историю необратимых отзывов; server expiry отсчитывался от конца медленного запроса. Три failing regression cases воспроизвели оба нарушения. Исправлены отдельная история отзывов/root latch и отсчёт server expiry от начала запроса. Это controlled development defects, не production incidents. [Evidence](../evidence/online-trust-2026-10-14.md) отделяет unit, native SQL и ещё не выполненную endpoint приёмку M11/M12.

Отдельное ревью admission обнаружило неполное множество revocable references. Исправление добавляет proposal и authorization envelopes, разрешение источника, train/validation/holdout byte digests, lineage ID и source fingerprint. 10 независимых negative subtests сначала воспроизвели пропуски, затем подтвердили отказ до записи. Отзыв aggregate dataset ID не подменяет проверку отзыва отдельного split.
