# PB-11 / RB-22 / RB-23 / RB-24: материалы candidate и восстановление публикации

Сфера: [unapproved material bundle](../material-bundle.md), owned synthetic lab. Ответственные: platform operator; curator при source approval; evaluator при subject/report; security reviewer при подозрении на подмену. Никакая процедура не разрешает production promotion и не ослабляет M10.

## PB-11: диагностика сначала, изменение отдельно

Prerequisites: pinned uv/Python environment, Docker Linux engine, известный owned SQL state, candidate/evaluation из **того же checkout**, private trust/client files. Не печатать содержимое ключей, SQL configs, raw model или dataset. Если ownership неизвестен, остановиться и уточнить владельца.

Read-only относительно SQL, из корня проекта:

```powershell
git status --short
git rev-parse HEAD
docker ps --format '{{.Names}} {{.Ports}}'
uv run --locked python -m scripts.material_bundle_qualification
uv run --locked python -m scripts.material_bundle_native_qualification
uv run --locked python -m scripts.candidate_lineage_native --state .runtime
```

Первые два suites используют временные fixtures. Lineage helper записывает только локальный diagnostic report; ожидаются 10 cases, exit 0, full_M19 inconclusive. При ошибке сначала [PB-10](candidate-lineage-troubleshooting.md). Не менять source/image pins, чтобы заставить старый candidate соответствовать новому checkout.

**Изменяющий шаг**, только для подтверждённого lab state:

```powershell
uv run --locked python -m scripts.material_bundle_native --state .runtime
```

Команда подписывает materials, вставляет до 9 объектов и envelope в releases, повторяет publication и читает всё ролью serving. Делает запрещённые SELECT и INSERT probes: ожидается 42501, запись probe не должна появиться. Это не read-only диагностика и не service startup. Она не retrain-ит, не резервирует holdout slot, не обновляет grants и не удаляет данные. Expected: exit 0, 12 cases, full_M10 inconclusive, release_ready false, свежий private report в `evidence/material-bundle-native.json`.

Сверить не только exit: reference envelope, model/projection digest, unchanged metadata/budget snapshot, exact releases set и source/image/runner digests. Подпись не доказывает, что код безопасен или модель устойчива. Image audit и poisoning failures остаются blocking.

Для отдельного нового стенда использовать штатные `mlsecops bootstrap`, `mlsecops.storage_bootstrap --state <fresh-owned-path> --port <unused-loopback-port>`, `mlsecops build` и `mlsecops.storage_pipeline --state <fresh-owned-path>`. Training/evaluation здесь действительно создают candidate и расходуют один slot нового research state; это нельзя использовать как reset рабочего holdout budget. Native проверка 2026-10-11 выполнена в отдельном `.runtime/material-bundle-native-20261011`, его container после ownership verification остановлен, volume/evidence сохранены. Не запускать подготовку поверх этой сохранённой папки как fresh.

## RB-22: signature, subject или material-set rejection

| Симптом | Диагностика без раскрытия данных | Действие |
| --- | --- | --- |
| wrong_payload_type / invalid_signature / untrusted_key | External trusted key и назначение envelope, не только keyid | Отказ, передать security reviewer; не брать trusted key из payload |
| bundle_material_integrity_failed / storage_object_missing | Exact reference, stored bytes length/hash приватно | Восстановить только подтверждённую immutable копию; не пересчитать index для неизвестной модели |
| dependency_missing / unreferenced_material / material_set_mismatch | Closed namespace/descriptor set и обязательные ссылки | Исправить assembler; лишний объект или missing evidence нельзя игнорировать |
| bundle_subject_or_context_mismatch / inventory_candidate_build_binding | Environment, policy, candidate/evaluation, source revision/fingerprint и image label | Подходящий checkout либо новый штатный candidate/evaluation, без редактирования старого metadata |
| expired_source_approval / signer_roles_not_separated | Срок и отдельные curator/evaluator/approver roots | Curator/security review; не отключать expiry и не подменять ключи |
| reader_identity_invalid / SQL 42501 вне negative probe | Конфигурация роли и endpoint ownership | Исправить выбор client, не выдавать serving metadata/admin права |
| object_count/size/envelope limits | Размеры и схема без загрузки в ONNX runtime | Отказ; расширение профиля требует отдельного review, не removal limits |

Проверенные controlled cases включают tamper, missing/extra objects, foreign context, неверную подпись вложенного evaluation при корректно переподписанном внешнем envelope, malformed/oversized input и wrong roles. Это adversarial tests, **не зафиксированная атака на production**.

При разработке negative test на deep nesting сначала ожидал RecursionError на глубине 2000, но среда обработала такую JSON-структуру и отвергла её по schema. Ошибка была в предположении теста, не обходе проверки. Fixture увеличен до 12000 и подтвердил controlled Rejected; отдельно проверяется циклический Python input. Порог приёмки не ослаблялся. Этот случай не доказывает защиту от любого resource-exhaustion input.

## RB-23: interrupted publication или недоступный readback

**Симптом:** nonzero exit, bundle storage integrity/readback error либо SQL connection failure; часть releases objects уже существует. Возможная причина: разрыв соединения/диск/ошибка transport. Не утверждать конкретную причину без SQL/runtime evidence. Алгоритм не обещает общей транзакции для всех blobs.

1. Прекратить попытку promotion, сохранить report/exit, timestamp и ожидаемый envelope reference. Если запись evidence невозможна, старый pass-файл может остаться: текущий nonzero exit имеет приоритет.
2. Проверить owned service, TLS и client identity по существующим storage procedures. Не отключать verify-full, не копировать admin credentials и не сбрасывать volume/ledger.
3. Сверить доступные objects по digest, исходные candidate/report/context и актуальность source approval. Не удалять lone copy или orphaned bytes автоматически; отсутствие mutable alias здесь намеренно.
4. После устранения причины повторить **тот же** `material_bundle.publish` с теми же проверенными inputs. Исполняемый PB-11 пересоберёт идентичный envelope только при неизменных inputs/context. Нужен полный успешный readback ролью serving, а не один successful INSERT.
5. Expected: один и тот же envelope reference, точный object set без дублей, metadata и budget unchanged, всё ещё unapproved. Если reference отличается или context изменился, остановиться и разбирать как отдельный candidate, не объявлять повтор идемпотентным.

```powershell
uv run --locked python -m unittest scripts.material_bundle_qualification.MaterialBundleContracts.test_partial_publication_retries_without_alias_or_false_success
uv run --locked python -m unittest scripts.material_bundle_qualification.MaterialBundleContracts.test_wrong_storage_receipt_and_failed_readback_cannot_report_success
```

Fault injection: вторая запись прервана после первой successful write; envelope отсутствует, успех не возвращён. Повтор сохранил ровно 10 objects и прочитанный unapproved результат. Это in-memory transport test. Реальный SQL подтвердил идемпотентный повтор и права, но power-loss/disaster recovery этой capsule **не моделировались**.

Rollback этого шага не требует переключения serving: активный release не менялся. При несовместимом verifier сохранить immutable материалы, прекратить publication, вернуть проверенную совместимую версию кода отдельным reviewed revert. Не удалять private evidence и не ослаблять schema. Эскалация обязательна при неверном signer, неожиданно разрешённом SQL probe, изменении metadata/ledger, неизвестном ownership или неповторимом envelope. Full release rollback/trust revocation ещё требуют T14-T20.

## RB-24: одинаковый ключ ошибочно считается разными identities

**Фактически воспроизведено при финальном review 2026-10-11.** Guards сравнивали строки Base64, а не decoded key bytes. Base64 - представление бинарных данных текстом; разные допустимые записи могут декодироваться в один public key. Controlled fixture меняет незначащие padding bits, сохраняя ключ. До исправления один curator мог также выступить evaluator или signer capsule: два test methods дали три `Rejected not raised` failures.

Precondition: внешняя trusted configuration уже назначила один реальный ключ нескольким ролям под разными строками. Это **не** обход Ed25519, не создание подписи без private key и не возможность случайного сетевого клиента заменить trust roots. Реальных совпадающих production keys или атак не обнаружено; схема вообще не выдавала release approval.

Исправлены guards `candidate_lineage` и `material_bundle`: сравнение decoded public key bytes. Строковое оформление перестало влиять на разделение ролей; подписи и внешний trust anchor по-прежнему проверяются. Не запрещать один вариант encoding вместо устранения ошибки идентичности.

Read-only diagnosis для подтверждённого state, выводит только fingerprints публичных ключей:

```powershell
uv run --locked python -c "from mlsecops.contracts import read_json,digest; from mlsecops.signing import decode64; public=read_json('.runtime/trusted-keys.json'); print({role:digest(decode64(public[role])) for role in ('curator','evaluator','approver')})"
uv run --locked python -m unittest scripts.candidate_lineage_qualification.CandidateLineageContracts.test_equivalent_public_key_encodings_cannot_split_signer_roles scripts.material_bundle_qualification.MaterialBundleContracts.test_equivalent_key_encodings_cannot_turn_curator_into_approver
```

Expected: все три fingerprints различаются, оба regression tests pass; одинаковые bytes дают controlled `signer_roles_not_separated`. При совпадении остановить сборку/promotion, сохранить references и передать owner/security reviewer. Другой текст того же ключа не исправляет проблему. Не перезаписывать `trusted-keys.json` или private keys вручную: нужна explicit key migration/re-authorization и проверка зависимых материалов, а не маскировка старых подписей новой конфигурацией.

После исправления выполнить component suites и fresh native PB-11 на отдельном разрешённом state. Возврат к уязвимому строковому сравнению не допустимый rollback. Production key rotation/revocation пока не реализованы; при подозрении на действующий общий ключ оставлять release заблокированным. Наличие различных ключей не доказывает независимость людей, host admin или KMS.

Проверенный результат исправления: [clean storage CI 38161458192](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38161458192) на `d6c2db2`, 21 lineage + 21 bundle + 9 runner tests pass и 12 native SQL checks pass. Report остаётся `full_M10=inconclusive`, `release_ready=false`. Image audit и poisoning workflows этого commit завершены failure по прежним security/robustness blockers, а не скрыты успешным component suite; детали в [STATUS](../../STATUS.md).
