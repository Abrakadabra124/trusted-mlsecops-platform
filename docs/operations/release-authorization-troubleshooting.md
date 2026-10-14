# PB-20 / RB-38 / RB-39: release proposal и отказ авторизации

Владелец диагностики: platform-owner; содержательную оценку evidence выполняет assessor, решение об approval - отдельный approver. Scope: synthetic local CPU. Эти роли криптографически разделены, но в лаборатории не означают разных людей.

## PB-20: воспроизвести компонент

**Read-only сначала.** Из корня checkout проверить `git status --short`, `git rev-parse HEAD`, `uv run --locked python scripts/check_docs.py`. Не публиковать вывод с приватными путями/материалами. Убедиться, что используемый worker image построен из этого source. Не заменять image, SQL volume или trust store действующей лаборатории.

Controlled tests, без Docker/SQL:

```powershell
uv run --locked python -m unittest scripts.release_policy_qualification scripts.release_bundle_qualification scripts.release_authorization_qualification scripts.release_native_qualification
```

Ожидается 29 methods pass. Это cryptographic/transport/orchestrator fixtures, **не 29 реальных gates**. Они не обучают модель и не подтверждают успешную production promotion.

Реальная SQL-проверка выполняется в workflow [storage.yml](../../.github/workflows/storage.yml), после bootstrap, M03, lineage и capsule. Для уже подготовленного **отдельного disposable state** команда:

```powershell
uv run --locked python -m scripts.release_native --state .runtime
```

**Изменяющее действие:** INSERT только immutable releases objects и новые приватные campaign key/report files. Предварительно runner проверяет ownership. Команда не bootstrap, не reset и не migration; на рабочем state её не запускать только ради демонстрации. В CI `.runtime` принадлежит свежему runner. Требуются current-source signed candidate/evaluation, TLS clients и разрешённый CPU image.

Expected: status=pass, cases=11, objects=20, documents=9, full_M10=inconclusive, release_ready=false. Внутри: два реальных отказа авторизации, одинаковые model bytes через serving, идемпотентный повтор одного package, прямой SQL INSERT ролью serving получает 42501, metadata и holdout budget неизменны. Проверять завершённый exit и актуальный source, не только наличие старого pass-файла.

**Проверено в clean-checkout CI на cd4c6fd:** все эти 11 checks прошли на настоящем PostgreSQL; [bindings и завершённый run](../evidence/release-authorization-2026-10-14.md). Power-loss recovery остаётся controlled-only. Полный M10 не принят даже при success этого компонента.

Приватное evidence: `.runtime/evidence/release-native.json`, `.runtime/release-proposals/<campaign>/report.json`. Не печатать PEM и не добавлять `.runtime` в Git. Новый CLI запуск создаёт **новую campaign/window/ID**, он не является retry прежнего proposal. Идемпотентность проверяется для одного package внутри запуска и отдельным controlled outage test.

## RB-38: корректно подписанный release не получает разрешение

1. Уточнить фазу: `release_assurance_required` означает отсутствие общей evidence, `release_gate_set_incomplete` - неполные M01-M23. В текущем продукте это ожидаемые отказы. Не снимать запрет, не переписывать fail в pass и не использовать unit fixtures как реальные отчёты.
2. При signature/context/digest ошибке сверить внешние trust fingerprints, policy/environment, source/model/serving digest. Ожидаемые значения брать из доверенной конфигурации, не из отвергнутого bundle. Строки keyid/alias не являются authority.
3. При time_binding/expiry сверить часы и issued/expires всех документов. Не отодвигать часы и не редактировать подписанные timestamps. Истёкший proposal требует новой оценки актуальности и нового решения, а не повторного использования старого approval.
4. При case/schema ошибке сверить `id/status/expected/actual`, уникальность ID и точное совпадение outcome. Идентификаторы `controlled:...` и `native:...` допустимы. Исправлять generator/verifier по согласованному контракту, не выкидывать неуспешные cases.
5. Успешный verifier всё ещё возвращает `authorized-not-activated`: пока нет durable transition/lease/loader, это **не команда запускать модель**. Сохранить отказ и эскалировать assessor при недостающих первичных материалах, approver при конфликте ролей, platform-owner при source/time/transport проблеме.

### Реально найдено во время разработки

- Reviewer обнаружил, что новый verifier принимал только id/status и не разрешал двоеточие в case ID, хотя существующий M07 использует четыре поля и префиксы. Regression сначала дал `unexpected_fields`; исправлены schema и отдельная проверка case ID. Добавлены mismatched expected/actual, bool-vs-int и duplicate negatives.
- Контроль времени проверял начало release, но не начало policy. Подписанная controlled цепочка с assurance на секунду раньше policy давала `Rejected not raised`. Теперь issued >= max(release.issued_at, policy.issued_at); regression проходит. Это дефект нового компонента, не обнаруженный production-инцидент.
- Test на глубину JSON ожидал RecursionError на фиксированной глубине, но Windows encoder отверг input по schema раньше. Убрано непереносимое предположение: реальный deeply nested input обязан быть Rejected, отдельная fault injection проверяет нормализацию RecursionError. Глобальный recursion limit не меняли.
- Повторный review нашёл три material digests без отдельных CAS objects: split manifest, evaluation policy и asset projection пересчитывались, но не сохранялись. Controlled проверка полноты CAS сначала упала; теперь сохраняются точные canonical bytes, все непосредственные material references разрешаются. Это не означает архивирование raw данных, упомянутых внутри lineage.
- Client-side role guard не доказывал SQL denial. Controlled transport с ошибочно разрешённым serving INSERT сначала не вызывал провал runner. Добавлен отдельный прямой SQL probe; при расширенных правах qualification теперь завершается ошибкой.

## RB-39: publication прервалась или readback отличается

**Симптом:** nonzero exit, storage receipt/readback/integrity error; часть blobs могла записаться. Конкретную причину соединения/диска устанавливать по приватным runtime logs, не по одной ошибке verifier.

1. Запретить promotion и сохранить исходный package/reference, timestamp и failure evidence в приватном owned state. Если запись report не удалась, старый pass может остаться; текущий nonzero exit важнее файла. При отказе начальной ownership validation runner намеренно ничего не пишет в потенциально чужой state: прежний report только исторический. Отдельный regression проверяет nonzero exit и отсутствие записи. Потребитель, читающий один файл без результата текущего процесса/ownership, некорректен.
2. Read-only проверить ownership и доступность точного service, TLS verify-full, права promoter/serving. Использовать [существующий storage recovery](../storage-recovery.md), не менять grants, не копировать admin credentials. Нет доступа к service - diagnosis inconclusive, не approval.
3. Сравнить CAS references и проверенные байты. При неизвестном ownership, неверном hash/подписи, неожиданном разрешении SQL или изменении ledger остановиться и эскалировать. Не чинить объект под старым digest.
4. После устранения причины повторить `release_bundle.publish` **с тем же сохранённым package и внешним context**, только пока окна и исходное доверие действительны. Успех требует полного serving readback и прежнего reference. Не выдавать новый CLI campaign за идемпотентный повтор.
5. Не удалять orphaned blobs автоматически: lifecycle/retention ещё отдельная задача. Никаких global prune, DROP/reset или удаления единственной копии evidence. При истёкшем окне прежний proposal остаётся неподтверждённым; новый оформляется отдельно.

```powershell
uv run --locked python -m unittest scripts.release_bundle_qualification.ReleaseBundleContracts.test_interrupted_publication_has_no_release_index_and_retry_is_safe scripts.release_bundle_qualification.ReleaseBundleContracts.test_storage_missing_or_replaced_model_card_is_rejected
```

Проверено controlled: обрыв на 12-й записи не публикует внешний index, повтор дописывает комплект; отсутствующий/подменённый model card и неверные receipt/readback отвергаются. Это in-memory fault injection, **не SQL power-loss test**. Native проверка отдельно подтверждает обычный SQL repeat/readback. Полный disaster recovery и активный release rollback этим не заявляются.

Rollback кода - отдельный reviewed revert после сохранения evidence; активная модель этим increment не менялась, SQL schema/grants не мигрировали. Старый verifier не обязан понимать новый descriptor: непонятный формат должен остаться недоступным, а не быть silently approved.
