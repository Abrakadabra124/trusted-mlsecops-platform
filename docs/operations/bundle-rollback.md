# Откат целого bundle с новым approval

Статус: реализация и local contracts проверены, native CI ожидается. [Протокол и ограничения](../decisions/0052-explicit-bundle-rollback.md). Полные M11/M16/R1 не приняты.

## Предпосылки и ответственность

Оператор выбирает прежний совместимый target по immutable selection hash и проверяет текущий head. Независимый approver подписывает новый schema-2 approval. Promoter публикует и записывает решение; serving отдельно проверяет всё перед ready. Trainer не получает ключ approver. Ни root key, ни database admin не требуются прикладному promoter.

Target должен иметь действительные bundle/assurance/reports, соответствовать текущим policy/root/runtime pins и не быть отозван. Для другого candidate нужен заранее проверенный config с его context. Нельзя автоматически копировать context или root из полученного request. При несовместимости/expiry/отзыве использовать manual-review fallback без ML и подготовить обычный новый release через полную оценку.

## Диагностика

Начать с текущих immutable receipt и operator config. Не выводить client certificates, private keys, токены, содержимое dataset или private report. Сравнить environment, policy SHA, current sequence/request и target sequence/request. Target должен быть более ранним событием, его subject/proposal должны совпасть с выбранным bundle.

| Симптом | Причина и действие |
| --- | --- |
| `rollback_from_history` | Подписанный from не совпадает с журналом. Перечитать head и запросить новое approval, не менять подписанные bytes. |
| `rollback_target_history` | Target не найден в нужном environment либо не является более ранним событием. Проверить selection hash, не подставлять model hash вместо selection. |
| `rollback_head_changed` | Current head изменился или повтор не совпадает с записанным новым request/previous link. Сначала readback, затем отдельное решение approver. |
| `promotion_sequence_conflict` | Конкурирующая запись успела изменить sequence. Не снижать minimum sequence и не сбрасывать ledger. |
| `promotion_rejected` | Прочие проверки не пройдены. Проверить подписи, сроки, gate/assurance, context/runtime и текущий trust через разрешённую private диагностику. Generic код не доказывает конкретную причину. |

## Плейбук

1. Зафиксировать текущий head и точный target из существующего журнала. Проверить, что новый selection будет `from_sequence + 1`; старый bundle не переписывать и не пересобирать.
2. Проверить target: signature/digests, reports/assurance, совместимость полного bundle и действующую policy. Новый approval обязан истекать не позже assurance и bundle. Изменение только model filename недостаточно.
3. Approver создаёт полный signed `release-approval` schema 2: прежние issuer/subject/environment/policy/assurance bindings, новые issued_at/expires_at, action rollback, новый sequence и rollback.from_sequence/from_request_sha256/target_request_sha256. Подпись формируется существующим `mlsecops.signing.sign(payload, 'release-approval', owned_key_path)` в среде approver; ключ не передаётся в promoter Job. JSON-фрагмент ADR не является полным документом или одобрением.
4. Опубликовать signed envelope как immutable CAS object. Обычный request schema 1 ссылается на прежние proposal/policy/assurance и новый approval_reference. Все readback SHA должны совпасть. Не создавать all-pass reports ради отката.
5. В существующем разрешённом стенде отправить request через обычный isolated entrypoint, используя собственные подготовленные файлы:

```sh
python -m mlsecops.kube_promotion submit --state .runtime --config .runtime/operator/rollback-config.json --request .runtime/operator/rollback-request.json
```

6. Ответ `recorded-not-activated` не означает ready. Сверить immutable receipt, новый sequence, прежние subject/proposal и previous link. При потерянном ответе повторять только те же bytes и только если этот request остаётся current. Не генерировать новый timestamp на автоматическом retry.
7. Явно активировать обычный serving config, закреплённый на target context и новый minimum sequence. Проверить ready, model/bundle digest, golden predictions и worker isolation. Не смешивать новую модель со старой предобработкой/config. Сохранить time trace. Текущий increment не автоматизирует staged traffic и не доказывает порог M16.
8. При повторном отказе/отзыве остановить ML-путь и передать оператору/approver. Старый отозванный target не является допустимым резервом. После controlled проверки подтвердить отсутствие owned Jobs, остановку SQL и удаление disposable cluster.

Локальные Docker/WSL/Kubernetes/SQL запрещены в текущей рабочей среде. Шаги с инфраструктурой выполняются только в разрешённом hosted CI. Pure/controlled тесты можно воспроизвести локально:

```powershell
uv run --locked python -m unittest scripts.rollback_authorization_qualification scripts.rollback_admission_qualification scripts.kube_rollback_qualification scripts.kube_approval_fixture_qualification scripts.promotion_controller_qualification scripts.kube_promotion_qualification
```

Native маршрут зарегистрирован в [configured-serving workflow](../../.github/workflows/kubernetes-serving.yml). После его завершения результат должен подтверждаться source/report hashes и cleanup, а не только зелёной отметкой. Не выполнять DELETE/UPDATE head, не понижать sequence, не очищать revocation lists и не заменять trust root для обхода отказа. При неизвестном state или несовпадении подписи эскалировать владельцу безопасности.
