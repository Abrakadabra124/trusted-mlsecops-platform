# Два независимых отзыва на одном actual candidate

Статус: реализация и локальные тесты, native verification pending. [Решение ADR 0051](../decisions/0051-independent-trust-qualification.md). Это qualification двух тестовых состояний, полный M11/R1 ещё не принят.

## Причина и границы

После отзыва модели повторный положительный inference с ней запрещён. Поэтому проверять следующий отзыв ключа в том же состоянии нельзя: первый запрет скрыл бы второй. Второй экземпляр authority создаётся заранее, со своим CA, PVC, immutable Secret и UID inventory. Оба получают один qualification permit для того же source/image/model/subject. Срок permit не продлевается. Ни один отзыв не удаляется.

Primary обслуживает прежний endpoint. Дополнительный `model-revocation` target доступен только явно выбранному candidate probe. Он не служит запасным endpoint для обычного serving. После обоих отзывов каждая authority должна отдельно отклонить новый cold Reader. Это не replication, production failover или доказательство M17 restore.

## Диагностика

Ответственный: оператор disposable CI. Prerequisites: авторизация gh, закреплённая ветка проекта, доступ к конкретному Actions run. Локальные Docker/WSL/SQL/Kubernetes не нужны и не запускаются.

Начать с чтения состояния уже запущенного run, используя фактический ID из Actions:

```powershell
gh run view <RUN_ID> --repo Abrakadabra124/trusted-mlsecops-platform --json status,conclusion,headSha,jobs,url
```

При timeout наблюдателя повторно прочитать тот же ID. Не создавать второй run для исправления ошибки наблюдения. В закрытом evidence сохранить итоговый отчёт и raw logs, перед публикацией извлечь только разрешённые технические поля.

| Код или симптом | Проверка и действие |
| --- | --- |
| `candidate_authorities_not_independent` | Сверить CA, host, UID inventory, volume UID и spec digest. Совпадение требует исправления provisioning; не разрешать aliasing. |
| `candidate_authorities_policy_or_root` | Сверить исходный public root и permit policy. Не переиздавать permit ради успешного отчёта. |
| `candidate_authority_isolation_binding` | Сверить CA hash и target отчёта с локальным owned inventory. Проверить, что `cross_ca_denied` является boolean true. |
| TLS negative дал timeout | Cross-CA isolation не доказана. Проверить owned network policy и готовность второго PostgreSQL; timeout не выдавать за отказ сертификата. |
| `candidate_terminal_baseline_revoked` | Модель или ключ были отозваны до terminal experiment. Сохранить отказ; не удалять revocations и не сбрасывать version floor. |
| `candidate_authority_revoke_transition` | Сверить history digest обоих targets и точное добавление одного отзыва. Изменение соседней истории или исчезновение старого отзыва блокирует результат. |
| `candidate_trust_window` | Осталось меньше 180 секунд перед очередным fault. Остановить этот опыт; старый permit не продлевать. При исправлении timing повторить весь workflow с новой campaign и документировать отдельный результат. |
| `candidate_terminal_cold_binding` | Cold report обязан содержать exact `trust_key_revoked` / `trust_artifact_revoked`, правильные model/subject и ноль workers. Expiry, сетевой сбой и generic rejection не заменяют этот результат. |
| `candidate_terminal_readback_changed` | Повторно прочитать полную историю обеих authority и CAS/promotion journal. Установить причину изменения, сохранить evidence; не объявлять pass по одному HTTP 503. |

## Плейбук воспроизведения

1. В чистом checkout проверить локальные pure/mocked contracts:

   ```powershell
   uv run --locked python -m unittest scripts.trust_targets_qualification scripts.kube_trust_isolation_qualification scripts.kube_authority_pair_qualification scripts.kube_trust_qualification scripts.trust_authority_qualification scripts.kube_candidate_faults_qualification scripts.kube_candidate_qualification
   uv run --locked python scripts/check_docs.py
   ```

2. Запустить только targeted hosted workflow на выбранном зафиксированном commit. Это создаёт временный кластер и выполняет реальные изменения только внутри него. Push в `codex/cp3-m11-trust` уже запускает его автоматически; дополнительный dispatch того же commit не нужен.

   ```powershell
   gh workflow run kubernetes-serving.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref <COMMIT_OR_BRANCH>
   ```

3. Дождаться положительных base checks, затем nonterminal outage/blackhole/policy/replay. После этого проверить `actual-candidate-model-revocation` и `actual-candidate-key-revocation`: каждый имеет свой положительный inference, live denial и точную cold-причину. Оба используют неизменные model/subject/source/permit.
4. Сверить `independent_authorities.states`: до отзыва, после модели, после ключа. Изменяется только выбранный target, версия растёт на один, прежние revocations сохраняются; другой target полностью неизменен. Проверить взаимный TLS отказ с чужим CA и SQLSTATE 42501 для запрещённых операций в обоих экземплярах.
5. Проверить два заключительных cold reports, неизменный CAS/promotion snapshot, hashes файлов отчётов и source fingerprint. Новый Worker при cold denial не создаётся.
6. Подтвердить success обоих cleanup steps: остановлена собственная source SQL, удалён только verified owned disposable cluster. Этот cleanup уничтожает тестовый стенд, а не снимает отзыв в работающей системе.

При отказе сохранить конкретный fault/stage/commit, отделить local contract tests от native результата. Повтор возможен после установленной причины и исправления. Rollback к отозванному ключу/модели запрещён; для нового опыта создаётся целиком новый disposable state с новой campaign. Ни успешный unit test, ни отдельный 503 не закрывают M11 или R1.
