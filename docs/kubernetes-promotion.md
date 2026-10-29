# Изолированное выполнение promotion

Неделя 8, T13, CP3/R1-B04. [Kubernetes authority](kubernetes-trust.md) подключён к существующему [promotion CLI](promotion-entrypoint.md) через отдельный restricted Job. Код реализует подачу immutable references, проверку результата и очистку owned ресурсов. Полный M10 и R1 остаются открытыми до общей приёмки actual candidate.

## Оператор и исполнитель

Операторский [kube_promotion](../mlsecops/kube_promotion.py) проверяет owned model/trust services, загружает image с проверенными source labels и immutable manifest, фиксирует отдельные ConfigMap с конфигурацией и запросом и запускает Job. Только операторская команда `configure` инициализирует журнал/прикрепляет environment к policy digest. Подача `submit` не выполняет migrations, не создаёт подписи и не меняет policy.

Исполнитель запускает прежний `mlsecops.promotion_controller` в `ml-promoter` под ServiceAccount `promoter`. Ему доступны два разных read-only bundle: `/client` для моделей и `/trust-client` для authority. Ключ подписи, API token, Docker socket и host filesystem не монтируются. Init containers копируют только собственные TLS client credentials в memory-backed volumes; основной процесс имеет read-only root, UID 65532, seccomp, dropped capabilities и resource limits. Worker image проверяется до запуска и по фактически завершившемуся Pod.

Конфигурация передаётся отдельно от запроса, ограничена 512 KiB, запрос ограничен 64 KiB. Storage paths фиксированы; request schema не допускает подмену roots, policy, image или credentials. Существующий верификатор повторно проверяет цепочку signed materials/reports/approval, свежую trust policy и SQL journal. Результат разрешённой записи остаётся `recorded-not-activated`, `release_ready=false`.

Driver различает ожидаемый отказ CLI (Failed Job, exit 1, точный constant diagnostic), crash/OOM/timeout и недопустимый receipt. Успешный exit без правильных proposal/environment/sequence/digests не принимается. В `finally` удаляются только созданные им Job и ConfigMap, после сверки UID/spec; проверяется их отсутствие. Неизвестная очистка запрещает успешный итог.

## Команды

В этой задаче инфраструктурное воспроизведение разрешено только в disposable hosted CI. Workflow [kubernetes-promotion.yml](../.github/workflows/kubernetes-promotion.yml) собирает pinned image, поднимает owned cluster, два SQL service и отдельный source candidate, затем проверяет admission и удаляет собственные ресурсы. Локальные Docker/WSL/Kubernetes/SQL не запускаются.

Операторский путь на разрешённом подготовленном стенде:

```sh
uv run --locked python -m mlsecops.kube_promotion configure --state .runtime --config /private/operator-promotion.json
uv run --locked python -m mlsecops.kube_promotion submit --state .runtime --config /private/operator-promotion.json --request /private/release-request.json --image trusted-mlsecops:dev
```

Operator config соответствует [CONFIG_FIELDS](../mlsecops/promotion_controller.py), с `storage_client=/client`, `trust_client=/trust-client`; остальные roots, context и pins берутся из проверенной release цепочки. JSON request содержит только `schema_version`, `proposal_reference`, `policy_reference`, `assurance_reference`, `approval_reference`. `null` assurance/approval допустимы для проверяемого отказа, но не для разрешённого promotion. Авторизованный signed trust document публикуется отдельным authority operator, signing key в Job не передаётся.

## Проверки и границы результата

Локально и затем в Linux CI прошли 41 test: 9 нового driver, 3 native harness и 29 существующих ledger/trust/controller. Driver: 131/131 statements, 40/40 branches. Native результат подтверждён ниже.

Native campaign отдельно формирует настоящий candidate и доказывает отказ `release_assurance_required` исходным верификатором. Его неизменённые proposal/policy bytes переносит в cluster CAS, запускает обычный CLI в Job и проверяет отказ без записи admission objects. Положительный сценарий использует явно обозначенный controlled signed fixture: missing approval отказан, initial head=0, разрешённая запись head=1, независимый SQL readback, exact retry с тем же receipt и без новых объектов, отзыв модели и отказ повторного promotion. Контрольные all-pass reports не выдаются за actual candidate acceptance.

Это соединение promotion CLI с изоляцией и authority. Оно не подтверждает штатный serving HTTP/ONNX в Kubernetes, полный M10/M11/M12/M13/M19, общий inventory или M18. [Все CP2-CP5](r1-delivery.md) сохраняются, включая system-image findings и независимые M22 challenges.

## Native результат 2026-10-29 МСК

[Run 40797761104](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40797761104), job `123198252561`, attempt 1, **success** на commit `a5452eebb1c60234996d646bda8d1588f1ec4d41`. Чистый checkout, `source_dirty=false`. Admission campaign: **04:03:32-04:05:14 МСК**. Пять настоящих Kubernetes Jobs выполняли прежний promotion CLI; каждый проверен по фактическому image/config, терминальному состоянию и owned cleanup.

**13/13 integration cases pass:**

| Проверка | Cases | Результат |
|---|---:|---|
| Настоящий candidate | 3 | Исходный verifier возвращает `release_assurance_required`; обычный CLI в изолированном Job отказывает по тем же staged proposal/policy references; CAS ledger не изменён после подачи |
| Контрольный release | 9 | Initial head 0; отсутствующий approval отказан без записи; корректная запись даёт head 1 и `recorded-not-activated`; независимый SQL readback совпадает; exact retry возвращает тот же receipt без новых объектов/sequence; signed model revocation запрещает повтор без изменения ledger |
| Source preservation | 1 | Исходный owned SQL container и source revision/fingerprint сохранены |

Привязки:

- Source fingerprint: `bddb0606ee2b535b95757e747459b9680511d7c16800375fe654343b204d3724`.
- Actual candidate: `7ead97623164afdcb10160956bac6eff13f9eb6b1b860278e649d39de905139f`.
- Actual proposal: `47f01ba582d9f330805823276afcd601f75c4c4be7ea8134298f9f19d151c29d`.
- Actual model: `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`.
- Worker config/image ID: `sha256:324cd9e21d4d199324f5b10911adc1d63711e5b1c7ab735757447c19edaf63e1`.
- Controlled model: `6e4e5e65497470e5fe72af895107f291245c1bfc70070378cf3cdf95d2058169`.
- Controlled request: `2ba4bb753d9d92f782c00a38267aeaae3727ff564230a9d29392c9f34788badc`.

После campaign отдельные cleanup steps подтвердили остановку owned source SQL (`State.Running=false`), удаление owned cluster и отсутствие его имени в `kind get clusters`. Linux CI: 32 adjacent/harness tests + 9 driver tests pass, driver coverage 100% statements/branches. Положительный controlled result не присвоен actual candidate; `full_M10=inconclusive`, `release_ready=false`.

Следующая обязательная интеграция - обычный serving configuration path и transport его постоянного изолированного ONNX worker. В текущем коде `serving_runtime.Worker` использует Docker stdin/stdout, поэтому запуск HTTP-контроллера внутри restricted Kubernetes Pod требует отдельного подходящего transport; Docker socket/hostPath для обхода ограничения не добавлялись. Это ещё не работающий Kubernetes serving и не завершённый CP3.

## Ранбук: отказ, неизвестный commit или cleanup

Ответственный - оператор платформы. Перед действиями нужны owned workspace/kubeconfig, точные immutable request references и операторские pins. Начать с чтения private receipt, состояния owned Job и SQL head; не печатать ConfigMap, ключи или raw service logs в публичный evidence.

1. **CLI отказал.** Проверить наличие и binding assurance/approval/reports, подписи, environment/policy/image, expiry и актуальный revocation set. Ожидаемый отказ не является crash. Не добавлять фиктивные reports и не менять policy ради зелёного результата.
2. **Job завершился аварийно или по deadline.** Проверить действительный image digest, завершение container, resource limits и доступ к двум service. `OOMKilled`, timeout или непредусмотренный stderr не считаются доказательством корректного запрета. Новый запуск допускается после установления терминального состояния прежнего Job.
3. **Получен отказ после возможного SQL commit.** Отсутствие успешного driver result не доказывает отсутствие записи. Сверить current head, event и immutable request digest с ожидаемым receipt. Повторять тот же запрос; не увеличивать sequence и не изменять approval наугад. После отзыва даже exact retry должен быть запрещён.
4. **Cleanup не подтверждён.** Сверить UID/spec с созданными ресурсами, проверить отсутствие активного Pod. Удалять только подтверждённые Job/ConfigMap. Чужой UID или неизвестный исход create требуют разбора, автоматического adoption нет. Private cleanup failure не означает автоматический rollback транзакции.

Плейбук native проверки: подготовить actual proposal -> подтвердить исходный отказ -> сверить staged CAS bytes -> выполнить изолированный отказ -> сравнить ledger -> отдельно настроить controlled authority/journal -> missing-approval negative -> positive/readback -> exact retry -> signed revoke -> denied retry -> проверить source -> удалить только owned cluster и остановить owned source SQL. Успешная очистка инфраструктуры подтверждается отдельно от результата admission.
