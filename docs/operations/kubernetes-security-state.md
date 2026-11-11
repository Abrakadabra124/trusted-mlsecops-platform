# Первичное состояние аудита Kubernetes

Статус: operator bootstrap и обязательный аудит promoter проверены в hosted
Kubernetes на4aeece4 /43102906649: [evidence](../evidence/kubernetes-audit-2026-11-12.md).
Отдельная periodic observer regression остаётся открытой; полный M23 не принят.
Этот документ не является инструкцией запуска всей платформы или доказательством R1.
[План](../../tasks/audited-kubernetes-promotion-plan.md),
[ADR0066](../decisions/0066-audited-kubernetes-promotion.md).

## Границы ролей

| Роль | Namespace / service account | Приватные материалы | Persistent state |
| --- | --- | --- | --- |
| Collector | ml-audit / collector | Server TLS, receipt key, collector key, ingress/operator tokens | Собственный journal |
| Trust observer | ml-serving / serving | Client TLS, собственный producer key, ingress token; существующий SELECT-only trust client | Собственный outbox |
| Promoter | ml-promoter / promoter | Client TLS, собственный producer key, ingress token; отдельные существующие model/trust clients | Собственный outbox |
| HTTP serving | ml-serving / serving | Отдельные client TLS и producer key, identity-audit.json; без promoter/observer signing keys | Отдельный outbox на security-serving |

Три прежних PVC имеют имя `security-events` в разных namespaces. Четвёртый,
`ml-serving/security-serving`, принадлежит HTTP role. Operator выбирает PVC
по namespace **и имени роли**, затем проверяет UID, PV и claimRef. Совпадение
namespace с trust observer не разрешает использование его тома.
В ml-serving бюджет явно ограничен двумя PVC и пятью Secrets: model client,
два trust clients, observer audit и HTTP audit. CPU/memory бюджет не увеличен.
Используется существующий storage class с Retain policy. Runtime не получает
CA private key; worker не получает audit profile. Network resources открывают
только TCP8443 между обозначенными namespace/service account и collector.
Кроме manifest checks, native test подтвердил отсутствие audit mounts и TCP-доступа trainer.

## PB: создание нового состояния

Выполняет доверенный operator только на разрешённом disposable hosted runner.
Локальные Docker/WSL/Kubernetes/SQL по условиям задачи не запускаются.

1. Bootstrap проверяет workspace/UID/spec и свежий PVC, сохраняет
   UID создаваемого Job до принятия результата. Обнаруженные чужие ресурсы или
   утерянный marker не разрешают adoption или повторный init.
2. Отдельный Job запускает `python -m mlsecops.security_event_provision --config /security/provision.json`.
   Конфигурация содержит ровно schema_version1, role, подписанный registry,
   registry_root, registry_sha256, producer_id. TLS/signing private keys ему не нужны.
3. Entry point проверяет подпись, срок действия, pin и producer role. Для trust
   heartbeat обязателен. Создаётся только фиксированный `/audit/state`, затем
   журнал повторно открывается с проверкой private permissions и identity pin.
4. Успех отдаёт конечный JSON с role, producer_id, registry_sha256,
   state_sha256 и release_ready=false. Bootstrap сохраняет pin и сверяет PVC/PV
   UID, claimRef, Retain class и spec digest перед выдачей runtime config.
   Один exit0 не доказывает PVC identity.
5. Collector, observer и promoter запускаются с существующими pins. Их runtime
   specifications не содержат init журнала. Замена Pod должна сохранять файлы,
   счётчики и envelopes; collector/observer replacement подтверждён в evidence.

Для disposable hosted окружения после успешных storage/trust bootstrap и явной
настройки trust authority предусмотрен entrypoint:

```text
python -m mlsecops.kube_security_events --state .runtime --environment local-cpu --initial-root PUBLIC_TRUST_ROOT --policy SECURITY_POLICY_SHA256 --image trusted-mlsecops:dev
```

Параметры в верхнем регистре - публичные значения согласованного профиля.
Security policy pin обозначает политику аудита, отдельно от ML promotion policy.
Runtime configuration promoter schema2 обязана содержать
`security_audit_config: /security/audit.json`. API возвращает только конечный статус,
registry pin и release_ready=false. Это не успешный release и не проверка healthy
heartbeat: каждый promotion сам проверяет свежий подписанный audit challenge.

Повтор bootstrap на полностью созданном профиле выполняет validate без новых ключей.
Незавершённый профиль, отсутствующие pins или несоответствие image/context запрещают
автоматическое продолжение. Не запускать provisioning вручную для восстановления.

В hosted campaign подготовка authority теперь использует закреплённый operator key
`keys/trust.pem` и сверяет его public key с trusted-keys.json. Ключ не создаётся при
его потере. Если trust schema уже принадлежит другой authority, подготовка
останавливается до изменения policy и audit profile. Для пустой signed history
создаётся seed `unapproved-campaign`; он не является model approval или qualification
permit. Существующая signed policy сохраняется при повторном prepare. Так actual
refusal выполняется после audit bootstrap, а следующий controlled/candidate этап
не выбирает несвязанный новый authority key. Это один lab operator, не независимые
администраторы. Ротация требует отдельного signed transition и observer update;
повтор prepare после неизвестной смены корня не должен принимать её автоматически.

Продолжение интеграции serving, его отдельного event identity/outbox и необходимых
fresh M13/M14 описано в [плане](../../tasks/audited-serving-integration-plan.md).

Registry живёт24часа; TLS leaf certificates90дней, CA365дней. Продление registry и
обновление observer rotation packages не выполняются автоматически этой версией.
Expiry вызывает отказ. Полная эксплуатационная миграция и fresh M13/M14 ещё нужны.

Для fresh профиля bounded quota ml-promoter/ml-serving допускает4Secrets:
model client, два trust clients и один audit role. ml-serving также учитывает
дополнительный observer1CPU/256Mi: общий limits.cpu3 и limits.memory1280Mi.
Существующий кластер со старым spec digest требует явной миграции; bootstrap не
расширяет его бюджет незаметно. Для проверки используется новый owned disposable
cluster, без изменений локальной инфраструктуры и без удаления старых данных.

## RB: существующий или повреждённый журнал

Для нового четырёхролевого профиля недопустимо дописывать файлы в старый
трёхролевой marker, пересоздавать identity или выдавать другой PVC за прежний.
Повтор bootstrap проверяет полный набор закреплённых файлов и ресурсов; потеря
serving PVC либо подмена его PV на observer PV приводят к отказу без repair.
Сохранить приватные marker/UID/pins, установить причину и эскалировать оператору.
В этом disposable стенде новую проверку проводят в новом принадлежащем задаче
окружении. Эта процедура не является миграцией действующего постоянного журнала.

Обычные serving/privacy Jobs используют `identity_audit_file` с фиксированным
значением `/security/identity-audit.json`. Поле `security_audit_config` принадлежит
promoter и отвергается до создания serving Job. Конвертация сначала валидирует
полную promotion schema2, затем формирует отдельную HTTP-конфигурацию; вложенные
объекты копируются, чтобы настройки HTTP не меняли исходный promotion context.
До создания Job operator проверяет существующий audit profile, image, environment
и initial root. После root rotation эта проверка остаётся закрытой до реализации
проверяемого обновления observer; удалять сравнение root нельзя.

`service_sha256` закрепляет workspace, environment и роль HTTP-сервиса. Это
стабильная идентичность сервиса между заменами Pod, не digest модели или образа.
Обычный HTTP lifespan запускает существующий identity child с этим файлом.
Непрерывный serving до/между promotion и обязательный serving heartbeat в registry
пока не соединены. Candidate qualification paths также ещё не интегрированы с
этой идентичностью. Provisioning и mount tests не являются свежими M13/M14/M23.

### PB: HTTP и выбор модели в одном hosted сценарии

В workflow `kubernetes-promotion.yml` добавлены последовательные ordinary HTTP
Jobs вокруг существующего controlled approval. До выбора модели readiness и
prediction должны отдавать503 без запуска inference worker. После выбора
проверяются ONNX golden scores, неизменная identity worker, привязка model/bundle,
HTTP401 для запроса без credentials, а также завершение собственного worker.
После отзыва модели ожидается `trust_artifact_revoked` и отказ до создания worker.
Команды CLI выполняются существующим `mlsecops.kube_serving_probe`, с проверкой
фактического Pod image/spec/UID и обязательной очисткой, не подменённым Engine.

До и после положительного HTTP-запуска считываются существующий serving outbox
и независимый collector journal. Новый identity.denied должен иметь тот же
event ID, digest подписанного envelope и receipt в обоих журналах. Старый event,
замена outbox pin, отсутствующий receipt или чужое событие не подтверждают доставку.
Каждая HTTP-фаза также проверяет неизменность model/promotion SQL snapshot.

При ошибке не повторять approval и не очищать журнал. Сначала прочитать конечный
статус того же workflow/job, сохранить приватные evidence и проверить owned cleanup.
Фиксированные phase/code в serving result помогают отличить startup, HTTP и shutdown.
Недоступный collector, неверные права ключа или потеря serving state требуют
восстановления исходной идентичности; отключение identity audit не является recovery.
Сценарий проверен на d86d3de /43113676523: [evidence](../evidence/kubernetes-audit-2026-11-12.md).
Три последовательных Job не доказывают работу HTTP между фазами: continuous_lifecycle=false сохраняется
в отчёте. Полный R1 требует непрерывного serving и всех исходных gates.

Симптом: `security_provision_rejected`, либо runtime отказ чтения identity/state.
Не удалять каталог и не повторять init. Сначала проверить ожидаемые namespace,
workspace, PVC/PV UID, binding, Retain policy и Job UID по приватному marker.
Затем сохранить приватную копию состояния и сверить identity hash с ранее
закреплённым state_sha256. Не печатать Secret, token, key, raw events в публичные логи.

- Каталог уже существует: повторный init запрещён даже для пустого каталога.
- Отсутствует identity при сохранном state: это повреждение, а не новый том.
- Утерян PVC/marker или неизвестен результат provisioning Job: восстановление
  требует решения оператора с прежними pins; автоматической новой эпохи нет.
- Изменились права0700/0600: проверить volume driver и fsGroup, не отключать reader
   и не выполнять рекурсивный chmod без установленной причины и проверенной копии.

`OnRootMismatch` выбран, чтобы при подходящем корне тома Kubernetes не менял
права вложенных файлов повторно. Указанный storage driver должен подтвердить это
после замены Pod; шаблон конфигурации не заменяет проверку конечных permissions.
Для config/key files init-container создаёт отдельный0700 каталог в tmpfs,
копирует только фиксированный список файлов и выдаёт runtime read-only subPath.

## Воспроизводимая проверка building blocks

### Отказ collector и изменение SQL при отклонённом выпуске

Первый кластерный запуск `1ec2222` /43101562581 прошёл bootstrap, actual candidate
refusal, fresh mTLS challenge и запрет доступа trainer. При сетевом отказе collector
настоящий promoter отклонил выпуск, но сценарий остановился перед подтверждением
неизменности хранилища. Исходный журнал не содержал точного exception location;
его общий отказ сам по себе не доказывает причину. Source SQL был остановлен,
owned cluster удалён, оба cleanup steps завершились success.

Локальная отрицательная проверка воспроизвела конкретный дефект: при изначально
недоступном audit сервисе `promotion.promote` успевал вызвать публикацию immutable
артефактов до первого audit challenge. Выбор релиза блокировался, но это не было
полным отказом без записи. Добавлена свежая проверка перед первой публикацией;
проверки до SQL record_selection и после него внутри транзакции сохранены.
Если audit пропадает уже после первой проверки, оставшиеся immutable артефакты
не являются разрешённым выбором релиза; финальная транзакция обязана отказать.

Для диагностики сравнивать единый snapshot content-addressed objects и promotion
journal через `scripts.kube_promotion_snapshot.read`, а не только таблицы объектов.
Не удалять новые объекты вслепую и не разрешать выпуск по старому health. После
восстановления сети проверяются исходные event_id/envelope, подписанные receipts,
свежий challenge и отсутствие изменения выбранной версии при отказе. Новый native
запуск после исправления обязателен; локальный regression pass его не заменяет.

Первый ручной dispatch /43101392544 разрешился в предыдущий `ae7b687` сразу после
push и упал на старом schema contract до создания кластера. Проверять `head_sha`
каждого workflow run против ожидаемого commit. Этот результат не относится к
`1ec2222`; следующий /43101562581 был привязан к нужной версии.

В подготовленном Python3.12.15 окружении с locked dependencies:

```text
python -W error -m unittest scripts.security_event_provision_qualification scripts.kube_security_resources_qualification
```

На Windows Linux filesystem case явно skipped; остальные tests не поднимают
инфраструктуру. На Linux проверяются реальные private files, повторный отказ
без изменения identity/state и отказ после удаления identity при сохранном state.
Resource tests проверяют role exclusion, Secret inventory, отдельные PVC,
fixed commands и узкие Cilium rules. Hosted workflow дополнительно требует
не менее95% statements и branches отдельно для каждого нового module.

Эскалация владельцу нужна при неизвестном ownership, утере pins/единственной
копии журнала или неподтверждённой очистке. Откат к loopback/unaudited promotion,
новый ключ/epoch и удаление истории не являются rollback этой интеграции.
