# Первичное состояние аудита Kubernetes

Статус: operator bootstrap и обязательный аудит promoter проверены в hosted
Kubernetes на4aeece4 /43102906649: [evidence](../evidence/kubernetes-audit-2026-11-12.md).
Отдельная periodic observer regression остаётся открытой; полный M23 не принят.
Этот документ не является инструкцией запуска всей платформы или доказательством R1.
[План](../../tasks/audited-kubernetes-promotion-plan.md),
[ADR0066](../decisions/0066-audited-kubernetes-promotion.md).

## Постоянный HTTP Deployment

Проверено на88e7c0a/Kubernetes43119250736: сериализованная замена28.737285s,
heartbeat2->3, retained outbox, действующий inference и отказ после отзыва в том
же Pod; service/worker/SQL/cluster cleanup подтверждены.
[Evidence и ограничения](../evidence/persistent-http-2026-11-12.md). Operator API:
`mlsecops.kube_serving_service.bootstrap(state, profile, promotion_config)`.
Вызывать после audit bootstrap и `controller_bootstrap.bootstrap(..., serving=True)`
на разрешённом hosted стенде. Профиль берётся из этого bootstrap, promotion config
из существующей campaign, без ручной подмены image/root/policy. Локальный запуск
Docker/WSL/Kubernetes/SQL для этой задачи запрещён.

`release-risk-advisor` имеет одну реплику, стратегию Recreate, неизменяемый
ConfigMap и существующий Secret security-serving. Новый service.token отличается
от collector ingress/operator tokens. Никакого нового Service или внешнего
plaintext listener: HTTP доступен на loopback Pod, диагностический доступ идёт
через уже авторизованный Kubernetes exec. Readiness обращается к реальному
`/readyz` с собственным токеном; liveness обращается к `/livez`. Живой процесс
без выбранной модели остаётся NotReady и возвращает503 на prediction.

Состояние operator хранится в `.runtime/kubernetes-serving-service/resources.json`.
Его ready подтверждает ресурсы и HTTP liveness, не допуск модели. Перед exec или
заменой operator проверяет ConfigMap/Deployment UID, спецификацию Pod, image,
цепочку Pod/ReplicaSet/Deployment и исходный audit pin. Missing/incomplete/foreign
state запрещает автоматическое принятие ресурсов. Удалять marker для обхода
отказа нельзя. Security outbox сохраняется на PVC security-serving. Обычный
HTTP request journal пока находится в приватном tmpfs и не переживает замену Pod.

Плейбук после выбора release:

1. На том же trusted hosted operator выполнить
   `python -c "from mlsecops.kube_serving_service import validate; validate('.runtime')"`.
   Отказ требует выяснения UID/config/pin mismatch, а не reset состояния.
2. Подтвердить целевой bundle/policy и новую SQL selection существующим verifier.
   Уже запущенный без модели процесс не получает автоматической активации.
3. Вызвать `kube_serving_service.restart(state)`. Operator записывает incomplete
   marker, заменяет Deployment с replicas0, проверяя UID/resourceVersion, и ждёт
   отсутствия прежнего HTTP Pod и worker Jobs. Только затем разрешает replicas1
   с повторной проверкой UID/resourceVersion. Credentials и outbox не меняются.
   Timeout или конфликт оставляет incomplete marker и запрещает новый запуск;
   не исправлять marker вручную. Это незавершённое восстановление, не успешный rollout.
4. Проверить authenticated readiness, фактические model/bundle hashes, ONNX scores,
   сохранённые outbox pin/records и увеличение signed heartbeat в collector.
   При отрицательном результате не направлять трафик и не повторять promotion
   автоматически. Отозванный bundle нельзя возвращать в fallback.
5. Для завершения disposable proof вызвать `kube_serving_service.stop(state)`:
   удалить только записанные Deployment/ConfigMap по UID, дождаться отсутствия
   service Pod и worker Jobs, сохранить PVC/Secret. Stop не является backup/restore.

При startup failure проверить существование приватного каталога HTTP journal:
его создаёт отдельный init-контейнер, без подписывающих ключей и без HTTP probes.
Readiness/startup/liveness probes разрешены только основному контейнеру.
Новый файл service.token меняет pinned inventory: существующее старое состояние
не мигрирует автоматически. Не пересоздавать ключи или PVC ради успешного старта;
для такого состояния требуется отдельная проверенная процедура миграции.

Registry пока требует heartbeat только trust. Этот increment проверяет фактический
serving heartbeat и его счётчик, но потеря serving ещё не является обязательным
условием отказа promotion. Это открытая работа M23, не разрешение полного R1.

Причина сериализованной замены: Recreate управляет обновлением Deployment, но
ручной DELETE Pod позволяет ReplicaSet создать замену до завершения старого.
Для единственной identity/outbox такая гонка недопустима. Контракт проверяет
отсутствие HTTP Pod и worker Jobs перед запуском новой реплики, отказ при чужом UID,
конфликте состояния и зависшем shutdown. resourceVersion используется как условие
записи; при проверке ответа принимается новая версия, присвоенная API server.

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
не менее95% statements и branches отдельно для перечисленных в нём модулей.
Этот порог остаётся обязательным для всей новой security-critical логики при M18.

Эскалация владельцу нужна при неизвестном ownership, утере pins/единственной
копии журнала или неподтверждённой очистке. Откат к loopback/unaudited promotion,
новый ключ/epoch и удаление истории не являются rollback этой интеграции.

## Переход observer после ротации корня

Ответственный: оператор принадлежащего проекту стенда. Prerequisites:
подписанная обоими корнями rotation package, отдельный ожидаемый next_root,
исходный workspace marker, неизменные producer keys/outbox pins/PVC UID и доступ
к разрешённому hosted runner. Локальные Docker/WSL/Kubernetes/SQL этим ранбуком
не запускаются. Нужен зафиксированный image с новым operator и observer.

Диагностика начинается с `mlsecops.kube_security_events.validate(state)` и
`mlsecops.kube_observer_readback.history(state, marker)` в операторском окружении.
История читается реальной serving SQL ролью из собственного observer Pod;
raw history и markers остаются приватными. Сопоставить environment,
первоначальный корень, порядок документов и обе подписи перехода.
Новый корень в аргументе сам по себе не является доверенным.

После отдельно подтверждённой записи ротации authority выполнить:

```text
python -m mlsecops.kube_security_rotation --state .runtime --package /private/rotation.json --next-root <expected-public-key>
```

Это изменяющий шаг. Operator сначала проверяет цепочку от исходного
корня, затем сохраняет ready=false и immutable ConfigMap с публичным доказательством.
Он меняет только owned trust Deployment: UID/resourceVersion-bound scale0,
подтверждение отсутствия старого Pod, затем scale1. Новые Secret/producer/PVC
не создаются. ConfigMap копируется init-container в отдельный0700/0600 tmpfs,
чтобы runtime не обходил защиту reader от symlink.

Успех требует нового Pod/container, его собственного первого успешного source
check с хешем конфигурации, сохранности префикса подписанных событий и producer pin,
роста durable heartbeat counter и независимого readback collector. Старый log
из предыдущего контейнера и поздний heartbeat старого процесса недостаточны.
Время перехода ограничено120s; это проверка observer, не доказательство
непрерывной доступности HTTP и не разрешение на выпуск модели.

Повтор той же package при ready=true не перезапускает Pod и не заменяет историю.
Runtime ML reader продолжает сверять текущий SQL root: исторический корень,
присутствующий в проверенной цепочке, не разрешает свежий ML-запрос.

При прерывании после ready=false повторный bootstrap/update отказывает.
Сохранить marker, UID объектов, обе конфигурации, package и journals в приватном
evidence; проверить replicas, Pod UID/container restartCount и collector.
Не выставлять ready=true вручную, не откатывать authority на отозванный
ключ, не удалять outbox и не создавать новую epoch. Автоматическое продолжение
прерванного перехода пока не реализовано: неизвестное конечное состояние требует
эскалации оператору. На disposable hosted стенде workflow выполняет проверенную
очистку своего source SQL и кластера; это teardown, не доказательство M17 recovery.

Воспроизведение: `kubernetes-promotion.yml` после существующей HTTP-проверки
исполняет `scripts.kube_observer_rotation_native`. Неподписанный/неподтверждённый
переход должен отказать до изменения marker; после успеха старый SQL reader root
отказывает, новый проходит, одно конкретное событие trust.revoked/key совпадает
по envelope и receipt с независимым collector, model ledger не меняется.
Hosted переход наe7ec709 подтверждён43125706293; followup4f726f5 прошёл
security43127559794 и clean checkout133tests/1Windows skip.
[Точные результаты и ограничения](../evidence/observer-rotation-2026-11-12.md).
Полный M11/M23/R1 и включение всех caller paths открыты.

Первый security run на e7ec709 /43125649611 выявил недостаточное покрытие новых
ветвей `kube_security_events.py` в измеряемом наборе. Порог не менялся; добавлена
проверка настоящей подписанной цепочки, чужого ConfigMap UID и повреждённой подписи.
Локальное измерение этого модуля:211/213 statements,74/76 branches. Исходный
combined84% baseline трёх новых observer-модулей расширен проверками второй
ротации, очистки obsolete ConfigMap, смены контейнера, ограничений размера и
позднего readback. Каждый модуль теперь отдельно требует95% statements/branches
в CI; локально profile71/71+26/26, readback54/54+12/12, operator122/123+29/30.
Успешный отдельный native сценарий не заменяет этот критерий и полный M18.

В том же run periodic trust observer не восстановил heartbeat за45s после
возврата SQL credential directory: две failed checks, один event с receipt
в outbox и collector. Такой симптом встречался раньше; причина не установлена.
Добавлен read-only failure readback конфигурации, подписанной SQL history и
producer state. Он не отправляет heartbeat, не повторяет событие и не заменяет
факт неуспешного процесса. Булевы результаты описывают состояние после сбоя,
а не доказывают его причину. SQL/collector payloads и exception text не публикуются.
Интервалы30s/10s и deadline45s сохраняются. Повторный pass не считается устранением
необъяснённой нестабильности.

### Включение перехода в serving и candidate

`scripts.kube_root_rotation.exercise` после подтверждения SQL-ротации, retry и
отказа retired key вызывает тот же `kube_security_rotation.update`. Затем обычный
serving-сценарий проверяет настоящий отказ старой конфигурации и запускает reader
с новым root pin. Ошибка observer не допускает отчёт success и не возвращает
отозванный ключ. Контекст первоначального корня остаётся неизменным.

В `scripts.kube_candidate_root.exercise` сначала полностью заканчивается
измеряемый HTTP trace отказа/восстановления PRIMARY. После проверки trace и
истории вызывается переход observer. Он не сдвигает начало измерения отказа
и не увеличивает допустимые60s. Только затем отдельно ротируется MODEL_REVOCATION.
Observer читает PRIMARY, его профиль не меняется на историю второй authority.
Это две отдельные операции, не атомарная ротация двух сервисов. При ошибке
observer PRIMARY уже изменена, peer ещё прежний; слепой повтор или возврат
старого root запрещён, требуется диагностика фактической истории и marker.

Локально14coordinator tests проверили порядок, обе подписи и прерывание без
возврата ключа. Coverage обычного coordinator78/78statements+18/18branches,
candidate77/77+30/30. Hosted проверка этого включения выполняется workflow
`kubernetes-serving.yml` через существующий M11 сценарий; до terminal evidence
новые caller paths не считаются принятыми. Общий обязательный serving heartbeat
и полный R1 остаются открытыми.

При локальном расширенном прогоне M11 с `-W error` выявлена ошибка двух
существующих CLI-тестов: `runpy.run_module` повторно запускал уже импортированные
trust_authority/trust_root_store, и RuntimeWarning становился ошибкой. Изоляция
исправлена через `runpy.run_path` известного файла в отдельном `__main__` namespace;
warnings не подавляются, production CLI и подтверждение authority не меняются.
Contract runner теперь показывает идентификаторы непрошедших тестов, без private
exception text. Проверены обе исходные ошибки и полный набор161tests22.322s,
1POSIX Windows skip. Это исправление тестового окружения не объясняет прежний
hosted45s recovery timeout observer.
