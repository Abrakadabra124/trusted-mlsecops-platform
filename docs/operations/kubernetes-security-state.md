# Первичное состояние аудита Kubernetes

Статус: operator bootstrap и обязательный аудит promoter реализованы и проверены
локальными contract tests. Native Kubernetes acceptance ещё не подтверждена.
Этот документ не является инструкцией запуска всей платформы или доказательством R1.
[План](../../tasks/audited-kubernetes-promotion-plan.md),
[ADR0066](../decisions/0066-audited-kubernetes-promotion.md).

## Границы ролей

| Роль | Namespace / service account | Приватные материалы | Persistent state |
| --- | --- | --- | --- |
| Collector | ml-audit / collector | Server TLS, receipt key, collector key, ingress/operator tokens | Собственный journal |
| Trust observer | ml-serving / serving | Client TLS, собственный producer key, ingress token; существующий SELECT-only trust client | Собственный outbox |
| Promoter | ml-promoter / promoter | Client TLS, собственный producer key, ingress token; отдельные существующие model/trust clients | Собственный outbox |

Все три PVC имеют имя `security-events`, но принадлежат разным namespaces.
Используется существующий storage class с Retain policy. Runtime не получает
CA private key; worker не получает audit profile. Network resources открывают
только TCP8443 между обозначенными namespace/service account и collector.
Проверка манифеста не доказывает фактическую сетевую изоляцию - нужен native test.

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
   счётчики и envelopes; этот сценарий ещё подлежит native проверке.

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
