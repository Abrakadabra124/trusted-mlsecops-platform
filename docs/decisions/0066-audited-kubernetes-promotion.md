# ADR 0066: обязательный аудит Kubernetes-promotion

Статус: принято для реализации существующей T29/M23, не новый scope R1.

## Проблема и результат

На25371bf воспроизведено: Kubernetes adapter требует schema1, controller требует
schema2/security_audit_config. Schema1 с новым полем проходит adapter и отвергается
controller; schema2 отвергается adapter. Дополнительно collector и transport
слушают/подключаются только к loopback, а настоящий promoter работает внутри Pod.
Простая замена номера schema не создаёт рабочую доставку аудита.

Результат: обычный Kubernetes promoter получает обязательный аудируемый профиль,
доставляет реальный отказ и проверяет свежую подписанную доступность collector
перед выпуском. Недоступность collector запрещает promotion. Stateful collector
и producer outbox сохраняются при замене Pod. Worker не получает ни TLS secrets,
ни event signing key, ни ingress/operator token, ни доступ к audit volumes.

## Транспорт

Прямой mTLS через стандартные Python ssl/uvicorn, без proxy/нового оркестратора.
TLS1.3, отдельный CA аудит-системы, обязательные client certificates, проверка
hostname `collector.ml-audit.svc.cluster.local`. Клиент использует конкретный
operator-pinned IPv4 из проверенного Kubernetes Service; DNS не входит в
двухсекундный wire deadline. Ни redirects, ни proxy/environment routing, ни
plain fallback не разрешены. Подписи event/receipt/challenge сохраняются:
TLS защищает канал, а не заменяет авторизацию события или release policy.

Producer config schema2 добавляет tls: address/server_name/ca_file/certificate_file/key_file.
Audit-admission config schema3 использует тот же транспорт; существующий
loopback producer schema1 и admission schema2 остаются для прежних lab fixtures.
Collector config schema2 добавляет tls: ca_file/certificate_file/key_file и
слушает0.0.0.0 только при успешно настроенной mutual TLS. Старый collector
schema1 остаётся строго127.0.0.1. Неполная конфигурация не понижает защиту.

## Развёртывание и роли

Operator bootstrap проверяет ownership workspace/UID/spec существующих ресурсов,
создаёт отдельный ml-audit namespace, Service, collector и trust-observer,
приватные TLS/config secrets и отдельное durable filesystem state. Применяются
существующие patterns restricted Pods, Cilium identity policies и owned local
storage. Не совмещать audit journal с модельной БД или worker scratch.
Promoter получает только собственный producer key/outbox и TLS/ingress client.
Collector receipt key, operator token и CA private key ему не передаются.
Trust observer использует существующий SELECT/TLS ml_serving доступ без новых
SQL write grants. Его настоящий heartbeat обязателен для healthy audit.

Kubernetes config schema2 требует фиксированный `/security/audit.json`, проверяет
развёрнутый audit profile до Job и монтирует только предназначенные роли файлы.
Отдельные network rules открывают нужный TLS port trusted identities; worker
остаётся без audit egress. Нельзя принять source/key/epoch/state reset за recovery.

## Альтернативы и ограничения

Размещение нового collector в каждом promoter Job теряло бы общее состояние
при завершении Job и усложняло бы обнаружение пропавшего источника. Sidecar proxy
создал бы дополнительный image/process без необходимости. Откат controller к
schema1 снял бы обязательное audit admission и потому не исправляет контракт.

Одноузловой owned lab, доверенный host administrator, синтетические credentials,
без HA/KMS/новых облаков. TLS keys и сертификаты создаются оператором, не worker.
Общий registry всех семи источников, свежие M13/M14/full M23 и все M01-M23/M18
на одном candidate остаются обязательны. Controlled approval не разрешает
настоящий candidate без остальных gates.

## Проверка

Negative-first: неправильные CA/name/client certificate, plain downgrade,
expired certificate, malformed/private paths, зависший handshake, total deadline,
config schema drift. Затем hosted: реальный cluster, TLS collector, trust heartbeat,
обычный promoter CLI с actual denial и отдельно controlled positive; audit outage
без записи active release; исходный event после восстановления; journal/counter
после Pod restart; worker mounts/network refusals; ownership-bound cleanup.
