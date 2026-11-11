# TLS для доставки security events

Часть [плана аудируемого Kubernetes-promotion](../../tasks/audited-kubernetes-promotion-plan.md).
[ADR0066](../decisions/0066-audited-kubernetes-promotion.md) фиксирует transport и
обязательное дальнейшее развёртывание. Наличие TLS-кода ещё не исправляет весь
Kubernetes profile и не завершает M23/R1.

## Контракт конфигурации

| Компонент | Loopback lab | Взаимная TLS |
| --- | --- | --- |
| Producer | schema1, прежние поля | schema2, дополнительно tls |
| Fresh audit admission | schema2, прежние поля | schema3, дополнительно tls |
| Collector | schema1,127.0.0.1 | schema2,0.0.0.0 только с TLS context |

Producer/admission tls содержит ровно `address`, `server_name`, `ca_file`,
`certificate_file`, `key_file`. Collector tls содержит только три file-поля.
Пути абсолютные, файлы приватные, каждый <=4096bytes; symlink/неподходящий тип
файла отвергаются существующим reader. CA и сертификаты не объединять с
подписывающим trust root модели: это разные границы доверия.

`address` - IPv4 из RFC1918 или loopback для проверки; endpoint Kubernetes
должен брать адрес из проверенного Service. DNS/URL/proxy/redirect не используются.
`server_name` фиксирован: `collector.ml-audit.svc.cluster.local`. Сертификат
сервера должен содержать этот DNS SAN даже при подключении к конкретному IP.
Только TLS1.3; server требует client certificate своего CA. Дополнительно
применяются прежние bearer роли и подписи каждого event/receipt/challenge.

Новый профиль не принимает отсутствие tls и не переключается на plaintext.
Старый профиль не принимает дополнительные TLS-поля. Настройка выполняется
оператором до запуска, не из входящего ML/security payload.

## RB: TLS-запрос не проходит

1. Read-only: проверить workspace/namespace и ожидаемый Service IP, даты и SAN
   публичного сертификата, контрольную сумму согласованного CA. Не выводить
   private key, token, DSN или целый secret/config в логи.
2. Проверить абсолютные пути, обычные файлы, ownership/private permissions,
   парность ключа и сертификата. `security_tls_materials` не раскрывает
   содержимое ошибки OpenSSL; отсутствие файла также не разрешает fallback.
3. Неверный CA/SAN, просроченный server/client certificate, server-only
   certificate вместо client-auth или TLS1.2 вызывают отказ. Восстановить
   согласованные материалы; не отключать hostname/chain/client verification.
4. Wire timeout2s включает TCP connect, handshake и весь HTTP response.
   Подготовка локального SSL context выполняется перед wire attempt.
   Отказ не означает, что remote collector не сохранил event: сверить pending
   outbox и signed receipt, повторить прежний envelope после восстановления.
5. После исправления проверить реальный heartbeat и signed receipt в независимом
   collector, затем fresh audit challenge. Сам по себе HTTP200 или TLS handshake
   не разрешает promotion.

## PB: безопасное восстановление

Остановить только принадлежащий профилю producer/observer, проверить reap его
child. Сохранить существующие outbox, registry pin и epoch. Проверить и заменить
ошибочные TLS-материалы согласно решению оператора; конфигурацию signer/registry
не менять для обхода отказа. Перезапустить тот же профиль, подтвердить retry
исходных событий и heartbeat counter без reset. При утере state/CA/private keys
эскалировать владельцу, не генерировать новую доверенную идентичность автоматически.

## Проверки и ограничения

`scripts.security_event_tls_qualification` использует реальные собственные TLS
сокеты: wrong CA/name/purpose/expiry, missing/foreign client certificate, TLS1.2,
plaintext endpoint, зависший handshake и запрет bearer до server authentication.
`scripts.security_event_tls_live_qualification` проверяет Linux collector process,
durable receipts, свежий audit challenge, outage/restart и original-event retry.
Результат hosted проверки пока не подтверждён; Kubernetes deployment - следующая
обязательная часть плана, не выполненная этим runbook.

При разработке Windows вернул ConnectionAbortedError/ConnectionResetError после
ожидаемого отказа TLS-клиента. Тестовый listener учитывает это только в явно
отрицательных сценариях. Он по-прежнему требует отсутствия HTTP payload и
завершения собственного thread; положительные сценарии reset не принимают.

Первый hosted run43093814194, contracts job130777400729, завершился отказом:
Linux listener получил `BrokenPipeError` после намеренного исчерпания deadline
сразу за handshake. Thread уже завершился; native job130777401404 прошёл.
Исправление ограничено тестовым listener: ожидаемый разрыв TLS1.3 при записи
служебных сообщений также допускается только в negative cases. Любые полученные
HTTP bytes теперь сохраняются сразу, включая неполный запрос перед EOF, чтобы
проверка отсутствия bearer не пропускала частичные данные. Runtime не изменён.
Локально повтор deadline10/10 и TLS15/15 прошёл; Linux collector требует hosted
проверки, один локальный skip не считается её заменой.
