# Отдельный trust service в Kubernetes

Неделя 8, T13/T14, CP3/R1-B04. Этот профиль соединяет существующий SQL authority доверия с изолированными Kubernetes readers. Это обязательная зависимость запуска promotion и serving внутри кластера. Полные M10/M11 и R1 остаются открытыми: проверка сервиса сама по себе не является выпуском модели или приёмкой serving lease.

## Архитектура и права

- PostgreSQL использует тот же закреплённый image, что и проверенное хранилище моделей. Отдельный StatefulSet `postgres` в `ml-trust`, отдельные PVC и CA, имя `postgres.ml-trust.svc.cluster.local:5432`. Хранилище моделей остаётся в `ml-storage`; никакого объединения trust и model database.
- TLS 1.3 с проверкой цепочки, имени сервера и клиентского сертификата. Клиентский loader допускает только два точных cluster FQDN и loopback lab profile; произвольные endpoint или порты для cluster profile не допускаются.
- Только `ml-promoter/promoter` и `ml-serving/serving` получают `trust-client` Secret и сетевой доступ к authority. Cilium ограничивает адресата и TCP/5432; DNS доступ остаётся в прежней storage policy. В namespace authority действует default deny, исходящий трафик сервера запрещён.
- SQL readers имеют SELECT на текущую подписанную trust policy. Запись документов, смена environment, переход в owner/superuser и доступ к model CAS в этой базе запрещены. Bootstrap использует существующие migrations, затем отзывает у trust readers доступ к схеме `ml`.
- Pod получает только собственный client bundle, read-only filesystem, non-root UID 65532, seccomp, сброшенные capabilities и ограниченные ресурсы. API token, signer key, host paths и Docker socket не монтируются. Сам PostgreSQL запускается по существующему restricted профилю UID 999.
- Signing key остаётся у оператора за пределами Pods. Существующий `trust_authority` проверяет подпись, версию, время, монотонный successor, идемпотентный повтор и SQL readback. Kubernetes backend меняет только способ выполнения административного SQL через проверенный owned Pod; формат доверия и правила верификации не меняются.
- Bootstrap запоминает UID, digest желаемых ресурсов и привязку сохраняемого тома. Чужой объект, изменённый Secret/policy, потерянный ownership marker, несовместимая спецификация или подмена PVC/PV требуют явного разбора; автоматического усыновления или reset нет.

Код: [deployment](../mlsecops/kube_trust.py), [authority](../mlsecops/trust_authority.py), [TLS client](../mlsecops/storage.py), [native reader probe](../mlsecops/kube_trust_probe.py), [hosted qualification](../scripts/kube_trust_native.py).

## Воспроизведение

В текущей задаче инфраструктурные команды выполняются **только в disposable GitHub-hosted CI**. Локальные Docker, WSL, Kubernetes и SQL не запускаются. Workflow [kubernetes-trust.yml](../.github/workflows/kubernetes-trust.yml) создаёт чистый checkout, ставит locked dependencies/tools, собирает worker, поднимает owned cluster/model storage, выполняет qualification и удаляет только проверенный owned cluster.

На заранее подготовленном разрешённом стенде операторский путь такой:

```sh
uv run --locked python -m mlsecops.kube_trust --state .runtime
uv run --locked python -m mlsecops.trust_authority install --backend kubernetes --state .runtime --environment local-cpu --root-public "$TRUST_ROOT_PUBLIC" --confirm-authority
uv run --locked python -m mlsecops.trust_authority publish --backend kubernetes --state .runtime --document /private/signed-trust-policy.json --confirm-authority
uv run --locked python -m mlsecops.trust_authority show --backend kubernetes --state .runtime
```

`TRUST_ROOT_PUBLIC` - проверенный публичный ключ оператора, не значение из неподтверждённого запроса на выпуск. Signed document готовится существующим signer вне reader Pods. Для повторной проверки кода без инфраструктуры:

```sh
uv run --locked python -m unittest scripts.kube_trust_qualification scripts.kube_trust_probe_qualification scripts.kube_trust_native_qualification scripts.trust_authority_qualification scripts.promotion_controller_qualification
```

Native campaign проверяет повтор bootstrap/install/publication, независимость CA, TLS/SQL права promoter и serving, network timeout для trainer/evaluator/publisher/scorer/ingestor/curator, подписанный отзыв version 2, реальную недоступность authority, восстановление того же тома и повторное чтение version 2. Read-only model storage ledger и Git checkout сравниваются до/после. Отрицательный отказ принимается только по ожидаемому виду ошибки; неизвестная SQL/TLS ошибка не считается успешным запретом.

## Статус проверки

Локально: 10 deployment tests, 4 reader-probe tests, 5 native-harness tests и 20 существующих authority/promotion-controller tests pass. Deployment: 132/132 statements, 42/42 branches; probe: 73/73 statements, 24/24 branches. Native CI на чистом checkout ещё требуется. Это компонентная проверка, не M10/M11/M18 acceptance.

## Ранбук: authority не запускается или не читается

Ответственный - оператор платформы. Prerequisites: owned kubeconfig и workspace marker, доступ к уже разрешённому disposable стенду. Начинать с read-only `trust_authority show --backend kubernetes`: успешный ответ подтверждает административный readback, но ещё не сетевую доступность для serving.

1. **Bootstrap отказал по ownership/spec.** Сверить `kubernetes-trust/resources.json`, workspace identity, UID ресурсов, TLS fingerprints и PVC/PV binding в приватном evidence. Не удалять marker, не принимать чужие ресурсы и не переключать Service на model storage. При неизвестном происхождении объекта остановить этот выпуск и передать оператору журнал изменений.
2. **Pod не Ready.** Проверить состояние owned `postgres-0`, PVC binding, image digest, лимиты и HBA-конфигурацию. Логи исследовать только приватно; не публиковать DSN, сертификаты с ключами или raw logs. Потеря готовности не разрешает обход verify-full или использование другой CA.
3. **Reader получает отказ.** Разделить DNS/network, TLS identity, SQL privileges, signed policy expiry/root/version. Использовать native probe из того же namespace/ServiceAccount. Произвольный connection error не доказывает network policy; тест требует timeout плюс рабочие разрешённые readers.
4. **Authority недоступен.** Serving обязан следовать прежнему lease, не продлевать его и не снимать revocations. Сам этот компонентный workflow не измеряет полную 60 s serving границу. После восстановления проверить текущую подписанную version, root/policy и revocation set; старый документ не использовать как fallback.
5. **Сбой публикации с неизвестным исходом.** Выполнить `show`, сравнить expected document digest/version, затем повторить тот же подписанный документ. Идемпотентный readback допускает повтор; другой successor после неопределённого исхода требует сначала установить актуальное состояние.

## Плейбук: контролируемый outage и восстановление

Исполняется только qualification на разрешённом disposable CI. Сохранить UID StatefulSet и PV, проверить текущую спецификацию, уменьшить replicas до 0, дождаться удаления Pod, проверить `trust.Unavailable` настоящим reader Job. В `finally` восстановить replicas=1 только у того же UID с ожидаемой предыдущей спецификацией, дождаться Ready, сверить тот же PV и прочитать version 2 с прежним отзывом. Удаление PVC или пересоздание authority с пустой историей не является восстановлением.

Успех этого плейбука подтверждает сохранение истории на том же томе после restart. Он не подтверждает backup restore в новом окружении, RTO/RPO M17, HA, полный approved promotion или production serving. Эти требования остаются в [CP3-CP5](r1-delivery.md).
