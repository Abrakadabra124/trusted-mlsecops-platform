# ADR 0008: Закрытое хранилище для изолированных controllers

Дата: 2026-10-08. Статус: implemented component, 436 local checks passed; full M04/M20 not accepted. Связь: T05/T26.

## Причина

Текущая PostgreSQL доступна только через host loopback. Перенос publisher/scorer в Pods не должен открывать host network, отключать TLS или выдавать им host kubeconfig. Поэтому добавляем отдельный private Kubernetes storage profile, а не расширяем доступ к действующему Docker instance.

## Ограниченный план изменения runtime

1. Только собственный cluster `trusted-mlsecops`, проверенный через workspace и namespace UID. Foundation, global kubeconfig, Docker source storage и operator restore instance не изменяются.
2. Новый namespace `ml-storage`, один PostgreSQL 18.6 с прежним pinned image digest и неизменённой SQL migration. ClusterIP без NodePort/Ingress/hostPort; non-root, read-only root, отдельный PVC, quota и default deny.
3. Отдельная CA и SAN `postgres.ml-storage.svc.cluster.local`. Клиент использует TLS 1.3 и `verify-full`; SQL identities и ACL сохраняются. CA private key остаётся на operator host. В server Pod нет client private keys, в role Pod нет чужих keys.
4. Отдельные namespaces/ServiceAccounts для storage clients. Network policy разрешает только DNS и PostgreSQL, серверу запрещены исходящие соединения. Никакого RBAC на создание workloads или чтение Secrets пока не выдаётся.
5. Сначала пустая schema и реальные положительные/отрицательные SQL/TLS/network проверки. Копирование signed backup и запуск publisher/scorer controllers - последующий increment, не неявное переключение defaults.
6. Bootstrap сохраняет UID созданных ресурсов; повтор проверяет identity/configuration, но не присваивает чужие ресурсы и не исправляет drift вслепую. Изменение spec требует отдельного migration plan.

## Хранение и откат

Используется отдельный StorageClass local-path с `Retain`, не изменяется global default StorageClass. Диск находится внутри единственного kind node: это persistence при перезапуске Pod, не защита от потери node/cluster и не offsite backup. Rollback этого additive increment - прекратить использовать новый profile; старый host storage остаётся доступен. Автоматически удалять namespace/PVC/PV нельзя. Ошибки bootstrap оставляют известные ресурсы для диагностики, а не запускают broad cleanup.

## Почему так и границы доверия

Изоляция по namespace упрощает последующее разделение controller RBAC и Secrets. Network policy не заменяет SQL ACL и mTLS. Cluster administrator и node root остаются доверенными; Kubernetes Secrets в локальном etcd не являются KMS или доказательством encryption at rest. Проверки отдельного storage profile не закрывают M04/M20 целиком.

Основание: [Kubernetes RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/), [Persistent Volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/), [PostgreSQL 18 server TLS](https://www.postgresql.org/docs/18/ssl-tcp.html), [libpq certificate verification](https://www.postgresql.org/docs/18/libpq-ssl.html). Проверено 2026-10-08. Применение этих принципов к одному kind node - инженерное решение проекта, не production certification.
