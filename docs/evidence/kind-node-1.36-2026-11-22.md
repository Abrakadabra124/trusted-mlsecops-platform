# Доступность предсобранного образа узла kind для Kubernetes 1.36

На 22 ноября 2026 года, 12:04 UTC, самый свежий официальный предсобранный образ ветки 1.36 для закреплённого kind v0.33.0 совпадает со штатным `kindest/node:v1.36.4` на ревизии `9fc19abac33b8afe6e61f5776c23a270589b62c0`. Второго, более свежего digest для парного скана нет. [Штатный образ](../../infra/kind.yaml) и [версия kind в контракте foundation](../../mlsecops/foundation.py).

## Проверка релизов и реестра

GitHub Releases API проекта kind вернул v0.33.0 как последний стабильный релиз. В release notes для него указан один образ ветки Kubernetes 1.36. Запрос Docker Hub к списку тегов `kindest/node` с фильтром `name=v1.36` вернул `count=2` и `next=null`. [Последний релиз kind](https://api.github.com/repos/kubernetes-sigs/kind/releases/latest), [release notes v0.33.0](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0), [список тегов Docker Hub](https://hub.docker.com/v2/repositories/kindest/node/tags/?name=v1.36&page_size=100).

| Тег kindest/node | Релиз kind, в котором опубликован образ | SHA-256 индекса из реестра | SHA-256 манифеста linux/amd64 |
|---|---|---|---|
| v1.36.4 | v0.33.0 | `099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed` | `597367624b4748b74b98e4fe2d661cd78063d02ecdaca702fd90572375b83e67` |
| v1.36.1 | v0.32.0 | `3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5` | `21c46cf61fd45873f89e6a1bfcba4b7904dffa84c2bec88aeeca9a0409af4725` |

Для обоих тегов запросил `GET /v2/kindest/node/manifests/<tag>` у `registry-1.docker.io`. SHA-256 байтов ответа совпал с заголовком `Docker-Content-Digest`, digest из Docker Hub и release notes соответствующего релиза kind. Выбрал дескриптор `linux/amd64`, прочитал дочерний манифест по digest и проверил его размер и SHA-256. В манифесте v1.36.4 указан config `sha256:0fa975026f71246c4e4744409d43e2e5884bb6e960851b438e50f455808c16f4`, тот же, что у штатного образа в историческом скане. [Релиз kind v0.32.0](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0), [тег v1.36.4 в Docker Hub](https://hub.docker.com/v2/repositories/kindest/node/tags/v1.36.4).

В Kubernetes опубликованы v1.36.5 (23 сентября) и v1.36.6 (28 октября). Для обоих тегов образа узла запрос того же манифеста вернул HTTP 404 с кодом реестра `MANIFEST_UNKNOWN`. Для v1.36.7 получены 404 и от Kubernetes Releases API, и от реестра образов узла. [Kubernetes v1.36.5](https://github.com/kubernetes/kubernetes/releases/tag/v1.36.5), [Kubernetes v1.36.6](https://github.com/kubernetes/kubernetes/releases/tag/v1.36.6), [API релизов Kubernetes](https://api.github.com/repos/kubernetes/kubernetes/releases).

## Что измерял эксперимент f8a15c4

На `f8a15c45b4544036df4de65fa904198ed2c5d065` проект сам собрал 1.36.6 из официального server archive на прежней базе kind. На одной базе уязвимостей у обоих образов Syft обнаружил по 878 пакетов. У штатного 1.36.4 Grype зарегистрировал 67 Critical, 394 High и 70 Unknown совпадений, у самосборки 1.36.6 соответственно 61, 349 и 67. Syft подтвердил `k8s.io/kubernetes v1.36.6` по путям `/usr/bin/kubeadm`, `/usr/bin/kubectl` и `/usr/bin/kubelet`. Итогом того аудита был `fail`. Эти числа относятся к исторической базе уязвимостей. Текущая проверка установила доступность образов по реестру. [Протокол исторической квалификации и config обоих образов](../operations/node-candidate.md#native-результат-2026-10-29-мск).

В полном аудите на `6abe6c7` узел имел этот же config ID. Сканер перечислил 878 записей, включая 160 пакетов Debian и 718 Go. Зарегистрированы 72 совпадения Critical, 491 High и 31 Unknown. В отчёте статус узла `fail`, профиль `unapproved-system`. Для платформы засчитаны 12 из 14 работающих образов. Узел kind остаётся одной из двух непокрытых целей. [Полный отчёт работающего профиля](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45018971253).
