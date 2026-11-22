# RB-18: отказ image audit и неполный просмотр CI

## Проверка опубликованного etcd в новом кластере

Этот сценарий проверяет штатный запуск с закреплённым системным образом. Он использует Linux AMD64 и одноразовые публичные runners GitHub. Рецепт и исходный архив закреплены в [квалификации сборки](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44962254649). [Публикация](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44962900166) связывает архив с digest манифеста и конфигурации.

1. В [конфигурации kind](../../infra/kind.yaml) найдите `etcd.local.imageRepository` и `imageTag`. Для ревизии `6abe6c7` kubeadm собирает ссылку на `ghcr.io/abrakadabra124/trusted-mlsecops-platform/etcd` с digest `sha256:1d1803f6520e4a8f35a3ee71972cd3d38b205eeb041d9340f500877ce3a06ebe`. Config ID работающего контейнера должен быть `sha256:b58a5d62eedb953d96c32200fcfafd40928b7514b40a32667c1f2fc4d8265976`.
2. Запустите два workflow из корня checkout командами ниже. Сохраните обе ссылки и проверьте поле `headSha` каждого запуска. Для сравнения результаты должны относиться к одному коммиту.

   ```sh
   gh workflow run kubernetes-trust.yml --ref qualify/r1-adopt-patched-etcd
   gh workflow run runtime-image-audit.yml --ref qualify/r1-adopt-patched-etcd
   gh run view <RUN_ID> --json headSha,status,conclusion,url
   ```

3. В шаге проверки etcd сверьте поле образа в спецификации готового Pod, RepoDigest и config ID из containerd. Ответ TLS endpoint должен подтвердить версию 3.6.17 и избранного лидера. При отказе проверьте доступ к GHCR без учётных данных и соответствие манифеста платформе Linux AMD64. Для воспроизведения перехода со штатной версии и отката используется отдельная [исходная конфигурация](../../infra/kind-etcd-3.6.17-baseline.yaml).
4. В полном отчёте найдите компонент по `observed_reference`, сверьте `runtime_image_id`, 154 строки описи и семь координат в `etcd_patched_supplemental`. Сверьте находки с `original_result` этого компонента. При неполной описи или отсутствии квитанции оставьте результат неопределённым и разберите расхождение по версии, пути и сборщику пакетов. Оцените остальные образы отдельно. При общем `fail` выпуск остаётся закрытым.
5. Убедитесь, что в журнале аудита есть `runtime_audit_cluster_absent=pass` и завершены шаги остановки сервисов. Прочитайте итог очистки и во втором workflow. Неподтверждённая очистка требует проверки журналов соответствующего одноразового запуска.

## Сравнение двух версий CoreDNS

В двух полных аудитах совпали схема Grype и время сборки базы. SHA-256 файлов `6/vulnerability.db` различался. Для проверки влияния обновления один hosted job просканировал оба закреплённых образа, смонтировав один каталог базы только для чтения. Проверены хеши файлов до и после каждого скана. SHA-256 файла базы в парном запуске составил `aaceea30e7446b2a365d171916ef3fbcaf719e194e0062c97c9ce2b4f0ccdfd8`. [Парный прогон](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44960164029), [код проверки](../../scripts/image_coredns_pair.py).

| Версия CoreDNS | Пакеты | Critical | High | Medium | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1.14.7 | 198 | 3 | 24 | 7 | 1 |
| 1.15.0 | 202 | 0 | 2 | 3 | 1 |

В старом образе воспроизвелись три совпадения по двум advisory, `GO-2026-6604` и `GO-2026-6612`. Новый бинарник собран Go 1.27.3 с `golang.org/x/net v0.60.0`. Оставшиеся High в новом образе относятся к `golang.org/x/net` и `github.com/klauspost/compress`. Чтобы повторить измерение, перезапустить парный workflow на проверенном коммите, сверить два config ID, хеши базы, исходные результаты и поле `target_criticals_removed`. Даже при успешном подтверждении устранения этих Critical результат скана нового образа остаётся `fail`. [Проверка DNS в работающем кластере](../runbooks.md), [полный аудит](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44959047516).

## Проверка замены etcd в одноразовом кластере

Проверку выполняет `etcd-candidate.yml` на GitHub-hosted runner. Workflow дважды собирает кандидат, сверяет SHA-256 трёх бинарных файлов и сканирует исходный и обновлённый образы на одной базе. Затем кластер стартует со штатным etcd. Проверка записывает контрольный ConfigMap и сохраняет его UID. [Workflow](../../.github/workflows/etcd-candidate.yml), [сценарий переключения](../../scripts/etcd_candidate_adoption.py).

На одноразовый узел загружается именно образ, config ID которого прочитан из отчёта Grype. Исходный манифест Pod сохраняется целиком. Подмена манифеста включает `imagePullPolicy: Never`, чтобы kubelet использовал локальный образ. Перед записью второго ConfigMap сценарий проверяет идентификатор работающего контейнера, его config ID, версию etcd и идентификаторы участника и лидера. После возврата исходного манифеста перечитываются оба ConfigMap с их первоначальными UID.

При отказе определить фазу по отметке `baseline`, `candidate` или `rollback` в журнале. На стадии загрузки сравнить config ID сканера и containerd, на стадии готовности проверить ответ TLS endpoint, на стадии чтения сопоставить UID и содержимое объекта. Сценарий помещает исходный манифест обратно даже при ошибке переключения. В конце отдельно проверить шаг удаления принадлежащего запуску кластера и узла. [Сравнение образов и исходный аудит](../evidence/etcd-inventory-2026-11-22.md).

## etcd 3.6.17 и локальные замены модулей Go

Если Syft показывает `UNKNOWN` у внутренних зависимостей etcd, сначала сверить digest запущенного образа Linux AMD64 и его конфигурации. Для образа `3.6.17-0` они начинаются с `3ced7fbd` и `be2dd319`. Полные значения и проверяемые материалы записаны в [реестре etcd](../../scripts/image_etcd_inventory.py). [Проверка работающего endpoint](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44957210068).

1. Сохранить исходные отчёты Syft и Grype в каталоге запуска. Сверить исходный config, дистрибутив и все 154 строки описи, включая пути и число вхождений. Из 148 записей Go в трёх бинарных файлах 13 ссылаются на локальные замены модулей. Остальные шесть записей принадлежат пакетам Debian. [Фикстура полной описи](../../scripts/image_etcd_inventory_fixture.py).
2. Для каждой замены сверить путь бинарного файла, SHA-256 релизного файла и ревизию исходников. Для пяти различных модулей запустить дополнительные проверки версии `v3.6.17` в той же базе Grype. Сохранить их отчёты и проверить принадлежность каждого отчёта нужному пакету. [Материалы upstream](https://github.com/etcd-io/etcd/tree/0689586e360e2c6b46f95ad5634c25d5fa1683db), [проверка привязки и объединение](../../scripts/image_kubernetes_scans.py).
3. Запускать `runtime-image-audit.yml` на проверяемом коммите в одноразовом hosted CI. При несовпадении описи или отсутствии одной из пяти квитанций оставить проверку открытой и сохранить причину отказа. При успешном объединении сверить исходные находки с `etcd_supplemental.original_result`. Записи `Unknown` для advisory по `golang.org/x/crypto` остаются в отчёте независимо от версий внутренних модулей. При отсутствии High и Critical такие записи сохраняют статус `inconclusive`. [Исходный полный аудит](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44954907094), [workflow](../../.github/workflows/runtime-image-audit.yml).

## Cilium Agent 1.20.5 и версии основных модулей Go

### Результат полного аудита Cilium

На чистом коммите `4fd80f09d7906adbac2f545c2ed8eb04c4799983` аудит сверил 947 записей агента, включая 823 Go-модуля и 124 пакета Debian. Четыре исполняемых файла соответствуют трём дополнительным координатам. На общей базе Grype каждый из трёх сканов дал ноль совпадений. Сохранились все 215 исходных находок, из них 206 Medium, 7 Low и 2 Negligible. Причина `image_audit_cilium_agent_application_provenance_incomplete` остаётся в результате компонента. [Первичный отчёт и очистка](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45022150263/attempts/1).

Чтобы повторить аудит на том же коммите, выполните следующую команду на машине с авторизованным GitHub CLI. Работа с кластером выполняется на одноразовом GitHub-hosted runner.

```shell
gh run rerun 45022150263 --repo Abrakadabra124/trusted-mlsecops-platform
```

В новой попытке найдите компонент по `observed_reference` и его раздел `cilium_agent_go_supplemental`. Сверьте версии всех трёх модулей, исходный список находок и итоговое покрытие. В первой попытке SHA-256 файла базы был `08b302c006875468fc087630ba33be9d814a2585047ddc874c8cd7a8bfab0d1b`. При обновлении базы результаты сканирования могут измениться. Первичный и опубликованный JSON первой попытки совпали после канонизации, SHA-256 `f0cb7116008c85d54aeef737713bfda2bad32325676bbbbe3ec80f81cc930d13`. Вывод `runtime_audit_cluster_absent=pass` подтвердил удаление стенда после общего отказа.

### Проверка встроенного Envoy

Два исполняемых файла взяты из Linux AMD64 манифеста `quay.io/cilium/cilium-envoy@sha256:32d2f9dd9981d92b11c8a37abac32f1c9397b3601af17b45b9403ad2bccc7dab`. У файлов в исходном и конечном образах совпали SHA-256. Для `/usr/bin/cilium-envoy` это `2d738902309dc2dd28753ee28a2c80d9dbdb99e2448ad0407bbdcff77cf885f2`, для `/usr/bin/cilium-envoy-starter` это `ebf97e60a561d2355c2b6c60e58711d9d879941ad934bdcd11c3a1a59c1f2244`. [Рецепт образа агента](https://github.com/cilium/cilium/blob/150121410c147fad575ac5dcbce6de923be69042/images/cilium/Dockerfile).

При разборе описи оператор сверяет предмет аттестации и отношения между файлами и пакетами. В SPDX образа-источника записаны 220 пакетов и ноль файлов. В SPDX агента есть оба пути, однако контрольные суммы SHA-1 указаны нулями и связи с компонентами отсутствуют. Запись BuildKit относится к нужной сборке и помечает список разрешённых зависимостей как неполный. Эти материалы позволяют проследить перенос файлов, но для проверки встроенных библиотек нужны фактические входы линковки обеих целей Bazel, привязанные к байтам этих файлов. Пока их нет, опись приложений агента остаётся неполной. [SPDX образа-источника](https://quay.io/v2/cilium/cilium-envoy/blobs/sha256:a6f26318b5e1b04ccf4a27d67ad73712f635e7ffaceabb3ae6e7e1363172c569), [запуск upstream](https://github.com/cilium/proxy/actions/runs/43392197364), [закреплённые цели сборки](https://github.com/cilium/proxy/blob/dee711ff0e84b106edd0abcdd71961af1b870359/BUILD).

В полном аудите у `runtime-005` совпали с содержимым слоёв все 947 строк Syft для `linux/amd64`. Из них 823 строки получены из метаданных Go в 13 бинарниках, ещё 124 относятся к установленным пакетам Debian в образе Ubuntu 26.04. Отдельный `/usr/bin/gops` совпал по SHA-256 с пересборкой `v0.3.29`. Зависимость `gops v0.3.28` в других бинарниках учитывается со своей версией. Для `/usr/sbin/iptables-wrapper` Go записал основной модуль как `(devel)`. [Полный аудит](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44959047516), [пересборка gops](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44953814982).

В попытке 1 пересборка wrapper из ревизии `bfef9e5087a198b50a4124bb9ce9d2c7c99025dd` дала те же байты, что и файл в образе. SHA-256 равен `3eb32c1812e6c31cfd92e323b7840c8f4ae3ee33f3844324b01577ddd743be72`, Go-версия модуля по этой ревизии равна `v0.0.0-20260420133543-bfef9e5087a1`. Оригинальная запись Syft сохраняет `UNKNOWN`. [Результат сравнения](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45020196030/attempts/1), [версия по ревизии](https://proxy.golang.org/github.com/kubernetes-sigs/iptables-wrappers/@v/bfef9e5087a198b50a4124bb9ce9d2c7c99025dd.info).

Для `/opt/cni/bin/cilium-cni` и `/usr/bin/hubble` исходная опись сохраняет `v1.20.5+dirty`. В попытке 1 запуска `45020758284` обе пересборки из дерева Cilium `150121410c147fad575ac5dcbce6de923be69042` побайтово совпали с полными файлами образа. В сборочном каталоге был один неотслеживаемый служебный файл для воспроизведения `vcs.modified=true`. Профиль `cilium-agent-go-supplemental` связывает четыре пути с тремя дополнительными Go-координатами. Перед выдачей координат реестр проверяет точный reference, config и все 947 строк вместе с путями, версиями и кратностью. [Сравнение cilium-cni](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45020758284/job/137202903438), [сравнение Hubble](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45020758284/job/137202903680).

В пяти проверенных слоях обнаружены пять самостоятельных ELF-файлов linux/amd64 без Go buildinfo и без владельца в 124 установленных пакетах dpkg. У всех пяти SHA-256 совпал с файлом из указанного исходного манифеста.

| Файлы в rootfs | Происхождение |
| --- | --- |
| `/usr/bin/cilium-envoy`, `/usr/bin/cilium-envoy-starter` | Release-стадия копирует их из [cilium-envoy v1.39.6, linux/amd64](https://quay.io/v2/cilium/cilium-envoy/manifests/sha256:32d2f9dd9981d92b11c8a37abac32f1c9397b3601af17b45b9403ad2bccc7dab). |
| `/usr/local/bin/clang`, `/usr/local/bin/llc` | Базовый cilium-runtime копирует их из [cilium-llvm 19.1.7, linux/amd64](https://quay.io/v2/cilium/cilium-llvm/manifests/sha256:db0f2fb57ec816d65a3fa34d69507c6df69595217361377ff854714ecab851d5). |
| `/usr/local/bin/bpftool` | Базовый cilium-runtime копирует его из [cilium-bpftool 7.8.1, linux/amd64](https://quay.io/v2/cilium/cilium-bpftool/manifests/sha256:427a210be922aecbb5162810ef04296b399bb981cca954bbece60b5057e60641). |

Происхождение этих байтов проверено. В текущей описи отсутствуют связанные с этими файлами компоненты и результаты их сканирования. Пока для них нет такого покрытия, агент остаётся `inconclusive` с причиной `image_audit_cilium_agent_application_provenance_incomplete`. Исходные находки сохраняются. Три shell-скрипта установки и удаления CNI в корне образа отдельно совпадают по байтам с файлами из дерева Cilium. [Рецепт агента](https://github.com/cilium/cilium/blob/150121410c147fad575ac5dcbce6de923be69042/images/cilium/Dockerfile), [рецепт runtime](https://github.com/cilium/cilium/blob/150121410c147fad575ac5dcbce6de923be69042/images/runtime/Dockerfile).

## Cilium Operator сообщает UNKNOWN для главного модуля gops

В образе оператора 1.20.5 для Linux AMD64 есть два файла, использующих `github.com/google/gops`. В `/usr/bin/cilium-operator-generic` метаданные компилятора указывают зависимость `v0.3.28`. В отдельном `/usr/bin/gops` основной модуль записан как `(devel)`. Для второго файла рецепт Cilium указывает `v0.3.29`. [Рецепт Cilium](https://github.com/cilium/cilium/blob/150121410c147fad575ac5dcbce6de923be69042/images/runtime/build-gops.sh), [стадии сборки образа](https://github.com/cilium/cilium/blob/150121410c147fad575ac5dcbce6de923be69042/images/operator/Dockerfile).

1. При обновлении образа сначала сверить SHA-256 архива Helm с индексом и проверить закреплённые digest обоих образов по официальному выпуску. Для 1.20.5 архив имеет SHA-256 `0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21`. [Индекс Helm](https://helm.cilium.io/index.yaml), [выпуск Cilium](https://github.com/cilium/cilium/releases/tag/v1.20.5).
2. Перейти от digest индекса оператора к манифесту `linux/amd64`, проверить config и слои. В этом манифесте файл `/usr/bin/gops` занимает 3 858 594 байта, SHA-256 `80cf2af7f90f1b5f6b515021fea1188a109200febae33b8ebe4b006347a95e3a`. При чтении архива учесть замены и удаления в последующих слоях. [Манифест платформы](https://quay.io/v2/cilium/operator-generic/manifests/sha256:3362404f43b6a01cf6e370fb637dac427b7b0259ff2629faa9e5b665121a3a76).
3. Для воспроизведения на отдельном GitHub-hosted runner выполнить `gh run rerun 44953814982`. Проверка берёт архив коммита upstream, сверяет его SHA-256, проверяет Go-модули и собирает файл штатным Go 1.26.11. Сравнить конечный SHA-256 с файлом из слоя. В первом запуске они совпали. [Исходный коммит](https://github.com/google/gops/tree/a2d8f7790eac63a6668583a060cb45903410a91b), [воспроизводимая сборка](../../.github/workflows/cilium-gops-rebuild.yml), [результат](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44953814982).
4. При несовпадении файла, состава пакетов или платформы оставить прикладное покрытие открытым. Для полного аудита сохранить исходный отчёт и проверить дополнительную координату только для отдельного файла на той же базе Grype. Отказ по Critical/High и неопределённость по Unknown сохраняются. Для возврата предыдущей версии в новой disposable среде использовать прежнюю проверенную ревизию конфигурации.

## Проверка etcd 3.6.17 в новом control plane

1. Сверить `imageTag` в [конфигурации kind](../../infra/kind.yaml) с digest кандидата `sha256:3ced7fbdc4cadcec31ab34a7513bc97be2b70db923e7154e2d88a980016b5e8b`. Кластер для этой проверки создаётся заново на одноразовом Ubuntu runner. Обновление работающего кластера и перенос его базы требуют отдельной проверки.
2. Выполнить штатную проверку `kubernetes-trust.yml` на той же ревизии, что и аудит. После установки должны работать Kubernetes API, закрытые базы модели и доверия, изолированные читатели и отзыв доступа. Проверить фактический итог и завершение удаления кластера. На `2a4eaef` прошли 79 проверок. [Проверка совместимости](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44954910234).
3. В полном отчёте отыскать **работающий** образ по `observed_reference` и сравнить его `image_config_id` с `sha256:be2dd319600bac16f542b8e46e1b78511c35a31e46829ee9acc82a83c94aa377`. Сверить три строки `golang.org/x/net` на путях `etcd`, `etcdctl`, `etcdutl`, затем исходные findings и состояние прикладного покрытия. После замены исходного образа отдельная строка `etcd-xnet-candidate` исчезает, а знаменатель проверки остаётся равным числу фактически работающих образов. [Первоначальное сравнение кандидата](../evidence/image-etcd-xnet-candidate-2026-11-20.md).
4. При расхождении digest, состава пакетов или сетевого поведения сохранить отказ и сверить журналы этапов. Воспроизвести предыдущую закреплённую ревизию с чистым кластером. Эта процедура не открывает существующий том etcd более старой версией.

Если GitHub выводит `Failed to download archive` на шаге `Set up job`, проверить в списке шагов, успела ли начаться установка кластера. В [попытке 44954661430](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44954661430) runner трижды получил тайм-аут загрузки закреплённого `setup-uv`. Код проекта ещё не исполнялся. Повторить проверку на новом runner с тем же digest action, затем проверить отдельно прикладной результат и очистку.

## Переход PostgreSQL 18.6 на 18.7 для новых экземпляров

Сравнение в [рабочей ветке](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44908733387/attempts/1) и [на базе main](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44909280914/attempts/1) показало 38 High у исходного хранилища и 0 Critical, High и Unknown у кандидата. В обоих запусках 435 проверок восстановления прошли и все 1000 эталонных прогнозов совпали. Изменились шесть APK семейства PostgreSQL и два пакета ICU, всего в образе 60 пакетов. [Версия PostgreSQL](https://www.postgresql.org/docs/18/release-18-7.html), [закреплённый рецепт Wolfi](https://github.com/wolfi-dev/os/blob/b286a29311dda92ad20559a390f9166d53eead88/postgresql-18.yaml).

Из [коммита публикации](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/8106d7a8cdeac72e723e5830fe585c9d184b9924) штатное задание [44909881813](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44909881813/attempts/1) заново проверило сборку и восстановление и опубликовало образ. При анонимном чтении из реестра совпали SHA-256 байтов manifest и config. Config подтверждает `linux/amd64`, `999:999`, команду `postgres`, `PG_VERSION=18.7`, ревизию и рецепт.

- Образ для загрузки по digest: `ghcr.io/abrakadabra124/trusted-mlsecops-platform-postgres@sha256:812316838ba6ffc54e65f5f764fc2c7946110267f02c9b8c1eeeceadf89ad094`.
- Config ID: `sha256:ca9b762fe51266ba97e2c8844dc39a1cdb99c3928e2af5626e4117780e358c69`.
- SHA-256 Dockerfile: `15d90bd5c78f68948cf0bb2e2861619128b0c68047e4356721abb4384b783bc2`.

Для нового экземпляра проверять `server_version_num=180007` и `data_checksums=on` в обеих базах Kubernetes и в отдельном экземпляре Docker. Сначала сверить реестр и SQL, затем выполнить восстановление и получить контрольные прогнозы. При несовпадении версии, контрольных сумм или данных остановить переключение. Исходный том сохранить.

Старые состояния и подписанные копии привязаны к digest версии 18.6. Для их проверки использовать прежнюю ревизию и соответствующую ей политику. Переход между версиями измерен логическим восстановлением в новый том. Открывать том 18.7 старым сервером или редактировать манифест резервной копии недопустимо.

## Сборка останавливается до обучения или сканирования

В [сквозном запуске 44908166197](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44908166197) на `d564325` установка из `uv.lock` прошла. Затем `pip-audit --strict` нашёл CVE-2026-126360 в `opentelemetry-api 1.45.1` и указал исправление 1.45.2. Обучение и восстановление в этой попытке не выполнялись.

1. Для ошибки аудита Python найти пакет и исправленную версию в строке `pip-audit`. Обновить только затронутые зависимости штатным `uv lock`. Сверить хеши файлов дистрибутива и актуализировать вход `uv.lock` в `data.lock` через генератор проекта. Повторить генерацию синтетического источника и сравнить хеш и размер выходных данных. Изменение исходных строк требует отдельного разбора.
2. Для ошибки покрытия образов посмотреть имя модуля в `coverage report`. На той же ревизии прежний локальный набор давал 91% после добавления проверки экспортированных слоёв Kubernetes. В набор входят также `scripts.image_kubernetes_integration_qualification` и `scripts.image_kubernetes_export_qualification`. Выполнить команды из первого шага [проверки образов](../../.github/workflows/image-audit.yml), включая отдельный порог для ветвей.
3. В публичном запуске сверить `headSha`, затем проверить каждый этап отдельно. Для обновления PostgreSQL нужны реальное восстановление с исходной версии на кандидат, совпадение 1000 прогнозов и сравнение обоих образов по одной базе сканера. Действующий образ устанавливается по отдельному проверенному digest. Отказ по старому образу и результат кандидата сохраняются оба.

## Ноябрьский отказ после неполного переноса исправлений

Повтор после интеграции: [43622958669](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43622958669/job/132532474071)
на `1a0f5d53cada44bb264a58b22f5cece018824d58` полностью завершился `success`.
Worker прошёл 74 compatibility checks, отдельный storage target 435 проверок,
включая 1 000 golden predictions; restore-to-golden составил 4,894914 с.
Все пять exact images прошли scan с 0 Critical/High/Unknown, подтверждёнными SBOM
и package bindings. Остаточные Medium/Low совпали с результатами описанного ниже
первого scan. SHA-256 канонического отчёта повторно вычислен из журнала:
`9a916352fb72a8e214b9612edc89b72e782e892cdc1e2ce4bd8f9e6bf7cb76c5`.
Это закрывает compatibility/restore/scan данного состава на этой ревизии.
Покрытие остальных девяти runtime images и общий B02/M18 остаются открытыми.

В [43560835791](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43560835791)
обновлённый PostgreSQL проходил audit, а worker и candidate Dockerfile сохраняли
уязвимые пакеты. Перенос одного storage digest не обновляет остальные образы.
В исправлении `b4fa42e` перенесён ранее проверенный состав APK: glibc 2.44-r17,
libexpat1 2.10.0-r0, py3-pip-wheel 26.2.2-r2 и worker Python 3.12.16-r3.
Host Python остаётся 3.12.15; совместимость этого сочетания проверяется отдельно.

[Свежий audit 43622143656](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43622143656/job/132529968042)
подтвердил по 0 Critical, High и Unknown для worker, storage, tracking и двух
candidate images. Scanner, SBOM и привязка пакетов к образам проверены во всех
пяти случаях; detection controls прошли. Worker и worker-candidate сохраняют
2 Medium/1 Low, tracking 1 Medium/1 Low. Канонический hash отчёта:
`a3a2b10364fcad3513958c3533696b0c7c6dc742b6fc1cccdbd03d3554d35154`.
Порог High, обработка Unknown и запрет исключений не изменены.

Весь workflow завершился `failure`: совместимость worker остановилась на
`qualification_failed:acceptance-dispatch-M02`, signed storage restore был
пропущен. Сам этот журнал не устанавливает более глубокую причину M02.
Исправленные рецепты соединены с явным обновлением source lock в основной
рабочей ветке. Успешный повтор после соединения описан выше; первый отказ
сохраняется как история проверки. Полный runtime inventory включает
14 образов; этот отчёт покрывает только пять и не закрывает B02/M18.

Порядок проверки: сверить все три Dockerfile и tracking recipe с закреплённым
составом пакетов, запустить `python -m scripts.image_candidates_qualification`,
затем workflow `image-audit.yml` на чистой опубликованной ревизии. Проверить
отдельно compatibility, signed restore и audit, source revision и digest каждого
образа. Успешный scanner при пропущенном restore не разрешает adoption.

Ответственные: platform operator и security reviewer. Процедура относится к scanner evidence лаборатории, не к production-инциденту. Рабочие SQL volumes, runtime tags и foundation не меняются.

## CP2: Brotli в закреплённых Wolfi images

Продолжение после описанного ниже первоначального исправления: [publication/adoption 2026-10-28](../evidence/cp2-runtime-adoption-2026-10-28.md). PostgreSQL опубликован workflow `40755338187`, manifest/config прочитаны анонимно, shared pin обновлён для fresh states. Tracking также переведён на Wolfi/MLflow 3.17.2. Component audit `40758097499` success: 0 Critical/High/Unknown во всех пяти images; worker/tracking сохраняют 6 Medium/1 Negligible. Отдельные ограничения runtime/system coverage и модели остаются. Старые failures ниже сохраняют историю, а не описывают новый image как всё ещё непубликованный.

2026-10-28, native `22371d8`, [40750705961](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40750705961): worker и storage получили по 3 Critical matches CVE-2026-111497 для `libbrotlicommon1`, `libbrotlidec1`, `libbrotlienc1` версии `1.2.0-r6`; GHSA alias дал ещё 3 Unknown matches. Это находки установленного пакета, не проверка достижимости уязвимого кода и не шесть независимых CVEs. Политика сохраняет refusal.

Источники проверены 2026-10-28: [Wolfi recipe](https://github.com/wolfi-dev/os/blob/main/brotli.yaml) содержит upstream `1.2.1`, epoch `2`; [advisory](https://github.com/advisories/GHSA-9v8h-qqgm-4m35) описывает Brotli decoder issue. Публичный [APK index x86_64](https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz) содержит все три `1.2.1-r2`; SHA-256 полученного архива `56c90c1fd9740197d6c47e035361ed60073e5907133b62713e219897b4dba64f`. Чтение index не заменяет проверку подписи APK при native build и повторный scanner result.

Исправление ограничено девятью pins: основной worker и отдельные worker/storage candidate recipes переходят на `1.2.1-r2`. Остальные packages, base digests, Python lock, модель и thresholds сохраняются. Опубликованный storage digest и действующие volumes пока не меняются: новый storage image сначала должен пройти signed restore, 1 000 golden predictions, package audit и отдельную публикацию с immutable readback.

Плейбук: запустить существующий `image-audit.yml` на точном feature ref в disposable hosted CI; проверить builds, worker compatibility, signed storage restore, все пять components и severity counts. Успех только трёх исправленных images не закрывает baseline storage, tracking и runtime system coverage. Не добавлять scanner ignores. При неуспехе сборки сохранить старый pin как исторический artifact без разрешения release; установить package/ABI/source причину и повторить новый run. Rollback working database не нужен, поскольку rehearsal использует отдельный target. Native результат нового pin фиксируется в STATUS; до него исправление не считается подтверждённым.

Предыдущий Brotli playbook проверен в [40753468138](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40753468138), `edc6862`: 74 worker / 435 storage checks, 1 000 golden predictions/error 0.0, основной worker и оба candidates без Critical/High/Unknown. Storage comparison удалил все шесть прежних advisory/package pairs, новых нет. Общий workflow failure сохранён из-за baseline storage и tracking. Следующий этап - отдельная guarded publication нового storage artifact и adoption по pinned digest; эти действия данным run не выполнены. Повторный общий image audit после adoption обязателен.

## CP2: состав системного приложения

### Go detection controls

Для system target без утверждённого application profile сначала проверить `package_binding_validated`, `diagnostic_only`, `scan_executed` и `reason`. После исправления раннего отказа из-за libc6/unknown distro scanner получает все непустые bound inventories; результат остаётся диагностическим. `sbom_validated=false` и coverage profile `unapproved-system` запрещают включение в approved coverage. Нет High/Critical - inconclusive, есть High/Critical - fail. Чужой config/distro, изменённый SBOM/DB, незнакомый package ID в finding, ignored matches или alerts не допускаются даже для diagnostic path. При отказе binding расследовать причину; не вырезать проблемный package или findings из отчёта.

Observed audit дополнительно сканирует два известных уязвимых package URL: `pkg:golang/golang.org/x/net@v0.16.0` и `pkg:golang/stdlib@go1.20.9`. Оба относятся к [GO-2023-2102 / CVE-2023-39325](https://pkg.go.dev/vuln/GO-2023-2102). Здесь исполняется только scanner, уязвимый код не запускается и атака не воспроизводится. Цель - проверить обнаружение Go modules и standard library в текущей базе, а не эксплуатируемость конкретного сервиса.

В summary обязательны `go_detection_controls.module` и `.stdlib`: точные package/version, статус, exit code 2, digest первичного ответа и ожидаемый advisory High/Critical. Grype pin, offline network и read-only snapshot DB совпадают с audit images. Другой advisory, тип пакета, версия, отсутствие detection, suppressed matches, alerts, другой DB build или изменение DB bytes вызывают отказ. Python/Wolfi controls остаются обязательными; положительный Go control не разрешает неизвестный application profile.

При `image_audit_go_detection_control_failed` сначала сверить head SHA/run ID, оба control observations и свежесть общей DB. При `image_audit_go_database_changed` проверить, что один snapshot использован во всех вызовах. Не менять известную уязвимую версию, severity или список допустимых aliases ради зелёного run. Если native matcher возвращает другой формат, сохранить ограниченный ответ и сопоставить его с официальным advisory; исправление contract требует RED/GREEN и повторного isolated CI. Raw scanner output остаётся в ignored state; действующие SQL/cluster не изменяются этой диагностикой. Контроль не доказывает полноту SBOM и не устраняет найденные CVE.

Проверенный native пример: [40765727216](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40765727216), `f12476c`. Module вернул High `GHSA-4374-p667-p6c8`, stdlib High `GO-2023-2102`, оба exit 2; оба controls pass. Общий audit остаётся fail из-за отдельных system findings и coverage 4/14. Это ожидаемое разделение исправности scanner и безопасности проверяемых images.

Native [40761233745](../evidence/cp2-system-images-2026-10-28.md) сохранил состав 13/14 targets; один дал `image_audit_package_observation_invalid`. Установлен отдельный parser defect: [optional поля Syft LinuxRelease](https://github.com/anchore/syft/blob/v1.54.1/syft/format/syftjson/model/linux_release.go) ошибочно считались обязательными даже для diagnostic observation. Controlled RED/GREEN проверяет отсутствие id/versionID; теперь они сохраняются как null, неверный тип по-прежнему отвергается. Native run 40763471155 на d3c54a2 подтвердил 14/14 observations: состав Cilium operator с тем же config 1fb303f6... сохранён, неизвестный distro не разрешает покрытие; при повторном отказе сохранить конкретный stage, не объявлять app coverage успешным и не подставлять Debian по предположению.

Для system targets с `image_audit_required_packages_missing` или неподдержанным distro сначала читать `package_observation`, `observed_reference`, `local_alias` и `host_roles` в summary. Observation сохраняется до отказа coverage и связан с фактическим config digest; alias служит только указателем на containerd bytes, не доверенным release identity. Сверить имя/версию/тип/cataloguer и путь исполняемого приложения, отдельно его Go `stdlib` и dependencies. Отсутствие `libc6` у минимального образа само по себе не доказывает отсутствие пакетов. Нельзя объявлять образ scratch по пустому distro или разрешать его по наличию любого одного Go module. Новый application profile требует конкретного native inventory и отрицательной проверки отсутствующего/неверного приложения. Unknown versions и неполное покрытие сохраняют отказ.

## CP2: отсутствующий образ tracking

**Симптом:** прежний успешный worker/storage audit не содержит MLflow, хотя tracking service использует отдельный образ. Причина установлена по списку targets: в нём было только два runtime components. Это пробел покрытия CP2/R1-B02, а не подтверждённая эксплуатация уязвимости.

**Исправление:** policy v2 требует tracking в обычном audit и при candidate comparison. Before-scan identity проверяет recipe digest и non-root USER; после scan проверяются неизменность materials, package coverage и тот же DB snapshot. Оба workflow, вызывающие audit, предварительно строят tracking image. Storage publication verifier принимает только новый полный scope; старый четырёхкомпонентный report не подходит.

**Диагностика без запуска services:** открыть sanitized summary `.runtime/evidence/image-audit.json`, сверить policy ID, наличие `tracking`, `recipe_digest`, `scan_executed`, `status` и `reason`. Сопоставить recipe с `images/tracking/Dockerfile`, lock и server/probe sources. Не публиковать raw Docker inspect: он может содержать environment. Пользоваться выбранными полями summary.

**Плейбук на разрешённом disposable runner:**

```text
uv sync --locked --python 3.12.15
uv run --locked python -m scripts.image_suite_qualification
uv run --locked python -m unittest scripts.storage_publication_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m scripts.tracking_spike build
uv run --locked python -m scripts.image_audit
uv run --locked python -m scripts.image_audit_publication
```

Команды build/scan изменяют cache/images и создают evidence, но не запускают приложение MLflow и не переключают рабочие БД. Ожидаемый корректный результат включает три runtime components. Код 1 означает findings, 2 означает неполную проверку; оба запрещают трактовать общий audit как pass. Publisher выводит данные, а не переопределяет результат предыдущей команды. Для `--compare-candidates` сначала нужны отдельные candidate builds и compatibility checks из существующего image-audit workflow.

- `image_audit_tracking_materials_mismatch`: сохранить отчёт, сверить checkout и recipe, пересобрать tracking из тех же locked материалов. Не переписывать Docker labels вручную.
- Missing image: выполнить предусмотренную сборку, не заменять локальный tag случайным образом из registry.
- Missing package, crash, Unknown или stale DB: устранить причину неполного покрытия; пустой findings не является доказательством безопасности.
- High/Critical в tracking: сохранить advisory/package/version, исправить соответствующий dependency/base image и проверить затронутый service. Успешное сравнение worker/storage не снимает этот отказ.
- Sources изменились во время scan: текущий результат inconclusive, нужен один новый scan после фиксации материалов. Не смешивать SBOM предыдущего build с новым image.

**Проверка исправления:** 166 controlled audit cases и 9 publication methods прошли локально; в том числе tracking failure/missing image при успешном comparison. Реальный новый hosted scan ещё требуется. Full controller/system inventory и R1 не приняты. При отказе не менять рабочие volumes или уничтожать source artifacts; сохранить исходный checkout/report, исправить причину и повторить на чистом runner. Возврат к v1 не является допустимым способом получить новый pass.

## CP2: подготовка storage artifact к scoped adoption

[ADR 0050](../decisions/0050-runtime-image-adoption.md) ограничивает изменение новыми R1 states, без переключения рабочих SQL volumes. Это следующий обязательный шаг R1-B02, не новый необязательный scope.

Read-only перед запуском: проверить commit на `main`, [workflow](../../.github/workflows/storage-artifact.yml), pinned recipes, отсутствие секретов в Docker context и результаты candidate qualification. Изменяющее действие только на disposable hosted runner:

```text
gh workflow run storage-artifact.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
```

Workflow повторяет actual compatibility/restore и fresh audit. Publication gate отвергает чужие/неполные/старше двух часов reports, dirty source, несовпадающие image/recipe identities, неправильную policy и blocking findings. Оба candidate gates обязательны. Baseline failures сохраняются в полном comparison: разрешение подготовить storage artifact не является разрешением выпускать R1. Только после этих проверок job получает registry login, публикует проверенный image ID под уникальным commit/run/attempt tag, читает manifest и выполняет pull-by-digest/readback. Tokens не выводятся, PAT не нужен; login удаляется в always step.

Отказы и действия:

- `storage_publication_dispatch_invalid` / `storage_publication_dirty_source`: не запускать локально и не менять guard. Нужен ручной запуск из правильного `main` checkout.
- `storage_publication_evidence_invalid`: сопоставить scopes, timestamps, source revision/fingerprint, identities, controls и severity. Не редактировать reports ради публикации; исправить причину и повторить затронутый pipeline.
- Push denied: проверить связь package с этим repository, job permission `packages:write` и OCI source label. Не выдавать token полные account/admin scopes.
- Manifest/config/readback mismatch или сетевой сбой после push: статус inconclusive; artifact может существовать. Не удалять его автоматически и не принимать tag как identity. Проверить конкретный manifest/config и ownership.
- `public_access_verified=false` в успешной публикации ожидаем: authenticated readback не доказывает anonymous доступ. GHCR новый package по умолчанию private. Перед baseline adoption подтвердить public visibility и anonymous manifest/config readback; не добавлять PAT в bootstrap.

Встреченный preflight defect `6127048`: GitHub отклонил dispatch с HTTP 422 до создания run, потому что `runner.temp` недоступен в job-level `env`. Actionlint 1.7.12 воспроизвёл тот же expression error. Исправление: создать приватный registry-config directory внутри шага через `$RUNNER_TEMP` и передать путь последующим шагам через `$GITHUB_ENV`, после проверки candidates и до login. Ни runner job, ни push не произошли в неудачной попытке dispatch. Локальный actionlint проверяет Actions expressions/YAML; shellcheck/pyflakes в этой диагностике не выполняются, Python проверяется Ruff и unit suite.

Rollback до adoption: baseline не меняется, runtime rollback не требуется. Остановить дальнейшее принятие, сохранить отказ и digest для расследования. Старые рабочие states/volumes, private keys и единственная копия backup не удаляются. Package publication, anonymous access и новое baseline runtime acceptance отмечаются отдельно в STATUS; unit contracts не заменяют эти три native результата.

### Подключение опубликованного artifact

Native publication `bbc20b4` и отдельный anonymous manifest/config readback подтверждены в [ADR 0050](../decisions/0050-runtime-image-adoption.md#проверенная-публикация). Новый root worker recipe совпадает с проверенным candidate, storage и tracking используют один registry manifest pin. Не путать manifest digest `dbd9ead...` с local config ID `f407b8a...`.

Только disposable hosted CI, из clean `main`, после targeted contracts:

```text
gh workflow run runtime.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
gh workflow run storage.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
gh workflow run kubernetes.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
gh workflow run tracking.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
gh workflow run image-audit.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref main
```

Ожидается anonymous pull без login, native bootstrap/qualification, сохранение TLS/roles и idempotency, restore-to-new-target, оба audit controls и отсутствие Critical/High/Unknown. Отдельно проверить actual image/config IDs в конечных containers. Failure не исправлять повторным неизменённым запуском: сопоставить step/reason с [R1 blockers](../r1-delivery.md). Старый известный `serving_output_rejected` не является автоматически image regression; требует своего разбора R1-B04/B08. Частичный зелёный набор не закрывает CP2.

Если старый state отвергнут после обновления pin, это ожидаемая защита. Сохранить checkout, marker, исходный volume и signed backups; не переписывать marker и не выполнять bootstrap поверх старой истории. Rollback/migration границы заданы ADR 0050. Для tracking helper USER и policy mismatch использовать [tracking runbook](tracking-troubleshooting.md#cp2-переход-на-non-root-postgresql-image).

Встреченный `91aa1b7`: developer/tracking/image workflows success, Kubernetes signed migration failure с общей причиной `kubernetes_request_failed`. Storage bootstrap и Kubernetes training/evaluation прошли; это не доказательство успешной миграции. Прежняя диагностика скрывала даже вид операции. Исправленный wrapper публикует только фиксированные operation/category: `container_pending`, `timeout`, `not_found`, `forbidden`, `connection_refused` или `unknown`; private stderr, arguments, names и SQL не публикуются. Категория является диагностической подсказкой, не доказанной причиной и не разрешением игнорировать failure.

При `logs:container_pending` сначала исследовать status/termination reason собственного pod и его Job, а не считать пустые logs успешной проверкой. При `delete:timeout` проверить ownership и конечное существование Job/pods, не делать global cleanup. При `get:not_found` сопоставить lifecycle/TTL; `forbidden` требует проверки выбранной identity, не admin bypass. Transport timeout/refused требует отдельной проверки API availability. При `unknown` сохранить закрытое evidence и добавить точечную диагностику, не вывести raw stderr. Нельзя молча увеличить deadline, отключить NetworkPolicy/TLS или объявить случайный следующий pass исправлением причины.

### Отсутствующая зависимость egress probe

`f9054fc`, [run 39482741891](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39482741891): повторный отказ `exec:unknown`. Единственный `kubectl exec` через этот wrapper в migration/storage qualification запускает Bash TCP redirection. В принятом PostgreSQL image 56 APK нет Bash; [обычная конфигурация Wolfi BusyBox](https://github.com/wolfi-dev/os/blob/main/busybox/busyboxconfig) также не предоставляет Bash или nc. Это зависимость executable проверки, не доказанный отказ NetworkPolicy или SQL migration.

Исправление ограничено R1-B02: pinned `bash=5.3-r14`, `coreutils=9.12-r4`, `libacl1=2.4.0-r4`, `libattr1=2.6.0-r4` в candidate. Полный closure увеличивается с 56 до 60, остальные pins и PostgreSQL 18.6 сохраняются. Это сознательный trade-off дополнительного runtime инструментария ради проверки из настоящего PostgreSQL container: не подменяем его другим pod, не добавляем privileged debug container и не выдаём host namespace права. Дополнительные packages обязаны пройти тот же audit до adoption. Новый candidate не меняет текущий registry reference автоматически.

Self-review исключил использование SIGKILL 137 как доказательства timeout: этот код может означать внешнее завершение/OOM. [GNU timeout](https://www.gnu.org/software/coreutils/manual/html_node/timeout-invocation.html) различает deadline 124, missing command 127 и SIGKILL 137. Поэтому build проверяет настоящий GNU timeout 9.12 и bounded sleep с exit 124. Native probe сначала открывает TCP `127.0.0.1:5432` в том же non-root PostgreSQL container, затем требует exit 124 и минимум 3 секунды для запрещённого DNS TCP. Прежний положительный контроль доступности того же DNS endpoint из разрешённой роли сохраняется. Открытая сеть, missing tool, раннее завершение, 137/143 и лишний stdout не проходят.

Последовательность: targeted contracts -> storage-artifact workflow с fresh audit/restore -> anonymous manifest/config readback -> новый immutable pin -> Kubernetes/storage/tracking regression. Эти три consumers используют общий PostgreSQL pin; GNU coreutils меняет также bootstrap utilities. Полная CI-матрица для этого исправления не требуется. До нового digest не запускать Kubernetes с прежним image и не считать unit success native fix. Если build/audit не проходит, сохранить fail/inconclusive и не отключать package-count/severity checks. Старый image и история отказов остаются доступны для rollback/диагностики; рабочие volumes не переключаются.

## CP2: новый Wolfi candidate не собрался или не прошёл audit

Причина изменения: повторные High/Critical findings прежних Debian candidates, не отказ работающей БД. [Новые recipes и источники](../image-candidates.md#cp2-wolfi-candidates-2026-10-20) требуют проверки для каждого нового image ID. Эта процедура не разрешает adoption.

1. Read-only: зафиксировать commit, stage, candidate recipe digest, image ID и `scan_executed`. Проверить pinned base/пакеты в Dockerfile, актуальный APK index, build/worker/restore/audit reports. Отсутствующий report не считать pass.
2. Ошибка package resolver: проверить доступность ровно заданных версий и signed repository metadata. Не заменять pin на `latest`, не использовать `--allow-untrusted`, не игнорировать ошибку загрузки. Изменение pin требует нового source review, build и qualification.
3. `image_audit_binding_or_coverage_invalid` / `image_audit_wolfi_package_coverage_invalid`: сравнить Syft и Grype distro/version/image IDs, наличие APK catalogue и обязательных Python/OS packages. Не удалять package database и не подменять distro вручную. Новый дистрибутив допускается только явным проверенным profile, а не wildcard.
4. `image_audit_wolfi_detection_control_failed` / `image_audit_wolfi_database_changed`: проверить свежесть и идентичность DB, exit code и detection известного уязвимого APK. До исправления причины candidate scan не считается надёжным, даже если список findings пуст. Не отключать control.
5. Worker или restore failure: сохранить конкретный отказ, не переключать baseline. Проверить Python/ONNX versions, PostgreSQL 18.6, UID 999, client binaries, TLS, signed backup и golden readback. Формат или model thresholds не менять для обхода compatibility failure.
6. После исправления проверить целиком changed image integration на disposable hosted CI: build -> actual training/inference -> signed restore в новый storage -> positive controls -> четыре scan на одной DB -> сохранение evidence. Общий audit может законно остаться fail из-за baseline; это не разрешение на adoption candidate.

Rollback: вернуть только candidate recipe/checker правку, не трогая рабочие volumes и tags. До принятия runtime необходимо зафиксировать весь установленный APK dependency closure из `apk_packages`, повторить compatibility/security проверки и выполнить предусмотренную миграцию. Локальная инфраструктура запрещена; без установленной причины не запускать неизменённую CI-матрицу повторно.

## Симптом и проверенная причина

### CP2: bootstrap наследует non-root USER image

[Run 39470747740](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39470747740), commit `e511f4f`: оба Wolfi images собраны, worker compatibility 74 cases pass; storage остановился с `storage_docker_failed:run`, audit не выполнялся. Исходный код не задавал пользователя для helper, подготавливающего новый volume. Wolfi recipe задаёт `USER 999:999`, а fresh volume требует root для подготовки ownership. Контракт воспроизвёл отсутствие explicit root; связь именно с native отказом требует нового integration run, поскольку старый report не сохранял этап.

Исправление ограничено helper: `--user 0:0`, `--network none`, read-only rootfs, `--cap-drop ALL`, только `CHOWN`, `no-new-privileges`, существующие resource limits и `--rm`. `initdb` и сервер остаются `999:999` без добавленных capabilities. Helper работает только с новым scoped volume, не с рабочей БД. Ошибки теперь различают `storage_docker_failed:volume_prepare` и `storage_docker_failed:initdb`, без вывода аргументов, сертификатов, stdout/stderr.

Read-only диагностика: проверить exact image ID, recipe USER, этап отказа и bootstrap command contracts. При `volume_prepare` проверить explicit UID и доступность shell/tar/chown; при `initdb` проверить user, client/server binaries и locale. Не лечить отказ `privileged`, снятием read-only или отключением TLS. До изменения причины не повторять тот же run. После исправления нужны полный signed restore/readback и ownership validation на disposable runner; controlled contracts не заменяют native recovery.

Image audit теперь выполняется после успешной сборки candidates даже при отказе compatibility, чтобы получить независимое evidence о packages. В workflow нет `continue-on-error`: compatibility failure сохраняет общий failure, scan pass не разрешает adoption. При build failure scan не запускается. Откат этой правки меняет только bootstrap harness/CI; действующие images и volumes не переключаются.

Native подтверждение: [run 39472427689](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39472427689), `2bb1afc`, 435 recovery checks pass, 1 000 golden rows/max error 0.0. Включены fresh target, signed backup, ownership/ACL/TLS, source/target collation и удаление собственных ресурсов. Storage ошибка устранена без ослабления runtime; это не полный M17.

### CP2: контрольная CVE имеет не ту severity

В том же run Grype DB и PyPI control прошли, все четыре SBOM прошли binding/inventory, но APK control отказал до image scans. Исходный контроль `libxml2@2.11.5-r0` требовал High для `CVE-2023-45322`, хотя [официальный advisory](https://github.com/advisories/GHSA-vqpg-m25j-7558) содержит Medium (6.5). Отсутствие image counts не трактовать как ноль findings.

Диагностика воспроизведена отдельно metadata-only PURL scan, без установки уязвимого APK и без локального контейнера/SQL service: Grype 0.120.1, тот же DB SHA256 `5bee2b8f39940a9eb07ae25eae384ae8b33fd334c9970f9f896f5941603ddbfc`; старый control дал точный match Medium и exit 0. Замена на Wolfi `openssl@3.0.7-r0` дала `CVE-2023-0286` High и exit 2; Wolfi advisory фиксирует исправление в `3.1.0-r0`. Версия бинарника проверена, официальный Windows archive SHA256 `32e3c811f31822d17592908bafdc6288aaaca3d52583c479167a8dc8399ed65d` сверён с GitHub release metadata и checksums. Это диагностический replay, не hosted acceptance образов.

Исправлен только контрольный пример, а не policy: High/Critical остаются блокирующими. Checker отвергает Medium, неправильные package/version/type/advisory/distro и exit 0. `wolfi_control_observation` сохраняет exit code, distro, выбранные ID/severity и digest исходного control report до проверки, в том числе при отказе. При новом отказе оператор сначала сравнивает эти поля с pinned profile и источником advisory; произвольный match, отсутствие данных или один exit 2 не достаточны. Отключать control, подменять distro образов либо добавлять scanner exceptions нельзя. После исправления необходим новый image audit на disposable hosted runner.

[Run 39474325096](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39474325096), `61b8e6b`, подтвердил исправление: оба controls pass, четыре scans выполнены, два Wolfi candidates pass при неизменной High policy. Baseline findings оставили весь workflow в failure. Для следующей сборки pinned полный APK closure из этого run. Если resolver или package-count guard отказывает, сначала сверить exact pins и новый inventory; не менять expected count и не снимать версии только ради зелёной сборки. Новая зависимость требует объяснения, обновления closure и повторных compatibility/security проверок. Полный список versions внутри каждого Dockerfile связан с уже существующим recipe digest, дополнительного неподписанного lock input нет.

Проверка конечного состояния с полной фиксацией packages: [run 39475658299](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39475658299), `0de97b6`, builds/count guards success, exact APK inventories 34/56 сохранены, actual worker 74 / storage 435 checks pass, оба candidate package gates pass. Общий workflow по-прежнему failure по baseline, не новый отказ control/restore. Дальше требуется отдельное принятие новых runtime references и полный image scope, а не повтор того же scan до случайного зелёного статуса. [Exact bindings и ограничения](../image-candidates.md#проверка-полностью-закреплённых-recipes).

В run `38151770889`, job `114506519932`, обычный `gh run view --log` через GitHub CLI 2.98.0 не показал итоговые JSON-строки audit и publication. Прямой job-log API сохранил обе строки длиной 188 989 байт с timestamp; сам canonical report занимает 188 960 байт и содержит 1 119 finding records. Отсутствие результата в одном viewer не означает отсутствие audit или нулевые findings. Это сравнение двух способов чтения логов, не доказательство конкретного внутреннего дефекта GitHub CLI.

Исправление: [publisher](../../scripts/image_audit_publication.py) выводит тот же JSON с переносами и отступами. Каждый символ данных сохраняется, JSON после parsing равен исходному; status, severity, findings и counts не переопределяются. Ограничения: 16 MiB canonical input и 16 KiB на строку, oversized/nonfinite input отклоняется целиком, не обрезается. Управляющие символы экранируются. Для сохранённого отчёта проверены 13 830 строк, максимум 110 байт/строка, все 1 119 findings сохранены.

Это formatter для уже очищенного image-audit summary, **не redactor для произвольного SBOM/raw log**. Не передавать ему приватные документы или model/data/keys. Исходный canonical JSON на диске не изменяется, формат остаётся обычным JSON, не NDJSON.

## Read-only диагностика

```text
gh run view 38151770889 --json status,conclusion,jobs
uv run --locked python -m scripts.image_audit_publication
```

Вторая команда читает локальный `.runtime/evidence/image-audit.json`, не CI report автоматически и не запускает scanner. Сверить его source revision, run ID, timestamps, image/config IDs, DB digest и `scan_executed` перед выводами о текущем состоянии.

Exit 0 publisher означает только успешную публикацию: внутри JSON может оставаться `status=fail`. Сам audit сохраняет exit 1 для findings, exit 2 для incomplete. Missing/invalid/oversized evidence даёт inconclusive и exit 2 publisher, без раскрытия содержимого ошибочного файла. Успешный шаг publication не разрешает выпуск после failed audit.

Если старый viewer теряет длинные строки, получить исходный job log **только в ignored файл**, не выводить terminal escape sequences на экран и не исполнять содержимое лога:

```text
gh api repos/Abrakadabra124/trusted-mlsecops-platform/actions/jobs/114506519932/logs --allow-escape-sequences > .runtime/image-audit-job.log
```

Команда проверена с gh 2.98.0. Флаг разрешает сохранение содержащих управляющие символы bytes в файл, а не отключает TLS/auth. Raw log не добавлять в Git. Для нового run сначала получить его job ID, не переносить исторические counts на текущий image.

## CP2: security patch Cilium 1.20.4

Основание: [официальный выпуск 1.20.4 от 2026-10-23](https://github.com/cilium/cilium/releases/tag/v1.20.4) устраняет CVE-2026-111943 обновлением Go до 1.26.10 и обновляет зависимости. Прежний pin 1.20.2 не включает этот security patch. Это устранение установленной зависимости, не утверждение, что все scanner findings или CP2 закрыты.

Оператор CP2 проверил SHA-256 скачанного chart против [официального Helm index](https://helm.cilium.io/index.yaml): `505abff8385811df1a949776fc42e9f10697989a332acc86d6e8933efcb855ed`; Chart.yaml version/appVersion равны 1.20.4. Содержимое архива проверялось без извлечения и исполнения. В values.yaml включён `useDigest`: agent `sha256:20fe92e4c86641233a450098c158d2d29085f3419931ab6bf681d2485dedf16e`, operator-generic `sha256:7a7a3489dc66ad67e420d285c8a8d2e169b0957ad15e120f593d27081bf38d82`. Оба digest совпадают с release notes. HTTPS и сверка hash подтверждают совпадение источников; независимая проверка подписи chart не заявляется.

Изменение затрагивает только version/hash в [bootstrap](../../mlsecops/cluster.py). NetworkPolicy, resource limits, namespace identities и остальные версии сохраняются. Рабочий Windows runtime не обновлять. Проверка разрешена только в новом disposable hosted checkout:

```text
gh workflow run kubernetes.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref codex/cp2-system-inventory
gh workflow run runtime-image-audit.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref codex/cp2-system-inventory
```

Перед запуском убедиться, что remote SHA соответствует проверяемому commit; сохранить оба run ID. Первый workflow должен подтвердить два bootstrap, Jobs, SQL/TLS и isolation denials с positive controls. Второй должен наблюдать фактические agent/operator digest, проверить неизменность inventory и просканировать те же bytes. Не выдавать успешную установку chart за устранение всех CVE. Native regression 40762255437 на ced7ea0 прошла; observed audit 40763471155 сохранил все 14 observations и корректно отказал: coverage 4/14, системные findings остаются.

При несовпадении chart hash ожидается отказ bootstrap. Не заменять digest на значение из неожиданного ответа и не отключать TLS. При regression сохранить очищенную причину и остановить adoption. Для воспроизведения прежнего поведения использовать отдельный checkout предыдущего commit и новый disposable runner; не делать автоматический downgrade живого кластера. Удалять только созданный и проверенный owned cluster через cleanup workflow. Возврат к старой версии сохраняет её security blocker и запрещает утверждать готовность release.

## CP2: сверка фактических образов

Симптом при расширении scope: прежние три scans ничего не доказывали о реально загруженных system/controller images. Исправление: read-only inventory, manifest/config reconciliation, дополнительное сканирование и повторный inventory после него. Controlled проверки воспроизводят ошибочные ownership, config/distro/source bindings, смену состава, отсутствующий image и неоднозначный digest. Реальный production-инцидент этим не заявляется.

Ответственный - оператор CP2. Prerequisites: чистая ветка с текущим кодом, доступ GitHub Actions и disposable hosted runner; запускать Docker/cluster этой процедурой на рабочей Windows запрещено. Для одного native прогона использовать workflow `Observed runtime image audit` на выбранном commit. Push в ветку `codex/cp2-runtime-image-audit` также запускает только этот workflow. Для ручного запуска после регистрации workflow в default branch:

```text
gh workflow run runtime-image-audit.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref codex/cp2-runtime-image-audit
gh run list --repo Abrakadabra124/trusted-mlsecops-platform --workflow runtime-image-audit.yml --branch codex/cp2-runtime-image-audit --limit 5
```

Команды требуют действующей CLI-авторизации; наличие подключения GitHub в Codex её не заменяет. Зафиксировать конкретный run ID/head SHA и наблюдать тот же run, не повторять запуск из-за timeout интерфейса. Не открывать PR только ради запуска: он запустит общую regression matrix.

Проверенный отказ публикации после переноса Windows: `create_tree` через connector дал 403 `Resource not accessible by integration`, хотя repository metadata показывала account push/admin permissions. Это разные полномочия: права пользователя не доказывают права конкретной интеграции. `gh auth status` также подтвердил отсутствие CLI-входа, браузер показал Sign in. Владелец восстанавливает обычный вход `gh auth login --hostname github.com --git-protocol https --web` либо разрешения подключения для этого репозитория. Не извлекать старые tokens из Windows credential store и не включать их в команды, Git или логи. После входа проверить account identity, затем обычный non-force push в выделенную ветку, remote head и конкретный workflow run. Пока write-операция не прошла, успешное чтение профиля не считать восстановленной публикацией.

Workflow выполняет bootstrap, build worker/tracking, cluster, private storage, scoped controllers, tracking service, затем `python -m scripts.image_audit --runtime-state .runtime`. Это интеграция существующих компонентов без migration рабочего volume. Expected summary: scope `observed-runtime-image-audit-only`, source revision текущего checkout, runtime_scope с expected/covered counts. `release_ready` всегда false.

Ветви диагностики:

Native `1a9a26d` поднял весь disposable lab, но collector вернул `required_tool_failed` до первого SBOM. Диагностический `eacf4f9` установил этап `pod-cri-identity`. Controlled RED воспроизвёл случай, когда Pod сообщает manifest digest, а CRI lookup принимает разрешённый image config ID. Исправление использует уже hash-checked config для `crictl inspecti`, сохраняя проверки returned ID, registry digest и экспортированных bytes. Native `c899f43` прошёл lookup, но ответ не удовлетворил `image_scope_cri_identity_invalid`; audit ещё не начался. Теперь причины разделены: `image_scope_cri_config_mismatch`, `image_scope_cri_references_invalid`, `image_scope_cri_references_missing`. Ни одна не разрешает пропуск образа. CRI (Container Runtime Interface) - интерфейс Kubernetes к container runtime; manifest digest и config digest обозначают разные объекты. Первичная реализация [containerd ImageStatus](https://github.com/containerd/containerd/blob/v2.1.3/internal/cri/server/images/image_status.go) формирует ID и RepoDigests отдельно; наличие config само по себе не доказывает наличие registry reference. Это справочный источник, не утверждение версии containerd в стенде.

- `image_scope_*` / `image_audit_runtime_*`: сверить ownership, controller profile, image IDs и stage failure. Registry manifest обязан указывать на наблюдённый config. Не заменять reference на `latest` и не исключать проблемный Pod из inventory.
- [40749336227](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40749336227), `c8e2f23`, установил `image_scope_cri_references_missing`: config совпал, но RepoDigests пуст. Исправление сохраняет hash-checked config и bounded CRI repoTag только как локальный указатель для экспорта. `ctr images export --local --platform linux/amd64 - <alias>` читает фактический containerd image в private archive; [upstream export](https://github.com/containerd/containerd/blob/v2.1.3/cmd/ctr/commands/images/export.go) описывает совместимый manifest.json. `--local` исключает transfer progress из бинарного stdout. Перед Syft проверяются архивный config digest, OS/architecture/layers/labels; смена alias на другие bytes блокируется. Timeout 300 s, archive limit 4 GiB, stderr limit 2 MiB. Экспорт не выполняет pull, load, tag либо замену runtime. Отсутствие и tags, malformed identity либо изменившийся snapshot по-прежнему запрещают pass. Native результат исправления фиксируется в STATUS отдельно от controlled tests.
- `image_audit_runtime_changed`: сохранить refusal; выяснить, менялся ли lab во время scan. После исправления причины допустим новый отдельный run. Старый snapshot не переписывать.
- Если CRI сообщает RepoDigest, это ещё не доказывает возможность скачивания через registry: предзагруженный image может иметь только локальную историю. При наличии validated repoTag теперь также используется containerd export с проверкой manifest -> config -> archive. Если локального alias нет, прежний digest-only registry путь сохраняет refusal при недоступности. Native `22371d8` впервые завершил before/after inventory (14 images, 4 fully covered) и выявил отдельные scanner findings; новая ветка экспорта для RepoDigest ещё требует native подтверждения.
- Подтверждение исправления: [40752836255](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40752836255), `4012505`, получил все 14 config/archive bindings без `required_tool_failed`, before/after inventory совпал. Шесть Debian targets не удовлетворяют текущему required-packages profile; Ubuntu и нераспознанный distro не поддержаны; два system applications остаются unapproved. Не переводить эти 10 targets в pass из-за успешного экспорта. Полное покрытие 4/14, audit fail из-за findings, все owned cleanup steps success.
- `image_audit_runtime_application_coverage_unapproved` или `image_audit_runtime_distro_unsupported`: OS/package coverage недостаточно. По фактическому SBOM определить состав application binaries, поддерживаемые catalogers и обязательные packages; оформить профиль с отрицательными тестами. Не разрешать pass по одному наличию libc.
- High/Critical сохраняют fail даже при неполном application coverage. Unknown, scanner crash и недоступность digest сохраняют inconclusive. Успешная печать summary не означает успешный scan.

Recovery/rollback: job останавливает только проверенные tracking/host-storage containers и удаляет только кластер с подтверждённым ownership. Если bootstrap не успел сохранить marker, cleanup не угадывает владельца; остатки исчезнут с disposable VM. При несовпадении ownership оператор прекращает ручные удаления и фиксирует блокер. Вне этой VM нет deployment, следовательно rollback действующей платформы не нужен. Raw runtime snapshots, keys, Docker inspect и SQL credentials не загружать в публичные artifacts. Завершение CP2 требует native evidence и устранения coverage/findings blockers; текущие controlled tests это не заменяют.

## Решение по результату

1. `scan_executed=false`, invalid/stale DB, timeout или missing coverage: evidence неполно. Проверить доступность registry/DB, ownership процесса и его текущий handle. Не запускать новый audit только из-за timeout наблюдения и не менять severity threshold.
2. Полный scan с High/Critical: это security failure. Сверить package/version/advisory с vendor и фактическим image, зафиксировать доступный fixed version либо отсутствие подтверждённого fix. `wont-fix/no-dsa` не превращается в автоматическое исключение из политики проекта.
3. Новый кандидат строится и проверяется по [отдельному candidate flow](../image-candidates.md), затем [fresh-target restore](../storage-candidate.md) и same-DB audit. Не заменять image работающей БД и не монтировать её volume в candidate.
4. Не удалять package database ради уменьшения findings. Удаление действительно ненужных binaries требует проверки зависимостей, работоспособности и новой SBOM, а не одного меньшего числа CVEs.
5. Publisher не меняет deployment, поэтому runtime rollback не требуется. При ошибке форматирования сохранить canonical evidence, исправить formatter и повторить только publication; новый scan нужен при изменившихся/устаревших scanner inputs.

## Проверенная triage на 2026-10-11

Из raw report `d44d1fe`: baseline worker 0 Critical/56 High, baseline storage 11/118; worker candidate 0/55, storage candidate 3/88 и 1 Unknown. Все четыре scans fail. Это scanner matches, не четыре доказанные exploit paths и не общее количество уникальных уязвимостей.

- В локальных candidate images уже установлен glibc `2.41-12+deb13u4`. [Debian CVE-2026-5450](https://security-tracker.debian.org/tracker/CVE-2026-5450) указывает исправление для этой trixie-версии; повторная установка той же версии не устранит оставшиеся findings.
- Storage содержит libxml2 `2.12.7+dfsg+really2.9.14-2.1+deb13u3`. [Debian CVE-2026-6653](https://security-tracker.debian.org/tracker/CVE-2026-6653) отмечает её уязвимой; fixed package указан для forky/sid, не выбранной stable trixie. Суффикс `really2.9.14` важен, нельзя считать пакет исправленным по префиксу 2.12.7.
- [Debian CVE-2026-88647](https://security-tracker.debian.org/tracker/CVE-2026-88647) и [страница GnuTLS package](https://packages.debian.org/trixie/libgnutls30t64) подтверждают, что выбранный `3.8.9-3+deb13u4` не имеет объявленного fix для этого advisory. Upstream assessment ещё отмечен как ожидаемый; это не основание скрыть scanner Critical.
- Для [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619) fixed GCC 14 указан в sid, тогда как trixie `14.2.0-19` уязвим. Смешивать stable/unstable packages без отдельного совместимого runtime плана нельзя.
- Третий Critical storage match `CVE-2026-95210` относится к тому же GnuTLS. Повторный vendor fetch в этой итерации завершился timeout; подтверждено наличие finding в scanner report, но не новый vendor fix. Отсутствующий ответ не доказывает отсутствие исправления.

Изменение форматирования не устраняет эти уязвимости. Нужны поддерживаемые исправленные runtime inputs и повторная квалификация; M01/R1 остаются непринятыми. Новые пороги, scanner ignores, расходы и перенос работающей истории этой процедурой не разрешаются.

## Проверка восстановления наблюдаемости

Unit suite: large-report round trip, сохранение всех outcomes/полей, escaping, size limits, отсутствие изменения input, generic failure на malformed/missing evidence и module entrypoint. Native критерий: из обычного `gh run view --log` нового completed run извлечён полный publication JSON, его fields/counts/DB/images доступны, audit всё ещё failure при прежних findings. Unit success сам по себе этот CI-критерий не доказывает. Ссылки на завершённые runs фиксируются в STATUS.

Критерий подтверждён в [clean-checkout CI 38153385533](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38153385533) на `57cfee7`: direct audit JSON и опубликованный JSON получены обычным CLI и совпали после canonical normalization, digest `cd3ce2c2d9180ae059ce0dbb827c9e5102cbae16e3046e5ad8f13a420be2edc3`. Все 1 119 finding records сохранены, maximum line 115 bytes. Семь tests и 21/21 statements/6/6 branches publisher прошли; audit завершился fail из-за оставшихся High/Critical. Publication success не замаскировал failure.
