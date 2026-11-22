# Изолированный Kubernetes node candidate

## OpenSSL в штатном node 1.36.4

Если проверка сообщает об OCI-маркере `.wh..wh..opq`, сравните состав каталога до и после наложения слоя. Для трёх каталогов лицензий проверка читает оба слоя исходного образа, сверяет их распакованные SHA-256 и применяет изменения в порядке манифеста. Пустой обычный маркер допускается только при отсутствии унаследованных записей, проверенных атрибутах каталога и единственном итоговом файле `copyright` с байтами из подписанного пакета. Журнал `opacity_readback` содержит результат по каждому каталогу. Скрытие даже одного унаследованного файла приводит к отказу. Политика Critical, High и Unknown продолжает действовать после проверки слоя.

В полном аудите 45030124975 штатный linux/amd64 config `sha256:0fa975026f71246c4e4744409d43e2e5884bb6e960851b438e50f455808c16f4` содержит Debian 13.6. Grype сообщает CVE-2026-63073 и CVE-2026-75803 для каждого из трёх пакетов `openssl`, `libssl3t64` и `openssl-provider-legacy`. Установлена `3.5.6-1~deb13u2`, первая исправленная версия в отчёте `3.5.7-1~deb13u2`. В подписанном индексе trixie от 21 ноября проверены три amd64 архива `3.5.9-1~deb13u1`. [Исходный job](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45030124975/job/137231665394), [Debian DSA-6465-1](https://security-tracker.debian.org/tracker/DSA-6465-1), [закреплённый InRelease](https://snapshot.debian.org/archive/debian/20261122T000000Z/dists/trixie/InRelease).

Для отдельного hosted измерения владелец проверяет commit и отправляет его в точную ветку `qualify/r1-kind-1364-openssl`. Job с правом `contents: read` повторяет проверку подписей, индекса и архивов, устанавливает только эти три пакета без сети и читает SHA-256 семи ELF. Затем он сравнивает OCI runtime config, исходные слои, состав дополнительного слоя, все 878 строк Syft с путями и результаты Grype на одном снимке БД. В логе искать записи `source` и `candidate`, шесть исходных совпадений и остаток по двум CVE. При расхождении входов или описи измерение отклоняется. Даже при устранении шести совпадений статус `fail` или `inconclusive` у кандидата завершает job с ошибкой. Весь образ кандидата живёт на одноразовом runner. [Workflow](../../.github/workflows/kind-node-openssl.yml), [пины и сравнение](../../scripts/image_node_openssl.py), [рецепт](../../images/candidates/node-openssl/Dockerfile).

[Первое парное измерение 45032600503](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45032600503/job/137239252108) дало шесть целевых Critical у источника и ноль у кандидата. Оба получили `fail`. Сравнение описи остановилось на `node_package_delta_mismatch`. Syft увидел у каждого обновлённого пакета собственный файл `/usr/share/doc/<package>/copyright`. Во всех трёх подписанных DEB это обычный файл размером 2543 байта с SHA-256 `6a7da622fe0637a334d2a8fc470852d2ffb77d9a2b2f930f854e32a41ad6ef35`. Исправленная проверка требует точные файлы и в DEB, и в добавленном слое, сверяет весь состав и печатает количество и SHA-256 остальных строк. При расхождении лог содержит количество удалённых и добавленных строк и до восьми примеров с каждой стороны. В первом job полный состав остальных 875 строк кандидата в лог не выводился.

[Попытка 45033355400](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45033355400/job/137241579448) завершилась на записи `tmp` дополнительного слоя до вывода результатов пары. Тип, Unix mode, UID/GID и xattrs этой записи в job не зафиксированы. Для проверки такого случая скрипт читает оба исходных слоя в порядке применения и сверяет SHA-256 распакованных байтов всех трёх слоёв с `diff_ids`. Повторная запись существующего каталога допустима при совпадении типа, прав со специальными битами, владельца, группы и расширенных атрибутов. Временные метки выводятся отдельно. Правило не распространяется на файлы внутри каталога. Лог выдаёт результаты обоих сканов до проверки слоя, затем количество нарушений и до 24 записей с путями и типами. При любом нарушении узкая квалификация завершается отказом.

## Историческая проверка Kubernetes 1.36.6

Неделя 1 «Контекст и foundation», T02 «Foundation P0 и совместимые зависимости». Ответственный: platform operator. Область: разрешённый disposable GitHub-hosted CI. Локальные Docker/WSL/Kubernetes/SQL не запускаются. Build/audit candidate не является adoption или закрытием CP2/R1.

## Симптом и причина

[Observed audit 40767489025](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40767489025) впервые просканировал все 14 targets. Kind node и Kubernetes control-plane images содержат Critical/High matches. Текущий node pin использует Kubernetes 1.36.4 и прежнюю базу kind. [Kubernetes 1.36.6](https://github.com/kubernetes/kubernetes/releases/tag/v1.36.6) опубликован 28 октября, но manifest `kindest/node:v1.36.6` при проверке registry отсутствовал (404).

[Kind 0.33.0](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/pkg/cmd/kind/build/nodeimage/nodeimage.go) поддерживает `kind build node-image --type file` из локального server archive. Его [base pin](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/pkg/build/nodeimage/defaults.go) не обновлён и в проверенном upstream commit `2b29bebb68be838c81ed868cc4f21836c5b1c911`. Поэтому patch Kubernetes измеряется отдельно от оставшихся OS/container-runtime/CNI/etcd/CoreDNS проблем. Замена номера версии сама по себе их не исправляет.

## Закреплённые материалы и границы

[Builder](../../scripts/image_node_candidate.py) использует:

- server archive `v1.36.6`, SHA-256 `702d6529b5eb7bfb919dab3542cd420ccf316fca6aa7c506b69169bd12b26a7c`, сверенный с [официальным checksum](https://dl.k8s.io/release/v1.36.6/kubernetes-server-linux-amd64.tar.gz.sha256);
- kind `v0.33.0`, установленный [checksum-pinned installer](../../scripts/install_ci_tools.py);
- base `docker.io/kindest/base:v20260820-69b56db7@sha256:8098fa3cae05bc15d9c4b93a566d19e1f8e65a25e26ebeb993b6cb41142cf791`; registry response hash сверён, Linux/amd64 child manifest `sha256:49207c7d517ca84ea87c880d314e2ebf25ae7f5dc85f54238f543a8b6681970f`;
- baseline `kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed` и отдельный candidate tag `trusted-mlsecops:node-v1.36.6-candidate`.

Архив загружается потоково с лимитом 2 GiB в новый каталог. До сборки проверяются checksum, hosted Linux x86_64, чистый checkout, версия kind и свободное место. Existing path не перезаписывается. После сборки фиксируются image config IDs, source revision и hashes исходных материалов; перед и после audit binding читается заново. Чужой/изменившийся candidate или source запрещает результат.

Kind сам импортирует вспомогательные images по upstream tags. Их результирующие байты требуют отдельного runtime inventory перед adoption. Старый base сохраняет уязвимые OS/Go runtime components. Docker commit не даёт заявления о побайтно воспроизводимой сборке; checksum не заменяет независимую проверку identity издателя. Здесь измеряется только проверяемый patch candidate, полный foundation ещё не принят.

## Плейбук запуска и диагностики

1. Прочитать branch/head и проверить активные runs: `gh run list --workflow node-candidate.yml`. Не запускать повтор при уже работающем job. Для первого добавления workflow используется push в отдельную ветку `codex/cp2-node-candidate`; следующие запуски доступны через workflow_dispatch после регистрации GitHub.
2. На разрешённом hosted runner [workflow](../../.github/workflows/node-candidate.yml) устанавливает lock, выполняет negative contracts и pinned tool install. Builder отвергает локальную Windows и self-hosted runner до первого runtime command.
3. Выполнить `uv run --locked python -m scripts.image_node_candidate`. Это создаёт только отдельный образ, не изменяет `infra/kind.yaml`, не создаёт рабочий cluster и не публикует image в registry.
4. Собрать текущие worker/tracking для обязательных audit controls. Выполнить `uv run --locked python -m scripts.image_audit --compare-node-candidate`. Baseline/candidate сканируются теми же Syft/Grype и одним snapshot базы, с обязательными Go-module/stdlib detection controls. Diagnostic result не может разрешить application coverage.
5. Прочитать `gh run view <run-id>` и bounded summary. Сравнивать findings по package/advisory, фиксируя версии и config IDs. Нельзя объявлять удалённые совпадения устранением всех угроз или считать исчезновение неизвестного package доказательством полноты.
6. При checksum/source/config/DB mismatch остановить цепочку. При High/Critical оставить fail; при Unknown или неполном покрытии оставить inconclusive. Проверить конкретный refusal, не добавлять waiver и не изменять порог ради зелёного job.

Kind обычно удаляет собственный build container через deferred cleanup. При timeout/cancellation это не гарантируется: runner disposal является границей очистки данного эксперимента. На машине пользователя cleanup не выполняется; global prune/reset запрещены. Перед повтором убедиться, что предыдущий hosted job terminal. При неизвестном результате не публиковать или принимать образ.

## Проверка и дальнейший adoption

Controlled tests проверяют ограничения runner, dirty checkout, нехватку места, неверный kind, archive digest/size, build failure, source/image substitution и отказ выдавать coverage при чистом diagnostic scan. Проверены **201 audit cases, 12 observation/Go/diagnostic methods и 7 node candidate methods**; builder до CLI entrypoint имеет 66/70 covered statements, 23/24 branches. Это controlled результаты, они не заменяют native сборку. Native result записывается только после terminal CI; первая проверка этого нового пути ещё требуется.

Успешный build report имеет scope `node-candidate-build-only`, release_ready=false. Общий diagnostic audit закономерно остаётся fail/inconclusive при текущей старой базе и unapproved application profiles. Перед adoption нужны актуальная база, полный inventory встроенных runtime images, функциональные M01/M04/M05/M21 и security checks на тех же bytes. Новый immutable image публикуется и перепроверяется отдельно; только затем меняются node/kubectl pins и version guards согласованным commit. Rollback на этом этапе не нужен: текущий runtime pin не меняется.

## Native результат 2026-10-29 МСК

[40777426055](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40777426055), head `f8a15c45b4544036df4de65fa904198ed2c5d065`, job `123130219970`: **failure**, attempt 1. Builder завершился success, затем общий audit корректно отказал. Сборка 01:07:17-01:08:35 МСК; audit 01:09:01-01:12:34 МСК. Все пять inputs просканированы, detection/Wolfi/оба Go controls pass. Worker/storage/tracking имеют 0 Critical/High/Unknown.

| Измерение на одной DB | Baseline 1.36.4 | Candidate 1.36.6 |
|---|---:|---:|
| Catalogued packages | 878 | 878 |
| Critical matches | 67 | 61 |
| High matches | 394 | 349 |
| Unknown matches | 70 | 67 |
| Medium matches | 195 | 183 |

Baseline config `sha256:0fa975026f71246c4e4744409d43e2e5884bb6e960851b438e50f455808c16f4`; candidate config `sha256:801636e7c8a763aff10e5612c33d3c650e907a929a14fcf54fa564c8c8314105`; base config `sha256:816692b104dfc1ccc2bf183a2c61bf5d40c8fbc232dd5c71210f4d71f622061d`. Source materials digest `72f61cbf79b17d01b90d32bdaf46f424a5f8b473a309b492095869a98c1e854c` повторно проверен после audit.

Syft наблюдает `k8s.io/kubernetes v1.36.6` в `/usr/bin/kubeadm`, `/usr/bin/kubectl`, `/usr/bin/kubelet`. Go 1.26.5 этих binaries сменился на 1.26.10, но старые runtime binaries всё ещё содержат Go 1.26.7. Matches являются package/advisory совпадениями, не уникальными CVE. Версии x/net, x/crypto и gRPC в [upstream go.mod 1.36.6](https://github.com/kubernetes/kubernetes/blob/v1.36.6/go.mod) остались прежними; patch Kubernetes не устраняет весь dependency scope.

**Решение: candidate не принят и не опубликован как новый runtime artifact.** Измеренное уменьшение findings не разрешает adoption. Нужны remediation base/runtime и зависимостей, разбор Unknown, application profiles и функциональная проверка перед сменой pins. CI build container завершён штатным kind builder; cluster/SQL здесь не запускались. Артефакт жил на disposable runner, durable registry image этим run не создан.
