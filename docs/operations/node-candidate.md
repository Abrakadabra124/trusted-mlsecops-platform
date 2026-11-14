# Изолированный Kubernetes node candidate

Неделя 1 «Контекст и foundation», T02 «Foundation P0 и совместимые зависимости». Ответственный: platform operator. Область: разрешённый disposable GitHub-hosted CI. Локальные Docker/WSL/Kubernetes/SQL не запускаются. Build/audit candidate не является adoption или закрытием CP2/R1.

## Симптом и причина

[Observed audit 40767489025](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40767489025) впервые просканировал все 14 targets. Kind node и Kubernetes control-plane images содержат Critical/High matches. Текущий node pin использует Kubernetes 1.36.4 и прежнюю базу kind. [Kubernetes 1.36.6](https://github.com/kubernetes/kubernetes/releases/tag/v1.36.6) опубликован 28 октября, но manifest `kindest/node:v1.36.6` при проверке registry отсутствовал (404).

[Kind 0.33.0](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/pkg/cmd/kind/build/nodeimage/nodeimage.go) поддерживает `kind build node-image --type file` из локального server archive. Его [base pin](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/pkg/build/nodeimage/defaults.go) не обновлён и в проверенном upstream commit `2b29bebb68be838c81ed868cc4f21836c5b1c911`. Поэтому patch Kubernetes измеряется отдельно от оставшихся OS/container-runtime/CNI/etcd/CoreDNS проблем. Замена номера версии сама по себе их не исправляет.

## Закреплённые материалы и границы

### Проверка etcd и CoreDNS в ветке R1-B02

Для нового disposable кластера [конфигурация kind](../../infra/kind.yaml) передаёт kubeadm два linux/amd64 manifest digest из `registry.k8s.io`. На 14 ноября в серии Kubernetes 1.36 официальный kind публикует образы node 1.36.1 и 1.36.4. В kind v0.33.0 закреплён 1.36.4. Даже kubeadm 1.36.6 по умолчанию выбирает etcd 3.6.8-0. Для двух компонентов проверяются отдельные patch releases в действующих minor-сериях. [Релиз kind](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0), [таблица версий kubeadm](https://github.com/kubernetes/kubernetes/blob/v1.36.6/cmd/kubeadm/app/constants/constants.go).

| Компонент | Manifest linux/amd64 | Ожидаемый config SHA-256 |
| --- | --- | --- |
| etcd 3.6.16-0 | `00edecc7baeaf69c61708ed713d55a8c928d539f200298d8d67cbfed59db9c7e` | `a17708350060c02414f0ecd9a0afd44404df2e4ed8cc9726a3a9c5776b40645e` |
| CoreDNS v1.14.7 | `2329f5f0e7e79fbe56dcdf11ecc4337ee2476bb251095bc275fe9461cb88a55b` | `97efff2babf85310d6f87bd969ac64d7006bbbadb147c90579d68d57634750f4` |

В шаге reconcile [runtime-image-audit](../../.github/workflows/runtime-image-audit.yml) найти оба config ID среди фактических Pod images. Для CoreDNS эталон получен независимо от Syft чтением слоёв указанного manifest с проверкой SHA-256. Из `/coredns` взяты строки mod/dep встроенного Go build info и версия stdlib. Всего 194 записи Go, в том числе stdlib go1.26.6. Четыре Debian-пакета получены из полей Package/Version в `/var/lib/dpkg/status.d`. SHA-256 канонического JSON отсортированных троек type/name/version равен `9b512c14911df8ec933a65f4a6010b2dc14fb7c63ef5ec6d632f9999058dc862`. Для совпадения требуются этот config ID, полный состав, ожидаемые пути бинарника и базы dpkg, соответствующие catalogers, согласованная distro и успешные Go controls. Любое несовпадение состава сохраняет диагностический скан с его findings. Coverage проверяется отдельно от результата допуска образа.

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
