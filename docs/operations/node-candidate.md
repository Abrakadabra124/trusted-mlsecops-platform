# Изолированный Kubernetes node candidate

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
