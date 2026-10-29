# Постоянный serving worker в Kubernetes

Неделя 9, T15 «Inference API и loader», CP3. Реализован и проверен native явный Kubernetes backend для обычного `mlsecops.serving_http --config`. Это component pass, не full M12 или завершённый R1.

**Native component pass:** code `e068328`, [run 40806590954](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40806590954). Полный M12 inconclusive, release_ready=false. Предыдущие отказы и исправления сохранены ниже.

## Решение и границы

HTTP controller в `ml-serving` читает releases и текущую trust policy через раздельные SQL identities. `kubernetes_worker` в конфигурации содержит полный закреплённый image profile: `image`, `image_id`, `config_id`, `manifest_id`, `source_fingerprint`, `source_revision`. Его `image_id` должен совпадать с `expected_serving_image`. Поле явно выбирает backend; ошибка Kubernetes никогда не вызывает fallback к Docker.

Controller создаёт один Job в `ml-serve`. Worker запускает существующий `mlsecops.serving_worker`, один раз загружает проверенные ONNX bytes и отвечает по тому же протоколу session/model/request binding. После первого load повторные predictions используют тот же процесс. Pod не получает API token, SQL certificates, approval/signing keys или сетевые разрешения. Существующая deny-all policy, UID 65532, read-only root, cap-drop, RuntimeDefault seccomp, память 1 GiB и 1 CPU сохраняют границу execution.

`attach` проходит через Kubernetes API по TLS 1.3, с проверкой CA/hostname и `v5.channel.k8s.io`. Закреплена `websockets==17.3`; proxy, compression и redirects запрещены. Проверены [версии каналов Kubernetes 1.36.4](https://github.com/kubernetes/apimachinery/blob/v0.36.4/pkg/util/remotecommand/constants.go) и [реализация клиента websockets 17.3](https://github.com/python-websockets/websockets/blob/17.3/src/websockets/sync/client.py). Используется готовый WebSocket клиент, собственный код только маршрутизирует bounded stdin/stdout protocol. Это транспорт к уже работающему worker, не API для исполнения произвольных команд.

Транспорт работает отдельным дочерним процессом controller. Существующий `Channel` ограничивает полное время обмена, включая DNS, handshake и заблокированную запись. Вход разбит на 16 KiB chunks; ответ ограничен 64 KiB, очередь WebSocket ограничена двумя frames, stderr/status/лишние/noncanonical/misbound replies отклоняются. При потере транспорта controller закрывает readiness, останавливает собственный bridge и удаляет Job с UID precondition, подтверждая отсутствие Job и Pods. Неудачная очистка остаётся ошибкой.

RBAC разрешает serving только create/get/delete Jobs, get/list Pods и get/create pods/attach в `ml-serve`. `exec`, port-forward, secrets, service accounts, другие namespaces и изменения Role не выдаются. Admission фиксирует command, образ, stdio, security context, volumes и ресурсы. Жизнь Job ограничена 3600 s; перезапуск или новое activation требует актуальной проверки Reader и trust. Это lab lifetime, не доказательство непрерывного production обслуживания.

## Воспроизведение на разрешённом disposable CI

Workflow [.github/workflows/kubernetes-serving.yml](../.github/workflows/kubernetes-serving.yml) запускается на `codex/cp3-kubernetes-serving` или вручную. Он проверяет locked dependencies, targeted tests и branch coverage, создаёт owned cluster/storage/trust, проверяет actual-candidate refusal, затем отдельно controlled release через обычный serving CLI. Ожидаются 503 до approval, verified readiness и golden ONNX predictions после controlled promotion, один worker на повторных запросах, 401/413/422, 503 после удаления worker и после signed revocation, реальные admission/RBAC denials и подтверждённая очистка.

Native entrypoint: `uv run --locked python -m scripts.kube_serving_native --state .runtime`. Он разрешён только на disposable hosted runner. Из текущей Windows его не запускать. Подготовка serving API permissions выполняется оператором через `uv run --locked python -m mlsecops.controller_bootstrap --serving`; вызов проверяет ownership, digest profile и admission type warnings. Замена существующего profile требует отдельного `--replace-profile` и отсутствия активных Jobs в обоих serving namespaces.

Probe запускает настоящий `mlsecops.serving_http` отдельным процессом, с private token file и audit directory в RAM. Эти временные credentials/audit fixtures не являются persistent deployment, retention evidence или M17 backup. Actual candidate не получает искусственный all-pass assurance. Controlled approvals используются только для проверки соединения компонентов. Full M10-M19/M23, системные image findings, независимые M22 challenges и final same-candidate acceptance остаются обязательными.

Отдельная граница M13: Kubernetes CRI сохраняет stdout worker, включая typed prediction replies, model/session/request identifiers и request hash. В отличие от Docker `log-driver=none`, здесь это дополнительный приватный канал. Raw features по протоколу в stdout не выводятся, но scores/hashes нельзя автоматически считать безопасными для публикации. До полного M13 нужны наблюдение этого канала, canaries и явная retention policy. Native probe проверяет пустой вывод HTTP CLI, но не доказывает privacy всего CRI log pipeline.

## Runbook: 503 или незавершённая очистка

Разбор `ef3ce2f`: probe отправлял POST JSON без `Content-Type: application/json`. До approval запрос отклоняется по readiness раньше разбора body, поэтому проблема была скрыта. Новый регрессионный тест запускает approved ветку probe с настоящим `serving_http.read_body`; до исправления он воспроизвёл `kube_serving_probe:three-HTTP-predictions`, после добавления заголовка весь сценарий прошёл. Это исправление клиента, не ослабление API. Точные assertion codes добавлены в whitelist диагностики; произвольный exception text и canary credential остаются скрытыми. Native подтверждение выполняется отдельным запуском.

Первый native run [40802380904](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40802380904), code `e476a86`, остановлен до serving: `source_lock_mismatch_explicit_update_required`. Linux 92 adjacent/harness и 23 transport/runtime tests прошли; SQL stop и cluster deletion подтверждены. Причина: добавление `websockets` изменило `uv.lock`, но прежний data provenance ещё ссылался на старые bytes. До correction дважды заново сгенерированы source bytes и сверены с прежним output: 1 915 576 bytes / SHA-256 `1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473`. Из inputs изменился только `uv.lock`; явный lock update, fresh generation и verified cache проверены без инфраструктуры. CI сам lock не обновляет. Это исправление воспроизводимости не означает успеха пока не выполненного serving run.

Второй run [40802762678](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40802762678), `8e9b09e`, прошёл preparation, но native scenario завершился failure; обе cleanup steps success. Общего кода ошибки недостаточно для точной причинной атрибуции. Отдельным source inspection найден дефект harness: Uvicorn 0.54.0 повторно посылает себе SIGTERM после lifespan cleanup, поэтому только exit 0 не является верным контрактом остановки. Исправленная проверка допускает -SIGTERM лишь после собственного сигнала и wait, затем отдельно подтверждает отсутствие worker. Native harness добавляет bounded stage labels и whitelist причины отказа; private logs не публикуются. Требуется повтор на новом commit.

Третий run [40803347878](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40803347878), `7837ed5`: Linux 93 adjacent/harness + 23 core tests pass; native дошёл до `controlled-before-approval` и завершился unclassified refusal, cleanup success. Это не pass serving. Подготовлена диагностика с whitelist stage/error categories. Также отдельно воспроизведено расхождение JSON API: Kubernetes `TTY bool` имеет `omitempty`, поэтому false отсутствует в readback. Regression сначала отверг корректный Pod, затем прошёл после исправления: default false допускается, true по-прежнему запрещён и admission, и runtime. Связь этого дефекта с предыдущим native failure пока не доказана.

Run [40804120526](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40804120526), `4b1d300`: 93+24 Linux tests pass; native отказ до approval, `kube_serving_service_exit`, cleanup success. Разбор startup выявил отсутствующий audit directory: `audit_retention.Spool` требует существующую приватную директорию и не создаёт её автоматически. Test launcher теперь создаёт её с mode 0700 до CLI. Регрессионный тест сначала упал на `audit directory must preexist`, после correction прошёл; ownership/retention guards не ослаблены. Probe audit остаётся временным RAM fixture, не production storage.

Ответственный - оператор owned lab. Сначала read-only: подтвердить revision/image profile, последнюю trust policy, release head и UID/spec ресурсов в `.runtime/serving/resources.json`; проверить состояние Jobs/Pods в `ml-serving` и `ml-serve` через kubeconfig этого стенда. Не выводить token, SQL connection files, raw request/features или полный audit в публичный лог.

- До approval, после revocation и при неподтверждённом образе 503 является ожидаемым отказом. Не менять trust root, minimum sequence или пороги для обхода.
- Если CLI жив, но ready=false, проверить terminal status worker, imageID, admission reason, projected API token, CA/hostname и scoped `pods/attach` permissions. Не выдавать cluster-admin, не монтировать Docker socket и не снимать default-deny.
- При transport timeout readiness должна стать false. Старый bridge и worker не переиспользуются. Удалять только ресурс с проверенным workspace ownership и UID, затем подтвердить отсутствие и только после этого повторить activation с текущим разрешённым bundle.
- Если ответ на create потерян, runtime проверяет уникальное имя и исходный spec перед удалением. Другой UID/spec считается конфликтом. Не выполнять namespace-wide delete или global prune.
- При неизвестном состоянии очистки остановить новые activation и сохранить private diagnostics. В disposable CI финальная проверенная teardown всего owned cluster остаётся последним уровнем очистки, а не доказательством корректности локального shutdown.

Playbook восстановления: подтвердить отказ и прекратить новый трафик -> проверить ownership/UID -> восстановить доступный trust/API либо удалить свой зависший worker -> подтвердить отсутствие старых процессов/Pods -> запустить CLI с теми же pins -> проверить authenticated readiness, bundle/model digest и golden prediction. Если bundle отозван, требуется новый разрешённый release; cached/revoked fallback запрещён. Шаги runtime recovery до native проверки не заявляются выполненными.

## Native результат 2026-10-29 МСК

Commit `e068328bb6e054540781dce862e37083a246232e`, [run 40806590954](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40806590954), job `123226915016`, attempt 1: **success**. Период native scenario: 05:31:25.641 - 05:33:02.875 МСК. Source clean; fingerprint `4fbd05e54279c2ed788e49549108892b9bf06a33e80e06f94d78bc363d8700c9`; runtime image `sha256:e1aa758164d9babf15b63aee3cc3150d50ab7d86b13f03f0d105630af25e27a8`.

| Проверка | Наблюдаемый результат |
| --- | --- |
| Actual candidate / proposal | `edf2a4580640cc48b7657e513673665513bec0868072e8eea270f7f88df69662` / `2548824b42185dac47abc2b7e9ef5b81c2af03f9b197be63b4e13e3603254e35` |
| Actual model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`; parent и isolated promotion отказали без assurance, без изменения ledger |
| До controlled approval | 13 checks pass: ready/predict 503, worker не создан, реальные admission/RBAC denials, shutdown и отсутствие worker подтверждены |
| После controlled approval | 22 checks pass: ordinary CLI ready, один persistent worker, три HTTP запроса по три строки, same worker UID, model/bundle binding каждого ответа |
| Golden parity | Max absolute error `7.583384781240099e-08` при лимите `1e-6` |
| API и остановка worker | 401 без credentials, 422 malformed input, 413 oversized body, 503 после удаления собственного worker Job |
| После signed revocation | 13 checks pass: новая активация ready/predict 503 до запуска worker; запреты доступа и cleanup повторно подтверждены |
| Controlled model | `6e4e5e65497470e5fe72af895107f291245c1bfc70070378cf3cdf95d2058169`; отдельная fixture, не actual acceptance |
| Linux regression | 96 adjacent/harness + 24 core tests pass; core 201/202 statements и 61/62 branches, runtime module полностью покрыт |
| Очистка | Private service output пуст, audit directory создан; CLI termination/worker absence подтверждены. Owned source SQL stopped и cluster deletion/absence steps success |

48 probe checks включают повторения на трёх стадиях; это не 48 уникальных M-критериев. Actual-candidate refusal проверяется отдельно. Raw Job logs остаются private `.runtime/evidence`, не включены в Git. Полные M11/M12/M13/M14 не заявляются: требуются live revocation/outage, полная input/TOCTOU матрица, все output channels/retention, нагрузка и final same-candidate acceptance. Этот run не проверяет restart после pod/node failure, persistent audit restore или production HA. Next CP3 step - live trust lifecycle на этом normal configured runtime и объединение обязательных privacy/readiness доказательств.
