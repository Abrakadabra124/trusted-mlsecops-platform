# M13: диагностика приватного сбора Kubernetes logs

Текущий [CLI privacy increment](../evidence/kubernetes-cli-privacy-2026-11-06.md): `36cd71d` / 42225259346 success, 22 CLI + 28 actual checks, 222 Linux tests, coverage gate и cleanup подтверждены. Полный M13 остаётся inconclusive.

Предыдущий retained-packet increment: [bc8948c / 42218670322](../evidence/kubernetes-audit-retention-2026-11-06.md), 28 cases / 203 Linux tests, post-exit и post-cleanup primary recheck pass. Ниже сохранена история первого native component.

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [Native component 90385fa / 42215561469](../evidence/kubernetes-privacy-2026-11-06.md) pass: 26 checks, первичный audit повторно проверен на runner, terminal worker stream точный, два service log windows и cleanup подтверждены. Полная M13 acceptance ещё не завершена.

## Назначение и права

CRI (Container Runtime Interface) связывает Kubernetes с container runtime. Его журналы сохраняют stdout/stderr контейнера; настройка Docker `log-driver=none` другого backend не отключает эти журналы. Worker передаёт в stdout приватный протокол с scores и identifiers, поэтому raw CRI logs нельзя публиковать как обычный CI report.

[Collector](../../scripts/kube_privacy_logs.py) выполняется только внешним оператором разрешённого disposable GitHub-hosted стенда. Caller сначала проверяет ownership Job/StatefulSet и image contract. Collector повторно сверяет Pod UID, owner UID, container ID, image ID, spec, restart count и состояние до/после чтения. Serving-роль сохраняет прежние права на attach без `pods/log`; production config не получает observer или дополнительные credentials.

[Worker observer](../../scripts/kube_privacy_worker.py) предназначен только для qualification probe. Он оборачивает настоящий transport, фиксирует канонические ответы без request features и перед очисткой закрывает attach bridge. Затем оператор должен дождаться успешного завершения контейнера и прочитать его логи до удаления Pod. Base cleanup выполняется и при ошибке/прерывании наблюдателя. Прямой запуск collector на текущей локальной инфраструктуре запрещён ограничениями задачи.

## Проверяемая последовательность

1. Получить verified owned Pod и expected image из текущей campaign, не выбирать произвольный Pod по похожему имени.
2. Для worker сохранить в памяти точный поток фактически полученных ответов. Не конструировать ожидаемый лог из желаемых scores и не добавлять request features.
3. Закрыть attach bridge и проверить завершение процесса. Любой stderr делает наблюдение неуспешным; raw stderr не выводить в диагностику.
4. Оператор проверяет terminal worker и читает не более 1 MiB плюс один контрольный байт. Restart count должен быть строго целым нулём. Совпадение только хвоста, неполный stream, дополнительные строки и canary запрещают pass.
5. Подтвердить неизменность идентичности после чтения. Сохранить raw capture и приватную receipt только в owned private evidence; [runner](../../scripts/kube_privacy_native.py) публикует ограниченные числовые counters и source revision, без raw logs и private identifiers.
6. Выполнить обычный scoped cleanup, проверить отсутствие собственного Job/Pod. Даже успешное чтение logs без подтверждённой очистки не завершает campaign.

Для PostgreSQL/trust collector допускает снимок работающего контейнера. Такая receipt явно отмечена как window, а не полный lifecycle: она не доказывает отсутствие более поздних записей, проверку всех контейнеров или всего M13.

## Сквозной hosted playbook

[Workflow](../../.github/workflows/kubernetes-privacy.yml) устанавливает locked dependencies, строит pinned image и создаёт отдельный disposable cluster. Обычный preparation формирует новую actual proposal и проверяет production refusal без assurance. Candidate permit разрешает только qualification inference и не подменяет release approval.

[Probe](../../scripts/kube_privacy_probe.py) запускает настоящий HTTP app и отдельный Kubernetes ONNX worker. Он проверяет golden prediction, auth, независимые client quotas, input canaries, metrics, HTTP 429 под давлением и HTTP 503 после fencing. Parent-процесс наблюдает stdout/stderr child до полного завершения; native stderr запрещён.

[Operator](../../scripts/kube_privacy_operator.py) обрабатывает два подтверждаемых шага: terminal worker и закрытый audit packet. [Private exchange](../../scripts/kube_privacy_exchange.py) связывает запрос с campaign и ответ с digest запроса, ограничивает размер и время. Operator повторно проверяет первичный audit packet и соответствие HTTP ledger, затем читает owned PostgreSQL/trust windows. Ошибка даёт отрицательное подтверждение, после которого worker обязан пройти обычный cleanup. Serving RBAC не расширяется.

Весь Pod output должен быть ровно каноническим отчётом с одним переводом строки. Ошибки печатают только fixed phase/code. Private packets сохраняются в `.runtime/evidence/privacy/<campaign>` только на runner; workflow не экспортирует их из ephemeral host. По [ADR 0049](../decisions/0049-private-audit-evidence.md) срок хранения этого increment ограничен campaign и жизнью VM. Долговременное forensic хранилище требует отдельной спецификации и не является условием этой компонентной проверки.

[Новый путь сохранения проверен на bc8948c / 42218670322](../evidence/kubernetes-audit-retention-2026-11-06.md): `audit-evidence/packet.json` создаётся один раз существующим `audit_snapshot.store_packet`. Он проверяет owner/mode, запрещает symlink/hardlink и overwrite, выполняет fsync файла, каталога и его родителя. После terminal Pod оператор перечитывает пакет и сверяет первичные bytes с receipt. После удаления probe Job/ConfigMaps основной runner повторно загружает подписанную proposal из CAS, permit/public key из собственного campaign directory и тот же пакет. Проверяются signatures, campaign/source/image/subject, окно permit, HTTP outcomes и точная public projection. Два новых cases добавляются только после этих проверок; `release_ready` остаётся false.

При `audit_packet_unavailable`, `privacy_operator_retained_packet_changed` или `serving_output_packet_binding` не удалять существующий пакет и не перезаписывать receipt. Проверить fixed stage, завершение child и cleanup, а в приватном runner - наличие собственного campaign directory и соответствие source revision. Для повторения использовать новую campaign. Отсутствующий/повреждённый пакет означает отказ проверки; согласованные summary counters его не восстанавливают. Не запускать эту диагностику на локальных SQL/Kubernetes данной системы.

Запускать через Actions `Kubernetes private output and audit integration` на опубликованной ветке `codex/cp3-m13-privacy`. Проверить exact commit, все test/native steps и оба cleanup steps. Не обновлять ветку во время run: concurrency отменяет предыдущую campaign. При отказе читать только fixed stage в публичном журнале, исправлять подтверждённую причину и повторять affected campaign. Нельзя превращать failed/inconclusive в pass переносом старой receipt.

Первый run обнаружил недостаток диагностики: после `actual-candidate-bind-proposal` был только общий отказ. Добавлена [диагностика расположения кода](../../scripts/kube_privacy_diagnostic.py): фиксированный тип исключения, существующий source file и номер строки без текста исключения, локальных переменных и абсолютных путей. Повторный [run 42211782862](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42211782862) указал на отказ SQL subprocess; cleanup снова прошёл. Проверка shortened preparation обнаружила пропущенную миграцию promotion journal: snapshot требует таблицы, которые раньше создавал controlled release runner. Добавлен вызов существующей idempotent migration перед candidate qualification. Он создаёт пустой журнал и не записывает authority, approval или release; последующий native run подтвердил прохождение этого шага.

Отдельно при проверке кода исправлена передача PostgreSQL image в runtime verifier: ему нужен digest descriptor, а не полная строка `repository@digest`. Это подтверждённая несовместимость интерфейсов, но она не объявляется причиной раннего SQL отказа.

[Run 42212390636](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42212390636) после миграции достиг HTTP stage, но probe не мог стартовать: production Dockerfile копирует `mlsecops`, а qualification entrypoint находится в `scripts`. [Packager](../../scripts/kube_privacy_bundle.py) теперь собирает ограниченное дерево импортов probe в immutable ConfigMap с digest, который проверяется при create/readback вместе с Pod spec. Только qualification Pod получает read-only `/app/scripts`; production image и worker RBAC не меняются. Отдельный тест импортирует probe из восстановленного bundle без fallback на host scripts. Последующий run 42215561469 прошёл actual-candidate component checks.

При завершении контейнера между Running snapshot и `kubectl exec` operator повторно читает тот же Pod. Только совпадение UID/spec и terminal state позволяет передать обработку штатной проверке exit code/logs; работающий или подменённый Pod не превращает ошибку exec в успех. Диагностика child сохраняет только проверяемое расположение кода, без exception text. Все три неуспешных run завершили source SQL и cluster cleanup.

## Отказы и действия оператора

| Код / симптом | Действие |
| --- | --- |
| `trust_hosted_runner_required` | Проверить тип runner. Не обходить guard и не переносить запуск на локальный Docker/WSL/Kubernetes/SQL |
| `privacy_log_request` | Проверить bounded canary inventory и expected stream. Terminal observation без полного expected output запрещено |
| `privacy_log_identity` / changed | Сверить UID, owner, image, spec и restart count с текущей campaign. Не читать новый контейнер под старой receipt |
| `privacy_log_limit` | Сохранить закрытый диагностический факт overflow. Не увеличивать лимит и не брать tail ради pass; найти producer лишнего вывода |
| `privacy_log_canary` | Оставить M13 fail, не публиковать capture. Установить producer утечки и исправить его; повторить всю затронутую campaign |
| `privacy_log_incomplete_stream` | Проверить EOF, restart/rotation, потерю префикса и наличие неожиданных строк. Отсутствие canary в неполном логе не является успехом |
| `privacy_worker_capture_missing` | Не было полного наблюдаемого exchange. Проверить startup/worker lifecycle; исторический успешный report не заменяет текущий |
| `privacy_worker_bridge_output` | Attach bridge не завершён либо записал stderr. Сохранить приватную диагностику и проверить cleanup; fixed exception code не доказывает исправление причины |
| Ошибка operator callback | Base cleanup остаётся обязательным. Не оставлять Pod ради ручного исследования без отдельного решения об ограниченном retention |

Read-only diagnosis предшествует любым действиям. При неизвестном ownership остановить сбор и передать оператору конкретные IDs в приватном канале. Не выполнять global prune, удаление чужих Pods, изменение RBAC, отключение проверки TLS или перезапись journal. Для повтора нужна новая owned campaign; сборщик не меняет production state, поэтому rollback приложения этим компонентом не требуется.

## Локальная проверка без инфраструктуры

### Проверка обычного CLI: native evidence подтверждено

[CLI privacy probe](../../scripts/kube_cli_privacy_probe.py) использует существующий `kube_serving_probe`: тот запускает отдельный `python -m mlsecops.serving_http`, а сервис самостоятельно создаёт и закрывает Journal через `configured`/`audit_path`. Внутри сервиса нет monkeypatch, подмены Journal или дополнительной serving-роли. Внешний клиент выполняет прежнюю матрицу 12 canary requests, шесть quota/refill requests, две проверки 503 после остановки собственного worker и scrape 69 approved metric series. Полный вывод CLI проверяется после подтверждённого завершения процесса.

[Controlled runner](../../scripts/kube_cli_privacy_native.py) создаёт отдельный подписанный контрольный выпуск существующими fixture/promotion механизмами. После probe cleanup повторно читает digest-bound selection/authorization, проверяет snapshot закрытого журнала, его контекст и соответствие фактически полученным HTTP responses. Сохраняет private snapshot один раз и перечитывает его. Actual candidate проверяется затем своим qualification permit; контрольный release не разрешает actual production. Смешение subjects запрещено публичной проекцией.

Граница доказательства: внешний CLI observer **не наблюдает независимо внутренний audit admission**. Он проверяет соответствие завершённых journal requests HTTP-ответам; для pre-admission 401/429/503 возможен ответ без journal request. Не выводить admission из проверяемого журнала и не выдавать этот snapshot за ADR 0049 independent-admission packet. Actual-candidate packet сохраняет прежний более строгий контракт. Полная M13 acceptance должна явно оценить достаточность этой композиции; текущий report остаётся inconclusive.

При `cli_privacy_*` отказах сохранять первый результат, private bytes и exact source. Не запускать локальную инфраструктуру и не менять consumer policy, чтобы пропустить отказ. Проверить terminal CLI/owned worker, post-cleanup snapshot и fixed location в native diagnostics; повторять новую campaign только после установления причины. Raw snapshot/HTTP IDs/credentials не выводить в публичный CI log. Незавершённый процесс, stderr, потерянное наблюдение, canary, несовпадение signed context или испорченный сохранённый snapshot запрещают компонентный pass.

```powershell
$env:PYTHONUTF8='1'
uv run --locked python -m unittest scripts.kube_privacy_logs_qualification scripts.kube_privacy_worker_qualification scripts.kube_serving_runtime_qualification
```

На проверенном `90385fa`: Linux 155 test method executions / 0 skips; clean Windows checkout 155 tests / 0 skips. Пять component modules bundle/exchange/logs/operator/worker покрыты на 295/296 statements и 103/104 branches, каждый проходит 95% по обоим показателям. Это не coverage всей оркестрации. Проверены ownership, overflow, canary, неполный stream, failure/interruption cleanup, private packet re-verification, handoff order и bounded CRI-exit grace. [Evidence](../evidence/kubernetes-privacy-2026-11-06.md) сохраняет результаты и неуспешные попытки.

Обычный CLI lifecycle подтверждён в указанном controlled scope. До полного M13 остаются полный service-output inventory с bounded closed windows и controls, композиция actual/controlled subjects и общая source-bound acceptance. Положительный component report всегда содержит `full_M13=inconclusive` и `release_ready=false`.

CLI lifecycle contracts дополнены отказами startup/readiness, oversized HTTP, transient connection, ограниченным ожиданием cleanup и завершением только собственного process group. Workflow требует не менее 95% statements и branches отдельно для ordinary CLI probe, privacy hook и native orchestration. Coverage gate подтверждён в успешном native run 42225259346 на 36cd71d.

Run `42224962681` на `6b90fc0` прошёл 222 Linux tests и coverage gate, но bootstrap отказал с `refusing_nonempty_unowned_workspace`: coverage преждевременно создал `.runtime/evidence`. Cluster/source SQL ещё не создавались. Исправление сохраняет bootstrap ownership guard и пишет coverage только в `RUNNER_TEMP`; нельзя обходить отказ принятием существующего произвольного каталога. Повторный native run 42225259346 на 36cd71d прошёл, включая оба cleanup steps.

### Общий CI после публикации

Storage run `42226136313` на `d28f501` отказал до создания SQL: legacy output suite не проверял новый guard `canary_count`, поэтому `serving_output_probe` получил 97% при обязательных 100%. В `serving_output_qualification` добавлены отказ до вызова operation для неверных типов/границ и допустимые границы 1/9/16. Локально 35 methods прошли, observer 47 statements / 14 branches 100%, parent 193/194 statements и 51/52 branches. Порог workflow сохранён; новый hosted storage run ещё требуется. Успех отдельного Kubernetes privacy component не означает успех всей CI-матрицы.

Повторный scoped storage run `42227840179` на `0334ecf` прошёл observer gate, но позднее отказал на legacy release authorization coverage: отсутствовали проверки missing approval и подписанной неизвестной/неверно типизированной schema version. Добавлены точные отрицательные cases; локально 24 methods pass, release_policy/bundle/authorization: 237 statements / 98 branches, 100%. Production authorization не менялся.

Этот отказ произошёл после запуска source PostgreSQL. В прежнем storage-component workflow не было отдельного always-stop, поэтому явный stop источника в failed run не подтверждён. Workflow теперь повторяет существующую ownership-checked процедуру: при наличии `.runtime/storage.json` валидирует marker/actual container, останавливает только его ID, повторно валидирует и требует `Running=false`. Повторный hosted run должен подтвердить этот шаг; неизвестный/подменённый marker не даёт права остановить контейнер. Остальные helper services сохраняют собственные cleanup contracts.

Run `42228824972` на `a70beea` подтвердил release authorization 100% и новый source SQL cleanup, но выявил POSIX fixture defect: старые release/material-bundle tests копировали PEM через обычный `write_bytes`, получая group/world-readable mode. Production `key_files` правильно отказал с `signing_key_file_permissions`. Оба fixture теперь используют существующий exclusive `key_files.opened(create=True)` и bounded read оригинала; запрет небезопасных ключей не менялся. Windows passing tests не доказывают POSIX mode, требуется Linux повторение.

До нового hosted запуска проверены следующие legacy coverage stages. Promotion и Reader не включали существующие rollback contracts, trust authority не включал существующие root-store/Kubernetes routing contracts. Эти наборы подключены к соответствующим coverage commands без изменения thresholds: promotion 38 methods / 137 statements / 48 branches, trust 42 / 257 / 100, Reader 31 / 138 / 40, везде 100%; recovery 21 methods / 51 statements / 18 branches, 100%. Это pure contracts, не доказательство native SQL/cluster.

Run `42230103970` на `4f04116` прошёл исправленные release fixtures и promotion contracts, но M03 вернул общий `worker_process_failed`. Source SQL cleanup подтверждён. Повторная pure filesystem qualification на настоящем Linux, до запуска сервисов, в run `42232180410` на `64ea757` установила точную причину: `dataset_integrity_wrong_rejection:manifest-symlink:artifact_unavailable`. После descriptor-based hardening чтение manifest с `O_NOFOLLOW` корректно отказывает с `artifact_unavailable`; старый qualification ожидал `symlink_rejected`. Существующий negative test подмены leaf при open в `scripts/artifact_files_qualification.py` уже проверяет новый контракт. Исправлено только ожидание Linux qualification, без изменения `bounded_read` или разрешения symlinks. Linux preflight сохранён перед запуском сервисов. Windows compatibility path возвращает другой код, поэтому mock `platform.system=Linux` на Windows не является доказательством Linux acceptance. Успешное полное повторение storage workflow после исправления ещё требуется.

Run `42232406810` на `91a65ec` подтвердил Linux filesystem preflight, M03, M07, storage backup/restore, promotion journal recovery и trust contracts. Следующий native trust stage остановился после `model-backup-excludes-authority-False`: extended backup пытался прочитать отсутствующую model-promotion migration раньше транзакционного запрета копирования trust authority. Это неверный порядок диагностики запрета, не подтверждённая выгрузка trust-данных. В `storage_backup.create` добавлена ранняя проверка разрешённого scope после ownership validation: только точный ответ `f` на наличие `ml_trust` допускает дальнейшие model-backup проверки. Запрет внутри snapshot transaction сохранён. Оба варианта backup в native qualification теперь требуют конкретный `trust_authority_backup_forbidden`; тесты проверяют отказ до migration/export и продолжение для model storage. Новая полная native проверка ещё требуется; source SQL cleanup в failed run подтверждён.

Полный scoped storage repeat завершён: `b60eb93` / [42233932160](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42233932160) success, включая source SQL cleanup. M03 431 cases, M07 97, trust45, actual-candidate HTTP85; 1041 Linux method executions/0skips, clean checkout69/0. [Сводка, все отказы и воспроизведение](../evidence/ci-regression-2026-11-06.md) сохраняет различия component/gate и исходную main-матрицу. Полные M13/M18/R1 не приняты.

### Закрытые журналы сервисов и приватный CLI handoff

Компонент [проверен native на 0d5ad83 / 42240476139](../evidence/kubernetes-service-privacy-2026-11-06.md): четыре закрытых окна, четыре обнаруженных control-утечки и перечитанных packets; cleanup verified. Полный M13 ещё не принят. [Наблюдатель](../../scripts/kube_privacy_services.py) начинает интервал до создания HTTP probe и закрывает его после завершения запросов. Для storage и trust проверяются owned StatefulSet/Pod UID, image, отсутствие restart/init/ephemeral containers, 18 текущих `pg_settings` и отсутствие соответствующих role/database overrides. Проверка читает реальные настройки; один config-файл не доказывает, куда пишет запущенный PostgreSQL.

Границы задаются уникальными `RAISE WARNING` в серверный stderr. `SET LOCAL client_min_messages=error` подавляет только передачу этой служебной метки клиенту; server logging policy не изменяется. Это опирается на раздельные [server/client уровни сообщений](https://www.postgresql.org/docs/18/plpgsql-errors-and-messages.html) и [назначения журналов PostgreSQL](https://www.postgresql.org/docs/18/runtime-config-logging.html). Команда не меняет SQL-данные и не устанавливает расширения. Проверяются полный ограниченный stream, сохранение начального префикса, ровно по одной упорядоченной start/end метке и отсутствие девяти input canaries. Это закрытый интервал, не вся история процесса и не доказательство неизменности настроек между двумя readbacks.

После закрытия каждого интервала отдельная synthetic control метка должна вызвать именно `privacy_log_canary` в настоящем collector. Пустой журнал, отсутствующая метка, ротация с потерей префикса, restart, overflow, неверная identity и иной отказ не засчитываются как успешная detection. Raw bytes и настройки сохраняются один раз через существующий POSIX private packet writer; после probe cleanup retained bytes перечитываются и проверяются. CLI закрывает окна уже после cleanup, actual path дополнительно повторяет readback после удаления своих Job/ConfigMaps. Public projection выдаёт только конечные counts, не журналы, input values или private hashes.

[CLI handoff](../../scripts/kube_cli_privacy_exchange.py) использует существующий bounded private exchange: probe пишет canaries в собственный временный файл, operator читает его через exec проверенного Pod, подтверждает digest request, затем probe удаляет request/ack до печати итогового отчёта. Ни plaintext, ни base64 canaries не допускаются в stdout/CRI. Это отдельный однофазный CLI канал; двухфазный actual worker/audit protocol и independent admission contract не менялись. Serving Pod не получает новых прав чтения логов или Secrets.

Контролируемые локальные проверки: 18 новых методов, 175 statements / 56 branches, 100% двух новых modules. CLI regressions: 30 методов; existing CLI modules сохраняют минимум95% statements/branches по отдельности. Связанный набор: 196 methods, 18 platform skips на Windows; эти skips не выдаются за Linux acceptance. Полная проверка выполняется `kubernetes-privacy.yml` на разрешённом GitHub-hosted runner с pinned dependencies и обеими cleanup процедурами. Native repeat: 244 Linux methods без skips, четыре окна и cleanup pass. Clean Windows checkout с новой venv: 244 methods/18 POSIX skips. Полный M13 остаётся inconclusive до fresh composition и отдельного acceptance gate.

| Отказ | Действие оператора |
| --- | --- |
| `privacy_service_settings` | Сверить runtime destinations, logging/extension settings и role overrides. Не менять policy ради pass |
| `privacy_service_marker_unobserved` | Сохранить failure; проверить доставку ограниченного CRI stream и uniqueness, не принимать tail или пустой вывод |
| `privacy_service_changed` / `privacy_log_identity_changed` | Сверить UID, spec, restart и ownership. Не продолжать окно на новом Pod |
| `privacy_service_window_incomplete_or_canary` | Оставить M13 fail, сохранить приватные байты; определить утечку либо потерю начала stream |
| `privacy_service_control_not_detected` | Считать collector непроверенным, не объявлять отсутствие утечек |
| `cli_privacy_handoff_*` | Не выводить request в журнал; проверить bounded private request/ack, exact Pod и cleanup |
| `privacy_service_retained_*` | Не переписывать единственную копию packet; сохранить inconclusive/fail и проверить owner, mode, bytes и закрытый интервал |

### Fresh M13 gate: диагностика и повторение

[Композиционный контракт](../decisions/0048-privacy-acceptance.md#исполняемая-композиция-2026-11-06) [проверен native на b03a5d9](../evidence/m13-privacy-acceptance-2026-11-06.md): M13 pass438cases, все430 required methods и cleanup verified. Ответственный - оператор disposable hosted campaign. Prerequisites: clean locked checkout, pinned tools/image, owned cluster/source storage и подготовленный actual candidate. На текущей Windows инфраструктуру не запускать.

Разрешённый hosted workflow выполняет:

```bash
uv run --locked python -m mlsecops.acceptance --gate M13 --profile local-cpu --state .runtime --output .runtime/evidence/M13.json
```

Ожидаемый результат после успешной полной проверки - exit0, `gate=M13`, `status=pass`; это никогда не означает `release_ready=true`. Недоступная среда даёт inconclusive/exit2, доказанное нарушение - fail/exit1. `.runtime/evidence/privacy-gate.json` сначала получает inconclusive, поэтому сбой не сохраняет прежний pass. Private fingerprints находятся отдельно в `privacy-gate-private.json`; не печатать raw packets, context, request/ack, URLs и exception values.

Порядок действий при отказе:

1. Прочитать finite gate status и текущий source SHA; проверить, что pipeline не был отменён новым push. Сохранить первичный failed run, не заменять его успешным retry в истории.
2. Для `M13_controlled_contracts_failed` проверить exact method inventory и finite `M13-contract-diagnostic`: missing count, первые 16 имён из текущего source inventory, nonzero exit и наличие stderr. Сырые stdout/stderr и неизвестные child identifiers в эту диагностику не экспортируются. Expected failure или platform skip не разрешают pass; threshold/список обязательных тестов ради результата не менять.
3. Для `M13_evidence_binding`/`M13_evidence_shape` сверить текущие source/image/methods, fresh timestamps, разные actual/controlled campaigns и subjects. Затем локализовать retained-packet/hash/primary disagreement по приватным материалам и constant diagnostic location. Не заменять mismatched packet или signed artifact согласованным summary.
4. Для service failures использовать таблицу выше. Для signed-primary refusal сверить public key pin, proposal/permit expiry и текущие immutable refs. Не переподписывать actual candidate контрольным approval.
5. Дождаться always-stop source SQL и удаления именно owned cluster, проверить readback и terminal job. Не останавливать чужие ресурсы и не делать global prune.
6. После исправления воспроизведённой причины выполнить новый workflow на clean commit. До этого результаты gate остаются fail/inconclusive. Rollback реализации - обычный revert конкретного изменения после завершения текущей campaign; он не превращает старые отчёты в новую acceptance.

Эскалировать владельцу при ownership mismatch, недоступных primary bytes, неочищенных owned resources или реальной утечке canary. Не продолжать через ослабление guards. На этапе разработки выполнены negative contracts, включая stale/future/naive times, wrong source/image, incomplete controls, private fingerprint export и post-run mutation; hosted проверка и финальный статус публикуются отдельно.

Первый общий run `42244584010` на `ca1d939` завершился fail до вывода native preparation stages; source SQL stop и cluster deletion подтверждены. Public M13 envelope сохранил fail/exit1 без cases. Точная причина пока не установлена: длительность около37 s указывает на controlled contracts, но это не доказательство. Добавлен finite diagnostic с именами только из фиксированного source inventory и отдельный Linux pure preflight перед инфраструктурой. Порог/required methods не ослаблены; в явный inventory дополнительно включены существующие прямые contracts `serving_access` для auth/quota, которые ранее проверялись через HTTP integration. До нового native результата M13 остаётся непринятым.

Локальный повтор всего fixed inventory после добавления direct access contracts выполнил416 methods и воспроизвёл один error: `WorkerPrivacyContracts.test_serving_guard_precedes_session_and_success_is_preserved` обращался к `sys.stdout.buffer`, полагаясь на настоящий console stream. Общий runner перенаправляет текстовый вывод в `StringIO`; тестовая среда не предоставляла binary buffer. Fixture теперь явно задаёт свои stdin/stdout buffers и stderr и проверяет передачу именно этих streams в `serve`. Production worker не менялся. RED log сохранён приватно; отдельный повтор под redirected stdout прошёл. Первичный traceback старого Linux run не был опубликован, поэтому локальная причина не выдаётся за извлечённый из него stacktrace; требуется fresh Linux preflight и вся native campaign. Windows platform skips по-прежнему не являются acceptance.

Linux pure preflight `e33819c` / run42246187189 прошёл все416 обязательных методов (missing count0, child exit0), но gate отказал из-за непустого stderr. Bootstrap/build/source SQL не запускались; cleanup step проверил отсутствие source marker, удаление cluster было skipped как неприменимое. Это не test skip внутри416 contracts и не успешный M13. Добавлены только byte count и признаки фиксированных diagnostic categories, без raw text/paths/identifiers; требование empty stderr сохранено.

Следующий pure run `fc79b60` / 42247058025 подтвердил: все416 методов pass, child exit0, stderr369 bytes с признаком `onnxruntime`. Содержание не публиковалось и exact old bytes не объявляются классифицированными по whitelist. M13 contract CLI теперь вызывает существующий pinned `runtime_bootstrap.initialize()` на Linux до импорта fixtures: bounded memfd/RLIMIT capture4096 bytes, exact PCI startup-warning validator и возврат исходных descriptors/limits. Неизвестный output, truncation, preimported runtime, другая версия или отказ init остаются fail. Parent по-прежнему требует пустой stderr. Добавлены RED/green ordering contracts и direct bootstrap tests в обязательный inventory. Production initializer/worker не менялись; новая native проверка должна подтвердить конкретный runtime output и все методы без skips.

Run `c91d134` / 42247819845 подтвердил пустой stderr после existing runtime bootstrap; один из430 methods отказал: `BootstrapBoundaryTests.test_privacy_and_timeout_precede_runtime_import_and_model_read`. Это второй fixture с неявной зависимостью от console `.buffer`, найденный при подключении direct bootstrap suite. Ошибка воспроизведена под redirected stdout; fixture получил собственные binary stdin/stdout и stderr и проверку переданных streams. Пять переносимых bootstrap contracts после исправления pass. Девять native descriptor/rlimit/import tests требуют Linux и не выдаются за Windows proof. Новая campaign ещё требуется; build/bootstrap в failed preflight не выполнялись.

Полный исправленный repeat `b03a5d9` / [42248499786](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42248499786) принят: M13 pass438cases,430contractsбезskips, source/policy/method hash и primary report сверены. Source SQL stop/readback16:08:31UTC, cluster deletion/absence16:08:34UTC. [Evidence и воспроизведение](../evidence/m13-privacy-acceptance-2026-11-06.md) сохраняют все первые отказы. T16 закрыт только в synthetic serving scope; независимые M22, image findings и весь R1 остаются открытыми.

При проверке primary report `gh run view --log` не показал строку JSON длиной81079 символов. Используйте исходный Actions job-log API в приватный файл, не выводите raw/ANSI stream в терминал. Парсер должен извлечь полный envelope, проверить exact source, все required IDs и hashes. Для Linux method-material hash сравнивайте exact Git blobs source commit: Windows checkout может иметь CRLF при том же clean Git status. Не меняйте глобальный Git config и не объявляйте mismatch, сравнив разные представления bytes.
