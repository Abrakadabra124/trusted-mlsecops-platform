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
