# Реализация R1

Начата 2026-10-07 по прямому запросу владельца. Исследовательская цель R0 завершена; теперь реализуется R1. Этот файл фиксирует решения текущей итерации, не заменяет исходные 23 gates.

## Порядок

Текущий increment T01/T02: [container audit](container-audit.md), [ADR 0014](decisions/0014-container-audit.md). Код находится в host-only `scripts`, не включён в privileged scorer/worker image и не меняет их принятый source fingerprint. Не считать native catalogue доказательством отсутствия CVEs; статус остаётся inconclusive до успешного Grype DB/control/scan с теми же inputs.

1. T01-T02: inventory, frozen policy, pinned dependency/image inputs, идемпотентный bootstrap и fail-closed acceptance runner.
2. T03-T04: синтетические данные, passport, split, signed manifests и отрицательные проверки.
3. T05-T10/T26: отдельные workers, обучение, ONNX export, воспроизводимость и независимый scorer.
4. Остальные задачи по зависимостям: attacks, intake, release/trust, serving, inventory, monitoring и recovery.
5. Сквозная приёмка, повтор из clean checkout, CI и публикация очищенного evidence.

## Изоляция от прежней платформы

Read-only inspection 2026-10-07: baseline checkout HEAD уже `52cc83067d146f6b103388facbbb9a88866d344d`, registry image остаётся `registry:3.0.0`. Исследование R0 ссылалось на другой commit. Чужие контейнеры, registry, kubeconfig и исходный Git не меняются.

Первый executable increment использует собственный Docker image и offline workers с protocol через stdin/stdout, без host mounts, host network, Docker socket, ключей и доступа к holdout labels. Это промежуточный developer profile; он не выдаётся за выполненные Kubernetes Jobs/RBAC/NetworkPolicy gates M04-M05. Их проверка остаётся обязательной для полного R1. При необходимости отдельного кластера его создание и ограничения будут записаны до запуска.

## Данные и пределы утверждений

Первый продукт - локальный Release Risk Advisor на 20 000 синтетических строк, не оценка реальных релизов. Политика фиксируется до первого обучения в `policies/local-cpu.json`. Нет реальных персональных данных, платного облака и GPU. Локальный host-admin входит в доверенную базу; разные роли одного процесса или пользователя не объявляются независимыми людьми.

Не реализованный gate отдаёт `inconclusive` и exit code 2. Наличие CLI, файла evidence или успешного component probe само по себе не означает прохождение полного gate. Отчёты с missing/fail/inconclusive не разрешают trusted promotion.

## Первый проверяемый increment

Команды запуска находятся в [README](../README.md). `mlsecops.qualification` - часть исполняемого acceptance-инструментария продукта, не замена полной приёмке. Она проверяет component boundaries и численное повторение; полные gates пока не переводятся в pass.

Три fresh-process runs дали одинаковые вероятности; AUPRC 0.9323007296445032, constant-score baseline 0.4073333333333333, parity error 2.086162567138672e-7. Точность на синтетике подтверждает механическую работоспособность, не бизнес-utility. Подписанный report имеет `release_status=unapproved`.

DSSE (Dead Simple Signing Envelope) связывает тип документа и точные bytes с Ed25519 подписью библиотеки cryptography. Это ограниченный single-signature application profile, не собственный криптографический алгоритм и не production KMS. Trust roots задаются при bootstrap отдельно от входящего envelope. Локальные ключи защищены от контейнерных workers отсутствием mounts, но не от администратора host.

Теги images сначала разрешаются в immutable image ID. Затем контроллер сравнивает label source fingerprint с текущими Python-файлами, policy, Dockerfile и lockfile. Stale image отвергается с требованием rebuild; image label не объявляется криптографической подписью или независимой build attestation.

Dataset/model bytes проверяются перед использованием. Candidate loader не загружает pickle; ONNX parser запускается в resource-limited worker, запрещает external tensors, вложенные graphs/functions и операторы вне ограниченного allowlist. Это проверка формата, не универсальный model malware scanner.

На текущую дату остаются полноценная приёмка M01/M04-M19/M21-M23, MLflow, dataset intake API, holdout query budget, adversarial campaign, promotion/revocation, online serving, monitoring, полный ML recovery и >=95% security branch coverage. Storage ACL, M03, scoped controllers и M20 добавлены последующими increments ниже. DVC не принят после security spike, source versioning реализован другим механизмом ниже. Goal остаётся активной, component increments не считаются R1 release.

## Второй increment: Kubernetes

Принят [ADR 0004](decisions/0004-isolated-kubernetes-lab.md), создан отдельный cluster. [Runbook](kubernetes-lab.md) объясняет две реализации executor и повторение из clean checkout. 52 isolation component checks прошли локально, Docker qualification после интеграции сохраняет 65 успешных checks. Настоящие Jobs обучают и оценивают ту же синтетическую модель. Действующая foundation не изменяется.

Отрицательные проверки выявили и помогли исправить реальные интеграционные ошибки: минимальное число log files kubelet должно быть 2; containerd добавляет вложенный OCI index; Kubernetes объединяет stderr/stdout, что нарушало strict protocol; deadline controller может удалить Pod до финального чтения, поэтому runner сохраняет последнюю наблюдаемую identity и отдельно подтверждает удаление. Конкретное содержание stderr не доказало причину в ONNX telemetry, поэтому такая атрибуция не утверждается. Исправление разделяет каналы через bounded wrapper, не фильтрует произвольные строки из общего вывода. Проверка PID limit изменена с неверного leaf-file assumption на фактическое ограниченное создание процессов. Ошибки не замаскированы отключением контроля.

## Третий increment: источник и quarantine

Реализованы [source lock и intake](data-lifecycle.md), 44 проверяемых сценария и M02 runner. Quarantine не даёт approved статус; curator повторяет validation, проверяет отдельную подпись исходного snapshot и текущий source approval. Типизированная signed lineage связывает dataset с source и lock, optional `--versioned-data` переносит её в training run. Старый developer путь не объявляется R1-совместимым.

DVC spike был остановлен после настоящего dependency finding, а не после ошибки установки. Уязвимая dependency chain удалена, не скрыта из audit. [ADR 0005](decisions/0005-data-lineage.md) меняет инструмент, но сохраняет integrity/reproducibility acceptance. Strict audit после удаления: известных vulnerabilities не найдено.

В Kubernetes CI исправлены различия OCI index/config между Docker stores. Протокол отделяет ограниченный stderr дочернего worker от JSON stdout: arbitrary stderr не печатается в публичный evidence, фиксируются только число bytes и разрешённый diagnostic flag. CI действительно наблюдал ненулевой stderr, но тип предупреждения не установлен; GPU-причина не заявляется. Все typed output checks остаются на стороне controller. 52 Kubernetes probes и 74 developer checks прошли в GitHub на `f7cdc59`.

## Четвёртый increment: storage identities

[PostgreSQL component](storage-lab.md) добавляет настоящие SQL GRANT и проверяемую mTLS identity вместо условных имён directories. 367 локальных checks подтверждают матрицу разрешённых/запрещённых операций, byte constraints, TLS negatives и идемпотентность. Storage client не требует Docker API; bootstrap-admin отделён от выдаваемых role credential directories. Runtime имеет 1 CPU/512 MiB/64 PID, readonly root и pinned image.

Первый storage commit `6c28987` воспроизведён в CI. Следующий slice добавляет настоящий SQL training/evaluation path: scoped publisher/scorer reads, candidate persistence, signed evaluation с binding до dataset/lineage и 26 integration checks. Общая математическая логика не дублируется: legacy filesystem wrappers и SQL controllers используют одни train/evaluate primitives. Проверка metadata отделена от загрузки всех split, поэтому publisher больше не открывает holdout в новом path.

Суммарная квота данных, image scan, полный ML recovery, MLflow и независимые controllers остаются отдельными задачами. SQL backup/restore добавлен последующим increment ниже. Network restriction у БД ограничивается loopback publication и mTLS, не deny-egress. Подробное evidence не подменяет полные M04/M20; общий host administrator остаётся доверенным.

## Пятый increment: приёмка целостности

[M03](integrity-gate.md) стал исполняемым gate: до изменения runner выдавал inconclusive; после подключения негативных fixtures и реальных SQL checks локально прошёл 431 case. Файловый suite использует Linux symlinks в offline container, не требует новых Windows privileges и не получает host artifacts/keys. SQL part заново выполняет существующие ACL/TLS и train/evaluate suites, затем сравнивает approved dataset hashes до и после. Это реальное чтение защищённых объектов, не только наличие GRANT statements в migration.

T04 завершена в synthetic-only профиле. Developer qualification отдельно проверяет fail-closed dispatch при отсутствующей БД; storage workflow запускает весь M03 из clean checkout. M01/M04-M23 остаются обязательными и незавершёнными; approved dataset не означает approved model release.

## Шестой increment: согласованный storage recovery

[ADR 0007](decisions/0007-storage-recovery.md) и [runbook](storage-recovery.md) добавляют native PostgreSQL backup/restore, а не только проверку наличия файла. Открытый snapshot связывает artifact bytes с ledger; metadata подписывается существующей ролью trust, приватные ключи не экспортируются. Restore отказывает до создания target при неверном archive/signature/context, проверяет пустоту нового storage, импортирует атомарно и сравнивает итоговый ledger. Повтор не меняет identity и не затирает последующие записи.

430 локальных checks подтвердили отрицательные сценарии, конкурентную вставку, отдельную восстановленную БД, реальные ACL/TLS и 1 000 golden predictions с max error 0.0. Strict negative fixture обнаружил `bool == int` в migration metadata, проверка типа исправлена до публикации. T02 получает настоящий restore smoke; T20/M17 остаются открытыми до полного release/trust/serving recovery и проверенного RPO. Чужие Docker resources и исходная foundation не изменяются.

## Седьмой increment: private cluster storage

[ADR 0008](decisions/0008-private-cluster-storage.md) добавляет отдельный private Kubernetes data plane, не открывая host loopback endpoint. Bootstrap создаёт 46 owned ресурсов, фиксирует UID, проверяет конфигурацию и не присваивает foreign resources. Роли используют отдельные client certificates, namespaces и ServiceAccounts; CA private key не попадает в Kubernetes. Прежние SQL migration и ACL переиспользуются через небольшой admin transport adapter.

436 локальных checks подтвердили шесть identity boundaries, настоящий TLS, запреты API/network и persistence после пересоздания Pod. Linux libpq warning не скрывался: некорректный `/dev/null` password-file profile заменён явным отсутствующим файлом с guard от подмены. Shared client regression: M03 431 cases; developer regression 74 cases. [Runbook](private-cluster-storage.md) отдельно описывает single-node persistence, concurrency ограничения и отсутствие production key custody. Следующий increment должен перенести проверенные artifacts и запустить scoped controllers; полные M04/M20 не закрыты.

## Восьмой increment: подписанная migration и чтение артефактов

[ADR 0009](decisions/0009-storage-migration.md) и [runbook](cluster-storage-migration.md) связывают backup digest с target namespace/volume/spec. Живая advisory-lock session координирует migration processes, database maintenance закрывает обычные clients до проверки native import. Signed intent сохраняет контекст незавершённого действия; receipt появляется только после совпадения ledger. Повтор не пересоздаёт identity и не перезаписывает позднюю историю.

Локально прошли 497 checks: реальные backup negatives, interruption после commit, отказ клиента в maintenance, resume без второй копии, receipt binding, publisher/scorer artifact reads и повтор всех 436 storage checks. 1 000 golden predictions совпали с max error 0.0; 40 объектов сохранены в private target. Source подготовительного demo меняется до backup, но migration не меняет его ledger. Подробные digests и различие training/verification images записаны в STATUS. Controllers и полные M04/M17/M20 по-прежнему не приняты.

## Девятый increment: scoped publisher/scorer

[ADR 0010](decisions/0010-scoped-controllers.md) реализован отдельным opt-in runtime. Десять owned RBAC/admission/network ресурсов ограничивают publisher/scorer их worker namespaces. API client работает через проверенный HTTPS и explicit projected token, model workers остаются offline. Scorer подписывает evaluation вне ONNX parser; его собственный Secret не монтируется в worker. Общие train/evaluate primitives сохранены, provenance берётся из проверенного image, а не из отсутствующего внутри image Git.

Локально прошли 133 controller checks: 37 request/mocked transport, 60 реальных admission/RBAC и остальные TLS, end-to-end, persistence и cleanup controls. AUPRC 0.9323007296445032, parity error 2.086162567138672e-7. Peak RSS publisher/scorer 159 336/149 896 KiB при отдельных 512 MiB limits. Зафиксированы candidate/evaluation digests и фактические worker/controller identities. Это измерение конкретного synthetic run, не worst-case capacity.

Отладка выявила три интеграционные ошибки: Dockerfile отсутствовал в allowlisted build context; digest из CRI inspection не был зарегистрирован как containerd image alias; тест путал admission Invalid с RBAC Forbidden и сначала использовал schema-invalid privileged fixture. Исправлены первопричины без отключения pin, policy или TLS. Негативные fixtures теперь требуют точную admission policy/reason. [Runbook](scoped-controllers.md) разделяет реальные и mocked проверки, а также предупреждает, что новые private SQL runs не входят в старый host backup.

## Десятый increment: ordered prediction protocol

[ADR 0011](decisions/0011-prediction-protocol.md) закрывает подтверждённый пробел consumer: неизвестная schema version и произвольный scan ранее попадали в evaluation report. Теперь общий helper фиксирует exact request bytes, fresh nonce и row IDs; consume одноразовый, malformed/reordered/replayed responses не доходят до signer и SQL writer. Наличие digest не доказывает правильность вычисления malicious worker, что отдельно записано в [runbook](prediction-protocol.md).

164 unit/controlled integration checks прошли. Coverage одного protocol module: 71 statements, 28 branches, 100%; это не >=95% security coverage всей платформы. Native Docker suite сохранила три fresh-process обучения (74 checks), Kubernetes controllers прошли 136 checks с настоящими train/evaluate и независимой проверкой persisted signature. Signed report связывает 3 000 row predictions с request digest и отдельным `ml-eval` worker, не с процессом signer.

Первая native regression выявила лишнее сравнение input image alias с actual image digest. Оно удалено: resolver по-прежнему проверяет source/image, а scorer сравнивает фактический digest execution с candidate. Постоянные tests проверяют и разрешённый alias, и отказ другого observed digest. Checks не заменялись на безусловный pass. Весь prediction path и golden verifiers обновлены вместе, без fallback на v1 или перезаписи старых artifacts.

## Одиннадцатый increment: live worker access matrix

[ADR 0012](decisions/0012-live-worker-boundary.md) добавляет положительно контролируемую проверку доступа, а не только отсутствие файлов в пустом контейнере. Scorer witness использует тот же builder, SQL identity, API token и signer mounts, что настоящий scorer. Он держит проверенные synthetic labels в памяти и qualification-only tmpfs file. CRI inspection связывает node PID с конкретным running container/Pod; workers пробуют `/proc` этого процесса, современные credential paths и настоящие Service IP.

Локально прошли 137 checks: 43 unit/controlled и 94 live/orchestration. Обе worker identities не прочитали ни один из 29 проверенных paths и не подключились к SQL/API. Scorer положительно проверил endpoints, identity, holdout и key до и после отрицательных probes; SQL ledger сохранился. Чужой UID не позволил удалить собственный temporary ConfigMap. Все созданные Jobs/Pods/ConfigMaps очищены, постоянные policies и permissions не расширены.

Review усилил observed-spec guard: subset matching недостаточно для optional shared/host PID flags и неожиданного init/ephemeral container. Добавлены отдельные rejects и постоянные negative fixtures. Первое выполнение unit suite на Windows выявило использование OS-dependent разделителя в Linux probe path; исправлен POSIX path contract, не ослаблен ожидаемый deny. Missing prerequisites теперь инвалидируют прежний component report, а не оставляют stale pass. [Команды и ограничения](live-worker-boundary.md).

Это конечная live проверка текущего access slice, но не full M20: нужны агрегированное subject binding и дополнительный native malformed-output сценарий до подписи. Общий host administrator, shared kernel, persistent evaluation budget и будущие metadata/serving services остаются вне этой локальной проверки.

## Двенадцатый increment: executable M20

[ADR 0013](decisions/0013-worker-authority-acceptance.md) объединяет ранее отдельные доказательства в заново исполняемый gate. Qualification scorer использует настоящие credentials и стандартный builder, вызывает реальный `storage_pipeline.evaluate`, а test executor намеренно повреждает response после настоящего prediction Job. Рабочий admission и permissions не ослабляются, test mode в production request не добавляется.

Для каждого из 19 повреждённых batches проверяются точная причина отказа, отсутствие вызовов sign/SQL writer и неизменность evaluation history. Before/after controls создают два настоящих signed reports, независимо проверяемых после сохранения. Gate также запускает обычный publisher/scorer positive path, live access matrix и isolation suite на том же source/image и проверяет dataset/candidate/model/policy binding. SQL rows не удаляются, unexpected write остаётся failure evidence, не маскируется rollback тестовых данных.

Отрицательные contract tests проверяют missing/failed/stale/mismatched component, пустые/повторные case IDs и stale CLI pass после missing prerequisites, Rejected, I/O error или unexpected crash. Пропущенная проверка не становится pass. [Runbook](worker-authority-gate.md) связывает каждое требование M20 с исполняемым доказательством; текущие measurements и CI находятся в STATUS. Это граница полномочий model worker, не semantic poison detector, независимый human review или готовый R1 release.

## Проверенные технические основания реализации

- [uv Docker integration](https://docs.astral.sh/uv/guides/integration/docker/): image и dependencies фиксируются, установка не происходит внутри training worker.
- [scikit-learn persistence](https://scikit-learn.org/stable/model_persistence.html): runtime не загружает pickle; ONNX применяется после проверки ограниченного профиля.
- [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md): подпись связывает тип и точные bytes payload; доверенные ключи определяются вне envelope.
- [ONNX external data](https://onnx.ai/onnx/repo-docs/ExternalData.html): external tensor data запрещены в первом профиле.
- [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/): лимиты проверяются в реальном runtime, не только в command arguments.
