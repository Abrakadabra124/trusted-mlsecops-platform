# ADR 0047: full-lifecycle serving output observation

Дата: 2026-10-19, обновлено 2026-10-20. Статус: implemented, native verification pending. Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [ADR 0046](0046-private-audit-correlation.md) проверил private chain, но не полноту всех output channels.

## Пробел и требование

Existing serving_privacy_probe проверяет HTTP body/headers, Python stdout/stderr/logging, disabled ambient OTel, approved metrics и owned audit для 12 input cases. Python redirect_stdout/stderr не охватывает os.write(1/2), уже открытые logging streams и subprocess output. Область hot loop также не включает imports/startup/shutdown и interpreter exit. Нельзя на этой основе объявлять all-output M13.

## Решение

В disposable Linux CI actual-candidate qualification запускать внутри отдельного Python child. Внешний observer использует существующий worker_transport.capture: bounded stdout/stderr pipes, timeout, owned process-group cleanup, подтверждённые exit и reader completion. Не писать новую систему управления процессами и не запускать локальные Docker/WSL/SQL.

Child сохраняет Python-level captures от lazy imports через qualify/HTTP shutdown/closed-journal callbacks. Existing privacy exercise передаёт private input needles через явный callback, не environment/global registry. После завершения операции child seals captures под отдельным lock, затем проверяет captures и сериализованный итоговый report на canaries; отсутствие callback/overflow/ошибка не даёт pass. Поздний nonempty write через сохранённый capture, включая cached handler в atexit, отбрасывает raw value и пишет только постоянный failure marker в FD2, поэтому outer observer отвергает результат. Raw capture не печатается и не сохраняется в evidence.

Публикуемый native document восстанавливается из тех же просканированных canonical bytes через strict decode. Исходный изменяемый объект producer больше не возвращается: сохранённая ссылка или фоновый callback не могут изменить уже проверенный snapshot. Copy после scan не заменяет привязку к проверенным байтам; регрессия явно меняет исходный объект между serialization и чтением capture.

Outer observer принимает только один JSON document с ожидаемым report и exact privacy summary; stderr должен быть пустым. Новый opt-in canonical_output=True в существующем transport до удаления raw bytes требует точное равенство canonical(document)+newline; даже дополнительные JSON whitespace bytes отвергаются. Default transport mode не меняется. Любой stderr, даже не содержащий известный canary, запрещает pass. Parent ждёт полного завершения child, включая interpreter exit; ошибки/timeout/cancellation дают только constant diagnostic и non-success. Существующие source/trust/signature/image/ML gates не изменяются.

В child qualify вызывается с publish_report=False и не сохраняет campaign/report.json. Единственный владелец final evidence - parent после проверки процесса, source и summary. Для owned state parent сначала заменяет старый evidence/candidate-serving.json на inconclusive, затем запускает workload. Ошибка ownership/guard до разрешённого доступа не даёт права менять чужой/непроверенный путь; прежний файл в таком случае не является результатом нового запуска.

Вложенный serving_privacy_probe использует тот же LifecycleCapture для stdout, stderr и Logger.handle. ExitStack регистрирует seal до установки redirects/hooks, поэтому при выходе сначала восстанавливаются hooks, затем закрываются все captures до последнего scan. Это выполняется также при exception и KeyboardInterrupt. Одного seal внешнего producer недостаточно: handler, сохранённый внутри HTTP exercise, мог писать в свой уже проверенный буфер после HTTP или в atexit. Этот обход отдельно воспроизведён отрицательным тестом и закрыт общим lifecycle contract.

Existing serving_privacy_probe остаётся hot-loop проверкой; новый observer её дополняет, не заменяет. Worker protocol stdout остаётся приватным IPC, stderr serving worker направляется в DEVNULL и container log-driver=none проверяется runtime inspection. Это не публичный лог и не повод раскрывать protocol bytes. Actual input needles и raw features не включаются в новый public summary.

## Контракт и границы

- Только explicit --confirm-disposable в существующем ubuntu-24.04 GitHub-hosted disposable workflow; локальный/shared/self-hosted профиль этим новым wrapper не поддерживается. Environment guard предотвращает случайный запуск, но не является remote attestation против hostile owner. Рабочее состояние определяется штатным ownership validator.
- Parent/child CLI guard запускается до private config/workload imports. Library helpers не меняют kernel state вызывающего процесса.
- Reuse лимитов transport: stdout <=16 MiB, stderr <=64 KiB, общий timeout <=570 s. Python capture <=64 Ki characters; overflow закрывает pass. Никакого бесконечного accumulate/communicate.
- Needles: bounded bytes от существующего exercise, включая credential, input marker, marker SHA-256, canonical raw row и numeric feature. Они живут только в owned child memory.
- Parent проверяет exact новое summary и исходный native report scope/source/status/release_ready. Child-only вызов не является полной FD qualification, что видно в summary; final pass возникает только после outer observation.
- Нельзя использовать успешный generic worker_transport decode вместо проверки expected shape. Не печатать caught exception, captured bytes или subprocess command с private values.
- Не устанавливаются OpenTelemetry collector/SIEM/новые зависимости. Core/dumpability policy и существующие bounded capture/cleanup contracts сохраняются.
- Новые доказательства покрывают serving qualification process lifecycle и его унаследованные FD, не произвольные host files, hostile same-UID admin или сторонние exporters вне управляемого runtime. Training/controller/service logs и общий M13 acceptance требуют отдельной карты и source-bound aggregation; full M13 остаётся открыт.

## Принудительное завершение и владелец восстановления

SIGKILL внешнего transport не доказывает очистку Docker daemon resources, private authority directory или вложенного attach session, который создал отдельную process group. Поэтому timeout/cancellation оставляет inconclusive и native_cleanup=unconfirmed-on-forced-stop; pass запрещён. Этот риск не маскируется успешным cleanup внешних pipes.

Для данного CI-only observer recovery owner - владелец disposable GitHub-hosted job: после failed forced-stop job прекращается, никаких следующих ML/release действий или upload private state; VM не переиспользуется следующей попыткой. Повтор допускается только в новом hosted job. Штатный успешный путь по-прежнему проверяет owned authority/container removal через существующие native contracts. Деструктивное автоматическое удаление ресурсов по неполному prefix не добавляется. Перед переносом wrapper на shared/local host обязательны отдельные resource receipts, ownership-validated recovery и native timeout tests; это не заявляется реализованным здесь.

## Приёмка increment

1. Failure-first tests: direct FD stdout/stderr, pre-opened logging stream, subprocess inherited FD, late atexit write, Python-level canary, report canary, capture overflow, missing observer, malformed summary, nonzero child, cleanup/timeout and cancellation must not produce pass.
2. Valid child preserves actual-candidate report and source binding; stdout is one bounded expected document, stderr empty, all transports closed. Python observer needles никогда не становятся полем public report.
3. Existing privacy matrix сохраняет 12 cases, 36 durable events, 69 approved series; callbacks non-native pure tests проходят.
4. Linux native proof: actual unchanged candidate, post-close private correlation/export и новые lifecycle observations; all terminal CI recorded. Local Windows tests не выдают себя за Linux kernel/container proof.
5. RB-66/PB-40, evidence, output-channel coverage map и следующий шаг M13 aggregation. Не закрывать всю T16 по результату одного observer.

## Основания

- [Python 3.12 contextlib](https://docs.python.org/3.12/library/contextlib.html#contextlib.redirect_stdout): redirect_stdout меняет sys.stdout, не перехватывает subprocess output и имеет process-global/threading ограничения. Поэтому нужен внешний process boundary, а не ещё один Python redirect.
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html): не включать секреты/чувствительные данные в logs, проверять logging failure modes и ограничивать доступ к operational records.
- [Python subprocess](https://docs.python.org/3.12/library/subprocess.html): pipes требуют drain/timeout/cleanup; существующий reviewed transport предпочтительнее нового неограниченного communicate.
- [GitHub-hosted runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners): обычный hosted runner создаётся в новой VM, в отличие от single-CPU container profile. Используется существующий ubuntu-24.04 job, не self-hosted runner. VM lifecycle не является доказательством очистки каждого Docker resource до конца job.

Источники проверяются по официальным docs; это engineering guidance, не certification или доказательство устранения membership inference.

