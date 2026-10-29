# Инициализация CPU runtime до чтения модели

## Симптом, причина и границы

На `45361ca` [CI 40901465590](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40901465590) остановился на запуске свежего worker для signed approval expiry: `worker-start / load / serving_attach_ort_device_warning`. SQL stop и cluster cleanup success. Сценарий unexpired replay не был достигнут; успешные 229 Linux method executions не доказывают его native приёмку.

Предыдущая настройка global logger перед `InferenceSession` помогла пройти run 40898945667, но не покрыла импорт. В [Python binding ONNX Runtime 1.30.0](https://github.com/microsoft/onnxruntime/blob/v1.30.0/onnxruntime/python/onnxruntime_pybind_module.cc) `CreateInferencePybindStateModule` вызывает `CreateOrtEnv` с WARNING ещё до появления Python setter. В [device discovery](https://github.com/microsoft/onnxruntime/blob/v1.30.0/onnxruntime/core/platform/linux/device_discovery.cc) `GetPciBusId` при нестандартном имени виртуального устройства пропускает необязательный PCI identifier и возвращает OK. Такая диагностическая строка найдена в приватном log прежнего runner. Все исторические generic failures этим автоматически не объясняются.

## Исправление

[Bootstrap](../../mlsecops/runtime_bootstrap.py) вызывается только из свежего Linux serving worker, после запрета core dumps и до чтения входного кадра. Таймаут 120 s действует уже во время импорта; родитель сохраняет свой меньший timeout. Предзагруженный ORT и версия, отличная от pinned 1.30.0, отвергаются.

На короткое время доверенного импорта native stderr направляется в анонимный `memfd`. Он живёт в памяти и освобождается при закрытии дескрипторов; файла в workspace нет. Soft `RLIMIT_FSIZE` ограничен 4096 bytes, hard limit не меняется, прежний более строгий soft limit не повышается. [Linux memfd](https://man7.org/linux/man-pages/man2/memfd_create.2.html) и [RLIMIT_FSIZE](https://man7.org/linux/man-pages/man2/getrlimit.2.html) дают эту механику без reader thread или постоянного log file.

Принимаются пустая диагностика или только полные строки известного WARNING `GetPciBusId` о пропуске PCI identifier в `/sys/devices/`. Формат, уровень, функция, ожидаемый шаблон PCI и допустимые символы проверяются целиком; разрешена только точная штатная ANSI-обёртка. Неизвестная строка, ERROR, неполная строка, переполнение, ошибка импорта, настройки logger или восстановления дают отказ. Полный буфер отвергается, даже если его префикс выглядит допустимым. Приватные пути не публикуются.

После импорта global logger переводится в ERROR, stderr и soft limit восстанавливаются, все временные descriptors закрываются. Только затем worker читает и проверяет модель. Во время model load/prediction stderr снова проходит обычный строгий transport; permissive режим для модели не введён. Это Linux startup adapter для pinned CPU runtime, не универсальная обёртка чужих плагинов и не средство принимать произвольные предупреждения.

## Диагностика и восстановление

Ответственный - владелец disposable qualification. На Windows выполнять только pure/mocked проверки. Linux fd/limit tests и инфраструктурный запуск выполняются в разрешённом GitHub-hosted CI.

1. Проверить конкретный commit и terminal state существующего run; сохранить приватный log в `.runtime/evidence`. Ошибка чтения статуса не является основанием для повторного dispatch.
2. Сопоставить stage и finite startup cause. `serving_worker_rejected` после bootstrap не доказывает проблему модели: проверить pinned runtime, раннюю инициализацию, неизвестные diagnostics и поддержку Linux primitive. Не публиковать raw stderr.
3. Запустить `python -m unittest scripts.runtime_bootstrap_qualification.DiagnosticTests scripts.runtime_bootstrap_qualification.BootstrapBoundaryTests scripts.worker_privacy_qualification scripts.serving_session_qualification scripts.model_contract_qualification`. На Windows проверены 43 methods. Два новых boundary tests были RED до изменения.
4. В Linux workflow запустить `python -m unittest scripts.runtime_bootstrap_qualification`. Native tests проверяют настоящий fd2/memfd/limit, ошибки import/setup/restore, overflow, меньший limit, отсутствие descriptor leaks и свежий реальный CPU import. До результата CI это подготовленные тесты, не проверенное Linux evidence.
5. Сквозной запуск обязан пройти actual refusal, обычный controlled inference, expiry/renewal, unexpired replay и trust faults. Только его полный результат вместе с cleanup подтверждает integration данного commit.
6. При новом unknown warning остановить qualification и исследовать его источник. Не расширять whitelist по substring, не направлять stderr в `/dev/null`, не удалять input validation и не повышать таймаут ради зелёного статуса.
7. Rollback - возврат code change в отдельном commit с сохранением failed evidence. Он возвращает прежнее строгое поведение и может вернуть отказ при известном предупреждении; не считать rollback восстановлением работоспособности без повторной проверки. Если stderr/limits невозможно восстановить, процесс завершается, его нельзя переиспользовать.

Полные M11/CP3/R1 остаются открыты. Ни известное предупреждение, ни успешный import не подтверждают release assurance, независимый review или production readiness.
