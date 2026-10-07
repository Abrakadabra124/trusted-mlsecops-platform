# Реализация R1

Начата 2026-10-07 по прямому запросу владельца. Исследовательская цель R0 завершена; теперь реализуется R1. Этот файл фиксирует решения текущей итерации, не заменяет исходные 23 gates.

## Порядок

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

## Текущий проверяемый increment

Команды запуска находятся в [README](../README.md). `mlsecops.qualification` - часть исполняемого acceptance-инструментария продукта, не замена полной приёмке. Она проверяет component boundaries и численное повторение; полные gates пока не переводятся в pass.

Три fresh-process runs дали одинаковые вероятности; AUPRC 0.9323007296445032, constant-score baseline 0.4073333333333333, parity error 2.086162567138672e-7. Точность на синтетике подтверждает механическую работоспособность, не бизнес-utility. Подписанный report имеет `release_status=unapproved`.

DSSE (Dead Simple Signing Envelope) связывает тип документа и точные bytes с Ed25519 подписью библиотеки cryptography. Это ограниченный single-signature application profile, не собственный криптографический алгоритм и не production KMS. Trust roots задаются при bootstrap отдельно от входящего envelope. Локальные ключи защищены от контейнерных workers отсутствием mounts, но не от администратора host.

Теги images сначала разрешаются в immutable image ID. Затем контроллер сравнивает label source fingerprint с текущими Python-файлами, policy, Dockerfile и lockfile. Stale image отвергается с требованием rebuild; image label не объявляется криптографической подписью или независимой build attestation.

Dataset/model bytes проверяются перед использованием. Candidate loader не загружает pickle; ONNX parser запускается в resource-limited worker, запрещает external tensors, вложенные graphs/functions и операторы вне ограниченного allowlist. Это проверка формата, не универсальный model malware scanner.

Осталось: полноценные M-gates, DVC, MLflow, storage-role ACL, least-privilege controller, dataset intake API, holdout query budget, adversarial campaign, promotion/revocation, online serving, monitoring, recovery и >=95% security branch coverage. Goal остаётся активной, component increments не считаются R1 release.

## Второй increment: Kubernetes

Принят [ADR 0004](decisions/0004-isolated-kubernetes-lab.md), создан отдельный cluster. [Runbook](kubernetes-lab.md) объясняет две реализации executor и повторение из clean checkout. 52 isolation component checks прошли локально, Docker qualification после интеграции сохраняет 65 успешных checks. Настоящие Jobs обучают и оценивают ту же синтетическую модель. Действующая foundation не изменяется.

Отрицательные проверки выявили и помогли исправить реальные интеграционные ошибки: минимальное число log files kubelet должно быть 2; containerd добавляет вложенный OCI index; Kubernetes объединяет stderr/stdout, поэтому ONNX telemetry initialization нарушала strict protocol; deadline controller может удалить Pod до финального чтения, поэтому runner сохраняет последнюю наблюдаемую identity и отдельно подтверждает удаление. Проверка PID limit изменена с неверного leaf-file assumption на фактическое ограниченное создание процессов. Ошибки не замаскированы отключением контроля.

## Проверенные технические основания реализации

- [uv Docker integration](https://docs.astral.sh/uv/guides/integration/docker/): image и dependencies фиксируются, установка не происходит внутри training worker.
- [scikit-learn persistence](https://scikit-learn.org/stable/model_persistence.html): runtime не загружает pickle; ONNX применяется после проверки ограниченного профиля.
- [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md): подпись связывает тип и точные bytes payload; доверенные ключи определяются вне envelope.
- [ONNX external data](https://onnx.ai/onnx/repo-docs/ExternalData.html): external tensor data запрещены в первом профиле.
- [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/): лимиты проверяются в реальном runtime, не только в command arguments.
