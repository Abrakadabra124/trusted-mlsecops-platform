# Статус и границы доказательств

Дата текущей реализации: **2026-10-07**. Стадия: **R1 in progress, developer preview**. R0.2 research/design остаётся исторической основой. Изменения: [CHANGELOG](CHANGELOG.md).

## Реализовано в первом increment

- Frozen synthetic policy, locked Python dependencies, pinned base image и проверка соответствия image текущему source fingerprint.
- Идемпотентный bootstrap с отдельными локальными ключами ролей, inventory и runner, возвращающий inconclusive для ещё не реализованных полных gates.
- Генератор 20 000 строк, split 14 000/3 000/3 000, signed source approval/dataset manifest, проверки схемы, digest, expiry и leakage.
- Linux Docker workers без сети, host mounts, root, capabilities и ключей. Обучение Logistic Regression и ONNX export; scorer считает метрики вне prediction worker и подписывает report.
- Исполняемая qualification: первоначально 65, после bounded transport 74 компонентные проверки, включая три fresh-process обучения, malformed model/protocol, tamper и fail-closed. Исходная платформа не изменена.

Локальный результат: AUPRC 0.9323007296445032 против 0.4073333333333333 у constant-score baseline, 1 222 positive labels из 3 000 holdout rows. Максимальная разница вероятностей между тремя повторами 0.0; Python/ONNX parity error 2.086162567138672e-7. Это synthetic developer evidence, не доказательство пользы для реальных релизов.

Dependency audit проверил 59 установленных пакетов, известных уязвимостей не сообщил. Первый запрос завершился timeout; успешный результат получен повторным полноценным запуском, без отключения проверок. Host-side qualification coverage около 64% combined line/branch, код внутри worker containers этим замером не покрыт. Требование M18 >=95% ещё не выполнено.

## Kubernetes increment

Развёрнут отдельный kind 0.33.0/Kubernetes 1.36.4/Cilium 1.20.2 lab, bootstrap повторён без изменения namespace identity. 52 локальные component checks прошли: реальные role API denials, admission, egress с positive control, readonly/non-root/capabilities, PID/RAM/CPU limits, OOM и deadline. Training и prediction проходят в отдельных Jobs/namespaces, scorer остаётся вне worker. Подробности: [runbook](docs/kubernetes-lab.md). Контрольный HTTP Pod не объявляется настоящим serving service; полные M04/M05/M20 остаются inconclusive.

Kubernetes isolation и настоящий train/evaluate независимо воспроизведены из clean checkout в [успешном run 37668677667](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37668677667), commit `f7cdc5913537f40e904da5aee153f02abc8563f9`. Docker qualification на том же commit: [успешный run 37668677845](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37668677845). Это CI до добавления нового data increment; его результат не переносится автоматически на последующие commits.

## Source lineage и M02

Локально прошли 44 проверки source/intake и executable M02. Source lock, signed snapshot authorization, quarantine, отдельное curator approval и signed lineage связаны с run. Kubernetes demo с `--versioned-data` обучил и оценил candidate с lineage; AUPRC и parity сохранились. [Описание и воспроизведение](docs/data-lifecycle.md). T03 завершена для synthetic-only профиля, T04 остаётся открытой до storage ACL.

DVC 3.67.1 был проверен в spike, но не принят: pip-audit обнаружил CVE-2025-69872 в diskcache 5.6.3, без указанной исправленной версии. Пакеты удалены из active environment/lock; повторный строгий audit не нашёл известных vulnerabilities, ignore не добавлен. [ADR 0005](docs/decisions/0005-data-lineage.md) фиксирует замену одним fixed-step SHA-256 source lock, не ослабляя пороги приёмки.

## Подготовлено исследованием

- Изучены статья PT, 11 страниц предоставленного PDF и изображение ML lifecycle; права третьих лиц сохранены через ссылки/атрибуцию без републикации оригиналов.
- Составлен реестр из 44 источников/записей evidence, включая локальный PDF, новый текст, CyberOrda и отдельные code/evidence/CI ссылки baseline.
- Дополнительно разобраны первоисточники восьми технологических компаний и отраслевых организаций; датированные выводы отделены от переносимых принципов и неприменимого к текущему сценарию LLM-инструментария.
- Сопоставлены DevSecOps baseline, отсутствующие ML-контроли, P0-долги и ограничения локального стенда.
- Подготовлены карта продукта, архитектура, 19 сценариев угроз, 23 критерия приёмки, план на 14-16 недель плюс 25% резерва и 29 задач.
- Добавлены 8 source-to-decision записей с owner, ограничениями и связями до gates/tasks; их структурная связность проверяется кодом.
- В R0 был реализован только документационный валидатор и workflow; с 2026-10-07 добавлен developer runtime, перечисленный отдельно.

## Что не реализовано

MLflow, storage ACL и least-privilege controller, защищённый promotion/verifier service, inference API, poisoning/evasion campaign, inventory/revocation service, drift monitoring и ML restore ещё не реализованы. Kubernetes Jobs и isolation probes не закрывают полный integration scope. M02 работает; полные M01 и M03-M23 остаются inconclusive. T03 завершена только в synthetic scope, остальные 28 задач открыты. Прогресс: [журнал реализации](docs/implementation.md). Обучение маленькой синтетической модели выполнено; дообучение ассистента не выполнялось.

## Что проверяется отдельно

Локальная команда `python scripts/check_docs.py` подтверждает структурную связность документов и ограниченные publication checks. CI повторяет её на опубликованном commit. Актуальный результат смотрите в [GitHub Actions](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions); наличие workflow-файла само по себе не доказывает успешный запуск.

В исходной платформе через GitHub API проверен успешный [run 37211112894](https://github.com/Abrakadabra124/enterprise-devsecops-platform/actions/runs/37211112894). Локальные инфраструктурные результаты от 2026-10-04 используются как историческое evidence, не как новые измерения 2026-10-06.

### Локальная проверка R0.2

2026-10-06 проверены 29 publication files, 24 Markdown-документа, 127 локальных ссылок, 44 source IDs, 23 gate IDs, 29 открытых задач и 8 decision records. Граф зависимостей всех 29 задач не содержит циклов. Это структурные результаты, не независимый научный review.

Дополнительно выполнены 35 отрицательных проверок валидатора через временную подмену чтения в памяти: неверные JSON/schema/date/scope, повтор ключа/ID, неизвестные sources/tasks, gate без связанной задачи, отсутствующий owner/limitation, выход artifact path за репозиторий, ложный runtime status, битые ссылки/якоря, закрытая research-only задача, marker конфликта, незакрытый code block и синтетический token marker. Все 35 отвергнуты. Harness выполнялся локально, не добавлен как постоянная test suite; обычный CI запускает структурный validator, не повторяет эти mutation cases и не вычисляет ML coverage.

## Ограничения исследования R0

Не измерялись актуальные ресурсы PC/кластера, не выбирался настоящий бизнес-dataset, не выполнялись новые security/ML эксперименты, не проверялось соответствие применимому законодательству. Веб-документация `latest` может измениться. Отдельные недоступные страницы обозначены в [реестре](docs/sources.md), выводы не основаны на их предполагаемом содержимом. Обзор не является исчерпывающей оценкой мирового рынка; публикации компаний не заменяют независимую проверку нашего решения.

## Следующий допустимый шаг

Продолжить активную цель R1: довести T01-T02/T04 до полной приёмки, реализовать storage permissions и least-privilege controller, затем MLflow и независимый evaluation budget по зависимостям. DVC не является обязательным инструментом после security ADR; требования воспроизводимости сохраняются. Не публиковать trusted release на основании зелёной developer qualification.
