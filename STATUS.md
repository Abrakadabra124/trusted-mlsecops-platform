# Статус и границы доказательств

Дата текущей реализации: **2026-10-08**. Стадия: **R1 in progress, developer preview**. R0.2 research/design остаётся исторической основой. Изменения: [CHANGELOG](CHANGELOG.md).

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

Локально прошли 44 проверки source/intake и executable M02. Source lock, signed snapshot authorization, quarantine, отдельное curator approval и signed lineage связаны с run. Kubernetes demo с `--versioned-data` обучил и оценил candidate с lineage; AUPRC и parity сохранились. [Описание и воспроизведение](docs/data-lifecycle.md). T03 завершена для synthetic-only профиля; последующее завершение T04/M03 описано отдельно ниже.

Clean checkout подтверждён на commit `8857eba675bdb50a4e8ceb9e664019a9a3d44ac7`: [runtime/M02 run 37672915427](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37672915427), [Kubernetes versioned demo run 37672915437](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37672915437) и documentation CI завершились success. Это приёмка перечисленного scope, не всех 23 gates.

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

MLflow, least-privilege controller, защищённый promotion/verifier service, inference API, poisoning/evasion campaign, inventory/revocation service, drift monitoring и полный ML release/serving restore ещё не реализованы. SQL backup/restore проверен отдельным компонентом ниже. Kubernetes Jobs и isolation probes не закрывают полный integration scope. M02 и M03 работают; полные M01 и M04-M23 остаются inconclusive. T03/T04 завершены только в synthetic scope, остальные 27 задач открыты. Прогресс: [журнал реализации](docs/implementation.md). Обучение маленькой синтетической модели выполнено; дообучение ассистента не выполнялось.

## PostgreSQL storage increment

Локально работает отдельный PostgreSQL 18.6: mTLS/TLS 1.3, шесть SQL identities, девять content-addressed tables, append-only runtime privileges, checksum migration и собственный persistent volume. Прошли 367 component checks, включая действительные SQLSTATE denials, wrong/expired certificates и positive controls. Повтор bootstrap сохранил container/keys; idle memory snapshot около 22.4 MiB при лимите 512 MiB, это не worst-case замер. [Воспроизведение и ограничения](docs/storage-lab.md).

Clean checkout component подтверждён на commit `6c289872ec23093493a76b73b4f94f68acdf941a`: [storage run 37676298502](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37676298502), [developer run 37676298438](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37676298438), [Kubernetes run 37676298377](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37676298377) и documentation CI завершились success. Это CI до следующего SQL pipeline slice.

Обычная bridge network публикует БД только на loopback; outbound БД не запрещён. `--internal` не обеспечил действительный host port mapping на этой среде, что выявлено проверкой, а не скрыто. Worker deny policies не менялись.

Новый SQL pipeline локально обучил и оценил модель через отдельные publisher/scorer credentials. Publisher читает train/validation, scorer - holdout; результат хранится в candidates/evaluations, signed report связан с точными dataset/candidate refs и lineage. 26 integration checks прошли в Docker profile, отдельный SQL demo прошёл и с Kubernetes Jobs. AUPRC `0.9323007296445032`, parity max error `2.086162567138672e-7`, release остаётся `unapproved`. Host orchestrator пока привилегирован, независимость controllers и полные M04/M20 не заявляются. M03 принят отдельным последующим gate ниже.

SQL pipeline независимо повторён на commit `18161b8c02499376d3ddd9a276f8aee92c367994`: [storage + pipeline run 37678040396](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37678040396), [legacy developer run 37678040284](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37678040284), [Kubernetes regression run 37678040291](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37678040291) и documentation CI завершились success. Storage workflow строит новую worker image и выполняет настоящие training/evaluation, не использует готовую модель. Kubernetes CI в этом commit проверяет старый versioned-filesystem demo; SQL+Kubernetes подтверждён отдельно локальным запуском, не этим CI job.

## Исполняемый M03

Локально прошёл полный synthetic-profile M03: 36 Linux файловых fixtures, 367 реальных SQL/TLS checks, 26 SQL pipeline checks и 2 сквозные проверки, всего 431 case. Approved dataset reference и hashes split/manifest/lineage/approval до и после denials сохранились. Подмены bytes, manifest/signature, split, stale source, missing objects, traversal и реальные symlink escape отклонены. [Покрытие, команды и ограничения](docs/integrity-gate.md).

Windows host не даёт текущему процессу symlink privilege, поэтому suite выполняется в offline Linux container, без изменения Windows security settings и без skip-as-pass. Все component checks запускаются заново. Отсутствие storage prerequisites = inconclusive, неправильный отказ = fail. T04 закрыта только в этом профиле; полномочия host administrator, независимость controllers и защита от semantic poisoning не объявляются решёнными.

Clean checkout M03 подтверждён на commit `534ed9e23bdd27a607b6976e15c97f3db20a0e77`: [storage/M03 run 37683278769](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37683278769) завершился success, в опубликованном report `status=pass`, 431 case и тот же source SHA-256. [Developer regression 37683278837](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37683278837), [Kubernetes regression 37683278782](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37683278782) и [documentation CI 37683278900](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37683278900) также success. CI создаёт новые ключи/dataset references; совпадение source bytes не означает совпадение всех identities или bit-for-bit container builds.

В этом increment container image audit не завершён: три запроса официального Grype updater закончились TLS/network timeout. Уязвимости образов не подсчитаны, отсутствие базы не записано как «0 findings». Python dependency audit и integrity gate не заменяют image scan; M01 и trusted release остаются незавершёнными.

## Согласованный backup и storage recovery

Реализованы [backup/restore CLI](docs/storage-recovery.md): native PostgreSQL exported snapshot для dump и ledger, DSSE manifest, внешние public trust roots, ограниченный data-only archive и восстановление только в новую БД. Исходные CA, signing keys, container и data не заменяются. Restore создаёт новую SQL identity/storage и не разрешает serving или promotion.

Локально 2026-10-07 прошли 430 checks, включая 367 повторных SQL/TLS probes уже восстановленного экземпляра. Настоящая конкурентная вставка не попала в более ранний snapshot. Ledger всех девяти таблиц совпал; 31 объект / 3 926 350 bytes восстановлены из archive 7 858 806 bytes. Storage restore 11.109 s, до 1 000 golden predictions и проверки evaluation signature 14.562 s, максимальная разница scores 0.0. Images уже были доступны на host; это не cold-machine или production RTO.

Дополнительно оставлен операторский recovery instance `.runtime/recovery/storage-01`, отдельный endpoint `127.0.0.1:15440`. Qualification создавала другой временный экземпляр и удалила только его проверенные owned resources. Source idle transactions после проверки: 0. Отчёты и dumps не публикуются как raw artifacts в Git; CLI evidence содержит только очищенные метаданные.

M17 остаётся inconclusive: нет полного release/serving recovery, динамической проверки отзыва через trust service, ежедневного расписания и offsite copy. Возраст копии <=24 h проверяется при restore, но это не доказательство ежедневного RPO. Ключи подписи не входят в backup и требуют отдельной custody/recovery процедуры.

Clean checkout подтверждён на commit `6722a0355062a3f1aca01ffb9445ebc0e1d1f1f1`: [storage + recovery run 37686666806](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37686666806) прошёл M03 (431 case) и recovery component (430 cases). CI восстановил 16 объектов из 7 813 539-byte archive; до golden verification 5.325799 s, 1 000 scores совпали. Число объектов отличается от локального workspace с накопленной историей. [Developer 37686666906](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37686666906), [Kubernetes 37686666871](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37686666871) и [documentation 37686666742](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37686666742) также завершились success. Эти результаты не закрывают остальной R1 scope.

## Закрытый storage внутри Kubernetes

По [ADR 0008](docs/decisions/0008-private-cluster-storage.md) развёрнут отдельный PostgreSQL profile: ClusterIP, DNS-bound mTLS/TLS 1.3, шесть SQL identities в отдельных namespaces, server deny-egress и restricted non-root StatefulSet с retained PVC. Host SQL source и operator restore instance не заменяются. [Команды и границы](docs/private-cluster-storage.md).

Локально 2026-10-08 (Europe/Moscow) прошли **436 component checks**: 378 SQL/TLS/runtime assertions в шести role Pods, реальные API denials, network negatives с положительными controls, повтор bootstrap, spec/config negatives и сохранение bytes после пересоздания PostgreSQL Pod на прежнем томе. Все IDs checks уникальны. Проверены актуальный image config digest и отсутствие оставшихся probe Jobs; в БД после qualification нет её test records. Source fingerprint `812d9caed8d9007bc67c01b761cd7007b89013b3e8c37a032877b310839835f4`.

Обнаружена и исправлена Linux-проблема общего libpq client: `/dev/null` в качестве password file выдавал stderr warning и ломал strict JSON чтение Kubernetes logs. Теперь используется явно заданный отсутствующий path в role bundle; существующий файл там отвергается. TLS verification не отключалась, посторонний текст из logs не фильтровался. После shared-client изменений M03 повторно прошёл 431 case; developer suite на финальном source fingerprint прошёл 74 cases.

Clean checkout подтверждён на commit `6577de7bc181dbdb462c08fa8eebff00f57a1e0a`: [Kubernetes run 37690561970](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37690561970) завершился success, report содержит 436 уникальных успешных cases и тот же source fingerprint. В этом же job прошли базовые isolation probes и настоящий train/evaluate. [Storage regression 37690562000](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37690562000) подтвердил M03 (431 case) и recovery (430 cases); [developer 37690561976](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37690561976) и [documentation 37690562024](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37690562024) также success. CI создаёт другие ключи, PVC UID и image config digest; это воспроизведение проверяемого поведения, не bit-for-bit builds.

Это подготовленный private storage, не работающие publisher/scorer controllers. Signed migration history добавлена следующим increment ниже; controller RBAC и постоянный serving ещё впереди. Нет HA, KMS, автоматической ротации сертификатов или подтверждённого image vulnerability scan. Namespace quotas не доказывают безопасную суммарную concurrency: probes последовательны, перед постоянными controllers нужны measured requests/limits. M04/M20 и R1 остаются открытыми.

## Подписанная migration history в Kubernetes

Реализован [snapshot import](docs/cluster-storage-migration.md) с внешними trust roots, native advisory lock, maintenance barrier и подписанными intent/receipt. Перенос не меняет исходную БД, не переключает demo и не выдаёт release-ready. Publisher/scorer Pods читают артефакты под собственными mTLS identities; signer private keys и host kubeconfig им не передаются.

Локально 2026-10-08 (Europe/Moscow) прошли **497 уникальных checks**. Перенесены 40 объектов / 3 939 142 bytes из archive 7 885 324 bytes. Проверены настоящий сбой перед записью receipt после commit, закрытый доступ обычного клиента, resume без второй копии, read-only повтор и отказ перезаписывать поздние данные. Повторные 436 storage checks входят в эти 497, их нельзя складывать как независимое покрытие. После замены PostgreSQL Pod ledger и volume UID сохранились; source identity/ledger до и после migration совпали.

1 000 predictions из прочитанных в Kubernetes model/validation bytes совпали с сохранёнными scores: max error **0.0**. Training image `sha256:d79d78d784516d77f48a653c4ce1db8cc2ab31c0a0059de155e73975d365d422` и verification image `sha256:555f547d95418b4752a09f795c24e2af304f249681e3a0afd2bbeedb200669a7` различаются: frozen backup подготовлен до исправления transport. Это успешная compatibility check, не три M06 повтора в одинаковой среде. Проверенный source fingerprint: `e9fffda788c86d99539c0d1284bb8d474c9c6b97e0ab39182e2db44054f8838b`.

При отладке обнаружено зависание `kubectl exec` на большом stdin: `pg_restore --list` завершал чтение после TOC. Ограниченный wrapper теперь дочитывает вход, сохраняет native exit status и не скрывает stderr. Первая попытка остановилась до изменения target; данные не удалялись для повторного запуска. Qualification воспроизводит этот путь настоящим archive, а не mock успешного import.

После изменения shared SQL-session helper повторно прошёл storage recovery suite: 430 cases. Developer regression на том же source fingerprint прошёл 74 cases. Дополнительный live negative с неверным 1 MiB archive подтвердил native-error propagation и неизменность target ledger; он не включён в число 497. Документационный validator прошёл 102 publication files / 40 Markdown documents / 228 local links, Ruff и diff whitespace checks также прошли. Эти проверки не являются полной M18 coverage или image security audit.

Это component progress T05/T26 и T20, не приёмка полных M04/M17/M20. Least-privilege controllers, независимое approval, serving/revocation и остальные R1 gates остаются открытыми. Новый CI workflow запускает migration из clean checkout; его наличие не считается успешным CI до проверки run.

## Что проверяется отдельно

Локальная команда `python scripts/check_docs.py` подтверждает структурную связность документов и ограниченные publication checks. CI повторяет её на опубликованном commit. Актуальный результат смотрите в [GitHub Actions](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions); наличие workflow-файла само по себе не доказывает успешный запуск.

В исходной платформе через GitHub API проверен успешный [run 37211112894](https://github.com/Abrakadabra124/enterprise-devsecops-platform/actions/runs/37211112894). Локальные инфраструктурные результаты от 2026-10-04 используются как историческое evidence, не как новые измерения 2026-10-06.

### Локальная проверка R0.2

2026-10-06 проверены 29 publication files, 24 Markdown-документа, 127 локальных ссылок, 44 source IDs, 23 gate IDs, 29 открытых задач и 8 decision records. Граф зависимостей всех 29 задач не содержит циклов. Это структурные результаты, не независимый научный review.

Дополнительно выполнены 35 отрицательных проверок валидатора через временную подмену чтения в памяти: неверные JSON/schema/date/scope, повтор ключа/ID, неизвестные sources/tasks, gate без связанной задачи, отсутствующий owner/limitation, выход artifact path за репозиторий, ложный runtime status, битые ссылки/якоря, закрытая research-only задача, marker конфликта, незакрытый code block и синтетический token marker. Все 35 отвергнуты. Harness выполнялся локально, не добавлен как постоянная test suite; обычный CI запускает структурный validator, не повторяет эти mutation cases и не вычисляет ML coverage.

## Ограничения исследования R0

Не измерялись актуальные ресурсы PC/кластера, не выбирался настоящий бизнес-dataset, не выполнялись новые security/ML эксперименты, не проверялось соответствие применимому законодательству. Веб-документация `latest` может измениться. Отдельные недоступные страницы обозначены в [реестре](docs/sources.md), выводы не основаны на их предполагаемом содержимом. Обзор не является исчерпывающей оценкой мирового рынка; публикации компаний не заменяют независимую проверку нашего решения.

## Следующий допустимый шаг

Продолжить активную цель R1: довести T01-T02 до полной приёмки, реализовать least-privilege controllers и связать проверенные storage/API/network identities, затем MLflow и независимый evaluation budget по зависимостям. DVC не является обязательным инструментом после security ADR; требования воспроизводимости сохраняются. Не публиковать trusted release на основании зелёных M02/M03 или developer qualification.
