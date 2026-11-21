# etcd 3.6.17 в рабочем кластере и границы выпуска R1

## Какие байты проверены

В GitHub Actions создан новый одноузловой кластер. Kubernetes сообщил о готовности Pod etcd, а containerd подтвердил манифест Linux AMD64 `sha256:3ced7fbdc4cadcec31ab34a7513bc97be2b70db923e7154e2d88a980016b5e8b` и конфигурацию `sha256:be2dd319600bac16f542b8e46e1b78511c35a31e46829ee9acc82a83c94aa377`. По TLS сервер вернул версию 3.6.17 и идентификатор лидера, совпавший с идентификатором участника. На исходном коде для `main` и в рабочей ветке прошли по 79 проверок службы доверия. [Изменение в main](https://github.com/Abrakadabra124/trusted-mlsecops-platform/pull/9), [проверка main до слияния](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44957210068), [проверка рабочей ветки](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44958011609).

Для трёх исполняемых файлов реестр сохраняет SHA-256 и сведения о сборке. Для внутренних модулей он хранит ревизию исходников и хеши архивов Go proxy. Полная опись воспроизвела 154 строки из исходного отчёта Syft, включая типы, версии, пути и кратность. Из 148 строк Go и 6 строк Debian 13 экземпляров модулей Go используют локальные замены. Они соответствуют пяти различным модулям версии `v3.6.17`. Сводный SHA-256 описи в каноническом представлении реестра равен `96cf1a57ab93e0093a29998a24f67918edf6043226896bc00baba1bad60f7a00`. [Исходники etcd](https://github.com/etcd-io/etcd/tree/0689586e360e2c6b46f95ad5634c25d5fa1683db), [реестр и алгоритм сверки](../../scripts/image_etcd_inventory.py), [процедура для оператора](../operations/image-audit-troubleshooting.md).

## Что показал полный аудит

На чистой ревизии `77aad6341e905aad997457f2d6d829c13683dcd3` пять дополнительных проверок Grype завершились без совпадений. Повторная сверка из опубликованного отчёта подтвердила исходную опись, пять координат, одну базу сканера и исходные находки. Две опубликованные копии JSON совпали, SHA-256 канонических байтов `c2d962d27a4c08e078d30edead59505e87ef6abc00873e76ad6e87cdeb181f12`. База Grype v6.1.10 от 21 ноября 06:20:06 UTC. После удаления проверено отсутствие кластера и контейнера узла. [Полный аудит](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44957782916).

| Область | Измеренный результат |
| --- | --- |
| Работающий etcd | 3 Medium по `GHSA-q7gw-24fr-5p69`, 2 Unknown по `GO-2026-5932`, 0 High и 0 Critical. Решение `inconclusive` |
| Прикладное покрытие работающих образов | 11 из 14 по действующей политике |
| Все компоненты аудита | 389 уникальных идентификаторов, включая 24 Critical и 140 High. Итог `fail` |

Отдельный кандидат etcd включает `golang.org/x/crypto v0.59.0`. В двух сборках без кеша SHA-256 совпал для каждого из трёх исполняемых файлов. На одной базе Grype у исходного образа пять совпадений, у кандидата три. Проверка потребовала обнаружить исходный advisory в обоих затронутых файлах baseline и его отсутствие в образе-кандидате. Отдельный сервер прошёл проверку лидера, запись и чтение ключа, сохранение snapshot и чтение его статуса. Для принятия обновления в рабочий кластер нужны доставка образа по digest, проверка его фактических байтов на узле и повторный полный аудит. [Рецепт на проверенном коммите](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/9fb5a078ab294fca952b6a04df801e7e07cc3101/images/candidates/etcd/Dockerfile), [протокол квалификации](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44958252711).

## Воспроизведение сквозного отказа

На чистом checkout `c30be0ef74ab844697015f495aad1f10e1412c10` получен кандидат `af76ff879973bafd1db2d2d498a4cbeb3599a8af276a3c18b4757fe243764475`. Платформа обучила и оценила модель, затем отказала в выпуске с причиной `release_assurance_required`. С диагностическим допуском прошли 85 проверок HTTP и наблюдения. После остановки исходной БД восстановление в новый том воспроизвело SHA-256 модели `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`. Все 1000 прогнозов совпали с эталоном, максимальная ошибка 0.0. От начала восстановления до сверки прошло 3,078 секунды. В отчёте сохранены `release_ready=false` и `r1_status=incomplete`. [Протокол запуска](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44958011618), [ранбук воспроизведения](../operations/r1-walkthrough.md).

В отдельном чистом Windows checkout того же коммита 49 тестов проверили обработку описи, привязку дополнительных отчётов и сохранение исходных находок. Выполнялись тесты Python с контролируемыми ответами сканера. Покрытие модуля реестра составило 81 из 81 операторов и 22 из 22 ветвей. Для повторения из корня репозитория с установленными зависимостями:

```shell
uv run --locked coverage run --branch --source=scripts.image_etcd_inventory -m unittest scripts.image_etcd_inventory_qualification scripts.image_kubernetes_scans_qualification scripts.image_kubernetes_integration_qualification scripts.image_cilium_join_qualification
uv run --locked coverage report --fail-under=95
```
