# Приватный канал между CI jobs

Неделя 13, T21. Ответственный: владелец репозитория и оператор pipeline.
Область: отдельный canary, который проверяет передачу шифрованного тестового
пакета между двумя GitHub-hosted jobs. Это не передача ML-кандидата, не M18
и не завершённый R1. Оригинальные candidate adapters пока допускают только
прежний public run owner и не используются этим workflow.

## Устройство и границы

[Workflow](../../.github/workflows/private-channel.yml) запускается вручную только
в `Abrakadabra124/trusted-mlsecops-ci-private`, ID `1465012664`. Это приватная
копия точного commit публичной платформы. [Driver](../../scripts/ci_private_channel.py)
проверяет фактические repository/run/attempt, private visibility, отсутствие
fork, Git SHA и наличие того же SHA в публичном исходном репозитории.
Не подменять `GITHUB_REPOSITORY` ради прохождения проверок.

AES-GCM шифрует фиксированный canary существующим [transport core](ci-transfer.md).
Его image/candidate/proposal hashes - явно синтетические идентификаторы, не
доказательство наличия образа или модели. Ciphertext передаётся через private
artifact, а ожидаемые context/pin через зависимость `needs.producer.outputs`.
Ключ берётся из временного `CHANNEL_AES_KEY` repository secret. Личный токен
владельца не передаётся в CI; `GITHUB_TOKEN` ограничен execution repository.

Producer и receiver имеют `contents: read`, `actions: read`. Только cleanup
получает `actions: write`. Upload использует штатную runtime identity job.
Скачивание ограничено одним ID после проверки его owner, name и размера.
Ожидаемый объект меньше 64 KiB; после загрузки чтение bytes тоже ограничено.
Это фиксированный canary от доверенного producer, не универсальный безопасный
распаковщик произвольных архивов. Payload/keys из реального проекта здесь нет.

## Прежде чем запускать

1. В авторизованном GitHub UI проверить account Actions budget `$0` со статусом
   `Usage blocked` и наличие included compute/storage. Этот статус относится
   к платному использованию; фактическую доступность бесплатного запуска покажет CI.
   Не увеличивать бюджет. Персональные billing details хранить вне Git.
2. Опубликовать проверенный source commit в публичной платформе. При выключенных
   Actions приватного репозитория отправить **тот же commit** на
   `qualify/private-channel-native` и назначить её default branch. Не генерировать
   новый commit с копией файлов: SHA должен совпадать.
3. Проверить приватность, числовой ID и список collaborators. Включить только
   нужный workflow. Сначала read-only metadata, затем scoped изменения настроек.
4. Сгенерировать новый 32-byte AES key средствами ОС и установить его как
   `CHANNEL_AES_KEY` только этого репозитория, передав через stdin. Не помещать
   значение в аргументы shell, файл Git, job output, artifact или чат.
5. Убедиться, что другой запуск этого workflow не использует ключ. Dispatch
   один раз на точной ветке. Не создавать новый run из-за timeout наблюдателя.

Диагностика без изменения состояния:

```text
gh api repos/Abrakadabra124/trusted-mlsecops-ci-private
gh run list --repo Abrakadabra124/trusted-mlsecops-ci-private --workflow private-channel.yml
gh run view RUN_ID --repo Abrakadabra124/trusted-mlsecops-ci-private --json status,conclusion,jobs,headSha
gh api repos/Abrakadabra124/trusted-mlsecops-ci-private/actions/runs/RUN_ID/artifacts
gh secret list --repo Abrakadabra124/trusted-mlsecops-ci-private
```

Не публиковать raw metadata/logs без отдельной проверки. Публичное evidence
содержит только source commit, статусы jobs, счётчики и ограничения результата.

## Успешное конечное состояние

Producer подготовил ciphertext. Receiver подтвердил его по внешним pins и
реально отклонил семь мутаций: ciphertext с новым pin, неверный ключ, неверный
pin, другой run, attempt, phase и другое разрешённое repository.
После receiver исходный encrypted файл удалён. Cleanup проверил metadata
единственного артефакта, удалил его по ID, получил 404 для этого ID и затем
успешно прочитал пустой список artifacts того же run. Один 404 сам по себе
не доказывает очистку, поскольку может означать потерю доступа.

После terminal state оператор удаляет временный repository secret и повторяет
`gh secret list`. Не удалять ключ, пока активный разрешённый run его использует.
Отдельно проверить отсутствие owned artifacts через CLI. Retention один день
служит запасным ограничением, но не заменяет доказанное немедленное удаление.

## Отказ и восстановление

| Симптом | Действие |
| --- | --- |
| Job не начинается, spending/quota error | Проверить included usage и hard zero budget. Не обходить запрет расходов и не покупать минуты. Сохранить блокер. |
| `inconclusive` до upload | Сверить repo ID/private flag, workflow path, branch, source SHA и clean checkout. Не подменять owner/env и не загружать пакет вручную в public repo. |
| Отказ authentication/pin/context | Сохранить исходные producer expectations приватно. Не вычислять новые доверенные pins из отказавшего artifact. Для новой попытки использовать новый key и новый run. |
| API 403, timeout, rate limit | Считать результат неопределённым. Не трактовать ошибку как отсутствие артефакта. Повторить read-only проверку после восстановления доступа. |
| Cleanup обнаружил чужой owner/name/attempt | Ничего не удалять по широкому фильтру. Проверить конкретные run и artifact IDs, эскалировать владельцу. |
| Run отменён до cleanup | Остановить только этот run, дождаться terminal state. По точному run ID проверить artifact ownership и удалить только принадлежащий этой попытке объект. Проверить ID 404 и пустой доступный список, затем удалить временный secret. |

GitHub/account/repository administrators остаются доверенными. Изменение
visibility злонамеренным владельцем между проверкой и upload не предотвращается
этим canary. Удаление artifact не является secure erase у провайдера; billing
accrual до удаления тоже не аннулируется. При проблеме rollback - выключить
этот workflow и прекратить handoff, сохранив уже проверенный public source.

## Проверка кода

[Qualification](../../scripts/ci_private_channel_qualification.py) использует
реальный AES, controlled GitHub API fixtures и временные каталоги. Live API,
repository policy и два независимых hosted jobs этим unit-тестом не доказаны.

```text
python -B -W error -m unittest scripts.ci_transfer_qualification scripts.ci_private_channel_qualification
python -B scripts/check_docs.py
```

Нужен отдельный coverage порог 95% statements и 95% branches каждого модуля.
Native результат и точный source публикуются после фактического запуска.
