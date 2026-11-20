# Один публичный образ для трёх заданий кампании

В `.github/workflows/candidate-cross-job.yml` задание `image` один раз собирает
образ из разрешённых файлов Git-коммита. Задания `producer`, `shared` и
`serving` получают его на отдельных свежих runners до работы с приватными
данными. Ответственный за интеграцию задаёт зависимости от `image` у каждого
читателя и запускает `image_cleanup` после завершения всех трёх читателей.

## Допуск

Каждая команда требует `workflow_dispatch` на ветке `qualify/candidate-cross-job`
публичного репозитория `Abrakadabra124/trusted-mlsecops-platform` с ID
`1407811916`. Требуются GitHub-hosted Ubuntu 24.04 x86_64, чистый checkout по
`github.sha` и совпадение SHA workflow с HEAD. Адаптер повторно читает
публичные метаданные репозитория и запуска, включая исходный репозиторий, событие,
путь workflow, номер попытки и состояние `in_progress`. Для сборки и загрузки
нужен классический Docker image store с драйвером `overlay2`.

Передавайте `GH_TOKEN` из `github.token` только шагам, которым нужен доступ к
публичному API. Для чтения нужны `contents: read` и `actions: read`.
Право `actions: write` для удаления требуется только `image_cleanup`. Используйте
checkout без сохранения credentials и закреплённые по SHA версии actions из
[процедуры переноса образа](source-image-transfer.md).

## Порядок шагов

1. В `image` выполните `python -B -W error -m scripts.ci_campaign_image build`.
   Шаг пишет в `GITHUB_OUTPUT` значение `receipt` с commit SHA, fingerprint
   исходников, config image ID, SHA-256 и размерами gzip и tar.
2. В этом же задании через `upload-artifact` опубликуйте единственный файл
   `.runtime/source-image/image.tar.gz` под именем
   `source-image-${{ github.run_id }}-${{ github.run_attempt }}`. Укажите
   `include-hidden-files: true`, `if-no-files-found: error`, `overwrite: false`,
   `retention-days: 1` и `compression-level: 0`. Свяжите выходы задания
   `image` с шагами сборки `prepare` и загрузки `upload` по таблице ниже.

   | Выход задания | Значение |
   | --- | --- |
   | `receipt` | `${{ steps.prepare.outputs.receipt }}` |
   | `artifact` | `${{ steps.upload.outputs.artifact-id }}` |

3. В каждом читателе задайте `SOURCE_IMAGE_RECEIPT` из `needs.image.outputs.receipt`
   и `SOURCE_IMAGE_ARTIFACT_ID` из `needs.image.outputs.artifact` через окружение
   шагов `precheck` и `receive`. Выполните
   `python -B -W error -m scripts.ci_campaign_image precheck`. Команда сверяет
   метаданные конкретного artifact, включая `workflow_run.head_branch`, ID запуска,
   SHA и текущую попытку в имени. Она также создаёт workspace этого задания и
   независимую запись владельца в `RUNNER_TEMP`.
4. Только после успешного `precheck` вызовите `download-artifact` с
   `artifact-ids: ${{ needs.image.outputs.artifact }}`, `merge-multiple: true`
   и `path: .runtime/source-image`. Выполните
   `python -B -W error -m scripts.ci_campaign_image receive`. До `docker load`
   команда сверяет исходники, оба хеша и размера, manifest и config ID архива.
   Предельные размеры составляют 385 MiB для GitHub artifact, 384 MiB для gzip
   и 2 GiB для tar. На свободный тег `trusted-mlsecops:dev` назначается
   проверенный image ID. После изолированного запуска `worker --help` по ID
   команда заново проверяет тег, платформу, пользователя и source labels.
   При коде выхода 0 обычный адаптер задания может использовать этот тег.
5. В `image` и каждом читателе назначьте завершающий шаг с `if: always()` и
   командой `python -B -W error -m scripts.ci_campaign_image local-cleanup`.
   Он удаляет временные файлы переноса по локальной записи владельца. Образ
   доступен обычному адаптеру до утилизации runner.
6. В отдельном `image_cleanup` с `if: always()` выполните
   `python -B -W error -m scripts.ci_campaign_image cleanup`. Команда проверяет
   полный список artifacts запуска и данные конкретного ID, повторяет проверку
   полномочий перед удалением и подтверждает HTTP 404 по ID и доступный пустой
   список. Если список уже пуст, результат содержит `artifacts_deleted: 0`.

## Отказ и проверка

При `inconclusive` шаг возвращает код 1. Остановите зависимые шаги. Сверьте
событие, SHA checkout и workflow, роль, run ID, попытку и outputs задания
`image`. При конфликтующем теге или записи владельца используйте свежий runner.
При постороннем artifact или остатке другой попытки cleanup прекращает работу
до удаления. Владелец workflow проверяет список и срок хранения. Повторная
кампания получает собственные outputs.

Публичная загрузка ограничена указанным gzip. Маркеры владельца, ключи,
candidate packets и первичные отчёты относятся к другим шагам и каталогам.
Локальная проверка воспроизводит приёмку через реальные функции чтения архива
и подставные Docker и GitHub API. Результат hosted workflow и приёмка R1
требуют отдельных свидетельств.

```bash
python -B -W error -m unittest scripts.ci_campaign_image_qualification scripts.ci_source_image_qualification scripts.ci_source_image_native_qualification
```
