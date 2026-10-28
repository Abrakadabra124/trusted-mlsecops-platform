# PB-08 / RB-15/16/17: poisoning campaign

Ответственные: ML owner и security reviewer, для runtime failure также platform operator. Это лабораторное исследование, не production incident и не атака сторонних сервисов.

## Исполняемый M08 и привязка кандидата

Ответственный - оператор CP2 вместе с ML/security reviewer. Симптом интеграционного разрыва: component campaign существовала, но `acceptance --gate M08` возвращал placeholder без выполнения. Добавлены fresh dispatch, проверка actual candidate и повторное чтение evidence. Это исправление отсутствующей связи, а не устранение исторических poisoning violations.

Prerequisites: current source-bound worker, owned workspace/storage, existing `storage-demo.json`, `storage-trust.json`, `trusted-keys.json`, publisher/promoter clients. Gate не создаёт и не меняет working candidate. Native запуск выполнять через `Candidate-bound M08 poisoning acceptance` в disposable hosted CI; локальные Docker/SQL не запускать. Зафиксировать run ID/head SHA, вызвать [команду M08](../poisoning-benchmark.md#исполняемый-m08-для-существующего-кандидата) и читать `M08.json` вместе с campaign/reconciliation, а не только exit code последнего шага печати.

- `M08_candidate_training_mismatch`, `M08_candidate_seed_unsupported`: pipeline/seed/materials не соответствуют frozen protocol. Проверить source, training input, profile и data lock. Не менять metadata JSON ради совпадения и не подбирать seed по желаемому результату.
- `M08_candidate_prediction_mismatch`: фактическая модель не воспроизвела fresh control в установленном допуске или изменились labels. Сохранить candidate и private proof, сравнить worker/lock/source. Не заменять candidate на control без нового полноценного train/evaluate цикла.
- `M08_candidate_scores_changed`, `M08_materials_changed`, `M08_candidate_readback_changed`: bytes или привязки изменились. Gate запрещает pass; остановить изменение среды, установить причину и создать новую campaign в чистом стенде. Старые результаты не переписывать.
- `M08_controlled_contracts_*`, `M08_primary_reconciliation_incomplete`, `M08_campaign_not_fresh`: проверки пропущены, неполны либо не относятся к текущему запуску. Не применять resume из готовых моделей; после исправления выполнить весь protocol заново.
- `status=fail` при complete 35 cases и успешной reconciliation: смотреть effective candidate-bound matrix. AP/targeted ASR violation остаётся релизным блокером. Исходные thresholds, denominator и confidence method не ослаблять. Недоступность tool/storage даёт inconclusive, а не доказательство устойчивости.

Финальное состояние: report связан с candidate reference/model digest, fresh campaign, runtime и source; SQL candidate повторно прочитан, direct prediction receipt сохранён, все 35 cases присутствуют. Контроли могут быть зелёными одновременно с failed robustness. Rollback модели не требуется: gate не выполняет promotion. CI cleanup проверяет ownership, останавливает свою БД и сохраняет volumes до уничтожения временной VM; ни backup действующей платформы, ни production release этим не создаются. Raw requests/responses и credentials не загружать в публичные artifacts. Независимые M22 challenges остаются обязательными.

## RB-15: benchmark завершается fail при исправной инфраструктуре

**Симптом:** все 35 runs выполнены, `execution_status=complete`, но `status=fail` и CLI exit 1. Это может быть правильным отказом security quality policy, а не багом CI.

1. Сначала read-only прочитать summary, исходный protocol digest, source/image и причины scenario decisions. Не переписывать report и не удалять неудачные cases.
2. Для `targeted-asr-upper-bound` сверить eligible count, matched seed и view, точечную ASR и обе границы CI. Хороший общий AP не оправдывает целевые false negatives.
3. Для `clean-auprc-drop` проверить matched clean reference и отсутствие случайного сравнения разных splits. Single-class/малый denominator означает inconclusive, а не доказанное прохождение.
4. Проверить receipts: менялся только train в заданном count; validation/probes/image одинаковы. Если protocol нарушен, признать эксперимент недействительным, исправить код и повторить полный frozen plan. Не исправлять statistical failure подбором удачного seed.
5. Если нарушение реально, оставить affected candidates запрещёнными для release. Защиту проектировать через review provenance/label controls и independent validation, с новым заранее утверждённым экспериментом. Нельзя после просмотра результатов понизить ASR threshold, сократить budgets, заменить probe set на удобный или объявить повтор новой независимой проверкой.

**Rollback:** здесь нет deployed model; откатывать production нечего. Сохранить research artifacts и запретить promotion. Любое будущее изменение defender оценивается отдельно; успешное исполнение контейнеров само по себе не доказывает безопасность модели.

## RB-16: incomplete/invalid matrix или прерванный запуск

**Симптом:** missing report, inconclusive marker, меньше 35 records, `poisoning_matrix_shape_invalid` или `poisoning_incomplete_or_changed_matrix`. Tests при разработке выявили, что `False == 0` мог скрыть некорректный count; добавлены strict types, canonical case comparison, run ID checks и отказ на malformed fields. Это controlled defect, не обнаруженная эксплуатационная атака.

Не принимать сохранённые первые successful cases за полный pass. Проверить process/session handle, не запускать второй benchmark только из-за timeout наблюдения. Если процесс подтверждённо завершился с ошибкой, сохранить campaign folder и причину, проверить Docker availability/current image/disk, затем начать новый полный run. Worker cleanup удаляет только контейнер с именем текущего вызова; SQL states, чужие containers и volumes не затрагиваются. При изменении Git/source во время campaign она отклоняется.

До исправления `fail/inconclusive` блокирует дальнейшую приёмку. Не редактировать summary count вручную. Recovery проверяется наличием всех 35 уникальных run IDs, 30 poisoned/5 clean cases, всех metrics/receipts и конечного статуса без пропусков; это не отменяет statistical violations.

## PB-08: диагностика и повтор

Read-only summary, без вывода моделей, строк данных или keys:

```text
uv run --locked python -c "from mlsecops.contracts import read_json; report=read_json('.runtime/evidence/poisoning.json'); print({name:report.get(name) for name in ('status','execution_status','training_runs','poisoned_runs','clean_controls','violating_scenarios','inconclusive_scenarios','release_ready')}); [print(case['id'],case['metrics']) for case in report.get('cases',[]) if case['metrics']['status'] != 'pass']"
```

Controlled contracts без изменения БД или сервисов:

```text
uv run --locked python -m unittest scripts.poisoning_qualification scripts.poisoning_native_qualification
```

После диагностики, если нужен именно повтор измерения, а не его обход:

```text
uv run --locked python -m scripts.poisoning_native
```

Последняя команда создаёт новые models/evidence и выполняет полную нагрузку. Threshold fail остаётся fail. Команда не устанавливает новую policy, не очищает holdout budget и не выдаёт approval. CI сохранит неуспешный status и напечатает очищенное evidence; корректно выявленный риск не маскируется зелёной сборкой.

## RB-17: summary не соответствует первичным артефактам

**Симптом:** `poisoning_evidence_*`, `evidence_integrity=fail`, отсутствующий artifact или отказ проверки текущего commit/image. Ответственные: security reviewer и platform operator. Любой такой результат запрещает использовать campaign как новое release evidence; это не доказывает, что причиной была атака.

1. Read-only проверить `git status --short`, `git rev-parse HEAD`, исходный report, его source revision и campaign ID. Не менять report на текущий SHA и не пересчитывать хеши для «исправления» противоречия.
2. Запустить отдельную сверку: `uv run --locked python -m scripts.poisoning_evidence`. Она не обучает, не исполняет модель и не обращается к SQL; создаёт только отдельный diagnostic report. Хранить исходный report и campaign. Для другого input использовать `--report`, а output оставлять в `evidence/` state и отличным от input.
3. `header/inputs/training_materials` - проверить commit, lock, image, версии, seed и dataset. `artifact_digest/mutation/prediction_binding/metrics` - несовпадение сохранённых байтов или вычислений: не использовать результат, выяснить источник изменения. `changed_during_read` - остановить совместную запись в эту campaign и повторить только verifier после проверки producer; второй training запуск вслепую не нужен.
4. `evidence_integrity=pass, status=fail` - verifier исправен, метрики всё ещё нарушают исходный порог. Перейти к RB-15, не ослаблять policy. Integrity pass не означает, что модель безопасна.
5. Если campaign действительно прервана или повреждена и оригинал не восстанавливается из доверенной копии, сохранить её для расследования и согласовать новый полный frozen run. Он создаст отдельную campaign. Старые результаты не удалять и не называть новую проверку независимым challenge.

**Встреченный defect:** отрицательный test воспроизвёл перезапись input report при одинаковых `--report` и `--output`; также разрешалась запись внутрь campaign. Исправление проверяет output location до первой записи, запрещает совпадение с input, traversal и symlink paths через существующий safe-child helper. Tests проверяют неизменность input и отсутствие запрещённого output. Это дефект разработки, не production incident.

Отдельное read-only code review выявило пропущенную проверку, когда сам `state` является symlink. Controlled test воспроизвёл перезапись диагностического файла до позднего `symlink_rejected`. Исправление проверяет весь путь начиная с `state`, а не только вложенный `evidence`; тест подтверждает неизменность существующего файла. Review выполнено другим AI agent, не независимым человеком и не закрывает T23.

**Проверка конечного состояния:** verifier сверил 35 cases/251 files, результат содержит source/image/protocol/report/materials/verifier digests; каждый scenario outcome заново рассчитан. Все нарушения остаются в итоговом status. Rollback runtime не требуется: команда не меняет deployed state. Эскалировать unexplained mutations, разные writers, согласованный подлог или сомнения в host: checksum reconciliation не заменяет независимые подписанные approvals и чистую доверенную среду.
