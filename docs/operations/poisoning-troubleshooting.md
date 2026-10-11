# PB-08 / RB-15/16: poisoning campaign

Ответственные: ML owner и security reviewer, для runtime failure также platform operator. Это лабораторное исследование, не production incident и не атака сторонних сервисов.

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
