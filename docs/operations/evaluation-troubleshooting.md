# Оценка модели: диагностика отказов

[Контракт](../frozen-evaluation.md). Ответственные: владелец оценки и platform operator; для signature/subject mismatch также security reviewer. Все описанные случаи - разработка и controlled qualification, не production-инциденты.

## RB-11: недостаток данных выглядел как плохое качество

**Причина:** прежний boolean объединял ограничения sample size и quality thresholds. Функция recall возвращала числовой fallback при нулевом denominator. Это не позволяло отличить неизвестное качество от доказанного ухудшения.

**Исправлено:** явные pass/fail/inconclusive, список `quality_reasons`, null для undefined metric. Проверяются общий positive count, каждый заявленный slice и наличие обоих классов. TP/predicted-positive counts связываются с precision/recall; противоречивый signed summary отвергается reader.

**Диагностика:** сначала убедиться в ожидаемом candidate и действительной подписи через `read_evaluation`, затем проверить rows, positives, slice counts и reasons. При `insufficient_positive_labels` не снижать minimum_positives. При `undefined_slice_recall` не заменять null на 0 или 1. При реальном источнике с незрелыми labels не притворяться synthetic source.

**Восстановление:** владельцу данных подготовить новую независимо утверждённую выборку/разметку либо оставить результат inconclusive. Не дополнять dataset дубликатами, не смешивать train с holdout, не тюнить модель на final holdout. При достаточных данных и quality fail использовать validation для изменения модели, затем расходовать новый evaluation slot по утверждённому порядку.

**Проверка:** 199 positives не дают fail/pass; ровно 200 при достаточных slices допускают проверку thresholds; пустой slice и single-class inputs дают inconclusive без NaN. Специальный test сначала воспроизвёл принятие противоречивого recall, затем проверил отказ после добавления TP/ratio consistency. Rollback к старому scorer не должен разрешать отчёты без нового контракта; старый pass не переносится на новую схему.

## RB-12: подпись верна, но report отвергнут

**Сигнал:** `stored_evaluation_subject_mismatch`, `evaluation_metric_mismatch`, `evaluation_slice_ratio_mismatch`, `evaluation_decision_mismatch` или reservation mismatch.

1. Остановить новый promotion, сохранить references и точную причину. Не переподписывать report автоматически и не править digest вручную.
2. Взять ожидаемый candidate reference из доверенного запроса на проверку, не из самого присланного отчёта. Сверить run/model/dataset/lineage/image с persisted candidate.
3. Проверить актуальные evaluator trust key, frozen policy digest и existing reservation. `read_evaluation` использует promoter SQL identity с SELECT только кандидатов/отчётов, не читает labels и не тратит новый слот.
4. Missing metric, old schema или inconsistent arithmetic означает непригодный report. Подпись подтверждает автора, но не исправляет ошибку вычисления или подмену subject. Wrong-role key не становится evaluator от наличия корректной криптографии.
5. При ошибке версии собрать текущий pinned image и выполнить новую квалификацию; при подозрении на компрометацию ключа остановить выдачу доверия и эскалировать. Автоматическая production rotation/revocation этим компонентом не реализована.

**Конечное состояние:** исходный валидный report по-прежнему проходит, подменённый или неполный не проходит, persisted artifacts не перезаписаны. Negative fixtures в qualification сохраняются как отвергнутые, а не удаляются из audit истории.

## PB-06: воспроизводимая проверка исправления

Контрактные тесты не меняют рабочую БД и не запускают сервисы; тест preprocessing выполняет локальный fit/export на synthetic fixtures:

```text
uv run --locked python -m unittest scripts.evaluation_quality_qualification scripts.evaluation_binding_qualification
```

Для live SQL/model проверки сначала создать **отдельный** state по [инструкции](../frozen-evaluation.md), затем:

```text
uv run --locked python -m mlsecops.evaluation_qualification --state .runtime/evaluation-lab
```

Вторая команда изменяет только выбранный owned стенд: создаёт training/evaluation, расходует slot и добавляет rejected fixtures. Она не read-only и не подходит для бесконечного retry. Expected exit 0 и component status pass; error сохраняется как fail, старый report не оставляется pass. CLI не реализует весь M07 и не заменяет production recovery.

При port/TLS/ownership failure использовать storage/runbook диагностику, не отключать проверки. Нельзя удалить чужой контейнер или перезаписать существующий state ради нового pass. После проверки остановить только сверенный owned контейнер; volume/evidence сохранить. Full cleanup и rollback рабочего serving к этому плейбуку не относятся.
