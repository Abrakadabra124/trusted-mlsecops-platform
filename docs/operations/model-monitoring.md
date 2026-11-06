# T18/M15: мониторинг распределений и качества

Ответственные: platform-owner за сбор/доставку, model-owner за reference/quality,
data-owner за проверенные labels. Scope: [ADR 0057](../decisions/0057-fixed-monitoring-contract.md).
Сейчас реализовано статистическое ядро. Actual collector, scheduled alert
delivery, dashboard и full M15 пока не приняты. Команды ниже не запускают
Docker, WSL, Kubernetes или SQL.

## Диагностика без изменения состояния

1. Сверить revision и digest reference с доверенной конфигурацией candidate.
   Не заменять reference текущими данными, чтобы убрать предупреждение.
2. Проверить sequence, times, суммы histogram и abstentions. Окно с999
   observations недостаточно; отсутствие alert при недостатке данных не значит
   нормальную работу. Public metrics не должны содержать feature values или IDs.
3. Различать `data_drift`, `prediction_drift` и будущую доставку
   `quality_degradation`. PSI не доказывает падение recall или poisoning.
4. При `telemetry_gap` найти потерянное окно/интервал и неисправный collector.
   Не восполнять потерю синтетическими наблюдениями. После восстановления
   требуется новая последовательность достаточных окон.
5. При ошибке reference/root/model binding остановить приём такого потока,
   сохранить private digest/sequence и эскалировать model-owner. Не отключать
   проверки и не ослаблять порог ради зелёного отчёта.

## Воспроизводимая проверка ядра

В отдельном checkout с pinned Python3.12.15 и установленным locked окружением:

```powershell
uv run --locked python -m unittest scripts.monitoring_qualification
uv run --locked coverage run --branch --data-file=.runtime/evidence/.coverage-monitoring --source=mlsecops.monitoring -m unittest scripts.monitoring_qualification
uv run --locked coverage report --data-file=.runtime/evidence/.coverage-monitoring --fail-under=95
```

Ожидаются отказ неизвестных/нецелочисленных counts, immutable reference,
идемпотентный repeat, отказ replay/conflict/overlap, сброс streak при gap или
недостаточной выборке, десять clean controls и точная граница recall0.05.
CI отдельно требует >=95% statements и branches каждого нового модуля.
Это controlled tests; они не являются доказательством доставки alert <=120s.

## Восстановление и ограничения

После восстановления collector повторить только существующие неизменные окна
с прежними IDs; новое reference допустимо только как отдельное явное
переконфигурирование с подтверждённым candidate и сохранением прежней evidence.
In-memory evaluator ещё не содержит durable checkpoint: его restart сейчас
не разрешает заявлять отсутствие gaps. При неизвестной истории сохранить
inconclusive, а не подтверждать promotion.

Delayed labels не принимать из произвольного HTTP payload или feedback как
доверенные. До реализации и проверки authenticated label join численная
`quality()` является только comparator проверенных агрегатов. Ни comparator,
ни drift alert не разрешают retrain, promotion или rollback автоматически.

В incident record указать reference/window digest, sequence, sample sizes,
точный отказ, наличие delivery receipt и пределы наблюдения. Не сохранять
сырые признаки, тексты labels, токены и ключи в публичных reports. Native
recovery и alert delivery будут проверяться только в owned disposable hosted CI.
