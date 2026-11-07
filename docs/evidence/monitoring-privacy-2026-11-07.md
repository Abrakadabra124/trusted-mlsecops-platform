# Monitoring API privacy: controlled component

Дата: 2026-11-07. Неделя10/T18, prerequisite fresh M13. **Компонент проверен
локально; actual-candidate M13 с monitoring/feedback ещё не принят.**

`scripts/monitoring_privacy_probe.py` проверяет обычный HTTP transport и реальные
operator/label routes без изменения auth, quotas, classifier или promotion policy.
В тесте используются настоящие HTTP listeners, scheduler, подписанный loopback
sink и временные Ed25519 keys. Predictor контролируемый, lineage/reference fixture;
это не исполнение actual ONNX candidate и не независимый security review.

## Проверенный сценарий

- 10 HTTP predictions по 100 rows, +1000 monitoring observations и закрытое окно.
- Операторский token отделён от inference token: четыре 401 на status/labels.
- Подписанная label привязана к observation ID реального HTTP response и закрытому
  окну. Первая отправка принимает1, повтор0; `release_ready=false`.
- Девять 400 для изменённой подписи, лишнего поля, неизвестного observation ID,
  строковой label, query, content type, oversize, malformed JSON и query status.
- Отдельные20 operator requests включают 429; число принятых ограничено burst8+
  refill4/s, измеренный интервал должен быть <1.5s. После refill доступ восстанавливается.
- Реальные audit counters +40 accepted/+40 durable; 10 HTTP responses сопоставлены
  с admissions. Operator routes явно исключены только у ledger с `operator_routes=True`,
  а их ответы проверены самостоятельной матрицей. Prefix/trailing route исключений нет.
- Canary scan HTTP headers/JSON, stdout/stderr/application logging, owned audit
  и Prometheus metrics; ambient OpenTelemetry emission запрещена. Cardinality69.
- Закрытие HTTP приводит scheduler в `stopped`, его task завершена, faults пусты.

Негативные controls не ограничены успешным сценарием: plaintext/JSON-escaped leaks,
неизвестные headers, overflow, ambient signals, неполный summary, fake bool counters,
private URL, потерянные audit events и 24 варианта отказа матрицы отклоняются.
Последнее состояние labels после отрицательной матрицы должно совпадать с
результатом безопасного повтора; ошибочный ingress не должен менять labels.

## Локальная проверка и воспроизведение

Python3.12.15, Windows, locked environment. Совместная регрессия49 методов
прошла за24.725s без skips, включая8 новых методов. Coverage helper137/137
statements и61/62branches.
Это измерение controlled fixture; performance/SLO inference из него не выводится.
Первый положительный прогон отказал: общий test engine возвращал короткий
ReleaseContext. Monitor корректно потребовал полную lineage; фикстура заменена на
QualificationTrace. Production validation не менялась.

Совместный запуск выявил прежнюю зависимость negative logging controls от порядка
тестов: loopback sink оставлял уровень `uvicorn.error=CRITICAL`, а контроль пытался
отправить `WARNING`. Canary фактически не испускалась, поэтому ожидание отказа было
неверным. Намеренные leak controls теперь явно разрешают эту запись через
`isEnabledFor` только на время инъекции. Runtime logging/маскирование не изменены;
общий набор49 методов после исправления прошёл.

```sh
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.monitoring_privacy_qualification scripts.audit_http_observation_qualification scripts.serving_native_qualification
```

Workflow `monitoring-contracts.yml` запускает эту регрессию и требует >=95% lines
и branches helper отдельно. Hosted результат фиксируется после завершения CI;
наличие workflow само по себе не является evidence успешного запуска.

Следующие обязательные действия: подключить матрицу к privacy probe фактического
candidate, проверить ordinary feedback CLI и quarantine, пересобрать exact M13
inventory/primary verification и выполнить fresh hosted gate с owned cleanup.
Полный R1 и M18 на одном candidate остаются открытыми. Диагностика и восстановление:
[operator privacy playbook](../operations/model-monitoring.md#privacy-regression-для-operator-api).
