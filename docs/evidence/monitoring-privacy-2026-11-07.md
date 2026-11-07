# Monitoring API privacy: controlled component

Дата: 2026-11-07. Неделя10/T18, prerequisite fresh M13. **Компонент проверен
на Windows и Linux CI; actual-candidate M13 с monitoring/feedback ещё не принят.**

Runtime commit [`d8cb286`](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/d8cb2866e6de738233e21706be7239fb2e3a2f69).
Contract run [42334890962](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42334890962),
job128289472903: **success**.

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
и branches helper отдельно. На указанном Linux runner прошли49 методов/0skips
за21.099s, helper137/137 statements и61/62branches. Смежные наборы142+77+52
теста/0skips также прошли. Это число запусков, не сумма уникальных методов:
часть HTTP tests исполнялась в нескольких наборах.

Чистый Windows checkout того же commit получил новую venv через `uv sync --locked
--no-build --python 3.12.15`:49методов/0skips за23.141s, tracked/untracked Git status
после выполнения пуст. Чистый checkout проверяет воспроизведение этого компонента,
не всей платформы R1 и не Linux epoch storage semantics.

## Регрессия actual-candidate M15

Отдельный [run42334890982](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42334890982),
job128289472846 на том же source commit завершился **success**. Он проверяет
существующий M15 observation/quarantine path, не новую M13 privacy matrix на
actual candidate:12000 observations,10clean+2shift windows,3signed receipts,
max delivery0.455095275s. Feedback10claims/1quarantine row, retry unchanged,
15 permission denials, protected tables/promotion unchanged.

Source SQL stop/readback success03:42:09UTC, owned cluster removal/absence
success03:42:14UTC, post-cleanup primary reconciliation success03:42:15UTC
2026-11-07. Финальный retained packet имеет тот же digest и12000observations.
`full_M15=inconclusive`, `release_ready=false` сохранены.

Проверенные bindings этой регрессии:

- Image: `sha256:9340b42d68c5d9fdc80c4e34373066b5e01d5a1623a07f7e5bb030acabbf6e40`.
- Model: `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`.
- Subject: `febc9455e807965dd7828d4c881eda31f886bc43ea034559720bf5e9215f61d9`.
- Reference: `b0e2b59cf97bcc2ecd2bc9ec1896ddc4b3328669accf75363b9e1ca2797b78b3`.
- Private packet digest: `f6803f076986f0d046b3182d970ddf8f319798f2cbda5ffd425cf1b86f0ab898`.

Raw packets, credentials и логи остаются приватными. Эти bindings не объединяют
M14 и M15 в один candidate и не доказывают bit-for-bit воспроизводимость image.

Следующие обязательные действия: подключить матрицу к privacy probe фактического
candidate, проверить ordinary feedback CLI и quarantine, пересобрать exact M13
inventory/primary verification и выполнить fresh hosted gate с owned cleanup.
Полный R1 и M18 на одном candidate остаются открытыми. Диагностика и восстановление:
[operator privacy playbook](../operations/model-monitoring.md#privacy-regression-для-operator-api).
