# Сериализованное владение serving identity

Компонент handoff проверен на реальном hosted Kubernetes. Полные M11/M23/M18
и R1 не приняты. Candidate/load/monitoring/privacy получили identity wiring,
но их новые сквозные проверки ещё не завершены успешно.

## Принятый результат на39e0159

- Source: `39e0159672efc1d14d628e130553d4d853488f97`.
- Runtime fingerprint: `210f14a8bddb4a4e04d280f1ce20d5ee5dc6bc1f5908e221da574c4dc248fa84`.
- [Primary43143770511](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43143770511),
  job130936696110: terminal success, включая SQL stop и owned cluster deletion/readback.
- Report:2026-11-12T02:49:56.923589Z ->03:01:25.056946Z.
-20 aggregate checks; внутри handoff22 обычных HTTP checks и10 checks
  восстановленного Deployment. Эти числа описывают разные вложенные проверки,
  а не новые acceptance gates.

| Проверка | Наблюдение |
|---|---|
| Возврат исходного Deployment и нового heartbeat |53.747003s, bound120s |
| Serving heartbeat после завершения временного HTTP owner |9 ->11 |
| Независимые receipts новых identity.denied |2 |
| Сохранение audit pin/permissions/outbox prefix |pass |
| Реальный ONNX inference после возврата |3предсказания, max golden error7.583384781240099e-08 |
| Подмена модели/bundle |exact binding checks pass |
| Отказы HTTP |401/422/413 проверены |
| Последующий revocation |refusal в том же восстановленном Pod |
| Завершение service |service_pods0, worker_jobs0, audit state retained |
| Допуск actual candidate |не получен; full_M10=inconclusive, release_ready=false |

Старый HTTP Pod `255b70c3-5e2c-4eff-8a1b-16b7c02d6ad7` заменён на
`551b3870-3a35-40e9-aa76-6657e2c396d7`. Между ними работал существующий реальный
qualification HTTP CLI. Это сериализованные владельцы одной serving identity,
не один непрерывно работающий PID и не доказательство multi-node HA.

Переход проверяет отсутствие предыдущего HTTP/worker перед следующим владельцем.
Trust observer находится в том же namespace, но имеет отдельные ключи/outbox.
Он исключается из inventory только после проверки audit state, Deployment/ReplicaSet
ownership, UID, spec/image, containerID/restartCount и повторного readback.
Исключения по одному label/имени нет. Граница - один trusted operator; отдельная
распределённая блокировка нескольких operators не реализована.

## Отказы, которые сохранены в истории

| Source/run | Результат и вывод |
|---|---|
|6d202b5 /[43139537422](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43139537422) |Первый handoff pass:44.281584s, heartbeat9->11,2receipts. Он ещё не проверял все orphaned Pods. |
|6d202b5 /[43139535579](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43139535579) |Observer45s recovery timeout:outbox2events/1receipt, collector1/1,3failed checks. Причина остаётся неизвестной. |
|86a6327 /[43141312875](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43141312875) |Handoff fail. Новое требование пустого namespace также считало legitimate trust observer; исправлена граница inventory. SQL/cluster cleanup pass. |
|86a6327 /[43141310976](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43141310976) |Linux unit выявил ошибку классификации flock conflict через общий path guard. Native job pass. Исправление сохраняет конечный security_store_busy непосредственно у flock. |
|39e0159 /[43143768272](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43143768272) |Store/lock и handoff tests pass; contracts job fail на старой load-fixture с пустым config. Native job130936684671 pass:25/37/15/46checks. Общий workflow остаётся failure. |
|39e0159 /[43143774536](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43143774536) |M11 fail до actual-candidate inference: approval истекло до reader в expiry probe. SQL/cluster cleanup pass, backup не принят. |

M11 дошёл до `controlled-after-approval` в02:54:30.874629Z, затем
`signed-approval-expiry` в02:55:14.818905Z. Reader в02:55:44.970128Z корректно
отказал с `release_expired_or_future_document`. Нет доказательства активного
перехода через expiry в этом запуске, поэтому его нельзя засчитать как M11 pass.
После этого подготовлена оптимизация повторной audit validation внутри одного
preflight; после Job состояние читается заново.90s approval, bounds expiry,
delivery и telemetry не изменены. Новый hosted результат этой оптимизации pending.

## Локальная проверка и границы

Clean checkout39e0159 с собственным locked Python3.12.15 environment:
229tests,4Linux-dependent skips, warnings as errors, чистое Git tree.
Ruff556files; docs947files/343Markdown/2507links в clean checkout.
Coordinator на39e0159:85/85statements,26/26branches; CI coverage gate pass.
Поздние fixture corrections и оптимизация preflight требуют своего нового CI.

Private logs, raw reports, ключи и snapshots не опубликованы. Публичные числа
извлечены из source-bound CI report; две копии primary report в log совпали.
Диагностические child codes не выводят exception text и не меняют scheduling.
Успешный новый observer run не является причинным исправлением старого45s timeout.
Предыдущий M11 HTTP response-contract failure также остаётся отдельной нестабильностью.

## Воспроизведение и дальнейшая работа

- [Код координатора](../../mlsecops/kube_serving_handoff.py),
  [native proof](../../scripts/kube_serving_service_native.py),
  [primary workflow](../../.github/workflows/kubernetes-promotion.yml).
- [Ранбук handoff/cleanup](../operations/kubernetes-security-state.md),
  [observer diagnostics](../operations/periodic-trust-observer.md),
  [identity wiring](../operations/identity-security-events.md).
- [План интеграции](../../tasks/audited-serving-integration-plan.md).

Следующий результат: свежий M11 с действующим approval при старте, затем общий
handoff всех callers и явные configuration/root transitions постоянного Deployment,
bootstrap до actual admission и mandatory serving heartbeat. После окончательного
профиля обязательны свежие M13/M14 и полная M23 campaign. Actual admission, M19,
независимые M22 challenges и итоговая M18-приёмка одного candidate остаются открытыми.
Локальные Docker/WSL/Kubernetes/SQL в этой задаче не запускались.
