# Обычный serving CLI: privacy от запуска до закрытого audit

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit», CP3/R1-B04.
Это компонентная проверка. Полные M13/M18/R1 остаются **inconclusive**, `release_ready=false`.

Проверенный source: `36cd71d75f4805454ef187f4c6973071e7427b9a`.
[GitHub Actions 42225259346](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42225259346), job `127917007808`, attempt 1: **success**.
Campaign 2026-11-06 13:24:37-13:29:20 UTC. Source SHA, обе идентичные public projections и конечные cleanup steps проверены отдельно.
Source SQL остановлен, owned disposable cluster удалён.

## Что изменено

Прежний actual-candidate probe создавал Journal через qualification wiring. Он проверял реальные HTTP/ONNX и независимо наблюдал audit admission, но не доказывал создание и закрытие audit обычной командой сервиса. Новый [CLI observer](../../scripts/kube_cli_privacy_probe.py) расширяет существующий [probe](../../mlsecops/kube_serving_probe.py), который запускает отдельный `python -m mlsecops.serving_http --startup-diagnostics --config ...`. Сервис сам выполняет `configured()` и `audit_path`, создаёт Journal и закрывает его через lifespan. Сервисный процесс не получает monkeypatch или дополнительные Kubernetes permissions.

[Native orchestration](../../scripts/kube_cli_privacy_native.py) использует существующий signed controlled release. Fixture имеет собственные model/subject и не разрешает actual candidate. Затем в той же hosted campaign проверяется actual candidate с qualification permit; production refusal `release_assurance_required` сохраняется. Оба пути используют общий root authority, но разные назначения ключей и контекстов.

1. Observer подготавливает приватные файлы трёх client principals и отдельный metrics credential. Существующая конфигурация сервиса ограничивает квоты и in-flight requests.
2. Внешний HTTP-клиент выполняет 12 прежних canary cases, шесть quota/refill requests и scrape 69 approved metric series. Наблюдение сохраняет bounded response bytes и метаданные ответов без request bodies.
3. После удаления собственного worker два запроса подтверждают корректные 503 для predict/readiness. Этот отказ не становится успешным inference.
4. Parent ждёт завершения CLI и отсутствия собственного worker. Полный stdout/stderr должен быть пуст. Только после этого читается закрытый audit manifest с сегментами, выполняется scan девяти canaries и проверка последовательности, digest, context и соответствия HTTP outcomes.
5. После удаления probe Job/ConfigMaps внешний runner повторно загружает signed selection/authorization из CAS, проверяет неизменность model/promotion storage и связывает snapshot с первичными материалами. Snapshot сохраняется однократно через существующий `audit_snapshot`, перечитывается и повторно проверяется.
6. Публичный report содержит строгий набор counters и флагов. Raw HTTP IDs, snapshot, credentials и private context остаются внутри disposable campaign.

## Native наблюдения

| Путь | Проверенное наблюдение |
| --- | --- |
| Controlled ordinary CLI | 22 checks, включая три response model/bundle bindings |
| Canary inputs | 9; общая input matrix 12 requests |
| Quotas | 6 requests: два независимых burst/refill сценария |
| После fencing | Predict/readiness 503, 2 requests |
| CLI output | 0 bytes после завершения процесса |
| Metrics | 69 разрешённых series |
| Closed snapshot | Повторно проверен после cleanup и после сохранения |
| Actual candidate | 28 checks, 25 HTTP responses, 68 audit events, 8 correlated requests |
| Actual privacy | 12 requests / 36 durable events, 9 canaries, native stderr 0 bytes |
| Actual worker | Точный terminal stream, owned cleanup подтверждён |
| SQL/trust | Два Running log windows; не весь lifecycle |

Девять canaries и проверки actual candidate не следует складывать с controlled cases как число независимых моделей или как общий M13 pass. Это разные subjects с явно разными правами.

## Покрытие и отрицательные проверки

CI требует **не менее 95% statements и branches отдельно для каждого из трёх модулей**. Общий процент coverage не подменяет branch threshold.

| Модуль | Statements | Branches |
| --- | --- | --- |
| `mlsecops/kube_serving_probe.py` | 193/195, 98.97% | 48/50, 96% |
| `scripts/kube_cli_privacy_probe.py` | 148/149, 99.33% | 63/64, 98.44% |
| `scripts/kube_cli_privacy_native.py` | 73/73, 100% | 16/16, 100% |

Проверены startup timeout/early exit, transient connection/readiness retry, oversized response, запрещённые сочетания режимов, неожиданный успешный admission/RBAC, stop/wait/kill только собственного процесса, readback после cleanup. Snapshot controls отвергают неверные sequence/digest/size, незавершённые requests, потерянный или дублированный HTTP outcome, чужой signed context, согласованную подмену child receipt и изменённые retained bytes. Canary/status/quota/refill/metrics/fencing ошибки дают отказ; исключения не печатают приватный текст.

Linux выполняет 222 test method executions без skips: **2 + 30 + 47 + 70 + 73**. В 47 входят POSIX filesystem/lease/fsync и parent-verifier contracts. Это отдельное доказательство от native Kubernetes step.

Чистый detached Windows checkout `6b90fc0` подтвердил **175 tests / 0 skips**: 30 за 4.705 s, 72 за 4.719 s, 73 за 11.215 s. Проверены фактический interpreter/import и чистота Git. Python 3.12.15 virtual environment был создан новым на `12f72e3` с 64 packages и затем использован при неизменных `uv.lock`/`pyproject.toml`. Между `6b90fc0` и финальным `36cd71d` изменены только workflow и ранбук; production/test modules совпадают. Это не повторная установка dependencies на каждом commit. На `12f72e3` свежая установка отдельно прошла 170 Windows tests. Локальные Docker/WSL/Kubernetes/SQL не запускались.

## История запуска и исправление CI

Первый native [42222317696](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42222317696), source `12f72e333341a2733c9bf8f3efa894ebee14019b`, success: CLI + actual candidate и cleanup подтверждены, 212 Linux tests. После него добавлены отрицательные сценарии и обязательный threshold.

[42224962681](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42224962681), source `6b90fc0f5fa0dede086ccd897313814288288fd9`, **failure**: все 222 теста и coverage gate прошли, но bootstrap отказал с `refusing_nonempty_unowned_workspace`. Coverage преждевременно создал `.runtime/evidence` без ownership marker. Кластер/source SQL ещё не создавались. Исправление `36cd71d` переносит coverage в `RUNNER_TEMP`, сохраняя прежний ownership guard. Не обходить этот отказ принятием произвольного каталога; повторять новую campaign с штатным bootstrap.

## Воспроизведение и границы

Запускать [workflow](../../.github/workflows/kubernetes-privacy.yml) на точном source в отдельном разрешённом disposable GitHub-hosted runner. Сверять SHA, test/coverage/native steps, повторённую public projection и оба cleanup steps. Не обновлять ветку во время run из-за `cancel-in-progress`. [Ранбук](../operations/kubernetes-privacy.md) описывает fixed diagnostics и порядок восстановления.

Локально разрешены только pure contracts:

```powershell
$env:PYTHONUTF8='1'
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.kube_cli_privacy_qualification scripts.kube_serving_native_qualification
```

CLI observer **не наблюдает независимо внутренний Journal admission**. Он проверяет завершённые journal requests против HTTP, но pre-admission 401/429/503 могут не иметь journal request. Флаг `controlled_cli_independent_admission_observed=false` обязателен. Этот snapshot не выдаётся за [ADR 0049](../decisions/0049-private-audit-evidence.md) independent-admission packet; actual candidate сохраняет более строгий packet/HTTP linkage.

Для полного M13 ещё нужны полный service-output inventory, runtime readback и bounded closed windows с controls, явное обоснование композиции controlled/actual subjects и строгий общий gate. Ранее проверенное [сохранение actual audit](kubernetes-audit-retention-2026-11-06.md) остаётся частью цепочки. Retention ограничен campaign/VM, raw captures не экспортируются. M22 independent review 0/2, image findings и общая candidate-bound M18/R1 acceptance остаются открытыми.
