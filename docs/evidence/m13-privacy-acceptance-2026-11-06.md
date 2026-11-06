# M13: свежая privacy/audit acceptance

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit», CP3/R1-B04.
**M13 принят для synthetic serving профиля. Полный R1 не принят.**

Source [b03a5d9dd5b8771f5318461eebc350c988f093a5](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/b03a5d9dd5b8771f5318461eebc350c988f093a5),
[run 42248499786](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42248499786),
job127996940836: **success**. Проверены primary envelope `gate=M13`, `status=pass`, `exit_code=0`, `source_dirty=false`, exact source/policy/method bindings и terminal cleanup.

## Результаты

| Проверка | Подтверждённый результат |
| --- | --- |
| Acceptance cases | 438: 430 обязательных executable contracts + 8 aggregate criteria |
| Полнота | Exact current method IDs, без missing/extra/duplicate/skipped/expected-failing methods |
| Linux executions | 256 qualification methods + 430 preflight + 430 fresh gate contracts = 1116, с повторами; это не число уникальных независимых тестов |
| Новая gate logic | 12 methods; 144 statements / 22 branches, 100% отдельно для обоих modules |
| Actual candidate / controlled CLI | 28 / 22 native checks; subjects и полномочия явно разделены |
| Privacy matrix | 9 input canaries, 12 actual requests, 36 durable events |
| HTTP/audit | 25 observed responses, 68 events, 8 correlated requests |
| Approved metrics | 69 series в actual и controlled CLI сценариях |
| Service outputs | 4 закрытых окна, 4 обнаруженных positive leak controls, 4 retained packets перечитаны |
| CLI | 12 matrix requests, 6 quota requests, 2 fenced requests, 0 output bytes |
| Actual process/worker | 0 native stderr bytes, terminal exact worker stream, cleanup подтверждён |
| Primary evidence | Signed source/candidate/permit/audit и четыре candidate artifacts перечитаны после native campaign |
| Controlled evidence | Closed CLI snapshot/context/HTTP outcomes перечитаны; независимый CLI admission **не заявляется** |
| Windows clean checkout | 85 переносимых methods, 0 skips, 17.364 s; Linux-only descriptor cases в этот subset не включены |

Source SQL stop и readback завершены в **16:08:31 UTC**. Owned cluster удалён с проверкой отсутствия имени в **16:08:34 UTC**. Это подтверждено Jobs API; успех одного M13 шага не использовался вместо проверки teardown.

Canonical primary report SHA-256: `162e0751240959b85cc8b9c6db4ed93e0e5d882873dd0c4af5764a1f4e1d84f7`.
Method-material hash: `7470bd3c2d0be6ae5be7634d6ee04983da10003023a64b6ca714511d3e26a50c`.
Последний сверён с exact Git archive blobs этого source. У семи файлов Windows working copy отличались переводы строк; локальные bytes не подменяли Linux source proof.

## Связь компонентов

[Runner](../../mlsecops/privacy_gate.py) сначала сохраняет inconclusive, фиксирует clean source/image и методы. [Fixed contracts](../../scripts/privacy_contracts.py) исполняются в отдельном процессе с обязательным полным inventory. На Linux existing bounded runtime initializer выполняется до импорта fixtures. Native operation заново выполняет ordinary CLI и actual-candidate сценарии через проверенный pinned runtime.

Actual path привязан к исходному подписанному proposal настоящего synthetic training/evaluation. Qualification permit разрешает только проверку, не production release. Отдельный controlled release проверяет approval/selection/context wiring и обычный CLI lifecycle того же source/image. Смешение subjects запрещено. Независимый admission/HTTP linkage проверяет actual shared audit path; controlled CLI не имитирует такую независимость.

Gate сверяет свежесть времени и bindings, повторно проверяет signed-primary audit, четыре candidate artifacts, exact CLI snapshot и четыре service packets. Private observation/packet fingerprints остаются в private state. Public envelope содержит finite metrics, fixed contract IDs, synthetic candidate references и hashes проверяющих материалов. [ADR 0048](../decisions/0048-privacy-acceptance.md#исполняемая-композиция-2026-11-06) фиксирует эту композицию и границы каналов; [карта outputs](../privacy-output-map.md) сохраняет различие serving telemetry, private IPC и управляемого training dataset.

## Первый отказ и исправления

| Source / run | Наблюдение и действие |
| --- | --- |
| ca1d939 / [42244584010](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42244584010) | M13 fail до native stages; SQL/cluster cleanup success. Локально воспроизведён fixture, зависевший от console `stdout.buffer`; ему назначены собственные streams. Exact old Linux traceback отсутствует, поэтому локальное объяснение не выдаётся за извлечённый из него traceback |
| e33819c / [42246187189](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42246187189) | Все416 methods pass, но child stderr непуст; ранний preflight отказал до инфраструктуры |
| fc79b60 / [42247058025](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42247058025) | Установлены369 bytes с marker ONNX Runtime; raw text не публиковался. Подключён existing exact bounded bootstrap validator, произвольный stderr не разрешён |
| c91d134 / [42247819845](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42247819845) | stderr0, один из430 methods отказал во втором fixture с `.buffer`; ошибка воспроизведена и исправлена. Инфраструктура не запускалась |
| b03a5d9 / [42248499786](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42248499786) | Полный preflight, M13 438cases, primary source verification и cleanup pass |

Проверка публикации обнаружила ограничение отображения логов: `gh run view --log` не вернул canonical primary JSON длиной81079 символов. Исходный job log получен через Actions job-logs API в приватный файл; из него извлечён и проверен полный envelope. Отсутствие строки в сокращённом представлении не было принято ни за missing evidence, ни за подтверждение pass.

## Воспроизведение и эксплуатация

Для Windows проверен чистый checkout `b03a5d9` в отдельном worktree. `.venv` впервые установлена на `ca1d939` через Python3.12.15 и `uv sync --locked --no-build`; `uv.lock`, `pyproject.toml`, `.python-version` после обновления checkout не изменились. Imports выполнялись из этого checkout; Git status пуст до и после. Это переносимые contracts, не запуск Linux infrastructure.

Полная приёмка выполняется [kubernetes-privacy.yml](../../.github/workflows/kubernetes-privacy.yml) на disposable GitHub-hosted runner:

```bash
uv run --locked python -m mlsecops.acceptance --gate M13 --profile local-cpu --state .runtime --output .runtime/evidence/M13.json
```

Prerequisites и подготовка находятся в workflow; одной команды без owned cluster/source candidate недостаточно. [Runbook](../operations/kubernetes-privacy.md#fresh-m13-gate-диагностика-и-повторение) описывает отказ, fixed diagnostics, безопасное восстановление, rollback и обязательную очистку. На текущей Windows Docker/WSL/Kubernetes/SQL не запускались и не изменялись.

## Остаточные ограничения

Это acceptance свойств synthetic serving, не production approval, differential privacy или устранение membership inference. Service evidence охватывает bounded intervals, не непрерывную историю процессов. Private retention действует внутри campaign/runner; внешний forensic архив не заявляется. Privileged host owner и неизвестные exporters вне этой гарантии. Реальный пилот требует purpose/retention/privacy specification.

M22 independent challenges остаются0/2. Published main517b3c0 имел9 successful workflows и image audit failure с25 findings в ограниченном worker/storage/tracking scope; этот M13 run не исправляет image findings и не заменяет full system-image inventory. M10/M19, CP4/M14-M17/M23 и общая candidate-bound M18/R1 приёмка сохраняются. Следующий плановый этап - неделя10, T17/M14: нагрузка, latency/error distribution и resource measurements с исходными порогами.
