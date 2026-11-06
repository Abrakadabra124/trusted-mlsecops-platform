# M13: actual-candidate Kubernetes privacy component

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit», CP3 / R1-B04.

**Компонент проверен, полный M13 и R1 не приняты.** Code commit `90385faf99efa8e8dace7631bb91fa551f8c7870`, [run 42215561469](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42215561469), job `127884581266`, success. Запуск: 2026-11-06 12:09:53-12:13:57 UTC. Воспроизводимый code tag: `m13-privacy-component-2026-11-06`.

## Что соединено и проверено

[Runner](../../scripts/kube_privacy_native.py) создаёт fresh source-bound proposal и проверяет отказ production promotion без assurance. Идемпотентная миграция создаёт пустой promotion journal для сравнения состояния. Qualification permit разрешает тестовый inference конкретного candidate; authority, approval и release этим шагом не выдаются.

[Probe](../../scripts/kube_privacy_probe.py) использует настоящий HTTP app, CandidateReader, SQL storage/trust и отдельный Kubernetes ONNX worker. ONNX - формат модели, исполняемый ONNX Runtime на CPU. Проверяются golden predictions, привязка audit context к candidate, auth, независимые client quotas, canary inputs, HTTP 429 при занятом Engine и HTTP 503 после fencing.

[Operator](../../scripts/kube_privacy_operator.py) работает снаружи Pod. Он повторно проверяет закрытый первичный audit packet, сопоставленный с независимо наблюдаемыми HTTP outcomes, и читает только журналы принадлежащих campaign ресурсов. Права serving на чтение `pods/log` не добавлены. [Qualification bundle](../../scripts/kube_privacy_bundle.py) поставляет необходимые Python helpers в immutable read-only ConfigMap только для probe; рабочий образ и worker privileges сохраняются.

| Проверенное значение | Результат |
| --- | ---: |
| Типизированные component checks | 26 / 26 |
| Наблюдаемые HTTP responses | 25 |
| Audit events | 68 |
| Requests с candidate context в audit correlation | 8 |
| Проверяемые input/credential canaries | 9 |
| Privacy request cases | 12 |
| Durable events этих privacy cases | 36 |
| Разрешённые metric series | 69 |
| Native stderr bytes за полный child lifecycle | 0 |
| PostgreSQL / trust log windows | 2 |
| Terminal worker stream точно совпал с полученными protocol replies | Да |
| Owned worker cleanup | Подтверждён |
| Source SQL остановлен, disposable cluster удалён | Подтверждено |

8 correlated requests - подмножество запросов с контекстом candidate, а не заявление, что остальные 17 responses не проверялись. Audit verifier сопоставляет первичный журнал и отдельный HTTP ledger. Числа 12/36 относятся к privacy matrix внутри общей campaign, не ко всему трафику.

Сборщик сверяет UID, owner, container ID, image, spec, restart count и состояние до/после чтения. Для worker требуются успешное завершение и точное совпадение **полного** CRI output с потоком ответов, полученных настоящим protocol peer. CRI (Container Runtime Interface) - интерфейс container runtime в Kubernetes; его журналы не отключаются настройкой Docker другого backend. Raw logs и packet остаются приватными.

Public projection содержит фиксированные поля, ограниченные числовые counters и публичный Git revision. Две её публикации в CI совпали. `release_ready=false`, `full_M13=inconclusive`; пропуск проверки или неизвестный stderr не даёт pass. Source/materials и storage/promotion snapshots проверены кодом runner на неизменность.

## Проверки и воспроизведение

Linux CI выполнил три группы: **2 + 80 + 73 = 155 test method executions**, без skips. Это количество запусков методов, не число независимых security controls. В отдельном Windows checkout с Python 3.12.15 тот же commit прошёл **82 + 73 = 155 tests**, 3.576 s и 10.986 s, без skips. Проверены путь импорта и чистота Git. Зависимости установлены в отдельный venv из lock-файла: 64 packages; между первоначальным checkout `b0ca0b9` и проверенным `90385fa` lock/config версии не менялись.

Локальная coverage-проверка пяти модулей bundle/exchange/logs/operator/worker: **295/296 statements и 103/104 branches** покрыты; каждый модуль проходит пороги 95% по statements и branches. Это не coverage всех orchestration modules и не полный M18 quality gate.

Чистое воспроизведение CPU/mocked regression без локальной инфраструктуры:

```powershell
git clone https://github.com/Abrakadabra124/trusted-mlsecops-platform.git
cd trusted-mlsecops-platform
git checkout --detach m13-privacy-component-2026-11-06
$env:PYTHONUTF8='1'
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.kube_privacy_bundle_qualification scripts.data_source_lock_qualification scripts.kube_privacy_logs_qualification scripts.kube_privacy_worker_qualification scripts.kube_privacy_exchange_qualification scripts.kube_privacy_operator_qualification scripts.kube_privacy_probe_qualification scripts.kube_privacy_native_qualification scripts.kube_serving_runtime_qualification scripts.kube_serving_native_qualification scripts.kube_candidate_qualification
uv run --locked python -m unittest scripts.serving_output_qualification scripts.serving_privacy_qualification scripts.serving_metrics_probe_qualification scripts.audit_evidence_qualification scripts.audit_correlation_qualification scripts.audit_export_qualification
git status --porcelain
```

Hosted reproduction запускается через workflow `Kubernetes private output and audit integration` на указанном code tag. Новый run формирует новую campaign; сверять его source revision, все native checks и cleanup, а не копировать исторические counters. Команда dispatch ниже документирует дальнейший запуск; отдельный повтор через tag в этом increment не выполнялся.

```powershell
gh workflow run kubernetes-privacy.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref m13-privacy-component-2026-11-06
```

Локальные Docker/WSL/Kubernetes/SQL в этой работе не запускались и не менялись. Native runner требует Linux GitHub-hosted environment. [Ранбук и playbook](../operations/kubernetes-privacy.md) описывают диагностику и безопасную очистку.

## Неуспешные попытки и исправления

| Run | Результат и действие |
| --- | --- |
| [42210974974](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42210974974) | Отказ до HTTP; слишком общий diagnostic. Добавлено безопасное расположение кода без exception text |
| [42211782862](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42211782862) | SQL subprocess refusal. В focused preparation отсутствовала миграция promotion journal; добавлена существующая idempotent migration |
| [42212390636](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42212390636) | Достигнут HTTP stage; qualification scripts отсутствовали в production image. Добавлены immutable source mount и тест изолированного импорта |
| [42213753543](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42213753543) | Отказ operator exec после Running snapshot; потребовалась безопасная классификация stderr |
| [42214766607](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42214766607) | Подтверждён `container_missing`: CRI уже завершил процесс, kubelet ещё показывал Running. Добавлено максимум 5 s ожидания terminal status только при прежних UID/spec. Это не ack и не pass |

Во всех пяти неуспешных run source SQL stop и disposable cluster removal завершились success. Они не включены в successful native evidence. Отдельно исправлена передача PostgreSQL image в runtime verifier: требуется digest descriptor, а не полное `repository@digest`.

## Что ещё требуется

- Полный M13 должен связать normal serving CLI lifecycle и все обязательные output channels; текущий probe использует настоящий Engine/HTTP внутри qualification harness.
- Service logs здесь являются двумя окнами наблюдения. Это не полные lifecycles служб и не проверка всех init containers.
- Исторический `90385fa` проверял packet на runner, но post-exit retained-copy и post-cleanup signed-primary verification ещё не завершал. [Следующий bc8948c](kubernetes-audit-retention-2026-11-06.md) закрыл этот компонент. По ADR 0049 retention ограничен campaign/VM; внешний долговременный storage не является требованием increment. После уничтожения VM доступна публичная сводка, не приватный packet.
- Общая candidate-bound M13 acceptance и полное coverage orchestration ещё не завершены. M22 independent review 0/2, image findings, CP4/CP5 и M18/R1 остаются открытыми.
- Проверка синтетических canaries не доказывает отсутствие membership inference и не является differential privacy или сертификацией production.
