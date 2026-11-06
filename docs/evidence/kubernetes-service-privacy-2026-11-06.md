# M13: закрытые окна журналов storage/trust

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit», CP3/R1-B04.
Компонент проверен; полный M13 и R1 ещё не приняты.

## Проверенный результат

Source [0d5ad83306772890b4b8bbe0a550c5104a189e03](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/0d5ad83306772890b4b8bbe0a550c5104a189e03),
[run 42240476139](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42240476139),
job 127969117961: **success**. Final public projection повторена дважды без различий и привязана к этому commit.

| Проверка | Результат |
| --- | --- |
| Actual candidate / controlled ordinary CLI | 28 / 22 checks pass; subjects различаются явно |
| Закрытые окна service logs | 4: storage и trust для каждого сценария |
| Positive leak controls | Все 4 обнаружены именно collector, после измеренного интервала |
| Сохранённые service packets | 4 перечитаны после probe cleanup |
| Actual HTTP / audit | 25 responses, 68 events, 8 correlated requests |
| Actual privacy matrix | 9 input canaries, 12 requests, 36 durable events |
| Approved metrics | 69 series в обоих сценариях |
| Controlled CLI | 12 matrix requests, 6 quota requests, 2 fenced requests, 0 output bytes |
| Actual output | 0 native stderr bytes, terminal worker stream verified |
| Primary audit | retained packet и post-cleanup primary recheck подтверждены |
| Linux contracts | 244 method executions: 2 + 18 + 30 + 47 + 73 + 74; 0 skips |
| Новые modules | 175 statements / 56 branches, 100% для каждого модуля |

Это результаты executable checks, не независимый security review и не доказательство отсутствия любых возможных утечек. `release_ready=false`, `full_M13=inconclusive`, `controlled_cli_independent_admission_observed=false` сохранены.

Source SQL остановлен с readback `Running=false` в 15:15:41 UTC. Удаление owned cluster и проверка отсутствия имени завершены в 15:15:49 UTC. Jobs API подтверждает успех обеих cleanup steps. Локальные Docker, WSL, Kubernetes и SQL не запускались.

## Как работает наблюдение

[Наблюдатель](../../scripts/kube_privacy_services.py) проверяет конкретные StatefulSet/Pod UID, image, отсутствие restart и дополнительных контейнеров. Для PostgreSQL он читает 18 текущих logging/extension settings и проверяет отсутствие соответствующих role/database overrides. Перед probe создаётся уникальная start-метка, после запросов и завершения probe - end-метка. Ограниченный CRI stream должен сохранить начальный префикс и содержать ровно две упорядоченные границы; потеря начала, restart, overflow или отсутствие метки дают отказ.

Каждый полный stream сканируется по девяти canaries. После закрытия окна отдельная synthetic control-метка должна вызвать точный `privacy_log_canary`. Raw bytes, runtime settings и identity сохраняются через existing exclusive private packet writer и перечитываются. Actual path повторяет проверку после удаления Job/ConfigMaps; CLI закрывает и сохраняет окно уже после очистки probe.

[Приватный CLI exchange](../../scripts/kube_cli_privacy_exchange.py) передаёт exact canary bytes оператору через bounded request/ack в собственном временном каталоге. Подтверждение связано с digest request и exact Pod identity. Request/ack удаляются до итогового stdout. Ни plaintext, ни base64 canaries не допускаются в публичный report. Serving Pod не получает прав чтения service logs или Secrets.

Public projection содержит только утверждённые counters/flags и source revision. Журналы, canary values, packet hashes и private context остаются в приватном disposable campaign state; они не загружены в публичный репозиторий. Retention здесь означает возможность проверки после probe cleanup в рамках campaign, а не долговременный внешний архив после удаления CI runner.

## Воспроизведение

Native workflow [kubernetes-privacy.yml](../../.github/workflows/kubernetes-privacy.yml) выполняет locked install, pure contracts, pinned build/bootstrap, source candidate preparation, оба сценария, finite projection и always cleanup. Запускать его только на разрешённом disposable GitHub-hosted runner; workflow не разрешает запуск инфраструктуры на текущей Windows.

Из чистого Windows checkout exact `0d5ad83` создана новая `.venv`: Python 3.12.15, `uv sync --locked --no-build`, 64 установленных packages. Тот же набор из 244 методов завершился успешно за 22.717 s, с **18 POSIX-only skips**. Linux run выше исполнил эти проверки без skips. Git status был пуст до и после; imports/test execution использовали новый checkout. Первую попытку записи локального evidence остановил неверный путь в одноразовой оболочке; результат той попытки не засчитан, путь исправлен и набор повторён с сохранённым результатом.

Минимальная локальная проверка новых contracts, без инфраструктуры:

```powershell
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.kube_privacy_services_qualification scripts.kube_cli_privacy_exchange_qualification
```

Negative cases проверяют identity/settings drift, missing/duplicate/reversed markers, dropped prefix, canary leak, blind collector, packet mutation, ownership/path errors, wrong phase/ack/Pod и output leakage. Тестовые diagnostic `status=fail` внутри negative suites не являются failed native campaign.

## Ограничения и продолжение

- Проверяется bounded closed interval; это не весь срок жизни PostgreSQL и не непрерывная гарантия неизменности settings между readbacks.
- Actual candidate и controlled release различны. Подмена actual assurance не допускается; production promotion остаётся отказан с `release_assurance_required`.
- Полный M13 требует отдельной fresh composition: primary source/candidate binding, полный inventory каналов, required contracts без skips, строгий private verifier и отдельный public gate export. Исторические зелёные компоненты разных commits не складываются в pass.
- M22 independent challenges по-прежнему 0/2, image findings и CP4/CP5/M18 остаются открытыми. [Основная CI-матрица](ci-regression-2026-11-06.md) на предыдущем published source имеет 9 success / 1 image-audit failure, 25 findings в ограниченном scope.
- Runbook с диагностикой и безопасным восстановлением: [Kubernetes privacy](../operations/kubernetes-privacy.md#закрытые-журналы-сервисов-и-приватный-cli-handoff). Пороги и критерии [M13](../acceptance.md#m13) не ослаблены.
