# T14: live смена release signer через SQL trust и HTTP

Дата: 2026-11-06. Неделя 8 «Bundle, approval и отзыв доверия», T14 «Trust lifecycle», CP3/R1-B04. Проверен механизм смены publisher, assessor и approver на controlled release. Полные M11/M18/R1 остаются открытыми.

## Проверенный запуск

[42198344418](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42198344418), job [127827148006](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42198344418/job/127827148006), source `94f56a36ce94d9751ee6af595af68ffa993d25b2`: **success**, 09:52:50-09:54:34 UTC. Выбран focused `release-key-component` в [storage workflow](../../.github/workflows/storage.yml). Полный `storage-component` не выбирался; Kubernetes workflow в этом increment не повторялся.

Проверены исходный commit, terminal status каждого выбранного шага, JSON reports, их hashes, строки coverage и конечная очистка. Production modules, dependency locks, Dockerfile и policies не менялись относительно предыдущей [SQL/history проверки](release-signer-history-2026-11-06.md). Source fingerprint:

`7cc12e1fd0dbee1bc85986b02bcecd1dbb10b090f8a27288c36d26ab2a885237`.

Worker image этого запуска: `sha256:60637061956c830d380e5b16b384539df9c52ebbcfe0f659d66e7edf9ecdc148`. Совпадение source fingerprint не является доказательством побайтно воспроизводимого image build.

## Что проверено в живом serving

[Native сценарий](../../scripts/release_key_serving_native.py) создал два отдельных TLS PostgreSQL targets: model/promotion storage и online trust authority. Reader использовал настоящий SQL transport с ролью serving, Engine запускал изолированный ONNX worker, запросы проходили через HTTP API. Ключи и reports controlled fixture отделены от настоящего candidate approval.

**68 typed native cases pass.** Для каждой роли последовательно выполнено:

1. Старый release отдаёт HTTP 200 с ожидаемыми subject/model hashes и golden scores.
2. Policy root подписывает смену одного ключа с привязкой к текущему head. Online authority публикует successor policy и сохраняет отзыв прежнего ключа.
3. Старый HTTP экземпляр возвращает два последовательных 503; после первого отказа ML response не допускается. Cold Reader со старой конфигурацией до SQL rotation получает `trust_policy_changed`. Старый worker удаляется.
4. Signed storage rotation сохраняет head. Старый pin после commit получает `serving_head_binding`; новый pin со старой selection получает `serving_selection_binding`.
5. Новый release без M22 отклоняется с `release_gate_set_incomplete`, полный CAS/promotion snapshot не меняется. Controlled полный комплект подписей записывает следующий sequence, но receipt остаётся `release_ready=false`.
6. Старый экземпляр сам не активируется. Только явный новый Engine с новой конфигурацией запускает новый worker и возвращает прежние golden predictions. Старый экземпляр остаётся fenced.

| Роль | Первый завершённый HTTP 503 | Trust version / новый sequence | Golden error до и после |
| --- | --- | --- | --- |
| Publisher | 0.531623744 s | 2 / 2 | 7.583387712228884e-08 |
| Assessor | 0.536259692 s | 3 / 3 | 7.583387712228884e-08 |
| Approver | 0.537451104 s | 4 / 4 | 7.583387712228884e-08 |

Начало измерения - до контрольного успешного запроса, предшествующего online update. Оно задаёт консервативную нижнюю границу последнего trust read. Порог проверки 60 s; это измерение немедленной смены policy, а не отдельный тест 60-секундного outage. Для каждого перехода записаны обе HTTP observations; после rotation, promotion и новой activation старый экземпляр дополнительно проверен на отказ.

Model SHA-256 до/после всех переходов:

`6e4e5e65497470e5fe72af895107f291245c1bfc70070378cf3cdf95d2058169`.

Итог: три rotation rows, четыре events, один head, online version 4 и три сохранённых отозванных ключа. Проверены удаление шести собственных workers, удаление обоих новых SQL targets вместе с volumes/networks, неизменность исходного source storage и revision. Финальный model/promotion snapshot SHA-256: `30ae3dc6cfb30493fd5927e0ed10a836188b69d92f663981598c6fa0d4e1e8dc`. Source SQL затем остановлен с проверкой `Running=false`.

## Regression и воспроизведение

В том же job повторены **37 SQL rotation** и **36 recovery cases**. Полный backup после policy migrations восстановлен в отдельном target при выключенном source: 1 000 golden rows, error 0.0, время до golden 6.622212 s. Это отдельная component campaign, не restore нового live signer target.

Linux preflight: **56 test methods, 0 skips**. Core protocol/store/recovery: 152 statements / 48 branches, 100%. Новые [fixture builder](../../scripts/release_signer_fixture.py) и [HTTP trace checker](../../scripts/release_signer_probe.py): 81 statements / 20 branches, 100%. Это покрытие перечисленных модулей, не всего native coordinator или репозитория.

Чистый Windows checkout `94f56a3` воспроизвёл те же 56 tests за 2.260 s. Использован ранее созданный из GitHub clone и его отдельный locked Python 3.12.15 venv: dependency files неизменны, `uv sync --locked --no-build` проверил 64 packages. Подтверждены import из clone и чистое tracked tree до/после. Новая установка venv в этом increment не заявляется; локальные Docker/WSL/Kubernetes/SQL не запускались.

```powershell
git clone https://github.com/Abrakadabra124/trusted-mlsecops-platform.git
cd trusted-mlsecops-platform
git checkout --detach 94f56a36ce94d9751ee6af595af68ffa993d25b2
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.release_signer_fixture_qualification scripts.release_signer_probe_qualification scripts.release_key_serving_qualification scripts.release_key_rotation_qualification scripts.release_key_store_qualification scripts.promotion_policy_history_qualification scripts.promotion_recovery_qualification scripts.kube_promotion_snapshot_qualification scripts.release_key_native_qualification scripts.promotion_recovery_native_qualification
git status --porcelain
```

Для native проверки нужен разрешённый disposable hosted runner: `storage.yml`, `workflow_dispatch`, input `release_key_only=true`. Сверять `headSha` выбранной ветки/tag с желаемым source; feature branch может продвинуться после публикации. [Runbook](../operations/release-signer-rotation.md) описывает последовательность, отказы и очистку.

## Evidence и границы

SHA-256 canonical JSON + LF:

| Отчёт | Digest |
| --- | --- |
| Live signer | `b836848b6fedb91829eb320eb7f9651651caef38f9373c71a814a58531253883` |
| SQL rotation | `2c8829b36ed77656dd64d3257101146078b7c3a3dd9431bf89168d690df1bccc` |
| Full recovery | `a7d84c52a791d592930c5c1e277f211cc47a8db31a1be5d5ec9009b1050257ba` |

Raw logs, keys, credentials и архивы остаются private. GitHub CLI первоначально отказал в выводе log из-за terminal escape sequences; log сохранён в файл без terminal rendering и разобран как данные. Это не ошибка runtime и не основание пропустить проверку отчётов.

Этот сценарий проверяет механизм подписи, отзыва, истории и HTTP, но использует controlled assurance. Он не подтверждает независимые M22 challenges, одобрение настоящего candidate, полный M11/M18, staged rollback M16 или namespace recovery M17. Следующий обязательный шаг - общая candidate-bound приёмка trust lifecycle с честным отказом при недостающих gates. Independent M22 остаётся 0/2; image findings и остальные CP4/CP5 gates сохраняются.
