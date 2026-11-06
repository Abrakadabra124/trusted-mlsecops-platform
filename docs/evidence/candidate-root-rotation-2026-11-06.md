# T14: смена корневого ключа на работающем candidate

Дата: 2026-11-06 МСК. Неделя 8 «Bundle, approval и отзыв доверия», T14 «Trust lifecycle», CP3/R1-B04. Код: `45c6bf8974a23ab282004ba80f0efe8338d4533e`.

Статус: **live root rotation и явное восстановление прежнего candidate проверены**. [Запуск 42183215170](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42183215170), job `127777395207`, conclusion success. Source, отчёты, HTTP trace, permit, snapshots, histories и cleanup сверены после завершения. Это компонент M11; полный M11 и R1 остаются непринятыми.

## Требование и реализация

Сменить online trust root во время работы настоящего HTTP inference, измерить прекращение ML-ответов, затем явно восстановить прежнюю модель с новым root. Не перевыпускать qualification permit, не продлевать его срок, не сбрасывать историю и не снимать отзыв старого ключа.

Ранее [плановая ротация](authority-root-rotation-2026-10-30.md) подтвердила подписанный переход и запуск обычного serving с новой конфигурацией. Здесь проверяется отдельно уже работающий процесс actual candidate, включая HTTP trace и recovery. Это synthetic qualification path с `release_ready=false`; production approval требует собственных обязательных evidence.

- [CandidateReader](../../mlsecops/candidate_serving_reader.py) закрепляет отдельно public key permit signer и online trust root. Подпись разрешения и свежесть политики имеют разные роли. Root не принимается автоматически из ответа сервиса.
- [Host coordinator](../../scripts/kube_candidate_root.py) готовит dual-signed переход и применяет его после первого успешного HTTP prediction. Ed25519 подтверждает согласие старого и нового ключей; SHA-256 связывает переход с конкретными документами. Ключи подписания и административные SQL credentials остаются у тестового оператора.
- [Lifecycle probe](../../mlsecops/kube_serving_lifecycle.py) записывает начало и завершение запросов. Отсчёт от начала успешного запроса является консервативной нижней границей времени последней успешной проверки доверия. Требуется первый завершённый HTTP 503 не позднее 60 s, отсутствие последующих ML-ответов и ready=503.
- [Candidate probe](../../mlsecops/kube_candidate_probe.py) проверяет точный cold refusal `trust_authority_missing_or_foreign`, закрывает старый Engine и проверяет отсутствие worker. Новый Engine получает явно закреплённые root/version и прежний подписанный permit. Его payload и envelope сверяются по SHA-256 до и после смены ключа.
- Две authority имеют собственные histories, CA и PVC. Сначала ротируется primary и проверяется восстановление; затем отдельной транзакцией ротируется peer. Это не распределённая атомарная операция. Проверяются сохранение histories/revocations, неизменность peer до его перехода и отсутствие изменений model/promotion storage.

Максимальная жизнь permit остаётся 600 s, предел остановки ML - 60 s. Версия каждого authority закрепляется по его собственной подтверждённой истории. Точный повтор операции не добавляет записей; старый root остаётся отозванным.

Архитектурное решение: [ADR 0054](../decisions/0054-candidate-trust-root-separation.md). Диагностика, частичный отказ между двумя транзакциями и восстановление: [ранбук](../operations/authority-root-rotation.md).

## Проверки до native приёмки

До паузы локально прошли 77 целевых test methods / 0 skips и 59 смежных methods. В целевой coverage-группе три файла имеют 197 statements / 70 branches, 100% обоих видов покрытия. Это не оценка покрытия всего проекта или всего CandidateReader.

| Модуль | Statements | Branches | Покрытие |
| --- | ---: | ---: | ---: |
| `scripts/kube_candidate_root.py` | 76 | 30 | 100% |
| `mlsecops/kube_candidate_trust.py` | 30 | 6 | 100% |
| `mlsecops/kube_serving_lifecycle.py` | 91 | 34 | 100% |

Отрицательные проверки включают неправильный root/version, отозванный permit signer, изменённое разрешение, неверный или неполный HTTP trace, поздний ML-ответ, нечисловые timestamps, неверный recovery result, изменение peer/history/storage, неизвестный результат commit и неправильный retry. Проверки подписей используют реальную криптографию, транспорт инфраструктуры в локальных tests подменён.

Предыдущий [запуск 40965767047](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40965767047) отменён 2026-10-30 МСК по распоряжению владельца при достижении лимита. Он выполнил 586 Linux test method executions, но native последовательность не завершил. Остановка owned SQL и удаление disposable cluster проверены. Эта отмена не считается успешным native run или установленным дефектом реализации.

## Подтверждённый native результат

Primary authority перешёл с версии **7 на 8**, peer с **1 на 2**. В каждом сохранены прежние policy, revocations и history prefix, добавлены ровно один document и один rotation record. Старый root добавлен в revoked keys. Primary retry не добавил записей. Peer не менялся до своей отдельной транзакции; после неё primary и полный model/promotion snapshot остались прежними.

В работающем primary процессе после применения нового root получены два полных HTTP 503: через **4.358405478999998 s** и **6.3606791490000205 s** от начала последнего успешного запроса. Оба измерения включают завершение ответа. Первый отказ укладывается в 60 s; последующих ML-ответов в trace нет. Cold Reader получил точную причину `trust_authority_missing_or_foreign`, прежний Engine остался заблокированным, worker был удалён.

Новый Engine с заранее заданными root/version прошёл HTTP contract и golden checks. Модель, subject, permit payload и подписанный envelope совпали с исходными. **Golden maximum error до и после перехода: 0.0**, допуск `1e-6`. Root probe содержит **107 typed assertions**, включая 200 до смены root, readiness 503 после неё, отрицательные inputs, recovery и отсутствие worker после закрытия.

В CI выполнены **586 test method executions, 0 skips**. Это число выполнений, не уникальных сценариев. Три модуля live root имеют 197 statements / 70 branches, 100% обоих видов покрытия. Четыре модуля прежней плановой ротации: 327 statements / 108 branches, 100%. Audit regression прошла: `contracts.py` 146/50, `key_files.py` 47/14, `tracking_sql_probe.py` 33/12, каждый 100%; private-file canary 6/6.

При отдельной сверке coverage локальный анализатор ошибочно требовал единственное вхождение строки модуля во всём логе. Два общих модуля законно входят в live-root и lifecycle группы. Анализатор исправлен: проверяет ровно три строки и итог 197/70 в таблице, связанной с `.coverage-live-root.json`. Удалённая строка, повтор строки и снижение покрытия до 94% отдельно отвергнуты. Исходные CI logs и результаты tests не менялись; ошибка относилась к разбору evidence.

Полная actual-candidate группа содержит **977 typed assertions с повторами**: base 195, root 107, outage 203, blackhole 181, policy/replay 133, model revoke 80, key revoke 72, final cold 6. Во всех этих работающих probe подтверждён один и тот же permit. После root recovery пройдены прежние отрицательные сценарии:

| Сценарий | Первый полный HTTP 503 |
| --- | ---: |
| Смена root | 4.358405478999998 s |
| Недоступный trust service | 59.78756109100004 s |
| TCP blackhole | 13.340089206999892 s |
| Смена policy | 5.159011827999848 s |
| Отзыв модели | 4.278571504999945 s |
| Отзыв ключа publisher | 4.462085035999962 s |

Пять injected clock/signature faults дали 25 HTTP 503, очистку cache/Reader и recovery. Реальные часы ОС не менялись. Подписанный старый trust document v8 после v10 отказан по `trust_version_replay`, хотя его срок оставался действительным ещё 3318.459622144699 s. Независимые terminal authorities сохранили разные CA/PVC/history: primary 10/10/11, peer 2/3/3; точные final cold causes и отсутствие worker подтверждены.

Отдельно повторно прошли controlled whole-bundle rollback A -> B -> A с sequence 1 -> 2 -> 3, три history refusals, неизменный retry и запрет revoked target; по 22 обычных serving checks на каждом шаге. Плановая ротация обычного serving также повторно прошла: четыре точных отказа, 14 old-config cold и 22 new-config checks. Эти controlled результаты не подменяют приёмку actual production release.

Actual production promotion сохранил `release_assurance_required`; `release_ready=false`. Source fingerprint пересчитан по **142 Git blobs**, два полных native report совпали. Native interval: `2026-11-06T07:51:16.019050Z` - `2026-11-06T08:08:13.632482Z`; job завершён `2026-11-06T08:08:20Z`. Owned source SQL остановлен, disposable cluster удалён; финальная проверка runner подтвердила отсутствие kind cluster.

| Привязка | SHA-256 |
| --- | --- |
| Source fingerprint | `b28a3395f80b018460f7c16d0c60bec4412b9bed61315672dfeb5aee68d8dbd6` |
| Worker image | `06c2a09fa2accac9745b7809c2f8a6fc9bfffe7160a2e66cb42847c7fc9af8f7` |
| Actual model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Actual release subject | `ae03bab3fe584332590f3e6b2a0acabc3bee50ac760d8bb47fe76ba155c89778` |
| Actual proposal | `3d33805f767ba1537f8b5a639b0948bfe6af4cdee9da9407a4982bd295a47ed8` |
| Неизменный permit payload | `2abc4c14ea74398b0db1d88163d2eb1db75bc3773c4298520db7ab3c87068dd4` |
| Неизменный permit envelope | `8dd7e1de273d2d468a73ffed54419b09f296d809992bea8d50a36b3aaa8e19cd` |
| Старый online root fingerprint | `b85db270f8e25d1ad8b0cc66f28091c828b91161892af39e7b9852e3ae4f78ff` |
| Новый online root fingerprint | `ee8c7cf3d4fd868ea8d003bd5e6a08c9736b687423b8fb97f57154cc19eefdeb` |
| Неизменный model/promotion snapshot, canonical JSON без LF | `edf46843cab091e18f2a60151c01015c060908816236fb7381475af170383107` |
| Live root subsection, canonical JSON + LF | `38adaacfa1a78040430ddb3448db38dd43ef3032b722aad954508dad3bc7bebd` |
| Full native report, canonical JSON + LF | `840ce74db47e4fe57b681e491507ac9cbb81f7fc9905a71c362996a502eebba0` |

## Воспроизведение

Локальные contracts не запускают инфраструктуру:

```powershell
git clone https://github.com/Abrakadabra124/trusted-mlsecops-platform.git trusted-mlsecops-live-root
git -C trusted-mlsecops-live-root checkout --detach 45c6bf8974a23ab282004ba80f0efe8338d4533e
Set-Location trusted-mlsecops-live-root
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.kube_candidate_root_qualification scripts.candidate_serving_reader_qualification scripts.kube_candidate_qualification scripts.kube_candidate_trust_qualification scripts.kube_serving_lifecycle_qualification scripts.kube_serving_faults_qualification scripts.kube_authority_pair_qualification scripts.kube_root_rotation_qualification
```

2026-11-06 инструкция проверена в новом GitHub clone `45c6bf8` на Windows: отдельное окружение Python 3.12.15, `uv sync --locked --no-build`, 64 установленных пакета, **77 tests / 0 skips / OK за 2.696 s**. Проверено, что импортированный код находится именно в новой копии, а `git status --porcelain` пуст до и после тестов. Из-за разных файловых систем `uv` скопировал пакеты из cache вместо hardlinks; установка завершилась успешно. Локальные Docker/WSL/Kubernetes/SQL не запускались.

Исторический повтор перед паузой также дал 77 tests / 0 skips за 3.039 s, но использовал уже установленное окружение с побайтно одинаковыми dependency files. Новый повтор выше отдельно проверяет создание окружения по инструкции.

Полная инфраструктурная проверка выполняется через [kubernetes-serving.yml](../../.github/workflows/kubernetes-serving.yml) на временном GitHub-hosted runner. Он заново устанавливает закреплённые зависимости. Для повтора нужен branch/tag на проверяемом commit; новый run создаёт собственные synthetic keys и timestamps. Сравниваются bindings и результаты внутри run, а не случайные ключи между runs. Обязательны итоговый native report, source/image binding, точные отказы, HTTP trace, неизменность snapshots и конечная очистка.

## Границы результата

- Эта процедура требует действительного старого ключа. Emergency recovery при его потере и ротация ключа подписания release не подтверждаются этим сценарием.
- Qualification permit не является production approval. Отсутствующее release assurance продолжает запрещать production promotion.
- Две подписи в lab выполняет тестовый оператор. Независимость людей и защищённость production key management этим не доказаны.
- Полные M11/M18/R1 остаются открытыми. M22 independent challenges 0/2, системные image findings, Windows ACL/reparse и остальные обязательные gates сохраняются.
- Private logs, key material и локальные диагностические JSON остаются вне Git. Публичный отчёт содержит только очищенные результаты.
