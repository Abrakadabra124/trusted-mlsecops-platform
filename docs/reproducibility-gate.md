# M06: исполняемая приёмка воспроизводимости

M06 проверяет исходный численный контракт [acceptance](acceptance.md): три свежих обучения, одинаковые inputs, заданные допуски и обнаружение настоящих изменений seed/data/environment. Пороги и остальные обязательные требования R1 не изменены. Результат текущей версии фиксируется в [STATUS](../STATUS.md), а не выводится из наличия этого ранбука.

## Что реализовано

[Acceptance dispatcher](../mlsecops/acceptance.py) вызывает [gate](../mlsecops/reproducibility_gate.py), который **заново** запускает [native campaign](../scripts/reproducibility_native.py). Gate не имеет режима «принять ранее сохранённый pass». Каждый запуск получает новый UUID; повторное использование каталога campaign запрещено.

После обучения контроллер повторно читает model bytes, `run.json`, golden vectors и подписанные dataset manifests. Он восстанавливает training request из фактических splits и policy, сверяет model/input/material/source/image digests, заново вычисляет AUPRC и численный разброс. AUPRC (Area Under the Precision-Recall Curve) измеряет площадь под кривой точности и полноты при разных порогах классификации. Сохранённый отчёт должен точно соответствовать этим материалам. SHA-256 связывает содержимое с digest, но не удостоверяет издателя сам по себе; dataset verifier дополнительно проверяет подпись curator.

MLflow служит журналом экспериментов, а не источником разрешений на release. Отдельный reader повторяет GET параметров, метрик и artifact bytes для всех шести опубликованных records через проверяемый HTTPS. Credentials остаются у host controller, не передаются worker.

## Карта требования к доказательству

| Требование | Проверка и evidence |
| --- | --- |
| Три fresh-process runs без model reuse | Реальные вызовы native executor, новый campaign и шесть разных training IDs; первые три относятся к baseline. Не только подсчёт записей в JSON. |
| Все baseline inputs совпадают | Request, dataset, policy, source, environment, golden digests; reconstructed request и signed split bytes. Runtime source fingerprint и хеш всех host scripts фиксируются до/после campaign. |
| Probability difference <= 1e-6 | Максимум `max-min` по трём вероятностям для каждой из 3 000 golden rows, затем общий максимум. Не только разница относительно первого run. |
| AUPRC difference <= 1e-4 | Повторный расчёт по сохранённым vectors и общей frozen holdout разметке; report-only metric не принимается. |
| Artifact hashes сохранены | Шесть model hashes, шесть vector hashes, шесть metadata hashes, native campaign и qualification report hashes. |
| Seed mutation выявлена | Seed 17 -> 18, неизменные split bytes, другое request/policy binding; не считается повтором. |
| Data mutation выявлена | Изменён один feature первой training row, остальные строки и validation/holdout неизменны. |
| Environment mutation выявлена | Отдельный actual image, OMP value 1 -> 2, отдельный input binding; совпадение предсказаний не отменяет изменение inputs. |
| Evidence доступно после публикации | Шесть разных tracking IDs и повторный reader read-back материалов. Неполный/подменённый report не заменяет эту проверку. |

Gate даёт **18 интеграционных cases**: 6 material reconciliation, fresh runs, common golden, numeric repeat, 3 native mutations и 6 tracking read-backs. Отдельные **47 controlled/fixture contracts** проверяют сам aggregator, dispatch, ошибки и stale-output handling; это не дополнительные реальные обучения. Controlled fixture содержит явно фиктивный model blob и никогда не подставляется в native acceptance.

## Проверенный локальный результат

`2026-10-11T11:37:52.067585Z`: CLI M06 **pass, exit 0**, 18 cases, 6 training + 6 prediction + 6 tracking runs, 3 000 golden rows, max probability difference **0.0**, AUPRC difference **0.0**. HEAD `6f41ea30737e782f6763fa575f3244ee5d0e1e00`, **source_dirty=true**: это локальная проверка до commit, не clean-checkout evidence.

- Runtime fingerprint: `171f4510002765fa2bd053006c6442abd809325805549594b96933820d83f6f2`.
- Host scripts fingerprint: `0c8ada271a0c31824ea2abd49a2156d91af4db7d085d76171b0997f327708122`.
- Worker: `sha256:e33db7e0b079093a72c10c61f6d7a72261d4327748e54aac52b5bbc7e200cd0f`.
- Qualification report hash: `fceabff533ee15e694e2f82cdfcb255c9a06b6237679e7b88ccb2d9165f9855c`.
- 47 contracts прошли; покрытие `mlsecops.reproducibility_gate`: **100/100 statements, 32/32 branches**. Это не coverage всей платформы.
- До rebuild реальный CLI вернул **inconclusive, exit 2**, `image_source_fingerprint_mismatch_rebuild_required`; прошлый pass не использован.

Private evidence: `.runtime/evidence/M06.json`, `.runtime/evidence/reproducibility-qualification.json` и отдельный UUID-state `.runtime/reproducibility/<UUID>/`. CI нового increment до отдельного подтверждения не объявляется успешным.

## Подтверждённый clean-checkout CI

[Run 38136658929](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38136658929), job `114461807391`, commit `c9e672fbf3dc4829e591ee92b4ed7b5cfcb5d118`: **success**, 4m13s. Gate завершён `2026-10-11T11:48:33.055179Z`, **source_dirty=false**, exit 0. Повторены 47 contract tests; M06 содержит 18 integration cases, шесть training/prediction/tracking runs и 3 000 golden rows. Разброс baseline probability/AUPRC **0.0**, baseline AUPRC **0.9323007296445032**.

- Runtime/host scripts fingerprints совпали с приведённым локальным результатом. Это совпадение исходников, не доказательство bit-for-bit image build.
- CI worker: `sha256:2fdedf27c8d8a78a30e5354d3cfbe6ba730dc365d9f7e82467ddb275b6481246`.
- CI environment mutation: `sha256:bb7093e9d0c628e93b55b64a0824b97f6a643e5c67a4a8aa25e0d7720291c9c5`.
- Qualification report hash: `a400246748d1123a1efaad1c06362471cd966e0c964b8ba40eab75c20cb5a4c6`; native report hash: `6394f214bd0a6e65eef6a8fbcac42dea5027f9298895df7549db85ebd737be54`.
- Seed и environment mutations дали probability difference 0.0, data mutation - **0.00036472082138061523**; все три отвергнуты как повторение. Значения отдельной mutated campaign не обязаны побитово совпадать между локальным host и CI.
- Проверены terminal success у M06, вывода sanitized evidence и остановки owned tracking services. Отдельные [documentation](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38136658886), [developer runtime](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38136658959) и [storage/TLS](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38136658877) этого commit завершились success.

[Image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38136658926) завершился failure, [Kubernetes regression](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38136658891) на момент записи ещё выполняется. Это не общий зелёный release. Документационный follow-up фиксирует результаты code commit, проверяется локальным docs checker и не запускает неизменённый runtime повторно.

## Плейбук PB-04

Ответственный - platform/ML engineer. Запускать из корня checkout на разрешённой CPU-лаборатории. Требуются locked Python 3.12 environment, Docker Linux amd64, место для новой campaign и уже настроенный private tracking service. Не запускать параллельно с изменением исходников, квалификацией tracking/restart или migration.

```text
uv sync --locked --python 3.12.15
uv run --locked python -m mlsecops build
uv run --locked python -m scripts.tracking_doctor
uv run --locked python -m mlsecops.acceptance --gate M06 --output .runtime/evidence/M06.json
```

Если tracking ещё не настроен, сначала использовать [его bootstrap/runbook](tracking-service.md) и [операционные инструкции](operations/tracking-troubleshooting.md). M06 без `configuration.json` и `resources.json` в выбранном state возвращает inconclusive, не создаёт новый tracking вместо отсутствующего.

Команда **изменяет лабораторное состояние**: создаёт отдельную campaign с ключами и signed synthetic datasets, шесть training/prediction runs, временный owned image, MLflow experiment/records и отчёты. Может возобновить ранее остановленный owned tracking service после проверок. Не меняет рабочую model storage, не пересоздаёт Kubernetes и не выдаёт approval. Новый worker build обновляет локальный тег для будущих workers, не перезапускает существующие Pod/контейнеры.

`--state <путь>` выбирает runtime root целиком: tracking, campaign и qualification evidence. Нет скрытого fallback на default `.runtime`. Команда запускается на host из checkout; это не API внутри model worker image. `scripts` - host tooling, проект не распространяется как установленный wheel.

## Ошибки и восстановление

| Сигнал | Действие |
| --- | --- |
| Exit 2, missing tracking prerequisites | PB-01, проверить выбранный state и owned service; не копировать credentials/receipts из другого окружения. |
| `image_source_fingerprint_mismatch_rebuild_required` | Пересобрать worker из текущего checkout. Не менять label руками и не отключать fingerprint check. Эта отрицательная ветвь проверена реальным запуском до rebuild. |
| `M06_campaign_or_source_changed` | Остановить принятие; проверить Git HEAD, runtime и host scripts. Закончить редактирование, затем запустить новую campaign, не «исправлять» старый report. |
| `M06_candidate_binding_invalid`, `M06_record_not_bound_to_materials`, dataset/model digest mismatch | Сохранить private state, проверить подмену/ошибку producer. Запретить принятие результата. Повторить тесты и новое обучение только после установленной причины. |
| Numeric tolerance или mutation failure | [RB-07 и PB-03](operations/reproducibility-troubleshooting.md), сравнить все inputs/vectors. Не расширять допуск и не выбрасывать неудачный run из тройки. |
| `tracking_read_back_mismatch` | Проверить права и фактические records; успешный training не заменяет сохранённую историю. Не выдавать release по cached alias. |
| Timeout / недоступный инструмент / потерянный артефакт | Inconclusive с причиной. Восстановить prerequisite, повторить новую campaign; отсутствие evidence не равно pass. |

CLI перед началом пишет inconclusive вместо старого `M06.json`. При ожидаемом нарушении - exit 1/fail, при недоступной проверке - exit 2/inconclusive, только полный успех даёт exit 0/pass. Unexpected crash не оставляет прежний pass в output. Native reports, keys и vectors сохраняются приватно в `.runtime`; не публиковать эту директорию целиком.

**Rollback:** M06 не переключает serving/release, поэтому откат модели не требуется. При остановке campaign сохранить её evidence и текущий tracking. Не удалять working DB/volumes, не применять global prune; временный image очищается только по точным identity и image ID. Не принимать прошлый pass после смены исходников. При неясном воздействии использовать [incident template](operations/incident-template.md).

## Границы приёмки

M06 pass не означает завершение всех задач T07/T08, M18 или R1. T08 по-прежнему требует Kubernetes publisher integration и проверки потери metadata без изменения **реального** runtime release/alias; recovery и usable restore остаются обязательными. Тест на пустом каталоге без существующего serving не будет доказательством этой границы. Эти требования не удалены и не объявлены выполненными: они проверяются при интеграции соответствующих компонентов.

Ранний tracking runbook перечислял восстановление metadata вместе с недостающей интеграцией M06. Теперь численный gate подключён по неизменённому контракту M06, а более широкий T08 остаётся открытым. Зелёный численный gate не закрывает будущую проверку целого lifecycle.

Host controller и администратор доверенные; проверки файлов не защищают от администратора, способного подменить код и все trust roots. Нет независимой build attestation, cross-platform reproducibility или доказанной business utility. Изменённый OMP ENV подтверждён, изменение фактической параллельности вычислений не заявляется. Image findings, другие gates, подписанный release, revocation и end-to-end recovery остаются release blockers.
