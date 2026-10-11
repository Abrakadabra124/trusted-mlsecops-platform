# Lineage из подписанных материалов настоящего candidate

Статус: компонент T25, **не полный M19 и не promotion**. Дополняет [asset graph](asset-graph.md); эксплуатация в [PB-10 / RB-20 / RB-21](operations/candidate-lineage-troubleshooting.md).

## Требование и граница доверия

Структурно корректный граф можно выдумать. Новый `mlsecops.candidate_lineage.collect` строит пять nodes из immutable SQL objects после проверки подписей curator/evaluator, модели, источника, policy и независимого evaluation binding. В отличие от первого fixture, native qualification работает с PostgreSQL, настоящим CPU training и ONNX candidate.

Lineage - происхождение артефакта и связи с использованными материалами. DSSE (Dead Simple Signing Envelope) - контейнер подписи с разделением типов payload; существующая реализация Ed25519 проверяет, кто подписал данные и для какого назначения. Это не доказывает добросовестность разрешённого signer или отсутствие poisoning.

Два клиента передаются явно: publisher читает только `manifests`/`lineage`, promoter - `candidates`/`evaluations`. Collector не вызывает обучение, ONNX loader, `storage.put`, reserve или signing. Он не запрашивает `train`, `validation`, `holdout` либо raw quarantine. PostgreSQL проверяет TLS client identity; обе роли не имеют SELECT на holdout. Их существующие права INSERT шире потребностей collector: это остаётся lab limitation, dedicated read-only inventory identity и migration ещё нужны. SQL grants не расширялись.

## Как работает

1. Проверяет синтаксис candidate/evaluation references, ожидаемых build pins и mapping owners. Curator/evaluator должны быть разными trust roots; identities клиентов - publisher/promoter.
2. Повторно читает candidate через существующий `load_candidate`: проверяются immutable object digests, schema, model bytes/digest/size, policy и unapproved state. Модель не исполняется.
3. Через `read_manifest` проверяет curator-signed dataset index, manifest, source approval и lineage. Approval должен быть актуальным по существующей policy. Metadata candidate должна ссылаться на те же dataset/lineage и exact split digest/bytes/rows metadata.
4. Сравнивает image ID, source fingerprint и revision с **отдельно переданными expected pins**, не берёт expected из candidate. Training execution должен указывать тот же image. Native helper вычисляет pins из checkout и реально разрешённого Docker image; `resolve_image` также сверяет source fingerprint label.
5. `read_evaluation` проверяет evaluator signature, exact candidate subject, model/run/policy/image, typed prediction protocol, scan receipt, quality summary и persisted budget reservation. Collector дополнительно сверяет holdout digest/rows с curator manifest и порядок training/evaluation timestamps. Holdout labels при этом не читаются, новая reservation не создаётся.
6. Собирает typed graph: dataset -> run -> model; runtime/policy -> run. Возвращает references и quality state рядом с графом. Quality fail сохраняется как fail; корректная подпись не превращает его в approval.
7. Проверяет граф уже реализованным `asset_graph.assess`. Deployment nodes отсутствуют намеренно: это projection candidate lineage, а не утверждение, что serving inventory пуст или здоров.

## Контракт graph identity

| Node | Digest содержимого | ID |
| --- | --- | --- |
| dataset | Canonical manifest digest = verified dataset ID | `dataset-<digest>` |
| runtime | Разрешённый exact image SHA-256 | `runtime-<digest>` |
| policy | Canonical policy digest | `policy-<digest>` |
| run | Persisted metadata object digest | `run-<digest>` |
| model | SHA-256 фактических model bytes | `model-<candidate-reference>` |

Model ID специально связан с candidate, а не только с model bytes. Два runs могут дать одинаковую модель; их provenance нельзя потерять при объединении графов. Они имеют разные nodes и одинаковый `(kind, sha256)`, поэтому content-alias revocation затрагивает обе версии. Test сначала воспроизвёл столкновение ID, затем подтвердил сохранение обеих run dependencies и распространение отзыва. Автоматическое merge/persistence пока не реализовано; не перезаписывать конфликтующие nodes вручную.

`bindings` сохраняет candidate/evaluation/dataset/lineage/source approval/budget receipt references и build pins. Это linkage index, не подписанный graph envelope. Поля output: `release_ready=false`, `full_M19=inconclusive`, `candidate_state=unapproved-candidate`; `quality_component` сохраняется из проверенного evaluation. Не использовать `assessment.component_status=pass` как release decision.

## Проверка и воспроизведение

```powershell
uv run --locked coverage run --source=mlsecops.candidate_lineage --data-file=.coverage-candidate-lineage -m scripts.candidate_lineage_qualification
uv run --locked coverage report --data-file=.coverage-candidate-lineage --fail-under=100
uv run --locked coverage run --source=scripts.candidate_lineage_native --data-file=.coverage-lineage-native -m scripts.candidate_lineage_native_qualification
uv run --locked coverage report --data-file=.coverage-lineage-native --fail-under=100
```

Локально: 18 collector tests, 50/50 statements и 22/22 branches; 8 diagnostic-runner tests, 96/96 statements и 26/26 branches. Cryptographic unit fixtures используют настоящие временные ключи и подписи, но mocked SQL transport и контролируемые model bytes без ONNX parser. Два targeted holdout consistency tests подменяют manifest reader, чтобы изолировать дополнительную проверку; они не заменяют native validation.

Отдельный native прогон использует свежий SQL state и настоящие signed datasets, обучение/оценку. Collector после этого выполняет 10 checks: exact lineage, actual read scope, точный dataset impact, missing candidate/report, wrong source pin, unknown owner, два SQL holdout denies, неизменность metadata/budget ledger. Перед/после сверяет immutable ID sets четырёх таблиц, source/image/HEAD, input files и owned container identity. Это не continuous tamper detection против администратора.

В existing **running** state с `storage-demo.json` того же checkout:

```powershell
uv run --locked python -m scripts.candidate_lineage_native --state .runtime
```

Команда не bootstrap-ит, не обучает, не рестартует сервис и не пишет SQL. Она пишет private diagnostic report в `.runtime/evidence/candidate-lineage-native.json`. Для чистого воспроизведения storage CI выполняет её после M03, где уже создан fresh signed candidate. Native result и exact CI привязка публикуются в [STATUS](../STATUS.md). Не воспроизводить успех заменой pins на значения из неподтверждённого candidate.

## Ограничения и следующий этап

Collector проверяет metadata lineage одного candidate. Он не перечитывает dataset row bytes, не пересчитывает evaluation metrics, не аттестует kernel/build service, не устраняет semantic poisoning и не доказывает полный список материалов произвольного ML pipeline. Отдельная M03/M07/M20 evidence остаётся необходимой. Текущие curator/evaluator и host входят в trust boundary.

Все IDs, граф и полные reports остаются private по умолчанию; console выводит только scope/status/count и отсутствие release approval. Полный signed graph lifecycle, expiry/retention inventory, persistent monotonic revocation, independent serving observations, signed release bundle, promotion и M11 lease пока не готовы. Native helper намеренно требует HEAD candidate совпадающим с текущим checkout; это правило свежей qualification, не универсальная политика выпуска исторических releases.
