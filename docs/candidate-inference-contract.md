# Проверка inference настоящего кандидата в Kubernetes

Первый native-прогон 2026-10-29 на `682a3e2`: [40814625074](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40814625074) success, 60/60 candidate checks, golden error 0.0, model `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`, probe 17.419958 s. Source SQL stop и cluster cleanup success. Это отдельная candidate qualification. Общая приёмка ниже реализована, её native результат пока не подтверждён. Полный M12 и R1 не приняты. [Критерии M12](acceptance.md#m12) и исходные пороги сохраняются.

## Что исполняется

[Hosted runner](../scripts/kube_candidate_native.py) получает существующий подписанный release proposal, проверяет его source/image/model binding и копирует неизменённые материалы в owned CAS. Настоящий promotion CLI отдельно подтверждает отказ без assurance; release ledger не изменяется. Затем создаётся отдельный qualification permit со сроком не более 600 секунд и собственным ключом. Подпись разрешает только испытание кандидата; signing key не передаётся в Pod и не становится publisher/evaluator key.

[CandidateReader](../mlsecops/candidate_serving_reader.py) перенесён из scripts в runtime package без изменения его контракта. Обычная команда `mlsecops.serving_http` продолжает использовать release Reader, требующий approval. Qualification доступна только отдельному test probe, она не является новым режимом обычного serving CLI.

[Probe](../mlsecops/kube_candidate_probe.py) запускает настоящий loopback HTTP через тот же FastAPI app, Engine, trust lease и audit journal. Модель исполняется отдельным Kubernetes worker без SQL credentials и API token. Матрица проверяет digest ответа, golden parity <= 1e-6, score в [0,1], abstain вне support, 401, 413, 422, 429, 503, NaN/Inf, поля/версию, 100 и 101 строку. Отдельно проверяются неподписанные permit и proposal, изменённые/изменяемые байты до создания worker, malformed ONNX, отсутствие worker после отказа и остановка работающего worker.

Malformed-model и подмена после Reader являются явно обозначенными fault injections в test harness. Они не подменяют настоящую модель, не изменяют original CAS object и не выдаются за отдельный обученный кандидат. Для отсутствующей подписи создаётся отдельный unsigned proposal object; исходный подписанный объект сохраняется.

Engine теперь проверяет тип `bytes` и SHA-256 до вызова worker factory; проверка после запуска остаётся. Это предотвращает передачу уже изменённых байтов модельному парсеру. Регрессионный тест до исправления подтвердил вызов factory с подменой и принятие mutable buffers; после исправления все три варианта отклоняются до factory.

## Воспроизведение

Локально разрешены только unit/contract tests:

```powershell
.venv/Scripts/python.exe -m unittest scripts.kube_candidate_qualification scripts.candidate_serving_reader_qualification scripts.serving_core_qualification
```

Полная последовательность подготовки, сборки image, owned cluster/storage, исполнения и очистки находится в [workflow](../.github/workflows/kubernetes-candidate.yml). Она запускается в disposable GitHub-hosted runner на ветке `codex/cp3-m12-inference`. На текущей Windows инфраструктуру не запускать. Для воспроизведения native нужен чистый checkout: runner отвергает dirty source и не переписывает lockfiles.

Для общей приёмки workflow вызывает `python -m mlsecops.acceptance --gate M12 --state .runtime --output .runtime/evidence/M12.json`. [Gate](../mlsecops/inference_gate.py) в новом процессе исполняет [полный набор controlled contracts](../scripts/inference_contracts.py), не принимает skips или неполный набор test IDs. Затем на одном image и source выполняет обычный CLI до approval, после controlled approval и после revocation, а также 60 проверок настоящего кандидата. Typed expected/actual сравниваются без смешивания `True` и `1`; смена source, model, subject или пропущенный case не разрешает pass.

Обычный CLI использует отдельно обозначенный controlled release. Настоящий кандидат остаётся без approval и выполняется только по qualification permit. Один ephemeral trust root сохраняется между этапами; новая подписанная policy меняет purpose-bound hash, а предыдущие revocations сохраняются. Это позволяет испытать candidate до окончательной M18 acceptance без фиктивного all-pass assurance и без подмены настоящей модели controlled fixture.

Приватные итоги: `.runtime/evidence/M12.json`, `inference-gate.json`, `inference-native.json`, `inference-contracts.json`; исходные reference/request/config/probe сохраняются в `.runtime/candidate-inference/<campaign>/`, signing key остаётся приватным. Публично разрешены проверенные summary и hashes, не raw logs, credentials, полный config или keys.

## Runbook отказа

Первый общий gate [40815547435](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40815547435), `a87e126`, завершился fail до native serving. Выявлена ошибка инвентаризации controlled tests: AST-список учитывал `FunctionDef`, но пропускал `AsyncFunctionDef`, поэтому ожидал 90 методов вместо фактически загруженных 113. Новый regression test сначала подтвердил отсутствие 23 async HTTP tests; исправление включает их в обязательный набор, не исключает из исполнения и не разрешает skips. SQL stop и cluster cleanup проверяются по terminal CI status. Повтор нужен на исправленном commit.

Ответственный - оператор disposable lab. Сначала проверить terminal status и failed step в GitHub Actions, затем приватные stage/failed-case markers. Не перезапускать ещё работающий job. Отсутствие итогового report или status=inconclusive не означает успеха.

1. `dirty_source`, source/image mismatch или короткое окно permit: остановить принятие результата; проверить commit, fingerprint, pinned image и timestamp. Не менять ожидаемый digest ради прохода.
2. Отказ signature case с другой причиной: проверить read-only доступ к отдельным model/trust services. Ожидается отказ именно подписи; unavailable storage не доказывает проверку подписи.
3. HTTP 503 в положительном сценарии: проверить приватную диагностику Reader, trust lease и worker lifecycle. Не подставлять approved fixture и не отключать audit/проверку доверия.
4. Оставшиеся worker Pods: сохранить UID и parent job identity. Очистку выполняет owned cleanup с проверкой UID; workflow завершает удаление disposable cluster и проверяет его отсутствие. Не применять global prune или удаление чужих ресурсов.
5. Повтор разрешён после исправления подтверждённой причины или отдельного воспроизводимого эксперимента. Сохранять первый failure и не объявлять его исправленным только потому, что повтор прошёл.

После исправления требуется весь targeted workflow, неизменность source и ledger, отсутствие worker и успешная cleanup. M13-M18, image findings и независимые M22 challenges этой проверкой не закрываются. Missing prerequisites дают M12 inconclusive/exit 2; реальный отказ проверки даёт fail/exit 1. Standalone candidate probe не заменяет полную команду M12.
