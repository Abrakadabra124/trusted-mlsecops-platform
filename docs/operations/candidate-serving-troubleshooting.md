# PB-26 / RB-50 / RB-51 / RB-52: Испытание настоящей модели без разрешения выпуска

Владельцы: platform owner для стенда, ML owner для source/evaluation, security owner для ключей и отзыва. Scope: synthetic CPU qualification, не production. [ADR 0032](../decisions/0032-candidate-serving-qualification.md), [проверенное evidence](../evidence/candidate-serving-2026-10-15.md): на `0a47b7b` 39/39 native checks pass в clean-checkout CI.

Qualification permit - подписанное разрешение испытать конкретный candidate в конкретной короткой campaign. Это не release approval: permit не утверждает, что M01-M23 прошли. Полные failed/inconclusive gates продолжают запрещать выпуск. У отдельного loopback API ready означает проверенную загрузку кандидата для испытания, не готовность к production.

## PB-26: Воспроизвести проверку и сохранить доказательства

### 1. Read-only диагностика и локальные contracts

Prerequisites: checkout проекта, Python 3.12, установленный `uv`, версии из `uv.lock`. Команды выполняются из корня репозитория. Docker для этого шага не нужен; тесты запускают только свои временные Python/HTTP процессы.

```powershell
git status --short
git rev-parse HEAD
uv run --locked coverage run --data-file=.coverage-candidate-serving --source=scripts.candidate_serving_reader -m unittest scripts.candidate_serving_reader_qualification
uv run --locked coverage report --data-file=.coverage-candidate-serving --fail-under=90
uv run --locked python -m unittest scripts.candidate_serving_native_qualification
uv run --locked python -m unittest scripts.serving_outage_qualification
```

После каждой команды проверять `$LASTEXITCODE`; при ненулевом коде следующий этап не выполнять. Эти тесты используют controlled signed fixtures и controlled clocks. HTTP contract действительно проходит через loopback server, но model worker в локальной harness suite подставной. Это не native Docker evidence.

### 2. Native replay только на disposable стенде

Рекомендуемый полный порядок уже зафиксирован в [storage workflow](../../.github/workflows/storage.yml). Clean checkout -> build -> M03 actual training/evaluation -> immutable material capsule -> signed unapproved release proposal -> qualification. Нельзя брать старый report от другого commit, latest alias или переподписывать старый descriptor ради совпадения digest.

До изменения ресурсов: подтвердить владельца workspace, clean checkout, работающий разрешённый Docker Linux x86_64, наличие pinned image, свободный loopback port 15446. При конфликте выбрать свободный порт через `--trust-port`; не останавливать штатный tracking-service на 15445. Не запускать/перезапускать чужой Docker, WSL, cluster или enterprise платформу ради этой проверки. Новая campaign требует свежий proposal с достаточным остатком срока. Чтение актуального состояния, без вывода credentials:

```powershell
docker info --format '{{.OSType}}/{{.Architecture}}'
uv run --locked python -c "from pathlib import Path; from mlsecops.storage_bootstrap import validate; validate(Path('.runtime')); print('owned storage validated')"
uv run --locked python -c "from pathlib import Path; from mlsecops.contracts import read_json; report=read_json(Path('.runtime/evidence/release-native.json')); print({key: report.get(key) for key in ('scope','status','source_dirty','release_ready')})"
```

Ожидается исходный proposal scope `release-proposal-and-authorization-denial-not-full-M10`, status pass, source_dirty false, release_ready false. Скрипт далее самостоятельно сверяет signatures, source/image, subject и canonical capsule references, а не доверяет этим четырём полям.

**Изменяющий шаг, только для подтверждённого disposable workspace:**

```powershell
uv run --locked python -m scripts.candidate_serving_native --state .runtime --image trusted-mlsecops:dev --trust-port 15446 --confirm-disposable
```

Он создаёт отдельную TLS SQL trust authority с одноразовым ключом, reference worker, persistent worker и loopback HTTP server. Source storage доступен только serving reader; training/evaluation и release envelopes не переписываются. Скрипт проверяет отрицательные запросы, реальное lock-pressure 429, остановку своего worker, reload и отзыв test model. Fault injection нельзя вручную переносить на рабочие контейнеры.

### 3. Проверка конечного состояния

Exit 0 необходим, но недостаточен. В `.runtime/evidence/candidate-serving.json` должны совпасть текущие source/image/proposal/model digests; scope `actual-candidate-serving-qualification-not-release-approval`, status pass, release_ready false, full_M12 inconclusive. Проверить cases сохранности source и удаления qualification authority/private key, реальные runtime measurements. В подтверждённом локальном workspace прежний pass заменяется inconclusive ещё до Docker preflight. При невалидном локальном marker или небезопасном пути чужие файлы не изменяются; любой старый report в таком каталоге нельзя считать результатом текущего запуска.

Reference response получен отдельным ONNX worker на тех же bytes: это consistency между одноразовым и постоянным runtime, не независимое сравнение с исходной sklearn-моделью. Не присваивать этому тесту M06/M07 или полную M12-приёмку.

Публиковать только очищенные counts, digests, timestamps, commit и terminal CI link. Не загружать `.runtime`, private keys, tokens, model bytes, raw features или полные logs. Повтор создаёт новый campaign; отозванный test trust не переиспользуется. Оригинальные CAS, holdout budget и signed envelopes должны остаться прежними.

## RB-50: Source, permit или approval не прошли проверку

**Симптом:** native command exit 2 / `candidate_serving_native_rejected`, API unready/503. Причина может быть в отсутствующих/чужих source materials, dirty checkout, expiry, signature mismatch, недоступной authority или реально непройденном release gate. Общая ошибка намеренно не печатает приватное содержимое.

1. Сохранить campaign/time/commit и последний безопасный case label. Не копировать весь private report в публичный issue.
2. Сверить source revision/fingerprint и image с исходным proposal; проверить M03 и source proposal stages в том же CI run. `storage-demo.json` после последующего M07 может указывать на другой candidate: это не основание менять оригинальную capsule.
3. При expired proposal/permit выполнить новую разрешённую upstream campaign в новом disposable workspace. Не менять системные часы, подпись, issued_at/expires_at или maximum lifetime. Не обнулять holdout ledger ради повторной оценки.
4. При TLS/trust outage сначала [RB-44/RB-45](trust-troubleshooting.md). Offline startup запрещён; при transient outage существующий lease не продлевается, верхняя граница 60 s сохраняется. Permit/proposal может истечь раньше lease.
5. При missing final assurance ожидается `release_assurance_required`. Это правильный запрет, не неисправность. Не прикладывать all-pass fixtures, не переносить qualification key в production trust и не менять signature domain на release-approval.
6. При worker failure/cleanup uncertainty использовать [RB-49](serving-troubleshooting.md). Не удалять source volume. После исправления повторить всю qualification и проверить ready/digests/golden/denial/cleanup, а не только успешный старт процесса.

**Rollback и эскалация:** production head эта процедура не меняет, поэтому rollback production alias не нужен. При неопределённом cleanup сохранить owned resource identifiers приватно, подтвердить workspace/container/volume ownership и обратиться к platform owner. При изменении source CAS/budget прекратить повторы и расследовать с security owner; успешный HTTP не компенсирует такой дефект. Global prune/reset и отключение TLS/подписей запрещены.

**Частичный bootstrap:** review выявил отсутствие cleanup при startup/migration error после создания storage marker. Теперь helper читает и проверяет реальные ownership/configuration, затем удаляет только свои container/network/volume и проверяет их отсутствие через успешные Docker list requests перед удалением private state. Если bootstrap прерван до marker, ownership не подтверждён или Docker недоступен, автоматическое удаление запрещено: `reader_bootstrap_cleanup_unconfirmed`/ошибка ownership, state сохраняется для оператора. Это намеренное ограничение автоматического recovery, не обещание отсутствия orphan resources при любом сбое. Controlled regression проверяет обе ветки и отказ при оставшихся ресурсах; реальный partial-bootstrap fault injection пока не проведён.

Readback опирается на отдельные запросы списка [контейнеров](https://docs.docker.com/reference/cli/docker/container/ls/), [сетей](https://docs.docker.com/reference/cli/docker/network/ls/) и [volumes](https://docs.docker.com/reference/cli/docker/volume/ls/). Пустой stdout команды с ошибкой не считается доказательством отсутствия ресурса. Успешная native cleanup проверена в этой campaign; это не проверка каждой возможной ошибки Docker daemon.

## RB-51: Срок истёк во время trust read или роли используют один ключ

Эти проблемы выявлены при review новой реализации, до её native приёмки. Это контролируемые воспроизведения, не зарегистрированные production-инциденты.

**Expiry race:** reader проверял deadline до сетевого refresh, но не после него. Если permit/proposal истекал во время ответа authority или timeout, ещё действующий trust lease позволял вернуть успешный результат. Исправление повторно проверяет permit и минимальный deadline после refresh, включая unavailable branch; при отказе сбрасывается current handoff. Четыре regression cases покрывают permit/proposal и success/outage. Нельзя увеличивать timeout/lease, чтобы скрыть проблему.

**Key separation:** сравнение Base64-строк допускало две разные кодировки одного Ed25519 public key. Теперь независимость qualification signer от publisher/curator/evaluator проверяется по декодированным bytes; три alias cases отклоняются. Это обход проверки независимости ролей при неправильной конфигурации, не возможность подделать подпись чужого ключа. При обнаружении в конфигурации выдать новый независимый qualification key; не менять encoding прежнего ключа.

Проверка исправлений выполняется командами PB-26. Локальная suite отдельно проверяет, что actual-candidate controller при импорте не загружает ONNX parser/runtime и approval fixtures; fixture-only imports перенесены в старый fixture path. Это проверка import boundary, не полная sandbox/security сертификация.

## RB-52: Authority недоступна, поздний HTTP-отказ или неудачный recovery

Ответственный: platform owner; при signature/ownership mismatch - security owner. Prerequisites и разрешённый disposable стенд те же, что в PB-26. [Метод, evidence и ограничения](../evidence/http-trust-outage-2026-10-15.md). Новый native этап останавливает только свою authority примерно на 60 s, затем проверяет online recovery. Source CAS не останавливается.

**Симптом и влияние:** prediction/readiness дают 503 после потери доверия. Это ожидаемый fail-closed режим, а не разрешение брать старый alias. ML недоступен, deterministic release gates продолжают действовать. Нельзя отключать verifier, увеличивать lease, подменять clock или создавать фиктивный approved report ради устранения 503.

### Read-only диагностика

1. Сохранить commit, campaign ID, model/bundle digests и безопасный trace своей `.runtime/serving-qualifications/<campaign>/http-outage.json`. Проверить `git status --short` и source revision. Не публиковать keys, clients, raw request/response или полный log.
2. Проверить `last_verified`: UTC Unix seconds в `wall`, `monotonic`, `deadline`, policy version/hash и sequence. Это последний успешный verified policy read, не последний HTTP 200 или время остановки контейнера. Ошибка чтения не меняет anchor.
3. В `records` сверить начало/конец запросов, status, response_valid и неизменные trust_sequence/lease_deadline. `assessment.first_503_seconds` включает transport/cleanup. Значение >60 - failure, даже если Engine заблокировал модель раньше клиентского ответа.
4. `missing_outage_phase`: нет pre-expiry 200, двух 503 или probe после deadline. `trust_refreshed_or_lease_changed_during_outage`: проверить остановку именно нужной authority. `ml_response_after_deadline_or_denial`: запретить выпуск, исследовать trust/runtime boundary. 429/timeout не заменяют 503.

### Восстановление и readback

Автоматический playbook проверяет marker и Docker identity. В `finally` выполняется start только прежнего полного container ID, затем bounded SQL readiness и повторная identity validation. Повторный bootstrap/migration/export credentials не нужен. При changed/unknown ownership restart запрещён; оставить состояние для ручного разбора. Никаких global restart/prune, остановки source storage или угадывания container name.

После restart ожидается 503 до explicit activation. Затем повторно читается signed policy, проверяется proposal, те же bytes загружаются в новый isolated worker и сравниваются golden scores. Требуются больший successful-read sequence, timestamp после старого deadline, прежние digests и другой worker ID. Успешный `docker start` этого не доказывает. Cleanup и source readback остаются обязательными.

Если authority восстановлена, но загрузка не проходит, проверить expiry и revoke set. Истёкший permit требует новой qualification campaign от свежих материалов. Отозванную модель нельзя вернуть старым backup. Повторить весь PB-26 на новом disposable стенде, сохранив failed trace; rollback к неподписанному/отозванному состоянию запрещён.

**Эскалация:** identity mismatch, неизвестные остаточные ресурсы, неверная подпись, ML после deadline, clock jump или поздний 503. До выяснения причины fail/inconclusive сохраняется. Controlled tests проверяют ownership/failure cleanup; сбой реального Docker daemon этим не считается проверенным.

### Встреченный failure и исправление lifecycle

На `2905e70` первый client-visible 503 получен через 60.082361397 s. Полный failed trace сохранён в evidence, successful recovery не скрывает нарушение. Код выполнял synchronous worker cleanup перед HTTP отказом; controlled blocking-close regression воспроизвёл эту зависимость. [ADR 0033](../decisions/0033-serving-retirement.md) вводит немедленную invalidation и отдельный retained retirement worker.

503 теперь не означает, что Docker container уже удалён. Перед activation/завершением стенда нужен explicit drain и проверка отсутствия своего полного container ID; сам native runner это выполняет. `serving_cleanup_pending` запрещает reload до завершения thread; `serving_cleanup_unconfirmed` сохраняет handle после ошибки удаления/start. Не запускать параллельные cleanup/reload вручную и не стирать state ради ready. При длительном pending проверить доступность разрешённого Docker и ownership, сохранить evidence, затем повторить scoped cleanup. Неудачный start retirement thread также требует cleanup retained worker, а не join не запущенного thread. Новая реализация ещё требует native replay.
