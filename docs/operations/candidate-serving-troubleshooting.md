# PB-26 / RB-50 / RB-51: Испытание настоящей модели без разрешения выпуска

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
