# Actual candidate: отказ старому подписанному trust response

Дата: 2026-10-29. Неделя 8, T14 Trust lifecycle, CP3/R1-B04.
Code commit: `dba0f75bca3412c281dba32dc06c85ca9dbe4b31`.
[GitHub Actions 40922974146](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40922974146), job `123620872921`: **success**.

## Подтверждённая цепочка

На actual обученной синтетической модели сохранён настоящий signed trust document версии **5**. Existing external policy-change coordinator опубликовал несовместимую версию 6, затем совместимую версию **7**. Fresh Engine выполнил успешный inference после online проверки версии 7.

В его Reader затем предъявлен исходный документ версии 5 с новым server timestamp из реального SELECT. До подстановки проверены подписи обоих документов, environment, wall/server times, одинаковые policy/revocation sets и совпадение версии 7 с payload, digest и high-water mark действующего Lease. Version floor не изменялся вручную; старая policy не публиковалась обратно в authority.

Старый документ ещё действовал **3361.685412407 s**. Настоящий `Lease.refresh` отклонил его именно по **`trust_version_replay`**, а не по expiry, signature, policy mismatch или revocation. Первый полный HTTP 503 получен через **0.015891782 s** от начала injection section. Это одно наблюдение qualification, не latency SLO.

Все пять denial observations дали 503 без predictions: predict/readiness при injection, два predict и readiness после восстановления transport. Cache и Reader.current очищены, старая generation fenced, Worker.predict после injection не вызывался. Fresh Reader подтвердил прежние model/subject. Отдельный новый Engine затем прошёл полный HTTP contract; golden error до replay и после восстановления **0.0** на фиксированных входах.

## Evidence и привязки

Replay находится в `actual_inference.trust_lifecycle.policy-change.probe.version_replay` внутри primary report. Policy-change Job содержит **131 typed assertion**, включая прежние 72 и 59 новых проверок replay/recovery. Новые replay IDs уникальны; общая lifecycle trace повторяет одинаковые проверки для нескольких observations. Во всех cases сверены типы и значения actual/expected.

| Поле | Значение |
| --- | --- |
| Prior version / current version | `5` / `7` |
| Prior document SHA256 | `352493946a187c651f7be511f30babfe53167f9a03c2a1f32fb4ebe6616149ac` |
| Current document SHA256 | `77d1866e39fa60aa05046e5c81f6442b6ffccb716ab153b2edc85cd79627093a` |
| Prior expiry epoch | `1793299687` |
| Checked wall epoch / real server epoch | `1793296325.3145876` / `1793296325` |
| Source fingerprint, 136 Git blobs | `6d067bf4a0510c1f3e88d03cca2ed4c89251b8a5e7050b70eba6a6e447884a99` |
| Image ID | `sha256:be29b826d984e182f442cfd7a1cc11663fa18c4e2ae1e986edd9b2200f047da1` |
| Synthetic candidate | `927b023a316bbf0369ec9159bd3483b887097f4587c87eaf3c630b629089b19a` |
| Model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Subject | `4ab889b612b3deae46f95ec522345e419e4fc6ec124f33c4a0bb434a69ca1fa2` |
| Proposal | `a4216ff2ed7cad0e160bc7ef51d6e395352869cb80495879a00fba759b3aa440` |
| Qualification permit | `55f13939ca45dafe197626bf8d08570b9e4e8cf49c6438e57cb097384d20c5be` |
| Full native report SHA256 | `c58a1cbc4097db2a37e5b70c87f32713bb34aeb9b05b00daae74e9033e4dc6e5` |
| policy-change.json SHA256 | `8f091119c4e148ab1434cd820ef4d80c45cb44535b7ed346b104f023a7133ac8` |
| Base probe.json SHA256 | `3a32266094002e266100720f843a9459f3dc88cf66b3e7c08d6600b1ea78eb0a` |
| Full CAS + promotion snapshot | `9f6b49edd55c17a46480d07198d78b083550905a6fc13503c8a1d67861aba968` |

Source fingerprint пересчитан из immutable Git blobs code commit. File/report hashes используют canonical JSON + LF; document hashes - canonical document bytes. Две копии полного primary report в CI совпали. Full snapshot одинаков до/после base Job и каждого authority fault Job; включает CAS и promotion authorities/events/heads. Отдельная trust authority при этом штатно сохраняет новые версии policy и необратимые revocations.

Full native interval UTC: `17:39:39.785466` - `17:52:42.522586`. Actual-candidate interval: `17:47:58.334189` - `17:52:42.521476`. Private primary JSON/raw logs: `.runtime/evidence/ci-40922974146-*`. Signed response bytes оставались в памяти probe и не публиковались. Private keys и credentials в evidence отсутствуют.

## Остальные проверки того же прогона

| Actual сценарий | Typed assertions | Первый полный 503, s |
| --- | --- | --- |
| Base HTTP + пять clock/cache faults | 185 | Пять exact clock/signature causes, все прошли |
| Outage | 213 | 59.777946142 |
| TCP blackhole | 158 | 13.651565457 |
| Policy change, включая subsequent replay/recovery | 131 | 5.975588480 для policy fault |
| Publisher key revoke | 70 | 5.299571206 |

Всего **757 typed assertions** с повторениями общего contract между Jobs. Outage/blackhole traces охватывают deadline 60 s; после первого отказа и границы lease ML-ответов нет. Exact cold denial, no-auto-reactivation и worker cleanup подтверждены. Последний key revoke не отменялся. Actual model/subject связаны во всех reports; golden error `0.0`.

Отдельный ordinary controlled release прошёл expiry, unexpired previous promotion sequence refusal, unchanged journal и retry текущего sequence 2. Старый release sequence оставался valid ещё 1600 s. Это иной механизм и controlled evidence; он не подменяет actual trust-version replay или полный M11.

Linux CI: **277 method executions** = 22 + 147 + 31 + 30 + 5 + 14 + 28, все семь групп OK, без skipped. Локально перед публикацией 85 methods pass. Replay verifier и общий denial harness: **118/118 statements, 24/24 branches, 100%**. Fault/snapshot 274/274 и 104/104; bootstrap 41/41 и 12/12; promotion replay 230/230 и 72/72; expiry 50/50 и 12/12. Attach/runtime остаётся 257/258 statements, 91/92 branches (99% report).

## Cleanup и границы приёмки

Worker absence подтверждён перед replay и после обоих replay/recovery Engines. Final source SQL stop и disposable cluster removal прошли с проверкой конечного состояния. Локальные Docker/WSL/Kubernetes/SQL не запускались, clock/DB state для имитации replay не сбрасывался.

Actual production promotion остаётся отказан по `release_assurance_required`; qualification permit сохраняет максимум 600 s и `release_ready=false`. Проверен in-process replay настоящего подписанного ответа; защита от злонамеренного rollback доверенного DB admin не заявляется. Полные M11/T14/CP3/R1 открыты. Далее обязательны независимые actual model/key revocation states, rotation и разрешённый whole-bundle rollback. M22 independent review остаётся 0/2, system-image findings и остальные gates не сняты. [Ранбук и плейбук](../candidate-trust-replay.md).
