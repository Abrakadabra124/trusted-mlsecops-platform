# RB-53 / PB-27: зависшее чтение доверия и HTTP deadline

Ответственный: platform operator; при подозрении на подмену authority также security reviewer. Только disposable lab с подтверждённым ownership. Рабочие Docker/WSL/SQL не изменять. [ADR 0034](../decisions/0034-serving-response-deadline.md), [evidence](../evidence/serving-deadline-2026-10-15.md).

Проверка процедуры: clean-checkout CI `ed87e97`, 52 actual-candidate cases pass, включая pause/denial/unpause/cleanup/explicit recovery. Локально 7 controlled harness methods pass, в том числе late-connect после finally и запрет pass при idle query. Это доказательства disposable профиля, не проверка восстановления промышленной инфраструктуры.

## RB-53: диагностика до изменения состояния

**Симптом:** `/livez` отвечает, но authenticated predict/ready возвращают 503; подлежащий SQL thread или cleanup может ещё работать. 503 не является подтверждением удаления worker. После восстановления SQL автоматический 200 намеренно не появляется.

**Причина:** connect timeout и server statement timeout не ограничивают HTTP при остановленной/недоступной после handshake authority. HTTP deadline ставит sticky fence; pending operation сохраняет slot до своего завершения. Это защита, а не утечка, если операции действительно ещё выполняются. Без их завершения новый executor/reload не создают.

1. Сохранить commit, UTC, campaign и безопасные case labels. Не выводить token, client keys, SQL config, features, predictions или полные logs.
2. Проверить docs/status и исходный pinned revision:

```powershell
git status --short
git rev-parse HEAD
uv run --locked python -m unittest scripts.serving_core_qualification scripts.serving_http_qualification scripts.serving_pause_qualification
```

Эти commands проверяют controlled contracts, не реальный runtime. Чистый checkout нужен для native source binding. У старого successful отчёта проверить campaign/commit/image и наличие свежего `http_paused_query`, не доверять одному status.
3. Сопоставить client-visible 503 с `connected_read_entered=true`, `libpq_query_active_at_denial=true`, `read_finished_at_denial=false`, `generation_fenced=true`. ACTIVE означает отправленную незавершённую SQL-команду, включая возможный implicit BEGIN, а не успешное чтение policy. В paired outage trace не должно быть 200 после lease deadline или первого denial. Отсутствующий/неполный trace - inconclusive, не pass.
4. Разделить 401 (auth), 413/422 (body), 429 (занятое действующее поколение), 503 (недоступная/недоверенная модель). Fenced generation отвергается до body и до overload. Не ослаблять auth/lease ради изменения статуса.
5. Для disposable Docker authority сверять `storage_bootstrap.validate(state)`: workspace marker, full container/network IDs, volume identity, image, limits и port. Нельзя выбирать контейнер по похожему имени, сокращённому ID или общему label. Сам факт paused/running недостаточен для права изменить ресурс.

## PB-27: воспроизводимое испытание и восстановление

**Prerequisites:** Linux disposable CI runner, clean checkout, pinned lock/images, штатно созданные upstream source/proposal по [PB-26](candidate-serving-troubleshooting.md). Эта команда не bootstrap: на произвольной машине без подготовленного source она должна отказать. Она меняет только новый qualification workspace; рабочую БД не использовать.

```bash
uv run --locked python -m scripts.candidate_serving_native --state .runtime --confirm-disposable
```

1. Runner проверяет actual candidate с отдельным short-lived permit, не с final release approval; прежние source envelopes/ledger остаются неизменными.
2. После stopped-authority trace и восстановления получает baseline 200/goldens. Узкая диагностическая обёртка перехватывает только exact trust client в выбранном HTTP thread, устанавливает настоящее TLS-соединение и приостанавливает только verified full container ID. Это fault injection, не штатная конфигурация продукта.
3. Штатный SQL read остаётся незавершённым. Runner измеряет окончание HTTP ответа клиентом; нужен 503 <=10.25 s от начала запроса, до последнего зафиксированного lease deadline и <=60 s от verified read. Успех socket connect не засчитывается как успешное trust refresh.
4. В `finally` повторно проверяет ownership и снимает pause с того же ID. Это должно произойти **до** Engine drain и закрытия HTTP. Нельзя читать lock-taking Lease observation или вызывать drain, пока fault ещё удерживает query. Проверяется фактический `Paused=false`.
   Pause/restore защищены общим guard; после выхода из injection context поздно завершившийся connect не вправе снова приостанавливать authority. При подозрении на такое поведение оставить qualification inconclusive и выполнить regression test `test_connection_finishing_after_context_exit_cannot_pause_authority`.
5. После завершения SQL ждёт Engine lock, выполняет retained drain и проверяет отсутствие старого worker. Проверяет, что восстановление authority само по себе не вернуло predictions. Late successful read может изменить Lease, но не event fence.
6. Только explicit verified activation создаёт новый worker. Повторяются fresh trust read, identity/golden checks, signed revoke и сохранность source. Final report обязан сохранять `release_ready=false`, `full_M12=inconclusive`: qualification не разрешает release.

## Дополнительный профиль PB-27: истекающая policy

Та же команда candidate qualification теперь планирует ещё один опыт после основного 10 s paused-query. Controller подписывает новую policy version с lifetime 8 s только в disposable authority. Отдельный файл `http-expiring-query.json` и runtime key `http_expiring_query` сохраняют его независимо от `http-paused-query.json` / `http_paused_query`. Не запускать такую публикацию вручную против working authority.

До fault проверяются receipt version/hash, короткий lease и более поздний approval. Оба профиля теперь требуют `active_observed.monotonic` между началом HTTP и завершением ответа; просто `libpq_query_active_at_denial=true` недостаточно. При отсутствии/позднем observer evidence сохранить inconclusive, не повторять update автоматически под новым key.

Проверяется именно timestamp из сохранённого denial snapshot, не более новое поле observer. Если короткая policy истекла ещё до baseline 200, trace всё равно должен содержать profile, expected receipt и status=inconclusive; отсутствие `last_verified` в таком отчёте ожидаемо. Не принимать наличие stdout key или успешное создание файла за pass. Stdout keys совпадают с runtime keys обоих профилей.

В expiry-профиле сравнить client-finished timestamp с lease deadline и `policy_expires_at`. Проверить второй 503 с `post_expiry.started_wall >= policy_expires_at` и незавершённым ACTIVE query. Только после unpause/drain разрешена signed renewal. Она должна вернуть следующую version, новый document hash, reused=false; recovery read обязан подтвердить именно этот receipt. Success публикации без такого readback не доказывает восстановление.

Ошибка early wake или late response не исправляется сдвигом часов, сокращением исходного trace или увеличением порога. Уже прошедший expiry требует не дополнительного ожидания, а проверки фактического времени следующего запроса. Статус новой native проверки и исправления находятся в [expiry evidence](../evidence/serving-expiry-2026-10-15.md).

## Неуспех, rollback и эскалация

- При pause/ownership/read-completion failure сохранить partial sanitized trace. Если ownership изменился, запрещено unpause чужого ресурса; оператор разбирает расхождение по full IDs. Не делать global prune/reset, не трогать source volumes.
- Если процесс runner аварийно завершён до finally, CI job teardown удаляет одноразовый runner. Для ручного lab сначала отдельно доказать ownership и восстановить доступность authority, затем повторить штатную проверку. Автоматическое восстановление после kill процесса этим harness не доказано.
- При бесконечно зависшем SQL HTTP остаётся fenced, но bounded shutdown не гарантирован. Не создавать поверх него новые поколения. Эскалировать platform owner для scoped process/resource recovery; простой 503 не доказывает, что thread остановлен.
- Rollback к коду без deadline возвращает известный риск зависшего denial. Безопасное временное состояние - unready, не cached serving и не увеличение 60 s. Production promotion/alias эта процедура не меняет.
- Если появился late 200, denial >60 s, чужой container operation, raw-data leak или изменение source ledger, остановить acceptance и сохранить fail. Повторный pass не стирает failed attempt.
