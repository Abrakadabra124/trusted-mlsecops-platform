# RB-54 / PB-28: client identity и quotas

Scope: один локальный serving process, T16 identity/quota slice. Ответственный: platform operator; изменение credential allowlist согласует security owner. [ADR 0035](../decisions/0035-serving-client-quotas.md), [API](../serving-api.md), [evidence](../evidence/serving-clients-2026-10-15.md). Это не runbook внешнего identity provider или distributed quota.

## RB-54: сначала диагностика без изменения состояния

1. Сохранить code revision, UTC, server-generated request ID, HTTP status и bounded error code. Не копировать Authorization, config, client IDs, feature rows, raw URLs или traceback в public issue.
2. Разделить 401 (credential отсутствует/не совпадает/duplicate header), 429 `client_limited` (rate либо retained in-flight), 429 `overloaded` (global capacity/Engine lock) и 503 (serving trust/runtime либо quota clock). `/livez=200` не означает готовность модели.
3. Проверить reproducible contracts без runtime изменений:

```powershell
git status --short
git rev-parse HEAD
uv run --locked python -m unittest scripts.serving_access_qualification scripts.serving_http_qualification scripts.serving_native_qualification
```

Последний module поднимает временный loopback HTTP с controlled Engine; Docker/WSL не запускает. Это не проверка working model или M13 целиком.
4. Оператор проверяет private конфигурацию локально, без вывода её содержимого: ровно один `token_file` или `principals_file`, absolute path, POSIX 0600/Windows owner-only ACL, 1-32 unique principals/tokens и bounds ADR. Не принимать клиентский `X-Client-ID` или forwarded IP за доказательство identity. Default legacy limits теперь 20 requests/s, burst 40, 4 in-flight; мониторингу нужен свой principal, если он не должен делить bucket приложения.
5. При обычном rate exhaustion остановить автоматические retries и дать refill. 429 не является причиной перезапуска. Если 429 сохраняется, проверить pending backend operation по [RB-53](serving-deadline-troubleshooting.md): HTTP timeout/cancel не освобождает client/global slot незавершённого SQL. Это намеренный resource bound, не доказательство утечки.
6. Не выводить внутренние counters/credentials в public diagnostics. Текущий slice ещё не имеет полноценного audit/metrics endpoint; отличить clock fault от всех причин 503 по одному ответу невозможно. Нужны scoped operator investigation и сохранённое sanitized evidence; не выдумывать причину.

## PB-28: disposable qualification

Prerequisites: Linux CI runner, clean checkout, pinned dependencies/images, owned upstream source/proposal по [PB-26](candidate-serving-troubleshooting.md). Working state запрещён. Команда меняет только отдельный qualification workspace, не final approval:

```bash
uv run --locked python -m scripts.candidate_serving_native --state .runtime --confirm-disposable
```

1. Runner генерирует три случайных credentials в памяти: основной 20/s burst 40 и два diagnostic clients по 1/s burst 1. Никакой фиксированный публичный token не используется.
2. Для diagnostic clients выполняет A/A/B/B с пустым JSON: ожидаются 422/429/422/429. Invalid body расходует rate token, но не запускает inference. Весь boundary опыт должен завершиться менее чем за 1 s, иначе результат inconclusive: refill мог уже наступить. Внутри окна ошибочное чужое списание должно изменить ожидаемый статус, а не спрятаться за большим остатком burst.
3. Через 1.05 s проверяет valid inference 200 обоих diagnostic clients после refill; длительность inference не используется для предположения, что следующий token ещё отсутствует. Затем проверяет primary 200 и foreign credential 401. Сохранить case labels без credential/ID/body. При отрицательном результате policy не повышается для успешного CI.
   Private in-process accounting обязан показать дельты `[2,2,4]`: по два успешных admission каждому diagnostic client, четыре всего в этом опыте. Это отдельная проверка: одни ответы 200 после задержки могут скрыть чужое списание с последующим refill. Snapshot не возвращается HTTP-клиенту, public evidence не содержит credential/ID.
4. Полный runner продолжает worker/trust outage, pause/expiry, explicit recovery, signed revoke и owned cleanup. Quota pass не заменяет остальные проверки и не даёт release_ready=true.
5. Сверить exact source revision, source_dirty=false, unique case labels и terminal workflow status. Native result публикуется отдельно от локальных mocks; до завершения CI считается pending.

Проверенный reference: [687a7c7, 67 cases pass](../evidence/serving-clients-687a7c7.md). Client window 0.002959852 s, statuses/refill/admissions совпали; trust outage, pause, genuine expiry, explicit recovery, revoke и source preservation также пройдены. Команда локальной диагностики RB-54 повторена: 36 methods pass. Credential rotation и full M13 audit не становятся проверенными от наличия этого reference.

Известная диагностическая ошибка `f273fd5`: частый polling trust-outage исчерпал primary client quota и дал 429, хотя первый 503 уложился в 60 s. [Failed trace](../evidence/serving-clients-f273fd5-failure.md) сохраняет все наблюдения. Исправлен сам polling: около deadline не менее 50 ms паузы после каждого ответа. Не повышать quotas и не разрешать 429 в outage assessment ради pass. Повторять полный disposable runner с новой code revision, не переименовывать старый failed report. Это конфликт двух проверок в лаборатории, не production-инцидент.

## Контролируемое изменение и восстановление

Credential rotation требует замены private файла и controlled restart; файл не перечитывается каждым запросом. До restart прекратить admission на уровне вызывающего клиента, дождаться завершения owned operations/cleanup. Не очищать Python executor и не обнулять buckets при ещё работающем SQL. При неопределённом cleanup следовать RB-53, не создавать параллельный serving process.

После restart проверить 401 старого credential, 200 нового только для разрешённой модели, независимые quotas и отсутствие автоматического обхода trust. Restart сбрасывает volatile counters и не является штатным лечением rate exhaustion. Engine activation/reload внутри процесса counters не сбрасывает. Этот rotation exercise ещё не является отдельным native credential-revocation acceptance; не заявлять его выполненным без проверки конечного состояния.

Rollback: вернуть предыдущую проверенную конфигурацию/код только после согласования риска. Возврат к версии без quotas снимает защиту и не считается безопасным автоматическим fallback. Не отключать auth/TLS/lease, не повышать все limits до максимума, не удалять единственный state. При сохраняющемся 503/неизвестном pending owner оставить ML недоступным и эскалировать; deterministic release gates продолжают действовать.

## Проблема, закрываемая реализацией

До этого slice был один token и общий 8-slot limit, без per-client rate/in-flight accounting. Новый ticket сохраняет ownership после HTTP cancellation; regression тесты проверяют отсутствие раннего release, double release и refill из clock rollback. Это обнаруженный архитектурный пробел и controlled qualification, не рассказ о production-инциденте. Audit, retention, public export canaries и полный M13 остаются следующей работой.
