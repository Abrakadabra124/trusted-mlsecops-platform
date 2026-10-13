# PB-15 / RB-32 / RB-33: подписанные отказы intake

Владелец: инженер MLSecOps lab. Область: synthetic SQL/scoped-controller path; [ADR 0025](../decisions/0025-signed-intake-denial.md), [intake](../artifact-intake.md). Файловый developer preview и preflight rejection до scanner request не получают этот SQL record. Полный M21 ещё не завершён.

## Зачем отдельный документ

DSSE (Dead Simple Signing Envelope) связывает JSON payload и его тип с цифровой подписью. Здесь Ed25519-подпись evaluator подтверждает отказ в оценке конкретного candidate, а не безопасность модели. `intake-denial` принципиально не является `stored-evaluation`: обычный reader оценки отклоняет его даже с правильной подписью.

Scorer уже имеет право append-only записи в evaluations. Он проверяет все поля отказа, подписывает bounded document, публикует по SHA-256 и читает его обратно. Promoter проверяет его без holdout labels и signing key. Новый столбец, DB role или расширение grants не требуются. Это сохранение результата карантина, не копирование опасной модели в новую доверенную область.

В SQL документе есть candidate/dataset/lineage/run/policy, существующая holdout reservation, model/image/tool/request/response hashes, counts и allowlisted reason. Нет labels, feature rows, приватных ключей, raw stdout/stderr и произвольной ошибки parser. `decision=deny-evaluation`, `release_ready=false` обязательны. Уже потраченный slot остаётся потраченным.

## RB-32: model_intake_fail / inconclusive с denial reference

**Симптом:** SQL evaluate заканчивается ошибкой `model_intake_fail:denial=<sha256>` или соответствующим inconclusive. Scoped controller возвращает nonzero и краткий JSON с `denial_reference`. Это штатное отклонение, а не успешная evaluation. Содержание роли worker не подписывается вслепую: controller сформировал и проверил отдельный отрицательный документ.

**Диагностика, read-only:** взять candidate reference из исходного запроса, denial reference из ошибки. Подставить проверенные SHA-256 в команды ниже. Trust-файл содержит публичные доверенные ключи; не подменять его автоматически. Работать из корня репозитория, с promoter client нужного lab state:

```powershell
$state = '.runtime/your-owned-lab'
$candidate = '<candidate SHA-256 из исходного запроса>'
$denial = '<denial SHA-256 из отказа>'
if ($candidate -notmatch '^[0-9a-f]{64}$' -or $denial -notmatch '^[0-9a-f]{64}$') { throw 'exact references required' }
uv run --locked python -m mlsecops.intake_denial --client "$state/storage-clients/promoter" --candidate $candidate --denial $denial --trust "$state/storage-trust.json"
if ($LASTEXITCODE -ne 0) { throw 'denial could not be verified' }
```

Exit 0 этой READ-ONLY команды означает лишь успешную проверку отрицательного документа. Проверить `decision=deny-evaluation`, `release_ready=false`, `intake.status`, пустой approved_outputs, правильные candidate/model/image и holdout slot. Это не команда promotion и не критерий допуска модели.

- `origin=worker`, model/profile rejection: проверить support matrix и исправить экспорт в новом candidate. Не загружать pickle на host и не переименовывать файл ради обхода проверки.
- `origin=controller`, scanner_protocol_rejected: проверить nonce/digest/version/counts. Не заменять report прошлым успешным scan.
- `scanner_timeout/crash/unavailable`: исследовать ресурсы и worker runtime по [PB-14](artifact-intake-troubleshooting.md). Inconclusive не преобразуется в pass.
- Документ не читается: сверить namespace, candidate reference, public trust, совместимый pinned tool/policy profile и наличие reservation. Не переподписывать историю после upgrade.

**Восстановление:** после установленного исправления выполнить новую evaluation, если budget доступен. Она получает новый nonce и тратит новую попытку. Прежний denial остаётся историей. Повтор публикации ТЕХ ЖЕ canonical bytes/nonce/timestamps идемпотентен и не резервирует дополнительный slot; это отдельная внутренняя операция, не новая evaluation.

**Rollback и эскалация:** остановить новые оценки при неожиданной подписи, несовпадении subject или потере integrity. Не удалять denial/reservation. Возврат к совместимой старой версии reader выполняется отдельным reviewed change без изменения данных. При подозрении на компрометацию ключа нужен trust/revocation process, не ручная замена public key ради green. Автоматический отзыв в этой процедуре не реализован.

## RB-33: intake_denial_persistence_failed

**Выявленный пробел:** до этого increment SQL pipeline не сохранял IntakeFailure. После завершения процесса оставался краткий отказ, а структурированный report мог исчезнуть. Это подтверждено source review, не заявляется production-инцидентом. Теперь negative contracts проверяют durable path и поведение при недоступном sink.

**Симптом и влияние:** pipeline не подтвердил подпись/SQL write/readback отрицательного документа. Quality evaluation не создаётся, prediction после отказа не возобновляется, holdout slot не возвращается. Ошибка не утверждает, что DB ничего не сохранила: acknowledgment мог потеряться после commit.

**Диагностика:** проверить существующий client/TLS/SQL service, ownership state и permission matrix штатными read-only средствами. Сопоставить время и reservation, сохранить очищенную причину и локальные закрытые логи. Не открывать SQL наружу, не расширять роль scorer и не отключать TLS. Если reference известен, проверить его через RB-32 в новом процессе.

**Безопасные действия:** восстановить существующий сервис по его scoped runbook; при сохранённых исходных report bytes допускается идемпотентная повторная публикация того же документа штатным writer. Если их нет, не реконструировать их догадками и не объявлять аудит полным. Новый scan - новый расход budget. Не делать reset ledger, global prune, UPDATE/DELETE аудита или очистку единственной копии SQL volume.

**Критерий восстановления:** signature/subject/reservation проверяются новым reader, original quality report не изменён, повтор той же публикации не добавляет rows/slots, нет нового approval. Контролируемые outage/readback tests не заменяют реальный disaster recovery drill. Неопределённое состояние сохраняется как operational limitation и эскалируется владельцу.

## PB-15: проверка на одноразовом SQL стенде

**Изменяющий плейбук.** Нужны pinned uv/Python, Linux Docker daemon, свободные ресурсы и Docker subnets. Не использовать рабочий state: создаются synthetic data/keys/candidates, три reservations и три signed denials. Один benign pickle fixture публикуется тестовым оператором для проверки отказа; это не результат настоящей атаки на обучение. Локальный [RB-28](qualification-environment-troubleshooting.md) описывает ранее установленное исчерпание subnet pool. При этом остановиться или использовать fresh CI, не удалять чужие сети.

```powershell
$state = '.runtime/denial-recheck-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
if (Test-Path -LiteralPath $state) { throw 'fresh disposable state required' }
uv run --locked python -m mlsecops bootstrap --state $state
if ($LASTEXITCODE -ne 0) { throw 'bootstrap failed' }
uv run --locked python -m mlsecops.storage_bootstrap --state $state
if ($LASTEXITCODE -ne 0) { throw 'SQL bootstrap failed; preserve partial state' }
uv run --locked python -m mlsecops build
if ($LASTEXITCODE -ne 0) { throw 'worker build failed' }
uv run --locked python -m mlsecops.storage_pipeline --state $state
if ($LASTEXITCODE -ne 0) { throw 'baseline evaluation failed' }
uv run --locked python -m scripts.intake_denial_native --state $state --confirm-disposable
if ($LASTEXITCODE -ne 0) { throw 'denial qualification failed; preserve state' }
```

Без `--confirm-disposable` script заканчивается exit 2 до обращения к среде. Подтверждение нельзя применять к рабочей БД: read-only preflight проверяет marker, current source/image и available budget, но не умеет доказать бизнес-одноразовость любой переданной папки.

Expected: 25 checks, три negative outcomes, ни одного prediction по этим попыткам, только шесть новых evaluation-table objects (3 reservations + 3 denials). Проверяются настоящие SQL permissions и fresh-process signature readback. UPDATE/DELETE probes адресуют только новый fixture record и в любом исходе откатывают транзакцию; неожиданное разрешение считается failure, не recovery action.

Два сценария выполняют настоящую инспекцию Docker: unsafe model и malformed response после чистой инспекции. Timeout здесь - transport-boundary exception fixture, не новый crash test процесса; настоящие Docker crash/deadline отдельно проверены в PB-14. Persistence проверяется commit/readback из другого процесса, а не отключением питания PostgreSQL. Full M21, Kubernetes-specific negative replay, serving/release integration и crash recovery этим не закрываются.

Evidence: `evidence/intake-denial-qualification.json` в выбранном state; исходная evaluation неизменна, три slots остаются spent, duplicate publication не добавляет rows. Public CI и подтверждённые результаты отражаются в [STATUS](../../STATUS.md). SQL state и keys остаются приватными. Этот плейбук намеренно не удаляет контейнеры/volumes: cleanup требует отдельной проверки ownership и сохранности нужных evidence.

## Проверенное выполнение PB-15

2026-10-13 на commit `10e5e8e9e886db8911ca4ad8866dc545e985df97` [storage CI 38438233449](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38438233449) выполнил этот Python playbook на fresh PostgreSQL с TLS и настоящими scoped roles: **25 checks pass, source_dirty=false**. Время native report - `17:26:30.393272Z`. Три outcomes сохранились в slots 3, 4, 5; новый процесс проверил подписи, original quality evaluation осталась неизменной, duplicate publication не создала дополнительные rows или reservation. Denial не принят quality reader. SQL UPDATE/DELETE probes завершились ожидаемым отказом и rollback, predictor не вызывался после intake denial.

Отдельные 15 controlled contracts прошли с coverage denial module 98% (75/76 statements, 15/16 branches); native subprocess проверил оставшийся CLI entry point. Outage/readback faults из этих contracts - контролируемые fixtures, не доказательство recovery после реального отключения SQL. Сам SQL native timeout тоже injected fixture; эти разные уровни evidence нельзя складывать в заявление об универсальной отказоустойчивости.

Fresh state в CI создаётся командами Linux shell из workflow; PowerShell orchestration выше соответствует этому порядку, но локальный полный replay не выполнялся из-за ранее зафиксированного subnet limitation. Рабочая БД и holdout ledger не затронуты. Полные digests, ссылки на остальные workflows и оставшиеся security blockers сохранены в STATUS. Публичный report подтверждает наблюдаемый результат проверки, но без private state не служит автономным архивом всех signed envelopes.
