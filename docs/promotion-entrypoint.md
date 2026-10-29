# T13: исполняемый promotion по подписанным references

Обязательный участок CP3/R1-B04 и [M10](acceptance.md#m10). До этого admission SDK и SQL journal вызывались из Python/qualification; обычный [serving CLI](../mlsecops/serving_http.py) уже существовал. [Новая команда](../mlsecops/promotion_controller.py) соединяет неизменяемые CAS-объекты, существующий verifier, online trust и durable selection без создания approval внутри команды.

CAS, content-addressed storage, хранит объект по SHA-256 его байтов. Ссылка выбирает точные материалы; подпись подтверждает автора и назначение документа. Отдельный operator config закрепляет корни доверия, promotion policy, runtime image, исходный candidate context и пути к двум TLS client identities. Пользовательский request не может заменить эти параметры или передать своё время проверки.

## Контракт и порядок работы

Config schema v1: `storage_client`, `trust_client`, `context`, `trusted_root`, `expected_policy`, `expected_serving_image`, `trust_root`, `minimum_trust_version`. Оба пути абсолютные; обе SQL identities обязаны быть `ml_promoter`. Model storage и независимая trust authority остаются разными сервисами. Приватные client keys находятся в credential directories, не в request/config JSON и не в Git.

Request schema v1: `proposal_reference`, `policy_reference`, `assurance_reference`, `approval_reference`. Все ссылки - SHA-256 CAS objects. Для последней пары допустим null только как явно отсутствующий документ; он приводит к штатному отказу, не к обходу verifier. Unknown fields/schema и попытки передать `clock`, credentials или другие roots отвергаются. Config <=1 MiB, request <=64 KiB, один report <=1 MiB, весь report transport <=8 MiB.

1. Проверить формы документов и identities до чтения CAS. Взять время из SQL, а не из request.
2. Прочитать canonical signed policy, сверить внешний root, digest, environment, разделение roles и неизменный набор M01-M23.
3. Загрузить полный proposal по digest, подписанные assurance/approval. Список reports берётся из подписанной assessor assurance; каждый report проверяется по hash и size.
4. Вызвать прежний `promotion.promote`: повторная полная авторизация, fresh online trust, публикация immutable proof, транзакционная запись selection, SQL/CAS readback и ещё одна проверка trust. Ключей publisher/assessor/approver команда не получает и ничего не подписывает.
5. Успех означает **recorded-not-activated, release_ready=false**. Штатный production Reader отдельно проверяет current selection, signatures и trust перед verified load; сама запись journal не означает готовность HTTP.

```bash
uv run --locked python -m mlsecops.promotion_controller \
  --config /secure/promoter/config.json \
  --request /secure/promoter/request.json
```

Это пример путей развёртывания. Operator должен сформировать и защитить config из проверенного candidate context и внешних pins. Нельзя автоматически брать доверенные roots/policy из пользовательского proposal. Подготовка настоящих assurance/approval остаётся работой независимых ролей после реальной полной приёмки, а не hidden option этой команды.

CLI предназначен для Linux и включает существующий process privacy guard: запрет core dumps и dumpable. Ошибки имеют постоянный stderr `promotion_rejected`, exit 1; interruption - exit 130. Для повторного запроса используются те же immutable references. Неоднозначный commit требует readback, а не выдачи нового sequence.

## Проверка и ограничения

Локально 11 negative/positive contract tests новой команды прошли, 73/73 statements и 24/24 branches. Проверены signed references, exact retry, отсутствующие reports/assurance/approval, чужая identity, подмена pins, noncanonical/forged envelopes, revocation/outage и transport budgets. Fixtures имеют искусственные all-pass reports и явно не являются приёмкой настоящей модели. 38 adjacent/controller tests и 6 probe tests также прошли; группы пересекаются и не складываются в число уникальных проверок.

[Hosted workflow](../.github/workflows/promotion-entrypoint.yml) выполняет два разных сценария. Настоящий evaluated candidate должен получить `release_assurance_required` в parent и отказ отдельного CLI process без записей после admission. Отдельные disposable model/trust stores содержат только controlled signed fixture; CLI записывает и повторяет selection, затем прежние Reader/HTTP/ONNX probes проверяют readback, запросы и отзыв. Положительная fixture не переносится на настоящий candidate. Native результат подтверждён ниже.

Это CLI с отдельными SQL credentials, **не доказанная OS/Kubernetes-изоляция promoter**. Operator host остаётся доверенным; read-only mounts, отсутствие signing keys/API token и сетевые ограничения отдельного deployed controller ещё требуют интеграции. Полные M10/M12/M18 и настоящий production promotion остаются открытыми; новая команда не меняет критерии R1.

## Native результат 2026-10-29 МСК

[Run 40792286657](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40792286657), job `123180164943`, commit `d78e451a948d04ec00532ce9ad54ef7f4828b2e8`, attempt 1: **success**. Clean checkout, source_dirty=false. Native integration 03:11:34-03:12:00 МСК. До неё на Linux прошли 33 adjacent/probe tests и 11 controller tests, 73/73 statements и 24/24 branches. Все **44 integration cases pass**: три actual-candidate refusal checks и 41 controlled Reader/HTTP case.

Настоящий candidate: `0fbf8d2ab375cdfa8286f43bed57eee27a14487d29b57b7229001cfad9f06dec`. Proposal: `8f3bae5717c73bbdb9574fa35e4b44c19054b1d09d37cfb85fdea8ddec899b11`. Model: `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`. Source fingerprint: `2ff22e6d695ced09e99c99999ae2790ca31f832c82f521a466140b5da450bb37`. Request digest: `d124d5642422788390f374839bf6bb92156fc2ccd76fe3a5ff86f59af2f8888f`.

- Parent получил точный `release_assurance_required`. Отдельный CLI с теми же сохранёнными config/request вернул exit 1, пустой stdout и постоянный stderr. Список immutable releases objects не изменился после отказа. CLI не выдаёт текст внутреннего exception, поэтому конкретная причина подтверждена parent-проверкой, а не угадана из exit code.
- В отдельных controlled model/trust stores два вызова реального CLI вернули один и тот же selection receipt. Production Reader прочитал и проверил current head, signed chain и точные model bytes; fixture не стала реальной acceptance-моделью.
- Controlled HTTP/ONNX: три golden rows, max error `7.583387712228884e-08`, правильный running digest, смешанные score/abstain. Проверены 401, 413, 422, 429 и 503; quota refill восстановил 200. Остановленный worker дал отказ за `2.0257453749999854` s, explicit verified reload восстановил путь. Это не нагрузочный M14 и не полный M12.
- Реальный отзыв controlled модели дал 503 для inference/readiness, старый handoff и новый load отвергнуты. SQL selection без signed authorization также отвергнут. Private audit correlation pass.
- Owned model/trust workspaces и их контейнеры/network/volumes удалены с проверкой отсутствия. Source state/checkout сохранены; cleanup исходной SQL БД success с `State.Running=false`.

Итог отчёта: `status=pass`, **full_M10=inconclusive**, `release_ready=false`; вложенный Reader report сохраняет full_M12=inconclusive. Исходный actual candidate не получал искусственную assurance. Тестовые root/signing keys и credential/config/request files не публикуются. После удаления runner приватный runtime state не сохраняется как production environment; повторение требует свежего disposable checkout.

## Ранбук и плейбук

Владелец: platform operator; право выдавать assurance/approval принадлежит отдельным assessor/approver. В этой сессии локальные Docker/WSL/Kubernetes/SQL запрещены; runtime-воспроизведение только в disposable hosted CI.

1. Read-only: сверить run ID/head SHA, `git status --short`, исходные proposal/policy digests и наличие обязательных подписанных документов. Не показывать credential directories или raw config в публичном evidence. Для native workflow после публикации на default branch: `gh workflow run promotion-entrypoint.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref <verified-commit>`.
2. Нет assurance/approval или полный gate fail/inconclusive: сохранить отказ. Не генерировать all-pass JSON, не брать другой candidate, не менять required_gates. Для M22 по-прежнему нужны независимые challenges.
3. `promotion_rejected` - постоянная приватная диагностика, сама по себе не доказывает причину. Native harness отдельно проверяет ожидаемый код parent exception и неизменность storage. В эксплуатации operator читает доверенные материалы и ledger через [PB-21](operations/promotion-ledger-troubleshooting.md); stdout пустого процесса не считается доказательством отсутствия commit.
4. После timeout/interruption проверить exact request SHA в journal и current head, действительность authorization/trust. Повторять только прежний request при действующем окне и подтверждённой совместимости. Новый sequence, изменение alias и отключение trust/TLS не являются recovery. Процедура неоднозначного commit описана в PB-21.
5. При trust outage/revocation не разрешать activation. Serving Reader обязан самостоятельно отказать; положительный receipt CLI не является бессрочной lease. Сохранить source, policy, request digests и timestamps, затем разбирать authority через [trust runbook](operations/trust-troubleshooting.md).
6. CI удаляет только проверенные owned model/trust fixtures через существующий reader cleanup, затем останавливает source SQL и проверяет `State.Running=false`. Рабочую БД, namespaces и ключи эта диагностическая команда не должна создавать или мигрировать. Повтор после сбоя начинает report с inconclusive, чтобы старый pass не сохранился как новый результат.

Контролируемый сбой записи evidence выявил вторичную ошибку в обработчике отказа harness. Исправлено: даже при недоступном файле процесс возвращает nonzero и постоянную диагностику без приватного пути. Если запись evidence невозможна, нельзя трактовать старый файл как результат нового процесса; нужны текущий exit code, run ID и source revision. Этот отказ проверен тестом, не является наблюдавшимся production-сбоем.

Ошибки и негативные сценарии в этом документе - controlled validation, не заявленные production-инциденты. Для полного выпуска ещё нужны остальные CP3-CP5 и приёмка всех gates на одном candidate.
