# Observer root rotation: компонентное доказательство

Source: `e7ec7097fc656749eeb93d57a2c8be0d9efb9722`, fingerprint
`7b7c57adbaf92cb79fe98f12191db4c0bac15ccdde02157f832eec933a5c81c5`.
Image: `sha256:744b6c4d0a0b61bc3e64d14ab4fcc61ab35497fba87edda43e3e48e3098bdb44`.
[Kubernetes run43125706293](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43125706293)
завершился success, job130877113634. Основной native сценарий исполнялся
2026-11-12 00:16:04-00:24:29UTC. Локальная инфраструктура не запускалась.

До ротации выполнены19promotion+12audit cases и существующий persistent HTTP
сценарий. Новая ротация проверила10 дополнительных условий:

- Ещё не записанный в SQL переход, повреждённая acceptance signature и неверный
  ожидаемый корень отказали без изменения marker.
- Новый observer Pod прошёл собственную проверку подписанной SQL history.
  Переход занял9.8959s при ограничении120s, heartbeat14->15.
- Producer pin и префикс подписанных событий outbox сохранены; ключи и PVC
  не заменялись. Проверен новый Pod и текущий контейнер, не предыдущий log.
- Старый корень отклонён реальным `trust_authority.read`, новый подтверждён.
- Конкретное событие trust.revoked/key новой trust document совпало по event ID,
  envelope digest и receipt с независимым collector:1совпадение.
- Повтор package не перезапустил Pod, model ledger не изменился.

Trust document digest:
`a9c5c4778c890d38f4c981a18e3cec2ad70139b8665bbf208d894b874bd4d1b1`.
Owned source SQL stop и disposable cluster deletion завершились success с
проверкой конечного состояния. Исходные логи хранятся приватно вне Git.

Clean checkout e7ec709 с собственным locked Python3.12.15 окружением воспроизвёл
123tests за7.268s,1POSIX test skipped на Windows; checkout оставался чистым.
Это локальная проверка кода, не кластерный результат.

## Отказы и ограничения

[Security run43125649611](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43125649611)
на том же source завершился failure. Contracts job130876921570 не достиг95%
покрытия изменённого audit operator. Добавлены реальные signed-history/ownership
negative cases; локально модуль достиг211/213statements и74/76branches.
Для трёх новых modules добавлен отдельный обязательный CI coverage gate:
profile71/71+26/26, readback54/54+12/12, rotation122/123+29/30 локально.
Обновлённый общий локальный набор:133tests7.638s,1Windows skip.

Native security job130876921167 отдельно остановился по45s deadline после
возврата SQL credentials периодическому observer. Диагностика:2failed checks,
1event/1receipt в обоих journals. Причина повторявшейся ранее нестабильности
не установлена. Добавлена безопасная read-only диагностика; нормативы сохранены.
Это не доказательство исправления таймаута; успешный Kubernetes run не заменяет
security CI.

## Повторная проверка после расширения тестов

Followup `4f726f53fcf1ba0b6309bea11bb15b18dbf1241b`:
[security43127559794](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43127559794)
terminal success. Contracts job130883397834 выполнил842test executions без
skips и подтвердил указанные per-module coverage ratios. Native job130883398202
выполнил25audit-admission,37trust-history,15periodic-observer и46identity cases.
Очистка принадлежащих fixtures процессов, SQL, volumes и private files подтверждена.

В periodic observer измерены30.025s между heartbeat, max commit-to-receipt
29.758074267s, обнаружение остановки90.871880413s при исходных нормативных пределах.
Read-only диагностика добавлена, но её failure branch в этом успешном native
run не исполнялась. Причина предыдущего таймаута всё ещё не установлена.

Runtime fingerprint совпадает с e7ec709 выше: production code между commits
не менялся, расширены tests/diagnostics/docs. Поэтому кластерное доказательство
остаётся точно привязанным к e7ec709/image выше; новый Kubernetes run не заявляется.
Чистый checkout4f726f5 с отдельным locked venv воспроизвёл133tests за7.930s,
1POSIX Windows skip, Git clean. Общая приёмка R1 из этих проверок не следует.

Actual candidate `1fd9d6094ad5cb3b419defb5bc367603b0b93a8db8c45a9f39ed2c6e097be67c`
не получил admission. `full_M10=inconclusive`, `release_ready=false`.
Mandatory serving heartbeat, остальные caller transitions, автоматическое
восстановление прерванной ротации, fresh M13/M14 и общий M18/R1 остаются открытыми.

Инструкции: [runbook](../operations/kubernetes-security-state.md#переход-observer-после-ротации-корня),
[план интеграции](../../tasks/audited-serving-integration-plan.md).

## Проверка caller-интеграции

Source `aa276b260e4689a59487221182eaa2648f20a878` подключил реальный observer
transition к ordinary и candidate PRIMARY rotation. Local161tests/1Windows skip,
чистый locked checkout161tests23.224s/1Windows skip; обе coordinator modules
имеют155/155statements и48/48branches. Эти результаты не доказывают hosted flow.

[Security43130462337](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43130462337)
завершился success:856Linux executions/0skips и25/37/15/46native cases.
Период trust30.020s, max commit delivery29.878474680s, stopped notice90.802325302s.
Прежний45s observer timeout остаётся необъяснённым.

[M11 run43130494941](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43130494941),
job130893141074, завершился failure. M11 выполнялся00:56:11-01:08:04UTC12ноября.
После `planned-authority-root-rotation` достигнут `live-trust-outage`, затем
`kube_serving_probe:trust-fault-response-contract`, HTTP phase, exit1. Сам
HTTP status/body исходная диагностика не сохраняла в публичном результате,
поэтому причина пока не установлена. Candidate rotation и следующие проверки
этой кампании не приняты. Backup/recovery step skipped, source SQL stop и
удаление owned disposable cluster success с проверкой конечного состояния.
M11 `status=fail`, `release_ready=false`; полный R1 не принят.

Следующий диагностический increment сохраняет конечный allowlist кодов отказа
HTTP вместо общего response-contract. Порог, успешный контракт и fail-closed
поведение не меняются. Отрицательные cases проверяют отсутствие private canary
в результате, сохранение отказа и доступность кода через CLI allowlist.
Local47смежных tests pass; отдельный lifecycle coverage набор36tests,
106/106statements и44/44branches в изменённом module. Hosted replay pending;
это улучшение диагностики, не доказанное исправление причины.

Последующий [5486596 /43132977638](m11-observer-callers-2026-11-12.md) завершился
success с146M11cases и обеими observer transitions. Причина прежнего отказа
не установлена; полный результат, primary hash validation и ограничения по ссылке.
