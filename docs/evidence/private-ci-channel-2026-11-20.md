# Private cross-job canary: verified prerequisite

Неделя 13, T21. 20 ноября 2026 проверена настоящая передача AES-GCM ciphertext
между двумя отдельными GitHub-hosted jobs. Это **canary transport**, не frozen
ML candidate, не полная M11/M18/R1-приёмка.

## Source and observation

Точный source: `932c2a411dd21a3ce8c7e909796682de2446c940`, опубликован в
`Abrakadabra124/trusted-mlsecops-platform`. Его неизменённый Git commit DAG
зеркалирован в приватный execution repository
`Abrakadabra124/trusted-mlsecops-ci-private`, ID `1465012664`.
Фактические environment identities не подменялись публичным repository name.

Оператор наблюдал private run **44681708741**, attempt 1. Доступ к его журналу
требует разрешения владельца. Raw log, metadata и continuation receipt сохранены
вне tracked Git; публичная запись содержит только закрытые outcomes.

| Job | Result | UTC start | UTC end | Duration |
| --- | --- | --- | --- | --- |
| producer | success | 05:32:39 | 05:32:59 | 20 s |
| receiver | success | 05:33:02 | 05:33:21 | 19 s |
| cleanup | success | 05:33:24 | 05:33:37 | 13 s |

Все три job terminal success. Интервал от первого старта до последнего
завершения - 58 секунд с промежутками очереди. Каждый job использовал свежий
checkout этого же SHA; guard проверил clean state, опубликованный source,
private metadata, run/attempt, branch, workflow path и роль job.

## What actually passed

- Producer создал шифрованный фиксированный canary, не ML-пакет. Обязательные
  image/candidate/proposal поля являются явно отмеченными fixture identities.
- Receiver проверил metadata exact artifact ID до скачивания. Context и pin
  пришли по доверенной зависимости jobs отдельно от artifact bytes.
- Обычный AES reader расшифровал исходный canary. **Семь отрицательных crypto
  проверок** отклонили ciphertext с обновлённым pin, неверный ключ, pin, run,
  attempt, phase и другое разрешённое repository.
- Cleanup удалил **1** принадлежащий запуску artifact и проверил его отсутствие
  через GET 404 плюс успешно прочитанный пустой run artifact list. Оператор
  дополнительно получил `total_count=0` отдельным CLI-запросом после завершения.
- Временный `CHANNEL_AES_KEY` удалён оператором после terminal state;
  повторный secret list пуст. Активных запусков private repo не осталось.
- Все четыре closed projections сохраняют `release_ready=false`.

Перед первым upload подтверждён account Actions hard zero-spend budget и
наличие included usage. После запуска billing UI показывал billable Actions
usage `$0`; это наблюдение интерфейса на момент проверки, не банковская выписка
и не резерв будущей квоты. Budget не увеличивался. Персональные billing details
не публикуются. В private repo активен только этот workflow; 37 остальных
отключены. Разрешены четыре Actions по exact commit SHA, SHA pinning обязательно,
default token read-only и PR approval capability выключена.

## Code qualification

Начальные negative tests сначала отказали на отсутствующем driver и на запрете
private execution в прежнем transport core. Дополнительный тест закрепил отказ
неверной роли job **до** Git/API. После реализации:

- **55/55** core/channel tests, 0 skipped; повторены scoped reviewer и hosted job.
- **60/60** adjacent bridge/validation/frozen tests, 0 skipped, 110.256 s локально.
- `ci_transfer`: 102/102 statements, 42/42 branches, оба 100%.
- `ci_private_channel`: 177/178 statements (99.44%), 23/24 branches (95.83%).
  Непокрыт только direct `__main__` launch; exclusions не добавлены.
- Hosted preflight отдельно проверил >=95% statements и >=95% branches каждого
  модуля. Ruff, documentation validator, YAML/permissions/pins, Bash и inline
  Python syntax checks passed. Scoped review: APPROVE, no P1/P2.

## Reproduction and limits

[Runbook и playbook](../operations/private-ci-channel.md) задают создание нового
временного key, один dispatch на exact SHA, наблюдение terminal state, cleanup
и проверку удаления secret. [План](../superpowers/plans/2026-11-20-private-ci-channel.md)
и [design](../superpowers/specs/2026-11-20-private-ci-channel-design.md) сохраняют
исходные ограничения.

Проверен фиксированный небольшой canary от доверенного producer, а не общий
защищённый downloader произвольных archives. Администраторы GitHub/аккаунта
остаются доверенными. Удаление не является доказанным secure erase у провайдера.

Следующий обязательный шаг - передача **исходного** frozen candidate, независимых
authority inputs, original primary evidence и ключей только разрешённым ролям.
Существующие пять candidate adapters ещё public-only; их нельзя обойти заменой
environment variables. Exact image provisioning, параллельные gates одного
candidate, image findings, два независимых M22 challenges и M18 последним
остаются открытыми. Canary не снимает эти блокеры и не продлевает proposal windows.
