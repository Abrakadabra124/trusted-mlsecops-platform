# Периодический trust observer: проверка 2026-11-11

Неделя11 «Security events и потеря telemetry», T29 «Security event contracts и replay».
Принят этот компонент: постоянное наблюдение за committed SQL trust history,
heartbeat после подтверждённой проверки, восстановление доставки и обнаружение
остановки. Полный M23 и R1 остаются открытыми.

## Source и воспроизведение

- Runtime: `df8ce0dac438889b63de3ca99a963168f10b75a2`.
- Исправленный qualification: `25371bfc0de5569d15cfa5dcff2a630eccc560d8`.
- [CI43087532653](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43087532653):
  jobs130755746772 contracts и130755746254 native завершены success.
- Linux runtime fingerprint:
  `35bccb23a756e63253a9adb978f6b01db31681a5b5bc6ecf079863c20d8cdb45`.
- [ADR0065](../decisions/0065-periodic-trust-observer.md),
  [план](../../tasks/periodic-trust-observer-plan.md),
  [ранбук](../operations/periodic-trust-observer.md).

Изменение25371bf не меняет production runtime или workflow относительно df8ce0d:
исправлены native readback и его regression test, порядок независимого чтения
heartbeat, выбор нового gap и cleanup проверочного процесса.

```sh
git checkout 25371bfc0de5569d15cfa5dcff2a630eccc560d8
uv sync --locked --no-build --python 3.12.15
uv run --locked python -W error -m unittest scripts.security_trust_service_qualification scripts.security_trust_events_qualification scripts.security_identity_events_qualification scripts.security_producer_heartbeat_qualification scripts.security_identity_http_qualification
```

Новый checkout и отдельное locked окружение Python3.12.15 на Windows:
**83tests /2.890s /3Linux-only skips**, `-W error`, import/interpreter paths
принадлежат checkout, git clean. Предыдущий df8ce0d clean запуск:54tests/5.681s,
3Linux-only skips. Это не локальная проверка SQL/POSIX; запрещённая инфраструктура
на Windows не запускалась. Hosted сценарий выполняет workflow
[security-events-contracts.yml](../../.github/workflows/security-events-contracts.yml)
через `python -W error -m scripts.security_trust_service_native`; guard отвергает
не-Linux, не-GitHub-Actions и не-github-hosted до создания инфраструктуры.

## Что именно подтверждено

Native использует настоящий отдельный supervisor и его child, SQL/TLS authority,
подписанный registry с trust heartbeat_required, POSIX outbox и отдельный HTTP
collector. Synthetic keys/revocations остаются приватными; worker/model inference
этот сценарий не использует.

| Проверка | Наблюдаемый результат |
| --- | --- |
| Первый heartbeat | Независимое чтение collector совпадает с подписанным producer envelope; health200 |
| Второй supervisor | Тот же приватный config directory занят; второй CLI exit1 до запуска child |
| Реальный период | **30.022s**, часы не ускорялись |
| SQL commit -> подтверждённое событие | **29.77508551599999s**, подписанный receipt и route `security.trust`, subject равен digest committed документа |
| Источник недоступен | Собственный каталог SQL credentials временно переименован на35s; supervisor жив, heartbeat и outbox не изменились; доступ затем восстановлен |
| Collector outage | Второй отзыв сохраняется pending; после восстановления доставлен исходный envelope, первый record неизменен, всего2events |
| Перезапуск supervisor | История/epoch сохраняются, heartbeat counter увеличивается, событий по-прежнему2 |
| Остановка | Две lifecycle остановки завершены exit0; отдельная проверка process group не нашла выживших child |
| Потеря heartbeat | Новый подписанный `telemetry.gap` с receipt через **90.93080405500004s**, health503 и fresh promotion audit refusal |
| Очистка | Collector/private files удалены; ownership-bound SQL container/network/volume удалены с readback; source/fingerprint неизменны |

**15native assertions**, включая повторную проверку cleanup двух lifecycle;
это не15 независимых attack scenarios. Также прошли25promotion,37trust-history
и46HTTP-identity/heartbeat assertions на том же source/fingerprint.

**593Linux test executions /0skips**:
21+25+47+10+1+38+85+65+9+36+60+31+36+129. Это число запусков unittest,
не количество независимых security guarantees.

| Модуль | Statements | Branches |
| --- | --- | --- |
| security_trust_events | 163/164 | 65/66,98.48% |
| security_trust_service | 89/90 | 21/22,95.45% |

Coverage exclusions нет. Module-main строки отсутствуют в unit coverage,
настоящие CLI отдельно выполнялись native. Тесты включают подмену config,
source/history/delivery failures без heartbeat, optional heartbeat registry,
legacy outbox, таймаут реального собственного Python child, SIGTERM/stop,
kill/reap/неподтверждённую очистку и восстановление signal handlers.

## Сохранённый первый отказ

[CI43087026043](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43087026043)
на df8ce0d: contracts success592Linux/0skips, native failure до запуска observer.
Диагностика TypeError указала на конструктор Store в native строке81: передан
несуществующий keyword `expected_sha256`, API принимает три positional arguments.
Отдельный тест воспроизвёл ошибку с реальным конструктором, после исправления
проверяет сохранение operator pin/registry и отказ malformed pin. Ошибка была в
соединении проверочного reader, не повод ослаблять verification или считать
первый запуск успешным. Context cleanup сохранил ownership/readback проверки.

## Ограничения и следующий шаг

Heartbeat подтверждает успешный проход наблюдателя, не release approval.
Нет SQL write grants и автоматической rotation/epoch migration. Транспорт
остаётся loopback; OS owner доверенный, защита от host administrator не заявлена.
Source outage выше означает недоступность credentials, не сетевой blackhole SQL.
Времена относятся к одному hosted lab, не production SLA.

Нужен обязательный deployed profile всех producers, согласование schema2
promoter с Kubernetes-обвязкой и защищённый транспорт между Pod; worker не должен
получать keys/outbox/collector credentials. Далее actual sequence gap, audit
outage при здоровой ML dashboard, свежие M13/M14 и общий M23. M10/fullM19,
independent M22 challenges0/2, M16/M17, image/reliability debt и M18 последним
на одном candidate сохраняются. Никакого полного R1 по этому evidence нет.
