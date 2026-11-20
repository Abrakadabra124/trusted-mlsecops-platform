# Native serving consumer M13/M14/M15 на 422accf7

20 ноября 2026 года [run 44662206137](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44662206137)
и [job 136042867747](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/44662206137/job/136042867747)
завершились **success** на exact source `422accf72d5f994b5501bcd83bbf07b7f8374600`.
Запуск: push ветки `qualify/original-serving-consumer-native`, disposable hosted
`ubuntu-24.04`, Python `3.12.15`, uv `0.12.23`, repository lock.
Metadata, selected summary и summaries private log сверены; порядок исполнения
проверен в source этого commit. Новый runtime при подготовке отчёта не запускался.

## Подтверждённый результат

| Участок | Результат |
| --- | --- |
| Transfer/import preflight | 131 tests, 64.195 s, `OK` |
| Serving preflight | 73 tests, 27.743 s, `OK` |
| M07 | CLI exit 0, diagnostic `status=pass` |
| Producer cluster cleanup | `required=1`, `verified=1`, pass |
| Основной driver | `status=pass`, `stage=complete`; M13 **514**, M14 **153**, M15 **188** cases |
| Consumer cleanup | `required=4`, `verified=4` |
| Source SQL stop | step success, marker и stopped-state verification выполнены |
| Отдельный cleanup CLI | `status=pass`, `stage=complete`, cleanup **4/4**, gate counts **0/0/0** |

Оба `Ran ...` summaries сопровождаются отдельным `OK`; skipped/FAILED summaries
отсутствуют.
Coverage script проверяет точный inventory четырёх модулей: `ci_serving_native`,
`ci_serving_recovery`, `ci_serving_retention`, `serving_campaign`, и минимум **95%**
отдельно для statements и branches каждого. Эти thresholds пройдены; фактические
coverage stats JSON в log не напечатаны. Native 100% или точные covered/total
не заявляются; parent offline coverage является отдельным evidence.

Job: **02:38:14-03:09:11 UTC, 30 min 57 s**. Driver:
**02:51:05-03:09:06 UTC, 18 min 01 s**. Source SQL stop завершён 03:09:07,
отдельный cleanup CLI - 03:09:09 UTC. Это измерение одного run, не гарантия времени.

## Candidate, cleanup и replay

Trio использует один original proposal/candidate, новый owned consumer SQL,
три последовательных owned clusters и два проверенных transitions.
В [driver](../../scripts/ci_serving_native.py) после ordinary gates обязательны:
cleanup -> private primary retention -> выход из upstream и candidate contexts
-> проверка отсутствия consumer state -> независимый offline replay архива
с исходными внешними аргументами -> повторная проверка source/producer stopped pin.
Только затем возможен `stage=complete`. Retention/replay требуют `release_ready=false`.
Этот порядок установлен по exact source и успешному завершению обязательных checks.

Cleanup 4/4 относится к трём cluster witnesses M13/M14/M15 и consumer SQL.
Для clusters проверяется отсутствие записанных Docker containers, owned volumes
и kind cluster. SQL cleanup подтверждает **остановку**, не удаление его
container/network/volume. Отдельный cleanup CLI перечитывает ownership witnesses
и producer stopped record; он не запускает gates заново, поэтому counts 0/0/0 ожидаемы.
Original proposal window **1800 s** и minimum **600 s** перед каждой фазой
не продлены. Job timeout остаётся 60 min.

## Границы доказательств

Private primary сохранены вне удаляемого consumer context, но только на disposable
runner. Retained packet backhaul и private cross-job storage не выполнены;
архив с runner не получен для отдельного локального replay. Pins, packets/model
data, raw logs, signatures и trust keys в этот документ не включены.
Успех [M11/M12 на f9bf7c5](consumer-native-2026-11-20.md#повтор-после-исправления)
относится к другому source/candidate. Эти runs нельзя объединять в same-candidate M18.
Полный R1 не принят: общий M18, independent M22 **0/2** и image audit blockers
при coverage **6/14** остаются открытыми. Native результат не переносится на новые commits.
Порядок запуска и восстановления: [serving playbook](../operations/ci-serving-native.md),
[workflow](../../.github/workflows/serving-consumer.yml) на указанном exact source.
