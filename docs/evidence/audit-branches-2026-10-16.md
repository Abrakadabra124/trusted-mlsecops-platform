# Audit branch coverage: qualification, 2026-10-16

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Increment после `5a4ab26`; [предыдущая native qualification](audit-retention-2026-10-16.md), [ADR 0037](../decisions/0037-audit-retention.md), [RB-56/PB-30](../operations/audit-retention-troubleshooting.md). Статус: local contracts pass, новая native qualification pending. Цель R1, полный M13 и полный M18 не закрыты.

## Требование и реализация

M18 требует >=95% branch coverage новой security-critical логики. Прежние 97%/93% Cover смешивали statements и branches и не доказывали этот критерий. Новый [checker](../../scripts/audit_branch_coverage.py) использует публичный Coverage.py `branch_stats`: отдельно суммирует total/taken exits для каждого из двух обязательных audit-модулей. Сравнение целочисленное `100 * taken >= 95 * total`, без округления при принятии и без усреднения модулей. Пустое/отсутствующее measurement, line-only data и отсутствие точного файла не дают pass.

Workflow создаёт fresh coverage в том же checkout без append, затем выполняет branch gate. Старые Cover thresholds остаются дополнительными проверками. Сам checker не является подписанным доказательством свежести произвольной сохранённой базы; код и evidence привязываются к конкретному CI revision. Любой failure/inconclusive возвращает exit 2 и release_ready=false.

По официальным [Coverage.py branch measurement](https://coverage.readthedocs.io/en/7.16.2/branch.html) и [public API](https://coverage.readthedocs.io/en/7.16.2/api_coverage.html), `Cover` учитывает несколько видов execution opportunities; `branch_stats` возвращает total/taken exits. Источники проверены 2026-10-16. Public `clear_exclude("exclude")` и `clear_exclude("partial")` отключают настраиваемые исключения; встроенные структурные defaults не обнуляются.

## Negative cases и проверка измерителя

- Первоначальный RED: новый module checker отсутствовал, import test завершился ошибкой. После реализации exact 95% проходит, 94.99% отказывается; покрытый второй module не скрывает недопокрытый первый.
- Missing/non-branch/single-module measurement не принимается. Зарегистрированные оба файла без выполненных arcs дают ноль covered branches и fail, а не фиктивные 100%.
- Design review уточнил опасность очистки всех внутренних partial-pattern списков Coverage.py. Выбраны только документированные public методы; negative test проверяет нулевое выполнение на настоящей CoverageData. Это уточнение альтернативы, не выявленный обход опубликованного checker.
- CLI error не экспортирует путь или исходный текст исключения. Test entrypoint проверяет настоящий exit 2 через runpy. Ошибки тестовых fixtures при разработке исправлены: для смены line/branch режима нужен новый CoverageData, пустые arrays сами не регистрируют файл, применяется touch_files.
- Добавлены fault cases: invalid boot/policy/platform, oversized/growing/truncated read с закрытием FD, write без прогресса, недопустимый reclaim credit, invalid record/sequence без изменения bytes, cross-segment sequence gap и переполнение budget при reopen, изменённый manifest, oversized close manifest и изменённый lease до handoff.
- Controlled mutation, отключающая `_write_all`, вызывает assertion failures нового теста. Это проверка чувствительности теста к удалению защиты, не реальная production corruption.
- Implementation review нового checker выявил два пробела исходных tests: постоянный lookup первого модуля и подсчёт только первой branch point не обнаруживались. Добавлена настоящая Coverage collection двух temporary modules с десятью условиями каждый: 100/100, 95/95, 90/100 и 100/90. Проверяются оба знаменателя и оба числителя. In-memory mutations теперь дают соответственно 2 и 4 assertion failures. Production checker не требовал исправления. Windows temporary root нормализован через resolve для совпадения DOS short path с canonical measurement path. Внешняя модель не использовалась.
- Повторный scoped review нового multibranch test завершён без конкретных дефектов; reviewer отдельно выполнил этот test и его четыре подслучая. Это два bounded implementation cycles нового checker/test, не повторный полный review backend и не независимый человеческий security audit.

## Локальные результаты

Первый Windows checkpoint: **70 methods, 47 pass / 23 explicit POSIX skips**, 2.160 s. После review checker расширен с 9 до **10 tests pass**, 0.262 s; core+retention остаётся 61 methods. Checker coverage: **39 statements / 8 branches, 100%**, no misses. Audit-only Windows measurement: core **78/80 branches = 97.5%**, retention **46/102 = 45.098%**. Branch gate ожидаемо возвращает fail/exit 2: skips не считаются pass, Linux coverage не выводится из Windows результата.

Смежная regression из 13 модулей после review: **202 methods, 179 pass / 23 explicit POSIX skips**, 28.416 s. Ruff check/format проходят, 206 files already formatted. Docs checker: 387 files, 150 Markdown documents, 1088 local links с локальными пользовательскими instructions; проверка документации не заменяет runtime acceptance.

Production audit modules не изменены: increment добавляет проверки ранее существующих границ и обязательный измеритель. Native byte preservation, manifest/lease failures и Linux branch threshold принимаются только после фактического CI. Рабочие Docker/WSL/Kubernetes пользователя не запускались и не менялись; локальные тесты используют собственные временные файлы/потоки. Отдельные пользовательские AGENTS.md/GOAL.md остаются вне коммита increment.

## Remaining scope

Дождаться native CI и зафиксировать exact branch counts, source revision и terminal matrix. Даже pass обоих модулей не принимает полный M18: критерий распространяется и на другую security-critical логику и требует all-gates на одном release candidate. Затем продолжить versioned immutable release/qualification audit contexts и HTTP actual-send correlation по [плану T16](../../tasks/plan.md). Crash/reboot reconciliation, all-output canaries, image/ML failures и полная R1 acceptance остаются открытыми.
