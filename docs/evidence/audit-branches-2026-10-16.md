# Audit branch coverage: qualification, 2026-10-16

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». Increment после `5a4ab26`; [предыдущая native qualification](audit-retention-2026-10-16.md), [ADR 0037](../decisions/0037-audit-retention.md), [RB-56/PB-30](../operations/audit-retention-troubleshooting.md). Статус: **native component qualification pass на 42ce792**, core 76/80 branches = 95%, retention 102/102 = 100%. Цель R1, полный M13 и полный M18 не закрыты.

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

## Native Linux qualification: 42ce792

[Storage CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38933422730), job `117082827528`, exact code `42ce7928d3518dd656c4b314e6861bc922ba29cf`. Ubuntu 24.04 / Python 3.12.15 / Coverage.py 7.16.2: **61 audit tests pass без skips**, 3.432 s; **10 checker tests pass**, 0.142 s. Checker 39 statements / 8 branches, 100%. Native retained module: 266 statements / 102 branches без misses. Native core: 211 statements / 80 branches, Cover 97%, но branch coverage **76/80 = 95%**, не 97%. Порог достигнут включительно, не округлён вверх.

Выполненный branch gate сохранил независимые знаменатели и release_ready=false:

```json
{
  "minimum_branch_percent": 95,
  "modules": [
    {
      "branch_percent": 95,
      "covered_branches": 76,
      "module": "mlsecops/serving_audit.py",
      "status": "pass",
      "total_branches": 80
    },
    {
      "branch_percent": 100,
      "covered_branches": 102,
      "module": "mlsecops/audit_retention.py",
      "status": "pass",
      "total_branches": 102
    }
  ],
  "release_ready": false,
  "schema_version": 1,
  "scope": "audit-branch-coverage-component-not-full-M18",
  "status": "pass"
}
```

Таким образом, критерий >=95% branch coverage подтверждён **для этих двух модулей**, не для всей платформы. Tests включают реальные filesystem операции в собственных временных каталогах и controlled syscall faults; это не испытание физического power loss, злонамеренного host administrator или полного M13 HTTP audit.

## Actual-candidate regression

Существующий serving повторно прошёл **67 cases**, source_dirty=false, release_ready=false. [Полный sanitized report](audit-branches-42ce792.md), canonical SHA-256 `349fb26fd8b8a5e05e9703c95029fa3a285fdc9b837bc126c102274d6935ecc5`, campaign `7457b344227f4ce889849adc610aafb6`. Runtime image `sha256:d1c1f26657cf9de5845711204608951d499782f1139b3cb3cc3b18bc5d1e1528`, source fingerprint `9eac6f96db4e55438097b792903abee05ae8f3cc10369a8789129a1eef16de18`. Fingerprint application code совпадает с предыдущим increment: production audit modules не менялись; новый revision фиксирует tests и CI enforcement. Разные image IDs не объявляются bit-for-bit reproducibility.

Golden consistency error 0.0; stopped-worker denial 2.013410773 s. Quotas: 422/429/422/429, refill 200/200, admitted deltas [2,2,4]. Первый client-completed trust-outage HTTP 503 через **59.755809643 s**, 53 observations. Paused-query denial **10.001805677 s** при ещё ACTIVE query; short signed-policy denial **5.702488787 s** до lease/policy expiry, повторный post-expiry 503 и renewal/recovery version 3 подтверждены. Это наблюдения одного controlled run, не месячный SLO.

Из опубликованного JSON повторно проверены canonical hash, exact revision, уникальность 67 cases, outage assessment через штатный assess, ACTIVE внутри request interval, поколение fenced, pending query, pre/post-expiry и quota invariants. HTTP audit integration этим не доказывается; квалификационный permit не становится release approval.

## Terminal CI matrix: 42ce792

Все **10 workflows terminal: 6 success / 4 failure**. Matrix проверена после завершения последнего Kubernetes job, а не до него. Docs-only публикация не прерывает работающий CI и не объявляется новым runtime qualification.

| Workflow | Результат |
| --- | --- |
| [Storage](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38933422730) | success; branch gate pass, audit 61, checker 10, M03 431, M07 97, actual-candidate 67 cases pass |
| [Developer](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38933422699) | success; три fresh trainings, maximum probability difference 0.0, sklearn/ONNX parity error 2.086162567138672e-7 |
| [Tracking](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38933422752) | success; M06 18 cases pass |
| [Kubernetes](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38933422708) | success; job 117082827787, M20 723 / M21 122 cases pass, M21 finished 2026-10-16T16:53:43.755852 UTC |
| [Intake contracts](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38933422823) | success |
| [Documentation](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38933422773) | success; documentation integrity, не runtime acceptance |
| [Image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38933422732) | failure; Critical/High worker 0/56, storage 9/132, worker-candidate 0/55, storage-candidate 1/85; все четыре scans executed и SBOM validated, scanner exit 2 |
| [Poisoning](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38933422705) | failure; execution complete, primary evidence integrity pass, 35 verified cases / 251 files, 10 violations, 0 inconclusive scenarios; full M08 inconclusive |
| [Evasion](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38933422755) | failure; execution complete / primary reconciliation pass; recall drop 0.07183673469387755 > 0.05 |
| [Paired robustness](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38933422610) | failure; execution complete / primary reconciliation pass; candidate drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 > 0.05 |

Campaign IDs: poisoning `0204ad8ed2694a02a7c33eb4ac575e9c`, evasion `cd538ed5473842519c2f832505131d6a`, paired `f6a3acb758954cf485cffe99237601b6`. Значения сверены с текущими primary reports. Ни scanner policy, ни ML thresholds, ни failure exits не ослаблены; branch pass не отменяет эти запреты выпуска.

## Remaining scope

Pass обоих модулей не принимает полный M18: критерий распространяется и на другую security-critical логику и требует all-gates на одном release candidate. Следом продолжить versioned immutable release/qualification audit contexts и HTTP actual-send correlation по [плану T16](../../tasks/plan.md). Crash/reboot reconciliation, all-output canaries, image/ML failures и полная R1 acceptance остаются открытыми.
