# PB-16 / RB-34: неполное или несвязанное intake evidence

Владелец: MLSecOps lab operator. Область: [M21 runner](../intake-gate.md). Требуются Linux, pinned uv/Python из lockfile, Linux Docker, доступный loopback 15453 и subnet pool. Без этих условий результат не считается pass. Рабочие SQL volumes и holdout budget изменять запрещено.

## RB-34: зелёные компоненты, но M21 inconclusive

**Установленный пробел:** source review показал отсутствие общего M21 runner, который заново запускает и связывает controlled/native/SQL reports. Раздельные успешные тесты не доказывали их принадлежность одному candidate, image и запуску. Это integration gap, не зарегистрированный production-инцидент. Новый runner проверяет эти связи, но сохраняет явный missing scoped-controller case вместо фиктивного pass.

**Симптом:** acceptance exit 2; `M21.json.status=inconclusive`. Если `intake-gate.json.component_status=pass`, искать `scoped-controller-native-intake-matrix` со status inconclusive. В этом случае 85 выполненных component cases не закрывают оставшуюся проверку. Если полного component report нет, мог не завершиться bootstrap/runtime; это другой исход и не 85 pass.

**Read-only диагностика:** из корня repository прочитать выбранный owned state, не выполнять новую evaluation для просмотра результата:

```bash
uv run --locked python -c "from pathlib import Path; from mlsecops.contracts import read_json; report=read_json(Path('.runtime/evidence/M21.json')); print(report['status'], report['exit_code']); print([(case['id'],case['status']) for case in report['cases'] if case['status']!='pass']); print(report['residual_risks'])"
git rev-parse HEAD
git status --short
docker ps --format '{{.Names}} {{.Status}}'
```

Сопоставить source revision/fingerprint, policy, image, campaign time, candidate и evaluation references с текущим запросом. Скрипт просмотра не восстанавливает доверие к отредактированному JSON: принятие требует нового runner со сверкой первичных подписанных SQL objects. Не публиковать raw SQL state, ключи или полные внутренние логи.

**Разбор причин:**

- Missing scoped-controller matrix: реализовать и выполнить эту проверку, затем интегрировать reconciliation. Rerun того же runner не исправит отсутствующую возможность. Не удалять case, не менять required status и не использовать M20 success как замену.
- `M21_evidence_not_fresh`, `M21_native_binding`, `M21_sql_material_binding`: проверить времена, subject и source/image. Не редактировать timestamps/digests ради pass; rebuild и fresh campaign после устранения установленной причины.
- `M21_case_set_*`, `M21_case_count_invalid`, `M21_denial_*`: сохранить evidence, сверить точные IDs, readers и три разные reservations. Не суммировать файлы разных campaigns.
- `M21_linux_required`: выполнять в Linux/CI; не отключать symlink case и не давать Codex административные права ради теста.
- Runtime/port/network unavailable: [RB-28](qualification-environment-troubleshooting.md). Не делать global prune или изменение daemon pools. Свободный порт не доказывает наличие subnet capacity.
- `M21_cleanup_identity_changed`: не останавливать resource с чужой identity. Сохранить отчёт, marker и обратиться к владельцу. Автоматическое восстановление ownership не предусмотрено.

## PB-16: свежая campaign

**Изменяющий плейбук.** Создаёт новый private state и отдельную SQL campaign; тратит четыре slots только в её новом ledger (clean evaluation + три denials). Сохраняет volumes и evidence, не удаляет предыдущие данные. Недоступность bootstrap может оставить partial resources; cleanup таких ресурсов требует отдельной сверки ownership.

```bash
state=".runtime/intake-recheck-$(date -u +%Y%m%dT%H%M%SZ)"
test ! -e "$state" || exit 1
uv run --locked python -m mlsecops bootstrap --state "$state" || exit 1
uv run --locked python -m mlsecops build || exit 1
uv run --locked python -m mlsecops.acceptance --gate M21 --state "$state" --output "$state/evidence/M21.json"
result=$?
printf 'M21 exit code: %s\n' "$result"
```

На текущем этапе ожидается exit 2 **только если** component report подтверждает 85 completed cases и один точно указанный missing case. Runtime failure тоже может дать 2, поэтому одного exit code недостаточно. Exit 1 требует расследования, exit 0 текущая версия не выдаёт. CI не подавляет exit 2: workflow остаётся failure, public gate inconclusive.

**Критерий завершения диагностики:** удалось классифицировать причину, сохранить evidence с верным scope, чужие ресурсы не изменены, новая promotion заблокирована. Это не критерий завершения M21. **Rollback:** остановить новые campaigns, использовать совместимую reviewed версию для чтения исторических материалов, не переписывать signatures и не сбрасывать budget. **Эскалация:** неизвестные identities, loss of evidence или повторный native mismatch передать владельцу; не заменять неизвестную причину гипотезой об успешном восстановлении.

Controlled tests проверяют stale/foreign/partial evidence, некорректную форму, cleanup guard и отсутствие pass при missing coverage. Native/CI outcomes фиксируются в STATUS после фактического исполнения, а не по наличию этого текста.

## Проверенный запуск

2026-10-13 [CI 38442903172](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38442903172), commit `12143a6d0cebc35832b7f50c0f18be5dc2a8ea8a`: native campaign завершена в `17:59:00.802340Z`, source_dirty=false. Подтверждены 54 controlled methods, 5 Docker cases, 25 SQL cases и сверка первичных signed materials. Итого **85 pass + 1 inconclusive**, именно missing scoped-controller case. Gate exit 2 сохранил workflow failure; это ожидаемое сохранение неполного покрытия, не свидетельство полного M21 pass. Отдельно runner contracts дали 15 methods/100% statements и branches. Digests в STATUS.

Локально выполнены Linux controlled suite и Docker faults, но полный SQL replay на Windows не запускался. CI проверил те же bootstrap/build/acceptance entry points на fresh Linux runner; это не native исполнение shell-примера на машине пользователя и не DB crash recovery drill.
