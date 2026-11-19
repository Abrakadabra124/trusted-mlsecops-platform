# B02: etcd x/net candidate, 2026-11-20

## Один исправляемый finding

Основание: [actual runtime audit 43625404562 / job 132539994035](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43625404562/job/132539994035),
source `f3b31b453065c9669aee7689e6ef8fc0e6d9b10c`, canonical report SHA-256
`a72ca814ddd70058455975c7c5435c14d017c5434a75bf201f14aab0eea15a2d`.
Это исторический report: `fail`, application coverage `6/14`.

| Поле | Значение |
|---|---|
| Component | `runtime-008`, etcd `3.6.16-0` |
| Observed reference | `registry.k8s.io/etcd@sha256:00edecc7baeaf69c61708ed713d55a8c928d539f200298d8d67cbfed59db9c7e` |
| Config digest | `sha256:a17708350060c02414f0ecd9a0afd44404df2e4ed8cc9726a3a9c5776b40645e` |
| Package | `golang.org/x/net v0.61.0` |
| Finding | `GO-2026-6860`, severity `High` в actual Grype report |
| Alias | `CVE-2026-78661` |
| Fixed version | `v0.62.0` |
| Affected image binaries | `/usr/local/bin/etcd`, `etcdctl`, `etcdutl` |

[Первичный Go advisory](https://pkg.go.dev/vuln/GO-2026-6860) описывает
квадратичные затраты при объединении текстовых узлов HTML parser и указывает
исправление в `v0.62.0`.
[Официальный JSON](https://vuln.go.dev/ID/GO-2026-6860.json) при проверке имел
SHA-256 `443304c129b9540dc46d28392b973a136db90644019dc20c3e25941833d49df3`.
Наличие module finding не является доказательством достижимости уязвимой
функции в etcd; исключения или waiver на этом основании не вводятся.

## Подготовленный candidate

[Официальный etcd v3.6.17](https://github.com/etcd-io/etcd/releases/tag/v3.6.17)
опубликован 2026-11-18. В registry обнаружен следующий patch tag
`3.6.17-0`. Зафиксирован linux/amd64 manifest, не mutable tag:

```text
registry.k8s.io/etcd@sha256:3ced7fbdc4cadcec31ab34a7513bc97be2b70db923e7154e2d88a980016b5e8b
config sha256:be2dd319600bac16f542b8e46e1b78511c35a31e46829ee9acc82a83c94aa377
```

Независимо проверены manifest/config SHA-256, 18 compressed layer digests,
размеры и uncompressed diff IDs. Загрузка ограничена известными descriptors:
24 485 593 compressed bytes суммарно. Извлечение сделано в памяти Python;
контейнеры и бинарники локально не запускались.

Buildinfo всех трёх бинарников содержит `golang.org/x/net v0.62.0` и
`go1.26.11`. Версия пакета получена из бинарников, не вычислена по image tag.
Их SHA-256 и buildinfo SHA-256 закреплены в
[image_etcd_candidate.py](../../scripts/image_etcd_candidate.py).

Это доказательство package contents. Native vulnerability scan и
совместимость candidate ещё не проверены. Baseline не переключён.

## Как запускается дополнительный scan

Изменение основано на `bf4ba7e8f0217d7901c7d72f0e641cd3acd48081`.
[image_audit.py](../../scripts/image_audit.py) добавляет
`etcd-xnet-candidate` только когда исходный etcd config присутствует
в реально собранном runtime inventory.

- Существующие три baseline targets и все runtime targets сохраняются.
- Candidate добавляется отдельно, с обязательной проверкой config digest.
- Для исходного inventory из 14 images ожидается 18 scan components:
  3 baseline + 14 runtime + 1 candidate. Candidate не входит в denominator 14.
- Raw SBOM/package observations и все scanner findings проходят существующий
  audit pipeline. Ничего не исключается по advisory ID или severity.
- Candidate остаётся `unapproved-system`; его scan не даёт application coverage.
  Даже нулевые findings не означают compatibility или release acceptance.
- `infra/kind.yaml`, application recipes и workflows не изменены.

Parent может вручную запустить существующий
[runtime-image-audit.yml](../../.github/workflows/runtime-image-audit.yml)
на `fix/r1-b02-etcd-xnet`. В этой задаче dispatch не выполнялся.

## Проверка native результата для parent

1. Сверить exact source SHA, clean checkout, policy, scanner/DB hashes,
   четыре detection controls и cleanup.
2. Подтвердить сохранение всех 14 observed targets и дополнительный
   `etcd-xnet-candidate` с закреплёнными manifest/config.
3. Проверить `scan_executed=true` и три x/net observations `v0.62.0`
   на путях `etcd`, `etcdctl`, `etcdutl`.
4. Проверить, что candidate scan больше не содержит `GO-2026-6860`
   или его alias `CVE-2026-78661`, сохранив все остальные candidate findings.
   Исходные baseline findings остаются в собственном компоненте.
   Разницу между историческим и свежим report объяснять также DB revision,
   не удалять findings ради совпадения чисел.
5. Общий report может и должен остаться `fail` при других C/H/U блокерах.
   Candidate не разрешает baseline promotion. Для замены deployed etcd нужна
   отдельная реальная compatibility-проверка disposable control plane.

Ни B02, ни M18/R1 этим candidate не закрываются.

## Локальная проверка и сохранённые материалы

Новый flow regression сначала упал без реализации на отсутствии дополнительного
scan при сохранении 14 targets. После реализации image suite содержит
211 checks, включая шесть новых controlled scenarios: clean candidate,
High, Unknown, foreign config, unavailable image и empty SBOM.
Они проверяют реальный audit flow с подменой только внешних Docker/scanner
boundaries. Это не native test и не свидетельство отсутствия CVE.

Дополнительно прошли 36 unit methods для package observations, Go controls,
diagnostics и runtime scope. Audit + candidate pins: 327/339 statements,
133/140 branches; новые executable строки audit покрыты flow cases.
Ruff, проверка документации и сверка pins с primary report/extracted buildinfo
прошли. Полный application/runtime acceptance этим не измерялся.

Локальные первичные материалы находятся в own worktree,
`.runtime/etcd-xnet-evidence/`: advisory/registry receipts, manifest/config,
`candidate-extraction.json`, три buildinfo records и результаты тестов.
Raw runner logs, секреты и полный private evidence в commit не включены.
