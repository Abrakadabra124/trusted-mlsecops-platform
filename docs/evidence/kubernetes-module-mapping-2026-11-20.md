# Kubernetes workspace modules: проверенное соответствие исходников

20 ноября 2026 года. Это проверка соответствия содержимого для будущего
консервативного module-level поиска CVE, а не принятый image scan или M18.
Покрытие runtime остаётся **6/14**. Исходные `UNKNOWN`, `(devel)`, pseudo-version
и findings Critical/High/Unknown не изменены.

## Основание доверия и метод

Проверка опирается на [аутентифицированные image signatures и source/release
SBOM](image-kubernetes-provenance-2026-11-20.md#проверка-доверенного-издателя).
Зафиксированный upstream revision:
`kubernetes/kubernetes@bb826b1d48562f110659e64e8ec444327433db95`.

Для каждого из 27 наблюдаемых workspace modules получены официальные Git refs
его отдельного upstream repository. Фактический tag `v0.36.4`, его tag object
и peeled commit сохранены отдельно. Версия не вычислялась из Kubernetes image
tag. Доверие к этим aliases основано на официальном HTTPS endpoint; подписанный
Git tag или attestation publishing bot этим результатом не заявляются.

Архивы immutable commits прочитаны без извлечения и исполнения их файлов.
Сверены file sets, SHA256, Git blob IDs, modes, Go/generated files, embed assets,
изменения `go.mod`/`go.sum`, локальные workspace dependencies и внешние версии.
Исходные SHA256 проверены по authenticated source SPDX. Исходные buildinfo
остались привязаны к прежним binary/image digests.

Родительский повтор выполнил `compare_all.py` и `finalize_matrix.py` в отдельной
приватной копии. Полученные факты полностью совпали с исходной матрицей, кроме
времени расчёта и локальных путей. Дополнительный `parent_verify.py` независимо
пересчитал Git tree object hashes из names, modes и child object IDs для source
tree и всех 29 published trees. SHA поля ответа API по commit не трактовался
как tree ID: вычисленный tree hash сверялся с tree в commit receipt.

## Результаты и знаменатели

| Проверка | Наблюдаемые модули | С двумя вспомогательными targets |
|---|---:|---:|
| Модули | 27 | 29 |
| Raw `(devel)` instances в 11 binary instances / 4 images | 96 | 96 |
| Исходные файлы | 13 871 | Не используется как знаменатель runtime |
| Go-файлы, совпавшие по SHA256 | 6 242 | Не используется как знаменатель runtime |
| Из них generated Go files | 2 512 | Не используется как знаменатель runtime |
| Локальные dependency edges | 128 | 134 |
| Уникальные внешние declared modules | 144 | 145 |
| Проверенные vendor version bindings | 1 280 | 1 368 |

Все 37 уникальных embed assets совпали побайтно. Для 27/27 наблюдаемых модулей
побайтово воспроизведён publishing transform `go.mod`; полный diff `go.sum`
сохранён. Нет неразрешённых local targets, vendor или buildinfo version
mismatches. `cli-runtime` и `code-generator` нужны для замыкания локальных
dependencies, но не добавлены в число обнаруженных modules/instances.

У 24 модулей file sets и содержимое совпали за исключением записанных изменений
`go.mod`/`go.sum`. У трёх есть семь конкретных path deltas:

| Module | Только в source | Только в published repository |
|---|---|---|
| `client-go` | `dynamic/testdata/TestGoldenRequest/.gitattributes`, `dynamic/testdata/TestGoldenResponse/.gitattributes`, `pkg/version/.gitattributes` | `CHANGELOG.md` |
| `component-base` | `version/.gitattributes` | Нет |
| `kube-aggregator` | Нет | `hack/godep-deps.sh`, `hack/sync-from-kubernetes.sh` |

Для каждой delta сохранены exact module, source revision, published commit,
direction, path, SHA256 и mode. `base.go`, на который действуют export-subst
attributes, также совпал побайтно. Scripts из `hack` не исполнялись.
Scoped review допускает только эти фиксированные различия для консервативного
сканирования целых модулей. Общего исключения для `.gitattributes`, `hack/*`
или всех non-Go files нет.

## Main modules и следующий исполняемый шаг

Четыре основных binaries уже содержат `k8s.io/kubernetes@v1.36.4` в raw и Syft
observations. Официальный Go proxy связывает этот coordinate с исходным
revision; `go.mod` совпадает с authenticated source. Семь runner binaries имеют
raw `k8s.io/component-base (devel)` и Syft pseudo-version
`v0.0.0-20260820030627-bb826b1d4856`. Их связь с published module подтверждается
отдельной строкой `component-base` в полной матрице.

Таким образом, прежние 96 unresolved instances состоят из 89 dependency entries
с Syft `UNKNOWN` и семи main pseudo-version entries. Для дополнительного scan
нужны **28 уникальных PURL**: 27 workspace modules плюс уже известный Kubernetes
root coordinate. PURL, Package URL, однозначно задаёт ecosystem, module и version
для scanner input. Это дополнительные inputs, а не переписанный SBOM.

[План проверки интерфейса scanner](../superpowers/plans/2026-11-20-go-purl-observation.md)
фиксирует отдельные JSON, CycloneDX и trace observations. Один `matches=[]`
не подтверждает, что package действительно был обработан. Для будущего coverage
нужны реальные дополнительные scans, неизменная свежая DB, полный исходный
inventory, exact image bindings и объединение со всеми исходными findings.

Compiler/package reachability equivalence не доказана и не используется для
исключения уязвимостей. Whole-module scan намеренно проверяет более широкий набор
возможных CVE. Это не отменяет остальные image targets, severity policy,
независимые M22 challenges и полную same-candidate приёмку R1.

## Приватное воспроизведение

Полный source proof хранится вне tracked files: в provenance worktree,
`.runtime/workspace-matrix-20261120/` и sibling
`.runtime/workspace-matrix-parent-20261120/`. Нужны сохранённые upstream receipts,
archives, authenticated source SPDX и первоначальные binary observations.
Один публичный checkout без этих локальных inputs не воспроизводит эту проверку.
Рецепт parent повторяет первичные сравнения, а не только читает готовые boolean
поля матрицы. Модели, candidate pins и raw logs этим документом не публикуются.

```text
python .runtime/workspace-matrix-parent-20261120/compare_all.py
python .runtime/workspace-matrix-parent-20261120/finalize_matrix.py
python .runtime/workspace-matrix-parent-20261120/parent_verify.py
```

Команды изменяют только производные отчёты в отдельной приватной копии.
Они не запускают Docker, WSL, Kubernetes, SQL или upstream source code.
