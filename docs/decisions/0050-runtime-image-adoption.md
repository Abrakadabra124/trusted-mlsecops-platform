# ADR 0050: scoped принятие исправленных runtime images

Статус: native adoption частично проверен; новый storage pin ожидает consumer regression. Scope: CP2/R1-B02, продолжение ADR 0015/0016, не изменение критериев R1.

## Основание

В `0de97b6` Wolfi candidates прошли actual worker/storage qualification, package audit и повторную сборку с точным APK closure. Baseline по-прежнему содержит High/Critical. [Evidence и digests](../image-candidates.md#проверка-полностью-закреплённых-recipes). Один успешный эксперимент не меняет default runtime.

## Решение и последовательность

1. Подготовить отдельный PostgreSQL artifact в `ghcr.io/abrakadabra124/trusted-mlsecops-platform-postgres`. Только ручной workflow из `main`, pinned Actions, минимальные `contents:read`/`packages:write`, временный `GITHUB_TOKEN`, без PAT и передачи registry credentials в build.
2. Перед публикацией заново выполнить build обоих candidates, actual worker qualification, signed restore и package audit. Проверить совпадение source revision/fingerprint, recipe/image identities, freshness, policy, positive controls и отсутствие blocking findings у обоих candidates. Baseline failures не скрываются: публикация подготовительного storage artifact не является deployment или выпуском модели.
3. Публиковать именно проверенный local image ID под уникальным tag commit/run/attempt. Разрешён только фиксированный repository. Прочитать registry manifest, проверить его config digest и повторно загрузить по manifest digest; readback должен сохранить identity. Config ID не подставлять вместо registry manifest digest.
4. Подтвердить публичное anonymous чтение. GHCR package visibility не наследуется автоматически от публичного Git repository; private artifact не допускается в clean-checkout baseline. Только после проверки записать настоящий immutable digest в storage policy.
5. Заменить root worker Dockerfile закреплённым многостадийным Wolfi recipe. Обычная сборка worker остаётся source-bound, без обязательной публикации отдельного application image.
6. Обновить явно ожидаемый distro profile audit, сохранить проверку Wolfi feed и политику severity. Старый baseline не выдавать за исправленный: его исторические findings остаются evidence, новый runtime проходит новый audit.
7. На disposable hosted CI проверить изменённые developer/storage/Kubernetes/tracking/image paths. Не объявлять CP2/R1 завершённым: полный controller inventory, model robustness/assurance и M18 остаются обязательными.

## Ограничения и rollback

Adoption относится только к новым UUID states лаборатории. Локальные Docker/WSL/Kubernetes/SQL services, существующая SQL-история и enterprise-devsecops-platform не меняются. Старый state нельзя открыть с новым image/config policy: сохранить fail-closed rejection, не переписывать marker и не подключать новый server к старому volume.

Для существующего состояния оператор сохраняет прежний checkout, immutable image и исходный volume. Перенос рабочей истории потребует отдельной подтверждённой процедуры signed backup -> новый target -> golden readback -> switch, с сохранением источника. Native synthetic rehearsal доказывает механизм, не успешную миграцию неизвестной рабочей истории.

Rollback новых пустых lab states: вернуть предыдущий code/immutable reference и создать отдельный state; не монтировать использованный новым server volume в старый image. Возвращение к старому уязвимому baseline не разрешает выпуск. Частично опубликованный artifact при сетевом отказе не удалять автоматически: сохранить tag/digest и статус inconclusive, проверить его identity перед дальнейшими действиями.

## Проверенная публикация

Clean hosted commit `bbc20b4662d6dc59ae6a20ae143e2149d7381efb`, [run 39479186325](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39479186325), attempt 1, job `118822983866`, success. Actual worker **74**, storage **435** checks pass, 1 000 golden rows/max error **0.0**. SQL restore 3.441858 s, restore-to-golden 4.990953 s; это не полный M17 RTO. Оба positive controls pass. Candidate worker: 0 Critical/High/Unknown, 6 Medium/1 Negligible; candidate storage: все severity counts 0. Baseline worker 56 High, storage 9 Critical/132 High сохранены, полный comparison fail.

- Immutable manifest: `ghcr.io/abrakadabra124/trusted-mlsecops-platform-postgres@sha256:dbd9ead6848515c5fcf7d709815853b510493f609f2715296c28d8d6d965f941`.
- Проверенный config/image ID: `sha256:f407b8a36c6836f7b527fe0b2bed7787fd3063aba73ecdadff62490ed6957673`; storage recipe SHA-256 `21acc908a1590e2122918ade69b379a2a96dfa5e427b909e90322da9f7aea6f0`.
- Source fingerprint: `0d11e3844edf96c2f8c660dfef496a3a58d4651ade4b503238163005a11dcc7d`.
- Canonical evidence SHA-256: audit `ce3be3f962ab4f3b602a9ced41c4e6b30284c90fa6aef6a3ffde53ebaee02ce6`, worker `9c5fbddfb33d7616408571ae1846d6d14f308912c9e8800aa1e41fe95ef645f0`, storage `52be16863735bb136d6bbbb6a90c0c879e7db8b60061eb503822f0d0e14a482f`.
- DB SHA-256: `5bee2b8f39940a9eb07ae25eae384ae8b33fd334c9970f9f896f5941603ddbfc`.

Publisher выполнил authenticated pull/readback и сохранил `public_access_verified=false`: это корректная граница его доказательств. Отдельная проверка `2026-10-20T19:05:31Z`: [package page](https://github.com/Abrakadabra124/trusted-mlsecops-platform/pkgs/container/trusted-mlsecops-platform-postgres) уже отображала Public; настройки доступа в этой проверке не менялись. Без GitHub credentials получены anonymous registry token, manifest и config; hashes совпали с manifest reference и проверенным image ID. Config: Linux/amd64, USER `999:999`, правильный OCI source label, 12 layers. Это проверка metadata/anonymous доступа, не отдельный полный anonymous Docker pull; его проверит bootstrap свежего hosted job без registry login.

Код adoption меняет root Dockerfile и общий storage reference, но не рабочие resources. Audit требует Wolfi inventory и known-vulnerable APK control также без `--compare-candidates`. Tracking отказывает startup state с прежним PostgreSQL pin, сохраняя read-only validation для безопасного stop. Native developer/storage/Kubernetes/tracking/image regression должна подтвердить эти изменения отдельно от публикации.

## Почему так

### Artifact с явными зависимостями egress probe

`8e50f58e396d60ff121d821dafc9d962fdc23290`, [run 40000844038](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40000844038), attempt 1, job `120576193609`: success. Build проверил 60 APK и настоящий GNU timeout/deadline exit 124. Actual worker 74 / storage 435 checks, signed restore 1 000 rows/error 0.0; SQL 3.312396 s, restore-to-golden 4.875550 s, не полный M17 RTO. Все четыре scans pass, 0 Critical/High/Unknown; worker 6 Medium/1 Negligible, оба storage без findings. Оба controls pass, severity policy не менялась.

- Новый manifest: `ghcr.io/abrakadabra124/trusted-mlsecops-platform-postgres@sha256:9172aa68aa0790240cd4597707d8d8fda875dcd944e0155277e2347142585b7b`.
- Config/image ID: `sha256:87758f47c070ff81b0acd3d55f2c85056a0e7425250e93c65438e32535fc053e`; recipe SHA-256 `d2bfade99aa7fedca18b9512ecca33fdf5119e9bb2128af8402762eed7af636c`.
- Source fingerprint: `0c926c0fd304953e7bc81d0b9079a3c6e3629236eaee326c6af7d5656c8943ba`.
- Canonical evidence SHA-256: audit `95109f3afeba3beef29ea5c16f0279a62836bc42f01366cebce885a9bf7378d3`, worker `2ec1e88440b5e2bb7fbf4f8f58f76124d19a2d1260607b14a0a74fe10a5a5208`, storage `f26d5e17e00173ec4a082458d57852f9c7b912d6c550b3c6bbeff32dd8640d9e`.
- DB SHA-256: `ebeb1361ad5ecec6cfee77b8c6b3287046a984dee448e91435c2b0ea04ca6d33`.

Anonymous readback `2026-10-23T18:14:40Z` отдельно подтвердил hashes manifest/config, Linux/amd64, USER 999:999 и OCI source label без GitHub credentials. Новый digest подключён к shared storage policy; рабочие volumes не изменены. Повторяется Kubernetes regression и затронутые storage/tracking пути, поскольку GNU coreutils меняет также используемые bootstrap utilities. Не запускается полная дорогая матрица. Publication, package audit и unit checks не заменяют результат этих native consumers.

Результаты consumers 2026-10-23: [Kubernetes 40002302850](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40002302850), `883c262`, **success**; signed migration 497 checks, egress positive control и GNU timeout 124 после 3.111868 s. Private SQL 436 checks с отдельным negative probe 3.110641 s; M01/M04/M05/M20/M21 pass. После Python dependency/source-lock correction `fa053bc` developer/tracking success; storage M03/M07/restore pass, но последующий output observer failure сохранён. [Точные scopes и ссылки](../../STATUS.md#cp2-устранение-image-blockers-в-работе). Новый pinned PostgreSQL действительно использован consumers; это не подтверждение полного controller/system image audit или всей CP2 acceptance.

Уточнение 2026-10-23 по native `91aa1b7`/`f9054fc`: четыре adoption workflows проходят, Kubernetes выявил неявные зависимости существующего PostgreSQL egress probe на Bash/GNU timeout. Новый candidate явно фиксирует эти два инструмента и их две дополнительные библиотеки, 60 APK вместо исторических 56. Non-root UID/capabilities/NetworkPolicy не меняются; положительный и отрицательный TCP controls выполняются внутри настоящего PostgreSQL container. Увеличение package surface допустимо только после нового полного audit и публикации; это исправление обязательного executable gate, не универсальный debug image. [Диагностика и порядок принятия](../operations/image-audit-troubleshooting.md#отсутствующая-зависимость-egress-probe).

Сборка PostgreSQL при каждом bootstrap вместо immutable registry reference добавила бы build toolchain и resolver в операционный путь. GHCR позволяет сохранить существующий pull-by-digest контракт. Worker уже собирается из source-bound кода; второй registry lifecycle для него сейчас не нужен.

Публикация не доказывает издателя, подпись модели, независимый review или отсутствие всех CVEs. GitHub runner/admin и pinned Actions остаются доверенными. Не добавляются scanner exceptions, paid services или автоматический promotion.

## Источники

- [GHCR: repository linking, GITHUB_TOKEN и anonymous pull](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).
- [Раздельные permissions и visibility](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).
- [GitHub Packages billing](https://docs.github.com/en/billing/concepts/product-billing/github-packages): на дату проверки 2026-10-20 container registry storage/bandwidth бесплатны; это не разрешение включать платные продукты или менять billing settings.
