# ADR 0050: scoped принятие исправленных runtime images

Статус: реализация, native adoption ещё не проверен. Scope: CP2/R1-B02, продолжение ADR 0015/0016, не изменение критериев R1.

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

## Почему так

Сборка PostgreSQL при каждом bootstrap вместо immutable registry reference добавила бы build toolchain и resolver в операционный путь. GHCR позволяет сохранить существующий pull-by-digest контракт. Worker уже собирается из source-bound кода; второй registry lifecycle для него сейчас не нужен.

Публикация не доказывает издателя, подпись модели, независимый review или отсутствие всех CVEs. GitHub runner/admin и pinned Actions остаются доверенными. Не добавляются scanner exceptions, paid services или автоматический promotion.

## Источники

- [GHCR: repository linking, GITHUB_TOKEN и anonymous pull](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).
- [Раздельные permissions и visibility](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).
- [GitHub Packages billing](https://docs.github.com/en/billing/concepts/product-billing/github-packages): на дату проверки 2026-10-20 container registry storage/bandwidth бесплатны; это не разрешение включать платные продукты или менять billing settings.
