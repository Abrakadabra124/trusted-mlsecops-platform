# Пакет независимого reviewer: M22

Назначение: подготовить и проверить минимум два независимых challenge-кейса для Release Risk Advisor, по одному для label-flip и backdoor. Один человек может подготовить оба кейса, если он не разрабатывал и не настраивал проверяемую защиту. Имя, отдельная учётная запись или новый ключ сами по себе не доказывают независимость.

**Текущее состояние:** пакет готов к передаче, reviewer ещё не идентифицирован, спецификации не получены, независимые кейсы 0/2. Полный M22 остаётся inconclusive, выпуск запрещён. Это не запрос подтвердить готовность R1: в проекте остаются другие незакрытые gates и intermittent startup failure.

## Что передать и что вернуть

Передать этот каталог вместе с source snapshot по [reference manifest](reference-manifest.md). Полный ZIP содержит публичные отслеживаемые файлы frozen commit и этот пакет; он не содержит `.runtime`, credentials, signing keys, private models или raw job logs. Для браузерного review достаточно ссылок на зафиксированный commit в manifest.

Reviewer возвращает владельцу проекта три заполненных Markdown-файла:

1. Копию [challenge-spec-template.md](challenge-spec-template.md) для нового label-flip кейса.
2. Вторую копию для нового backdoor кейса.
3. [review-results-template.md](review-results-template.md): сначала разделы о независимости и предварительной проверке, затем результаты после исполнения.

Не нужно присылать пароль, токен или доступ к GitHub. Контактные данные можно передать владельцу приватно; публичному evidence достаточно согласованного идентификатора reviewer. Матвей сам передаёт пакет и получает ответ. Автоматическая отправка сообщений reviewer не выполняется.

## Короткая техническая вводная

Release Risk Advisor оценивает риск неуспешного релиза на синтетических табличных данных. Это учебный CPU-reference стенд, не подтверждённая бизнес-модель и не средство автоматического разрешения релизов. Текущая защита обучения использует bounded-loss refit с balanced weights; её score не объявляется откалиброванной вероятностью.

Label-flip - манипуляция метками части train. Backdoor - изменение части train и создание триггера, вызывающего выбранное поведение на заданной области входов. Нужно независимо придумать новые стратегии в разрешённых границах, а не переименовать известную случайную замену positive labels или `change_entropy=1.0`.

Начать чтение в таком порядке:

1. [Reference manifest](reference-manifest.md): source, image, candidate и ограничения старых доказательств.
2. [Критерий M22](../acceptance.md#m22), [threat model](../threat-model.md#дополнение-r02-absolute-и-adaptive-challenges).
3. [Model card](../model-card.md), [протокол защиты и компромиссы](../noise-training-validation.md).
4. [Frozen absolute matrix](../absolute-poisoning.md), [все 42 прошлых исхода](../evidence/m22-absolute-2026-10-29.md).
5. Реализация, перечисленная и захешированная в manifest. Известные regression probes открыты для понимания границ, но не считаются независимым challenge.

## Правила до запуска

- Только synthetic lab и train-only изменения. Не менять validation/final holdout, signing keys, verifier, policy, runtime image или критерии ради удачного исхода. Не атаковать внешние сервисы.
- Зафиксировать возможности атакующего, его знания, выбранные строки/признаки/метки, стратегию, seed, бюджет изменённых строк, число запросов к feedback и лимит времени. Любое поле без согласованного значения означает, что выполнение ещё не разрешено.
- Базовая матрица использует train 2 000/14 000 строк, budgets 1/5/25 и seeds 17/29/43. Reviewer задаёт новый метод в пределах согласованных capabilities. Иной бюджет/эффект оформляется отдельным предварительным решением, не задним числом.
- Финальные labels и доступ к final holdout не выдаются. Для адаптивной стратегии заранее определить, какой feedback и сколько запросов разрешены; неограниченный tuning по известным probes недопустим.
- Для сопоставимых probes сохранить AP drop <=0.03, upper paired ASR increase <=0.10, eligible >=500 и исходный interval method. Для иного воздействия согласовать metric/severity до исполнения. Недостаточная выборка не даёт pass.
- Сохранить спецификацию с UTC timestamp и SHA-256 **до** раскрытия challenge разработчику/реализации/исполнения. Reviewer удерживает свой оригинал и подтверждает, что frozen defence не менялась после reveal. Git commit и digest фиксируют байты, но не доказывают личность или независимость.

## Как проходит работа

1. Reviewer изучает frozen snapshot и самостоятельно заполняет две спецификации. Автор платформы не подсказывает ему конкретные стратегии, которые затем назовёт независимыми.
2. Владелец и reviewer согласуют capabilities, budgets, metrics, severity, доступ к feedback и полномочия. Фиксируются hashes двух спецификаций. Если source/defence меняется, прежний freeze не переносится молча.
3. Инженер реализует только зафиксированные сценарии в изолированном harness. Reviewer сверяет реализацию со своими спецификациями до исполнения. Полученный от reviewer код сначала изучается как недоверенный ввод и не запускается автоматически.
4. Оператор создаёт fresh candidate на закреплённом source/image и сохраняет private primary evidence. Старые 300 primary files M22 удалились вместе с disposable runner, поэтому их наличие в ZIP не обещается. Reference hashes не подменяют новый execution manifest.
5. Выполняются оба challenge и matched clean controls, сохраняются все попытки, отказы, bypass и false alarms. Все обязательные campaign и итоговые gates затем должны быть привязаны к одному release candidate для M18.
6. Reviewer независимо проверяет исходы, соответствие метрик и реализации. Подтверждённый обход integrity/authorization boundary блокирует release; неразобранный результат, нехватка данных или отсутствие reviewer decision дают inconclusive.

Интеграция новых challenge в исполняемый M22 пока не реализована. Нельзя закрыть gate только заполненным Markdown или ручной заменой status в JSON. Автоматический admission должен отдельно проверять freeze, exact methods, budgets, complete outcomes и reviewer attestation; фактическое независимое авторство подтверждает человек.

## Воспроизведение без запуска инфраструктуры

Для чтения точной версии в отдельной новой папке:

```powershell
git clone https://github.com/Abrakadabra124/trusted-mlsecops-platform.git trusted-mlsecops-m22-review
Set-Location trusted-mlsecops-m22-review
git checkout --detach 5fd9d309cc314192c2e06990b7d25b9e34a675de
git rev-parse HEAD
git status --porcelain
```

Ожидаются указанный commit и пустой status. Пакет reviewer добавлен позднее и читается отдельно; эти добавленные документы не относятся к runtime fingerprint. Для ZIP: `git rev-parse` неприменим, так как `git archive` не включает `.git`; сверять hashes по manifest и проверенному commit.

Хеш заполненной спецификации в PowerShell: `(Get-FileHash -Algorithm SHA256 -LiteralPath '.\challenge-label-flip.md').Hash.ToLowerInvariant()`. Не редактировать файл после фиксации без новой версии и нового предварительного согласования. Полные infra-прогоны выполняет оператор только в разрешённом disposable GitHub-hosted CI. Текущую Windows, Docker, WSL или Kubernetes для review запускать/перенастраивать не требуется.
