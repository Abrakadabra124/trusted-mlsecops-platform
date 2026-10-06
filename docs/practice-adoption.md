# Применение практик: источник -> решение -> проверка

R0.2, 2026-10-06. **Применено к проекту решения и документационному CI. Runtime-контроли остаются PLANNED.** Машиночитаемая версия: [research-decisions.json](research-decisions.json). Здесь не устанавливаются vendor products и не заявляется соответствие их frameworks.

| Решение | Источник | Изменение проекта | Gates / задачи | Ответственный |
| --- | --- | --- | --- | --- |
| D01 | S28, S30, S42 | Asset graph, owner/lifecycle, transitive revocation и сверка running digest | M19, M11 / T25, T14 | Platform owner |
| D02 | S32, S33 | Детерминированное разрешение действий вне ML output; score не authority | M04, M10, M12 / T05, T13, T15 | Security reviewer |
| D03 | S30, S32 | Разделить trusted evaluator controller и untrusted model worker; keys/labels не в worker | M20, M05, M07 / T26, T06, T10 | Platform + ML owner |
| D04 | S35, S36, S43 | Quarantine для imported/converted artifacts, coverage-aware scan, no automatic load | M21, M09 / T27, T12 | Security reviewer |
| D05 | S29, S31, S37 | Absolute poison budget, адаптивные challenge cases, корректное описание uncertainty | M22, M08 / T28, T11 | ML evaluator |
| D06 | S28, S40 | Privacy contract и data minimization; DP отдельно от de-identification | M13 / T16 | Data owner |
| D07 | S32, S39, S42 | Typed security events, replay/health checks, отказ не скрывается пустым dashboard | M23, M15 / T29, T18 | Platform/SRE owner |
| D08 | S26, S34, S38, S41, S44 | Risk-based maturity, conditional GenAI profile, maintenance/support checks | M01, M18 / T01, T02, T22 | Project owner |

Владельцы - роли будущего процесса, не назначенные внешние сотрудники. Для solo lab один человек может исполнять роли раздельными identities; независимость людей не симулируется.

## D01
Реестр должен отвечать на вопрос «какие выпущенные модели и endpoints зависят от этого dataset/runtime?». Перечень имён без dependency edges непригоден для такого incident response. Сохраняются digest, owner, scope, deployment binding и retention; публичный экспорт не раскрывает закрытые storage URI.

## D02
ML возвращает advisory данные, а не policy instructions, executable commands или разрешения на release. Это сохраняет опасные действия под контролем обычной авторизации даже при ошибочном предсказании. GenAI-инструменты не добавляются только потому, что принцип сформулирован в статье об агентах.

## D03
Candidate parser может быть атакован. Поэтому отдельный prediction worker получает только model bytes и ограниченный batch features, не holdout labels, signing keys или полный каталог. Scorer/controller валидирует результат и создаёт report, но тоже ограничен в доступе и не имеет права production promotion.

## D04
Сканирование - дополнительный сигнал. Format unsupported, parse error, timeout, zero objects и отсутствие свежей scanner policy дают inconclusive, а не pass. Конвертация pickle не допускается в обычном runner; если она вообще нужна, это отдельная одноразовая sandbox-задача без credentials, с повторной проверкой output.

## D05
Сохраняется старый reproducible benchmark, но появляется независимый challenge-трек. Процент и абсолютное число poison rows записываются вместе. Выводы ограничены выбранными budget/capabilities; manual/adaptive review не выдаётся за «полное обнаружение всех атак».

## D06
Цель обработки и допустимый экспорт важнее выбора модного privacy SDK. Public evidence не содержит raw inputs, labels, приватные URLs и идентификаторы субъектов. Хеш чувствительного маленького значения не считается анонимизацией: его можно перебрать.

## D07
До Sigma/SIEM задаются event schema, audit producer identity, последовательность, время, разрешённые поля и тесты alarm pipeline. Логи действий/проверок остаются минимальными; текст рассуждений модели не нужен как security authority и может раскрывать чувствительный контекст.

## D08
Не всякая практика нужна в MVP. Самая сильная рекомендация, неприменимая к workload, превращается в лишний доверенный компонент. Условный agent-трек требует отдельного ADR, asset list, scoped identities, tool authorization и новой приёмки; рекомендации CoSAI изучены, но MCP не устанавливается.

## Что CI подтверждает уже сейчас

Восемь decision records связаны с существующими source IDs, gates, tasks и документами; проверяются уникальность, обязательные поля, scope/status и task-gate coverage. Это проверка структуры reasoning trail, **не доказательство истинности источника, корректности security-дизайна или работы runtime**. Ручной review содержания остаётся обязательным.
