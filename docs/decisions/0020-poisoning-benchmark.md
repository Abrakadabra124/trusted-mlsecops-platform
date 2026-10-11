# ADR 0020: замороженная train-only poisoning campaign

- Дата: 2026-10-11.
- Статус: protocol принят для synthetic research, native результаты ещё не получены на момент фиксации.
- Задачи: T11/M08; расширение T28/M22 остаётся отдельным обязательством.

## Контекст

После M07 есть проверенный scorer, но нет измеренного поведения при семантическом отравлении до approval. Подпись защищает происхождение bytes, а не истинность labels. Требуется выполнить исходные 30 poisoned runs + 5 matched controls, не выбирать удачные seeds и не выдавать статистическую suite за универсальный detector.

## Решение до первого эксперимента

Host-only [protocol](../../scripts/poisoning.py) фиксирует два семейства: targeted positive-to-negative label flip и такой же target с trigger `change_entropy=1.0`. Меняются только выбранные positive train rows: 70/140/700 из 14 000 (0.5/1/5%). Пять seeds: 17/29/43/71/101. Внешняя campaign controller знает экспериментальные labels; offline training/prediction worker не получает keys, SQL credentials или evaluation labels. Native runner не создаёт approved release.

Baseline train и validation воспроизводятся из pinned synthetic source. Security evaluation использует отдельные 3 000 synthetic entities с seed 73031 и отдельным пространством IDs. Их clean и trigger views заморожены до обучения; target означает false-negative на risky label, а не полезное изменение реального исхода. Это модель манипуляции представлением telemetry, не доказательство физических свойств релиза.

Final M07 holdout не используется для 35 экспериментальных оценок. Его cap 32 не меняется, рабочий SQL ledger не очищается. Security probes - публичная research suite, не новый способ обхода production holdout policy. Один native run обучает полную фиксированную матрицу; partial/resume/model reuse не разрешаются. Новое исследование после изменения защиты нельзя считать новой независимой оценкой на прежних probes.

ASR (attack success rate, доля целевых ошибок) измеряется на positive probes, которые matched clean model корректно определяет в том же view; eligible count >=500. Падение clean AP <=0.03, upper ASR increase <=0.10 сохраняются. Paired IID bootstrap: 2 000 resamples, seed 73037, two-sided 95% percentile interval; независимая единица - synthetic entity, не seed. На eligible probes clean ASR равна нулю по определению; дополнительно считается Wilson interval. Для решения берётся максимум bootstrap upper и Wilson upper, чтобы нулевой empirical bootstrap не выдавать за отсутствие uncertainty. Это консервативное дополнение, не ослабление порога.

Все scenario outcomes публикуются. Нет pooling одинаковых probes между seeds и нет одновременной 95% гарантии по всей матрице. Недостаточные probes дают inconclusive; известное превышение AP/ASR даёт fail. Known-violation score fixtures проверяют threshold enforcement отдельно от фактической эффективности атак. M22 требует ещё 36/6 runs и независимых challenges; эта матрица их не заменяет.

## Основания и ограничения

[NIST AML taxonomy](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) требует явно различать цели, возможности и знания противника; не задаёт гарантию detection для нашей модели. [SciPy bootstrap reference](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.bootstrap.html) описывает paired resampling одних индексов и ограничения методов интервалов. Реализация использует уже pinned NumPy/stdlib, без новой зависимости; единичные CI не доказывают популяционную устойчивость.

Host administrator и автор этой лаборатории остаются доверенными; независимый человеческий reviewer не заявляется. Проверенная целостность неизменного source не означает устойчивость к одобренному плохому источнику. Полный M08 будет принят только после native matrix, привязки inputs/evidence и общей gate-интеграции; этот ADR не является pass.
