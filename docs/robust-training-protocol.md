# Эксперимент robust logistic training

С 2026-10-29 текущий paired protocol v2 сравнивает явный `reference-logistic-train` с `train`, то есть [balanced candidate](noise-training-validation.md), выбранным только на development validation. Three probe seeds, attacker budgets, AP loss <=0.03, quality/recall thresholds, 14 executions, parity/readback и abstention проверки ниже сохранены. Это проверка нового алгоритма на известных regression probes, не три новых независимых challenges. [Native v2 40784734008](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40784734008) на `2d3e43e` завершился pass: recall drops 0.0318367/0.0232365/0.0435154, все AP losses <=0.03. Полные bindings/ограничения в [evidence](noise-training-validation.md#подтверждённый-native-результат-2026-10-29-мск).

Дальнейший текст сохраняет **исторический design v1** и его неудачный research-robust-train. Эта action остаётся воспроизводимой на зафиксированных commits. Текущий protocol явно фиксирует другой recipe/source, не переносит старые results на новый candidate. Scoped production controllers не разрешают reference/research actions. V2 training convergence проверяется внутри source-bound worker и numeric contracts; стандартный train response не содержит отдельного optimization receipt, поэтому поле optimization в v2 summary пусто.

Зафиксировано 2026-10-13 до обучения нового варианта и просмотра новых probe outcomes. Область: T12, synthetic CPU research; baseline не меняется автоматически. Прежний [evasion failure](evidence/robustness-2026-10-13.md) остаётся историческим результатом.

## Обоснование и альтернативы

Проверяется один заранее выбранный вариант: минимизация worst-case logistic loss при прежнем attacker budget. Для бинарной линейной модели внутреннюю задачу можно решить аналитически; [учебные материалы авторов Adversarial ML Tutorial](https://adversarial-ml-tutorial.org/linear_models/) выводят этот случай. Здесь дополнительно учитываются mutable coordinates и пересечение perturbation box с [0,1]^6. Это наша ограниченная адаптация, не новая общая гарантия.

[Madry et al.](https://arxiv.org/abs/1706.06083) рассматривают robust optimization как постановку adversarial training. [Tsipras et al.](https://arxiv.org/abs/1805.12152) показывают, что robustness и clean accuracy могут конфликтовать. Поэтому уменьшение атакуемости без проверки utility не принимается. Удаление двух признаков проще, но безусловно выбрасывает сигнал; tuning threshold или уменьшение attacker budget ослабили бы исходную приёмку. Ни один из этих обходов не применяется.

## Frozen design

- Неизменные 14 000 training rows и 3 000 validation rows из data.lock, training seed=17. StandardScaler обучается только на train. Final holdout/SQL budget не используются.
- Attacker тот же: только change_size и change_entropy, L-infinity=0.05/L1=0.10, clipping [0,1], остальные coordinates/labels неизменны. На evaluation атака адаптируется к каждой модели отдельно через прежние four-corner queries.
- Пусть standardized coefficients `w=p-n`, `p,n>=0`. Для каждого training row берутся фактические lower/upper perturbation distances с учётом clipping и scale. Минимизируется mean worst-case logistic loss + `||w||²/(2*N)`, что сохраняет C=1. Это не подмена внешнего robustness измерения training loss.
- Один solver: SciPy L-BFGS-B, analytic gradient, maxiter=500, ftol=1e-12, gtol=1e-8, без hyperparameter search. Дополнительная numerical acceptance: finite coefficients, nonnegative split variables, пересчитанный projected-gradient infinity norm <=1e-5 и objective не хуже initial baseline. Неуспех solver не разрешает silent fallback к обычному fit.
- ONNX profile прежний: StandardScaler -> LinearClassifier, шесть входов, labels 0/1. Golden parity <=1e-5 на 3 000 validation rows и совпадение labels вне epsilon-zone. Новая worker action research-only не добавляется в allowlist scoped controllers.

## Evaluation до выбора кандидата

Два впервые используемых в этом эксперименте synthetic probe seeds: **73043 и 73047**, по 3 000 rows, IDs с отдельных диапазонов 3 000 000 и 4 000 000. Проверяются disjoint IDs и feature vectors между datasets. Seed 73041 из опубликованного эксперимента дополнительно используется только как known regression, не как независимый challenge. Все три outcomes публикуются, pooling или выбора удобного seed нет.

Для каждого набора: clean AUPRC >=0.80, gain к constant prior >=0.10, >=200 positives, recall drop <=0.05, threshold=0.5. Дополнительный guard против utility regression: clean AUPRC loss относительно fresh baseline <=0.03. Reporting включает clean/attacked recall и false-positive rates; это point estimates, не production SLA или доказанная калибровка. Нарушение на любом наборе оставляет candidate unacceptable. Отдельно повторяются domain-support abstain fixtures.

Новые seeds не являются независимым человеческим reviewer challenge: протокол составлен тем же агентом. M22/T23 не закрываются. После публикации эти probes также нельзя использовать как untouched set для tuning.

## Numerical verification и границы

Review до публикации добавил проверку полного числа abstentions, semantic readback training/intake, sanitized cleanup timeout и Decimal-сравнение clean AP loss. Последнее исправляет `0.90 - 0.87 > 0.03` из-за binary float rounding, не меняет лимит: `0.86999999` при baseline `0.90` всё ещё fail. Ни способ обучения, ни seeds/attack budgets после результатов не менялись.

Аналитическая производная сверяется с finite differences. Worst-case margin сверяется с явным перебором corners для обоих labels и знаков coefficients, включая domain boundaries. Разложение p/n может дать консервативную margin при одновременно positive частях, поэтому финальные coefficients сворачиваются в w и numerical checks повторяются на canonical split. Solver success сам по себе не считается certificate. [SciPy описывает projected-gradient stopping criterion](https://docs.scipy.org/doc/scipy/reference/optimize.minimize-lbfgsb.html); наши checks не заменяют точную арифметику.

Источники проверены 2026-10-13. Baseline, thresholds, generated dataset bytes и SQL grants не меняются. Native training/prediction выполняются без сети/секретов; privileged host не загружает модель. Adoption требует отдельного policy/version decision, повторения poisoning/M07 и полной release/serving приёмки. Эксперимент не может сам разрешить promotion.

До первого обучения полный запуск остановился на source lock: прямое объявление уже установленной SciPy 1.18.1 изменило uv.lock, но не версии пакетов. После побайтной проверки generated output обновлена только привязка uv.lock в data.lock. Output SHA-256 остался `1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473`, 1 915 576 bytes. Это явное обновление provenance, не смена данных или обход проверки. Campaign выполняет 14 workers: train, intake и пять prediction batches на каждую из двух моделей; 12 outside-support fixtures на модель не вызывают worker.
