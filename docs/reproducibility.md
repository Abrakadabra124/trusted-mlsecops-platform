# Native воспроизводимость и изменения inputs

Компонент T07/T08, 2026-10-11. Это исполняемая проверка на synthetic local CPU профиле, не полный M06 и не разрешение release. [Ранбук повторения и устранения проблем](operations/reproducibility-troubleshooting.md).

Следующий increment подключает этот runner к [общему M06 gate](reproducibility-gate.md): новая campaign плюс reconciliation с сохранёнными model/data/vector bytes и повторный tracking read-back. Сам standalone report со scope `not-full-M06` по-прежнему не заменяет acceptance output.

## Требование и реализация

Проверить, что три свежих обучения на одинаковых inputs воспроизводят предсказания, а реальные изменения seed/data/environment не принимаются за повторение. Сравнение только accuracy или model filename не обнаруживает изменение происхождения модели.

- [Comparator](../scripts/reproducibility.py) проверяет точную схему, три разных run IDs, шесть типов input digest, конечные вероятности, vector digest, длину golden set и численные допуски. Сначала сравниваются inputs, затем числа. Допуски M06 не изменены: probability <= `1e-6`, AUPRC <= `1e-4`.
- [Native runner](../scripts/reproducibility_native.py) создаёт отдельный UUID-state и signed synthetic dataset: 14 000 train, 3 000 validation, 3 000 frozen holdout. `train_candidate` трижды запускает настоящий worker, каждый раз отдельно выполняется ONNX prediction. Новые IDs - дополнительная проверка; fresh execution обеспечен реальными вызовами без cache/reuse модели.
- Шесть digest полей связывают request, signed dataset, policy, source revision/fingerprint, фактический image/versions/environment и common golden rows. Полные labels остаются на host, prediction worker получает features. Модель и векторы не загружаются в MLflow.
- Seed 17 -> 18: training request/policy меняются, split bytes проверяются на точное равенство. Data: первый feature первой training row меняется на `1-value`; validation/holdout остаются прежними. Environment: отдельный image с `OMP_NUM_THREADS=2` вместо 1, actual value проверяется в network-none контейнере, исходный source fingerprint сохраняется.
- Каждая mutation вызывает новое обучение и prediction, всего **шесть + шесть**. Comparator обязан отклонить смешанную тройку с конкретным `reproducibility_inputs_changed`, даже при одинаковых предсказаниях.
- Внешний publisher записывает шесть очищенных records в private PostgreSQL/TLS MLflow. Reader сверяет params, metrics и artifact bytes. Каждый record связан с реальным training ID и immutable image ID, но имеет статус `unapproved-candidate`.

Выбран отдельный host runner, а не новый orchestration framework: он использует уже проверенную sandbox boundary, не добавляет MLflow SDK/credentials в worker и позволяет независимо проверять численный comparator. Host/controller пока доверенный; это не доказательство независимого publisher в Kubernetes.

## Проверенный локальный результат

Последний native report: `2026-10-11T11:02:03.181911Z`, HEAD `89b42ec3a4fe1533a9632cbb5320fb06628fbfc8` + dirty host scripts, после исправления pairwise comparison. Runtime fingerprint `5c42a8f25bb59fde14446e9864b5c812a26893e9bf5527a2e3ae740c8e7f54e3`. Это локальная проверка до commit, не clean-checkout CI текущего increment.

- Три baseline runs, 3 000 golden rows, max probability difference **0.0**, AUPRC difference **0.0**, AUPRC **0.9323007296445032**.
- Model digest всех трёх: `09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f`.
- Vector digest всех трёх: `faba956b15aa6a066c834a96eb10dc4b94c3fed6d629b6b5e654a999d8677a14`.
- Seed mutation: changed dataset/policy/request, probability difference **0.0**, отклонена как повторение.
- Data mutation: changed dataset/request, probability difference **0.00036460161209106445**, отклонена как повторение.
- Environment mutation: changed environment, probability difference **0.0**, отклонена как повторение.
- Шесть разных training IDs и шесть разных MLflow run IDs, каждый опубликован и прочитан обратно. Temporary derived image tag удалён только после проверки ownership label и immutable ID.
- **33 controlled comparator tests**: missing/reused runs, changed inputs, invalid hashes/shapes, NaN/bool/huge/out-of-range значения, missing/mismatched vectors, численный drift и pairwise spread по всем трём повторам. Покрытие малого comparator: **25/25 statements, 14/14 branches**. Это не coverage всего runner/репозитория.

Private authoritative reports: `.runtime/evidence/reproducibility.json` и `.runtime/reproducibility/<UUID>/evidence/reproducibility.json`. Статус до начала работы - inconclusive; после успеха - `native-input-mutations-and-tracking-not-full-M06`, `release_ready=false`. Не добавлять целиком `.runtime` в Git.

## Границы результата

`OMP_NUM_THREADS` и image metadata действительно меняются. Это **не** доказательство изменения фактической параллельности BLAS/ONNX и не cross-platform/GPU reproducibility. Seed может не влиять на детерминированный solver; нулевая разница не отменяет новое происхождение. UUID ownership label также меняет image identity; не приписывать все различия одному ENV.

Численный контракт допускает разные model hashes при одинаковых inputs и прогнозах в допуске. Здесь hashes совпали, но bit-for-bit reproducible builds между машинами не обещаются. Синтетическая AUPRC не является business utility.

M06 теперь интегрируется через отдельный dispatcher/gate с reconciliation. Полная lifecycle lineage, scoped Kubernetes publisher и metadata-loss/recovery остаются открытыми задачами T07/T08 и продукта. Known High/Critical image findings не устранены. Tracking mutable, не WORM и не источник approval. Foundation repository и рабочая model storage не менялись.

## CI и эксплуатация

[Workflow](../.github/workflows/tracking.yml) запускает controlled cases с порогом comparator coverage, native campaign после private tracking qualification и read-only [diagnostic playbook](../scripts/tracking_doctor.py), затем останавливает только owned CI tracking containers. Наличие workflow не считается результатом выполнения; подтверждённый run фиксируется отдельно после завершения.

**Подтверждено:** [run 38134212049](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38134212049), job `114454639899`, commit `44deac94528ccae45e426c01d354a81f5e225a76`, **success**, 5m18s. Native campaign завершена `2026-10-11T11:09:21.938060Z`, `source_dirty=false`. Повторены 33 comparator tests, 26 doctor tests, три live doctor stages, шесть trainings/predictions/MLflow records и все три native mutations. Golden rows 3 000, max probability difference 0.0, AUPRC difference 0.0, AUPRC 0.9323007296445032. Baseline model/vector digests совпали с указанными локальными результатами; input bundle digest CI `44f861d8eb05af39b53229bac8d0a9cb57e6a483178189cef2118f011d3809ab` относится именно к CI material identities, не обязан совпадать с локальным.

CI base worker `sha256:5ad361b46bc1b624b1fdf7bf7949e50fa910dd9ef237847c976c98075dc5c0e8`, mutated environment `sha256:f86da717cafe21b783a5d74d0334e5465019f6d5b9d65ccc12c0bbf0e3376f01`. Seed/env output difference 0.0, data difference 0.00036460161209106445; все изменённые inputs отвергнуты как повторение. Очистка temporary image и остановка owned CI tracking services завершились успешно. Это проверка данного component, не закрытие полного M06.

На том же commit [documentation](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38134211808), [developer runtime](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38134211991) и [storage/TLS](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38134211892) завершились success. [Image audit](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38134211927) завершился failure на `Audit exact worker and PostgreSQL images`; functional green не отменяет release block. [Kubernetes](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38134211863) на момент записи ещё выполнялся и не объявляется успешным. Документационный follow-up не меняет код, проверен локальным docs checker и не запрашивает повторный CI; evidence привязано к указанному code commit.

[Каталог ранбуков](runbooks.md) разделяет уже реализованные процедуры и будущую эксплуатацию полного продукта. Первый native отказ `invalid_json_value` и исправление преобразования NumPy массива описаны в RB-05, не скрыты повторным pass.
