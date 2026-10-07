# Воспроизводимые данные и карантин

## Что работает

Один фиксированный источник: 20 000 synthetic records, шесть normalized features, integer label 0/1. `data.lock` связывает SHA-256 и размеры generator inputs с ожидаемыми source bytes. Это маленький fixed-step runner, не универсальная замена DVC или workflow engine. Причина выбора: [ADR 0005](decisions/0005-data-lineage.md).

```text
reviewed code + policy + uv.lock + data.lock
  -> fresh generation / verified cache
  -> curator source-snapshot signature
  -> bounded quarantine intake
  -> повторная validation + curator approval
  -> signed dataset/split manifest
  -> signed source lineage -> isolated training -> independent scoring
```

SHA-256 проверяет точные bytes. DSSE/Ed25519 подтверждает, что snapshot разрешён локальным curator; простого совпадения `source` недостаточно. Подпись не гарантирует смысловую корректность labels.

## Запуск

Окружение и worker собираются по README. Команды выполняются из root репозитория:

```bash
uv run --locked python -m mlsecops bootstrap
uv run --locked python -m mlsecops.data_source repro --fresh
uv run --locked python -m mlsecops.data_source verify
uv run --locked python -m mlsecops.data_source prepare
uv run --locked python -m mlsecops demo --versioned-data
uv run --locked python -m mlsecops.acceptance --gate M02 --output .runtime/evidence/M02.json
```

`prepare` здесь является curator-side orchestration: проверяет lock, выдаёт source attestation, подаёт запись в intake и отдельно выполняет approval. Это не право недоверенного ingestor. Ручное разделение:

```bash
uv run --locked python -m mlsecops.data_source authorize
uv run --locked python -m mlsecops.intake submit --file .runtime/source/records.json --source synthetic-release-lab-v1
uv run --locked python -m mlsecops.intake approve --intake INTAKE_ID_FROM_OUTPUT
```

Проверяйте точное поле `source` в frozen policy, не придумывайте новое разрешение для внешних данных. `intake submit` никогда не пишет approved storage. Только совпавшие с signed source snapshot bytes допускаются curator; feedback не является готовой обучающей разметкой.

После `data_source prepare` IDs находятся в `.runtime/source/prepared.json`. Для отдельного обучения передайте оба: `python -m mlsecops train --dataset DATASET_ID --lineage LINEAGE_ID`. Kubernetes demo использует `--backend kubernetes --versioned-data`.

## Обновление source lock

Обычный `repro` отказывает, если code/policy/dependency lock изменились. Он не обновляет `data.lock` сам. Для намеренного изменения inputs:

```bash
uv run --locked python -m mlsecops.data_source repro --update-lock
uv run --locked python -m mlsecops.data_qualification
git diff -- data.lock
```

Изменение lock проходит обычный code review вместе с изменением generator/policy. Для reference seed 24017 source имеет 1 915 576 bytes и SHA-256 `1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473`. Это hash открыто описанной синтетики, не приватных данных. Dataset ID дополнительно зависит от разрешения curator, поэтому между fresh workspaces может отличаться.

Cache - отдельная копия, не hardlink. Подменённый cache вызывает отказ, не silent regeneration. Оператор расследует и удаляет только подтверждённо повреждённый объект собственного workspace, после чего выполняет `repro --fresh`; общий cache/чужие данные не очищаются. Истёкшее source approval требует явного review/renewal, автоматического продления нет.

## Приёмка и отрицательные сценарии

44 проверки выполняются в новом временном workspace со своими ключами; временный каталог удаляется после проверки. Проверены fresh regeneration/cache restore, mutation source/cache/input, все обязательные schema/duplicate/range/nonfinite fixtures, неизвестный/поддельный/просроченный source, forged feedback, изменение после intake, zero approved при отказах, стабильный повтор approval, disjoint splits, lineage binding и tamper.

M02 runner возвращает pass только после реального повторного выполнения suite; нет чтения старого зелёного файла вместо проверки. Остальные полные gates остаются inconclusive. Source lock - не независимая build attestation; negative cases не доказывают отсутствие всех возможных уязвимостей.

## Что ещё не защищено

Host administrator и curator доверенные. CLI-разделение и разные directories не являются полноценными storage ACL: T04/T05 и M03/M04 остаются открыты. Legacy `mlsecops prepare`/demo без `--versioned-data` сохранены для developer qualification, дают preview candidate без lineage и не подходят для будущего R1 promotion. Реальные данные не поддерживаются; нужны отдельные purpose, labels, privacy/retention и review. Signed source не заменяет poisoning benchmark.
