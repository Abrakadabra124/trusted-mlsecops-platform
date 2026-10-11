# Подписанное восстановление в отдельный candidate PostgreSQL

Scope: T02, compatibility component. Не adoption образа, не полная приёмка M17 и не production recovery. [ADR 0016](decisions/0016-candidate-storage-restore.md) сохраняет baseline policy; [предыдущий security audit](evidence/image-candidates-2026-10-09.md) остаётся fail.

## Что и зачем

При переходе с Debian bookworm на trixie одинаковая версия PostgreSQL не гарантирует совместимость TLS, локалей и восстановления. PostgreSQL хранит SQL-объекты и подписанные артефакты платформы; `pg_dump`/`pg_restore` переносят согласованный логический snapshot вместо подключения нового server к старому volume.

Новый runner создаёт baseline source и candidate target с новыми identities, локальными test keys, networks и volumes. Он использует существующий recovery path, а не отдельную упрощённую копию. Рабочая SQL-БД, Kubernetes deployment и baseline image tags не переключаются.

## Цепочка проверки

1. Удалить смысл старого pass: записать `inconclusive`. Проверить у обоих candidate images source fingerprint, recipe digest, роль и Linux amd64, получить immutable local image IDs.
2. Создать новый UUID state под `.runtime/image-candidates`, baseline source на loopback port 15442. Обучить и оценить synthetic model; сохранить артефакты через настоящие SQL roles.
3. Сделать подписанный snapshot. Проверить подпись, доверенные внешние public keys, возраст, hashes и точный набор таблиц до создания target.
4. Поднять независимый target на loopback port 15443. Candidate ID передаётся только keyword-only внутренним Python interface; обычный CLI и marker не могут выбрать новый образ. Проверяются `Config.Image` и фактический `container.Image`.
5. Восстановить и сравнить ledgers девяти таблиц, model/evaluation bindings и подписи. Проверить 1 000 golden predictions и native SQL permissions/mTLS (mutual Transport Layer Security, проверка сертификатов обеих сторон).
6. Проверить UTF8, provider `c`, `C.UTF-8`, recorded/actual collation versions и порядок 12 Unicode strings. Совпадение этого sample не доказывает эквивалентность всех локалей или ABI.
7. Повторный restore сохраняет container и certificates. Default restore и другой image ID не могут принять candidate receipt. Поздняя запись блокирует повторное восстановление и не теряется.
8. Recovery suite очищает только свой target после identity check. Runner повторно проверяет оба candidate bindings и удаляет только три проверенных source resources: container ID, network и volume. Итоговый report появляется после проверки удаления; private evidence остаётся ignored.

Это проверка доверенного административного backup: подпись сама по себе не делает SQL dump от злоумышленника безопасным. Host admin, source admin и backup signer остаются в trusted computing base.

## Воспроизведение

Требования: Linux amd64 Docker Engine, Python 3.12.15, uv 0.12.23, свободные порты 15442/15443 и минимум 8 GiB свободного диска для bootstrap плюс место образов. Один runner за раз. Выполнять из checkout:

```bash
uv sync --locked --python 3.12.15
uv run --locked python -m scripts.storage_image_qualification
uv run --locked coverage run --source=scripts.storage_candidate -m scripts.storage_candidate_qualification
uv run --locked python -m scripts.image_candidates build
uv run --locked coverage run --append --source=scripts.storage_candidate -m scripts.storage_candidate
uv run --locked coverage report --fail-under=95
uv run --locked coverage json -o .runtime/evidence/storage-candidate-coverage.json
uv run --locked python -c "import json; totals=json.load(open('.runtime/evidence/storage-candidate-coverage.json'))['totals']; raise SystemExit(0 if totals['num_branches'] and totals['covered_branches']/totals['num_branches'] >= 0.95 else 1)"
```

Runner summary: `.runtime/evidence/storage-candidate.json`. Полный private report/backup остаётся в созданном UUID state. Не публиковать эту директорию, ключи, dump или raw logs. Exit 0 означает завершённую проверку совместимости, не разрешение выпуска: `release_ready=false`.

При ошибке запуск не восстанавливает старый pass. Созданные test resources могут остаться для диагностики, особенно если отказ произошёл до готового receipt. Не повторять вслепую при занятом порте, не использовать `docker system prune`: сопоставить UUID state, storage marker, labels и реальные container/network/volume identities. Чужие ресурсы и рабочие SQL states не удалять. Предыдущая проверенная copy остаётся отдельно от failed attempt.

## Проверенный локальный результат 2026-10-11

- Первый native run завершился `2026-10-11T09:04:28.054725+00:00`: **434 checks, pass**, 1 000 predictions, max error **0.0**. Restore-to-golden **9.906 s**, SQL restore **6.672 s**. Это component timings, не весь M17 recovery lifecycle.
- Baseline source: `postgres:18.6-bookworm@sha256:9551dd5bf356409a21b31248f49b33bba9bb1877365f3a7e933aecd9af3cf52d`.
- Candidate worker: `sha256:2931ffbe14f0b54d5d3722f8094c9cf18ae20d0c11eec63fa4df9626683081b0`; storage: `sha256:0f548a60905a14494921f15c509306bd562ec02d7bf0275333f7a6d8533f9f88`.
- Source fingerprint: `5c42a8f25bb59fde14446e9864b5c812a26893e9bf5527a2e3ae740c8e7f54e3`. Revision `81da8b56e5acec9df7845c8a02a0e958e9c2e89d` плюс незакоммиченный increment; этот локальный запуск не выдаётся за clean-checkout CI.
- Canonical full report SHA-256: `6c902ed67d87bee4e29d076309403acf8f85ff1940a80f6c431c0e13e4d75640`. Hash связывает private report, не является независимой аттестацией.
- Обе database profiles: UTF8 / provider `c` / `C.UTF-8`; recorded/actual versions `null`. Это действительные значения этого профиля, не неизвестная версия, преобразованная в pass.
- **33 controlled image contracts** и **14 runner contracts** прошли отдельно от native SQL. Только contracts покрывают 9/10 ветвей runner: entrypoint дополнительно проверяется native запуском. Coverage этого малого runner нельзя переносить на весь recovery/bootstrap или M18.
- Повторный запуск под coverage завершился `2026-10-11T09:08:40.155845+00:00` как **inconclusive**, `storage_docker_failed:pull`. Он не оставил старый pass; первый успешный результат сохраняется как историческое evidence, не outcome этой попытки.

[CI workflow](../.github/workflows/image-audit.yml) запускает этот rehearsal до vulnerability scan. Clean-checkout outcome фиксируется отдельно после проверки run; наличие workflow не доказывает success. Общий image audit не обязан быть green: compatibility pass не снимает High/Critical findings.

## Что ещё требуется

Исправление residual vulnerabilities, publisher verification, утверждённая image migration policy, перенос свежей рабочей истории, rollback и полный restore metadata/artifacts/approvals/serving. Затем единый release candidate со всеми M01-M23. Нельзя подключать этот candidate к существующему volume на основании одного rehearsal.
