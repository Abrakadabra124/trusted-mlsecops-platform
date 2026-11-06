# T14: release signer policy history и полный restore

Дата: 2026-11-06. Неделя 8 «Bundle, approval и отзыв доверия», T14 «Trust lifecycle», CP3/R1-B04. Проверен компонент signed rotation/storage/recovery; полный M11/M17/M18/R1 не принят.

## Проверенные запуски

| Запуск | Source | Итог и границы |
| --- | --- | --- |
| [42191314037](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42191314037), job 127803747791 | `52a0a880590b69c9ddd78bf787c00f9ae46c67d3` | **Job failure**. Existing serving step success, новые SQL-ротации остановились до первой SQL mutation; recovery skipped. Source SQL и cluster cleanup success |
| [42194888914](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42194888914), job 127815580087 | `a501ac58bc17dcbe473e67af96e47828b066370b` | **Focused job success**, 09:25:18-09:26:31 UTC. Три SQL-ротации, полный recovery и cleanup success. Обычный storage-component job не выбран в этом dispatch |

Первый отказ вызван использованием `contracts.now()` как арифметических секунд, хотя функция возвращает ISO timestamp. Новый regression test воспроизвёл `TypeError` до вызова `promotion_state.install`; native clocks исправлены на epoch seconds, отчётные timestamps остались ISO. Ошибка не скрыта повторным запуском без изменений.

Между двумя sources изменены native script, его regression test и режим workflow. `mlsecops`, dependency locks, Dockerfile, images и policies побайтно неизменны. Проверены 144 Git blobs и общий source fingerprint:

`7cc12e1fd0dbee1bc85986b02bcecd1dbb10b090f8a27288c36d26ab2a885237`.

## Ротации на настоящем PostgreSQL

**37 native cases pass.** Publisher, assessor, approver последовательно заменены отдельными owner-authorized переходами. Policy version 1 -> 2 -> 3 -> 4; новые controlled selections имеют sequence 1 -> 2 -> 3 -> 4.

- Одновременные одинаковые запросы дают одну строку истории на переход; точный повтор не меняет snapshot.
- Ротация сохраняет head/events. Следующая selection с прежней policy отклоняется с SQLSTATE `P1002`, с новой принимается.
- SQL guards отклоняют неверный head и истёкший переход без изменения журнала.
- Старые и новые события остаются валидными относительно своих политик. Повреждение current policy, цепочки policy hashes и boundary/request обнаруживается; диагностические mutations откатываются.
- Все шесть application roles лишены права прямого удаления rotation history.

Migration 1 остаётся прежней: `d6378c6fbf34cbe6fe527f7ea87499bb205309654a3acb3b1e3ff2d3161e7304`.

Additive migration 2: `7992109ef049991a007e007b4af4aa96ec76c734e3ae9eb252fa271915065a4c`.

Exact rotation package SHA-256:

1. `f0f0205de24700bb3395a28366ebc7abf328ac696b2ead12169747c8fab29dd0`
2. `c11a5fe8e5a59e71247cf0e84d961cdc14dc2322f4472b4eb8a9748bfd61b8e9`
3. `073cd3121683a3b609d0c6056973da49bb1ad721e4395bc7950871832608e8bb`

Online trust в этом компоненте - настоящий подписанный in-process fixture. Это не проверка смены release signer через живой authority service и HTTP serving. Controlled selections не являются принятыми ML releases; `release_ready=false`.

## Backup/restore после ротаций

**36 native recovery cases pass.** Один exported snapshot включает CAS, authorities/events/heads и policy_rotations. Concurrent selection после snapshot остаётся в source, но не попадает в выбранный recovery point. Полный журнал восстановлен в другом container/volume при выключенной source БД и сравнен с исходным snapshot.

| Метрика | Результат |
| --- | --- |
| Archive bytes | 7 847 752 |
| Storage restore/readback | 4.001339 s |
| От начала recovery до golden predictions | 6.047658 s |
| Golden rows | 1 000 |
| Максимальное расхождение | 0.0 |
| Backup ID | `6a134cc97fe7c99d769668b5af4ded4fb11584590e0ed9a783c45c86d596d008` |

Проверены missing/wrong external pin, отозванный backup signer, изменённый/обрезанный/отсутствующий archive, старый sequence, повтор без import, сохранение поздней записи target, неимпортированные private keys. Потеря ответа после import не выдаёт success: target остаётся в maintenance, реальный serving client не подключается, повтор не перезаписывает target. Повреждённая связь head/events обнаруживается. Оба recovery targets удалены; source history сохранена, в конце source SQL подтверждённо остановлен.

Этот результат проверяет recovery компонента и не заменяет полный M17 в целевом namespace, current trust и activation.

## Regression и воспроизведение

На `52a0a88` локально прошли 162 regression methods; Linux preflight первого CI выполнил 631 method execution без skips. Existing serving step дал 980 typed actual assertions с повторами, actual production отказан без assurance. Live root HTTP 503 за 5.482712914 s, model revoke за 6.682017144 s, key revoke за 5.774412603 s; golden error 0.0. Полный job при этом **failed** на новом SQL script.

После clock fix focused Linux preflight: **46 tests / 0 skips**. `release_key_rotation`, `release_key_store`, `promotion_recovery`: **152 statements / 48 branches, 100%**. Исходный первый clean Windows clone создал новый venv и установил 64 locked packages; после checkout `a501ac5` эти 46 tests повторены за 1.017 s, tracked tree чистое. Локальные Docker/WSL/Kubernetes/SQL не запускались.

```powershell
git clone https://github.com/Abrakadabra124/trusted-mlsecops-platform.git
cd trusted-mlsecops-platform
git checkout --detach a501ac58bc17dcbe473e67af96e47828b066370b
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.release_key_rotation_qualification scripts.release_key_store_qualification scripts.promotion_policy_history_qualification scripts.promotion_recovery_qualification scripts.kube_promotion_snapshot_qualification scripts.release_key_native_qualification scripts.promotion_recovery_native_qualification
git status --porcelain
```

Hosted режим: существующий `storage.yml`, `workflow_dispatch`, `release_key_only=true`. Полный storage job сохраняет прежний default; режим выбирается явно. При повторении необходимо сверять `headSha` выбранной ветки/tag, terminal outcome и cleanup. Команды и границы находятся в [runbook](../operations/release-signer-rotation.md), решение в [ADR 0055](../decisions/0055-release-signer-policy-history.md).

## Привязка evidence и оставшаяся работа

SHA-256 canonical JSON + LF: rotation report `0dfe7fc19e8658dea973685a01d28a6f79afd2b94e139290129f0f40c6abb205`; recovery report `4bac6b22199357dec229e5d73154fb97c40298abd2316e7200c50892aa4d13fa`. Existing serving report первого failed job: `bf391a3917b9b59b56889203ef4f288dd3d2fd3640e3218686027898122b61e8`. Исходные отчёты, архивы, ключи и raw logs остаются в private evidence; опубликовано очищенное описание.

Следующий обязательный шаг T14 - live release-signer transition с новым capsule/release/assurance/approval, HTTP отказом старого конфигурационного состояния и явным восстановлением. Полная приёмка M11 и общий candidate-bound M18, independent M22 0/2, image findings и остальные CP4/CP5 gates сохраняются. Разные component campaigns не объединяются в один принятый R1 candidate.
