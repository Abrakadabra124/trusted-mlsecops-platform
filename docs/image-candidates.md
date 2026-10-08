# Отдельные images для исправления findings

Scope T01/T02. Candidates не заменяют `trusted-mlsecops:dev`, pinned working PostgreSQL, работающие containers или persisted volumes. Пороги security audit не ослабляются. Решение и альтернативы: [ADR 0015](decisions/0015-image-candidates.md).

## Что изменено

Worker собирается в два этапа: pinned uv устанавливает locked Python dependencies, а отдельный pinned Python 3.12.15 runtime получает только venv и код. Исполняемые uv/uvx с Rust dependencies не попадают в final image. Debian libpcre2-8-0 установлен в точной исправленной версии `10.46-1~deb13u3` с проверкой APT signatures/hashes через HTTPS. Остальные пакеты не подвергаются плавающему dist-upgrade.

PostgreSQL candidate сохраняет версию 18.6 и использует pinned trixie вместо bookworm. Неиспользуемые проектом gosu/auto-init entrypoint удалены в подготовительном stage, final filesystem копируется в новый image без старых layers. Сохранены dpkg package inventory и библиотеки PostgreSQL. Это не попытка удалить metadata, чтобы scanner ничего не нашёл. Server запускается напрямую; UID 999 задаётся runner, как в текущем storage profile. По умолчанию image не инициализирует database и не является drop-in заменой обычного Docker Hub postgres entrypoint.

У recipes разные SHA-256 labels. Дополнительно проверяются role, app source fingerprint, Linux amd64 и immutable local image ID. App source fingerprint сам по себе недостаточен: разные recipes могут содержать одинаковый app code. Квалификация и audit повторно проверяют recipe binding.

## Воспроизведение

Выполнять из корня checkout с Linux amd64 Docker Engine и locked Python environment:

```bash
uv sync --locked --python 3.12.15
uv run --locked python -m scripts.image_suite_qualification
uv run --locked python -m mlsecops build
uv run --locked python -m scripts.image_candidates build
uv run --locked python -m scripts.image_candidates qualify-worker
uv run --locked python -m scripts.image_audit --compare-candidates
```

Build создаёт только `trusted-mlsecops:worker-candidate` и `trusted-mlsecops:storage-candidate`. Worker qualification использует новый UUID state в `.runtime/image-candidates`, immutable image ID и existing developer suite, не рабочие signing keys или SQL. Отсутствие image и сбой нового запуска инвалидируют старый qualification pass.

Последняя команда повторно сканирует четыре images на одном read-only DB snapshot. Baseline findings сохраняются, даже если candidate лучше. Общий audit остаётся fail, пока любой image в scope содержит блокирующие findings. `comparison.status=pass` означает только полноту сопоставления, не прохождение security policy; `release_ready` всегда false. Пары сравниваются по advisory ID и package name, а не installed version: обновление версии при сохранении того же advisory не выдаётся за исправление.

Результаты, ignored: `.runtime/evidence/image-candidate-build.json`, `.runtime/evidence/image-candidate-worker.json`, `.runtime/evidence/image-audit.json`. Raw SBOM/config и keys не публиковать. `--compare-candidates` не делает restore и не переключает deployment.

## Проверено локально 2026-10-09

- Build обоих recipes завершился. Worker: `sha256:7aa0567ae25dd6b376171b0fe371d896b552f9f8cd582a05d70d2b45bc4d0f35`, 649 129 357 bytes. Baseline tag остался `sha256:1d3097282d04d64be21329fc9c60690c6a64f3517a9df4d102335000a6e933e0`.
- Storage candidate: `sha256:05ddb14c7244f4c6d1264f8b6412a1fffe3882a6d88702173b02caa71775f012`. Ни одна working БД не заменялась.
- 74 developer checks worker candidate прошли. Три fresh training runs дали max probability difference 0.0, AUPRC 0.9323007296445032, max ONNX parity error 2.086162567138672e-7. Это synthetic component qualification, не доказательство бизнес-utility или прохождение M20 нового image.
- Native Syft подтвердил 128 package artifacts worker candidate и 145 storage candidate против 1 152/151 baseline. Package artifacts могут включать повторяющиеся libraries в разных binaries; уменьшение этого числа не измеряет снижение риска в процентах.
- 123 controlled checks: 43 policy/report, 15 archive, 25 scanner/CLI, 18 orchestration, 16 candidate и 6 comparison. У пяти audit/candidate modules branch coverage 98/100 (98%), combined 98,45%. Контрактные fixtures и mocks не заменяют native scan.
- Native comparison завершился локально и в [clean-checkout CI 37847315083](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37847315083) на `d4b5514`: одинаковая vulnerability DB, одинаковые findings/deltas. Worker High 56 -> 55; storage Critical 7 -> 1, High 101 -> 79. Оба candidates остаются fail, исключений нет. [Evidence и 37 residual triage groups](evidence/image-candidates-2026-10-09.md).
- Storage candidate добавил четыре advisory IDs, включая восемь High matches. Уменьшение общего количества не доказывает отсутствие регрессии. Pair deltas также включают переименования packages при смене Debian; их нельзя интерпретировать как число исправленных CVEs.
- CI повторил 74 worker checks и 123 controlled checks. После локального audit все 10 принадлежащих ему scanner containers отсутствуют; baseline worker tag не изменён. Старые timeout attempts сохраняют свой прежний inconclusive, но не определяют результат нового завершённого run.

## Что остаётся до adoption

1. Исправить или доказательно исследовать остаточные High/Critical, включая Critical libxml2 и новые GnuPG findings. Native comparison завершён, security gate не пройден. Не создавать исключения только по vendor marketing или названию hardened image.
2. Для storage выполнить подписанный backup/restore в отдельный новый target с новым image: identities, TLS, schema, ledger, разрешения, golden predictions и повторный restore. C.UTF-8/collation и ABI могут измениться при смене Debian, даже если PostgreSQL major тот же.
3. Включить новый image в проверяемый bootstrap/migration policy, подготовить rollback и лишь затем менять deployed reference. К текущему volume candidate не подключать до этих проверок.
4. После adoption повторить затронутые M02/M03/M20 и связать все gates с одним candidate в M18. Старые source-compatible pass не являются доказательством безопасности нового runtime.

[Исходные findings](evidence/container-audit-2026-10-08.md), [audit runbook](container-audit.md), [CI](../.github/workflows/image-audit.yml). Полный R1 остаётся незавершённым.
