# Release authorization: evidence 2026-10-14

Scope: complete proposal materials и отдельный authorization contract для T13, не полный M10. [Контракт](../release-authorization.md), [PB-20](../operations/release-authorization-troubleshooting.md).

## Controlled результаты

На Windows 20 methods проверяют policy/bundle/authorization, ещё 6 проверяют native runner через controlled transport. Реальные Ed25519 signatures и digest reconciliation, но SQL заменён тестовым transport. Security core: 215 statements, 86 branches, 100% coverage. Runner: 99 statements, 16 branches, 98%; module entrypoint не покрыт этой suite. Coverage не доказывает отсутствие всех ошибок.

Проверены decoded-key separation, внешние policy/runtime pins, все отсутствующие M-gates, failed/inconclusive/skipped reports, true вместо integer schema/exit code, subject/environment/action/sequence/digest mismatches, сроки, полный material readback, idempotency, interrupted publication, missing/swapped documents и ложный status=pass при несовпадающих outcomes. Failed signed model quality не переопределяется all-pass fixture reports. Positive authorization существует только в controlled tests, state=authorized-not-activated/release_ready=false.

Два регрессионных дефекта воспроизведены до исправления: несовместимые case fields/ID и assurance раньше начала policy. Причины и безопасные действия в RB-38. Reviewer-agent - дополнительный source review, не независимый human challenge M22.

Adjacent regression на Windows: объединённые 85 methods pass (новые 26 плюс material bundle, candidate lineage и оба прежних native runner contracts). Ruff check/format прошли. Docs check обнаружил неверную локальную ссылку runbook на storage.md; исправлена на существующий storage-recovery.md перед публикацией. Рабочие runtime services эта suite не использует.

## Native и CI

На момент подготовки этого файла новый native SQL replay и clean-checkout CI ещё не выполнены. Workflow содержит отдельный шаг после реального M03: complete proposal publication, serving readback, exact object set, unchanged metadata/budget и отказ без общей assurance. Результаты будут добавлены только после чтения завершённых runs.

Рабочая локальная SQL/cluster среда не изменялась. Не создано фиктивных all-pass reports для native candidate. Существующие image, poisoning и evasion blockers сохраняются; M10/M11/M12 и общий R1 не закрыты.
