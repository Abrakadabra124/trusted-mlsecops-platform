# Release authorization: evidence 2026-10-14

Scope: complete proposal materials и отдельный authorization contract для T13, не полный M10. [Контракт](../release-authorization.md), [PB-20](../operations/release-authorization-troubleshooting.md).

## Controlled результаты

После review на Windows 21 methods проверяют policy/bundle/authorization, ещё 8 проверяют native runner через controlled transport. Реальные Ed25519 signatures и digest reconciliation, но SQL заменён тестовым transport. Security core: 229 statements, 94 branches, 100% coverage. Runner: 100 statements, 16 branches, 98%; module entrypoint не покрыт этой suite. Coverage не доказывает отсутствие всех ошибок.

Проверены decoded-key separation, внешние policy/runtime pins, все отсутствующие M-gates, failed/inconclusive/skipped reports, true вместо integer schema/exit code, subject/environment/action/sequence/digest mismatches, сроки, полный material readback, idempotency, interrupted publication, missing/swapped documents и ложный status=pass при несовпадающих outcomes. Failed signed model quality не переопределяется all-pass fixture reports. Positive authorization существует только в controlled tests, state=authorized-not-activated/release_ready=false.

Два регрессионных дефекта воспроизведены до исправления: несовместимые case fields/ID и assurance раньше начала policy. Причины и безопасные действия в RB-38. Reviewer-agent - дополнительный source review, не независимый human challenge M22.

Adjacent regression на Windows: объединённые 85 methods pass (новые 26 плюс material bundle, candidate lineage и оба прежних native runner contracts). Ruff check/format прошли. Docs check обнаружил неверную локальную ссылку runbook на storage.md; исправлена на существующий storage-recovery.md перед публикацией. Рабочие runtime services эта suite не использует.

Второй source review обнаружил незаписанные derived materials и отсутствие прямого SQL write-denial probe. Оба дефекта воспроизведены до исправления; теперь 20 CAS objects/9 documents и отдельный SQL 42501 check. Дополнительно проверена длина каждого загруженного SQL material до накопления полного package. Ранний ownership failure сохраняет прежнее evidence намеренно: запись в неподтверждённый state запрещена, nonzero exit делает старый pass непригодным для текущего решения. Это documented trade-off, не попытка переписать чужую среду.

## Native и CI

Первый [storage CI на 9d3c965](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38597308956) завершился success. Campaign f59150337334430db2a71a9c2ca48810, source_dirty=false, 10 checks, 17 objects/6 documents, model SHA-256 09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f, release_ready=false. Это исторический результат до correction CAS closure/SQL probe, не доказательство новых 20 objects/11 checks.

После corrections объединённые **88 methods pass** на Windows; Ruff и docs integrity pass. Новый clean-checkout SQL replay расширенного контракта будет добавлен после завершённого CI. Рабочая локальная БД не используется для повторения.

Рабочая локальная SQL/cluster среда не изменялась. Не создано фиктивных all-pass reports для native candidate. Существующие image, poisoning и evasion blockers сохраняются; M10/M11/M12 и общий R1 не закрыты.
