# Promotion recovery evidence: 2026-10-14

Scope: signed backup v2 и независимый restore CAS + promotion journal. [ADR 0028](../decisions/0028-promotion-recovery.md), [PB-22/RB-42/RB-43](../operations/promotion-recovery-troubleshooting.md). Не full M17/M11 или production DR.

## Локальные controlled результаты

После review и driver-boundary correction объединённые **125 adjacent unittest methods pass** на Windows: прежние 106, новые 12 recovery contracts, 4 CLI/probe и 3 OS-lock methods. Проверены реальный второй процесс и освобождение lock после os._exit. Python helpers `promotion_recovery`: 32 statements/6 branches, `recovery_lock`: 29 statements/4 branches, оба 100% coverage. Это не покрытие SQL ветвей, всей backup/restore integration или всего native orchestrator; validators/transport substitutes не заменяют реальную БД. Ruff check/format и diff whitespace check прошли.

TDD сначала выявил отсутствие нового module/API, затем snapshot/manifest v2 contract; после реализации все targeted tests прошли. Проверяются exact migration/scope, неизвестная schema, aggregate limits, TOC, maintenance, отсутствие pin до создания target, interrupted import без reopen, post-import mismatch, retry без reimport и CLI redaction/ownership. Настоящие подписи используются для manifest fixtures, SQL transport подменён.

Fresh-context reviewer обнаружил конкурентную гонку restore: поздний процесс мог закрыть уже восстановленный target. Добавлена OS lock до target check, удерживаемая до receipt/thaw; API regression и реальные subprocess tests проверены. Это same-model agent review, не независимая human acceptance M22. Cross-model review пропущен в автономном режиме, внешние CLI не запускались.

Docker Engine локально недоступен через dockerDesktopLinuxEngine named pipe. Working Docker/WSL/SQL/cluster не менялись. Native command проверен отдельно в fresh CI после прежних storage/release/ledger checks, а не на working state пользователя.

## Первый CI и correction

[Storage run 38610935513](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38610935513) на `75dbf56` завершился failure на новом recovery step; прежние CAS recovery, M03/M07 и 108 promotion checks прошли. Полный native recovery этого commit не принят. Исходный runner сохранил только generic failure, поэтому точный последний успешный шаг по тому log не устанавливается.

Code inspection выявил ошибочную границу negative probe: `storage.connect` преобразует psycopg startup failure в `Rejected`, а runner ожидал psycopg.Error. Controlled regression воспроизводит это преобразование; теперь используется прежний maintenance probe с непосредственным psycopg connection и точным распознаванием database-limit denial, посторонняя TLS/auth error не считается pass. Добавлены безопасные case progress и allowlisted failure codes без вывода SQL/credentials. Полный native outcome проверяется новым run, не выводится только из исправления.

Intake evidence первого run показывал source_dirty=true: legacy negative restore исходного `.runtime` теперь создаёт sibling `..runtime.recovery.lock` у корня checkout. Добавлен узкий ignore для `*.recovery.lock`, не для исходников; `git check-ignore` подтвердил этот путь. Новый runner требует чистый checkout до и после campaign. Presence lockfile не доказывает живой процесс. После correction 19 focused recovery/CLI/lock methods pass.

## Проверенный native recovery

[Storage run 38612183286](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38612183286) завершился success на `8f94e2e0ce018ffacf86ba803a06418e15896209`. Recovery campaign **1e0be20cce9e4e8cbe6bc721285afd75**, **36 native checks pass**, source_dirty=false. Интервал 2026-10-14 18:09:16.645702 - 18:09:30.905630 UTC.

- Source fingerprint: `0ab06551320a8a7d79e01ca1161cdac3d23d5da68a812177b48604e0ab565a1f`.
- Runner SHA-256 из source commit: `da107b462cb13da82abae8146485cf3fd3a8dc06f723fb0966e4231ca38c8b60`.
- Signed backup ID: `be5d780f0c37ecbe66ce55ae642d498b5a3c66f30864ba6e828a5a395dd33e44`; archive **8 157 611 bytes**.
- Promotion migration v1 SHA-256: `d6378c6fbf34cbe6fe527f7ea87499bb205309654a3acb3b1e3ff2d3161e7304`.
- Storage restore **4.168267 s**; от начала source-offline recovery до golden/signature checks **6.870389 s**. Images уже доступны на CI runner; это не cold-machine disaster recovery benchmark.
- **1 000 golden predictions**, maximum difference **0.0**, через sandbox worker из реально восстановленного model artifact. Stored evaluation signature и binding проверены.

Проверены: единый CAS/journal snapshot; source успел записать sequence=3, но backup и target согласованно сохранили sequence=2 без позднего CAS object; wrong/missing pin, corrupt/truncated/missing archive и withdrawn backup signer отвергнуты до bootstrap. Исходная БД остановлена на время независимого restore и predictions. После restart source её поздняя история сохранилась. Target имеет отдельные workspace/container/volume и новые private signing keys; SQL direct mutations запрещены.

Current request остаётся идемпотентным, старый sequence отвергнут. Завершённый restore не перезаписывает поздний target write. Controlled exception после **настоящего SQL commit** оставила target без receipt и с CONNECTION LIMIT 0; реальное serving connection получило database-limit denial, повтор не затёр target. Намеренное несоответствие head/event обнаружено. Только созданные qualification targets удалены по ownership. Это observation-loss injection, не внезапная потеря питания.

В том же storage run прошли 108 promotion ledger checks, 12 release checks, M03 431, M07 97 и прежний CAS recovery 433 checks/1 000 predictions/error=0.0. Release proposal отдельно показал source_dirty=false и worker image `sha256:f5b84df927dac1f11a14b56fa34774f0e35672d9a49c440a3114c299f03c0c5d`; это не подмена нового recovery report старым candidate approval. Linux OS-lock subprocess tests тоже прошли в этом CI, Windows tests проверены локально.

`scope=promotion-journal-and-cas-recovery-not-full-M17`, `full_M17=inconclusive`, `release_ready=false`. Положительный компонентный результат не означает общий green CI.

## Итоговая CI-матрица

Все десять workflows на `8f94e2e0ce018ffacf86ba803a06418e15896209` завершены: **6 success / 4 failure**. Следующий documentation-only commit фиксирует эти результаты, но не становится новым runtime evidence. Исторический Kubernetes run на `75dbf56` отменён superseding run, не принят как pass.

| Workflow | Run | Итог |
| --- | --- | --- |
| Storage role and TLS qualification | [38612183286](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38612183286) | success |
| Developer runtime qualification | [38612183258](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38612183258) | success |
| MLflow tracking compatibility and private service | [38612183142](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38612183142) | success |
| Kubernetes isolation qualification | [38612183219](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38612183219) | success |
| Intake evidence contracts | [38612183213](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38612183213) | success |
| Documentation integrity | [38612183365](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38612183365) | success |
| Worker and storage image audit | [38612183288](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38612183288) | failure |
| Frozen poisoning research matrix | [38612183361](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38612183361) | failure |
| Frozen evasion and domain guard | [38612183295](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38612183295) | failure |
| Paired robust training research | [38612183208](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38612183208) | failure |

Developer: 74 component checks, три fresh trainings, max probability difference=0.0, ONNX parity error=2.086162567138672e-07. Tracking M06: 18 cases pass. Kubernetes M20: 723 cases pass, завершён 2026-10-14 18:18:21.710228 UTC. M21: 122 cases pass, source_dirty=false, завершён 18:20:17.786175 UTC. Это regression evidence, не закрытие остальных release gates.

Image audit исполнил все четыре scans; каждый имеет scan_executed=true и status=fail. Critical/High/Unknown: worker 0/56/0, storage 9/115/19, worker-candidate 0/55/0, storage-candidate 1/85/0. Candidate images не приняты, severity exceptions не добавлены.

Poisoning campaign `9c9d1950510e414cb04a4a6a7d025727`: 35 cases/251 files, primary reconciliation и integrity pass, 10 statistical violations, 0 inconclusive. Baseline evasion campaign `1379ba1fcf1e439592e1516f52cae511`: execution complete, reconciliation pass, source_dirty=false, восемь workers; recall drop=0.07183673469387755 при лимите 0.05. Paired campaign `f266d1b2c0fb4c2bbe3235c5819b1afc`: execution complete, reconciliation pass, source_dirty=false, 14 workers, 12 abstentions на arm; candidate recall drops 0.052244897959183675 / 0.06224066390041494 / 0.06143344709897611 превышают 0.05. Эти failures не скрыты и не исправлены изменением порогов после измерения.

## Оставшиеся ограничения

V2 квалифицирован для независимого Docker restore, не для Kubernetes storage migration. Source inspection подтвердил: прежний kube migration вызывает validate_toc с v1 scope до maintenance/import, поэтому архив с ml_promotion tables отвергается, а не импортируется частично. Это проверка существующей границы по коду, не отдельная native v2 Kubernetes campaign.

Recovery pin выбирает конкретный snapshot, но не доказывает latest state и не восстанавливает post-snapshot promotions. Controlled SQL selections не являются одобренными моделями. Target без завершённого receipt остаётся fenced; автоматический pre-receipt resume ещё не реализован. Online revocation, serving activation, расписание/offsite/encryption и полный M17 остаются открытыми. Security/research failures не обходятся.
