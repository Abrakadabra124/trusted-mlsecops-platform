# CI после публикации CLI privacy: исправления и границы

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit», CP3/R1-B04.
Эта запись дополняет [native CLI privacy](kubernetes-cli-privacy-2026-11-06.md). Полный R1 не принят.

## Исходная матрица main

Публикация `d28f50140b8a209f54b44871c715c01b7d1c74fe` запустила десять workflows. Семь завершились success, три failure. Зелёный отдельный privacy run не заменял эту проверку.

| Workflow | Run | Итог |
| --- | --- | --- |
| Documentation | [42226136283](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42226136283) | success |
| Intake contracts | [42226135928](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42226135928) | success |
| Developer runtime | [42226136023](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42226136023) | success |
| M08 | [42226135948](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42226135948) | pass, primary report 69 cases |
| M09 | [42226136068](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42226136068) | pass, primary report 44 cases |
| Paired robustness | [42226136223](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42226136223) | success, component not adoption |
| Kubernetes isolation | [42226135831](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42226135831) | success, cluster cleanup step success |
| Storage | [42226136313](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42226136313) | failure: legacy output coverage 97%, required 100% |
| Tracking | [42226136291](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42226136291) | failure: four findings in pyasn1 0.6.4 |
| Image audit | [42226135884](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42226135884) | failure, 29 vulnerabilities in report summary |

M08/M09 primary reports имеют указанный source SHA, `source_dirty=false`, pass и exit 0. Для Kubernetes отдельно проверены workflow, строки M04/M05/M21 pass и cleanup; здесь не заявляется дополнительная повторная проверка их полных primary envelopes. Image audit охватывал worker/storage/tracking и два candidate images; это не новая полная проверка всех 14 controller/system images. Component counts 25/2/29/25/2 нельзя суммировать как уникальные CVE.

## Исправление tracking dependency

В [release pyasn1 0.6.5](https://github.com/pyasn1/pyasn1/releases/tag/v0.6.5) исправлены четыре decoder/CPU security issues. `uv pip compile` использован с прежними Python/platform/no-build/hash параметрами и `--upgrade-package pyasn1==0.6.5`. В [lock](../../images/tracking/requirements.lock) изменились только pyasn1 version/hashes; остальные 90 package pins сохранились. `requirements.in`, MLflow version и Dockerfile pins не менялись.

Локальный audit `--disable-pip --require-hashes --strict` подтвердил 91 dependency / 0 известных findings. Это не доказательство отсутствия неизвестных vulnerabilities или чистоты OS image. Orchestration/configuration/client contracts: 12/16/19 pass; четыре SQL-probe methods также прошли.

[Tracking 42227844457](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42227844457), source `0334ecf6456025a1c4ea0658007e12442eaa3a9d`, job `127925789882`: **success**. Пройдены locked build, три реальных training runs, offline authorization, persistent SQL/TLS publication/readback/restart, doctor и свежий M06. Primary M06 report: 18 cases pass, source clean, exit 0. Owned tracking services остановлены, cleanup step success. [Ранбук](../operations/tracking-troubleshooting.md#dependency-audit-точечное-обновление-pyasn1) сохраняет исходные findings и порядок повторения.

## Исправления storage contracts

1. `1737523`: legacy observer suite дополнен отклонением неверного `canary_count` до начала operation и допустимыми границами 1/9/16. 35 local/clean-checkout tests pass; observer 47 statements / 14 branches, 100%, parent 193/194 statements и 51/52 branches. Production observer и threshold не ослаблены.
2. [42227840179](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42227840179) на `0334ecf` прошёл прежнее место отказа, затем остановился на release authorization coverage. `a70beea` добавляет missing approval и подписанные ошибочные schema versions: 24 methods, 237 statements / 98 branches, 100%.
3. Тот же `a70beea` добавляет отсутствовавший source SQL always-stop в [storage workflow](../../.github/workflows/storage.yml). Он валидирует ownership marker, останавливает точный container ID, повторно проверяет identity и требует `Running=false`. Старый failed run после создания SQL не имеет подтверждённого явного stop; он не выдаётся за cleanup acceptance.
4. [42228824972](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42228824972) на `a70beea` подтвердил release coverage и новый cleanup, но обнаружил POSIX fixture error. Два старых tests копировали PEM обычным `write_bytes`, получая небезопасные permissions. `4f04116` переводит их на существующие `key_files.opened(create=True)` и bounded read оригинала. Production key-permission guard сохранился; локальный Windows pass сам по себе не доказывает POSIX mode.
5. Предварительное выполнение последующих coverage commands выявило неполное подключение уже существующих rollback/root-store/Kubernetes routing tests. Они добавлены к соответствующим командам. Без новой production logic получены 100%: promotion 38 methods / 137 statements / 48 branches, trust 42 / 257 / 100, Reader 31 / 138 / 40. Recovery 21 / 51 / 18, privacy 39 / 202 / 90 и context 15 / 52 / 8 также 100%. Thresholds сохранены.

6. [42230103970](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42230103970) на `4f04116` прошёл fixtures, но M03 завершился `worker_process_failed`. Добавленный ранний Linux filesystem preflight в [42232180410](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42232180410) на `64ea757` точно воспроизвёл `dataset_integrity_wrong_rejection:manifest-symlink:artifact_unavailable`. `91a65ec` исправляет только устаревшее ожидание Linux refusal. Descriptor guard и запрет symlinks не изменены.
7. [42232406810](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42232406810), source `91a65ec8734f05ae982d94daedeb7e81630e4747`: Linux filesystem 36 cases, **M03 431 cases**, **M07 97 cases**, storage recovery и promotion journal recovery прошли. Primary M03/M07: pass/exit0/exact source; M07 содержит `source_dirty=false`, M03 отдельного поля не содержит. Workflow далее failed на extended model backup в отдельной authority, cleanup source SQL success. Существующий transaction guard расположен после запроса promotion migration, которой в authority нет. `b60eb93` добавляет явный early scope refusal `trust_authority_backup_forbidden` перед model migration lookup, сохраняя transaction guard. Два новых failure-first метода и 26 adjacent methods pass. Нативный результат подтверждён ниже.

Локальная проверка остальных legacy commands: HTTP audit 48 methods, из них два Windows platform skips, 101 statements/34 branches 100%; client access 32 methods/0 skips, 93/30 100%; serving 84 methods/0 skips, aggregate89% при прежнем пороге85%; candidate reader 100%. Skips не выдаются за Linux qualification.

## Успешное повторение storage

[42233932160](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42233932160), source `b60eb93209b640afa3089baea9aea65d990f5959`, job `127946554287`: **success**; source SQL cleanup завершён 2026-11-06 14:36:39 UTC. Linux выполнил **1041 test method executions в 39 командах, 0 skips**. Повторяющиеся методы в разных coverage-командах не являются уникальными независимыми испытаниями. Альтернативный `release_key_only` job намеренно не выбран; это не пропуск обязательной проверки этого профиля.

| Проверенный путь | Результат и scope |
| --- | --- |
| Linux filesystem preflight | 36 cases pass до создания SQL |
| M03 | 431 primary cases pass, source совпадает, exit 0 |
| M07 | 97 primary cases pass, source совпадает, `source_dirty=false`, exit 0 |
| Storage recovery | 433 component cases pass, не полный M17 |
| Intake denial | 25 cases pass, component not full M21 |
| Promotion ledger | 108 controlled SQL cases pass, не полный M10 |
| Promotion journal recovery | 36 cases pass, не полный M17 |
| Separate trust authority | 45 cases pass, оба backup refusals, restart и outage; первый отказ lease за 59.989852641 s при пороге60 |
| Release reader / HTTP ONNX | 18 SQL-reader и 40 controlled HTTP cases pass, не полный M12 |
| Actual candidate HTTP | 85 cases pass, exact source и `source_dirty=false`, `release_ready=false` |
| Source SQL cleanup | success; точный owned container остановлен и `Running=false` проверен повторно |

Primary M03/M07 envelopes и actual-candidate source binding перепроверены из сохранённого журнала. Component scopes сохранены; их pass не превращён в полную приёмку соответствующих gates.

Чистый detached checkout `b60eb93`: **69 методов, 0 skips, 17.295 s**, Python3.12.15. Проверены путь импорта и чистота Git до/после. Использована ранее созданная изолированная venv с byte-identical `uv.lock`, `pyproject.toml`, `.python-version`; это не новая установка всех зависимостей. Linux CI использовал checkout и locked sync самостоятельно. Пользовательские изменения `AGENTS.md`/`GOAL.md` сохранены byte-for-byte.

## Воспроизведение

Pure checks без инфраструктуры:

```powershell
uv run --locked python -m unittest scripts.trust_native_qualification scripts.promotion_recovery_qualification scripts.promotion_policy_history_qualification scripts.release_native_qualification scripts.material_bundle_native_qualification scripts.serving_output_qualification scripts.release_authorization_qualification
uv run --locked python scripts/check_docs.py
```

Полное storage повторение требует разрешённого disposable GitHub-hosted Linux runner и чистого ref с этими изменениями. Запустить `storage.yml` через `workflow_dispatch`, `release_key_only=false`, сохранить commit SHA и итоговый cleanup. Не запускать Docker/WSL/Kubernetes/SQL локально в текущей цели. Не пересобирать evidence путём объединения отчётов разных source refs в один acceptance envelope.


## Ограничения

Проверки на разных commits не складываются в единый M18 acceptance envelope. Native M06 относится к `0334ecf`, CLI privacy - к `36cd71d`; полный R1 требует все обязательные gates на одном candidate/source/policy. M22 independent challenges остаются 0/2. Findings image audit не игнорируются и не устраняются одним обновлением Python dependency.

До полного M13 остаются service-output inventory/runtime readback/closed windows с leak controls, явная композиция controlled/actual subjects и общий строгий gate. Локальные Docker/WSL/Kubernetes/SQL не запускались. Raw CI logs, snapshots и private credentials не публикуются. Подробная диагностика и история попыток - [операционный ранбук](../operations/kubernetes-privacy.md#общий-ci-после-публикации).
