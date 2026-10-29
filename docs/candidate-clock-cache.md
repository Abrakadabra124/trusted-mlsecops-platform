# M11: часы и недействительный trust cache на actual candidate

Статус: [native 2b11bf5 / 40916783930](evidence/candidate-clock-cache-2026-10-29.md) success. Пять injected fault cases, exact causes, 25 denial observations, zero late worker calls и same-candidate recovery подтверждены. Полные M11/CP3/R1 остаются открыты. Это компонент candidate qualification, а не разрешённый production release.

## Что проверяется

[Probe](../mlsecops/kube_candidate_clock.py) использует настоящий CandidateReader, Lease, Engine и HTTP API. В hosted CI Engine запускает отдельный ONNX worker с той же фактически обученной моделью, подписанным proposal и прежним qualification permit. Private signing key в Pod не передаётся. До каждого fault нужны успешный prediction, точные model/subject hashes и golden error <=1e-6.

Пять fault cases вводятся только в зависимости Reader:

| Case | Изменение | Обязательная причина |
| --- | --- | --- |
| wall-backward | wall clock меньше последней выборки на 0.25 s | trust_clock_invalid |
| monotonic-backward | monotonic clock меньше последней выборки на 1 s | trust_clock_invalid |
| wall-jump | wall clock +30 s при обычном monotonic | trust_clock_invalid |
| server-skew | настоящий trust read, затем server timestamp -10 s | trust_server_clock_skew |
| invalid-signature | настоящий trust read, затем инверсия одного бита подписи в копии ответа | invalid_signature |

Это контролируемая инъекция clock/response dependencies. Часы узла, Windows и SQL не изменяются; сценарий не доказывает перенастройку NTP или реальное рассогласование часов инфраструктуры. Подпись намеренно повреждается, новая trust policy/approval не выпускается. Старые trust versions и equivocation пока покрыты отдельными controlled tests, не этой actual-candidate матрицей.

## Исполнение и доказательства

Замена зависимостей проходит под `Engine.exclusive`, но HTTP выполняется после освобождения lock. Наблюдатель записывает только ожидаемый конечный код отказа или `unexpected_rejection`; raw exception не попадает в report. Отказ может обнаружить HTTP check либо heartbeat, в обоих случаях требуются 503 и fenced generation.

После первого отказа проверяются точная причина, очищенный trust payload и Reader.current, отсутствие вызовов Worker.predict после injection. Затем providers возвращаются в исходное состояние. Ещё два predict и readiness должны дать 503, старая generation остаётся закрытой. Новый Reader заново проверяет те же model/subject. Каждый fault получает новый Engine; после всей матрицы отдельный Engine снова выполняет полный успешный HTTP contract, подтверждая восстановление inference.

Для каждого из пяти случаев сохраняются пять timestamped denial observations: predict/readiness при injection, два predict/readiness после восстановления providers. Это конечная матрица, не непрерывный нагрузочный тест. Модель и production trust enforcement не изменяются. Клиентские/worker identities, source/image binding, сетевые запреты и максимум permit 600 s сохраняются.

[Native coordinator](../scripts/kube_candidate_native.py) включает матрицу в начальном candidate Job только для configured-serving lifecycle run. Повторять её в outage/blackhole/policy/key Jobs нельзя. До и после начального Job сравнивается полный CAS + promotion snapshot; его hash записывается в `actual_inference.base_snapshot_sha256`. `native.clock_cache` находится внутри primary `probe.json` и связан его SHA256 с общим report.

## Ранбук и воспроизводимый плейбук

Ответственный - владелец disposable hosted qualification. Prerequisites: чистый checkout нужного commit, разрешённый GitHub-hosted workflow, отсутствие другого активного run. Локальные Docker/WSL/Kubernetes/SQL не нужны и не разрешены для этой проверки.

1. Read-only диагностика: проверить `gh run view RUN_ID --json status,conclusion,headSha,jobs`. При timeout наблюдателя повторно запросить тот же run; не dispatch новый, пока старый не завершён.
2. Локальная компонентная проверка: `python -m unittest scripts.kube_candidate_clock_qualification scripts.kube_candidate_qualification scripts.candidate_serving_reader_qualification scripts.trust_qualification scripts.serving_core_qualification`. ONNX worker/transport здесь doubles, это не native evidence.
3. После публикации проверенного code commit запустить один configured-serving workflow. Ветка `codex/cp3-m11-trust` запускает его push-триггером; дополнительный dispatch создаст лишний run. Workflow создаёт и удаляет только принадлежащий ему disposable стенд.
4. Принять только все пять `native.clock_cache` cases, точные причины, пять 503 в каждом trace, no-late-worker-call, same-candidate recovery, typed cases и неизменный full snapshot. Проверить source fingerprint, image, model/subject, permit и SHA256 primary report. Missing case, wrong cause, unexpected success, 429 или expiry вместо clock fault означают fail/inconclusive.
5. При `candidate_clock_fault` проверить finite case name. При case failure сохранить report и raw logs приватно в `.runtime/evidence`; не менять clock tolerances, не обходить подпись, не продлевать permit. При неверном golden или recovery digest не запускать выпуск.
6. Restore тестовых зависимостей выполняется в finally. Затем owned Engine/worker закрывается, проверяется отсутствие Pod, source SQL stopped и cluster absence. Если cleanup не подтверждён, эскалировать владельцу run с commit/run/phase и finite cause; не делать global prune/reset.

Настоящий operational clock incident диагностируется отдельно на владельце инфраструктуры: проверить источник времени и логи синхронизации, восстановить корректное время, затем создать новый Reader/Engine и повторно проверить доверие. Нельзя вручную сбрасывать broken_clock, generation, version floor или revocations в старом процессе. Этот hosted тест подтверждает fail-closed код и recovery path, но не выполняет ремонт NTP.

Локально 72 method executions pass без skipped; новая probe имеет 81/81 statements и 10/10 branches (100%). В тесты входят восстановление dependencies при исключении транспорта, отказ на wrong recovered candidate, обнаружение позднего Worker.predict даже при HTTP 503 и отсутствие raw private exception в диагностике. В native CI выполнены 264 method executions, 185 typed assertions базового candidate Job и 653 assertions всей actual-candidate группы с повторениями. Source/report hashes, одинаковый snapshot всех Jobs и cleanup проверены; [primary evidence](evidence/candidate-clock-cache-2026-10-29.md) отделяет injected cases от реальных network/SQL faults.
