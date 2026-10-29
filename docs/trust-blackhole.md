# M11: зависшее сетевое чтение trust authority

Требование M11: serving прекращает ML-ответы не позднее 60 s после последней успешной проверки policy, включая медленное или зависшее соединение. Отдельный TCP refusal при остановленном PostgreSQL не доказывает этот случай. Полный M11 также требует expiry, keys, replay/rollback и clock checks; этот сценарий не заменяет остальные.

## Исполнение и границы

[Hosted coordinator](../scripts/kube_trust_blackhole.py) создаёт временную CiliumNetworkPolicy со случайным именем и workspace label. Она добавляет ingress deny только от service account `serving` namespace `ml-serving` к PostgreSQL в `ml-trust`. Исходные политики, workload и SQL не изменяются. Operator API и PostgreSQL admin остаются доступны для проверки ownership и очистки.

[HTTP probe](../mlsecops/kube_serving_lifecycle.py) сначала получает корректный prediction через обычный CLI. Начало этого запроса используется как консервативная нижняя граница успешного trust read. Во время injection приостановлен только owned HTTP child, чтобы heartbeat не продлил lease. Probe отдельно подтверждает именно TCP connect timeout с того же Pod; `connection refused` не принимается как blackhole. Затем HTTP child продолжает работу, фиксируются полностью полученные ответы до и после исходной 60-секундной границы.

После отказа coordinator удаляет только созданную политику, с UID precondition. Неопределённый исход create разрешается readback полного spec, случайного имени и labels; чужая identity не удаляется. Проверяются отсутствие политики, прежние Pod/PVC UID и работоспособность authority. Probe подтверждает восстановленный TCP connect, но уже отозванное поколение serving остаётся 503 без auto-reactivation.

Production timeout, verification и HTTP semantics не ослабляются. Fault injection выполняется только в disposable GitHub-hosted CI. На Windows разрешены лишь unit tests.

## Подтверждённый native результат

На `b5a933e` / [40823156897](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40823156897) blackhole **pass**: TCP timeout, первый полный 503 за 13.149598977 s, 41 HTTP отказ до и после 60 s, UID-bound policy cleanup, тот же Pod/PVC, TCP recovery и отсутствие auto-reactivation. Outage, policy-change и model-revocation также pass; source SQL stop и cluster absence подтверждены. 145 Linux tests, fault scope 100% statements/branches. [Полный очищенный trace и bindings](evidence/trust-blackhole-2026-10-29.md). Это controlled component, не полный M11 или release actual candidate. Intermittent worker startup failure не воспроизведён и остаётся необъяснённым.

## История диагностики

Первый запуск `4d97e0d` / [40821440191](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40821440191) остановился до injection: ordinary CLI после approval, исходная диагностика `worker-start / load / serving_attach_stderr`, Reader verified. Linux 99 + 26 + 17 tests pass; lifecycle/coordinator/fault 208 statements и 88 branches полностью покрыты. SQL stop и cluster cleanup success. Это уточняет прежний intermittent startup failure до канала stderr, но ещё не устанавливает содержание/причину. Следующий диагностический запуск различает пустой stderr, фиксированный worker refusal и известное семейство ONNX Runtime device-discovery warning; все варианты по-прежнему дают отказ, текст кадров не публикуется.

На `78a6d62` / [40822103126](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40822103126) сохранился общий `serving_attach_stderr`; cleanup success. Проверка диагностики выявила, что она классифицировала только первый WebSocket fragment. Новый RED regression воспроизвёл потерю классификации при отдельном ANSI prefix и фрагментированном сообщении. Исправляется только bounded сбор диагностического stderr: <=4096 bytes, <=8 дополнительных кадров и <=0.5 s в пределах исходного exchange deadline. Stderr всё ещё отвергает запуск; payload не выводится. Конкретная runtime-причина ещё требует native evidence.

## Ранбук

Ответственный - оператор isolated lab. Запуск: [configured-serving workflow](../.github/workflows/kubernetes-serving.yml), ветка `codex/cp3-m11-trust`; CLI внутри runner: `python -m scripts.kube_serving_native --state .runtime`. Не запускать инфраструктуру на текущей Windows.

1. Проверить terminal run status и safe stage marker `live-trust-blackhole`. Живой job не перезапускать.
2. `trust-blackhole-TCP-blocked` fail означает, что требуемый сетевой отказ не подтверждён. Проверить exact Cilium policy и identity Pod; не трактовать обычный HTTP 503 как доказательство blackhole.
3. Первый полный HTTP 503 позже 60 s или ML-ответ после границы - fail M11. Сохранить приватный trace и исходную привязку времени, не увеличивать порог и не переносить anchor на время injection.
4. При ошибке coordinator cleanup всё равно выполняется. Drift/чужой UID/неподтверждённое удаление останавливают принятие результата; не применять global delete или отключение исходных network policies.
5. После удаления fault policy подтвердить TCP recovery, прежние Pod/PVC UID, отсутствие auto-reactivation, source SQL stop и удаление owned cluster. Отсутствие хотя бы одного результата означает незавершённую проверку.

Локальная проверка: `.venv/Scripts/python.exe -m unittest scripts.kube_trust_blackhole_qualification scripts.kube_serving_lifecycle_qualification scripts.kube_serving_faults_qualification`. Она проверяет ошибки ownership, cleanup после неизвестного create, различение timeout/refusal и запрет поздних ML-ответов; не доказывает фактическую работу Cilium.
