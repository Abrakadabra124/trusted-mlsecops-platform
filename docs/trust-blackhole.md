# M11: зависшее сетевое чтение trust authority

Требование M11: serving прекращает ML-ответы не позднее 60 s после последней успешной проверки policy, включая медленное или зависшее соединение. Отдельный TCP refusal при остановленном PostgreSQL не доказывает этот случай. Полный M11 также требует expiry, keys, replay/rollback и clock checks; этот сценарий не заменяет остальные.

## Исполнение и границы

[Hosted coordinator](../scripts/kube_trust_blackhole.py) создаёт временную CiliumNetworkPolicy со случайным именем и workspace label. Она добавляет ingress deny только от service account `serving` namespace `ml-serving` к PostgreSQL в `ml-trust`. Исходные политики, workload и SQL не изменяются. Operator API и PostgreSQL admin остаются доступны для проверки ownership и очистки.

[HTTP probe](../mlsecops/kube_serving_lifecycle.py) сначала получает корректный prediction через обычный CLI. Начало этого запроса используется как консервативная нижняя граница успешного trust read. Во время injection приостановлен только owned HTTP child, чтобы heartbeat не продлил lease. Probe отдельно подтверждает именно TCP connect timeout с того же Pod; `connection refused` не принимается как blackhole. Затем HTTP child продолжает работу, фиксируются полностью полученные ответы до и после исходной 60-секундной границы.

После отказа coordinator удаляет только созданную политику, с UID precondition. Неопределённый исход create разрешается readback полного spec, случайного имени и labels; чужая identity не удаляется. Проверяются отсутствие политики, прежние Pod/PVC UID и работоспособность authority. Probe подтверждает восстановленный TCP connect, но уже отозванное поколение serving остаётся 503 без auto-reactivation.

Production timeout, verification и HTTP semantics не ослабляются. Fault injection выполняется только в disposable GitHub-hosted CI. На Windows разрешены лишь unit tests. Native результат пока не подтверждён.

## Ранбук

Ответственный - оператор isolated lab. Запуск: [configured-serving workflow](../.github/workflows/kubernetes-serving.yml), ветка `codex/cp3-m11-trust`; CLI внутри runner: `python -m scripts.kube_serving_native --state .runtime`. Не запускать инфраструктуру на текущей Windows.

1. Проверить terminal run status и safe stage marker `live-trust-blackhole`. Живой job не перезапускать.
2. `trust-blackhole-TCP-blocked` fail означает, что требуемый сетевой отказ не подтверждён. Проверить exact Cilium policy и identity Pod; не трактовать обычный HTTP 503 как доказательство blackhole.
3. Первый полный HTTP 503 позже 60 s или ML-ответ после границы - fail M11. Сохранить приватный trace и исходную привязку времени, не увеличивать порог и не переносить anchor на время injection.
4. При ошибке coordinator cleanup всё равно выполняется. Drift/чужой UID/неподтверждённое удаление останавливают принятие результата; не применять global delete или отключение исходных network policies.
5. После удаления fault policy подтвердить TCP recovery, прежние Pod/PVC UID, отсутствие auto-reactivation, source SQL stop и удаление owned cluster. Отсутствие хотя бы одного результата означает незавершённую проверку.

Локальная проверка: `.venv/Scripts/python.exe -m unittest scripts.kube_trust_blackhole_qualification scripts.kube_serving_lifecycle_qualification scripts.kube_serving_faults_qualification`. Она проверяет ошибки ownership, cleanup после неизвестного create, различение timeout/refusal и запрет поздних ML-ответов; не доказывает фактическую работу Cilium.
