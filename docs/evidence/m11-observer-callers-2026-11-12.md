# M11 после интеграции observer rotation в оба caller paths

Неделя11 «Security events и потеря telemetry», T29 «Security event contracts и
replay». Механизм M11 прошёл в этой synthetic-only кампании. Полный R1 не принят.

## Проверенный результат

[Run43132977638](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43132977638),
[job130901391447](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43132977638/job/130901391447):
terminal success на source `5486596d7523b2688b9459a9dff7f3fa2514c91a`.
M11 report: **146 cases pass**, включая125controlled contracts и21aggregate
criteria. В полном job выполнено701Linux test executions,0skips.
Интервал M11 report:2026-11-12 01:18:49.362192-01:39:00.539626UTC.
Подготовка candidate предшествовала этому интервалу.

Все workflow steps завершились success, включая отдельный backup/recovery,
остановку принадлежащего campaign source SQL и удаление disposable cluster
с проверкой конечного состояния. Локальные Docker/WSL/Kubernetes/SQL не запускались.

| Привязка | Значение |
| --- | --- |
| Runtime fingerprint | `39e9ef2a9078ab969a7e1cb8883187b84be3d6c380b4f25c9942c57a83f4f9a0` |
| Image | `sha256:cf408ccd976e040e063442e23a4a74c4c04b644d5bab958f2483fd1f22a43a89` |
| Actual candidate | `11191e2dc1cb70aea6fabc005f55dfab95d0c2ee345c35aa464fd04e1231baeb` |
| Model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Proposal | `f923f5c28f9a5c90916970b38f8853c904de13eb4db36224117a0550ce672c6b` |
| Qualification subject | `ea99859d01deb548438229c4ab1a96acadd12458cd71c455ecbf8411ebf85f1f` |

## Переход observer и HTTP refusal

В ordinary caller после committed SQL rotation обновлён существующий observer,
затем проверены отказ старого root pin и работа reader с новым root. В candidate
caller сначала завершён измеренный PRIMARY HTTP trace, затем обновлён observer,
и только после этого отдельно ротирована MODEL_REVOCATION authority.

| Переход observer | Время | Heartbeat | Подтверждение |
| --- | ---: | --- | --- |
| Ordinary authority rotation |11.688843s|16 ->17|новый Pod, first source check, retained outbox|
| Candidate PRIMARY rotation |10.732460s|25 ->26|новый Pod, first source check, retained outbox|

Pod UID после первого перехода совпадает с исходным UID второго. Это проверка
последовательной смены одного observer с сохранённой identity, а не два новых
независимых bootstrap. `reused=false`, `release_ready=false` у обоих переходов.
Operator проверяет counter также на независимом collector; строка first-success
сама по себе не считается доказательством доставки.

| HTTP scenario | Первый завершённый503 |
| --- | ---: |
| Actual candidate: outage |59.768404579s|
| Actual candidate: blackhole |12.345475371s|
| Actual candidate: policy change |4.859270329s|
| Actual candidate: root rotation |4.764507252s|
| Actual candidate: key revocation |4.867260315s|
| Actual candidate: model revocation |5.066949374s|
| Controlled release: outage |59.809117999s|
| Controlled release: blackhole |12.454635966s|

Все времена отсчитываются от начала последнего успешного HTTP-запроса,
нижней границы последнего trust read. Traces содержат минимум два503, запрещают
последующий200 и при outage/blackhole продолжаются за60s. Исходный60s норматив
не увеличен. Подписанный approval перестал разрешать ответ за0.996759415s до
expiry. Пять clock/cache injections, действующий старый sequence/version и
независимость model/key authorities также проверены.

Live publisher/assessor/approver transitions:68cases, first503 соответственно
0.461666353/0.450959436/0.442860018s, удалены6workers. Отдельная SQL signer/history
проверка:37cases. Controlled backup/recovery:36cases, restore-to-golden5.599796s,
1000golden rows, max error0.0. Последний report сохраняет `full_M17=inconclusive`:
это не полная приёмка recovery всего R1.

## Проверка первичных данных и воспроизведение

После загрузки очищенных JSON reports из job выполнен повторный локальный
`trust_gate.reconcile` и `trust_gate.release_signers`. Они пересчитали traces и
подтвердили все соответствующие M11 metrics. Хеши трёх primary reports совпали
с M11 artifact_hashes. Хешируется canonical JSON **с завершающим LF**, как в
`contracts.write_json`; хеш без LF не соответствует файлу.

| Report | SHA256 файла |
| --- | --- |
| M11 | `8afe7719f0a13396e0e3088af9c1fb120690d3a21cb0a2740ccd74b7bf27f1e4` |
| kubernetes-serving | `3e455103de2fd5dc93f403bff85b8d80b67509c593c48f67826a628d79b9ede1` |
| release-key-native | `8a6e51491b0af0d86d60c11b235bc69519ec415f979200645a3746d73eec95e1` |
| release-key-serving | `ef1d23004b64377227d90761b6e042f115b6b323d6033148a02e3c4e0a46ee18` |
| promotion-recovery | `5eb9784eb477bd751281e873abd996053893819dac6e3a3f95386f8ab4edcde7` |

Чистый checkout5486596, собственный locked Python3.12.15 venv и imports:
72targeted tests за1.336s,0skips, Git clean. Для точного повторения взять указанный
source, выполнить `uv sync --locked --no-build --python 3.12.15` и набор
`scripts.kube_serving_lifecycle_qualification`, `scripts.kube_serving_native_qualification`,
`scripts.kube_root_rotation_qualification`, `scripts.kube_candidate_root_qualification`,
`scripts.kube_promotion_snapshot_qualification`, `scripts.kube_candidate_trust_qualification`,
`scripts.kube_serving_faults_qualification`, `scripts.kube_trust_blackhole_qualification`,
`scripts.kube_candidate_faults_qualification` через `python -W error -m unittest`.
Это code validation без локальной инфраструктуры. Полную campaign выполнять
только в разрешённом hosted disposable workflow по [runbook](../operations/trust-acceptance.md).

[Security43132975200](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43132975200)
на том же source:856Linux executions/0skips и25/37/15/46native cases, success.
Trust period30.024s, max commit delivery29.894145288s, stopped notice90.998896267s.

## Незакрытые ограничения

Предыдущий [aa276b2 /43130494941 отказ](observer-rotation-2026-11-12.md#проверка-caller-интеграции)
в live-trust-outage не повторился. Изменение5486596 добавило только ограниченную
диагностику response contract, не исправляло runtime contention. Контролируемый
real Engine/ASGI эксперимент со stubbed reader/worker показал429 при удержании
блокировки фоновой проверкой1.5s и последующий200; он не устанавливает причину
предыдущего hosted отказа. Эта нестабильность и прежний45s observer recovery
timeout остаются открытыми. Более поздний pass не является причинным исправлением.

Actual promotion по-прежнему отказан с `release_assurance_required`; candidate
выполнялся только по отдельному qualification permit. `release_ready=false`,
`full_M12=inconclusive`, `full_M17=inconclusive`. Обязательный serving heartbeat,
остальные M23 источники/сценарии, свежие M13/M14, M22 independent challenges,
остальные gates и общая M18 приёмка одного candidate остаются обязательными.
Raw logs, private packets и ключи не публикуются.
