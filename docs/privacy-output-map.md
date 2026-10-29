# M13: карта каналов вывода и границ доказательств

Неделя 9 «Serving и privacy», T16 «Privacy, quotas и audit». [Критерий M13](acceptance.md#m13), [ADR 0047](decisions/0047-serving-output-observation.md). Это карта полноты, не pass-report M13.

Обновление [ADR 0048](decisions/0048-privacy-acceptance.md), [native b0df48e](evidence/privacy-evidence-b0df48e-native.md): parent проверяет signed primary и fresh private receipt; нового наблюдаемого канала этот checker не добавляет. Design review требует retained exact snapshots/HTTP linkage, production lifecycle/429/503, service-log coverage, subject composition и отдельную public projection. Эти пробелы не закрыты согласованными summaries.

## Поток данных и статус наблюдения

| Канал / producer | Реализованный контроль | Подтверждение и оставшийся пробел |
| --- | --- | --- |
| HTTP body/headers, включая unknown paths/query/Host | Strict input/output, no redirects, no raw errors; request ID генерируется сервером | [Native privacy](evidence/serving-privacy-2026-10-19.md): 12 cases / 36 durable events. Actual credentials/input canaries проверяются в той же операции. |
| Python stdout/stderr и Logger.handle в HTTP hot loop | Bounded LifecycleCapture, seal на всех путях выхода, marker/credential/hash/raw row/numeric feature scan | Late writes через сохранённые вложенные streams отвергаются внешним observer. Hot-loop scan сам по себе не доказывает весь lifecycle/native FDs. |
| Serving qualification stdout/stderr с imports до interpreter exit | ADR0047: owned child, sealed nested Python captures + strict outer FD pipes + checked report snapshot | [Native 2a70ffc](evidence/serving-output-2a70ffc-native.md): 82 cases, zero native stderr, 6 canaries. Cached stream, subprocess, atexit, whitespace/overflow и snapshot mutation controls проверены; не full M13. |
| FastAPI/OpenTelemetry spans/logs/metrics/operation spans | Explicit disabled settings, environment auto-configure off, provider hooks с positive control | Existing privacy suite и actual-candidate no ambient signals. Это управляемая конфигурация, не защита от произвольного injected exporter/admin. |
| Approved metrics endpoint | Operator identity, bounded labels/series, distinct quota, no request/client hashes | [Native metrics](evidence/serving-metrics-2026-10-19.md): 69 approved series; independent schema/canary probe. |
| Private audit journal / manifest | Owned bounded retention, strict event/context, no raw request body | [Native correlation](evidence/audit-correlation-54cbe50-native.md): 332 events / 83 completed; 58 v2 contexts. Source/run/report/authority refs приватны и не являются raw features. |
| Public audit export | Fixed counters only, exact schema, nested canaries проверены | [Native export](evidence/audit-export-f0d0542-native.md) и новый [correlation proof](evidence/audit-correlation-54cbe50-native.md). IDs/private graph отсутствуют. |
| Persistent serving worker | Private framed stdout IPC; stderr DEVNULL; runtime-verified log-driver=none, no network/mounts, core=0 | serving_runtime проверяет реальный container contract. Protocol не публичный лог: признаки нужны worker для inference; нельзя публиковать raw IPC как evidence. |
| Kubernetes serving worker и CRI logs | [Новый backend T15](kubernetes-serving.md): network-denied worker, bounded attach, stdout только typed replies, stderr фиксированный отказ | Native интеграция ещё проверяется. CRI сохраняет stdout с scores и model/session/request identifiers/hash. Docker log-driver=none не распространяется на этот backend. Требуются отдельные canaries, private collection и retention; raw CRI logs не публиковать. |
| Kubernetes attach bridge / normal serving CLI | Private logger без propagation, proxy/redirect/compression off, родительские deadlines и owned process cleanup | Bounded protocol/cleanup unit tests не доказывают отсутствие утечек во всех native outputs. Probe отдельно проверяет пустой stdout/stderr HTTP CLI; целостное M13-наблюдение bridge, worker и service logs остаётся обязательным. |
| Training worker / scoped controller transport | Private bounded protocol, fixed diagnostics, role isolation, guards и no raw stderr retention | [Controller native](evidence/controller-privacy-2026-10-19.md), [worker native](evidence/worker-privacy-2026-10-19.md). Это предыдущие scoped proofs, не новая единая M13 campaign. |
| PostgreSQL/trust metadata | TLS roles, fixed serving queries, configured log_statement=none и terse/panic error policy | API feature rows не передаются в SQL: serving читает control-plane refs. Конфигурация сама по себе не доказывает все возможные service logs; отдельную scope/coverage связь должен проверить M13 runner. |
| Tracking/model pipeline evidence | Publisher/scorer имеют отдельные обязанности, public records ограничены | API untrusted bodies не поступают в MLflow/training. Не переносить serving canary pass на все upstream/operational reports без проверки их схем и потоков. |
| Final CI evidence/report | Не публиковать raw captures, child report deferred до observer; public export отделён от synthetic native report | Новый observer проверяет весь сериализованный candidate report на те же input needles. Synthetic source/model digests уже допустимы в native evidence; private production report не становится безопасным автоматически. |

## Что считать полным M13 для R1

Нужен отдельный executable gate, который связывает один current source/candidate с наблюдавшимися controls: auth/quotas, approved metric cardinality, input canaries во всех релевантных serving outputs, private source-to-request chain, public export и retention policy. Он должен явно перечислять наблюдаемые каналы и исключённые потоки, отличать отсутствие канала по архитектуре от непроведённого теста и отвергать stale/missing/failed/inconclusive evidence.

Не суммировать зелёные исторические reports разных commits как новую приёмку. Qualification permit и controlled approval не принимают failed actual release. M13 runner пока отсутствует в acceptance dispatch и остаётся inconclusive; source-dependent image/ML failures сохраняются.

Raw training datasets хранятся по назначению в quarantine/approved storage. Требование не сохранять raw features относится к serving request journal/telemetry по умолчанию, а не к запрету иметь управляемый training dataset. Private IPC, necessary authorized API response и public logs - разные границы; успешное удаление одного вывода не доказывает отсутствие данных во всех остальных.

## Ограничения

Это synthetic local-CPU reference без реальных персональных данных. Нет обещания differential privacy, устранения membership inference, защиты от same-UID host admin, неизвестных exporters или полного forensic стирания RAM. Реальный пилот по-прежнему требует purpose/retention/privacy specification и отдельного review.

