# Постоянный HTTP-сервис в CP4/T29

Неделя11 - Security events и потеря telemetry. T29 - Security event contracts и replay.
Scope: synthetic-only controlled admission, существующий real HTTP CLI, Kubernetes
worker, SQL selection, signed audit events и отзыв. Полный M10/M23/R1 не принят.

## Изменение

Ранее обычный HTTP CLI запускался тремя отдельными Jobs. Теперь operator создаёт
один Deployment release-risk-advisor: процесс живёт до и во время выбора release.
Без выбранной модели `/readyz` и `/v1/predict` возвращают503. Сам факт поступления
security heartbeat не означает, что модель разрешена или загружена.

После выбора operator останавливает реплику, проверяет отсутствие прежнего HTTP
Pod и worker Jobs, затем запускает одну новую реплику. Записи Deployment защищены
UID и resourceVersion. Если shutdown не подтверждён, запуск замены запрещён,
marker остаётся incomplete. Startup reader загружает только проверенный выбранный
bundle. Автоматической активации в уже запущенном без модели процессе нет.

Secret security-serving содержит отдельные TLS/signing credentials и service.token,
отличный от collector ingress/operator tokens. Security outbox остаётся на PVC
security-serving. ConfigMap неизменяемый, HTTP слушает только loopback Pod.
Readiness проверяет реальный authenticated `/readyz`, liveness проверяет `/livez`.
Подмена UID/config/image/pin запрещает operator exec/restart.

Это один экземпляр с контролируемым перерывом при активации. Не заявляются
бесшовный rollout, HA или production SLO. Обычный HTTP request journal пока
находится в приватном tmpfs; только security outbox переживает замену Pod.

## Проверенные предыдущие шаги

[54394bc](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/54394bc6d89df639d44544a6e2a3a65abfd983ec)
и [Kubernetes43117686817](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43117686817)
подтвердили19promotion+12audit checks и4/4/10/4HTTP checks:
до выбора, после выбора до замены, после загрузки модели, после отзыва.
ONNX max error7.583384781240099e-08; один новый identity.denied сопоставлен по
event/envelope/receipt с независимым collector. Heartbeat3->4, замена28.095852s.
После отзыва тот же активный Pod отказывает; actual candidate остаётся отклонён
с release_assurance_required. Cleanup:0service Pods,0worker Jobs, retained audit
state; отдельно подтверждены stop source SQL и удаление disposable cluster.

Тот первый вариант использовал ручной DELETE Pod. Self-review выявил возможность
создания ReplicaSet новой реплики до завершения старой. В этом CI гонка не была
зафиксирована, но его успех не доказывает её отсутствие. Поэтому этот механизм
заменён на сериализованные scale0/cleanup/scale1; предыдущий запуск не является
доказательством исправленной процедуры.

Security43117502816:771Linux tests,0skips, native25/37/15/46. Чистый checkout54394bc:
150tests14.764s,1Windows-only skip POSIX-проверки; в Linux она выполняется.

## Исправленная процедура

Код [88e7c0a](https://github.com/Abrakadabra124/trusted-mlsecops-platform/commit/88e7c0a3c0c30e090c9e326811543d4347e744d5).
[Kubernetes43119250736](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43119250736)
завершился success на точном88e7c0a. Job130855194981:23:22:02-23:31:47UTC,
внутри исходного25min timeout. Отдельные stop source SQL и remove disposable
cluster завершились success с проверкой конечного состояния.

| Этап | Результат | Проверки |
| --- | --- | --- |
| До SQL selection | Тот же живой HTTP, ready/predict503, worker отсутствует | 4 |
| После selection, до замены | Тот же Pod остаётся unready, автоматической активации нет | 4 |
| После сериализованной замены | Ready, три предсказания, точный model/bundle, один worker,401/422/413 | 10 |
| После отзыва | Тот же активный Pod отказывает503; точный trust_artifact_revoked | 4 |

Native report:19promotion+12audit checks. ONNX max error7.583384781240099e-08
при пороге1e-6. Замена с readback и доставкой нового heartbeat:28.737285s при
пределе120s; счётчик2->3. Outbox pin/records/private permissions сохранены.
Один новый identity.denied имеет независимо прочитанные совпадающие
event/envelope/receipt в collector. Cleanup:0service Pods,0worker Jobs,
security audit state retained. Это подтверждение проверенного профиля, не HA/SLO.

- Source: `88e7c0a3c0c30e090c9e326811543d4347e744d5`.
- Runtime fingerprint: `c4dff67e0291a5e388db044127c62ae058c4b211433ad8284a9b7339fbb23dd3`.
- Image: `sha256:fe93184b03bf7b7ca1827d1a0458cd7ea75fc124ce3ebacdeecf05e1ba9a5f62`.
- Actual candidate: `5143b585b4ed79ac9f031f96c9ac7e582cc5f70ee366172d22c888bd6f82abc4`.
- Actual refusal: `release_assurance_required`; `full_M10=inconclusive`, `release_ready=false`.

[Security43119182873](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43119182873)
завершился success:774Linux tests,0skips, native25/37/15/46. Trust periodic30.023s,
operation-start-to-receipt29.8554379s, stopped-source notice90.768791792s.
HTTP identity heartbeat30.098s, stopped-producer notice90.685793705s.
Эти scoped regressions не закрывают полный M23 и не доказывают устранение ранее
необъяснённого45s observer timeout другой campaign.

Локально153tests14.698s-Werror,1POSIX skip. В чистом checkout с отдельным locked
CPython3.12.15 окружением:153tests14.509s-Werror, тот же1Windows skip. Проверены
пути интерпретатора/imports внутри checkout и отсутствие изменений Git.
Новые отрицательные проверки: зависший old Pod/worker, чужой UID, отсутствующий
resourceVersion, неверное число реплик, изменение Pod во время exec, потеря audit
pin/config marker, попытка запуска новой реплики до очистки. Test-first readback
проверка воспроизвела неправильное сравнение старого resourceVersion с ответом;
исправление принимает новую версию API server, сохраняя UID/spec binding.

## Воспроизведение и ограничения

Операторские процедуры, диагностика, действия при incomplete marker и ограничения
миграции: [runbook](../operations/kubernetes-security-state.md#постоянный-http-deployment).
Hosted executable chain: [workflow](../../.github/workflows/kubernetes-promotion.yml),
[campaign](../../scripts/kube_promotion_native.py),
[operator](../../mlsecops/kube_serving_service.py),
[HTTP readback](../../mlsecops/kube_serving_service_probe.py).
Локальная инфраструктура в этой задаче не запускалась. Raw CI logs и приватные
операторские материалы не публикуются; CPU/memory quotas не увеличивались.

Остаются: обязательный serving heartbeat во всех campaign/caller paths,
collector outage при одновременно здоровом ML/dashboard, все семь M23 sources,
signed observer root-rotation transition, свежие M13/M14 и реальный допуск M10.
M19/M16/M17, два независимых M22 challenge-кейса, image findings и shutdown debt
также остаются открыты. M18 должен собрать все обязательные gates на одном candidate.
