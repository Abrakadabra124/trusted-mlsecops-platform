# Candidate trust campaign: один цикл владения serving

Неделя 8, T14, M11. Ответственный за интеграцию и native запуск - основной
исполнитель R1. Это изменение orchestration и unit-проверка, не подтверждение
устранения release blocker на Kubernetes.

## Симптом и границы

Переданный для исправления [job 132530989069 в run 43622475622](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43622475622/job/132530989069)
на `a48f441` отказал с `candidate_trust_window` перед key-revocation, после
model-revocation. По переданным очищенным timestamps root rotation началась
в 18:12:06, HTTP matrix в 18:13:54, model-revocation в 18:18:44, отказ в 18:19:48.
Эти интервалы включают полезные проверки; они не измеряют стоимость handoff.
По исходному сообщению cleanup, source SQL/cluster и M04/M06 offline прошли.
В рамках этого исправления исторический run повторно не проверялся.

Исходный код возвращал persistent serving после root Job и приостанавливал
его снова перед остальными восемью Jobs того же кандидата. Удаляется этот
промежуточный цикл. Фактическая экономия времени ещё не измерена.

## Порядок и сохранённые проверки

[Native coordinator](../../scripts/kube_candidate_native.py) вызывает один
`ownership.run`: suspend -> live primary root denial/recovery -> observer update
-> явная peer rotation -> HTTP matrix -> outage -> blackhole -> policy change
-> model revocation -> key revocation -> два cold probes -> проверенный return.

[Root exercise](../../scripts/kube_candidate_root.py) получает raw probe от
владельца кампании. Его standalone вызов сохраняет собственный owned invoke.
[Post-root campaign](../../scripts/kube_candidate_campaign.py) вызывается внутри
того же внешнего владения, без второго handoff. Каждый probe по-прежнему вызывает
[native invoke](../../scripts/kube_serving_native.py): новый Job/ConfigMap, свежий
audit inventory, ownership preflight, cleanup и подтверждение отсутствия Pods.

Observer обновляется только после проверки полного live denial/recovery trace
primary и точного rotation retry, затем отдельно ротируется peer. Его
[update](../../mlsecops/kube_security_rotation.py) валидирует отдельные collector
и observer Deployment, конфигурацию, подписи и сохранённые audit volumes.
Suspended persistent serving не входит в эти Deployment. Успешный update
сохраняет serving marker, audit pin и исходный handoff ticket; это проверено
unit-тестом с настоящими валидаторами и подменённым инфраструктурным вводом-выводом.

Permit payload/envelope не меняются: максимум 600 секунд, минимум 180 секунд
остатка перед каждым fault. При 179 секундах key-revocation всё ещё отклоняется
после model-revocation. Выдача permit и установка authority не переставлены;
продление и повторная выдача отсутствуют. Успех кампании требует отдельной проверки
финального Pod UID, свежего heartbeat, identity receipts и прежних permissions.
В отчёте она остаётся в `trust_lifecycle_ownership_return`; промежуточного
`root_rotation.probe.ownership_return` у общей кампании больше нет.

## Проверка и восстановление

1. Для локальной проверки использовать отдельный worktree и зависимости проекта,
   без Docker, WSL, Kubernetes и SQL:

   ```text
   python -m unittest scripts.kube_candidate_campaign_qualification scripts.kube_candidate_root_qualification
   python scripts/check_docs.py
   ```

   Тесты включают отказы root/observer/peer и каждого последующего probe, порядок
   cleanup/restore/return, запрет вложенного handoff, сохранение permit и оба
   граничных значения 180/179 секунд. Unit pass не доказывает native timing.
2. Основной исполнитель интегрирует commit и согласует один disposable CI run
   с clean source/image binding. На этом этапе workflow, quotas и retention
   не изменялись. Повтор должен пройти всю прежнюю последовательность с одним
   permit, всеми отрицательными проверками и неизменными сроками.
3. Сверить private primary reports и их hashes, root denial <=60 секунд, recovery
   того же permit/model, отдельные histories, оба terminal/cold отказа, отсутствие
   worker после каждого Job, финальный ownership receipt и source/cluster cleanup.
   Только этот native результат может подтвердить устранение blocker.
4. При любой ошибке сначала завершается cleanup Job и восстановление обратимого
   fault, затем внешний owner пытается вернуть serving. Подтверждённый возврат
   не превращает исходную ошибку в pass. Root и terminal revocations не отменяются.
5. Если observer update прерван после изменения marker, audit остаётся unready.
   Проверка ticket/resume обязана отказать; нельзя принудительно выставлять ready
   или запускать serving поверх неопределённого состояния. Сохранить приватные
   материалы, выполнить предусмотренный владельцем disposable teardown и
   эскалировать по [ранбуку ротации](authority-root-rotation.md).
6. При повторном `candidate_trust_window` закончить campaign и сохранить очищенные
   timings. Не увеличивать TTL, не снимать guard, не пропускать negative cases.
   Откат кода не откатывает уже committed root rotation или revocations; новый
   разрешённый CI experiment требует отдельного disposable workspace.

Исходные [M11 сроки](../candidate-trust-lifecycle.md) и
[контракт root rotation](../decisions/0054-candidate-trust-root-separation.md)
остаются обязательными. M18/R1 этим изменением не принимаются.
