# Kubernetes audit: scoped promotion and durable recovery

Дата:2026-11-12 МСК. Неделя11, T29. Это приёмка соединения collector, trust
observer и promoter в disposable hosted Kubernetes. Полный M23 и R1 не приняты.

## Версия и воспроизводимый запуск

- Runtime/qualification commit: `4aeece446465d959c94c844fdb0d17b360a66855`.
- [Kubernetes workflow43102906649](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43102906649): completed/success, job130798673737.
- Source fingerprint: `aac7400979f8616c57040fcc9586be7ece898e10fce5ef51402b52acafaf5e45`.
- Image ID: `sha256:bda385bac833c719a410addc4e4611331c9f2e59bdc00828f61af529af1baba6`.
- Native interval:2026-11-11T21:27:54.442180Z to21:31:59.531294Z.
- Linux workflow:98 unit executions, затем13 promotion assertions и10 audit assertions.
  Итоговый report печатается дважды; это один запуск, а не удвоенная проверка.
- Чистый checkout4aeece4, отдельная locked Python3.12.15 environment:
  71 scoped tests/0skips с `-W error`; реальные interpreter/import paths внутри checkout,
  Git worktree clean. Базовая интеграция1ec2222 также проверена в чистом checkout:
  98tests/1POSIX skip на Windows. Пропуск не является Linux evidence.

Воспроизведение требует разрешённого disposable hosted runner. Для исходного
commit использовать отдельную новую remote branch на его SHA, затем запустить
workflow `.github/workflows/kubernetes-promotion.yml` через workflow_dispatch.
Локальный checkout сам по себе не определяет source удалённого workflow.

```text
git push origin 4aeece446465d959c94c844fdb0d17b360a66855:refs/heads/reproduce-audit-4aeece4
gh workflow run kubernetes-promotion.yml --repo Abrakadabra124/trusted-mlsecops-platform --ref reproduce-audit-4aeece4
gh run list --repo Abrakadabra124/trusted-mlsecops-platform --branch reproduce-audit-4aeece4 --event workflow_dispatch --json databaseId,headSha,status,conclusion
```

Имя предназначено для новой scoped branch; если оно уже занято другим SHA,
выбрать другое имя, не применять force. Перед dispatch сверить remote SHA, затем
проверить `head_sha` самого run, terminal conclusion,
source/image pins, итоговый report и оба cleanup steps. Команды bootstrap,
locked dependencies и qualification закреплены в workflow. Локальная Windows
инфраструктура в этой работе не запускалась и не менялась.

## Что проверено на настоящих ресурсах

Operator создал три раздельных persistent journals, immutable role Secrets,
collector и SELECT-only trust observer. Проверки ownership связывают resource UID,
PVC/PV claimRef, Retain class и spec digest, Pod ancestry и фактический image ID.
Fresh state создаётся отдельными одноразовыми Jobs; обычный runtime не выполняет
init, не принимает неизвестный том и не заменяет потерянный pin новой эпохой.

Десять audit assertions подтвердили:

1. Свежий подписанный challenge доставляется по mTLS в collector через Service IP.
2. Trainer не имеет `/security`, `/audit` и TCP-доступа к audit endpoint.
3. Временный owned Cilium ingress deny вызывает отказ настоящего promoter.
4. При этом не меняются ни content-addressed objects, ни promotion journal:
   сравнивается единый SQL snapshot до и после отказа.
5. Событие отказа остаётся в постоянном outbox без receipt.
6. После снятия deny доставляются те же event_id/envelope, появляются signed receipts.
7. Независимый readback collector совпадает с подтверждёнными записями promoter.
8. Замена collector Pod сохраняет journal identity, события и receipts.
9. После замены сохраняются права0700 на каталог и0600 на identity/state.
10. Замена observer Pod сохраняет возрастающий heartbeat counter:5 ->6.

Collector Pod UID изменился с `c7fba763-cdf7-44ae-868b-b27d019e5c01` на
`4ca11bd9-0cb6-4f2b-9878-b460ce1958f9`; observer с
`7c8fd6da-7656-48da-a0bf-f4dc46294ab0` на
`2a0d7d94-305d-42c7-91d6-3ea735fca75c`. Это фактическая замена процессов,
а не повторное чтение прежнего Pod. После каждой замены заново проверены
UID/spec/backing volume pins и свежий audit challenge.

Тринадцать promotion assertions включают actual candidate refusal, отсутствие
записи при неполном разрешении, controlled positive без активации, независимый
SQL head readback, идемпотентный повтор, отказ после revocation и неизменность source.
Actual candidate `ae9667373798f73873b2f85abf6eab732eebd40ce873922ff15f7a722060e067`
остался отклонённым: parent `release_assurance_required`, Kubernetes job `rejected`.
Модель: `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`.
Controlled approval не является его разрешением. Report сохраняет
`full_M10=inconclusive`, `release_ready=false`.

Оба always cleanup steps завершились success: источник SQL остановлен с readback
Running=false; принадлежащий run cluster удалён с проверкой отсутствия имени в
kind inventory. Временная Cilium policy и probe Jobs очищались по созданным UID.

## Проверки кода и история отказов

[Security CI43102811593](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43102811593)
на том же4aeece4 в целом FAILED: contracts job прошёл691Linux executions/0skips,
native promotion25 и trust history37 прошли, continuous observer затем не уложился
в45s ожидания committed revocation. Это открытый регрессионный отказ; успешный
Kubernetes run его не отменяет. Причина не установлена; добавлена ограниченная
диагностика в4156d41, без изменения runtime и временных порогов.

[Повтор4156d41 /43104110909](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43104110909)
завершился success:692Linux executions/0skips, native25promotion+37history+
15continuous+46identity assertions. Fingerprint runtime совпадает с4aeece4.
Период observer30.019s, начало SQL revocation operation -> receipt29.85712158s,
stopped-source detection90.759104269s. Первая длительность включает SQL update
и ограничивает задержку после commit сверху; отдельный commit timestamp не измерен.
Чистый checkout4156d41:23tests/1POSIX skip. Диагностика изменила только harness;
этот pass не устанавливает причину предыдущего таймаута и не закрывает нестабильность.

Coverage обязательных новых компонентов, измеренный hosted contracts:

| Module | Statements | Branches |
| --- | --- | --- |
| security_event_provision |43/43|8/8|
| kube_security_resources |70/70|16/16|
| kube_security_materials |120/120|26/26|
| kube_security_events |201/203|68/70|

Каждый превышает95% по обеим метрикам отдельно. Coverage не заменяет native proof.

Первый integration run1ec2222 /43101562581 отказал после audit outage. Новый
отрицательный unit test воспроизвёл публикацию артефактов до первого challenge;
исправление4aeece4 переносит проверку перед publication, сохраняя pre/post-SQL
проверки и настоящий rollback test. Точная exception location первого native
отказа не была сохранена, поэтому не заявляется единственная доказанная причина.
Stale dispatch /43101392544 наae7b687 упал на старой schema до создания кластера.
Подробности и действия: [ранбук](../operations/kubernetes-security-state.md),
[observer timeout](../operations/periodic-trust-observer.md).

## Оставшиеся обязательства

Не завершены все семь actual event sources, mandatory serving identity profile,
trust rotation update, свежие M13/M14, real elapsed sequence-gap campaign и отказ
нового выпуска при здоровой ML-панели и потерянном security sink. Registry expiry
и обновление material/observer config требуют явной operator procedure, не reset.
Независимые M22 challenges0/2, полный M10/M19/M16/M17, image findings, shutdown debt
и M18 на одном candidate также сохраняются. Этот increment не заменяет рабочий R1.

## Продолжение: единая authority кампании

`00b7c39a6cfae6f6fb2a1e3b82a26501e990b7e9` использует существующий pinned
operator trust key до actual refusal и передаёт его controlled/serving/privacy/
candidate этапам. Qualification permit остаётся отдельным разрешением другого
назначения. Потеря ключа и чужая authority приводят к отказу, существующая signed
policy не сбрасывается. [План](../../tasks/audited-serving-integration-plan.md).

[Kubernetes43107249594](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43107249594)
success:13promotion+10audit assertions, image
`sha256:406e2c0e33e4534c45f9a90892803c114bcdd2c11ba0516751dffc13b4c5d883`,
runtime fingerprint прежнийaac7400979f8616c57040fcc9586be7ece898e10fce5ef51402b52acafaf5e45.
Heartbeat после observer replacement6->7. Source SQL stop/readback и cluster
delete/readback success. Actual candidate
`2122fe3b6de4fbe20be66e08345cf06cb75a86cece35fea2ebc8b5d38873182c`
корректно отклонён с parent release_assurance_required, Kubernetes rejected.

[Security43107221066](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43107221066)
success:753Linux executions/0skips и25+37+15+46native assertions. Observer
period30.019s, operation-start->receipt29.800075426s, stopped-source90.958373612s.
Это новый успешный запуск, не доказательство причины старого observer timeout.
Clean checkout00b7c39 с отдельной locked Python3.12.15 environment:
77tests3.194s с-Werror,0skips; interpreter/imports и Git clean подтверждены.

HTTP exact-field conversion, mandatory serving identity/outbox и operator update
observer после root rotation ещё открыты. Подготовлены дополнительные regression
checks для остановки serving/candidate при incomplete audit и native проверка
повторной подготовки после установки рабочей SQL policy; её отдельный результат
нужно получить до утверждения о native идемпотентности этого helper.
