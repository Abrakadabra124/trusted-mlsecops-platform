# Независимый отзыв модели и ключа на одном actual candidate

Подтверждённый component result: **pass**, `release_ready=false`, полный M11/R1 не принят. [Run 40936376995](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40936376995), job `123667888699`, commit `bfe295bb3aa3093dfd70b16ab0d75ccd55a0f99a`. Сквозной сценарий: 2026-10-29 19:05:28-19:19:25 UTC. Оба cleanup steps success. [ADR 0051](../decisions/0051-independent-trust-qualification.md), [ранбук](../operations/independent-authority-revocation.md).

## Что проверено

Один actual candidate прошёл отказ production promotion с причиной `release_assurance_required`, затем отдельную qualification HTTP matrix по одному короткоживущему permit. Для двух необратимых отзывов заранее созданы два явно выбранных тестовых состояния: primary и model-revocation. У них разные CA, host, UID inventories и PVC, один public root и исходная permit policy. Это не production failover или репликация.

Перед каждым terminal revoke подтверждён работающий inference той же модели. После отзыва модель или ключ не возвращались в trusted state. Тесты проверили точный cold refusal, отсутствие автоматического возвращения к работе и неизменность полной истории соседней authority. После обоих отзывов два отдельных холодных Jobs снова подтвердили оба запрета без создания worker.

| Проверка | Наблюдение |
| --- | --- |
| Отзыв модели, model-revocation target | Первый завершённый HTTP 503 за **4.686277214 s**, точная причина `trust_artifact_revoked`; 78 typed assertions |
| Отзыв publisher key, primary target | Первый завершённый HTTP 503 за **5.688685663 s**, точная причина `trust_key_revoked`; 70 typed assertions |
| Заключительные cold Jobs | По 3 assertions на target: initial worker count 0, exact refusal, final worker count 0 |
| Primary versions: before / after model / after key | **7 / 7 / 8** |
| Model authority versions: before / after model / after key | **1 / 2 / 2** |
| SQL/TLS в обеих authority | Реальный TLS 1.3, правильная роль; UPDATE/DELETE/INSERT/SET ROLE отказаны SQLSTATE 42501; чужой CA даёт certificate verification failure, не timeout |
| CAS + promotion authorities/events/heads | Полный snapshot одинаков до/после base, каждого fault и заключительного readback |
| Cleanup | Собственная source SQL остановлена; verified owned disposable cluster удалён |

До terminal revoke повторены outage, blackhole и policy change на том же candidate. Первый 503 соответственно 59.768939719 / 13.551727350 / 5.473841305 s. Пять clock/signature injections и still-valid signed replay сохранились: old v5 при current v7 ещё действовал 3361.825 s, отказан именно по `trust_version_replay`; новый Reader и Engine восстановили golden inference. Максимальная ошибка golden prediction во всех actual probes 0.0.

В actual группе **837 typed case assertions с повторениями**: base 193, outage 195, blackhole 164, policy/replay 131, model revoke 78, key revoke 70, final cold 6. Это не число независимых атак или закрытых M-gates. Подготовительные Linux tests: **328 method executions, 0 skips**. Четыре новых target/isolation/history/terminal модуля: 122 statements / 26 branches, 100%. Все установленные workflow thresholds пройдены.

## Привязка evidence

Source fingerprint независимо пересчитан по 138 Git blobs этого commit; совпадает с runtime report. Две напечатанные в Actions копии структурированного отчёта совпали. Hashes относятся к canonical JSON с завершающим LF. Локальные копии отчёта и логов сохранены в ignored `.runtime`; в Git tree добавлен этот очищенный Markdown. Это не обещание приватности публичных Actions logs.

| Материал | SHA-256 |
| --- | --- |
| Source fingerprint | `1a46043cbfbecbff71a784c480ab2c2a88cf179091b6ce0e3a41a9f63ddbf4ee` |
| Worker image ID | `3af0c93acaf1036f8dec2358e60b1ca39185f207441a8d50a11ae9628ded36bd` |
| Candidate | `27ab81195a77202a9f483cbde433b476f52db51e0c61adac8d382d2a9479e4cd` |
| Model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Subject | `9bb42fbaba85014575275c8edd5f955e7240236962cae00fa23df13cc9f28f29` |
| Proposal | `e597307b284b8cc33a1e08c15342f9853cfe0ee918e75456239cf95376f7ec3a` |
| Qualification permit | `8d6904a2acd15caef963c3802729fe2cd282ba53947d0242b4b17bafa01dc7b9` |
| Full report | `a8dabb50bfa6c80b55d6772a7f42f94e6d25b5d857d3b2e8633949ade84ec4b7` |
| Independent authorities report | `6f992b43826c68736c27807cd9e36252ac873b9d493fcaa71816615e32c7c13a` |
| Model revocation report | `2e875ecc2a8a7558dc9de2192327947e6b74dcf70775e7055851ee2e0c7bf208` |
| Key revocation report | `af2e75a909eb00d6942149a50592e19d6f2a1fa167f753e6cb28f6b41e430f86` |
| Full CAS/promotion snapshot | `8a587a40974fc2359536db95c6c6ad29c3dce100bd1f46dcf4e8a4cbb519c3de` |

## Предшествующий отказ и ограничения

Run `40933488855` на `3f52fcc` завершился generic runtime refusal до actual matrix. Позднее composition test воспроизвёл недостаточную Secret quota: 3 требуемых объекта при limit 2 в двух reader namespaces. В `bfe295b` limit 3 задан только там, добавлены bootstrap stages. Новый run прошёл. Отсутствующий diagnostic старого run не восстановлен, поэтому его точную причину нельзя объявлять доказанной задним числом.

При локальной сверке нового отчёта найден дефект самого verifier: он ожидал literal cause в поле, которое in-Job check записывает как boolean результата точного сравнения. После сверки с кодом проверяется boolean true, а literal cause отдельно проверяется в каждом final cold Job. Это исправление наблюдателя, не изменение runtime или ослабление acceptance.

Не закрыты: root/key rotation, авторизованный whole-bundle rollback, полная M11/M18-приёмка одного кандидата и остальные CP3-CP5; независимые M22 challenges по-прежнему 0/2, system-image findings сохраняются. U01/U02 из дополнительного внешнего аудита реализованы последующими commits и проверяются отдельно; этот run их не содержит. Windows ACL и общий filesystem U03 не считаются исправленными этим evidence.
