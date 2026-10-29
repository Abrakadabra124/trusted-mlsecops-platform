# Разрешённый откат целого bundle с новым sequence

Статус: **local contracts и native rollback проверены**, conclusion success. Source commit `f2f102c1ce51094ed83c4fd5cee8c067baaf3ffe`, [run 40952320387](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40952320387), job `123723355422`. Запуск начат 29 октября, проверка завершена 30 октября 2026 МСК. Это компонент T14 и подготовка T19, не приёмка полного M11/M16/R1.

## Что изменено

Возврат к прежнему разрешённому bundle теперь требует отдельного подписанного approval schema 2. Оно связывает точный текущий selection, исторический target и новый sequence. Обычный approval schema 1 сохраняет прежние требования. Model, preprocessing, capsule и исходный signed bundle остаются неизменными; меняются approval и selection.

[release_rollback.py](../../mlsecops/release_rollback.py) сверяет intent с неизменяемыми событиями SQL, загружает target selection по SHA-256 и проверяет environment/policy/subject/proposal. Проверка выполняется до публикации, после commit и при загрузке serving Reader. Существующий SQL compare-and-set под блокировкой строки сериализует изменение head. Поэтому возврат A -> B -> A использует sequence 1 -> 2 -> 3, а повтор старого sequence не становится допустимым откатом.

Target проверяется по действующим policy/root/runtime pins и всем прежним gates, assurance и срокам. Отзыв модели или target selection запрещает откат. Approval не продлевает старую assurance и не отменяет revocations. Context целевой модели передаётся оператором отдельно от недоверенного request. Конфликтующий request не превращается в автоматический выбор другого target.

Решение и границы: [ADR 0052](../decisions/0052-explicit-bundle-rollback.md). Эксплуатационная последовательность, диагностика и fallback: [ранбук](../operations/bundle-rollback.md).

## Локальная проверка

До реализации новые тесты воспроизвели отсутствие rollback schema; после добавления schema выявили отсутствие проверки истории. Итоговая целевая группа прошла **76 test methods**. Дополнительная regression group прошла 29 methods. Это controlled Python tests, без локального запуска Docker, SQL или Kubernetes.

| Модуль | Statements | Branches | Покрытие statements / branches |
| --- | ---: | ---: | --- |
| `mlsecops/promotion.py` | 75 | 24 | 100% / 100% |
| `mlsecops/release_authorization.py` | 76 | 42 | 100% / 100% |
| `mlsecops/release_reader.py` | 138 | 40 | 100% / 100% |
| `mlsecops/release_rollback.py` | 37 | 16 | 100% / 100% |
| `scripts/kube_rollback_native.py` | 55 | 12 | 100% / 100% |

Всего 381 statement и 134 branches. Coverage не заменяет проверку требований: тесты отдельно проверяют чужую подпись, missing assurance/reports, expiry, неверные типы и sequence, неизвестные from/target, подмену bytes и binding target, changed head, unavailable history, revoked target/model, idempotent retry и Reader previous link. Публичная диагностика истории ограничена тремя постоянными кодами; произвольный error text не принимается.

## Подтверждённый native результат

Контрольные модели A и B обучаются на разных синтетических наборах, имеют разные ONNX bytes и предсказания. Обе проходят обычный isolated promoter и обычный serving CLI с отдельным worker. Затем новый approval возвращает прежние subject/proposal/model A без перепаковки bundle. Это проверка настоящего runtime и SQL с явно контрольными approvals.

Native coordinator проверяет три подписанных отказа: неизвестный from request, неизвестный target request и другой request с уже занятым sequence. Snapshot берётся после подготовки входных signed CAS objects, до вызова production promoter. Отказ и точный retry должны сохранить полный CAS/promotion snapshot. Успешный откат должен добавить одно событие и новый head, сохранив authorities, migration и остальные CAS tables. После отзыва target повтор должен отказать.

**459 Linux test method executions, 0 skips**, включая 76 methods целевой группы; пять модулей из таблицы выше снова дали 100% statements и branches. Число executions включает повторный вызов некоторых test methods в разных группах, это не число независимых сценариев.

Native report: `2026-10-29 20:52:21.082373` - `21:09:10.892056 UTC`. Получен точный переход **1 -> 2 -> 3 / A -> B -> A**:

| Serving stage | ONNX SHA-256 | Checks | Max golden error |
| --- | --- | ---: | ---: |
| A, sequence 1 | `6e4e5e65497470e5fe72af895107f291245c1bfc70070378cf3cdf95d2058169` | 22 | 7.583387712228884e-08 |
| B, sequence 2 | `ec34400c5ff6bd98682408aa3adf809b3788fa1dfdc563b8a4c307d7b827ccf8` | 22 | 1.327432095354908e-07 |
| Восстановленная A, sequence 3 | `6e4e5e65497470e5fe72af895107f291245c1bfc70070378cf3cdf95d2058169` | 22 | 7.583387712228884e-08 |

Обычный CLI probe сохраняет ordered labels успешных проверок. Его `check()` выполняет явный отказ до добавления label; сверена точная последовательность всех 22 labels, включая три проверки model/bundle digest в HTTP-ответах. Это другой формат, чем typed expected/actual cases actual-candidate probe ниже; они не смешиваются в один счётчик.

Target и rollback имеют одинаковые subject `22123b981307c581b6b7ce4a667609f3313e7c8c16234646f8cc1f819bce1880` и proposal `c9d9b66dccacaa9e402cff65912696ef289716b512b58b119ca49e47dfdfc9f6`. Selection изменился с `adbaf7187d1baeacf879c83503eb5a87d51e7c3aacf49c77e629d94665bdcf33` на `b2b914d6adbf7b9b132df21203a505f91ef66345e6026ef591aee9feb88572f3`. Между ними был другой subject/model B с request `5b7ae650620157e72a8879efea1afa2b9db85600e03bde14cd67af639607d5b0`. Это возврат точного старого bundle, а не просто ещё один положительный load той же модели.

| Native отрицательная проверка | Подтверждённый отказ |
| --- | --- |
| Подписанный неверный from request | `rollback_from_history` |
| Подписанный неизвестный target request | `rollback_target_history` |
| Другой signed request с уже занятым sequence 3 | `rollback_head_changed` |
| Повтор rollback после отзыва target | `rejected`, без receipt/activation |

Для трёх history refusals подтверждено точное совпадение полного snapshot до/после вызова promoter. Успешный откат увеличил events с 2 до 3, число heads осталось 1, добавлены ровно 2 release objects: authorization и selection. Migration, authorities и non-release CAS tables не изменились. Точный retry вернул то же решение без новой записи; свежая trust observation не считается частью идентичности receipt. Последующий revoked retry также сохранил полный snapshot.

Actual candidate отдельно прошёл qualification/trust regression: **834 typed assertions с повторами**, base 193, outage 174, blackhole 182, policy/replay 131, model revoke 78, key revoke 70, два final cold Jobs 6. Max golden error 0.0. Пять clock/signature faults дали 25 HTTP 503; still-valid signed v5 после v7 отказан точно по `trust_version_replay`, остаток срока 3350.099752665 s. Model/key authority используют разные CA/PVC/history; peer state не изменился, версии primary 7/7/8 и model authority 1/2/2. Финальные cold причины точны, workers отсутствуют.

| Actual-candidate fault | Первый полный HTTP 503 |
| --- | ---: |
| Model revocation | 6.085654688 s |
| Key revocation | 5.497843742 s |
| Trust outage | 59.792812481 s |
| TCP blackhole | 13.256226056 s |
| Policy change | 6.185400769 s |

Полный CAS/promotion snapshot actual candidate одинаков до и после faults. Его production promotion остался отказан по `release_assurance_required`; `release_ready=false`, `full_M12=inconclusive`. Контрольный rollback не выдаёт ему разрешение.

Source fingerprint пересчитан по **140 Git blobs**; два экземпляра полного native report совпали. Шаги `Stop verified owned source SQL` и `Remove verified owned disposable cluster` завершились success с проверкой конечного состояния, job завершён `2026-10-29T21:09:18Z`.

| Привязка | SHA-256 |
| --- | --- |
| Source fingerprint | `a6d67742aec954cc4ebf5ea4dba15f255eaedd0b412f1be2a9cf8eaac3fd5558` |
| Worker image | `36c318241599110add0881542006dfe251844d922a79f8240fade33f9b17e940` |
| Full native report, canonical JSON + LF | `8e265e112490257623563134b9d786e2e4d6c2f33e623e651cc980bf4a9e09da` |
| Rollback subsection, canonical JSON + LF | `2e402b906159af49925968fd7579ab27ef2d2df09ec3da977ee556ba9c6e1475` |
| Independent-authority pair report | `e6eb69a376217aa7611fd7371a2d664723892d2f6ddb0cd38a980d5dadd5b485` |
| Actual full CAS/promotion snapshot | `307ce2536e34fba36c3d93473e44ad4dcd9ddcea2efa1eef8399a5cf795247d4` |
| Actual candidate | `b6dad2d9a22d0649625a45a6fcfea3ef6201832518e4ed8599a44fd4c5782107` |
| Actual model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Actual subject | `11464ba9d85f5f1388987b4017be1633d7551fe482d79f58568537f9314be4a2` |
| Actual proposal | `9dead32759bb697169977c9f957a908f776b0973004bea960b2cdbb67407284a` |

## Повторение из чистого checkout

Локальная часть использует только Python и синтетические CPU fixtures:

```powershell
git clone https://github.com/Abrakadabra124/trusted-mlsecops-platform.git trusted-mlsecops-rollback
git -C trusted-mlsecops-rollback checkout --detach f2f102c1ce51094ed83c4fd5cee8c067baaf3ffe
Set-Location trusted-mlsecops-rollback
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.rollback_authorization_qualification scripts.rollback_admission_qualification scripts.kube_rollback_qualification scripts.kube_approval_fixture_qualification
```

Полная preflight group и native последовательность закреплены в [kubernetes-serving.yml](../../.github/workflows/kubernetes-serving.yml) этого commit. Native повтор выполняется только на разрешённом disposable GitHub-hosted runner через этот workflow на branch/tag, указывающем на проверяемый commit. Перед сравнением фиксируются фактический head SHA, runtime source fingerprint, image ID и новые report hashes. Новый run создаёт новые synthetic identities и timestamps, поэтому равенство всех report bytes между разными запусками не требуется. Требуются те же contracts, правильные bindings внутри каждого run и подтверждённый cleanup.

## Остаточные ограничения

- Полные M11/M16/R1 остаются открытыми. Staged traffic 10% -> 50% -> 100%, минимум 100 наблюдений на стадии, latency/error gates и rollback <=120 s этим increment не принимаются.
- Ротация root/key требует отдельной реализации и проверки. Сброс trust state, journal или minimum sequence не является ротацией или rollback.
- Trusted SQL admin и filesystem administrator вне adversary scope. Проверка history не защищает от администратора, который заменил всё хранилище.
- Между trust service и model storage нет распределённой транзакции. Неизвестный commit требует readback. Конкурентный проигравший request может оставить immutable unselected objects, но не получить activation.
- Основной внешний `security-review.ru.md` не предоставлен; independent M22 challenges остаются 0/2. Исправления supplemental U01-U03 не подменяют эти требования.
- В CI используются синтетические данные и test identities. Локальные raw reports, внешний архив и private diagnostics не коммитятся. GitHub Actions logs публичны.
