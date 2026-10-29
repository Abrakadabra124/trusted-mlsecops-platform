# CPU bootstrap и отказ действующему предыдущему sequence

Неделя 8, T14, CP3. Код `801a9ed8037e451f1877e3cc97d4c241a7985d59`, [CI 40905790753](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40905790753), job `123560040901`: **success**. Native interval UTC: 2026-10-29 15:54:20.864589 - 16:02:39.142417. Checkout в CI чистый; owned source SQL остановлен, disposable cluster удалён и его отсутствие проверено.

Это проверка конкретного increment и сквозного qualification на synthetic-only стенде. Полные M11/CP3/R1 остаются открыты, `release_ready=false`. Controlled signed approvals не являются приёмкой actual candidate.

## Что подтверждено

1. Новый [bootstrap](../operations/runtime-bootstrap.md) прошёл Linux tests настоящих fd2/memfd/RLIMIT_FSIZE, ошибки импорта/настройки/восстановления, overflow и отсутствие утечек descriptors. Свежий реальный ORT import успешен; stderr после initialization снова доступен. В native serving все свежие workers этого run запустились. Это не утверждение, что любые прежние generic failures имели ту же причину.
2. До controlled approval обычный CLI отказал, после approval выполнил ONNX inference. Approval expiry привёл к первому полному HTTP 503 за **0.770330429 s до** срока. Cold Reader отказал, expired retry не изменил совместный CAS + promotion journal snapshot.
3. Явное обновление выбрало sequence **2**. Прежний signed sequence **1** оставался действителен: проверен в epoch `1793289468`, expires `1793291091`, запас **1623 s**. Изолированный promoter отказал точно с `promotion_sequence_conflict`; receipt отсутствует. Authorities/events/heads не изменились. Это отказ по последовательности, а не истечению времени.
4. Точный повтор текущего sequence 2 вернул тот же immutable receipt, включая subject/request/proposal; свежий trust observation допускается. Полный snapshot после retry неизменен. Затем обычный serving CLI выполнил 22 checks и inference выбранного sequence 2; golden error `7.583384781240099e-08`.
5. Controlled trust faults прошли с finite отказом и без автоматического возобновления. Отдельно actual candidate выполнил 60 base + 70 key-revocation typed cases, все pass; golden error **0.0**. После настоящего отзыва ключа первый полный HTTP 503 получен через **4.288907611 s**, cold Reader отказал точно по `trust_key_revoked`; worker absence и неизменность полного journal подтверждены.
6. Actual production promotion продолжает корректно отказывать с `release_assurance_required`. Qualification permit не создаёт отсутствующую assurance и не разрешает выпуск.

| Controlled fault | Первый полный 503, s | HTTP observations |
| --- | ---: | ---: |
| Authority outage | 59.806216413 | 44 |
| TCP blackhole | 13.352852689 | 36 |
| Policy change | 5.087142518 | 2 |
| Model revocation | 4.881535941 | 2 |

Отсчёт - от начала последнего успешного HTTP запроса, консервативной нижней границы последнего trust read. Это не выдуманный точный timestamp SQL SELECT. Blackhole подтверждён TCP timeout, затем восстановлением соединения; outage сохраняет owned PVC. Оба сценария наблюдали отказ и после 60 s. Полные primary traces находятся в приватном отчёте, raw logs/внутренние пути не публикуются.

## Tests и bindings

Linux выполнил **243 method executions**: 143 + 31 + 22 + 5 + 14 + 28, без skips. Это сумма запусков групп, не число уникальных методов. Новый bootstrap: **41/41 statements, 12/12 branches**; replay/promotion boundary: **230/230 statements, 72/72 branches**; joint snapshot/trust faults: **232/232 statements, 92/92 branches**; expiry: **50/50 statements, 12/12 branches**. Attach/runtime scope остаётся 99%: 257/258 statements, 91/92 branches.

До публикации независимо пересчитан source fingerprint из **134 Git blobs**, включая новый runtime module. Обе копии итогового JSON в log совпадают, typed case values и типы совпадают с expected. Hash отдельного key report совпадает с artifact_hashes. Проверены model/subject/source/image bindings и cleanup steps. Hash полного отчёта ниже относится к canonical JSON + LF.

| Поле | Значение |
| --- | --- |
| Source fingerprint | `55df63a084feccbd68041d90e38c4e799958b714dc97461644129d097c672599` |
| Image | `sha256:a5388bf2673461cedecb81eb26f7ab2edc40ca96a5c47aeac4c4a20caf597ef7` |
| Full report SHA256 | `d614849b2b152a260b63ca460b9872844c3954592f5fdd8bf25165edfc498c7c` |
| Unchanged replay journal SHA256 | `0b44e038b68593a76d53bc73db146da9a4e1278a2b1354bfcc5204b2fd9051f9` |
| Unchanged current retry full snapshot SHA256 | `d12c8a0ed5c9c5b86a9ff0bd10fd84b62121ede3c03fe820b791e8fdcbbc66e4` |
| Actual candidate | `3fa4082dc0c8729bec98628abb2e7d820aeb6a9e1b681b52342d6884069aaec1` |
| Actual proposal | `468f7ff20467571a70ccb041014caa316132aaba6a55e3ed2d7131dd0a2f1599` |
| Actual model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Actual subject | `f3c7a9a5b944eb8729e3f34244ec3491d2a3da6851da152903b777d341e9987b` |

## Что осталось

Actual-candidate binding остальных M11 scenarios, negative clock/cache cases, root/key rotation и разрешённый whole-bundle rollback остаются обязательными. Необратимый model/key revoke нельзя отменять для удобства следующего теста. Independent M22 challenges всё ещё 0/2; system-image findings и CP3-CP5 не закрыты. См. [M11](../acceptance.md#m11), [replay runbook](../promotion-replay.md), [общий план R1](../r1-delivery.md).
