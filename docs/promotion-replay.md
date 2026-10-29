# M11: отказ действующему предыдущему выпуску

Реализация и локальные проверки подготовлены; native проверка ещё не выполнена. Это controlled synthetic integration обычного isolated promotion CLI, не независимая приёмка actual candidate и не разрешённый rollback.

## Что проверяется

После привязки fixture к реальному image harness сохраняет независимую копию подписанного sequence 1 с исходным сроком действия. Затем существующий сценарий сокращает другой approval, проверяет expiry и явно выпускает sequence 2. [Replay probe](../scripts/kube_promotion_replay.py) проверяет первоначальный пакет настоящим verifier с текущим временем, отправляет его через обычный изолированный promoter и требует точную причину `promotion_sequence_conflict`.

Причина соответствует SQLSTATE `P1004` из `ml_promotion.record_selection`, где проверка времени предшествует проверке последовательности. CLI раскрывает только этот фиксированный код; произвольный текст исключения, SQL, credentials и другие причины остаются общим `promotion_rejected`. Generic refusal, expiry, crash или успешный результат не доказывают replay protection.

До stage снимается [совместный snapshot](promotion-snapshot.md). После отказа неизменными должны остаться authorities/events/heads. CAS может сохранить immutable материалы невыбранного запроса, поскольку publication предшествует SQL selection; их наличие не означает активацию. Старый пакет ещё раз проверяется по текущим часам после отказа, затем точный повтор текущего sequence 2 обязан вернуть прежний bundle/request и не изменить полный snapshot. Новое наблюдение trust может отличаться. Обычный serving probe после этого подтверждает inference выбранного sequence 2.

## Ранбук

1. Выполнять только в owned disposable hosted CI, через configured-serving workflow. На текущей Windows разрешены pure/mocked tests, не native SQL/cluster.
2. Проверить stage `unexpired-previous-sequence`, отдельный `unexpired_replay`, времена действительности и обе последовательности. Если первоначальный approval успел истечь, результат неприменим; не выдавать expiry за защиту от rollback.
3. Требовать `promotion_sequence_conflict`, отсутствие receipt старого запроса, неизменный журнал, успешный идемпотентный retry текущего запроса и последующий working serving. Один exit code 1 недостаточен.
4. При различии journal прекратить qualification. Сохранить приватные snapshots, не откатывать SQL head вручную, не очищать events и не убирать подписи или проверки срока.
5. При unknown refusal или worker startup failure устранить конкретную причину. Не перезапускать CI из-за таймаута чтения его статуса; сначала проверить существующий run.
6. Подтвердить удаление принадлежащих прогону Jobs/maps/cluster и остановку source SQL. Только затем публиковать очищенное evidence с source/image/candidate bindings.

Локальные tests: `python -m unittest scripts.kube_promotion_replay_qualification scripts.kube_approval_fixture_qualification scripts.promotion_controller_qualification scripts.kube_promotion_qualification scripts.kube_serving_native_qualification`. 39 methods pass в текущем Windows pure/mocked профиле; helper 25/25 statements, 8/8 branches. Это не доказательство SQL-сценария в native CI. Положительный разрешённый rollback целого bundle относится к M16 и здесь не реализован.
