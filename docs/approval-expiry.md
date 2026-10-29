# M11: истечение approval и явное восстановление

Реализован hosted сценарий, native результат ещё не подтверждён. Это controlled release, отдельно от actual candidate, которому по-прежнему требуется полная assurance. Production verifier, часы и пороги не меняются.

## Последовательность

1. [Fixture helper](../scripts/kube_approval_fixture.py) подписывает approval с реальным сроком `now + 90 s`. Его descriptor, policy и assurance остаются действующими дольше, чтобы отказ можно было связать именно с approval.
2. Обычный isolated promotion CLI записывает sequence 1; serving CLI подтверждает model/bundle binding и ONNX golden parity. Второй обычный serving process наблюдается до и после подписанного expiry.
3. [HTTP observer](../mlsecops/kube_serving_expiry.py) сохраняет wall/monotonic trace. Нужны 200 до expiry, первый полный 503 не позже expiry и не ранее чем за 2 s, затем минимум два отказа и запрос после expiry + 1 s. Ранний посторонний outage, скачок часов, поздний ML-ответ, пропущенная граница или реактивация не дают pass. Двухсекундная нижняя граница учитывает существующие ceil(wall)/SQL clock semantics; срок самого approval не продлевается.
4. Новый холодный serving process должен дать 503 до worker и подтвердить Reader refusal `release_expired_or_future_document`. Повтор того же promotion request должен быть отвергнут без изменения ledger.
5. Явное восстановление выпускает новый descriptor/release_id с sequence 2, заново связывает и подписывает controlled reports/assurance/approval. Candidate и evaluation context сохраняются. Новый promotion receipt и обычный CLI подтверждают новый subject; ledger не очищается и не откатывается.
6. Outage, blackhole, policy-change и model-revocation затем проверяются уже на sequence 2. Итоговый source/ledger readback и owned cleanup обязательны.

## Исправленная проблема fixture

Failure-first test выявил, что повторный вызов полного `bind_real_runtime` менял evaluation reference. Это сделало бы прежнюю serving configuration несовместимой с новым release. Выделен `bind_release`: повторно подписываются материалы release, существующий candidate не пересоздаётся. Тест проверяет неизменность context, разные subject, корректную подпись и sequence 2, отказ старого approval в момент expiry. Это исправление тестового orchestration, не production verifier.

## Ранбук и проверочный плейбук

Ответственный - оператор disposable hosted lab. Prerequisites: исходный код зафиксирован, GitHub-hosted runner, pinned tools/images, действующие trust authority и контролируемые lab signing keys. На текущей Windows инфраструктуру не запускать.

1. Запустить [configured serving workflow](../.github/workflows/kubernetes-serving.yml). Внутри runner используется `python -m scripts.kube_serving_native --state .runtime`. Не перезапускать живой job.
2. При `signed-approval-expiry` проверить native outcome и finite failure code. Нет положительного запуска - сценарий expiry не выполнен; сначала диагностировать startup по [serving runbook](kubernetes-serving.md#runbook-503-или-незавершённая-очистка).
3. `approval-expiry-window` означает истёкшее или слишком далёкое окно до наблюдения; подготовить новый подписанный тестовый release при следующем отдельном запуске, не подменять часы и не править существующие записи SQL.
4. `approval-expiry-no-late-ML` или `approval-expiry-first-denial` означает неприемлемое поведение/timing. Сохранить исходный приватный trace и bindings; новый approval не маскирует этот failure.
5. Проверить cold refusal, отказ expired retry и неизменный ledger. Только затем переходить к explicit renewal. Повторно использовать просроченное разрешение или сбрасывать sequence нельзя.
6. `explicit-release-renewal` требует receipt sequence 2, новый subject и положительный обычный CLI. Не считать один успешный promotion доказательством работающего inference.
7. Проверить завершение owned SQL stop/cluster cleanup. При неподтверждённом ownership остановить destructive cleanup и сохранить блокер; global prune запрещён. В случае ошибки безопасный rollback - сохранить отказ serving, не возвращать старое истёкшее разрешение.

Локальные pure/mocked tests: `python -m unittest scripts.kube_serving_expiry_qualification scripts.kube_approval_fixture_qualification scripts.kube_serving_native_qualification`. Новые observer/helper проверены на 50/50 statements и 12/12 branches. Они не заменяют native результат, candidate-bound M11 report или R1 acceptance. Intermittent worker startup stderr остаётся отдельной открытой проблемой.
