# M11: отзыв ключа издателя actual candidate

Реализация подготовлена, native проверка ещё требуется. Это проверка actual candidate с отдельным qualification permit, не разрешённый production release и не полный M11. Controlled approval не используется для допуска actual candidate.

## Сценарий и границы

[Hosted harness](../scripts/kube_candidate_native.py) читает настоящий подписанный proposal, проверяет source/model/subject и получает reference predictions в изолированном worker. Сначала исполняется прежняя HTTP матрица actual candidate, затем новый отдельный probe. В новом probe успешные prediction и проверка golden parity должны предшествовать отзыву; старт с уже отозванным ключом не засчитывается.

[Coordinator](../scripts/kube_serving_faults.py) получает SHA256 декодированного публичного ключа издателя из проверенного config. После сигнала `ready` он публикует подписанную следующую trust policy с этим ключом в `revoked_keys`. Model digest при этом не отзывается. Ключ authority, подписывающий trust policy, отличается от отзываемого publisher key.

[Probe](../mlsecops/kube_candidate_trust.py) использует production Engine/HTTP/Worker через qualification Reader. Он требует timestamped отказ в пределах 60 s, отсутствие последующих ML-ответов и auto-reactivation. Новый Reader обязан независимо отвергнуть candidate с точной причиной `trust_key_revoked`; `trust_artifact_revoked`, другая ошибка или успешная загрузка не принимаются. Worker cleanup, неизменный SQL ledger и source bindings проверяются после завершения.

Сценарий запускается после controlled model-revocation: actual и controlled model имеют разные digest, их publisher keys также независимы. Это позволяет проверить оба механизма без отмены уже опубликованного отзыва. Qualification probe не доказывает ротацию production trust root или восстановление на новом ключе: это отдельные незакрытые требования T14.

## Ранбук

Ответственный - оператор disposable hosted lab. [Configured-serving workflow](../.github/workflows/kubernetes-serving.yml) включает actual-candidate key probe; внутри runner команда `python -m scripts.kube_serving_native --state .runtime`. На текущей Windows разрешены только pure/mocked tests.

1. Проверить stage `actual-candidate-HTTP-matrix`, затем `actual-candidate-key-revocation`. Если initial positive отсутствует, отзыв ещё не проверен; сначала исправить причину исходного отказа.
2. Сверить source revision/fingerprint, model/subject и `revoked_key_sha256`. Не выбирать ключ из произвольного вывода или текущего alias.
3. После `ready` проверить подписанный successor trust document. Отзыв монотонный, обратного удаления ключа из revocation set нет.
4. Проверить live HTTP trace и case `cold-reader-key-revocation`. Общий HTTP 503 без точной cold Reader причины недостаточен: возможны worker failure, model revocation или другой сбой.
5. Подтвердить no-auto-reactivation, worker absence, unchanged ledger/source, затем owned SQL stop/cluster cleanup. Не отключать verification и не восстанавливать старую trust policy ради зелёного результата.
6. При отказе сохранить приватные первичные отчёты и finite codes. Безопасное состояние - serving отказан. Новый deployment/ротация требует отдельного подписанного разрешения и повторной проверки; этот сценарий её не выполняет.

Локальная проверка: `python -m unittest scripts.kube_candidate_trust_qualification scripts.kube_serving_faults_qualification scripts.kube_serving_lifecycle_qualification scripts.kube_trust_blackhole_qualification`. Native результат и полная M11-приёмка пока не заявляются.
