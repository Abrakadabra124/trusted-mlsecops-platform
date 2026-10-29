# Actual candidate: отзыв ключа издателя

[Hosted run 40826185111](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40826185111), job `123289642538`, success на source `71a77b0aba5f0d004c23f3145c905e9489697bef`. Статус run и обоих cleanup steps повторно проверен после возобновления работы. Это qualification actual candidate через production Engine/HTTP/isolated Worker, **не разрешённый production release и не полный M11/CP3/R1**.

## Привязка результата

- Source fingerprint `023514f5b3226d1460b08e6a3c6e8fb59f35e6135b14c29913240d3fc78070ad`, ранее независимо пересчитан по 133 Git blobs проверяемого commit.
- Image `sha256:3671ea6b6b07a9c95485476146236137296ee87005ef3d7f8d32dd8f1a0e41a7`.
- UTC interval `2026-10-29T05:58:46.246223+00:00` - `2026-10-29T06:07:09.289628+00:00`.
- Actual candidate `8f036e44f90cbaf08fd9d8e0eaf4ca20a34914313c1e56ff0cf95c2b4b980196`, proposal `4d5b32e05753a452ad9de67af37c923ad147e11723139019ec66a229de866ee4`.
- Model `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`, subject `6c4177919914b411f9a65fe2e25f4844e5ad482b6407da809a7793e95f48208a`.
- Отозванный publisher key SHA256 `b4d6f3c8e92939ca367ef122707c1a66234bb768915ffcd8444b46cd24feee7a`.
- Canonical full report + LF SHA256 `bddf15047179324cee8526fd90a608f246f125d8b966972616b2c3cffc9b1766`.
- Canonical key report + LF SHA256 `d48a1105361ec6792d1e255bf646ee5bbad8ffd582938e95ab623b12762f196b`, совпадает с `artifact_hashes["key-revocation.json"]`. Оба report hashes повторно пересчитаны из сохранённых первичных материалов; raw logs и reports остаются приватными.

## Что проверено

176 Linux test methods (122 + 29 + 20 + 5), без skips. Fault/key-helper scope: 224/224 statements, 92/92 branches; expiry: 50/50 и 12/12; attach/runtime: 253/254 и 87/88. Это покрытие перечисленных модулей, не всего проекта.

Actual candidate прошёл базовую HTTP матрицу из 60 cases и отдельный key probe из 70 typed cases. Все cases имеют `status=pass`, фактические значения совпадают с ожидаемыми. До отзыва получен успешный inference, golden error 0.0. После публикации подписанного successor trust document первый полностью полученный HTTP 503 наступил через **5.290494312 s** от начала успешного запроса перед инъекцией. Это консервативная нижняя граница времени последнего trust read, не точное время коммита отзыва.

| Начало запроса, s | Ответ полностью получен, s | HTTP |
| ---: | ---: | ---: |
| 5.246985901 | 5.290494312 | 503 |
| 7.290618307 | 7.292192861 | 503 |

Новый Reader независимо отверг загрузку именно с `trust_key_revoked`: другая причина отказа тест не удовлетворяет. Подтверждены отсутствие auto-reactivation и конечное отсутствие worker. Model digest при этом не отозван. Controlled model `6e4e5e65497470e5fe72af895107f291245c1bfc70070378cf3cdf95d2058169` отличается от actual model; прежний controlled model-revocation не объясняет этот отказ.

В том же run повторены signed expiry, cold expiry refusal, renewal sequence 2 и четыре trust faults. Owned source SQL stop и disposable cluster removal завершены успешно. Production promotion actual candidate сохранил отказ `release_assurance_required`; `release_ready=false`.

## Границы доказательства

Сверка `ledger` в этом commit охватывает CAS inventory таблиц `ml.*`. Она **не экспортирует отдельный snapshot** `ml_promotion.authorities/events/heads`. Нельзя считать прежнюю фразу «ledger unchanged» доказательством этой дополнительной сверки. Snapshot журнала проверяется следующим increment; исторические результаты здесь не расширяются задним числом.

Root/key rotation, допустимость rollback, stale policy/replay/negative clock и общий candidate-bound M11 report ещё требуют завершения. Intermittent worker startup stderr в этом run не воспроизведён, причина не установлена. M22 independent challenges 0/2 и system-image findings продолжают блокировать общую приёмку.

[Реализация и ранбук](../candidate-key-revocation.md)
