# M11: свежая приёмка trust lifecycle

Дата: 2026-11-06. Неделя 8 «Bundle, approval и отзыв доверия», T14 «Trust lifecycle», CP3/R1-B04. Свежая M11 campaign принята в synthetic local-CPU scope. Общий R1 не завершён.

## Результат и границы

[CI 42202109996](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42202109996), [job 127839656588](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/42202109996/job/127839656588), source `21317fd60495b49a3f78d2458a64dce9b03085a2`: **success**, 10:22:02-10:44:07 UTC. M11: **141 cases pass**, включая 120 controlled contracts и 21 aggregate criterion; 0 skips. Все workflow steps завершились успешно.

M11 проверяет механизм отказа при потере доверия. Настоящий candidate обучен и подготовлен в этой кампании; его qualification permit предназначен только для изолированной проверки. Положительные approval, rollback и смена release signer используют отдельно обозначенные controlled releases. Они не создают независимый M22 report и не разрешают production promotion. Actual promotion по-прежнему получает `release_assurance_required`, все receipts сохраняют `release_ready=false`.

Это новая кампания, а не объединение старых зелёных reports. [Runner](../../mlsecops/trust_acceptance.py) готовит proposal до начала checks, запускает текущий controlled inventory и native producers, затем проверяет неизменность исходников, методов и входов. [Reconciler](../../mlsecops/trust_gate.py) проверяет связи candidate/model/subject/source/image, полноту результатов и независимость authorities. [Trace validator](../../mlsecops/trust_trace.py) пересчитывает времена из HTTP observations.

## Что проверено

1. Настоящий candidate даёт ожидаемые ONNX predictions. Неверные подписи, изменённые и malformed model bytes не дают готовый worker.
2. Outage и blackhole прекращают ML-ответы не позднее 60 s после контрольного trust read. Trace продолжается за эту границу; после первого 503 новый 200 запрещён. Изменение policy и отдельные отзывы model/key также блокируют serving.
3. Пять fault injections проверяют wall/monotonic clock rollback, wall jump, server skew и неверную подпись. Cache и Reader очищаются; прежний Engine не активируется автоматически после восстановления зависимостей. Это подмена зависимостей в тесте, а не изменение часов ОС.
4. Действующий старый trust document отвергается как version replay. Истечение подписанного approval проверено в живом HTTP до и после срока; expired promotion retry не меняет storage. Старый ещё действующий release sequence получает точную причину отказа.
5. Разрешённый whole-bundle rollback A -> B -> A сохраняет исходные subject/proposal/model, создаёт новый sequence и допускает идемпотентный retry. Три неверные history links и revoked target отклоняются без скрытого fallback.
6. Смена trust root сохраняет signed permit, историю и прежние revocations. Отдельные model/key authorities имеют разные CA/storage; изменение одной не меняет другую. Новая activation явная.
7. Publisher, assessor и approver меняются по очереди через подписанную policy и настоящий SQL ledger. Старые HTTP экземпляры остаются fenced, новый выпуск без M22 отказан без записи, новая конфигурация восстанавливает прежние golden predictions.

| Сценарий | Первый завершённый HTTP 503 |
| --- | --- |
| Actual candidate: blackhole | 13.445524737 s |
| Actual candidate: key revocation | 4.568226116 s |
| Actual candidate: model revocation | 4.961443480 s |
| Actual candidate: outage | 59.871216281 s |
| Actual candidate: policy change | 4.170101386 s |
| Actual candidate: root rotation | 4.279362463 s |
| Controlled: blackhole | 12.860866283 s |
| Controlled: outage | 59.779359954 s |
| Controlled: policy change | 4.390940929 s |
| Controlled: model revocation | 4.685970677 s |
| Signer: approver | 0.547933532 s |
| Signer: assessor | 0.500069859 s |
| Signer: publisher | 0.546508692 s |

Первый отказ по подписанному approval завершился за **0.961759329 s до expiry**; после expiry отказ сохранялся. Actual golden error до и после root recovery: **0.0**.

Для каждого fault требуются минимум два отказа и отсутствие последующего успеха. Начало измерения перед контрольным успешным запросом задаёт консервативную нижнюю границу последнего trust read. Signed approval expiry имеет отдельную шкалу относительно срока подписи.

## Проверки и очистка

В Linux job пройдено **656 top-level method executions в 17 группах, 0 skips**. Некоторые группы повторно запускают общие regression methods; это не 656 уникальных независимых сценариев. Четыре новых модуля M11: 346 statements / 74 branches, 100% покрытия каждого. 120 controlled contracts также выполняются внутри fresh acceptance; вложенные вызовы не суммируются с top-level методами.

Отдельная локальная сверка прочитала primary JSON и восстановила fingerprints из immutable Git blobs: 147 source blobs, 394 method/material blobs. Отдельно пересчитаны HTTP traces, сохранение root history и permit, A -> B -> A history, idempotent retry и exact denial reasons.

Повторены **37 SQL rotation**, **68 live signer** и **36 recovery cases**. Restore storage: 4.725856 s, до 1 000 golden predictions: 6.815035 s, maximum error 0.0.

В том же job полный backup после policy rotations восстановлен в независимом target при выключенном source. Эта проверка дополняет M11, но не заменяет полный M17 с новой namespace/storage, RPO и всеми отказами.

Подтверждены удаление всех созданных worker Jobs/Pods, шести signer workers и собственных SQL targets/networks/volumes. Source SQL остановлен с проверкой `Running=false`; собственный Kubernetes cluster удалён с проверкой отсутствия. Исходные model/promotion snapshots и source checkout сохранялись там, где сценарий требовал неизменности.

| Привязка | SHA-256 / reference |
| --- | --- |
| Source fingerprint | `4ab995c4a538ebd6bdf3407e152c8ea9aa12b1cadb5c35cba98383dc1cde6693` |
| Worker image | `sha256:0c575995c62f748c85bd9f7b1c0d9aac5670d73659321df72786236ef753eec5` |
| Actual candidate | `01beeabc910fba08cb9d7b8982d755dd2e874270f7ffe55075cfd286e9d1c56c` |
| Actual model | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Report M11 | `b8ee2c023e112f07eab6c5ed0d9b7ea221b311a95aa5d0a45780e4b925aea0e5` |
| Report native | `f54778cf388feaba31b3b62ec454873fc6db9627d1ab8d62dfb5880c14a7b170` |
| Report promotion-recovery | `bf9e7874ee3fa6812fe5c07bbbf7cb5110d795e4d633bb9013aadd4d1ba160f4` |
| Report release-key-native | `6e0e07bbfd204ca918747484aa80e588f66e46939bfe25d4469388a13658fdd4` |
| Report release-key-serving | `3388251b06e2a4f94cc76fd31f74fec539ad13626102f1edf288568012642cb9` |

Raw logs, ключи, credentials и private primary packets не публикуются. Hashes связывают этот отчёт с наблюдавшимся synthetic стендом; они не доказывают bit-for-bit воспроизводимость image build на другой системе.

## Воспроизведение

Чистый checkout проверенного source:

```powershell
git clone https://github.com/Abrakadabra124/trusted-mlsecops-platform.git mlsecops-M11
Set-Location mlsecops-M11
git checkout 21317fd60495b49a3f78d2458a64dce9b03085a2
$env:PYTHONUTF8='1'
uv sync --locked --no-build --python 3.12.15
uv run --locked python -m unittest scripts.trust_trace_qualification scripts.trust_gate_qualification scripts.trust_acceptance_qualification scripts.inference_gate_qualification scripts.source_lock_qualification
git status --porcelain
```

Локальный прогон выполняет pure/mocked CPU checks без Docker/WSL/Kubernetes/SQL. В проверенном Windows checkout зависимости уже были установлены отдельно: Python 3.12.15, 64 locked packages, dependency files совпадали; импорт модулей шёл из этого checkout. 26 top-level methods, 0 skips, 13.945 s; дерево чистое до и после. Вложенный inventory содержит 120 controlled methods и не прибавляется второй раз к числу независимых top-level проверок.

Для native воспроизведения использовать [kubernetes-serving workflow](../../.github/workflows/kubernetes-serving.yml) на собственном disposable GitHub-hosted runner. Внутренний entrypoint: `uv run --locked python -m mlsecops.acceptance --gate M11 --state .runtime --output .runtime/evidence/M11.json`. Prerequisites, diagnosis, отказ и cleanup описаны в [ранбуке](../operations/trust-acceptance.md). Не запускать этот стенд на запрещённых локальных Docker/WSL/Kubernetes/SQL.

## Оставшаяся работа

M18 и R1 не приняты. Нужны independent M22 (сейчас 0/2), устранение image findings и полное coverage, M13 channels/privacy/audit, load/monitoring/staged rollout/restore и остальные обязательные gates на одном frozen candidate. T14 mechanism evidence не закрывает всю CP3 delivery chain и зависимость T13/M10. Следующий обязательный шаг - M13 в Kubernetes; новые исследования и необязательные усиления не входят в этот increment.
