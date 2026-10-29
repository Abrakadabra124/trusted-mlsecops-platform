# M11 component: serving при сетевом blackhole

Native [40823156897](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40823156897), job `123280017423`, завершён success. Source `b5a933e360251e2285ba2528c071abd0fc31834e`. Это controlled synthetic integration, **не полный M11, CP3 или R1**; `release_ready=false`.

## Привязка результата

- Source fingerprint: `5c1782ae85112ee26dffd0b2cfca7522f480ecb9d8a65329171af1a73146d730`, независимо пересчитан по 131 Git blob проверенного commit, без Windows CRLF.
- Image: `sha256:af8a429ce7691f6f7fef39cd73bbd25dc13bf2ca7486ba554c35a852db745e7e`.
- UTC interval: `2026-10-29T05:26:19.010635+00:00` - `2026-10-29T05:31:07.295945+00:00`.
- SHA256 приватного canonical native report с завершающим LF: `8c2518cb956705543227aeaaa205befc0234038db4263aecddec61c375a03599`. Две напечатанные workflow копии совпадают. Raw logs не публикуются.
- Actual candidate `0562326ba4f00f5cc5d0838a03e7a89faecada0a0bdca05c363bcf9b416eb021`, proposal `7e0eb08bbacb51b5174fcdefff6e2f74eb7eb8088607c0276447138291d42357`, model `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46`: отказ `release_assurance_required`, ledger не изменён.
- Ordinary CLI positive и fault probes используют отдельно обозначенный controlled release с model `6e4e5e65497470e5fe72af895107f291245c1bfc70070378cf3cdf95d2058169`. Этот approval не разрешает actual candidate.

## Исполнение и проверка

145 Linux test methods (99 + 29 + 17) pass без skips. Attach/runtime: 253/254 statements, 87/88 branches; lifecycle/coordinator/blackhole: 208/208 statements и 88/88 branches. Native сценарии выполнили 400 assertions с повторениями, это не 400 независимых критериев приёмки.

| Сценарий | Assertions | Первый полностью полученный 503, s | HTTP observations |
| --- | ---: | ---: | ---: |
| До approval | 13 | Не измеряется | Отказ до worker |
| После controlled approval | 22 | Не измеряется | Golden parity и stopped-worker отказ |
| SQL outage | 137 | 59.770946722 | 37: 31 ответ 200, 6 ответов 503 |
| Сетевой blackhole | 151 | 13.149598977 | 41: все 503 |
| Смена policy | 32 | 3.784528250 | 2: оба 503 |
| Отзыв модели | 32 | 4.671830954 | 2: оба 503 |
| Холодный запуск после отзыва | 13 | Не измеряется | Отказ до worker |

Для всех четырёх fault probes сначала подтверждены успешные предсказания через обычный HTTP CLI, ONNX parity с ошибкой `7.583384781240099e-08`, model/bundle binding и один persistent worker. Отсчёт ниже начинается от начала последнего успешного HTTP запроса перед injection. Это консервативная нижняя граница успешного trust read, а не выдуманное точное время внутреннего чтения.

Blackhole применён временной CiliumNetworkPolicy только к трафику serving identity в `ml-trust`. TCP connect timeout подтверждён отдельно от HTTP отказа; connection refused не принимается как эквивалент. После удаления exact owned policy с UID precondition подтверждены её отсутствие, прежние PostgreSQL Pod/PVC UID и восстановленный TCP connect. Ready/predict остались 503: автоматической реактивации остановленного поколения нет.

Независимая проверка отчёта подтвердила отсутствие 200 после первого 503, отсутствие ML-ответов после исходной 60 s границы и наличие отказов после 60 s для outage/blackhole. Source/ledger не изменились. Финальные шаги остановки owned source SQL и удаления owned cluster завершились success. Локальная Windows инфраструктура не запускалась.

## Неустранённая ошибка запуска

Предыдущие `4d97e0d` / [40821440191](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40821440191) и `78a6d62` / [40822103126](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40822103126) отказали до injection: `worker-start / load / serving_attach_stderr`, Reader verified, cleanup success. В диагностике исправлен доказанный тестом дефект классификации fragmented stderr: ограниченный сбор до 4096 bytes, 8 дополнительных кадров и 0.5 s внутри исходного exchange deadline. Любой stderr по-прежнему вызывает отказ; содержимое не выводится.

Успех `b5a933e` не воспроизвёл runtime stderr и **не доказывает исправление его причины**. Гипотезы о device-discovery warning или пустом stderr не подтверждены native. Полные M11 expiry/key/replay/rollback/clock checks, общий candidate-bound report, M13 и CP3-CP5 остаются обязательными. Значение 13.15 s в одном blackhole опыте не является latency SLO.

[Реализация и ранбук](../trust-blackhole.md)

## HTTP trace

В таблице приведены только времена и статусы, без request identifiers, features, predictions или credentials.

| Fault | Request start, s | Response complete, s | HTTP |
| --- | ---: | ---: | ---: |
| outage | 1.045850798 | 2.126187747 | 200 |
| outage | 4.126307966 | 4.164671465 | 200 |
| outage | 6.164777714 | 6.202350193 | 200 |
| outage | 8.202468731 | 8.268820954 | 200 |
| outage | 10.268889384 | 10.313388281 | 200 |
| outage | 12.313505501 | 12.357110343 | 200 |
| outage | 14.357177092 | 14.396990650 | 200 |
| outage | 16.397106682 | 16.444294588 | 200 |
| outage | 18.444402876 | 18.512071041 | 200 |
| outage | 20.512177541 | 20.569638572 | 200 |
| outage | 22.569760449 | 22.617285186 | 200 |
| outage | 24.617399951 | 24.655443483 | 200 |
| outage | 26.655549760 | 26.699112139 | 200 |
| outage | 28.699219401 | 28.755261610 | 200 |
| outage | 30.755367735 | 30.828554264 | 200 |
| outage | 32.828659019 | 32.867528628 | 200 |
| outage | 34.867634488 | 34.910954446 | 200 |
| outage | 36.911066404 | 36.954895187 | 200 |
| outage | 38.955027483 | 39.005359063 | 200 |
| outage | 41.005484816 | 41.061771253 | 200 |
| outage | 43.061877875 | 43.110497896 | 200 |
| outage | 45.110606944 | 45.170107395 | 200 |
| outage | 47.170214713 | 47.218526204 | 200 |
| outage | 49.218656518 | 49.272302282 | 200 |
| outage | 51.272411990 | 51.326031671 | 200 |
| outage | 53.326134116 | 53.373317039 | 200 |
| outage | 55.373428709 | 55.422863657 | 200 |
| outage | 57.422970984 | 57.469040464 | 200 |
| outage | 59.469147293 | 59.520855926 | 200 |
| outage | 59.570957768 | 59.611476624 | 200 |
| outage | 59.661589501 | 59.697934015 | 200 |
| outage | 59.748044568 | 59.770946722 | 503 |
| outage | 59.821038183 | 59.824669247 | 503 |
| outage | 59.874765874 | 59.875939116 | 503 |
| outage | 59.926030363 | 59.927272657 | 503 |
| outage | 59.977362639 | 59.978394476 | 503 |
| outage | 60.028483404 | 60.029569698 | 503 |
| blackhole | 3.146880439 | 13.149598977 | 503 |
| blackhole | 15.149662712 | 15.150816624 | 503 |
| blackhole | 17.150914727 | 17.151945455 | 503 |
| blackhole | 19.152041525 | 19.153087913 | 503 |
| blackhole | 21.153180391 | 21.154537080 | 503 |
| blackhole | 23.154649969 | 23.155718934 | 503 |
| blackhole | 25.155813626 | 25.157459298 | 503 |
| blackhole | 27.157556113 | 27.158619082 | 503 |
| blackhole | 29.158736604 | 29.159942258 | 503 |
| blackhole | 31.160043053 | 31.161144591 | 503 |
| blackhole | 33.161241963 | 33.162436264 | 503 |
| blackhole | 35.162531398 | 35.163594583 | 503 |
| blackhole | 37.163685053 | 37.164816405 | 503 |
| blackhole | 39.164861316 | 39.166199631 | 503 |
| blackhole | 41.166295748 | 41.167544903 | 503 |
| blackhole | 43.167658831 | 43.169274154 | 503 |
| blackhole | 45.169370795 | 45.170407941 | 503 |
| blackhole | 47.170504560 | 47.171677397 | 503 |
| blackhole | 49.171774270 | 49.172928958 | 503 |
| blackhole | 51.173025229 | 51.174126104 | 503 |
| blackhole | 53.174231346 | 53.175465926 | 503 |
| blackhole | 55.175564616 | 55.176613810 | 503 |
| blackhole | 57.176729450 | 57.178683792 | 503 |
| blackhole | 59.178787343 | 59.180008057 | 503 |
| blackhole | 59.230102888 | 59.231161363 | 503 |
| blackhole | 59.281265071 | 59.282356532 | 503 |
| blackhole | 59.332445277 | 59.333287555 | 503 |
| blackhole | 59.383371908 | 59.384329137 | 503 |
| blackhole | 59.434415276 | 59.435177492 | 503 |
| blackhole | 59.485264624 | 59.486070294 | 503 |
| blackhole | 59.536159457 | 59.536906064 | 503 |
| blackhole | 59.586997188 | 59.587886648 | 503 |
| blackhole | 59.637988264 | 59.638954362 | 503 |
| blackhole | 59.689047929 | 59.690660347 | 503 |
| blackhole | 59.740736770 | 59.741802549 | 503 |
| blackhole | 59.792106967 | 59.793276521 | 503 |
| blackhole | 59.843371161 | 59.844328142 | 503 |
| blackhole | 59.894417668 | 59.895214231 | 503 |
| blackhole | 59.945318740 | 59.946221533 | 503 |
| blackhole | 59.996310003 | 59.997266100 | 503 |
| blackhole | 60.047364134 | 60.048364868 | 503 |
| policy-change | 3.764961625 | 3.784528250 | 503 |
| policy-change | 5.784655514 | 5.786074076 | 503 |
| revocation | 4.651046837 | 4.671830954 | 503 |
| revocation | 6.671944620 | 6.673130093 | 503 |
