# Изолированный Kubernetes node candidate

## Проверка kubectl в системном образе узла

Для повтора измерения на `8486b03c95a55eb349f52dc426854c7f4030e283` выполните `gh run rerun 45053630761 --repo Abrakadabra124/trusted-mlsecops-platform`. Для текущей версии основной ветки используйте `gh workflow run kind-kubectl-inventory.yml --ref main`. На одноразовом раннере задание проверяет OCI index, manifest linux/amd64, config и слои штатного узла kind. Оно читает `/usr/bin/kubectl` из созданного контейнера до его запуска, удаляет контейнер и проверяет отсутствие по ID.

В JSON сверьте хеши ELF, список из 82 пакетных записей, девять координат модулей, результаты двух положительных контролей Grype и хеш базы. Исходные совпадения бинарника находятся в `original_matches`, дополнительные измерения по модулям в `supplemental`. Если изменился файл, состав, источник или база, считайте измерение неопределённым до разбора. При несовпадении восьми повторных сканов со старым аудитом сверьте версию и байты базы. При `status=fail` откройте `original_severities` и результаты по каждому модулю.

В первой попытке ELF совпал с официальным kubectl v1.36.4, SHA-256 `8b8f088da2dab964f853b38464033b1be15ede2839eca751482357c45abdd05a`. По девяти дополнительным координатам `v0.36.4` найдено 0 совпадений. В оригинальном бинарнике осталось 34 совпадения по 29 уникальным идентификаторам, включая 3 Critical и 21 High. 23 совпадения относятся к стандартной библиотеке Go, 7 к `golang.org/x/net`. Хеш канонического полного отчёта `553c8c26c32058eb812a684ffc24dd2c870d351e5ea9b13f615736909ba700c3`. Сохраняйте `node_profile=unapproved-system` и исходные находки до проверки всех компонентов узла. [Проверка файла](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45053630761/attempts/1), [официальная контрольная сумма](https://dl.k8s.io/release/v1.36.4/bin/linux/amd64/kubectl.sha256).

Неделя 1 «Контекст и foundation», T02 «Foundation P0 и совместимые зависимости». Ответственный: platform operator. Область: разрешённый disposable GitHub-hosted CI. Локальные Docker/WSL/Kubernetes/SQL не запускаются. Build/audit candidate не является adoption или закрытием CP2/R1.

## Симптом и причина

[Observed audit 40767489025](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40767489025) впервые просканировал все 14 targets. Kind node и Kubernetes control-plane images содержат Critical/High matches. Текущий node pin использует Kubernetes 1.36.4 и прежнюю базу kind. [Kubernetes 1.36.6](https://github.com/kubernetes/kubernetes/releases/tag/v1.36.6) опубликован 28 октября, но manifest `kindest/node:v1.36.6` при проверке registry отсутствовал (404).

[Kind 0.33.0](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/pkg/cmd/kind/build/nodeimage/nodeimage.go) поддерживает `kind build node-image --type file` из локального server archive. Его [base pin](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/pkg/build/nodeimage/defaults.go) не обновлён и в проверенном upstream commit `2b29bebb68be838c81ed868cc4f21836c5b1c911`. Поэтому patch Kubernetes измеряется отдельно от оставшихся OS/container-runtime/CNI/etcd/CoreDNS проблем. Замена номера версии сама по себе их не исправляет.

## Закреплённые материалы и границы

[Builder](../../scripts/image_node_candidate.py) использует:

- server archive `v1.36.6`, SHA-256 `702d6529b5eb7bfb919dab3542cd420ccf316fca6aa7c506b69169bd12b26a7c`, сверенный с [официальным checksum](https://dl.k8s.io/release/v1.36.6/kubernetes-server-linux-amd64.tar.gz.sha256);
- kind `v0.33.0`, установленный [checksum-pinned installer](../../scripts/install_ci_tools.py);
- base `docker.io/kindest/base:v20260820-69b56db7@sha256:8098fa3cae05bc15d9c4b93a566d19e1f8e65a25e26ebeb993b6cb41142cf791`; registry response hash сверён, Linux/amd64 child manifest `sha256:49207c7d517ca84ea87c880d314e2ebf25ae7f5dc85f54238f543a8b6681970f`;
- baseline `kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed` и отдельный candidate tag `trusted-mlsecops:node-v1.36.6-candidate`.

Архив загружается потоково с лимитом 2 GiB в новый каталог. До сборки проверяются checksum, hosted Linux x86_64, чистый checkout, версия kind и свободное место. Existing path не перезаписывается. После сборки фиксируются image config IDs, source revision и hashes исходных материалов; перед и после audit binding читается заново. Чужой/изменившийся candidate или source запрещает результат.

Kind сам импортирует вспомогательные images по upstream tags. Их результирующие байты требуют отдельного runtime inventory перед adoption. Старый base сохраняет уязвимые OS/Go runtime components. Docker commit не даёт заявления о побайтно воспроизводимой сборке; checksum не заменяет независимую проверку identity издателя. Здесь измеряется только проверяемый patch candidate, полный foundation ещё не принят.

## Плейбук запуска и диагностики

1. Прочитать branch/head и проверить активные runs: `gh run list --workflow node-candidate.yml`. Не запускать повтор при уже работающем job. Для первого добавления workflow используется push в отдельную ветку `codex/cp2-node-candidate`; следующие запуски доступны через workflow_dispatch после регистрации GitHub.
2. На разрешённом hosted runner [workflow](../../.github/workflows/node-candidate.yml) устанавливает lock, выполняет negative contracts и pinned tool install. Builder отвергает локальную Windows и self-hosted runner до первого runtime command.
3. Выполнить `uv run --locked python -m scripts.image_node_candidate`. Это создаёт только отдельный образ, не изменяет `infra/kind.yaml`, не создаёт рабочий cluster и не публикует image в registry.
4. Собрать текущие worker/tracking для обязательных audit controls. Выполнить `uv run --locked python -m scripts.image_audit --compare-node-candidate`. Baseline/candidate сканируются теми же Syft/Grype и одним snapshot базы, с обязательными Go-module/stdlib detection controls. Diagnostic result не может разрешить application coverage.
5. Прочитать `gh run view <run-id>` и bounded summary. Сравнивать findings по package/advisory, фиксируя версии и config IDs. Нельзя объявлять удалённые совпадения устранением всех угроз или считать исчезновение неизвестного package доказательством полноты.
6. При checksum/source/config/DB mismatch остановить цепочку. При High/Critical оставить fail; при Unknown или неполном покрытии оставить inconclusive. Проверить конкретный refusal, не добавлять waiver и не изменять порог ради зелёного job.

Kind обычно удаляет собственный build container через deferred cleanup. При timeout/cancellation это не гарантируется: runner disposal является границей очистки данного эксперимента. На машине пользователя cleanup не выполняется; global prune/reset запрещены. Перед повтором убедиться, что предыдущий hosted job terminal. При неизвестном результате не публиковать или принимать образ.

## Проверка и дальнейший adoption

Controlled tests проверяют ограничения runner, dirty checkout, нехватку места, неверный kind, archive digest/size, build failure, source/image substitution и отказ выдавать coverage при чистом diagnostic scan. Проверены **201 audit cases, 12 observation/Go/diagnostic methods и 7 node candidate methods**; builder до CLI entrypoint имеет 66/70 covered statements, 23/24 branches. Это controlled результаты, они не заменяют native сборку. Native result записывается только после terminal CI; первая проверка этого нового пути ещё требуется.

Успешный build report имеет scope `node-candidate-build-only`, release_ready=false. Общий diagnostic audit закономерно остаётся fail/inconclusive при текущей старой базе и unapproved application profiles. Перед adoption нужны актуальная база, полный inventory встроенных runtime images, функциональные M01/M04/M05/M21 и security checks на тех же bytes. Новый immutable image публикуется и перепроверяется отдельно; только затем меняются node/kubectl pins и version guards согласованным commit. Rollback на этом этапе не нужен: текущий runtime pin не меняется.

## Native результат 2026-10-29 МСК

[40777426055](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40777426055), head `f8a15c45b4544036df4de65fa904198ed2c5d065`, job `123130219970`: **failure**, attempt 1. Builder завершился success, затем общий audit корректно отказал. Сборка 01:07:17-01:08:35 МСК; audit 01:09:01-01:12:34 МСК. Все пять inputs просканированы, detection/Wolfi/оба Go controls pass. Worker/storage/tracking имеют 0 Critical/High/Unknown.

| Измерение на одной DB | Baseline 1.36.4 | Candidate 1.36.6 |
|---|---:|---:|
| Catalogued packages | 878 | 878 |
| Critical matches | 67 | 61 |
| High matches | 394 | 349 |
| Unknown matches | 70 | 67 |
| Medium matches | 195 | 183 |

Baseline config `sha256:0fa975026f71246c4e4744409d43e2e5884bb6e960851b438e50f455808c16f4`; candidate config `sha256:801636e7c8a763aff10e5612c33d3c650e907a929a14fcf54fa564c8c8314105`; base config `sha256:816692b104dfc1ccc2bf183a2c61bf5d40c8fbc232dd5c71210f4d71f622061d`. Source materials digest `72f61cbf79b17d01b90d32bdaf46f424a5f8b473a309b492095869a98c1e854c` повторно проверен после audit.

Syft наблюдает `k8s.io/kubernetes v1.36.6` в `/usr/bin/kubeadm`, `/usr/bin/kubectl`, `/usr/bin/kubelet`. Go 1.26.5 этих binaries сменился на 1.26.10, но старые runtime binaries всё ещё содержат Go 1.26.7. Matches являются package/advisory совпадениями, не уникальными CVE. Версии x/net, x/crypto и gRPC в [upstream go.mod 1.36.6](https://github.com/kubernetes/kubernetes/blob/v1.36.6/go.mod) остались прежними; patch Kubernetes не устраняет весь dependency scope.

**Решение: candidate не принят и не опубликован как новый runtime artifact.** Измеренное уменьшение findings не разрешает adoption. Нужны remediation base/runtime и зависимостей, разбор Unknown, application profiles и функциональная проверка перед сменой pins. CI build container завершён штатным kind builder; cluster/SQL здесь не запускались. Артефакт жил на disposable runner, durable registry image этим run не создан.

## Проверка обновления OpenSSL от 22 ноября 2026 года

Сравнили штатный образ узла kind для Kubernetes 1.36.4 с кандидатом на том же базовом образе. Изменились три пакета Debian: `openssl`, `libssl3t64` и `openssl-provider-legacy`, с `3.5.6-1~deb13u2` до `3.5.9-1~deb13u1`. Сканер Grype обработал оба образа с одной базой уязвимостей, SHA-256 файла базы `fd8b429aa7ff8fa4d7fc0adc64e4fddd54790e336ed52126c79fb63902967ad9`. В каждой описи 878 пакетных записей. У остальных 875 записей совпал хеш с учётом путей и кратности. [Исходный код проверки](https://github.com/Abrakadabra124/trusted-mlsecops-platform/tree/f0bcccff79fec2f3b361776f2f10ff7bc8ea2bf0), [первичный журнал](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45034371986/job/137244721689).

| Совпадения пакетных записей с бюллетенями | Штатный узел | Кандидат |
| --- | ---: | ---: |
| Critical | 72 | 66 |
| High | 491 | 458 |
| Unknown | 31 | 31 |
| Два целевых бюллетеня OpenSSL на трёх пакетах (входят в Critical) | 6 | 0 |

Верхний слой содержит по одному маркеру `.wh..wh..opq` в каталогах `/usr/share/doc/libssl3t64`, `/usr/share/doc/openssl` и `/usr/share/doc/openssl-provider-legacy`. Такой маркер скрывает унаследованные элементы каталога. Проверка подтвердила точные байты всех трёх новых файлов `copyright` и атрибуты десяти повторно записанных каталогов, включая режим `1777` у `/tmp`. Список скрытых элементов в протоколе отсутствует. Проверка слоя завершилась с `node_overlay_mismatch`, последующие шаги приёмки в этом задании были пропущены.

**Решение.** Кандидат отклонён. Его config digest `sha256:9171cd285423b4ec6ee761eccca0de8797cf5ccf0ced4ba3edadf78b158bdfda` относится к одноразовой сборке. Публикация и замена штатного узла не выполнялись. Для следующего кандидата требуется сверить итоговый состав затронутых каталогов базового и собранного образов с файлами пакетов и повторить аудит оставшихся блокирующих находок. Успешная сверка каталогов закрыла бы только проверку слоя.

Для воспроизведения квалификации в одноразовом GitHub Actions runner выполните `gh run rerun 45034371986 --repo Abrakadabra124/trusted-mlsecops-platform`. При повторе сохраните версию и SHA-256 базы сканера. Первое измерение закреплено в [попытке 1](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45034371986/attempts/1). Для сравнения доступен [полный аудит штатного кластера](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45030124975/attempts/1).

### Что скрывали три маркера

Манифест `linux/amd64` штатного узла имеет digest `sha256:597367624b4748b74b98e4fe2d661cd78063d02ecdaca702fd90572375b83e67`. Оба слоя прочитаны из реестра без запуска контейнера. Для каждого проверены размер и SHA-256 архивных байтов по манифесту и SHA-256 распакованного слоя по конфигурации образа. Последовательное наложение слоёв показало, что каталоги `/usr/share/doc/openssl`, `/usr/share/doc/libssl3t64` и `/usr/share/doc/openssl-provider-legacy` в исходном образе отсутствовали. Маркеры из [первой попытки](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45034371986/job/137244721689) скрыли ноль унаследованных записей.

В [повторной проверке на свежем runner](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45035838576/job/137249298035) собрался другой образ, с config `sha256:a9ff9f650b9d32a2a0be3e97fb531cdd6e005272ac41a632bda44bd0a6dfa502`. В его верхнем слое таких маркеров уже не было. Проверены байты трёх лицензий, опись из 878 записей и отсутствие всех шести целевых совпадений. Получены `overlay_errors=0` и `candidate policy status: fail`. Отдельный регрессионный тест предъявляет маркер на пустом каталоге и на каталоге с унаследованным файлом. Второй случай блокирует приёмку. Сверка одинакового состава пакетов не устанавливает побайтовую воспроизводимость образа. [Код и тесты этой попытки](https://github.com/Abrakadabra124/trusted-mlsecops-platform/tree/d95d0e2ab19050cb5d53e1850cd6d0ebf1e2250e).

База Grype в этой попытке имела SHA-256 `08b302c006875468fc087630ba33be9d814a2585047ddc874c8cd7a8bfab0d1b`. Внутри пары по-прежнему измерены 72 → 66 Critical, 491 → 458 High, 31 → 31 Unknown. Образ остаётся отклонённым по политике уязвимостей.

### Обновление runc внутри штатного узла

Штатный `/usr/local/sbin/runc` содержит runc v1.4.3 и стандартную библиотеку Go 1.26.7. Для проверки выбран патч-релиз runc v1.4.4 из той же ветки. Его ELF-файл для amd64 содержит Go 1.26.11 и ревизию `6d1032fdfb7d3432125806826b50b37ac42b6b23`. SHA-256 опубликованного файла равен `378e4c545dee19f310bf470fae5b4d1362d740f3f10a5eb6f788ca392c4592de`. Проверены отдельная подпись файла, подписанный список контрольных сумм и ключ подписанта `C2428CD75720FACDCF76B6EA17DE5ECB75A1100E` из набора ключей предыдущего релиза. [Релиз поставщика](https://github.com/opencontainers/runc/releases/tag/v1.4.4), [источник ключей](https://github.com/opencontainers/runc/blob/bb14dabeb7185bb72c8c86735d090dcb20f36587/runc.keyring).

В одноразовой сборке проверены исходная конфигурация узла, SHA-256 каждого нижнего слоя, единственный заменённый файл в верхнем слое, его права `0755`, владелец `0:0` и отсутствие дополнительных атрибутов доступа. На одной базе сканера опись до и после содержала по 25 записей для самого runc. Остальные 853 строки совпали. Изменение только runc дало 72 → 70 Critical, 491 → 482 High и 31 → 31 Unknown. Добавленных блокирующих совпадений по парам «бюллетень, уровень» не было. Итог образа `fail`, публикация в реестр и запуск кластера с кандидатом не выполнялись. [Первичный отчёт](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45036732716/job/137252044372), [проверяющий код](https://github.com/Abrakadabra124/trusted-mlsecops-platform/tree/a08af50328ce1c5e0c83407bd4cbbe000d21286a).

### Совместная проверка на одном образе

Для нового измерения из чистого checkout основной ветки выполните `gh workflow run kind-node-patches.yml --ref main --repo Abrakadabra124/trusted-mlsecops-platform`. [Ручная проверка](../../.github/workflows/kind-node-patches.yml) использует одноразовый хост с правом чтения репозитория. Убедитесь, что `headSha` запуска совпал с выбранной ревизией `main`. Код возврата 1 с итоговым отчётом и состоянием `fail` означает отказ политики. При отсутствии итогового отчёта откройте первый ошибочный шаг и установите причину незавершившегося измерения. Сравните digest базы с предыдущей попыткой до сопоставления числа совпадений.

Из одних и тех же проверенных входных файлов собраны промежуточный образ с OpenSSL и конечный образ с OpenSSL и runc. Проверка связала промежуточный образ с двумя распакованными слоями штатного узла, а конечный образ с точными слоями промежуточного. Конфигурация запуска совпала. Сканер обработал все три образа с одной доступной только для чтения базой, SHA-256 `08b302c006875468fc087630ba33be9d814a2585047ddc874c8cd7a8bfab0d1b`. [Код проверки](https://github.com/Abrakadabra124/trusted-mlsecops-platform/tree/7704be3a79c4ae855c205b218d6dfce2ec649a89), [результаты и хеши трёх описей и отчётов](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45037743093/job/137255130015).

| Конфигурация | Пакетные записи | Critical | High | Unknown |
| --- | ---: | ---: | ---: | ---: |
| Штатный узел | 878 | 72 | 491 | 31 |
| После обновления OpenSSL | 878 | 66 | 458 | 31 |
| После обновления OpenSSL и runc | 878 | 64 | 449 | 31 |

У конечного кандидата config digest `sha256:dc3f53249355fe96715ae70ced037967b67492dc049e645ab74f493170d597e4`. Все 850 строк вне трёх пакетов Debian и файла runc совпали. По сравнению со штатным образом удалено 50 блокирующих совпадений, добавлено 0. Измерение учитывает кратность пар «бюллетень, уровень». Результат `fail` вызван оставшимися находками. Образ не опубликован и не проверялся как работающий узел.

В первом совместном запуске проверка слоя сообщила `unproven_opacity` у каталога OpenSSL. В новом запуске она подтвердила ноль унаследованных записей для всех трёх маркеров и проверила пустой подкаталог `/usr/share/doc/openssl/HOWTO` по атрибутам каталога из подписанного пакета. Единственный обычный файл под каждым из трёх каталогов лицензий совпал с соответствующим `copyright`. Лишний или изменённый файл по-прежнему вызывает отказ. Прошли 16 тестовых методов. [Первоначальный отказ](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45037336717/job/137253896225), [проверка состава и решение сканера](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45037743093/job/137255130015).

Для воспроизведения выполните `gh run rerun 45037743093 --repo Abrakadabra124/trusted-mlsecops-platform`. В журнале найдите объект со scope `one-node-openssl-and-runc`. Он появляется после сверки слоёв, пакетов, базы и отчётов. Сравните SHA-256 базы, значения `results`, `added_blocking_matches` и `removed_blocking_matches`. Запись `scanner-measurements-before-composition-checks` отражает только промежуточное измерение.
