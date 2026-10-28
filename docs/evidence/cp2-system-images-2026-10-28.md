# CP2: фактические системные образы, 2026-10-28

Неделя 1 «Контекст и foundation», T02 «Foundation P0 и совместимые зависимости». Статус: диагностика расширена и проверена, CP2/R1 остаются открытыми. Это evidence конкретных hosted runs, не приёмка всех M01-M23 или production deployment.

## Native inventory на 3393480

[Run 40761233745](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40761233745), commit `3393480b1b127dcec9908db46db552de8c32152a`, attempt 1: **failure**. Bootstrap worker, tracking, cluster, SQL и controllers прошёл. Сверка inventory до и после аудита выполнена; summary опубликован, owned cleanup завершился успешно. Из 14 наблюдаемых image references полное approved application coverage есть у **4**, итог coverage `inconclusive`, audit `fail`, `release_ready=false`.

Новая ограниченная проекция SBOM сохраняет package name/version/type/cataloger и пути бинарников, привязанные к точному image config ID. Произвольные metadata не экспортируются. Состав доступен для **13 из 14** targets. Полный bounded JSON находится в шаге `Publish bounded summary without raw runtime snapshots` указанного run; таблица ниже содержит диагностический subset, не полный SBOM и не декларацию покрытия. Raw runtime snapshots не публикуются.

| Target в этом run | Наблюдаемое приложение | Пакеты | Результат |
| --- | --- | ---: | --- |
| runtime-000 | kube-apiserver 1.36.4, Go 1.26.5 | 138 | Отсутствует требуемый прежним OS-профилем libc6; полного scan нет |
| runtime-001 | kube-proxy 1.36.4, Go 1.26.5 | 159 | 9 Critical / 69 High / 6 Unknown matches; application coverage не принят |
| runtime-002 | kube-controller-manager 1.36.4, Go 1.26.5 | 165 | Прежний профиль требует libc6; полного scan нет |
| runtime-003 | kube-scheduler 1.36.4, Go 1.26.5 | 126 | Прежний профиль требует libc6; полного scan нет |
| runtime-004 | Закреплённый PostgreSQL, registry reference | 60 | pass, 0 Critical/High/Unknown |
| runtime-005 | Cilium 1.20.2, Ubuntu 26.04 | 955 | Дистрибутив ещё не поддержан текущим audit contract; scan не выполнен |
| runtime-006 | Config `26de0949...`, состав не сохранён | Не установлено | `image_audit_package_observation_invalid`; приложение не угадывается по соседним targets |
| runtime-007 | kind node, kubeadm/kubectl/kubelet 1.36.4 | 878 | 67 Critical / 394 High / 70 Unknown matches; application coverage не принят |
| runtime-008 | Фактический tracking-server | 125 | pass, 0 Critical/High/Unknown, 6 Medium / 1 Negligible |
| runtime-009 | CoreDNS, наблюдаемый Go module pseudoversion | 184 | Прежний профиль требует libc6; полного scan нет |
| runtime-010 | Worker/controller image | 68 | pass, 0 Critical/High/Unknown, 6 Medium / 1 Negligible |
| runtime-011 | local-path-provisioner v0.0.34 | 61 | Прежний профиль требует libc6; полного scan нет |
| runtime-012 | etcd/etcdctl/etcdutl, Go 1.24.13 | 151 | Нет полного scan; часть Go modules имеет UNKNOWN version |
| runtime-013 | Тот же PostgreSQL через config reference | 60 | pass, 0 Critical/High/Unknown |

Индексы runtime-NNN локальны для этого run, не стабильные имена компонентов. Registry reference и config reference PostgreSQL считаются отдельными наблюдаемыми targets текущим collector, поэтому 4/14 не означает четыре разных приложения. Severity counts - совпадения package/advisory, не число уникальных уязвимостей. Отсутствующий scan не означает отсутствие CVE.

Наблюдение объясняет пробел прежнего профиля: минимальные Debian images содержат package database с base-files/netbase/tzdata и статически собранные Go-приложения, но не libc6. Удаление требования libc6 само по себе не докажет полноту. Нужен профиль каждого приложения с ожидаемыми бинарниками, Go modules/stdlib и проверенным matcher. Kubernetes и etcd содержат UNKNOWN versions для внутренних modules; их нельзя заменить версией container tag без отдельного проверяемого основания.

## Исправление диагностического отказа

В [модели Syft 1.54.1 LinuxRelease](https://github.com/anchore/syft/blob/v1.54.1/syft/format/syftjson/model/linux_release.go) id/versionID являются optional (`omitempty`). Прежний observation parser требовал оба поля, хотя не использовал этот результат как разрешение покрытия. Controlled RED подтвердил отказ для `{}`, id-only и version-only. Parser теперь сохраняет отсутствующее поле как null, остальные package facts остаются доступны; неправильные типы и чужой image ID отклоняются. Ссылка на observed image сохраняется до разбора package facts.

Native [40763471155](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40763471155) на `d3c54a23cae09d4cb4c6066ae4076cead40df515` подтвердил исправление: observation доступен для **14/14** targets. Тот же config `sha256:1fb303f6baa0bebe9e86930cbba8ef68dc9d10944a4f235cefd51689b5ef2067` принадлежит `quay.io/cilium/operator-generic@sha256:7a7a3489dc66ad67e420d285c8a8d2e169b0957ad15e120f593d27081bf38d82`: 174 Go packages, Cilium v1.20.4, Go 1.26.10, id/versionID неизвестны. Прежний parser refusal сменился на корректный `image_audit_runtime_distro_unsupported`; application coverage по-прежнему **4/14**, audit fail. Наличие всех observations не превращается в полное scanner coverage или release approval.

Проверка исправления: **6 unittest methods**, включая три формы optional distro, неизвестные версии, malformed types, foreign image/scanner/source, duplicate IDs, лимиты и metadata canary. Существующая audit suite: **188 cases pass**. Contract module: **98/98 statements, 36/36 branches**; audit runner: **281/287 statements, 110/112 branches**. Ранбук: [CP2 состав системного приложения](../operations/image-audit-troubleshooting.md#cp2-состав-системного-приложения).

## Отдельное исправление Cilium

Commit `ced7ea067487f21523adac72c632e04a5fbdba37` закрепляет **1.20.4**, сохраняя сетевую политику и resource limits. Chart hash проверен против upstream index, image digests против release notes. [Причина и точные pins](../operations/image-audit-troubleshooting.md#cp2-security-patch-cilium-1204). Локально 33 проверки cluster command, storage egress, foundation и observation прошли.

[Observed audit 40762260195](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40762260195) на `ced7ea0` завершён: **fail**, coverage **4/14**. Фактический agent reference совпал с новым pin `quay.io/cilium/cilium@sha256:20fe92e4c86641233a450098c158d2d29085f3419931ab6bf681d2485dedf16e`, config `sha256:1320017dd0b611d024c18a7e2f59a0378221a9bb840b16f35f159ecbb03d5c8a`. SBOM наблюдает `github.com/cilium/cilium v1.20.4` в `/usr/bin/cilium-agent` и Go `1.26.10`. Это доказывает фактическую смену bytes/runtime, но Ubuntu application coverage ещё не принят. Worker/storage/tracking сохраняют 0 Critical/High/Unknown. Новый config `1fb303f6...` также не прошёл прежний optional-distro parser.

Полная [Kubernetes regression 40762255437](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40762255437) на `ced7ea0` завершилась **success**, attempt 1, job `123076994439`: двойной bootstrap, train/eval Jobs, storage migration, M01/M04/M05/M21 и owned cleanup прошли. В terminal log явно подтверждены `M01: pass`, `M04: pass`, `M05: pass`, `M21: pass`; successful bootstrap сам по себе не использовался вместо этих проверок. Исправление parser `d3c54a2` подтверждено отдельным run выше. Run 3393480 относится к прежней Cilium 1.20.2.

У kube-proxy/kind основной вклад в High/Critical дают Go stdlib/modules и OS packages. [Kubernetes 1.36.6](https://github.com/kubernetes/kubernetes/releases/tag/v1.36.6) существует, но запрос anonymous Docker Registry `kindest/node:v1.36.6` на 2026-10-28 вернул HTTP 404. [kind 0.33.0](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0) публикует предсобранный 1.36.4. Поэтому простая смена строки version не является готовым исправлением: требуется проверенная сборка node/base либо новый официальный artifact с функциональной regression и полным audit. Текущий node pin не менялся.

## Main checkpoint aaae245

Все 10 workflows завершились: **7 success / 3 failure**, attempt 1. Успешны [Kubernetes](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096779), [storage](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096468), [tracking](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096263), [component images](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096347), [developer](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096432), [intake](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096377) и [docs](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096584).

- [M08 40760096184](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096184): fail, 68 checks, 35 training/prediction runs, 251 primary files, candidate replay error 0.0, 25 nonviolating / 10 violating / 0 inconclusive scenarios. Проверка evidence прошла, statistical robustness не прошла.
- [Evasion 40760096258](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096258): fail, recall drop `0.07183673469387755` при лимите `0.05`, 3 000 probe rows / 1 225 positives. Это component campaign, не подключённый full M09.
- [Paired robust training 40760096531](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096531): fail; эксперимент не принят как исправление и не используется для разрешения release.

## Следующий обязательный результат

Проверка Cilium и optional-distro fix завершена в указанных границах. Реализованы [два Go detection controls](../operations/image-audit-troubleshooting.md#go-detection-controls) на известных уязвимых module/stdlib versions. На `f12476c` локально **192 audit cases + 8 unittest methods pass**; audit runner **296/302 statements, 116/118 branches**, contract **109/109 statements, 38/38 branches**. Native [40765727216](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40765727216) подтвердил оба controls: module `v0.16.0` выявляет High `GHSA-4374-p667-p6c8`, stdlib `go1.20.9` выявляет High `GO-2023-2102`, оба exit 2 и status pass. Digests report: module `29b94a2da7dfa090a7f23046f5b9ba50e8b4768bab35ddec7827e12ed84d2a40`, stdlib `fee220cbc81660c0ef8ec6353fc4a63cbc68e48c755ccefbd32791cceaec2c7b`. Общий run fail, coverage 4/14; никакой system application profile этим не принят.

Состав operator показывает отдельный `/usr/bin/gops` с main module version `UNKNOWN`, хотя зависимость gops внутри `/usr/bin/cilium-operator-generic` имеет `v0.3.28`. Перенос версии между этими разными бинарниками запрещён. Это конкретный оставшийся пробел application coverage.

Следующий реализованный diagnostic path допускает сканирование связанного непустого inventory минимальных Debian, Ubuntu и unknown-distro images. Он сохраняет findings, но никогда не возвращает pass для неподтверждённого application profile. **197 audit cases + 12 unittest methods pass**; audit runner **299/306 statements, 117/120 branches**, contract **130/130 statements, 50/50 branches**. Controlled tests подтверждают, что строгие worker/storage/tracking contracts не ослаблены, empty/foreign/malformed/suppressed evidence отклоняется. Native проверка этого path ещё требуется.

## Native diagnostic scan завершён 2026-10-29 МСК

[40767489025](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40767489025), head `1be1accc7761361d2bf1caac95d5397da3dbca1b`, завершился **failure**. Scan: 2026-10-28 20:57:45-21:01:42 UTC, то есть 23:57:45-00:01:42 МСК. Все **14/14 наблюдаемых targets** действительно просканированы; с тремя явными worker/storage/tracking inputs в отчёте 17 component entries. Повторное чтение runtime совпало. Application coverage остаётся **4/14**, release_ready=false. Отсутствие approved application profile не скрывает severity findings и не превращается в pass.

| Компонент | Critical matches | High matches | Unknown matches | Результат |
|---|---:|---:|---:|---|
| kube-apiserver 1.36.4 | 5 | 43 | 5 | fail |
| kube-proxy 1.36.4 | 9 | 69 | 6 | fail |
| kube-controller-manager 1.36.4 | 7 | 58 | 6 | fail |
| kube-scheduler 1.36.4 | 7 | 58 | 6 | fail |
| Cilium agent 1.20.4 | 0 | 0 | 18 | inconclusive |
| Cilium operator 1.20.4 | 0 | 1 | 3 | fail |
| kind node 1.36.4 | 67 | 394 | 70 | fail |
| CoreDNS image 1.14.2 | 11 | 51 | 4 | fail |
| local-path-provisioner | 3 | 20 | 3 | fail |
| etcd image 3.6.8-0 | 26 | 127 | 11 | fail |

Это package/advisory matches, не число независимых CVE. Для Cilium operator scanner связывает `GHSA-mgcc-cww5-fp2q` с `github.com/go-jose/go-jose/v4 v4.1.4`, предлагая fixed `4.1.6`; это находка для vendor verification, не доказанная exploitability или уже выполненное исправление. Worker/storage/tracking сохраняют 0 Critical/High/Unknown. В Cilium agent отсутствие High не снимает Unknown и неподтверждённое покрытие приложения.

Оба Go controls прошли с exit 2 и ожидаемым High advisory; общая detection control также pass. Все три cleanup steps - tracking, owned host SQL и disposable cluster - success. Raw snapshots/logs не опубликованы. Прежняя формулировка о pending native diagnostic выше относится к состоянию перед этим run.

Следом устранить реальные findings и ввести проверяемые application profiles. Для Kubernetes готовится [изолированный patch candidate](../operations/node-candidate.md), без замены текущего pin. Отдельно сохраняются M08/M09, M22 independent challenges и незавершённые CP3-CP5. Полученный inventory делает блокеры конкретными, но не закрывает их изменением статусов.
