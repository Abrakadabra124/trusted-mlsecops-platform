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

Это подтверждённая ошибка совместимости parser. Точный исходный SBOM runtime-006 не публиковался, поэтому её причинную связь с этим единственным native отказом ещё требуется проверить в новом run. Неизвестный distro по-прежнему не разрешает scan approval или release.

Проверка исправления: **6 unittest methods**, включая три формы optional distro, неизвестные версии, malformed types, foreign image/scanner/source, duplicate IDs, лимиты и metadata canary. Существующая audit suite: **188 cases pass**. Contract module: **98/98 statements, 36/36 branches**; audit runner: **281/287 statements, 110/112 branches**. Ранбук: [CP2 состав системного приложения](../operations/image-audit-troubleshooting.md#cp2-состав-системного-приложения).

## Отдельное исправление Cilium

Commit `ced7ea067487f21523adac72c632e04a5fbdba37` закрепляет **1.20.4**, сохраняя сетевую политику и resource limits. Chart hash проверен против upstream index, image digests против release notes. [Причина и точные pins](../operations/image-audit-troubleshooting.md#cp2-security-patch-cilium-1204). Локально 33 проверки cluster command, storage egress, foundation и observation прошли.

Native regression запущена отдельно: [Kubernetes 40762255437](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40762255437) и [observed audit 40762260195](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40762260195). Оба результата пока ожидаются; run 3393480 выше относится к прежней Cilium 1.20.2 и не доказывает качество нового pin.

## Main checkpoint aaae245

Все 10 workflows завершились: **7 success / 3 failure**, attempt 1. Успешны [Kubernetes](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096779), [storage](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096468), [tracking](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096263), [component images](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096347), [developer](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096432), [intake](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096377) и [docs](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096584).

- [M08 40760096184](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096184): fail, 68 checks, 35 training/prediction runs, 251 primary files, candidate replay error 0.0, 25 nonviolating / 10 violating / 0 inconclusive scenarios. Проверка evidence прошла, statistical robustness не прошла.
- [Evasion 40760096258](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096258): fail, recall drop `0.07183673469387755` при лимите `0.05`, 3 000 probe rows / 1 225 positives. Это component campaign, не подключённый full M09.
- [Paired robust training 40760096531](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40760096531): fail; эксперимент не принят как исправление и не используется для разрешения release.

## Следующий обязательный результат

Завершить native проверку Cilium и optional-distro fix; затем ввести проверяемые application profiles для системных образов, положительный Go detection control и устранить реальные findings. Отдельно сохраняются M08/M09, M22 independent challenges и незавершённые CP3-CP5. Полученный inventory делает блокеры конкретными, но не закрывает их изменением статусов.
