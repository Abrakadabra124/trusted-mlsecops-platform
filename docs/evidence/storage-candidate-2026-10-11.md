# Candidate restore и регрессия 2026-10-11

## Исполняемая версия

Commit `3b4aaa0fff9495560b3a6ce4fdec807c32203fa3`; source fingerprint `5c42a8f25bb59fde14446e9864b5c812a26893e9bf5527a2e3ae740c8e7f54e3`. Evidence прочитан из завершённых CI steps, не выведен из наличия YAML. Worker/storage experiment: [run 38127540803](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38127540803), job `114434926699`.

## Restore, а не adoption

Native step **success**, завершён `2026-10-11T09:14:22.509559+00:00`, `source_dirty=false`. **434 checks, 1 000 golden predictions, max error 0.0**. SQL restore 2.924581 s; restore-to-golden 5.145659 s. Эти timings не включают создание backup и всю будущую serving/release recovery chain M17.

- Worker image: `sha256:84b6bd928897039695a1e3e497ac59b6593a3ddd9d4ee3ef3ab4eb24f66ec690`.
- Storage image: `sha256:d2c9c4e10adf06d3b77ddc1f572f09a3a0df875bd706178ba5ca13910d0c32de`.
- Source baseline: `postgres:18.6-bookworm@sha256:9551dd5bf356409a21b31248f49b33bba9bb1877365f3a7e933aecd9af3cf52d`.
- Canonical private report hash: `d557c0a67411b0d59b90e3bb4508a6434f7178a791f9a7d469573bfeb5512947`.
- Source resources удалены и их отсутствие проверено; target очищен native suite. Рабочие volumes не использованы.
- UTF8/provider c/C.UTF-8 и 12-string order sample совпали. Recorded/actual collation versions null в обеих БД.
- 33 image contracts, 14 runner contracts, 74 worker checks и 123 audit/comparison contracts прошли в этом job. Runner после controlled + native запусков: **51/51 executable lines, 10/10 branches**. Audit modules отдельно: 98/100 branches. Это не 100% покрытия проекта.
- Trained worker сохранил три fresh runs и прежний synthetic результат; checkpoint/models из другого процесса не переиспользуются как обучение.

Локальные build IDs отличаются от CI image IDs. Совпадение app fingerprint и predictions не доказывает bit-for-bit reproducible container build. В рамках этого CI job compatibility и scan привязаны к одним exact candidate IDs; baseline workflows собирают собственные images и не объединяются автоматически в M18.

[Runbook и локальная история](../storage-candidate.md) сохраняют успешный первый run и отдельную последующую inconclusive попытку из-за Docker Hub TLS timeout. CI success не переписывает outcome той попытки.

## Security gate остаётся fail

Audit завершён `2026-10-11T09:16:49.213229+00:00`, run ID `ef9fa2cf7a8c4ebe965c0bed6bbf0c12`. Positive detection control прошёл, все четыре scans выполнены. DB schema `v6.1.10`, built `2026-10-11T06:30:42Z`, SHA-256 `d3efb76b6a38aecd903f92c97c0f3ba0c9109c97298f325977c565882203525e`.

| Image | Package artifacts | Finding matches | Critical | High | Unknown | Итог |
| --- | --- | --- | --- | --- | --- | --- |
| worker | 1152 | 173 | 0 | 56 | 0 | fail |
| storage | 151 | 466 | 11 | 118 | 20 | fail |
| worker-candidate | 128 | 172 | 0 | 55 | 0 | fail |
| storage-candidate | 145 | 308 | 3 | 88 | 1 | fail |

Это scanner matches, не число доказанных exploit paths. Необработанный Unknown также не разрешает pass. Известные blocking findings имеют приоритет fail; нет scanner ignore или severity downgrade. Database обновилась относительно [2026-10-09](image-candidates-2026-10-09.md): новые counts не следует выдавать за регрессию кода или сравнивать как одно frozen-DB измерение.

Same-DB сравнение внутри этого run: worker убрал один advisory/package pair, storage убрал 205 и добавил 47, сохранив 261. Смена package names входит в эти числа, поэтому это не «205 исправленных CVEs». Оба candidates остаются непринятыми.

В candidate storage три Critical matches: `CVE-2026-6653` в libxml2 `2.12.7+dfsg+really2.9.14-2.1+deb13u3`; `CVE-2026-88647` и `CVE-2026-95210` в libgnutls30t64 `3.8.9-3+deb13u4`. В совокупности candidates имеют 39 High/Critical groups по advisory/severity/installed-version/fix-state. Scanner DB не указывает fixed version для этих groups. Это состояние базы, не доказательство отсутствия upstream исправления или основание для waiver.

- worker: scanner report SHA-256 `f74edc8c5f19d17feea9e59f36259f18a0b38d020f9df5b6760cc5b6f33b2a62`.
- storage: scanner report SHA-256 `b95a1b933d90dbb7b1b117d1e68e951b2ee723fa9dc71c7bd5addc83b0d9158a`.
- worker-candidate: scanner report SHA-256 `6d96730ca60da3e5cc2fdcadd31f76a10e1837eee6c0755be37d8c11aad966f2`.
- storage-candidate: scanner report SHA-256 `a1a765cbe431198017d90b28e77660cf51f295f7c6c707bfca35bf85a38fdb40`.

Полные очищенные finding records доступны в CI log данного job; raw SBOM/config, private dump и keys в Git не добавлены. Следующая remediation должна опираться на проверенные vendor advisories и повторный scan, не только на counts.

## Проверенная baseline регрессия

- [Documentation 38127540864](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38127540864): success.
- [Developer runtime 38127540910](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38127540910): success.
- [Storage 38127540841](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38127540841), job `114434927053`: success, M03 **431** checks; baseline recovery **432** checks, 1 000 golden predictions/error 0.0. Дополнительные две проверки касаются encoding/collation.
- [Kubernetes 38127540912](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38127540912), job `114434927041`: success. Signed migration **497** checks; M20 **722** checks, включая **19** отрицательных native prediction batches и **2** положительных контроля. M20 завершён `2026-10-11T09:24:07.883250+00:00`, baseline worker `sha256:7b9998385f947354a49388bc3f8b2d85bb81c36f9f55ae97791b6d4ec2d1784c`. Это не M20 candidate image и не полные M04/M05.

T02, M01, M17 и M18 не закрываются этим component. Release readiness false. Нужны исправление vulnerabilities, полный inventory/publisher verification, migration актуальной истории, независимый reviewer и остальные обязательные gates.
