# Reference manifest для независимого M22 review

Подготовлен 2026-10-29. Статус: **reference для разработки challenge, не execution acceptance**. Перед исполнением оператор создаёт fresh candidate и фиксирует фактические inputs вместе с reviewer. Старые primary files удалены с disposable runners; пакет не содержит готовую модель или training rows.

| Привязка | Значение |
| --- | --- |
| Проверенный runtime source | `5fd9d309cc314192c2e06990b7d25b9e34a675de` |
| Snapshot архива, включая опубликованные документы M12 | `dfbddcf74802508b6d8cdd0aa2fde4ea6043f8c4` |
| Reference candidate | `cf03ee09a45d6ba321d18c52049d5e28df9eff5be7fdfd20f7564da134af1a3d` |
| Reference proposal | `883d5b15b66b32dfd578e1873503c4b2a84671934e1f36267e1efad00cd1e5bf` |
| Reference model SHA-256 | `fa71479b9a98fa26644fbfdb692ef4dd64b291964c2d1fdaa2140e41a96ead46` |
| Reference release subject | `5a9a33a590db452353269df88aa0c408575bbab075725d5d5451f834c3ccae78` |
| Source fingerprint | `27588a40566ee55cd6b21078eb53e968d0404b04c223900bc2bd42510cb0f2b3` |
| Reference image ID | `sha256:330925d8cf61a93db9004ef944e48e949d152e9ec7fe4cc6c5ee1012b6b7db29` |
| Reference M12 | [40819797749](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40819797749), [очищенное evidence](../evidence/m12-inference-2026-10-29.md) |
| Независимые спецификации/кейсы | 0/2, не получены и не исполнены |

Image ID описывает image проверенного runner, а не обещание доступного `docker pull` адреса. Пересборка проверяет фактические digests; нельзя подменить expected image на полученный без нового согласованного execution manifest. Local key material, timestamps, candidate references и runtime evidence повторного запуска фиксируются заново, а не копируются из reference.

## Зафиксированные байты защиты и протокола

Хеши SHA-256 вычислены по Git blobs runtime commit, с LF. Windows checkout может иметь CRLF; для точной проверки использовать Git blob либо байты ZIP. Runtime и archive snapshot совпадают по этим файлам. Сравнение с `e063998` ниже касается файлов защиты, а не общей source/image/candidate acceptance.

| File / pinned source | SHA-256 | Same bytes as historical M22 |
| --- | --- | --- |
| [mlsecops/noise_training.py](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/5fd9d309cc314192c2e06990b7d25b9e34a675de/mlsecops/noise_training.py) | `fa94afa020c40a5ea8ca33a9fb6381611c03d9671d589ba0a631f4acbfd98cd0` | true |
| [mlsecops/worker.py](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/5fd9d309cc314192c2e06990b7d25b9e34a675de/mlsecops/worker.py) | `fb1f7a55ce0fda4e5143734c1a3756c191d0c46ddc4efff06da5db3ecbbd4bf3` | true |
| [mlsecops/model.py](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/5fd9d309cc314192c2e06990b7d25b9e34a675de/mlsecops/model.py) | `2f82a96b10fcc1d645a8b5e4e3bc1673c13fd6b5feef2509ed079f7ba7695e63` | true |
| [mlsecops/datasets.py](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/5fd9d309cc314192c2e06990b7d25b9e34a675de/mlsecops/datasets.py) | `d14df772167073758e9d31c92ac748a8abbf1b16fed5e6cb5f22d38ce861dcef` | true |
| [mlsecops/absolute_poisoning_gate.py](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/5fd9d309cc314192c2e06990b7d25b9e34a675de/mlsecops/absolute_poisoning_gate.py) | `cf9d29de047c765ef4ed3c015074150b11b879b437a5e12e80aaca648cf5dc18` | true |
| [scripts/poisoning.py](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/5fd9d309cc314192c2e06990b7d25b9e34a675de/scripts/poisoning.py) | `e8d434170e58e92fe1fcad6bb4beb67b25af37af76fd08791a7de2284791088e` | true |
| [scripts/poisoning_native.py](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/5fd9d309cc314192c2e06990b7d25b9e34a675de/scripts/poisoning_native.py) | `38a1fe06c52f119bee143244139dda7edebf8bb57f606bb11d4eef3195a77d1e` | true |
| [scripts/absolute_poisoning.py](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/5fd9d309cc314192c2e06990b7d25b9e34a675de/scripts/absolute_poisoning.py) | `ba88acc9789f7ece03d21d7e51f7bf984e4e22b48eb05aefba8dbf42d5b703fd` | true |
| [data.lock](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/5fd9d309cc314192c2e06990b7d25b9e34a675de/data.lock) | `531647faa6a8796b5d4734338c7fe4f06415b117b5d0ba4857b40a03164e2750` | false |
| [policies/local-cpu.json](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/5fd9d309cc314192c2e06990b7d25b9e34a675de/policies/local-cpu.json) | `08ed4127479bee6ad9d9f01179add227e81bdb0bb1ff0374028e1bc747df9513` | true |
| [uv.lock](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/5fd9d309cc314192c2e06990b7d25b9e34a675de/uv.lock) | `078685aef1f4c01459a594a10a7c1d6e6896c02481e9f874c88275deb9435f2c` | false |
| [Dockerfile](https://github.com/Abrakadabra124/trusted-mlsecops-platform/blob/5fd9d309cc314192c2e06990b7d25b9e34a675de/Dockerfile) | `04615e455867f94461a1a728b0f9328d02289e7c7532ef022c30a12391963727` | true |

## Предыдущая M22 campaign

[40788141737](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40788141737), source `e063998ed241aa9c712158b6261ce47a51a9f166`: 36 poisoned trainings + 6 clean controls, component pass, полный M22 inconclusive. [Все результаты](../evidence/m22-absolute-2026-10-29.md), [границы доказательств](../absolute-poisoning.md).

- Исторический candidate: `b3e17ff65df8b17999e6863c212dc7611ec6716895c1a0ed31397f42a4f9a3a9`.
- Исторический evaluation: `42bbb9ec97d58657af3c6f93ead651df96f31ba57f3f05ac4a48cb62a810880e`.
- Исторический image: `sha256:ad78b2b42b8fbf6e54377db99e16cf44faf50a4d70f06153a55ac0ffe2e97f31`.
- Protocol digest: `d379f4d1ffec561ef852f0d84b4934230fbe39e4e44e6265ecd404928c6ce25d`.
- Primary snapshot digest: `ae939fd8e310ecb6ba33815c2aa1206bac99392c750c75a4550ec2818b6eb0b2`.

Model bytes совпали с reference M12, но source/image/evaluation/candidate references различаются. Прошлые 42 случая не считаются M22 для нового release автоматически. Для полного M22 нужны повторная связанная absolute campaign, оба независимых challenge и проверяемое evidence; для M18 все обязательные gates должны относиться к одному candidate.

## Что считается отсутствующим

Identity/независимость reviewer, две frozen спецификации, agreed query/time budgets, execution adapter и verifier независимых challenges, новые primary materials и итоговое решение. Ничего из этого не заполняется именем ассистента или искусственным pass. Текущие изменения serving на development branch также не включаются в freeze без явной новой версии manifest.
