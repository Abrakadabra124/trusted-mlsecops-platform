# B02: Kubernetes workspace module provenance, 2026-11-20

## Результат и границы

Проверка выполнена в отдельной ветке `fix/r1-b02-kubernetes-provenance` от
`f3b31b453065c9669aee7689e6ef8fc0e6d9b10c`. Production verifier и правила
image audit не изменены: полной доказанной подстановки версий для сканера
не получено. Runtime application coverage не увеличено.

Для 96 экземпляров Go-модулей с `(devel)` в четырёх pinned образах
установлены 27 source paths, Git tree IDs и точные SHA-256 module manifests.
Это source-level evidence для дальнейшей проверки, не доказательство того,
что все экземпляры являются опубликованными модулями `v0.36.4`.

Последний разобранный native image report остаётся историческим:
[43625404562 / job 132539994035](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/43625404562/job/132539994035),
source `f3b31b4`, report SHA-256
`a72ca814ddd70058455975c7c5435c14d017c5434a75bf201f14aab0eea15a2d`.
Его результат: `fail`, coverage `6/14`, C/H/U findings сохранены.
Нового runtime run в этой итерации не было. B02, общий M18/R1 и independent
M22 не закрыты.

## Что проверено

1. Cached manifest/config SHA-256 сверены с закреплёнными
   [image inventories](../../scripts/image_kubernetes_inventory.py).
   Четыре свежих manifest, полученные по digest из `registry.k8s.io`,
   побайтово совпали с cached manifest. Manifest config IDs совпали с
   runtime inventory; layer descriptors и diff IDs совпали с сохранёнными
   extraction receipts. Layer blobs и бинарники заново не скачивались:
   это повторная проверка сохранённой цепочки, не новая экстракция.
2. Все 11 cached buildinfo записей согласованы с 588 закреплёнными
   inventory rows, включая пути бинарников. Во всех buildinfo указан
   `bb826b1d48562f110659e64e8ec444327433db95` и `vcs.modified=false`.
   Хеши четырёх основных бинарников совпали со свежими официальными
   `dl.k8s.io/release/v1.36.4/bin/linux/amd64/<component>.sha256`.
   Хеши всех 11 бинарных экземпляров, включая runner, найдены в file
   records release SBOM.
3. [Официальный release SBOM](https://sbom.k8s.io/v1.36.4/release)
   имеет SHA-256 `8528a907e260fdbe8a4976ac712bc7fffc42558697cb16911a8326f72c14be76`.
   Он ссылается на [source SBOM](https://sbom.k8s.io/v1.36.4/source)
   через SHA-1 `068a345b2b3db49a5736f5945caa1b4bf7ef806d`.
   Source SBOM проверен также по опубликованному SHA-256
   `fde4662d04b0c44a403a8951f8d539bfabf745ed24180dcc10662a49f364b34d`.
   Размер проверен до скачивания и ограничен 22 226 711 байтами.
4. Source SBOM содержит файловые хеши, совпадающие с полученными по
   immutable VCS revision `go.mod`, `go.work`, `vendor/modules.txt`,
   `hack/lib/golang.sh` и всеми 27 staging `go.mod`.
   Суммарный размер последних 27 файлов: 75 690 байт.
5. Подписи двух SBOM математически проверены относительно приложенных
   сертификатов; subject содержит официальную release identity.
   **Доверенная certificate chain и transparency log не проверены.**
   Поэтому результат не называется полной проверкой доверенного издателя.
   [Официальная процедура](https://kubernetes.io/docs/tasks/administer-cluster/verify-signed-artifacts/)
   требует проверки identity/issuer средствами Sigstore.
6. Для каждого из четырёх amd64 manifest получены два Cosign signature
   payload. Их layer digests и manifest subjects совпали.
   Payload содержит image digest и, во второй подписи, версию kpromo;
   source/module-version mapping в этих payload нет. Корректные
   `sha256-<digest>.att` endpoints вернули 404, OCI referrers endpoints
   вернули пустые manifests. Это наблюдение только для проверенных
   digest/endpoints, не утверждение об отсутствии любых upstream attestations.

## Почему tag-to-version замена не принята

[go.work при embedded revision](https://raw.githubusercontent.com/kubernetes/kubernetes/bb826b1d48562f110659e64e8ec444327433db95/go.work)
включает staging modules как workspace main modules.
[go.mod того же revision](https://raw.githubusercontent.com/kubernetes/kubernetes/bb826b1d48562f110659e64e8ec444327433db95/go.mod)
заменяет их на локальные source paths. По
[официальной модели Go workspaces](https://go.dev/ref/mod#workspaces)
main modules не получают версию из имени релиза контейнера.

Проверен конкретный контрпример для побайтового отождествления:
официальный tag `kubernetes/apimachinery v0.36.4` указывает через tag object
`7fc5b2cc3c5bfb45b3057d3dca06e47510919c82` на commit
`612c0eced3341bcb6be9f19fb99d5b79cb4cd617`.

- [Фактический staging go.mod](https://raw.githubusercontent.com/kubernetes/kubernetes/bb826b1d48562f110659e64e8ec444327433db95/staging/src/k8s.io/apimachinery/go.mod):
  SHA-256 `85021a42db4c17d309ceb4bc7efca3dfcfc8ba1551e67b1c676725f7fd344d5e`,
  зависимость `k8s.io/streaming v0.0.0` с локальным `replace`.
- [Опубликованный module go.mod](https://raw.githubusercontent.com/kubernetes/apimachinery/612c0eced3341bcb6be9f19fb99d5b79cb4cd617/go.mod):
  SHA-256 `c971284af7ffc5c90b9a6405ae5d38fe92f2e0e9bb7cf38d7c1ed7bb78ae8380`,
  зависимость `k8s.io/streaming v0.36.4`, локального `replace` нет.

Различие manifests само по себе **не доказывает различие compiled Go code**.
Но простой tag lookup не доказывает равенство всех compiler inputs и
dependency bindings. Полное такое соответствие для 27 модулей не установлено.
Release/source SBOM даёт файловую provenance-цепочку; он не является готовой
таблицей scanner-compatible версий этих workspace modules.

Для безопасного повышения application coverage недостаёт:

1. Проверенной trusted publisher chain для используемой release/source provenance.
2. Полной привязки каждого workspace module к конкретной опубликованной версии
   с проверкой compiler inputs и учётом publishing transformations, либо
   поддерживаемого сканером способа оценить точную source identity без
   выдуманной semantic version. Наличие `vcs.revision` не заменяет эту связь.
3. Реального дополнительного scan, который оценивает эти dependency identities
   и сохраняет исходные findings. Static source mapping не доказывает
   обнаружение уязвимостей.

Текущие [diagnose](../../scripts/image_kubernetes_inventory.py),
[audit](../../scripts/image_audit.py) и [coverage](../../scripts/image_scope.py)
оставлены без изменений. `High`, `Unknown` и запрет exceptions не ослаблены.
Новый status-only production wrapper не добавлен.

## Exact source identities

Все paths имеют вид `staging/src/<module>` в
`kubernetes/kubernetes@bb826b1d48562f110659e64e8ec444327433db95`.
Git tree IDs получены из official GitHub contents API по этому revision;
побайтовые SHA-256 `go.mod` отдельно сверены с source SBOM.
Это не новые версии пакетов для scanner input.

| Module | Git tree ID | go.mod SHA-256 |
|---|---|---|
| `k8s.io/api` | `86808dcba9d03b96914029e14f2d3f91c24a6cb9` | `28a40703ee2097ed5344b2d9cd66a72d56047510851c7b92949daeda679d88f0` |
| `k8s.io/apiextensions-apiserver` | `5e4d78c3e733273f8e2ef12f8571d24bb8870b2e` | `e8de88e9292d67369ce1c60e5311dcf6043f03c66c920b0fbafc733cc80353fd` |
| `k8s.io/apimachinery` | `31058064f5fee5f2a5316101418f4541634eced4` | `85021a42db4c17d309ceb4bc7efca3dfcfc8ba1551e67b1c676725f7fd344d5e` |
| `k8s.io/apiserver` | `3710fda3b1a0669636b6c2348d82eb62a613fb29` | `fb36fe4fe31260cf6b35f1d7637fa962bf82b37f5961cf4ffdff7bf9738205ab` |
| `k8s.io/client-go` | `a99224c7423d131e07272a0556b8876e17e17886` | `f0b8f274f08f76dd5e33346425309a378e46b6aa0aed952b829c70eba0945129` |
| `k8s.io/cloud-provider` | `6e603024fb238bb9c5735b34b1e56326651382b2` | `c2f4de14af3a75ff65219b067cc07d3c82281c9769890f876ad9ce3936bad629` |
| `k8s.io/cluster-bootstrap` | `69e89cac2e89945db452348cbaf11977d93ddefd` | `57ee942e497c60008c974750e836dacdc460b6121fcf839e801694b5361138da` |
| `k8s.io/component-base` | `c72820b6a5aa872eec11a232ddf5b91447811ceb` | `8a30039637d0cd595bfd38848f502eb35aa74c8dadeb0a429dc77274a5489daa` |
| `k8s.io/component-helpers` | `e02e4646a710dbcfb6383cbd7cc4b1547cc2e905` | `8a223393b9e80158f88a83e3af9f19317c5dc3ac6348f5b665dc3369fdca2b40` |
| `k8s.io/controller-manager` | `35d328adb09c5ddb0e656807ee00a06fa7ee4130` | `91a5a56c70b6478fb3914ade262c1b48e0f3f58db23e751e3ad9daafa7aeee2e` |
| `k8s.io/cri-api` | `510e5e7bcf625e1e017011e6e76b670822ab3503` | `3ce2e855c46699cd418ff87da9fdbddde412fb0883c71414857aced5ba3d25e6` |
| `k8s.io/cri-client` | `36ffd12d5f095a79e815b89e61df98eeaadd2310` | `096c9c8e23e2816cb1d0ae8183afae531923d706883389d3bbe50c6fcc0c98ee` |
| `k8s.io/csi-translation-lib` | `270258a845d46567f6de60113801270b71050658` | `7995fb322c804c0494dadef87dc2654450f5a7fb314a00ac93961a2d48eeb54c` |
| `k8s.io/dynamic-resource-allocation` | `ab84622eea15977bc1d40e97d74a0051695d6a29` | `b896d320de62de593b28242d5ee67e68289c3580863267976a9eea133a47b7f0` |
| `k8s.io/endpointslice` | `eae360ed63df96b92b0ced318cd07ff6349d2cc1` | `dd72d255cf3f9cd332e3fc8993ea97373d209996f49731a67738c8353cfd2f59` |
| `k8s.io/externaljwt` | `aa58f2c931225109d912df9e3a0406838e259c6c` | `6381fc7bf23dd04cd0ef649d38d4c54806191d81be6b56928f1191e2e553b79f` |
| `k8s.io/kms` | `5d14016add45e599f03aabe03cfa94d217446956` | `1e01ea46a969e23d0a8dfd05ed02ffa64cd2fc6e5130afed1a832810408e7f88` |
| `k8s.io/kube-aggregator` | `e498b2a8956f38b7c4a04df9a1493fe319b00a3b` | `10209c4cfe0b0a676910d290018a8b8b44e3e7668afffc56864edcf48d702efe` |
| `k8s.io/kube-controller-manager` | `2c61e1c3e80e67bffc195221c392f78833ef0e42` | `18048a64d5c53a9a178fe5939957699fa5fcebe538948f107dff3ecd220fe34f` |
| `k8s.io/kube-proxy` | `1eb5bf0dff7be4bb884fdb9280e6f3c3b4b2c73f` | `3310f1069a10ffd86cbd946a30b8d751e1c630b1bf8bfed544a0f4a2440e1e3e` |
| `k8s.io/kube-scheduler` | `9b537f004dfb9caf4dd3a010c36dcc6007aab3ec` | `ef0d5a554a5c6f18831703169247e090a486963532151b9aacbc4b41b6487457` |
| `k8s.io/kubectl` | `0977720b9dbe26c0d7fcbe4cdb457691d4700342` | `1b4a0d7bcec36f94ad99d021e950ad4290dd5edaae67bbcea2a19d49c37ea32d` |
| `k8s.io/kubelet` | `263203dfc617a5311edb14815fa042ac9f15ce99` | `cc56d5e5f41a189f9d29e54d932904b5b2aea6457a266bcde71fdb49ae430374` |
| `k8s.io/metrics` | `cefeca5a3ce9224434232256ca982199c5ad8981` | `feda5f8c071f4b69f8ac73b01070edfbc7d454f9c76eb0fa549ac195623f8547` |
| `k8s.io/mount-utils` | `068b5931f7a5e89fb120bf82d6b2be3e6abf3954` | `6cddc87aa10c04abfc2de596bb54404be83ea1b5b3459948b18842549f65a414` |
| `k8s.io/pod-security-admission` | `f9a4254fbc0480b54973c289ef5281c7a32ab669` | `faae3e68081d7f1d59ac75eafc322cb42658a36e28f2985b52d5dcd8a61b12e4` |
| `k8s.io/streaming` | `0b66fca8054536d5000fe182aa51490ba90ca4e7` | `98afd05003f304a2d09941fc5cc2b950a3e1dab178897d7788b749aa55e71469` |

## Воспроизведение и отрицательные проверки

Приватный пакет этой проверки находится в own worktree,
`.runtime/kubernetes-provenance/`: network receipts, официальные manifests,
release/source SBOM, supplied signatures/certificates,
`check_evidence.py` и `provenance-assessment.json`.
Первичная экстракция остаётся в sibling worktree
`r1-b02-kubernetes-inventory/.runtime/kubernetes-image-evidence/`.
Эти локальные inputs нужны для повторного запуска; они не включены в commit.
Raw runner logs и сертификаты не публикуются этим изменением.

Из корня provenance worktree с ранее закреплённым Python:

```text
python .runtime/kubernetes-provenance/check_evidence.py
python -m unittest scripts.image_package_observation_qualification
python scripts/check_docs.py
```

Offline evidence check подтверждает 27 unique modules / 96 instances и
15 отрицательных проверок: две изменённые signed payload, четыре изменённых
source manifests, восемь подстановок `v0.36.4`/`v0.0.0` в реальные inventories,
одно ошибочное отождествление published и staging `apimachinery go.mod`.
Этот результат не заменяет trusted signature verification или native scan.
Inventory qualification: 11 unit methods pass. Проверка документации и
`git diff --check` выполняются перед публикацией evidence commit.

Никаких локальных Docker/WSL/Kubernetes/SQL, внешних моделей, платных сервисов
или subagents в этой итерации не использовалось.
