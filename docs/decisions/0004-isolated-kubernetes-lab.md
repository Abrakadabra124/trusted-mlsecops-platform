# ADR 0004: отдельный Kubernetes lab

Дата: 2026-10-07. Решение принято до создания кластера. Проверяемый runtime status записывается отдельно, наличие ADR не доказывает M04-M05.

## Контекст и границы

Docker developer profile уже выполняется локально и в чистом GitHub runner: [run 37656458568](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/37656458568), commit `188884d9c0238fb31a155bafab79a1be6e115b77`, 65 component checks. В CI получена та же AUPRC; внутри каждого окружения три обучения дали одинаковые вероятности. ONNX hash между host и CI различается, точная причина без сравнения артефактов не установлена. Численное cross-host сравнение ещё не выполнено; bit-for-bit воспроизводимость не заявляется.

Для предусмотренных планом Kubernetes Jobs и identity/network probes нужен отдельный кластер. Существующие `sdp`, `kube-simulator`, registry, Git и default kubeconfig не изменяются. Это не migration исходной платформы. Новые объекты ограничены cluster `trusted-mlsecops` и namespace prefix `ml-` внутри него.

## Решение

- kind 0.33.0, Kubernetes 1.36.4 pinned image digest из upstream release; одна node, без HA.
- Cilium 1.20.2 вместо kindnet для реального enforcement NetworkPolicy. Kubernetes 1.36 входит в заявленную upstream compatibility matrix. Chart bytes фиксируются SHA-256; это integrity pin, не утверждение об independently verified publisher signature.
- API server слушает только 127.0.0.1. Kubeconfig хранится в ignored `.runtime/kubeconfig`, всегда задаётся явно вместе с context. Никакого переключения глобального context.
- Pod/service CIDR 10.78.0.0/16 и 10.79.0.0/16 не пересекаются с прочитанными Windows routes/Docker bridge. При иной сети пользователь должен проверить маршруты до bootstrap.
- Новый node ограничивается 4 CPU и 12 GiB, worker Job до 2 CPU/4 GiB/600 s. Первоначальные 8 GiB увеличены до параллельных resource probes: kind сообщает kubelet память всей VM, а не node cgroup. Поэтому отдельно действуют суммарные namespace memory quotas: train 4 GiB, evaluation 1 GiB, serving 1 GiB, control 512 MiB; requests worker равны memory limits. Это не позволяет нескольким 4 GiB workers одновременно заполнять одну namespace. Измеренные capacity Docker: 24 CPU/31.3 GiB; прежние контейнеры суммарно около 7 GiB. Bootstrap требует >=15 GiB общей памяти Docker; свободный headroom проверяется отдельно.
- Pod Security Admission `restricted` плюс собственная native ValidatingAdmissionPolicy для readonly root, отсутствия tokens и ограниченных volumes. Новый Kyverno controller для этих узких правил не нужен; исходная Kyverno foundation не удаляется и не объявляется перенесённой. Signed release admission будет отдельным этапом M10.
- Trainer/evaluator/serving имеют отдельные namespaces и ServiceAccounts без RBAC grants. Ни signing keys, ни holdout labels, ни host storage в workers не монтируются. Контроллер передаёт ограниченный gzip JSON через immutable ConfigMap, только нужные данному Job bytes. ConfigMap не является шифрованным хранилищем реальных данных.
- Egress workers по умолчанию запрещён целиком. Нет потребности скачивать зависимости во время обучения. Artifact publication выполняется вне worker. Результат извлекается контроллером из ограниченного protocol output, затем повторно валидируется.

## Остаточные риски и проверка

kind node привилегирован относительно Docker VM, CNI имеет системные privileges. Host/Docker/Kubernetes administrator остаются trusted computing base. Это не hostile multi-tenant production и не защита от kernel escape. Отдельные роли не означают независимых людей.

Проверяются реальные неуспешные API запросы с short-lived identity, admission rejects, deny egress с положительным control, отсутствие token/host/keys, read-only filesystem, deadline и OOM termination. YAML или `can-i` отдельно недостаточны. Storage service isolation и полноценный serving ещё должны быть реализованы; их нельзя закрывать canary fixtures.

## Основания

- [kind configuration](https://kind.sigs.k8s.io/docs/user/configuration/)
- [kind 0.33.0 images](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0)
- [Cilium kind installation](https://docs.cilium.io/en/stable/installation/kind/)
- [Cilium compatibility](https://docs.cilium.io/en/stable/network/kubernetes/compatibility/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/)
