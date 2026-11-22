"""One immutable etcd proposal; never replaces the deployed baseline.

The three binary buildinfo records were extracted from verified OCI layers.
GO-2026-6860 is fixed by golang.org/x/net v0.62.0 according to vuln.go.dev.
These pins prepare an additional native scan, not compatibility or audit acceptance.
"""

BASELINE_CONFIG = "sha256:a17708350060c02414f0ecd9a0afd44404df2e4ed8cc9726a3a9c5776b40645e"
NAME = "etcd-xnet-candidate"
REFERENCE = (
    "registry.k8s.io/etcd@sha256:3ced7fbdc4cadcec31ab34a7513bc97be2b70db923e7154e2d88a980016b5e8b"
)
CONFIG = "sha256:be2dd319600bac16f542b8e46e1b78511c35a31e46829ee9acc82a83c94aa377"
EVIDENCE = {
    "upstream_release": "https://github.com/etcd-io/etcd/releases/tag/v3.6.17",
    "registry_tag_observed": "3.6.17-0",
    "advisory": "https://vuln.go.dev/ID/GO-2026-6860.json",
    "advisory_sha256": "443304c129b9540dc46d28392b973a136db90644019dc20c3e25941833d49df3",
    "baseline_run": "43625404562",
    "baseline_source": "f3b31b453065c9669aee7689e6ef8fc0e6d9b10c",
    "package": "golang.org/x/net",
    "baseline_version": "v0.61.0",
    "extracted_candidate_version": "v0.62.0",
    "go_version": "go1.26.11",
    "binaries": {
        "/usr/local/bin/etcd": {
            "sha256": "b185e71ff67f3f35661fea57967bca11225b3e6268288fccae0cf5d23aecf8c8",
            "buildinfo_sha256": "d22982a53e033ed7d67806ff13140d945cb1baeb4ff534aca23feaee807f5d56",
        },
        "/usr/local/bin/etcdctl": {
            "sha256": "fc2721bb95ba175a550b6da208b58822c104d58b9e1659a8b0b4897f080b533c",
            "buildinfo_sha256": "816848a77fc736d07f8f229f9282d6c519b823879012ae851142605552b72c3d",
        },
        "/usr/local/bin/etcdutl": {
            "sha256": "6ed0d9dbc0cc24274461feffca5badbeed23e10144b50fe983ef86ea0b25e6cc",
            "buildinfo_sha256": "048b12bae0330405a02dd2403edb7a1f1ad4787c5488281b600658b0ba11befb",
        },
    },
}
