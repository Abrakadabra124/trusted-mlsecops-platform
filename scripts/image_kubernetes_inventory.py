"""Independent Kubernetes inventory evidence; unresolved modules never grant coverage.

Registry manifests, config and compressed/uncompressed layers were SHA-256 checked.
Raw Go build info and dpkg records were compared to runtime run 43623592528.
The scanner projection retains UNKNOWN and its VCS-derived main-module pseudo-version;
it does not replace (devel) with a Kubernetes image tag or a guessed module release.
"""

from mlsecops.contracts import canonical, digest


def diagnose(observation):
    """Explain independently confirmed missing versions without granting coverage."""
    if not isinstance(observation, dict) or not isinstance(observation.get("image_id"), str):
        return None
    spec = INVENTORIES.get(observation.get("image_id"))
    if spec is None:
        return None
    result = {
        "status": "inconclusive",
        "scope": "independent-inventory-not-application-coverage",
        "component": spec["component"],
        "independent_registry_manifest": spec["manifest_digest"],
        "image_config_id": observation["image_id"],
        "independent_rows_sha256": spec["independent_rows_sha256"],
        "independent_inventory_verified": False,
        "reason": "image_audit_kubernetes_inventory_mismatch",
    }
    try:
        if observation.get("distro") != spec["distro"]:
            return result
        rows = []
        for package in observation["packages"]:
            paths = package["paths"]
            if package["type"] == "go-module":
                if (
                    package["foundBy"] != "go-module-binary-cataloger"
                    or len(paths) != 1
                    or paths[0] not in spec["binary_paths"]
                ):
                    return result
                location = paths[0]
            else:
                location = f"/var/lib/dpkg/status.d/{package['name']}"
                if (
                    package["type"] != "deb"
                    or package["foundBy"] != "dpkg-db-cataloger"
                    or location not in paths
                ):
                    return result
            rows.append([package["type"], package["name"], package["version"], location])
        if (
            len(rows) == spec["package_count"]
            and digest(canonical(sorted(rows))) == spec["scanner_rows_sha256"]
        ):
            result.update(
                independent_inventory_verified=True,
                reason="image_audit_kubernetes_module_versions_unresolved",
                package_count=spec["package_count"],
                unversioned_module_instances=spec["unversioned_module_instances"],
            )
    except (KeyError, TypeError, AttributeError):
        pass
    return result


INVENTORIES = {
    "sha256:b0f70fa6ec47eb5682e7030c5799ea8ba42e52f5e7ea24f0f46bd9e8170b183c": {
        "component": "kube-apiserver",
        "manifest_digest": "sha256:feb6509b541379d76b37cf6e7a5c1e3767458f7468288525f75574672fee1b18",
        "distro": {"id": "debian", "versionID": "12.14"},
        "binary_paths": ["/go-runner", "/usr/local/bin/kube-apiserver"],
        "package_count": 138,
        "unversioned_module_instances": 27,
        "independent_rows_sha256": "86d6f5066d882db2a0de7a7bc23192c6c9197fbef132bc5ed6621aa93c516084",
        "scanner_rows_sha256": "d8e6b17b3339aab12bdebd7ffbfc055f2c6c74f77cbd8a98b48c607b668a7e84",
        "binary_materials": [
            {
                "path": "/go-runner",
                "sha256": "293178fba9c9d3ff52025fbbcba0b2e2a357a10efc93dcc390dd12b7ce63d891",
                "go_version": "go1.26.5",
            },
            {
                "path": "/usr/local/bin/kube-apiserver",
                "sha256": "90939ee07af61ac3701c665647f9ce27f2f988f5c7fff406aa5794fd3e6328a6",
                "go_version": "go1.26.5",
            },
        ],
    },
    "sha256:c27613cea70f9808cc25955886c764ad38de589a9faeb2a8341cb27af6714684": {
        "component": "kube-controller-manager",
        "manifest_digest": "sha256:ff4b86d6ed3cb2a8ef22c2fea31054bdc16099e583c343aabf3d54d212480c8e",
        "distro": {"id": "debian", "versionID": "12.14"},
        "binary_paths": [
            "/go-runner",
            "/usr/local/bin/kube-controller-manager",
            "/usr/local/bin/kube-log-runner",
        ],
        "package_count": 165,
        "unversioned_module_instances": 31,
        "independent_rows_sha256": "8d0550194b8e4b5ffb7b5a4a530693ed45892a55c46f8d148738f89e95acfb4a",
        "scanner_rows_sha256": "7f340e1a0642035f112f70b222c1c8b0009487e35f9709fb0ccfdb4d5ee20663",
        "binary_materials": [
            {
                "path": "/go-runner",
                "sha256": "293178fba9c9d3ff52025fbbcba0b2e2a357a10efc93dcc390dd12b7ce63d891",
                "go_version": "go1.26.5",
            },
            {
                "path": "/usr/local/bin/kube-controller-manager",
                "sha256": "ddde92e0dd14e5a01c3b178b235a85c71d531f2f344eb519500c1032f0a0d234",
                "go_version": "go1.26.5",
            },
            {
                "path": "/usr/local/bin/kube-log-runner",
                "sha256": "293178fba9c9d3ff52025fbbcba0b2e2a357a10efc93dcc390dd12b7ce63d891",
                "go_version": "go1.26.5",
            },
        ],
    },
    "sha256:a5280d36e1aa3602794efd60dc157d55bbd1bed8f755b5c12e0a6ca5dce9d3bd": {
        "component": "kube-proxy",
        "manifest_digest": "sha256:70f5e02ebce27a7a3b1bc9b164f64e1982acf46f4ed68348c9a7b94a43d6d014",
        "distro": {"id": "debian", "versionID": "12.14"},
        "binary_paths": [
            "/go-runner",
            "/usr/local/bin/kube-log-runner",
            "/usr/local/bin/kube-proxy",
        ],
        "package_count": 159,
        "unversioned_module_instances": 19,
        "independent_rows_sha256": "c49280db017fa6406dcf5e94a3d8799fd0d6e913ad519b083b1193a671268db0",
        "scanner_rows_sha256": "885b6b2a3978f0c1712136a3ac59811aa765e1fb7cc7f92d7abc327b31600064",
        "binary_materials": [
            {
                "path": "/go-runner",
                "sha256": "293178fba9c9d3ff52025fbbcba0b2e2a357a10efc93dcc390dd12b7ce63d891",
                "go_version": "go1.26.5",
            },
            {
                "path": "/usr/local/bin/kube-log-runner",
                "sha256": "293178fba9c9d3ff52025fbbcba0b2e2a357a10efc93dcc390dd12b7ce63d891",
                "go_version": "go1.26.5",
            },
            {
                "path": "/usr/local/bin/kube-proxy",
                "sha256": "74cb03e6251ae711a9363c27d1050f5106cc71ecc3334722cf9c29404638cf7a",
                "go_version": "go1.26.5",
            },
        ],
    },
    "sha256:11ce0d8bbc73b7c08c30bb040fac58fac8ba3405b92b85451b643ee1c08dcd9f": {
        "component": "kube-scheduler",
        "manifest_digest": "sha256:883d4d505bf015f73cea8bfead8b9d9d1ec3a9f19bcad6c004f929d666102c2a",
        "distro": {"id": "debian", "versionID": "12.14"},
        "binary_paths": [
            "/go-runner",
            "/usr/local/bin/kube-log-runner",
            "/usr/local/bin/kube-scheduler",
        ],
        "package_count": 126,
        "unversioned_module_instances": 19,
        "independent_rows_sha256": "1ee1fba94fe880a8d2923fa8428bc60cf9c9d371950a07b8c26625e3d83a7d86",
        "scanner_rows_sha256": "86e25a319010367b59dc5794ef4ca9f2a762e9ddd8fadb383f8ff542f2eca7c7",
        "binary_materials": [
            {
                "path": "/go-runner",
                "sha256": "293178fba9c9d3ff52025fbbcba0b2e2a357a10efc93dcc390dd12b7ce63d891",
                "go_version": "go1.26.5",
            },
            {
                "path": "/usr/local/bin/kube-log-runner",
                "sha256": "293178fba9c9d3ff52025fbbcba0b2e2a357a10efc93dcc390dd12b7ce63d891",
                "go_version": "go1.26.5",
            },
            {
                "path": "/usr/local/bin/kube-scheduler",
                "sha256": "6ffbffcc6d57990b86a7ac4a547ad3e75b2c28cc901964f99bd13ffb304d2373",
                "go_version": "go1.26.5",
            },
        ],
    },
}
