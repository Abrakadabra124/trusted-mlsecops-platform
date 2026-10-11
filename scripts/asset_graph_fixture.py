import json

from mlsecops.contracts import canonical, digest

OWNERS = ["data-owner", "ml-owner", "platform-owner"]
ENVIRONMENT = "local-cpu"


def fixture():
    assets = []

    def add(asset_id, kind, owner, dependencies=()):
        assets.append(
            {
                "asset_id": asset_id,
                "kind": kind,
                "sha256": digest(f"synthetic-fixture:{asset_id}".encode()),
                "owner": owner,
                "environment": ENVIRONMENT,
                "dependencies": [
                    {"asset_id": name, "sha256": by_id[name]["sha256"]} for name in dependencies
                ],
            }
        )
        by_id[asset_id] = assets[-1]

    by_id = {}
    for name in ("dataset-a", "dataset-b"):
        add(name, "dataset", "data-owner")
    add("runtime-shared", "runtime", "platform-owner")
    add("policy-shared", "policy", "platform-owner")
    for suffix, dataset in (
        ("a-current", "dataset-a"),
        ("a-previous", "dataset-a"),
        ("b", "dataset-b"),
    ):
        add(f"run-{suffix}", "run", "ml-owner", (dataset, "runtime-shared", "policy-shared"))
        add(f"model-{suffix}", "model", "ml-owner", (f"run-{suffix}",))
        add(
            f"release-{suffix}",
            "release",
            "platform-owner",
            (f"model-{suffix}", "runtime-shared", "policy-shared"),
        )
    deployments = {
        "deployment-a-primary": "a-current",
        "deployment-a-canary": "a-current",
        "deployment-a-rollback": "a-previous",
        "deployment-b": "b",
    }
    for deployment, suffix in deployments.items():
        add(deployment, "deployment", "platform-owner", (f"release-{suffix}",))
    graph = {"schema_version": 1, "assets": assets}
    snapshot = {
        "schema_version": 1,
        "environment": ENVIRONMENT,
        "graph_sha256": digest(canonical(graph)),
        "deployments": [
            {
                "asset_id": name,
                "sha256": by_id[name]["sha256"],
                "release_sha256": by_id[f"release-{suffix}"]["sha256"],
                "model_sha256": by_id[f"model-{suffix}"]["sha256"],
                "runtime_sha256": by_id["runtime-shared"]["sha256"],
                "policy_sha256": by_id["policy-shared"]["sha256"],
            }
            for name, suffix in deployments.items()
        ],
    }
    revoked = [{"asset_id": "dataset-a", "sha256": by_id["dataset-a"]["sha256"]}]
    return graph, snapshot, revoked


def main():
    from mlsecops.asset_graph import assess

    graph, snapshot, revoked = fixture()
    result = assess(graph, OWNERS, ENVIRONMENT, snapshot, revoked)
    print(json.dumps({"synthetic_fixture": True, **result}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
