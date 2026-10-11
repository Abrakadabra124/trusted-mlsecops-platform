import re
from collections import Counter, defaultdict, deque

from mlsecops.contracts import Rejected, canonical, digest, require_fields

MAX_ASSETS = 1000
MAX_DEPENDENCIES = 32
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
KINDS = {"dataset", "runtime", "policy", "run", "model", "release", "deployment"}


def _name(value):
    if not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9._-]{0,95}", value) is None:
        raise Rejected("inventory_invalid_name")
    return value


def _sha256(value):
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise Rejected("inventory_invalid_digest")
    return value


def _sequence(value, maximum, minimum=0):
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise Rejected("inventory_invalid_sequence")
    return value


def _version(value, fields):
    require_fields(value, ("schema_version", *fields))
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise Rejected("inventory_unknown_schema")
    try:
        size = len(canonical(value))
    except RecursionError as error:
        raise Rejected("inventory_document_nesting") from error
    if size > MAX_DOCUMENT_BYTES:
        raise Rejected("inventory_document_too_large")


def _reference(reference, assets):
    require_fields(reference, ("asset_id", "sha256"))
    asset_id = _name(reference["asset_id"])
    expected = _sha256(reference["sha256"])
    if asset_id not in assets or assets[asset_id]["sha256"] != expected:
        raise Rejected("inventory_unknown_or_mismatched_reference")
    return asset_id


def _graph(document, owners, environment):
    _version(document, ("assets",))
    trusted_owners = [_name(owner) for owner in _sequence(owners, 128, minimum=1)]
    if len(set(trusted_owners)) != len(trusted_owners):
        raise Rejected("inventory_duplicate_owner")
    _name(environment)
    assets = {}
    for asset in _sequence(document["assets"], MAX_ASSETS, minimum=1):
        require_fields(
            asset, ("asset_id", "kind", "sha256", "owner", "environment", "dependencies")
        )
        asset_id = _name(asset["asset_id"])
        if asset_id in assets:
            raise Rejected("inventory_duplicate_asset")
        if _name(asset["kind"]) not in KINDS:
            raise Rejected("inventory_unknown_kind")
        _sha256(asset["sha256"])
        if _name(asset["owner"]) not in trusted_owners:
            raise Rejected("inventory_unknown_owner")
        if _name(asset["environment"]) != environment:
            raise Rejected("inventory_environment_mismatch")
        assets[asset_id] = asset
    dependencies = {}
    descendants = defaultdict(set)
    for asset_id, asset in assets.items():
        references = _sequence(asset["dependencies"], MAX_DEPENDENCIES)
        names = [_reference(reference, assets) for reference in references]
        if len(set(names)) != len(names):
            raise Rejected("inventory_duplicate_dependency")
        dependencies[asset_id] = names
        for name in names:
            descendants[name].add(asset_id)
    remaining = {asset_id: len(names) for asset_id, names in dependencies.items()}
    queue = deque(asset_id for asset_id, count in remaining.items() if count == 0)
    visited = 0
    while queue:
        asset_id = queue.popleft()
        visited += 1
        for descendant in descendants[asset_id]:
            remaining[descendant] -= 1
            if remaining[descendant] == 0:
                queue.append(descendant)
    if visited != len(assets):
        raise Rejected("inventory_cycle")
    required = {
        "dataset": {},
        "runtime": {},
        "policy": {},
        "model": {"run": 1},
        "release": {"model": 1, "runtime": 1, "policy": 1},
        "deployment": {"release": 1},
    }
    for asset_id, asset in assets.items():
        counts = Counter(assets[name]["kind"] for name in dependencies[asset_id])
        if asset["kind"] == "run":
            valid = counts == {"dataset": counts["dataset"], "runtime": 1, "policy": 1}
            valid = valid and counts["dataset"] > 0
        else:
            valid = counts == required[asset["kind"]]
        if not valid:
            raise Rejected("inventory_invalid_dependency_kinds")
    by_kind = {
        asset_id: {assets[name]["kind"]: name for name in names}
        for asset_id, names in dependencies.items()
    }
    for asset_id, asset in assets.items():
        if asset["kind"] == "release":
            release = by_kind[asset_id]
            run = by_kind[by_kind[release["model"]]["run"]]
            if any(run[kind] != release[kind] for kind in ("runtime", "policy")):
                raise Rejected("inventory_release_material_mismatch")
    return assets, descendants, by_kind


def _reconcile(snapshot, document, assets, by_kind, environment):
    _version(snapshot, ("environment", "graph_sha256", "deployments"))
    if _name(snapshot["environment"]) != environment or _sha256(snapshot["graph_sha256"]) != digest(
        canonical(document)
    ):
        raise Rejected("inventory_snapshot_binding_mismatch")
    observed = set()
    for record in _sequence(snapshot["deployments"], MAX_ASSETS):
        fields = (
            "asset_id",
            "sha256",
            "release_sha256",
            "model_sha256",
            "runtime_sha256",
            "policy_sha256",
        )
        require_fields(record, fields)
        asset_id = _name(record["asset_id"])
        if (
            asset_id in observed
            or asset_id not in assets
            or assets[asset_id]["kind"] != "deployment"
        ):
            raise Rejected("inventory_unknown_or_duplicate_deployment")
        observed.add(asset_id)
        release_id = by_kind[asset_id]["release"]
        expected = {
            "sha256": assets[asset_id]["sha256"],
            "release_sha256": assets[release_id]["sha256"],
            **{
                f"{kind}_sha256": assets[name]["sha256"]
                for kind, name in by_kind[release_id].items()
            },
        }
        if any(_sha256(record[field]) != value for field, value in expected.items()):
            raise Rejected("inventory_observed_digest_mismatch")
    deployments = {asset_id for asset_id, asset in assets.items() if asset["kind"] == "deployment"}
    if observed != deployments:
        raise Rejected("inventory_incomplete_observations")
    return deployments


def assess(document, trusted_owners, environment, snapshot, revoked):
    assets, descendants, by_kind = _graph(document, trusted_owners, environment)
    deployments = _reconcile(snapshot, document, assets, by_kind, environment)
    roots = [_reference(reference, assets) for reference in _sequence(revoked, MAX_ASSETS)]
    if len(set(roots)) != len(roots):
        raise Rejected("inventory_duplicate_revocation")
    aliases = defaultdict(set)
    for asset_id, asset in assets.items():
        aliases[(asset["kind"], asset["sha256"])].add(asset_id)
    impacted = set()
    queue = deque(roots)
    while queue:
        asset_id = queue.popleft()
        if asset_id in impacted:
            continue
        impacted.add(asset_id)
        asset = assets[asset_id]
        queue.extend(descendants[asset_id] - impacted)
        queue.extend(aliases.pop((asset["kind"], asset["sha256"]), set()) - impacted)
    return {
        "schema_version": 1,
        "component_status": "pass",
        "full_M19": "inconclusive",
        "release_ready": False,
        "graph_sha256": digest(canonical(document)),
        "snapshot_sha256": digest(canonical(snapshot)),
        "asset_count": len(assets),
        "revoked_assets": sorted(roots),
        "impacted_assets": sorted(impacted),
        "blocked_deployments": sorted(deployments & impacted),
        "unaffected_deployments": sorted(deployments - impacted),
    }
