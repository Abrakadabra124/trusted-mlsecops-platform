import subprocess
import sys

from mlsecops import audit_snapshot
from mlsecops.contracts import Rejected, canonical, decode, require_fields


def scan(payload, *, private=()):
    if type(payload) is not bytes or not 1 <= len(payload) <= 4096:
        raise Rejected("audit_export_probe_bytes")
    value = decode(payload, 4096)
    require_fields(
        value,
        (
            "schema_version",
            "scope",
            "status",
            "release_ready",
            "events",
            "requests",
            "routes",
            "context_kinds",
        ),
    )
    if (
        canonical(value) + b"\n" != payload
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["scope"] != "serving-audit-public-window-not-full-M13"
        or value["release_ready"] is not False
        or type(value["events"]) is not int
        or not 1 <= value["events"] <= 65536
        or any(needle in payload for needle in private)
    ):
        raise Rejected("audit_export_probe_schema")
    for field, names in (
        ("requests", ("completed", "aborted", "unresolved")),
        ("routes", ("predict", "ready")),
        ("context_kinds", ("release-selection", "candidate-qualification", "none")),
    ):
        require_fields(value[field], names)
        if any(
            type(count) is not int or not 0 <= count <= 16384 for count in value[field].values()
        ):
            raise Rejected("audit_export_probe_counts")
    total = sum(value["requests"].values())
    expected = "inconclusive" if value["requests"]["unresolved"] else "pass"
    completed, aborted, unresolved = (
        value["requests"][name] for name in ("completed", "aborted", "unresolved")
    )
    extra_intents = max(0, total - value["context_kinds"]["none"] - completed - unresolved)
    if (
        not 1 <= total <= 16384
        or not total <= value["events"] <= 4 * (completed + aborted) + 3 * unresolved
        or value["events"] < 4 * completed + 2 * aborted + unresolved + extra_intents
        or total != sum(value["routes"].values())
        or total != sum(value["context_kinds"].values())
        or value["status"] != expected
    ):
        raise Rejected("audit_export_probe_accounting")
    return value


def exercise(path):
    before = audit_snapshot.read_closed(path)
    events = [decode(line)["event"] for chunk in before for line in chunk.splitlines()]
    identities, contexts, needles = {}, {}, set()
    terminals = {"completed": 0, "aborted": 0, "unresolved": 0}
    for event in events:
        identifier = event["request_id"]
        identities[identifier] = event["route"]
        needles.update((identifier.encode(), event["principal_id"].encode()))
        if event["context"] is not None:
            contexts[identifier] = event["context"]["kind"]
            needles.update(
                value.encode()
                for name, value in event["context"].items()
                if name.endswith("_sha256")
            )
            needles.update(value.encode() for value in event["context"].get("lineage", {}).values())
        if event["stage"] in ("response_completed", "aborted"):
            terminals["completed" if event["stage"] == "response_completed" else "aborted"] += 1
    result = subprocess.run(
        [sys.executable, "-m", "mlsecops.audit_export", "--spool", str(path)],
        capture_output=True,
        check=False,
        timeout=15,
    )
    if result.returncode != 0 or result.stderr:
        raise Rejected("audit_export_probe_cli")
    value = scan(result.stdout, private=needles)
    routes = {name: list(identities.values()).count(name) for name in ("predict", "ready")}
    kinds = {
        name: list(contexts.values()).count(name)
        for name in ("release-selection", "candidate-qualification")
    }
    kinds["none"] = len(identities) - len(contexts)
    if (
        not needles
        or value["events"] != len(events)
        or value["requests"] != terminals
        or value["routes"] != routes
        or value["context_kinds"] != kinds
        or value["status"] != "pass"
        or before != audit_snapshot.read_closed(path)
    ):
        raise Rejected("audit_export_probe_source")
    return value
