"""Retain the owners' hosted source campaigns and replay their signed records offline."""

from collections import Counter
from pathlib import Path

from mlsecops import security_events as events
from mlsecops import security_identity_evidence as identity
from mlsecops import security_intake_evidence as intake
from mlsecops import security_trust_evidence as trust
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    safe_child,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.security_event_config import Registry
from mlsecops.security_event_ledger import Ledger
from mlsecops.trust_acceptance import materials
from scripts import security_event_sequence_native as sequence
from scripts import security_identity_events_native as identity_native
from scripts import security_source_campaign as intake_native
from scripts import security_trust_service_native as trust_native

CHECKOUT = Path(__file__).resolve().parents[1]
MAX_BYTES = 4 * 1024 * 1024
KINDS = {
    "artifact.rejected",
    "worker.policy_violation",
    "identity.denied",
    "trust.revoked",
    "telemetry.gap",
}


def _require(condition):
    if not condition:
        raise Rejected("M23_source_evidence_binding")


def _paths(root, state):
    root, state = Path(root).resolve(), Path(state).absolute()
    _require(state == root / ".runtime" and state.resolve() == state)
    return root, state


def _source(root):
    _require(not command(["git", "-C", str(root), "status", "--porcelain"]))
    revision = events.hexadecimal(command(["git", "-C", str(root), "rev-parse", "HEAD"]), 40)
    methods = materials(root)
    return dict(
        source=revision,
        fingerprint=source_fingerprint(root),
        methods_sha256=digest(canonical(methods)),
    ), methods


def _trust_files(state):
    return set(safe_child(state, "evidence").glob("trust-service-*.primary.json"))


def capture(root, state):
    """The gate owner must persist and pin this manifest at the end of the stage."""
    root, state = _paths(root, state)
    _require(root == CHECKOUT)
    source, _ = _source(root)
    cases = []

    def run(name, native, *fields):
        report = native.qualify()
        _require(
            type(report) is dict
            and report.get("status") == "pass"
            and report.get("release_ready") is False
            and report.get("source") == source["source"]
            and report.get("fingerprint") == source["fingerprint"]
        )
        cases.extend(_case_ids(name, report.get("cases")))
        return {field: events.hexadecimal(report.get(field)) for field in fields}

    manifest = dict(schema_version=1, source=source)
    pair = ("primary_sha256", "binding_sha256")
    manifest["intake"] = run("intake", intake_native, *pair, "primary_file_sha256")
    manifest["identity"] = run("identity", identity_native, *pair)
    before = _trust_files(state)
    manifest["trust"] = run("trust", trust_native, *pair)
    added = _trust_files(state) - before
    _require(len(added) == 1)
    run_id = added.pop().name.removeprefix("trust-service-").removesuffix(".primary.json")
    manifest["trust"]["run_id"] = events.hexadecimal(run_id, 32)
    # The first owner's result is the external anchor for both sequence registries.
    manifest["sequence"] = run("sequence", sequence, "primary_sha256")
    _require(replay(root, state, manifest)["cases"] == cases)
    return manifest


def _read(state, name, pin, hashes, *, newline=False):
    events.hexadecimal(pin)
    raw = bounded_read(safe_child(state, name), MAX_BYTES)
    _require(digest(raw) == pin)
    document = decode(raw, MAX_BYTES)
    _require(raw == canonical(document) + (b"\n" if newline else b""))
    hashes[name] = pin
    return document


def _pair(state, path, binding_path, pins, hashes, *, newline=False):
    file_pin = pins["primary_file_sha256"] if newline else pins["primary_sha256"]
    owner = _read(state, binding_path, pins["binding_sha256"], hashes, newline=newline)
    packet = _read(state, path, file_pin, hashes, newline=newline)
    return packet, owner


def _expected(owner, primary_pin, **checks):
    events.shape(owner, ("expected", "primary_sha256"))
    _require(owner["primary_sha256"] == primary_pin)
    expected = owner["expected"]
    _require(all(expected[key] == value for key, value in checks.items()))
    return expected


def _registry(state, root, pin):
    authority = state["registry"]
    return Registry(
        authority["envelope"],
        trusted_root=root,
        expected_sha256=pin,
        clock_ms=authority["clock_ms"],
    )


def _measure(registry, event, record, routes):
    receipt = registry.receipt(record["receipt"], event)
    kind = event.document()["kind"]
    routes[kind] = max(routes.get(kind, 0), receipt["routed_at_ms"] - receipt["ingested_at_ms"])


def _case_ids(name, cases):
    _require(type(cases) is list)
    seen = Counter()
    result = []
    for case in cases:
        seen[case] += 1
        suffix = "" if seen[case] == 1 else ":" + str(seen[case])
        result.append(f"{name}:{case}{suffix}")
    return result


def _intake(root, state, pins, current, methods, hashes, routes):
    events.shape(pins, ("primary_sha256", "primary_file_sha256", "binding_sha256"))
    packet, owner = _pair(
        state,
        "evidence/security-source-private.json",
        "evidence/security-source-private.bindings.json",
        pins,
        hashes,
        newline=True,
    )
    expected = _expected(
        owner,
        pins["primary_file_sha256"],
        **current,
        materials=methods,
        transport="owned-linux-http",
        policy_sha256=digest(canonical(read_json(root / "policies/local-cpu.json"))),
    )
    report = intake.verify(packet, expected=expected)
    _require(report["primary_sha256"] == pins["primary_sha256"])
    for measurement in report["events"]:
        kind = measurement["kind"]
        routes[kind] = max(routes.get(kind, 0), measurement["delivery_ms"])
    return report["cases"]


def _identity(state, pins, current, methods, hashes, routes):
    events.shape(pins, ("primary_sha256", "binding_sha256"))
    base = "security-identity-primary/" + events.hexadecimal(pins["primary_sha256"])
    packet, owner = _pair(state, base + ".json", base + ".bindings.json", pins, hashes)
    expected = _expected(
        owner,
        pins["primary_sha256"],
        **current,
        method_materials={key: methods[key] for key in identity.METHOD_FILES},
    )
    report = identity.verify(packet, expected=expected)
    delivery = packet["delivery"]
    registry = _registry(delivery, expected["registry_root"], expected["registry_sha256"])
    for record in delivery["collector"]["records"]:
        event = registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"])
        _measure(registry, event, record, routes)
    return report["cases"], report["stopped_producer_notice_seconds"]


def _trust(state, pins, current, methods, hashes, routes):
    events.shape(pins, ("primary_sha256", "binding_sha256", "run_id"))
    base = "evidence/trust-service-" + events.hexadecimal(pins["run_id"], 32)
    packet, owner = _pair(state, base + ".primary.json", base + ".binding.json", pins, hashes)
    _require(
        owner["expected_source"] == current["source"]
        and owner["expected_fingerprint"] == current["fingerprint"]
        and owner["expected_materials"] == {key: methods[key] for key in trust.METHOD_FILES}
    )
    report = trust.verify(packet, **owner)
    delivery = packet["stages"][-1]["state"]
    registry = _registry(delivery, owner["expected_registry_root"], owner["expected_registry_pin"])
    queue = delivery["outboxes"][0]
    clock = delivery["registry"]["clock_ms"]
    problems = Ledger(registry, delivery["collector"]).poll(clock_ms=clock)["problems"]
    (notice_id,) = (
        p["notice_id"]
        for p in problems
        if p["reason"] == "heartbeat" and p["producer_id"] == queue["producer_id"]
    )
    # Only the two outbox revocations and this stopped producer's scheduled gap count.
    for row in queue["records"]:
        event = registry.verify(row["envelope"], clock_ms=row["queued_at_ms"])
        _measure(registry, event, row, routes)
    for record in delivery["collector"]["records"]:
        event = registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"])
        body = event.document()
        if body["kind"] == "telemetry.gap" and body["asset_sha256"] == notice_id:
            _measure(registry, event, record, routes)
    return report["cases"], report["stopped_source_notice_seconds"]


def _sequence(state, pins, current, hashes, routes):
    events.shape(pins, ("primary_sha256",))
    packet = _read(state, "evidence/security-sequence-private.json", pins["primary_sha256"], hashes)
    report = sequence.verify(
        packet, expected_source=current["source"], expected_fingerprint=current["fingerprint"]
    )
    for mode in packet["modes"]:
        # The externally pinned packet binds both mode authorities before verification.
        record = mode["captures"]["noticed"]["state"]["records"][-1]
        registry = Registry(
            mode["registry"],
            trusted_root=mode["registry_root"],
            expected_sha256=mode["registry_sha256"],
            clock_ms=record["ingested_at_ms"],
        )
        event = registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"])
        _measure(registry, event, record, routes)
    return report["cases"], {
        mode: report["timings"][mode]["notice_seconds"] for mode in sequence.MODES
    }


def replay(root, state, manifest):
    """Replay only with a manifest already authenticated by the caller's stage digest."""
    root, state = _paths(root, state)
    events.shape(manifest, ("schema_version", "source", "intake", "identity", "trust", "sequence"))
    events.version(manifest["schema_version"])
    source, methods = _source(root)
    _require(source == manifest["source"])
    current = dict(source=source["source"], fingerprint=source["fingerprint"])
    hashes, routes = {}, {}
    try:
        intake_cases = _intake(root, state, manifest["intake"], current, methods, hashes, routes)
        identity_cases, identity_notice = _identity(
            state, manifest["identity"], current, methods, hashes, routes
        )
        trust_cases, trust_notice = _trust(
            state, manifest["trust"], current, methods, hashes, routes
        )
        sequence_cases, notices = _sequence(state, manifest["sequence"], current, hashes, routes)
        cases = [
            *_case_ids("intake", intake_cases),
            *_case_ids("identity", identity_cases),
            *_case_ids("trust", trust_cases),
            *_case_ids("sequence", sequence_cases),
        ]
        _require(routes.keys() == KINDS and len(cases) == len(set(cases)))
        return dict(
            cases=cases,
            routes=routes,
            sequence_notice_seconds=notices,
            heartbeat_notice_seconds=max(identity_notice, trust_notice),
            artifact_hashes=hashes,
        )
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise Rejected("M23_source_replay_invalid") from error
