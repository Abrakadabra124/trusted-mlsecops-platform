"""Durable private serving preimages and historical replay, never release authority."""

import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from mlsecops import final_evidence as final
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    require_fields,
    safe_child,
)
from mlsecops.storage import object_id
from scripts import ci_upstream_transfer as upstream
from scripts import frozen_candidate_transfer as transfer
from scripts import m18_delivery_freeze as frozen
from scripts import m18_serving_retention as serving
from scripts import serving_campaign as campaign

LIMIT = 16 * 1024**2
TOTAL = 256 * 1024**2
MAX_FILES = 384
MAX_OBJECTS = 512
SCOPE = "original-serving-primary-not-M18-acceptance"
DRAFTS = "m18-serving-drafts"


def need(value, reason):
    final.need(value, "ci-serving-retention-" + reason)


def authority(
    freeze_pin,
    freeze,
    expected,
    run_owner,
    report_pins,
    admission_pins,
    transitions,
    consumer_storage_pin,
):
    # Snapshot every caller-owned nested map before touching artifacts. The clock
    # argument validates shape only; historical evidence grants no new window.
    raw = canonical(
        dict(
            freeze_pin=freeze_pin,
            freeze=freeze,
            expected=expected,
            run_owner=run_owner,
            report_pins=report_pins,
            admission_pins=admission_pins,
            transitions=transitions,
            consumer_storage_pin=consumer_storage_pin,
        )
    )
    owner = decode(raw, final.LIMIT)
    transfer.authority(
        owner["freeze_pin"], owner["freeze"], owner["expected"], owner["run_owner"], 1
    )
    for field, gates in (("report_pins", campaign.GATES), ("admission_pins", serving.GATES)):
        require_fields(owner[field], gates)
        for pin in owner[field].values():
            object_id(pin)
    steps = owner["transitions"]
    need(type(steps) is list and len(steps) == 2, "transitions")
    for step in steps:
        require_fields(step, ("before", "after", "source_sql"))
        for side in ("before", "after"):
            require_fields(step[side], ("namespace", "volume"))
    campaign.chain(steps, owner["consumer_storage_pin"])
    return owner


def plain(path):
    path = Path(path).absolute()
    need(".." not in path.parts, "path-traversal")
    need(
        all(not p.is_symlink() and not p.is_junction() for p in (path, *path.parents)), "path-link"
    )
    return path.resolve()


def location(root, destination):
    runtime = plain(safe_child(plain(root), ".runtime"))
    path = plain(destination)
    need(path.is_relative_to(runtime), "destination-root")
    relative = path.relative_to(runtime)
    need(bool(relative.parts), "destination")
    return safe_child(runtime, relative.as_posix())


def inventory(root, reader, object_reader, owner):
    """Fixed producer paths, authenticated references, and canonical producer maps only."""
    files, objects = {}, {}

    def store(raw):
        need(type(raw) is bytes and 0 < len(raw) <= LIMIT, "object-size")
        transfer.no_credentials(raw)
        pin = digest(raw)
        objects[pin] = raw
        need(
            len(objects) <= MAX_OBJECTS and sum(map(len, objects.values())) <= TOTAL - final.LIMIT,
            "object-budget",
        )
        return pin

    def read(name, limit=LIMIT):
        raw = reader(name, min(limit, LIMIT))
        pin = store(raw)
        need(name not in files or files[name] == pin, "changed-file")
        files[name] = pin
        need(len(files) <= MAX_FILES, "file-budget")
        return raw

    closure, _, _ = transfer.checked_files(
        read, **{k: owner[k] for k in ("freeze_pin", "freeze", "expected")}
    )
    upstream._inventory(read)
    serving_files = {}

    def serving_read(name, pin=None):
        raw = read(name)
        if pin is not None:
            need(digest(raw) == object_id(pin), "serving-original-pin")
        need(name not in serving_files, "serving-file-duplicate")
        serving_files[name] = digest(raw)
        return raw

    _, retained = serving.inventory(
        root,
        serving_read,
        store,
        freeze_pin=owner["freeze_pin"],
        reports={g: owner["report_pins"][g] for g in serving.GATES},
        admissions=owner["admission_pins"],
    )
    raw = read("storage.json", final.LIMIT)
    need(digest(raw) == owner["consumer_storage_pin"], "storage-pin")
    need(raw == canonical(decode(raw)) + b"\n", "storage-json")
    refs = set(retained.values())
    for gate, pin in owner["report_pins"].items():
        raw = objects[files["evidence/" + gate + ".json"]]
        need(digest(raw) == pin, "report-pin")
        report = decode(raw)
        need(raw == canonical(report) + b"\n", "report-json")
        artifacts = report["artifact_hashes"]
        need(type(artifacts) is dict and 0 < len(artifacts) <= MAX_OBJECTS, "artifacts")
        refs.update(object_id(p) for p in artifacts.values())
    # The signed closure is already fully selected by checked_files. No CAS scan.
    refs.update(name[len(transfer.CAS) :] for name in closure if name.startswith(transfer.CAS))
    for pin in sorted(refs):
        if pin not in objects:
            need(store(object_reader(pin)) == pin, "artifact-preimage")
    record = dict(
        schema_version=1,
        scope=serving.SCOPE,
        freeze_sha256=owner["freeze_pin"],
        reports={g: owner["report_pins"][g] for g in serving.GATES},
        admissions=owner["admission_pins"],
        retained=retained,
        files=serving_files,
    )
    receipt_pin = store(canonical(record) + b"\n")
    return files, objects, receipt_pin


def verify(root, parent, files, objects, serving_pin, owner):
    with TemporaryDirectory(prefix="serving-reader-", dir=parent) as temporary:
        view = Path(temporary)
        for name, pin in files.items():
            atomic_write(safe_child(view, name), objects[pin])
        for pin, raw in objects.items():
            atomic_write(safe_child(view, transfer.CAS + pin), raw)
        index = decode(objects[owner["freeze_pin"]])
        values, _, _ = transfer.delivery.frozen(root, view, index)
        final.same(
            {k: values[k] for k in transfer.IDENTITY},
            owner["expected"],
            "serving-export-original-identity",
        )
        frozen.verify_early(
            root, view, values, {"M02": owner["report_pins"]["M02"]}, intake_only=True
        )
        frozen.verify_integrity(root, view, values, owner["report_pins"]["M03"])
        frozen.verify_evaluation(root, view, values, owner["report_pins"]["M07"])
        args = dict(
            freeze_pin=owner["freeze_pin"],
            reports={g: owner["report_pins"][g] for g in serving.GATES},
            admissions=owner["admission_pins"],
        )
        need(serving.capture(root, view, **args) == serving_pin, "capture-pin")
        primary = serving.replay(root, view, serving_pin, **args)
        receipt, _ = campaign.replay(
            root,
            view,
            pins=owner["freeze"],
            reports=owner["report_pins"],
            admissions=owner["admission_pins"],
            transitions=owner["transitions"],
            source_pin=owner["consumer_storage_pin"],
            revision=owner["expected"]["source_revision"],
        )
    final.clean(root, owner["expected"]["source_revision"], owner["expected"]["source_fingerprint"])
    return dict(
        scope=SCOPE,
        classification=transfer.CLASSIFICATION,
        release_ready=False,
        receipt=receipt,
        replay=primary,
    )


def retain(
    root,
    state,
    destination,
    *,
    freeze_pin,
    freeze,
    expected,
    run_owner,
    report_pins,
    admission_pins,
    transitions,
    consumer_storage_pin,
):
    """Publish a verified private directory before the disposable consumer exits."""
    owner = authority(
        freeze_pin,
        freeze,
        expected,
        run_owner,
        report_pins,
        admission_pins,
        transitions,
        consumer_storage_pin,
    )
    final.clean(root, owner["expected"]["source_revision"], owner["expected"]["source_fingerprint"])
    target = location(root, destination)
    state = plain(state)
    need(
        not target.is_relative_to(state) and not state.is_relative_to(target), "destination-overlap"
    )
    files, objects, serving_pin = inventory(
        root,
        lambda name, limit: bounded_read(safe_child(state, name), limit),
        lambda pin: final.blob(state, pin, LIMIT),
        owner,
    )
    record = dict(
        schema_version=1,
        scope=SCOPE,
        classification=transfer.CLASSIFICATION,
        authority=owner,
        files=files,
        objects={p: len(raw) for p, raw in objects.items()},
        serving_pin=serving_pin,
    )
    raw = canonical(record) + b"\n"
    need(
        len(raw) <= final.LIMIT and sum(map(len, objects.values())) + len(raw) <= TOTAL,
        "index-budget",
    )
    index_pin = digest(raw)
    if target.exists():
        # External authority and the newly computed index must match every byte.
        # A foreign or incomplete destination is never overwritten/repaired.
        result = replay(root, target, index_pin=index_pin, **owner)
    else:
        need(target.parent.is_dir(), "destination-parent")
        with TemporaryDirectory(prefix="serving-export-", dir=target.parent) as temporary:
            staging = Path(temporary) / "archive"
            staging.mkdir(mode=0o700)
            for pin, content in {**objects, index_pin: raw}.items():
                atomic_write(safe_child(staging, transfer.CAS + pin), content)
            result = replay(root, staging, index_pin=index_pin, **owner)
            # The trusted private parent must not be writable by foreign actors.
            # An existing target is always a collision, even if created mid-export.
            need(not target.exists(), "destination-collision")
            staging.rename(target)
    return dict(result, index_pin=index_pin)


def replay(
    root,
    destination,
    *,
    index_pin,
    freeze_pin,
    freeze,
    expected,
    run_owner,
    report_pins,
    admission_pins,
    transitions,
    consumer_storage_pin,
):
    """Read only this archive and exact source; no consumer, SQL, keys or current window."""
    owner = authority(
        freeze_pin,
        freeze,
        expected,
        run_owner,
        report_pins,
        admission_pins,
        transitions,
        consumer_storage_pin,
    )
    final.clean(root, owner["expected"]["source_revision"], owner["expected"]["source_fingerprint"])
    target = location(root, destination)
    raw = final.blob(target, object_id(index_pin), final.LIMIT)
    record = decode(raw, final.LIMIT)
    require_fields(
        record,
        (
            "schema_version",
            "scope",
            "classification",
            "authority",
            "files",
            "objects",
            "serving_pin",
        ),
    )
    need(raw == canonical(record) + b"\n", "index-json")
    final.subset(
        record,
        dict(
            schema_version=1, scope=SCOPE, classification=transfer.CLASSIFICATION, authority=owner
        ),
        "serving-export-external-authority",
    )
    files, sizes = record["files"], record["objects"]
    need(type(files) is dict and 0 < len(files) <= MAX_FILES, "file-budget")
    need(type(sizes) is dict and 0 < len(sizes) <= MAX_OBJECTS, "object-budget")
    for pin, size in sizes.items():
        object_id(pin)
        need(type(size) is int and 0 < size <= LIMIT, "object-size")
    need(sum(sizes.values()) + len(raw) <= TOTAL, "total-budget")

    def obj(pin, limit=LIMIT):
        content = final.blob(target, object_id(pin), limit)
        need(len(content) == sizes[pin], "object-length")
        return content

    selected, objects, serving_pin = inventory(
        root, lambda name, limit: obj(files[name], limit), obj, owner
    )
    final.same(files, selected, "serving-export-file-inventory")
    final.same(sizes, {p: len(value) for p, value in objects.items()}, "serving-export-objects")
    need(record["serving_pin"] == serving_pin, "serving-pin")
    for pin, content in objects.items():
        need(obj(pin) == content, "stored-preimage")
    # Enumerate only three finite archive levels, never the consumer or whole CAS.
    for directory, names in (
        (target, {"evidence"}),
        (target / "evidence", {"M18-objects"}),
        (target / transfer.CAS, set(objects) | {index_pin}),
    ):
        seen = set()
        for path in directory.iterdir():
            need(path.name in names and path.name not in seen, "foreign-file")
            seen.add(path.name)
        need(seen == names, "missing-file")
    return verify(root, target.parent, files, objects, serving_pin, owner)


def assemble_draft(root, archive, *, index_pin, freeze_pin, plan_pin, **owner):
    """Replay the six original gates and publish only their private draft outside the archive."""
    runtime = plain(safe_child(plain(root), ".runtime"))
    source = location(root, archive)
    output = location(root, runtime / DRAFTS)
    need(not output.is_relative_to(source) and not source.is_relative_to(output), "draft-overlap")
    plan = final.pinned(safe_child(runtime, "evidence/M18-plan.json"), plan_pin)
    verified = replay(root, source, index_pin=index_pin, freeze_pin=freeze_pin, **owner)
    # verify() checked the three upstream primaries. The campaign receipt binds all six to this freeze.
    receipt, trio = verified["receipt"], verified["replay"]
    require_fields(receipt["reports"], campaign.GATES)
    final.subset(receipt["reports"], trio["reports"], "draft-serving-report-pins")
    raw = serving._draft_bytes(
        source,
        dict(trio, reports=receipt["reports"]),
        freeze_pin=freeze_pin,
        proposal_reference=receipt["proposal_reference"],
        plan_raw=plan,
        plan_pin=plan_pin,
    )
    result = dict(status="inconclusive", release_ready=False, index_sha256=digest(raw))
    # A private receipt locates the draft without sending object pins to stdout.
    path = safe_child(output, f"receipts/{object_id(index_pin)}/{object_id(plan_pin)}.json")
    content = canonical(result) + b"\n"
    if path.exists():
        need(bounded_read(path, final.LIMIT) == content, "draft-receipt-collision")
    serving.put(output, raw)
    final.blob(output, result["index_sha256"], final.LIMIT)
    if not path.exists():
        atomic_write(path, content)
    final.pinned(path, digest(content))
    return result


def main(arguments=None):
    need((sys.argv[1:] if arguments is None else arguments) == ["assemble-draft"], "arguments")
    root = Path(__file__).resolve().parents[1]
    native = location(root, root / ".runtime/ci-serving-native")
    raw = final.pinned(
        safe_child(native, "retention-private.json"), os.environ["M18_SERVING_OWNER_SHA256"]
    )
    receipt = decode(raw, final.LIMIT)
    require_fields(receipt, ("authority", "index_pin", "release_ready"))
    need(receipt["release_ready"] is False, "owner-mode")
    owner = receipt["authority"]
    require_fields(
        owner,
        (
            "freeze_pin",
            "freeze",
            "expected",
            "run_owner",
            "report_pins",
            "admission_pins",
            "transitions",
            "consumer_storage_pin",
        ),
    )
    result = assemble_draft(
        root,
        native / "retained",
        index_pin=receipt["index_pin"],
        plan_pin=os.environ["M18_PLAN_SHA256"],
        **owner,
    )
    print(canonical({k: result[k] for k in ("status", "release_ready")}).decode())


if __name__ == "__main__":
    try:
        main()
    except (Rejected, OSError, KeyError, TypeError, ValueError):
        sys.exit("M18 serving archive draft verification failed")
