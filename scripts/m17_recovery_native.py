"""Owned hosted daily snapshot, source-offline restore and post-cleanup M17 replay."""

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path

from mlsecops import load_clock, recovery_observation, storage_backup, storage_bootstrap
from mlsecops.canary_native_evidence import read_pinned
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.security_events import hexadecimal
from mlsecops.trust_acceptance import materials
from scripts import m17_restore_native, m17_restored_proposal
from scripts.kube_trust_native import hosted

IMAGE = "trusted-mlsecops:dev"
PACKET = "evidence/m17-recovery-private.json"
TARGET = "evidence/m17-restored-storage"


def require(condition):
    if not condition:
        raise Rejected("m17_recovery_binding")


def inputs(root, state):
    require(not command(["git", "-C", str(root), "status", "--porcelain"]))
    pins = {
        label: hexadecimal(os.environ[var])
        for label, var in (
            ("proposal", "M17_PROPOSAL_SHA256"),
            ("keys", "M17_KEYS_SHA256"),
            ("demo", "M17_DEMO_SHA256"),
        )
    }
    read_pinned(safe_child(state, "storage-demo.json"), pins["demo"])
    read_pinned(safe_child(state, "evidence/release-native.json"), pins["proposal"])
    public = storage_backup.trusted_keys(read_json(safe_child(state, "trusted-keys.json")))
    require(digest(canonical(public)) == pins["keys"])
    installed = materials(root)
    for rel in (
        "infra/systemd/mlsecops-daily-backup.service",
        "infra/systemd/mlsecops-daily-backup.timer",
        ".github/workflows/storage-recovery.yml",
    ):
        installed[rel] = digest(bounded_read(root / rel))
    return dict(
        source_revision=command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        source_fingerprint=source_fingerprint(root),
        methods=digest(canonical(installed)),
        pins=pins,
        runner={k: os.environ[k] for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")},
    )


def capture(root, state):
    from scripts import daily_backup_systemd_native, restore_negative_native

    hosted()
    owner = inputs(root, state)
    pins = owner["pins"]
    campaign = uuid.uuid4().hex
    marker = storage_bootstrap.validate(state)
    public = read_json(state / "trusted-keys.json")
    vault = Path(os.environ["RUNNER_TEMP"]) / ("m17-owner-" + campaign)
    vault.mkdir(mode=0o700)
    principal = vault / "owner.json"
    inventory_path = vault / "backup.json"
    write_json(principal, dict(workspace_id=marker["workspace_id"], trusted_keys=public))
    target = safe_child(state, TARGET)
    bind_candidate = partial(bind_evaluated_model, root, state, marker["port"], pins["demo"])
    with restore_negative_native.seeded(
        root, state, IMAGE, campaign, bind_candidate=bind_candidate
    ) as seed:
        print("Executing the daily unit in the owned runner", flush=True)
        inventory, schedule = daily_backup_systemd_native.capture(
            root, state, principal, inventory_path
        )
        require(
            inventory == read_json(inventory_path)
            and schedule["inventory_sha256"] == digest(bounded_read(inventory_path))
        )
        pin = hexadecimal(inventory["backup_id"])
        print("Restoring the scheduled snapshot with the source offline", flush=True)
        start = load_clock.sample()
        recovery = m17_restore_native.capture(
            root,
            state,
            target,
            IMAGE,
            demo_pin=pins["demo"],
            keys_pin=pins["keys"],
            include_promotion=True,
            backup_pin=pin,
        )
        proposal = m17_restored_proposal.verify(
            root,
            state,
            target,
            IMAGE,
            proposal_pin=pins["proposal"],
            keys_pin=pins["keys"],
            demo_pin=pins["demo"],
        )
        print("Checking restored approvals, serving and refusal paths", flush=True)
        approvals = seed.verify_restored(target, pin)
    require(owner == inputs(root, state))
    return dict(
        schema_version=1,
        owner=owner,
        campaign=campaign,
        inventory=inventory,
        schedule=schedule,
        recovery=recovery,
        proposal=proposal,
        approvals=approvals,
        start=start,
    )


def bind_evaluated_model(root, state, port, demo_pin, fixture, image):
    from scripts.serving_native import bind_model

    demo = decode(read_pinned(safe_child(state, "storage-demo.json"), demo_pin))
    model, features, scores = m17_restore_native.evaluated_materials(
        state,
        port,
        demo,
        read_json(root / "policies/local-cpu.json"),
        read_json(safe_child(state, "storage-trust.json")),
        image,
    )
    bind_model(fixture, image, model, demo["evaluation"]["report"])
    return features[:1], scores[:1]


def stop_owned(directory):
    if not (directory / "storage.json").exists():
        return
    marker = storage_bootstrap.validate(directory)
    handle = marker["container_id"]
    if storage_bootstrap.inspect("container", handle)["State"]["Running"]:
        storage_bootstrap.docker(["stop", "--time", "20", handle])
    require(
        storage_bootstrap.validate(directory) == marker
        and storage_bootstrap.inspect("container", handle)["State"]["Running"] is False
    )


def stop(state):
    hosted()
    try:
        stop_owned(safe_child(state, TARGET))
    finally:
        stop_owned(state)


def replay(root, state):
    from scripts import restore_negative_native

    hosted()
    owner = inputs(root, state)
    path = safe_child(state, PACKET)
    packet = decode(read_pinned(path, os.environ["M17_PRIMARY_SHA256"]))
    require_fields(
        packet,
        (
            "schema_version",
            "owner",
            "campaign",
            "inventory",
            "schedule",
            "recovery",
            "proposal",
            "approvals",
            "start",
        ),
    )
    require(
        type(packet["schema_version"]) is int
        and packet["schema_version"] == 1
        and packet["owner"] == owner
    )
    rec = packet["recovery"]
    for directory, identity in ((state, rec["source"]), (safe_child(state, TARGET), rec["target"])):
        marker = storage_bootstrap.validate(directory)
        require(
            {k: marker[k] for k in m17_restore_native.IDENTITY} == identity
            and storage_bootstrap.inspect("container", marker["container_id"])["State"]["Running"]
            is False
        )
    inventory, schedule = packet["inventory"], packet["schedule"]
    pin = hexadecimal(inventory["backup_id"])
    vault = Path(os.environ["RUNNER_TEMP"]) / ("m17-owner-" + hexadecimal(packet["campaign"], 32))
    require(decode(read_pinned(vault / "backup.json", schedule["inventory_sha256"])) == inventory)
    require(
        inventory["source_revision"] == owner["source_revision"]
        and inventory["workspace_id"] == rec["source"]["workspace_id"]
        and schedule["backup_id"] == pin
        and schedule["runtime_units_removed"] is True
        and schedule["exit_status"] == 0
        and schedule["trigger"] == "controlled-on-active"
        and schedule["daily_cadence_observed"] is False
    )
    public = read_json(state / "trusted-keys.json")
    require(
        read_json(vault / "owner.json")
        == dict(workspace_id=inventory["workspace_id"], trusted_keys=public)
    )
    policy = read_json(root / "policies/local-cpu.json")
    sql = m17_restore_native.replay(
        rec, backup_pin=pin, demo_pin=owner["pins"]["demo"], public=public, policy=policy
    )
    archive = safe_child(state, "backups/" + pin)
    statement, archive_bytes = storage_backup.read_backup(archive, public, policy)
    require(
        read_json(archive / "manifest.json") == rec["manifest"]
        and digest(canonical(statement)) == pin
        and statement["schema_version"] == 2
        and inventory["recovery_point_at"] == statement["recovery_point_at"]
    )
    approval = packet["approvals"]
    require(
        approval["backup_manifest"] == rec["manifest"]
        and approval["backup_public"] == public
        and approval["backup_policy"] == policy
        and canonical(approval["restore"])
        == canonical({k: v for k, v in rec["receipt"].items() if k != "reused"})
        and all(
            approval[role] == {k: rec[role][k] for k in restore_negative_native.IDENTITY}
            for role in ("source", "target")
        )
    )
    control = restore_negative_native.replay(
        approval,
        backup_id=pin,
        campaign=packet["campaign"],
        image=sql["image_id"],
        archive_bytes=archive_bytes,
    )
    verified = approval["healthy"]["verified_clock"]
    timing = recovery_observation.measure(
        dict(start=packet["start"], end=verified),
        primary=rec,
        sql=sql,
        statement=statement,
        proposal=packet["proposal"],
        report=read_json(state / "evidence/release-native.json"),
        serving_verified_ns=verified["monotonic_ns"],
    )
    return dict(
        timing=timing,
        sql=sql,
        control=control,
        schedule=schedule,
        proposal=packet["proposal"],
        owner=owner,
        started_at=(
            datetime(1970, 1, 1, tzinfo=UTC)
            + timedelta(microseconds=packet["start"]["before_ns"] // 1000)
        ).isoformat(),
    )


def main():
    try:
        root = Path(__file__).resolve().parents[1]
        state = root / ".runtime"
        if sys.argv[1:] == ["capture"]:
            record = capture(root, state)
            path = safe_child(state, PACKET)
            write_json(path, record)
            pin = digest(canonical(record) + b"\n")
            read_pinned(path, pin)
            with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
                print("sha256=" + pin, file=out)
            print(canonical(dict(primary_sha256=pin)).decode())
        elif sys.argv[1:] == ["stop"]:
            stop(state)
        elif sys.argv[1:] == ["replay"]:
            result = replay(root, state)
            print(canonical(result).decode())
        else:
            raise Rejected("m17_recovery_arguments")
        return 0
    except Exception as error:
        from scripts.kube_load_native import failure_site
        from scripts.kube_security_outage_native import failure_report

        print(
            canonical(
                dict(
                    status="fail",
                    site=failure_site(error),
                    callers=failure_report(error)["callers"],
                )
            ).decode(),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
