"""Public M17 lab report from the owner-pinned, post-cleanup native replay."""

import os
import re
from datetime import UTC, datetime, timedelta

from mlsecops.contracts import Rejected, canonical, read_json, safe_child
from mlsecops.security_events import hexadecimal
from scripts import m17_recovery_native as native

SCOPE = "local-cpu-scheduled-backup-source-offline-restore-and-controlled-approvals"
CASES = (
    "daily-calendar-and-controlled-service-activation",
    "owner-pinned-snapshot-and-independent-storage",
    "restored-evaluated-candidate-and-golden-predictions",
    "restored-proposal-requires-assurance",
    "restored-controlled-approvals-and-serving",
    "recovery-through-verified-serving-within-rto",
    "signed-snapshot-point-within-rpo",
    "corrupt-archive-refused-before-target-creation",
    "missing-artifact-refused-before-target-creation",
    "revoked-approver-refused-before-cold-ready-and-prediction",
)


def require(condition):
    if not condition:
        raise Rejected("recovery_acceptance_evidence")


def number(value, ceiling):
    require(type(value) in (int, float) and 0 <= value <= ceiling)
    return value


def utc(value):
    stamp = datetime.fromisoformat(value)
    require(stamp.utcoffset() == timedelta(0))
    return stamp.astimezone(UTC)


def scheduler(schedule, backup, restore_started):
    require(
        schedule["calendar"] == "*-*-* 02:00:00 UTC"
        and schedule["trigger"] == "controlled-on-active"
        and schedule["daily_cadence_observed"] is False
        and schedule["runtime_units_removed"] is True
        and type(schedule["exit_status"]) is int
        and schedule["exit_status"] == 0
        and schedule["backup_id"] == backup
        and re.fullmatch(r"mlsecops-daily-backup-[0-9a-f]{32}\.timer", schedule["unit"])
    )
    last, begin, end, following = (
        utc(schedule[field])
        for field in (
            "last_trigger_utc",
            "service_started_at",
            "service_exited_at",
            "next_elapse_utc",
        )
    )
    next_daily = last.replace(hour=2, minute=0, second=0, microsecond=0)
    if next_daily <= last:
        next_daily += timedelta(days=1)
    require(last <= begin <= end <= restore_started and end < following == next_daily)
    return dict(
        calendar=schedule["calendar"],
        trigger=schedule["trigger"],
        exit_status=0,
        last_trigger_utc=last.isoformat(),
        next_elapse_utc=following.isoformat(),
    )


def qualify(root, state):
    files = (
        native.PACKET,
        "storage.json",
        native.TARGET + "/storage.json",
        "trusted-keys.json",
        "storage-demo.json",
        "evidence/release-native.json",
    )
    workflow = ("M17_PRIMARY_SHA256", "M17_PROPOSAL_SHA256", "M17_KEYS_SHA256", "M17_DEMO_SHA256")
    if not all(safe_child(state, name).is_file() for name in files) or not all(
        os.environ.get(name)
        for name in (*workflow, "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_TEMP")
    ):
        raise FileNotFoundError("M17 recovery prerequisites unavailable")
    primary, proposal_pin, keys_pin, demo_pin = (hexadecimal(os.environ[k]) for k in workflow)
    runner = {k: os.environ[k] for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
    require(all(re.fullmatch(r"[1-9][0-9]*", v) for v in runner.values()))
    evidence = native.replay(root, state)
    owner, sql, proposal, control, timing, schedule = (
        evidence[k] for k in ("owner", "sql", "proposal", "control", "timing", "schedule")
    )
    require(
        owner["runner"] == runner
        and owner["pins"] == dict(proposal=proposal_pin, keys=keys_pin, demo=demo_pin)
    )
    backup = hexadecimal(sql["backup_id"])
    require(
        sql["scope"] == "source-offline-sql-evaluated-candidate"
        and sql["release_ready"] is False
        and type(sql["golden_rows"]) is int
        and sql["golden_rows"] == native.m17_restore_native.ROWS
        and proposal["status"] == "verified-proposal-requires-assurance"
        and proposal["release_ready"] is False
        and all(
            proposal[k] == sql[k]
            for k in ("candidate_reference", "evaluation_reference", "model_sha256")
        )
    )
    target = hexadecimal(proposal["target_workspace"], 32)
    require(
        control["scope"] == "controlled-approvals-in-shared-v2-snapshot"
        and control["status"] == "pass"
        and control["release_ready"] is False
        and control["backup_id"] == backup
        and control["target_workspace"] == target
        and hexadecimal(control["source_workspace"], 32) != target
        and re.fullmatch(r"sha256:[0-9a-f]{64}", sql["image_id"])
        and control["image"] == sql["image_id"]
        and control["model_sha256"] == sql["model_sha256"]
        and control["release_subject"] != proposal["subject_sha256"]
        and canonical(control["approved_sequences"]) == b"[1,2]"
        and canonical(
            [control[k] for k in ("healthy_status", "cold_ready_status", "cold_predict_status")]
        )
        == b"[200,503,503]"
        and control["archive_refusals"]
        == dict(
            missing="backup_archive_integrity_failed", corrupt="backup_archive_integrity_failed"
        )
    )
    rto = number(timing["rto_seconds"], 900)
    require(0 < number(sql["rto_seconds"], rto))
    rpo = number(timing["rpo_seconds"], 86400)
    parity = number(
        sql["max_error"], read_json(root / "policies/local-cpu.json")["repeat_tolerance"]
    )
    started = utc(evidence["started_at"])
    cases = [dict(id="M17-" + name, status="pass", expected=True, actual=True) for name in CASES]
    return dict(
        status="pass",
        scope=SCOPE,
        release_ready=False,
        source_dirty=False,
        started_at=started.isoformat(),
        cases=cases,
        checks=len(cases),
        metrics=dict(
            rto_seconds=rto,
            rpo_seconds=rpo,
            golden_rows=sql["golden_rows"],
            max_error=parity,
            scheduler=scheduler(schedule, backup, started),
            daily_cadence_observed=False,
            controlled_healthy_status=200,
            cold_ready_status=503,
            cold_predict_status=503,
            archive_refusals=control["archive_refusals"],
        ),
        input_digests=dict(
            source_revision=hexadecimal(owner["source_revision"], 40),
            source_fingerprint=hexadecimal(owner["source_fingerprint"]),
            dataset_reference=hexadecimal(sql["dataset_reference"]),
            candidate_reference=hexadecimal(sql["candidate_reference"]),
            evaluation_reference=hexadecimal(sql["evaluation_reference"]),
            qualified_candidate_model=hexadecimal(sql["model_sha256"]),
            qualified_candidate_subject=hexadecimal(proposal["subject_sha256"]),
            proposal_reference=hexadecimal(proposal["proposal_reference"]),
            image_id=sql["image_id"],
            controlled_subject=hexadecimal(control["release_subject"]),
            controlled_model=hexadecimal(control["model_sha256"]),
        ),
        artifact_hashes=dict(
            recovery_packet=primary,
            backup_id=backup,
            daily_inventory=hexadecimal(schedule["inventory_sha256"]),
            demo=demo_pin,
            public_keys=keys_pin,
            proposal_packet=proposal_pin,
            method_materials=hexadecimal(owner["methods"]),
            golden_features=hexadecimal(sql["features_sha256"]),
            controlled_approval=hexadecimal(control["approval_sha256"]),
            controlled_selection=hexadecimal(control["selected_request_sha256"]),
            revoked_approver=hexadecimal(control["revoked_approver_sha256"]),
        ),
        limitations=[
            "Synthetic local-cpu recovery in independent storage on one hosted machine.",
            "The daily calendar was configured and the service was activated by a controlled timer trigger. "
            "Successive daily runs, offsite recovery and high availability remain unmeasured.",
            "Restored HTTP serving uses the evaluated candidate's ONNX bytes under controlled signed "
            "approvals in the same snapshot. The original proposal still requires M18 and release authorization.",
        ],
    )
