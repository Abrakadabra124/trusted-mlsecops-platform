"""Replay native canary observations using the capture owner's bindings."""

from datetime import UTC, datetime, timedelta

from mlsecops import (
    audit_lineage,
    canary_campaign,
    canary_evaluation,
    canary_journal,
    release_policy,
    trust,
)
from mlsecops.candidate_serving_reader import KIND
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    require_fields,
    safe_child,
)
from mlsecops.load_golden import Golden
from mlsecops.security_events import hexadecimal, integer

SECOND = 1_000_000_000


def require(condition):
    if not condition:
        raise Rejected("canary_native_evidence")


def read_pinned(path, pin, limit=16 * 1024 * 1024):
    raw = bounded_read(path, limit)
    require(digest(raw) == hexadecimal(pin))
    return raw


def candidate_source(state, directory, campaign, owner, clock):
    raw = read_pinned(directory / "candidate-source.json", owner["source_evidence_sha256"])
    private = decode(raw)
    require_fields(private, ("permit", "storage_demo_sha256", "lineage"))
    demo = decode(
        read_pinned(safe_child(state, "storage-demo.json"), private["storage_demo_sha256"])
    )
    require(
        demo["candidate"]["candidate_reference"]
        == owner["candidate_reference"]
        == demo["evaluation"]["candidate_reference"]
    )
    require(demo["evaluation_reference"] == owner["evaluation_reference"])
    meta = demo["candidate"]["metadata"]
    require(meta["model_digest"] == owner["model_sha256"] and meta["image_id"] == owner["image_id"])
    lineage = audit_lineage.checked(private["lineage"])
    require(
        lineage.source_revision == owner["source_revision"] == meta["source_revision"]
        and lineage.source_fingerprint == owner["source_fingerprint"] == meta["source_fingerprint"]
        and lineage.dataset_sha256
        == demo["dataset"]["dataset_reference"]
        == demo["evaluation"]["dataset_reference"]
        and lineage.source_approval_sha256 == demo["dataset"]["source_approval_digest"]
        and lineage.run_sha256 == digest(canonical(meta))
        and lineage.evaluation_sha256 == owner["evaluation_reference"]
    )
    permit = release_policy.checked(private["permit"], KIND, owner["trust_root"])
    fixed = dict(
        schema_version=1,
        purpose=KIND,
        campaign_id=campaign,
        environment="local-cpu",
        proposal_sha256=owner["proposal_reference"],
        **{
            k: owner[k]
            for k in (
                "subject_sha256",
                "model_sha256",
                "source_revision",
                "source_fingerprint",
                "image_id",
            )
        },
    )
    require_fields(permit, (*fixed, "issued_at", "expires_at"))
    require(digest(canonical(permit)) == owner["permit_sha256"])
    require(canonical({k: permit[k] for k in fixed}) == canonical(fixed))
    release_policy.window(permit, clock, maximum=600)
    return private["lineage"], permit["issued_at"]


def check_recovery(
    record, *, stable, candidate, owner, last_stage_end, candidate_attempts, permit_issued
):
    """The clock starts before the trust mutation and ends after the golden reply."""
    require_fields(
        record,
        (
            "start_ns",
            "committed_ns",
            "trust",
            "candidate",
            "restored",
            "observed_at_ns",
            "denial_admissions",
        ),
    )
    proof = record["trust"]
    require_fields(proof, ("root", "before", "after"))
    require(proof["root"] == owner["trust_root"])
    before, after = [
        trust.validate(proof[k], proof["root"], "local-cpu", record["observed_at_ns"] // SECOND)
        for k in ("before", "after")
    ]
    trust.successor(before, after)
    require(
        before["promotion_policy_sha256"]
        == after["promotion_policy_sha256"]
        == owner["permit_sha256"]
    )
    require(
        before["version"] == 1
        and before["revoked_artifacts"] == []
        and after["revoked_artifacts"] == [candidate.model]
        and before["revoked_keys"] == after["revoked_keys"] == []
        and permit_issued <= before["issued_at"]
    )
    start = integer(record["start_ns"])
    cursor = integer(record["committed_ns"])
    require(last_stage_end <= start <= cursor)
    samples = record["candidate"]
    require(type(samples) is list and 1 <= len(samples) <= 200)
    admissions = record["denial_admissions"]
    require_fields(admissions, ("before", "after"))
    admitted = integer(admissions["before"], 0)
    delta = integer(admissions["after"], 0) - admitted
    require(admitted == candidate_attempts + len(samples) - 1 and delta in (0, 1))
    for sample in [*samples, record["restored"]]:
        require_fields(sample, ("status", "reply", "start_ns", "end_ns"))
        require(cursor <= integer(sample["start_ns"]) <= integer(sample["end_ns"]))
        cursor = sample["end_ns"]
    for sample in samples[:-1]:
        require(sample["status"] == 200 and candidate.valid(sample["reply"]))
    denial = samples[-1]
    reply = denial["reply"]
    require_fields(reply, ("schema_version", "request_id", "error"))
    hexadecimal(reply["request_id"], 32)
    require(
        denial["status"] == 503
        and type(reply["schema_version"]) is int
        and reply["schema_version"] == 1
        and reply["error"] == {"code": "model_unavailable"}
    )
    restored = record["restored"]
    require(restored["status"] == 200 and stable.valid(restored["reply"]))
    require(cursor - start <= 120_000_000_000)
    return (cursor - start) / SECOND, delta == 0, before["issued_at"], after["issued_at"]


def replay(state, packet, *, proposal_pin, source, methods, runner):
    require_fields(
        packet,
        (
            "schema_version",
            "campaign",
            "started_at",
            "finished_at",
            "source",
            "methods",
            "runner",
            "proposal_sha256",
            "stable",
            "candidate",
            "goldens",
            "traffic",
            "recovery",
            "journals",
        ),
    )
    require(type(packet["schema_version"]) is int and packet["schema_version"] == 1)
    require(
        packet["source"] == source
        and packet["methods"] == methods
        and packet["runner"] == runner
        and packet["proposal_sha256"] == proposal_pin
    )
    directory = safe_child(state, "evidence/canary-native-" + hexadecimal(packet["campaign"], 32))
    report = decode(read_pinned(safe_child(state, "evidence/release-native.json"), proposal_pin))
    current = packet["candidate"]
    stable = packet["stable"]
    require(
        report["status"] == "pass"
        and report["source_dirty"] is False
        and report["release_ready"] is False
    )
    require(report["source"] == {**source, "image_id": current["image_id"]})
    require(all(current[k] == v for k, v in source.items()))
    for field in ("model_sha256", "subject_sha256", "proposal_reference"):
        require(hexadecimal(current[field]) == report[field])
    for field in ("candidate_reference", "evaluation_reference", "permit_sha256"):
        hexadecimal(current[field])
    require(integer(stable["sequence"]) == 1)
    for field in ("subject_sha256", "model_sha256", "request_sha256", "proposal_reference"):
        hexadecimal(stable[field])
    stamps = [
        datetime.fromisoformat(x)
        for x in (report["finished_at"], packet["started_at"], packet["finished_at"])
    ]
    require(all(x.utcoffset() is not None for x in stamps) and stamps == sorted(stamps))
    fault = packet["recovery"]
    observed = fault["observed_at_ns"]
    require(type(observed) is int and 0 < observed < 2**63)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    start_us, finish_us = [(stamp - epoch) // timedelta(microseconds=1) for stamp in stamps[1:]]
    require(start_us <= observed // 1000 <= finish_us)
    # CandidateReader.clock uses ceil(wall), unlike trust's integer SQL clock.
    lineage, permit_issued = candidate_source(
        state, directory, packet["campaign"], current, (observed + SECOND - 1) // SECOND
    )
    require(start_us // 1_000_000 <= permit_issued)
    goldens = {}
    for role, binding in (("stable", stable), ("candidate", current)):
        fields = packet["goldens"][role]
        goldens[role] = Golden(
            fields["body"].encode(),
            binding["model_sha256"],
            binding["subject_sha256"],
            fields["score"],
        )
    owned = packet["traffic"]
    raw = read_pinned(
        safe_child(
            state, "evidence/canary-" + hexadecimal(owned["campaign"], 32) + "/traffic.json"
        ),
        owned["primary_sha256"],
        canary_campaign.MAX_BYTES,
    )
    stages = decode(raw, canary_campaign.MAX_BYTES)
    result = canary_evaluation.evaluate(
        stages, stable_golden=goldens["stable"], candidate_golden=goldens["candidate"]
    )
    require(
        result["decision"] == "complete"
        and result["stages"] == owned["stages"]
        and owned["decision"] == "complete"
    )
    require(all(owned[role] == golden.binding() for role, golden in goldens.items()))
    seconds, pre_admission, active_at, revoked_at = check_recovery(
        fault,
        stable=goldens["stable"],
        candidate=goldens["candidate"],
        owner=current,
        last_stage_end=stages[-1]["rows"][-1]["end_ns"],
        candidate_attempts=sum(s["candidate_attempts"] for s in result["stages"]),
        permit_issued=permit_issued,
    )
    counts = {}
    for role, extra, binding, authority in (
        (
            "stable",
            [fault["restored"]],
            stable,
            dict(kind="release-selection", selection_sha256=stable["request_sha256"]),
        ),
        (
            "candidate",
            fault["candidate"],
            current,
            dict(
                kind="candidate-qualification",
                permit_sha256=current["permit_sha256"],
                proposal_sha256=current["proposal_reference"],
                schema_version=2,
                lineage=lineage,
            ),
        ),
    ):
        rows = [row for stage in stages for row in stage["rows"] if row["target"] == role]
        journal = read_pinned(directory / (role + ".jsonl"), packet["journals"][role])
        counts[role] = canary_journal.reconcile(
            journal,
            rows,
            extra,
            subject=binding["subject_sha256"],
            model=binding["model_sha256"],
            authority=authority,
            **({"pre_admission_denial": pre_admission} if role == "candidate" else {}),
        )
        # response_intended is written before the client can observe the reply.
        # response_completed can be recorded after the client has already read it.
        recovery_ids = {sample["reply"]["request_id"] for sample in extra}
        for line in journal.splitlines():
            entry = decode(line)
            event = entry["event"]
            if event["stage"] != "response_intended":
                continue
            stamp = entry["recorded_at_ns"]
            if event["request_id"] in recovery_ids:
                require(revoked_at * SECOND <= stamp <= observed)
            elif role == "candidate" and event["status"] == 200:
                # Trust SQL records issuance in whole (floored) epoch seconds.
                require(active_at <= stamp // SECOND <= revoked_at)
    return dict(
        stages=result["stages"],
        requests=sum(s["attempts"] for s in result["stages"]),
        audit_completed=counts,
        route_recovery_seconds=seconds,
        primary_traffic_sha256=owned["primary_sha256"],
        candidate=current["candidate_reference"],
        model=current["model_sha256"],
        release_subject=current["subject_sha256"],
    )
