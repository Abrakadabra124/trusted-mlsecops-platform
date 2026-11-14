"""M22 staged reviewer intake. Only the operator can create the trusted pre-reveal receipt."""

import argparse
import re
import sys
from pathlib import Path

from mlsecops import absolute_poisoning_gate as gate
from mlsecops import m22_methods
from mlsecops.absolute_poisoning_gate import metrics as compare_views
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.prediction_protocol import PredictionBatch, validate_request
from mlsecops.signing import ROLES, decode64, sign, verify
from scripts import absolute_poisoning as protocol
from scripts import poisoning_evidence as evidence
from scripts import poisoning_native as native
from scripts.candidate_lineage_native import KNOWN_OWNERS

FAMILIES = ("label-flip", "backdoor")
LIMIT = 65536
RULES = {
    "format": "m22-fixed-train-ids-v1",
    "independent_of_defence_and_tuning": True,
    "methods_new_and_unused_in_tuning": True,
    "capabilities": "public-defence-and-locked-synthetic-train-only",
    "train_rows": 14000,
    "seed": "candidate-training-seed",
    "training_runs_per_case": 1,
    "control": "actual-candidate-on-identical-clean-and-challenge-views",
    "prediction_runs_per_case": 2,
    "worker_deadline_seconds": 600,
    "feedback_queries": 0,
    "final_holdout_queries": 0,
    "decision": "absolute-policy-comparable-probes-hard-boundary-bypass-fails",
}


def _hex(value, length):
    if type(value) is not str or not re.fullmatch(f"[0-9a-f]{{{length}}}", value):
        raise Rejected("M22_review_identifier")
    return value


def _once(directory):
    try:
        directory.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError:
        raise Rejected("M22_review_already_reserved") from None


def _matrix(root, state, image, campaign_id):
    campaign = safe_child(state, "absolute-poisoning/" + _hex(campaign_id, 32))
    candidate = gate.subject(root, state, image)
    raw = bounded_read(campaign / "report.json")
    old = decode(raw)
    manifest = read_json(campaign / "campaign.json")
    inputs, revision, started = (manifest[k] for k in ("inputs", "revision", "started_at"))
    evidence.equal(inputs["image"], image, "M22_review_image")
    finished = old["finished_at"]
    records, error, snapshot = gate.reconcile(
        root, campaign, candidate, inputs, revision, started, finished
    )
    report = gate.matrix_report(
        root,
        state,
        campaign,
        candidate,
        inputs,
        revision,
        started,
        finished,
        records,
        error,
        snapshot,
    )
    evidence.equal(old, report, "M22_review_original_matrix")
    if report["source_dirty"]:
        raise Rejected("M22_review_dirty_source")
    binding = {
        "campaign_id": campaign_id,
        "matrix_report_sha256": digest(raw),
        "primary_sha256": report["artifact_hashes"]["primary_materials"],
        "revision": revision,
        "inputs": report["input_digests"],
        "bindings": candidate["bindings"],
        "policy_sha256": digest(canonical(candidate["policy"])),
        "rules": RULES,
    }
    return binding, candidate, report


def _check_freeze(envelope, reviewer_key, keys, binding, owner, latest):
    public = decode64(reviewer_key)
    if len(public) != 32 or public in [decode64(keys[r]) for r in ROLES]:
        raise Rejected("M22_review_self_key")
    freeze = verify(envelope, "m22-freeze", reviewer_key)
    require_fields(freeze, ("binding", "reviewer", "frozen_at", "files"))
    reviewer = freeze["reviewer"]
    if any(
        type(v) is not str or not re.fullmatch("[a-z0-9][a-z0-9.-]{0,63}", v)
        for v in (owner, reviewer)
    ) or reviewer in {owner, *ROLES, *KNOWN_OWNERS, "trainer"}:
        raise Rejected("M22_review_self_identity")
    evidence.equal(freeze["binding"], binding, "M22_review_frozen_subject")
    evidence.timestamp(freeze["frozen_at"], "2026-01-01T00:00:00+00:00", latest)
    names = [family + ext for family in FAMILIES for ext in (".md", ".json")]
    require_fields(freeze["files"], names)
    for value in freeze["files"].values():
        _hex(value, 64)
    if len(set(freeze["files"].values())) != len(names):
        raise Rejected("M22_review_duplicate_files")
    return freeze


def intake(root, state, image, campaign_id, envelope_path, reviewer_key, owner):
    binding, _, report = _matrix(root, state, image, campaign_id)
    received = now()
    envelope = decode(bounded_read(envelope_path, LIMIT))
    keys = read_json(safe_child(state, "trusted-keys.json"))
    freeze = _check_freeze(envelope, reviewer_key, keys, binding, owner, received)
    evidence.timestamp(freeze["frozen_at"], report["finished_at"], received)
    receipt = {
        "campaign_id": campaign_id,
        "reviewer_key": reviewer_key,
        "owner": owner,
        "received_at": received,
        "freeze": envelope,
    }
    sealed = sign(receipt, "m22-intake", safe_child(state, "keys/approver.pem"))
    evidence.equal(verify(sealed, "m22-intake", keys["approver"]), receipt, "M22_review_owner")
    directory = safe_child(state, "m22-review")
    _once(directory)
    write_json(directory / "receipt.json", sealed)


def _open(root, state, image):
    directory = safe_child(state, "m22-review")
    keys = read_json(safe_child(state, "trusted-keys.json"))
    raw = bounded_read(directory / "receipt.json", LIMIT * 2)
    receipt = verify(decode(raw), "m22-intake", keys["approver"])
    binding, candidate, report = _matrix(root, state, image, receipt["campaign_id"])
    received = receipt["received_at"]
    evidence.timestamp(received, report["finished_at"], now())
    freeze = _check_freeze(
        receipt["freeze"], receipt["reviewer_key"], keys, binding, receipt["owner"], received
    )
    evidence.timestamp(freeze["frozen_at"], report["finished_at"], received)
    return directory, receipt, digest(raw), freeze, candidate, report


def _packet(folder, freeze):
    contents = {}
    for name, expected in freeze["files"].items():
        raw = bounded_read(safe_child(folder, name), LIMIT)
        if digest(raw) != expected or not raw.strip():
            raise Rejected("M22_review_reveal_bytes")
        contents[name] = raw
    return contents


def _prepared(root, candidate, inputs, contents):
    profile, train, validation, probes, _ = native.materials(root)
    evidence.equal(profile, candidate["policy"], "M22_review_policy")
    for name, rows in (("train", train), ("validation", validation), ("probes", probes)):
        evidence.equal(digest(canonical(rows)), inputs[name], "M22_review_locked_" + name)
    cases = [
        m22_methods.prepare(
            decode(contents[family + ".json"]),
            family,
            train,
            probes,
            candidate["policy"]["training_seed"],
        )
        for family in FAMILIES
    ]
    return profile, train, validation, probes, cases


def _reviewed_methods(approval, seal, receipt, latest):
    value = verify(decode(approval), "m22-methods", receipt["reviewer_key"])
    require_fields(value, ("intake_sha256", "checked_at", "matches_frozen_methods"))
    evidence.equal(value["intake_sha256"], seal, "M22_review_methods_binding")
    evidence.equal(value["matches_frozen_methods"], True, "M22_review_methods_checked")
    evidence.timestamp(value["checked_at"], receipt["received_at"], latest)


def execute(root, state, image, packet):
    directory, receipt, seal, freeze, candidate, _ = _open(root, state, image)
    run = safe_child(directory, "run")
    if run.exists():
        raise Rejected("M22_review_already_reserved")
    contents = _packet(packet, freeze)
    approval = bounded_read(safe_child(packet, "methods.dsse.json"), LIMIT)
    _reviewed_methods(approval, seal, receipt, now())
    profile, train, validation, probes, cases = _prepared(
        root, candidate, freeze["binding"]["inputs"], contents
    )
    _once(run)
    started = now()
    write_json(run / "start.json", {"intake": seal, "started_at": started})
    atomic_write(run / "methods.dsse.json", approval)
    for name, raw in contents.items():
        atomic_write(run / name, raw)
    for case, mutation, triggered in cases:
        folder = safe_child(run, case["id"])
        features = [row["features"] for view in (probes, triggered) for row in view]
        batch = PredictionBatch(candidate["model"], features)
        output, execution = gate.run_worker(image, batch.request)
        clean, _, _ = batch.consume(output)
        record, scores = native.execute(
            root,
            folder,
            case,
            train,
            validation,
            (probes, triggered),
            profile,
            image,
            experiment_policy={"absolute": protocol.policy(), "intake": seal},
            prepared_mutation=mutation,
        )
        write_json(
            folder / "control.json",
            {"request": batch.request, "response": output, "execution": execution},
        )
        record["metrics"] = compare_views(probes, clean.tolist(), scores, case["family"])
        write_json(folder / "result.json", record)
    write_json(run / "end.json", {"finished_at": now()})
    # Give the reviewer the exact replay-derived payload to inspect before signing.
    result, _ = _outcomes(root, directory, receipt, seal, freeze, candidate, image)
    write_json(
        run / "observations.json", sign(result, "m22-observations", state / "keys/approver.pem")
    )
    return result


def _run_hashes(run):
    names = [
        "start.json",
        "end.json",
        "methods.dsse.json",
        *(family + ext for family in FAMILIES for ext in (".json", ".md")),
        *(
            "review-" + family + "/" + n
            for family in FAMILIES
            for n in (*gate.CASE_FILES, "control.json")
        ),
    ]
    return {n: digest(bounded_read(safe_child(run, n))) for n in names}


def _outcomes(root, directory, receipt, seal, freeze, candidate, image):
    run = safe_child(directory, "run")
    snapshot = _run_hashes(run)
    start = read_json(run / "start.json")
    evidence.equal(start["intake"], seal, "M22_review_start")
    started, finished = start["started_at"], read_json(run / "end.json")["finished_at"]
    evidence.timestamp(started, receipt["received_at"], now())
    evidence.timestamp(finished, started, now())
    _reviewed_methods(bounded_read(run / "methods.dsse.json", LIMIT), seal, receipt, started)
    profile, train, validation, probes, cases = _prepared(
        root, candidate, freeze["binding"]["inputs"], _packet(run, freeze)
    )
    outcomes = []
    for case, mutation, triggered in cases:
        folder = safe_child(run, case["id"])
        record, scores = evidence.case_materials(
            folder,
            case,
            profile,
            train,
            validation,
            probes,
            triggered,
            freeze["binding"]["inputs"],
            freeze["binding"]["revision"],
            started,
            finished,
            experiment_policy={"absolute": protocol.policy(), "intake": seal},
            prepared_mutation=mutation,
        )
        proof = read_json(folder / "control.json")
        request, output = proof["request"], proof["response"]
        if validate_request(request) != candidate["model"]:
            raise Rejected("M22_review_control_model")
        features = [row["features"] for view in (probes, triggered) for row in view]
        evidence.equal(request["features"], features, "M22_review_control_views")
        clean = gate.control_scores(request, output, proof["execution"], image)
        metrics = compare_views(probes, clean, scores, case["family"])
        evidence.equal(record["metrics"], metrics, "M22_review_metrics")
        outcomes.append(
            {
                **case,
                "run_id": record["run_id"],
                "fraction": mutation[1]["fraction"],
                "metrics": metrics,
            }
        )
    if len({case["run_id"] for case in outcomes}) != len(FAMILIES):
        raise Rejected("M22_review_duplicate_run")
    evidence.equal(snapshot, _run_hashes(run), "M22_review_run_changed")
    return {
        "intake_sha256": seal,
        "primary_sha256": digest(canonical(snapshot)),
        "outcomes": outcomes,
        "finished_at": finished,
    }, snapshot


def _status(values):
    return "fail" if "fail" in values else "inconclusive" if "inconclusive" in values else "pass"


def _decision(decision_raw, folder, observed, reviewer_key):
    findings_hashes = {}
    decision = verify(decode(decision_raw), "m22-decision", reviewer_key)
    require_fields(decision, ("observations_sha256", "decided_at", "findings"))
    evidence.equal(
        decision["observations_sha256"], digest(canonical(observed)), "M22_review_decision_binding"
    )
    evidence.timestamp(decision["decided_at"], observed["finished_at"], now())
    require_fields(decision["findings"], FAMILIES)
    for family, finding in decision["findings"].items():
        require_fields(finding, ("decision", "hard_boundary_bypass", "result_md_sha256"))
        if (
            finding["decision"] not in ("pass", "fail", "inconclusive")
            or type(finding["hard_boundary_bypass"]) is not bool
        ):
            raise Rejected("M22_review_finding")
        filename = family + "-result.md"
        details = bounded_read(folder / filename, LIMIT)
        if not details.strip() or digest(details) != finding["result_md_sha256"]:
            raise Rejected("M22_review_finding_bytes")
        findings_hashes[filename] = digest(details)
    return decision["findings"], findings_hashes


def _observed(root, directory, receipt, seal, freeze, candidate, image, state):
    observed, snapshot = _outcomes(root, directory, receipt, seal, freeze, candidate, image)
    raw = bounded_read(directory / "run/observations.json")
    attested = verify(
        decode(raw), "m22-observations", read_json(state / "trusted-keys.json")["approver"]
    )
    evidence.equal(attested, observed, "M22_review_observations")
    return observed, snapshot, digest(raw)


def record_decision(root, state, image, packet):
    directory, receipt, seal, freeze, candidate, _ = _open(root, state, image)
    observed, _, _ = _observed(root, directory, receipt, seal, freeze, candidate, image, state)
    raw = bounded_read(safe_child(packet, "decision.json"), LIMIT)
    _, hashes = _decision(raw, packet, observed, receipt["reviewer_key"])
    contents = {name: bounded_read(safe_child(packet, name), LIMIT) for name in hashes}
    evidence.equal({n: digest(v) for n, v in contents.items()}, hashes, "M22_review_decision_copy")
    folder = safe_child(directory, "decision")
    _once(folder)
    for name, content in contents.items():
        atomic_write(folder / name, content)
    atomic_write(folder / "decision.json", raw)
    write_json(
        folder / "owner.json",
        sign(
            {"intake": seal, "decision": digest(raw)},
            "m22-recorded-decision",
            state / "keys/approver.pem",
        ),
    )


def replay(root, state, image):
    directory, receipt, seal, freeze, candidate, report = _open(root, state, image)
    cases = []
    observed, snapshot = None, None
    observations_hash = None
    decision_hash = None
    findings_hashes = {}
    reviewed = 0
    run = safe_child(directory, "run")
    if (run / "end.json").exists():
        observed, snapshot, observations_hash = _observed(
            root, directory, receipt, seal, freeze, candidate, image, state
        )
        decision_path = safe_child(directory, "decision/decision.json")
        findings = {}
        if decision_path.exists():
            decision_raw = bounded_read(decision_path, LIMIT)
            findings, findings_hashes = _decision(
                decision_raw, decision_path.parent, observed, receipt["reviewer_key"]
            )
            seal_path = decision_path.parent / "owner.json"
            recorded = bounded_read(seal_path, LIMIT)
            accepted = verify(
                decode(recorded),
                "m22-recorded-decision",
                read_json(state / "trusted-keys.json")["approver"],
            )
            evidence.equal(
                accepted,
                {"intake": seal, "decision": digest(decision_raw)},
                "M22_review_recorded_decision",
            )
            findings_hashes["owner.json"] = digest(recorded)
            reviewed = 2
            decision_hash = digest(decision_raw)
        matrix_runs = {r["run_id"] for r in report["records"]}
        for outcome in observed["outcomes"]:
            if outcome["run_id"] in matrix_runs:
                raise Rejected("M22_review_duplicate_run")
            finding = findings.get(outcome["family"], {})
            reviewer_status = (
                "fail"
                if finding.get("hard_boundary_bypass")
                else finding.get("decision", "inconclusive")
            )
            cases.append(
                {
                    "id": outcome["id"],
                    "status": _status([outcome["metrics"]["status"], reviewer_status]),
                }
            )
    else:
        cases = [{"id": "review-" + f, "status": "inconclusive"} for f in FAMILIES]
    # Re-read the actual subject and both sets of primary files before publishing.
    binding = freeze["binding"]
    campaign = safe_child(state, "absolute-poisoning/" + binding["campaign_id"])
    if (
        gate.subject(root, state, image) != candidate
        or digest(canonical(gate.primary_hashes(campaign))) != binding["primary_sha256"]
        or digest(bounded_read(campaign / "report.json")) != binding["matrix_report_sha256"]
        or digest(bounded_read(directory / "receipt.json")) != seal
        or gate.materials_digest(root) != binding["inputs"]["host_scripts"]
        or gate.source_fingerprint(root) != binding["inputs"]["source"]
        or digest(bounded_read(root / "data.lock")) != binding["inputs"]["data_lock"]
        or gate.command(["git", "-C", str(root), "rev-parse", "HEAD"]) != binding["revision"]
        or gate.command(["git", "-C", str(root), "status", "--porcelain"])
        or (
            observations_hash
            and digest(bounded_read(run / "observations.json")) != observations_hash
        )
        or (snapshot is not None and snapshot != _run_hashes(run))
    ):
        raise Rejected("M22_review_material_changed")
    if decision_hash and any(
        digest(bounded_read(decision_path.parent / name, LIMIT)) != value
        for name, value in {**findings_hashes, "decision.json": decision_hash}.items()
    ):
        raise Rejected("M22_review_decision_changed")
    report["cases"] = report["cases"][:-1] + cases
    report.update(
        scope="M22-absolute-matrix-and-frozen-review",
        finished_at=now(),
        status=_status([report["component_status"], *(c["status"] for c in cases)]),
        checks=len(report["cases"]),
    )
    report["metrics"]["independent_challenges"] = reviewed
    report["metrics"]["review_primary_files_verified"] = len(snapshot or {})
    report["artifact_hashes"]["review_intake"] = seal
    if observed:
        report["challenge_records"] = observed["outcomes"]
        report["artifact_hashes"]["review_observations"] = observations_hash
        report["artifact_hashes"]["review_primary"] = observed["primary_sha256"]
    if decision_hash:
        report["artifact_hashes"]["review_decision"] = decision_hash
        report["review_findings"] = findings
    report["limitations"][0] = (
        "Human independence and pre-reveal secrecy rely on the "
        "operator's identity check and the reviewer's custody"
    )
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    commands = parser.add_subparsers(dest="action", required=True)
    manifest = commands.add_parser("manifest")
    manifest.add_argument("campaign_id")
    freeze = commands.add_parser("intake")
    freeze.add_argument("campaign_id")
    freeze.add_argument("freeze", type=Path)
    freeze.add_argument("--reviewer-public", required=True, help="Authenticated out of band")
    freeze.add_argument("--owner", required=True, help="Verified defence owner ID")
    for name in ("execute", "record-decision"):
        commands.add_parser(name).add_argument("packet", type=Path)
    signer = commands.add_parser("sign")
    signer.add_argument("kind", choices=("m22-freeze", "m22-methods", "m22-decision"))
    signer.add_argument("payload", type=Path)
    signer.add_argument("output", type=Path)
    signer.add_argument("--key", type=Path, required=True)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        if args.action == "sign":
            write_json(
                args.output, sign(decode(bounded_read(args.payload, LIMIT)), args.kind, args.key)
            )
            return 0
        gate.owned(args.state)
        image = gate.resolve_image("trusted-mlsecops:dev")
        if args.action == "manifest":
            binding, _, _ = _matrix(root, args.state, image, args.campaign_id)
            print(canonical(binding).decode())
        elif args.action == "intake":
            intake(
                root,
                args.state,
                image,
                args.campaign_id,
                args.freeze,
                args.reviewer_public,
                args.owner,
            )
            print(digest(bounded_read(args.state / "m22-review/receipt.json")))
        elif args.action == "execute":
            observations = execute(root, args.state, image, args.packet)
            print(digest(canonical(observations)))
        else:
            record_decision(root, args.state, image, args.packet)
        return 0
    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        OSError,
        RecursionError,
    ) as error:
        print(
            str(error) if isinstance(error, Rejected) else "M22_review_incomplete", file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
