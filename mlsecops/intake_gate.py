import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path

from mlsecops import artifact_intake, intake_denial, storage_pipeline
from mlsecops.bootstrap import initialize
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.sandbox import resolve_image
from mlsecops.storage_bootstrap import bootstrap, docker, validate

NATIVE_CASES = (
    "clean-isolated-intake",
    "renamed-pickle-rejected",
    "deadline",
    "crash",
    "clean-after-faults",
)
CONTRACT_FILES = (
    "intake_contracts",
    "artifact_intake_qualification",
    "intake_denial_qualification",
    "model_contract_qualification",
    "evaluation_contracts",
    "artifact_intake_native",
    "intake_denial_native",
    "candidate_lineage_qualification",
)


def contract_source(root):
    return digest(
        canonical(
            {name: digest(bounded_read(root / "scripts" / f"{name}.py")) for name in CONTRACT_FILES}
        )
    )


def checked_cases(evidence, expected):
    try:
        cases = evidence["cases"]
        if not isinstance(cases, list) or len(cases) != len(expected):
            raise Rejected("M21_case_set_incomplete")
        names = [case["id"] for case in cases]
        if (
            evidence["status"] != "pass"
            or any(type(name) is not str for name in names)
            or set(names) != set(expected)
            or any(case["status"] != "pass" for case in cases)
        ):
            raise Rejected("M21_case_set_invalid")
        if "checks" in evidence and (
            type(evidence["checks"]) is not int or evidence["checks"] != len(cases)
        ):
            raise Rejected("M21_case_count_invalid")
        return cases
    except (KeyError, TypeError) as error:
        raise Rejected("M21_case_shape_invalid") from error


def fresh(value, started):
    try:
        observed = datetime.fromisoformat(value)
        if observed.tzinfo is None or not datetime.fromisoformat(
            started
        ) <= observed <= datetime.fromisoformat(now()):
            raise ValueError
    except (TypeError, ValueError):
        raise Rejected("M21_evidence_not_fresh") from None


def run_contracts(root):
    from scripts.intake_contracts import SCOPE, case_ids

    result = subprocess.run(
        [sys.executable, "-m", "scripts.intake_contracts"],
        cwd=root,
        capture_output=True,
        timeout=180,
        check=False,
    )
    if result.returncode:
        raise Rejected("M21_contracts_failed")
    evidence = decode(result.stdout, 1024 * 1024)
    checked_cases(evidence, case_ids())
    if evidence.get("scope") != SCOPE or len(evidence["cases"]) < 54:
        raise Rejected("M21_contract_scope_invalid")
    return evidence


def check_native(evidence, content, image, fingerprint, started):
    cases = checked_cases(evidence, NATIVE_CASES)
    if (
        type(evidence.get("schema_version")) is not int
        or evidence["schema_version"] != 1
        or evidence.get("scope") != "native-docker-intake-component-not-full-M21"
        or evidence.get("source_fingerprint") != fingerprint
        or evidence.get("image_id") != image
        or evidence.get("release_ready") is not False
    ):
        raise Rejected("M21_native_binding")
    fresh(evidence.get("observed_at"), started)
    identities = set()
    try:
        for case in cases:
            report = case["report"]
            fresh(report["started_at"], started)
            fresh(report["finished_at"], started)
            if report["inspection_id"] in identities:
                raise Rejected("M21_reused_inspection")
            identities.add(report["inspection_id"])
            if case["id"] in ("clean-isolated-intake", "clean-after-faults"):
                artifact_intake.validate_receipt(report, content, image)
            else:
                unsafe = case["id"] == "renamed-pickle-rejected"
                artifact_intake.validate_failure(
                    report, b"\x80\x04N." if unsafe else content, image
                )
                reason = {
                    "renamed-pickle-rejected": "model_parse_rejected",
                    "deadline": "scanner_timeout",
                    "crash": "scanner_crash",
                }[case["id"]]
                if report["reason"] != reason or (
                    not unsafe and case.get("owned_container_removed") is not True
                ):
                    raise Rejected("M21_native_fault_not_proven")
    except (KeyError, TypeError) as error:
        raise Rejected("M21_native_shape_invalid") from error
    return cases


def reconcile(root, state, demo, native, denials, image, started):
    try:
        return _reconcile(root, state, demo, native, denials, image, started)
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("M21_sql_material_shape") from error


def _reconcile(root, state, demo, native, denials, image, started):
    from scripts.intake_denial_native import CHECK_IDS

    policy = read_json(root / "policies/local-cpu.json")
    trust = read_json(safe_child(state, "storage-trust.json"))
    reader = safe_child(state, "storage-clients/promoter")
    candidate = demo["candidate"]["candidate_reference"]
    record, metadata, content = storage_pipeline.load_candidate(reader, candidate, policy)
    bound = storage_pipeline.read_evaluation(
        reader, demo["evaluation_reference"], candidate, policy, trust
    )
    fingerprint = source_fingerprint(root)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    if (
        metadata["image_id"] != image
        or metadata["source_fingerprint"] != fingerprint
        or metadata["source_revision"] != revision
        or bound != demo["evaluation"]
        or denials.get("source_fingerprint") != fingerprint
        or denials.get("source_revision") != revision
        or denials.get("image_id") != image
        or denials.get("release_ready") is not False
        or denials.get("scope") != "durable-sql-intake-denial-not-full-M21"
        or type(denials.get("schema_version")) is not int
        or denials["schema_version"] != 1
        or denials.get("input_digests")
        != {
            "trust": digest(canonical(trust)),
            "policy": digest(canonical(policy)),
            "original_candidate": candidate,
            "original_evaluation": demo["evaluation_reference"],
        }
    ):
        raise Rejected("M21_sql_material_binding")
    for value in (metadata["created_at"], bound["report"]["created_at"], denials["observed_at"]):
        fresh(value, started)
    intake = bound["report"]["intake"]
    artifact_intake.validate_receipt(intake, content, image)
    fresh(intake["started_at"], started)
    fresh(intake["finished_at"], started)
    native_cases = check_native(native, content, image, fingerprint, started)
    denial_cases = checked_cases(denials, CHECK_IDS)
    expected = {
        "unsafe-model": ("fail", "model_parse_rejected"),
        "malformed-response": ("fail", "scanner_protocol_rejected"),
        "transport-fixture": ("inconclusive", "scanner_timeout"),
    }
    entries = denials.get("denials")
    if not isinstance(entries, list) or len(entries) != 3:
        raise Rejected("M21_denial_set_incomplete")
    names, references, slots = set(), set(), set()
    for entry in entries:
        payload = intake_denial.read(
            reader, entry["denial_reference"], entry["candidate_reference"], policy, trust
        )
        report = payload["intake"]
        name = next(
            (
                name
                for name, outcome in expected.items()
                if outcome == (report["status"], report["reason"])
            ),
            None,
        )
        if name is None or name in names:
            raise Rejected("M21_denial_case_invalid")
        names.add(name)
        if (
            payload != entry["payload"]
            or (name != "unsafe-model" and entry["candidate_reference"] != candidate)
            or payload["dataset_reference"] != record["dataset_reference"]
        ):
            raise Rejected("M21_denial_material_binding")
        if name == "unsafe-model":
            _, unsafe_metadata, unsafe_content = storage_pipeline.load_candidate(
                reader, entry["candidate_reference"], policy
            )
            if unsafe_content != b"\x80\x04N." or any(
                unsafe_metadata[field] != metadata[field]
                for field in ("image_id", "source_revision", "source_fingerprint", "materials")
            ):
                raise Rejected("M21_unsafe_fixture_binding")
        fresh(report["started_at"], started)
        fresh(report["finished_at"], started)
        references.add(entry["denial_reference"])
        slots.add(payload["holdout_access"]["slot"])
    if len(references) != 3 or len(slots) != 3:
        raise Rejected("M21_denial_reuse")
    return {
        "input_digests": {
            "source_fingerprint": fingerprint,
            "worker_image": image,
            "candidate_reference": candidate,
            "dataset_reference": record["dataset_reference"],
            "model": digest(content),
            "evaluation_reference": demo["evaluation_reference"],
            "policy": digest(canonical(policy)),
            "trust": digest(canonical(trust)),
        },
        "metrics": {
            "native_cases": len(native_cases),
            "sql_cases": len(denial_cases),
            "quality_component": bound["report"]["quality_component"],
        },
    }


def qualify(root, state):
    from scripts.artifact_intake_native import qualify as scan
    from scripts.intake_denial_native import qualify as deny

    root, state = Path(root).resolve(), Path(state).resolve()
    initialize(root, state)
    output = safe_child(state, "evidence/intake-gate.json")
    started = now()
    write_json(output, {"status": "inconclusive", "release_ready": False, "started_at": started})
    if sys.platform != "linux":
        raise Rejected("M21_linux_required")
    image = resolve_image("trusted-mlsecops:dev")
    fingerprint, sources = source_fingerprint(root), contract_source(root)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    policy_digest = digest(bounded_read(root / "policies/local-cpu.json"))
    data_digest = digest(bounded_read(root / "data.lock"))
    contracts = run_contracts(root)
    campaign_id = uuid.uuid4().hex
    campaign = safe_child(state, "intake-gate/" + campaign_id)
    initialize(root, campaign)
    bootstrap(campaign, 15453)
    marker = validate(campaign)
    try:
        demo = storage_pipeline.demo(root, campaign, image)
        _, _, content = storage_pipeline.load_candidate(
            campaign / "storage-clients/promoter",
            demo["candidate"]["candidate_reference"],
            read_json(root / "policies/local-cpu.json"),
        )
        native = scan(image, content)
        denials = deny(root, campaign, image)
        result = reconcile(root, campaign, demo, native, denials, image, started)
        if (
            fingerprint != source_fingerprint(root)
            or sources != contract_source(root)
            or revision != command(["git", "-C", str(root), "rev-parse", "HEAD"])
            or policy_digest != digest(bounded_read(root / "policies/local-cpu.json"))
            or data_digest != digest(bounded_read(root / "data.lock"))
            or resolve_image(image) != image
        ):
            raise Rejected("M21_source_changed_during_campaign")
        hashes, cases = {}, []
        for name, report in (("contracts", contracts), ("native", native), ("denials", denials)):
            path = safe_child(campaign, "evidence/M21-" + name + ".json")
            write_json(path, report)
            hashes[name] = digest(bounded_read(path))
            cases.extend(
                {
                    "id": name + ":" + case["id"],
                    "status": "pass",
                    "expected": "pass",
                    "actual": "pass",
                }
                for case in report["cases"]
            )
        cases.append(
            {
                "id": "signed-materials-reconciliation",
                "status": "pass",
                "expected": "pass",
                "actual": "pass",
            }
        )
        cases.append(
            {
                "id": "scoped-controller-native-intake-matrix",
                "status": "inconclusive",
                "expected": "pass",
                "actual": "not-yet-implemented",
            }
        )
        result.update(
            schema_version=1,
            scope="M21-intake-acceptance",
            status="inconclusive",
            component_status="pass",
            release_ready=False,
            campaign_id=campaign_id,
            started_at=started,
            source_revision=revision,
            source_dirty=bool(command(["git", "-C", str(root), "status", "--porcelain"])),
            cases=cases,
            checks=len(cases),
            artifact_hashes=hashes,
            limitations=[
                "Full M21 remains inconclusive until scoped-controller native negative intake replay is reconciled",
                "Docker faults are real replacement processes; SQL timeout is a controlled transport exception",
                "Fresh disposable SQL state does not reset or refund any working holdout budget",
                "Trusted host, local keys and synthetic data; not independent attestation or universal malware detection",
                "Release/serving integration, M08 and image security blockers remain mandatory",
            ],
        )
        result["input_digests"].update(host_contracts=sources, data_lock=data_digest)
    finally:
        if validate(campaign)["container_id"] != marker["container_id"]:
            raise Rejected("M21_cleanup_identity_changed")
        docker(["stop", marker["container_id"]], timeout=60)
    result["finished_at"] = now()
    write_json(output, result)
    return result
