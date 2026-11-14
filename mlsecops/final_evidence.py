"""M18 offline acceptance of retained local-cpu evidence. Never a release authority."""

import os
import re
from datetime import datetime

from mlsecops import (
    data_source,
    evaluation_gate,
    evaluation_quality,
    holdout_budget,
    material_bundle,
    release_bundle,
    release_policy,
    reproducibility_gate,
)
from mlsecops.acceptance import GATES
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    safe_child,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.signing import decode64
from mlsecops.storage import object_id
from scripts.candidate_serving_reader import bind_proposal
from scripts.check_docs import SENSITIVE
from scripts.evaluation_contracts import SCOPE as EVALUATION_CONTRACT_SCOPE
from scripts.evaluation_contracts import case_ids as evaluation_contract_ids

CHILDREN = tuple(g for g in GATES if g != "M18")
INDEX = "evidence/M18-index.json"
LIMIT = release_policy.MAX_DOCUMENT
CARDS = ("docs/model-card.md", "docs/dataset-card.md")
REVIEWS = ("documentation", "expiry", "retention", "teardown", "redaction", "limitations")
# Which original input must bind, including names that differ between gate producers.
BINDINGS = {
    "M01": "worker_image",
    "M02": "source data_lock",
    "M03": "source data_lock dataset_reference candidate_reference evaluation_reference worker_image",
    "M04": "worker_image",
    "M05": "worker_image",
    "M06": "request policy source environment golden worker_image candidate_reference evaluation_reference dataset_reference model_digest candidate_training_input frozen_demo",
    "M07": "candidate_reference evaluation_reference dataset_reference dataset_source model holdout training_request evaluation_policy worker_image data_lock",
    "M08": "source image train validation data_lock candidate_reference evaluation_reference model_digest candidate_training_input",
    "M09": "image_id data_lock training_materials candidate_reference evaluation_reference model_digest candidate_training_input",
    "M10": "source_revision image_id release_subject model candidate_reference evaluation_reference proposal_reference promotion_policy policy_reference",
    "M11": "source_revision image_id candidate_reference proposal_reference model release_subject",
    "M12": "source_revision image_id candidate_reference evaluation_reference proposal_reference model release_subject",
    "M13": "source_revision image_id candidate_reference proposal_reference evaluation_reference model_sha256 subject_sha256",
    "M14": "source_revision image_id candidate_reference proposal_reference model_sha256 subject_sha256",
    "M15": "source_revision image_id candidate_reference proposal_reference model_sha256 subject_sha256",
    "M16": "source_revision image_id candidate_reference evaluation_reference proposal_reference qualified_candidate_subject qualified_candidate_model",
    "M17": "source_revision image_id dataset_reference candidate_reference evaluation_reference qualified_candidate_subject qualified_candidate_model proposal_reference",
    "M19": "source_revision candidate_reference qualified_model dataset qualified_subject",
    "M20": "image_id dataset_reference candidate_reference model_digest policy_digest",
    "M21": "worker_image candidate_reference dataset_reference model evaluation_reference policy trust data_lock",
    "M22": "source image train validation data_lock candidate_reference evaluation_reference model_digest",
    "M23": "source_revision image_id candidate_reference evaluation_reference model_sha256 model release_subject",
}
# Additional inputs must be present and well formed but belong to the experiment/control.
OTHER_INPUTS = {
    "M01": "inventory materials",
    "M03": "storage_config",
    "M06": "host_scripts mutated_worker_image",
    "M08": "host_scripts protocol security_probes trigger_probes",
    "M09": "host_scripts protocol probes reference_model_digest",
    "M14": "qualification_permit_sha256",
    "M15": "qualification_permit_sha256",
    "M16": "qualification_permit_sha256 stable_selection stable_subject",
    "M17": "controlled_subject controlled_model",
    "M21": "host_contracts kubernetes_candidate_reference",
    "M22": "host_scripts protocol probes",
}
PRIMARY = {
    "M01": "foundation_qualification",
    "M02": "data_qualification",
    "M03": "integrity_qualification",
    "M04": "isolation_qualification",
    "M05": "isolation_qualification",
    "M06": "reproducibility_qualification",
    "M07": "evaluation_gate",
    "M08": "poisoning_gate",
    "M09": "robustness_gate",
    "M20": "authority_qualification",
    "M21": "intake_gate",
    "M22": "absolute-poisoning_gate",
}
REQUIRED_ARTIFACTS = {
    "M10": "promotion_primary actual_proposal_report",
    "M11": "method_materials trust-contracts",
    "M12": "native contracts contract_materials",
    "M13": "method_materials controlled_contracts",
    "M14": "method_materials private_observation controlled_contracts",
    "M15": "method_materials controlled_contracts",
    "M16": "traffic_packet rollback_packet proposal_packet",
    "M17": "recovery_packet demo public_keys proposal_packet",
    "M19": "primary demo public_keys proposal graph snapshot fleet",
    "M22": "primary_materials review_intake review_primary review_observations review_decision",
    "M23": "method_materials stage-sources stage-inventory stage-outage",
}


class Invalid(Rejected):
    """Only fixed labels may reach the public report."""


class Missing(Rejected):
    pass


def need(condition, reason):
    if not condition:
        raise Invalid(reason)


def same(actual, expected, reason):
    need(canonical(actual) == canonical(expected), reason)


def subset(document, expected, reason):
    same({k: document.get(k) for k in expected}, expected, reason)


def timestamp(value):
    stamp = datetime.fromisoformat(value)
    need(stamp.utcoffset() is not None, "time-zone")
    return stamp


def pinned(path, reference, limit=LIMIT):
    object_id(reference)
    # lstat distinguishes missing files from broken links. bounded_read pins parents on POSIX.
    try:
        path.lstat()
    except FileNotFoundError:
        raise Missing("material-missing") from None
    raw = bounded_read(path, limit)
    need(digest(raw) == reference, "digest-mismatch")
    return raw


def blob(state, reference, limit=16 * LIMIT):
    return pinned(state / "evidence/M18-objects" / object_id(reference), reference, limit)


def retain(state, raw):
    """Store exact producer bytes. This function cannot issue an owner pin."""
    ref = digest(raw)
    atomic_write(safe_child(state, "evidence/M18-objects/" + ref), raw)
    return ref


def retain_package(state, package):
    for raw in (
        canonical(package["envelope"]),
        canonical(package["capsule"]["envelope"]),
        *package["documents"].values(),
        *package["capsule"]["objects"].values(),
    ):
        retain(state, raw)


def checked_at(label, action, *args):
    try:
        return action(*args)
    except (Invalid, Missing) as e:
        raise type(e)(f"{label}/{e}") from None
    except (
        ValueError,
        OSError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        OverflowError,
        RecursionError,
    ):
        raise Invalid(f"{label}/invalid-material") from None


def frozen(root, state, index, revision, fingerprint):
    files = index["freeze"]
    paths = (
        "storage-demo.json",
        "storage-trust.json",
        "trusted-keys.json",
        "evidence/release-native.json",
    )
    same(sorted(files), sorted(paths), "freeze-files")
    demo, trust, keys, proposal = (decode(pinned(safe_child(state, p), files[p])) for p in paths)
    src = dict(source_revision=revision, source_fingerprint=fingerprint, image_id=index["image_id"])
    # Replay the signed proposal at its externally pinned capture time. This verifies historical
    # evidence only. The promoter separately checks current validity, assurance and approval.
    captured = timestamp(proposal["finished_at"])
    need(
        proposal["full_M10"] == "inconclusive"
        and {
            "actual-candidate-without-assurance-denied",
            "actual-promotion-admission-without-assurance-denied",
        }
        <= set(proposal["cases"]),
        "actual-proposal-refusal",
    )
    need(captured <= timestamp(now()), "future-proposal")
    clock = int(captured.timestamp())
    policy_env = decode(blob(state, index["policy_reference"], LIMIT))
    policy = release_policy.verify_policy(
        policy_env,
        trusted_root=keys["trust"],
        expected_policy=proposal["policy_sha256"],
        environment="local-cpu",
        clock=clock,
    )
    publisher = policy["identities"]["publisher"]["public_key"]
    need(publisher == keys["approver"], "publisher")
    subset(trust, {k: keys[k] for k in ("curator", "evaluator")}, "data-authorities")
    need(
        len({decode64(keys[k]) for k in ("trust", "approver", "curator", "evaluator")}) == 4,
        "role-separation",
    )
    envelope = decode(blob(state, proposal["proposal_reference"], LIMIT))
    manifest = release_bundle.index(envelope, publisher)
    refs = manifest["materials"]
    capsule = decode(blob(state, refs["capsule"], material_bundle.MAX_ENVELOPE_BYTES))
    descriptors = material_bundle._index(capsule, publisher)["objects"]
    package = dict(
        envelope=envelope,
        documents={k: blob(state, refs[k], LIMIT) for k in release_bundle.DOCUMENTS},
        capsule=dict(
            envelope=capsule,
            objects={
                (r["namespace"], r["sha256"]): blob(state, r["sha256"], r["bytes"])
                for r in descriptors
            },
        ),
    )
    local = decode(bounded_read(root / "policies/local-cpu.json"))
    context, verified = bind_proposal(
        proposal,
        package,
        policy=local,
        source_trust=trust,
        publisher_public=publisher,
        expected=src,
        clock=clock,
    )
    need(
        verified["quality_component"] == "pass"
        and manifest["issuer"] == policy["identities"]["publisher"]["issuer"],
        "proposal-quality-or-issuer",
    )
    objects = package["capsule"]["objects"]
    metadata = decode(objects["candidates", refs["provenance"]])
    signed_eval = release_policy.checked(
        decode(objects["evaluations", context["evaluation_reference"]]),
        "stored-evaluation",
        trust["evaluator"],
    )
    splits = decode(package["documents"]["split_manifest"])["objects"]
    dataset_statement = release_policy.checked(
        decode(objects["manifests", refs["dataset_manifest"]]), "stored-dataset", trust["curator"]
    )
    projection = decode(package["documents"]["asset_projection"])["bindings"]
    lineage = release_policy.checked(
        decode(objects["lineage", projection["lineage_object"]]), "data-lineage", trust["curator"]
    )
    lock = data_source.validate_lock(root)
    lock_digest = digest(bounded_read(root / "data.lock"))
    subset(
        lineage,
        dict(
            source_sha256=lock["output"]["sha256"], lock_sha256=lock_digest, inputs=lock["inputs"]
        ),
        "data-lock",
    )
    same(
        demo["candidate"],
        dict(candidate_reference=context["candidate_reference"], metadata=metadata),
        "demo-candidate",
    )
    same(demo["evaluation"], signed_eval, "demo-evaluation")
    need(
        demo["evaluation_reference"] == context["evaluation_reference"], "demo-evaluation-reference"
    )
    subset(
        demo["dataset"],
        dict(
            dataset_reference=refs["dataset_manifest"],
            dataset_id=metadata["dataset_id"],
            lineage_id=metadata["lineage_id"],
            source_approval_digest=trust["source_approval_digest"],
        ),
        "demo-dataset",
    )
    need(
        package["documents"]["dependency-lock"] == bounded_read(root / "uv.lock"), "dependency-lock"
    )
    model, subject = refs["model"], verified["subject_sha256"]
    request, dataset_source = metadata["input_digest"], lineage["source_sha256"]
    values = dict(
        **src,
        candidate_reference=context["candidate_reference"],
        evaluation_reference=context["evaluation_reference"],
        dataset_reference=refs["dataset_manifest"],
        proposal_reference=proposal["proposal_reference"],
        release_subject=subject,
        subject_sha256=subject,
        qualified_subject=subject,
        qualified_candidate_subject=subject,
        model=model,
        model_digest=model,
        model_sha256=model,
        qualified_model=model,
        qualified_candidate_model=model,
        dataset=metadata["dataset_id"],
        source=dataset_source,
        dataset_source=dataset_source,
        data_lock=lock_digest,
        worker_image=src["image_id"],
        image=src["image_id"],
        request=request,
        candidate_training_input=request,
        training_request=request,
        policy=refs["evaluation_policy"],
        policy_digest=refs["evaluation_policy"],
        promotion_policy=proposal["policy_sha256"],
        policy_reference=index["policy_reference"],
        evaluation_policy=digest(canonical(evaluation_quality.freeze(local))),
        environment=digest(
            canonical(
                dict(image_id=src["image_id"], versions=metadata["versions"], OMP_NUM_THREADS="1")
            )
        ),
        train=splits["train.json"]["sha256"],
        validation=splits["validation.json"]["sha256"],
        holdout=splits["holdout.json"]["sha256"],
        golden=splits["holdout.json"]["sha256"],
        trust=digest(canonical(trust)),
        training_materials=digest(
            canonical({k: splits[k] for k in ("train.json", "validation.json")})
        ),
    )
    values.update(
        proposal_issued_at=manifest["issued_at"],
        proposal_expires_at=manifest["expires_at"],
        captured_at=clock,
        frozen_demo=files["storage-demo.json"],
        split_materials=metadata["materials"],
        prediction_protocol=signed_eval["report"]["prediction_protocol"],
        evaluation_scan=signed_eval["report"]["scan"],
        reproducibility_host_scripts=reproducibility_gate.host_source(root),
        evaluation_auprc=signed_eval["report"]["auprc"],
        integrity_snapshot={
            **{k: splits[k + ".json"]["sha256"] for k in ("train", "validation", "holdout")},
            "manifest": refs["split_manifest"],
            "index": refs["dataset_manifest"],
            "lineage": dataset_statement["lineage_object"],
            "approval": dataset_statement["approval_object"],
        },
        evaluation_metrics={
            k: signed_eval["report"][k]
            for k in (
                "rows",
                "positives",
                "auprc",
                "dummy_auprc",
                "auprc_gain",
                "slices",
                "confidence_intervals",
            )
        },
        evaluation_artifacts={
            "candidate_record": context["candidate_reference"],
            "signed_evaluation": context["evaluation_reference"],
            "metadata": refs["provenance"],
            "manifest": refs["split_manifest"],
            "reservation": signed_eval["holdout_access"]["reservation"],
        },
    )
    return values, keys, policy


def check_cases(gate, cases):
    need(isinstance(cases, list) and 1 <= len(cases) <= 5000, "cases")
    seen = set()
    for case in cases:
        name = case["id"]
        need(
            isinstance(name, str)
            and 0 < len(name) <= 256
            and name not in seen
            and case["status"] == "pass",
            "case-result",
        )
        seen.add(name)
        if gate in {"M08", "M09", "M22"} and set(case) == {"id", "status"}:
            continue
        need(set(case) == {"id", "status", "expected", "actual"}, "case-fields")
        expected, actual = case["expected"], case["actual"]
        need(
            not isinstance(actual, str)
            or actual.lower()
            not in {"skipped", "inconclusive", "not-run", "backend-not-available"},
            "skipped-case",
        )
        if gate == "M06" and name in {
            "three-run-numeric-repeat",
            "signed-candidate-three-fresh-repeats",
        }:
            same(expected, dict(probability_max=1e-6, auprc_max=1e-4), "numeric-thresholds")
            for key in ("probability", "auprc"):
                need(
                    type(actual[key]) in (float, int)
                    and 0 <= actual[key] <= expected[key + "_max"],
                    "numeric-result",
                )
        elif gate in {"M02", "M03"} and expected == "reject":
            need(
                isinstance(actual, str)
                and bool(re.fullmatch(r"[A-Za-z0-9_:/.-]+", actual))
                and actual.lower()
                not in {"pass", "skipped", "inconclusive", "success", "accepted"},
                "negative-result",
            )
        else:
            same(actual, expected, "case-observation")
    return seen


def check_gate(gate, report, values, latest, expected_cases):
    subset(
        report,
        dict(
            schema_version=1,
            gate=gate,
            profile="local-cpu",
            source_revision=values["source_revision"],
            policy_digest=values["policy"],
            redaction_version=1,
        ),
        "header",
    )
    if (
        report["status"] == "inconclusive"
        and type(report["exit_code"]) is int
        and report["exit_code"] == 2
    ):
        raise Missing("gate-inconclusive")
    subset(report, {"status": "pass", "exit_code": 0}, "gate-not-pass")
    # Five older wrappers omit source_dirty. Their producer bytes and source checkout
    # are pinned by the protected job. An explicitly dirty report always fails.
    default = False if gate in {"M01", "M03", "M04", "M05", "M20"} else None
    need(
        report.get("source_dirty", default) is False
        and report.get("release_ready", False) is False,
        "dirty-or-authorized",
    )
    need(
        timestamp(report["started_at"]) <= timestamp(report["finished_at"]) <= latest, "report-time"
    )
    risks = report["residual_risks"]
    need(
        isinstance(risks, list) and risks and all(isinstance(r, str) and r.strip() for r in risks),
        "limitations",
    )
    observed = check_cases(gate, report["cases"])
    # The approved, pre-run case inventory is independent of the reporting producer.
    same(digest(canonical(sorted(observed))), object_id(expected_cases), "case-inventory")
    metrics = report["metrics"]
    need(
        all(metrics.get(k, 0) == 0 for k in ("skipped", "skipped_gates", "skipped_cases")),
        "skipped-metrics",
    )
    if gate != "M02":
        same(metrics["checks"], len(observed), "case-count")
    inputs = report["input_digests"]
    for key, value in inputs.items():
        if key == "source_revision":
            need(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{40}", value), "input-revision")
        else:
            object_id(value.removeprefix("sha256:"))
    bindings = {k: values[k] for k in ("source_fingerprint", *BINDINGS[gate].split())}
    if gate in {"M08", "M22"}:
        bindings["source"] = values["source_fingerprint"]
    if gate == "M06":
        bindings["source"] = digest(
            canonical({k: values[k] for k in ("source_fingerprint", "source_revision")})
        )
    subset(inputs, bindings, "candidate-inputs")
    for k in OTHER_INPUTS.get(gate, "").split():
        object_id(inputs[k].removeprefix("sha256:") if k == "mutated_worker_image" else inputs[k])
    if gate == "M06":
        need(
            inputs["mutated_worker_image"].startswith("sha256:")
            and inputs["mutated_worker_image"] != values["image_id"],
            "mutation-image",
        )
    # Validate even redundant native aliases; a report cannot tell two different stories.
    for k in inputs.keys() & values.keys() - (
        {"source", "dataset"} if gate == "M06" else {"source"}
    ):
        same(inputs[k], values[k], "inconsistent-input")
    refs = report["artifact_hashes"]
    need(isinstance(refs, dict) and 1 <= len(refs) <= 2048, "artifacts")
    for k in REQUIRED_ARTIFACTS.get(gate, "").split():
        object_id(refs[k])
    return refs


def evaluation_cases():
    return {
        "controlled": evaluation_contract_ids(),
        "native": evaluation_gate.QUALITY_CASES,
        "budget": evaluation_gate.BUDGET_CASES,
    }


def evaluation_primary(report, packet, obj, values):
    refs = report["artifact_hashes"]
    groups = evaluation_cases()
    same(
        sorted(refs),
        sorted(
            [*values["evaluation_artifacts"], "contracts", "native", "budget", "evaluation_gate"]
        ),
        "evaluation-artifacts",
    )
    subset(refs, values["evaluation_artifacts"], "evaluation-signed-materials")
    subset(
        packet,
        {
            "schema_version": 1,
            "status": "pass",
            "source_dirty": False,
            "release_ready": False,
            "scope": "M07-synthetic-local-cpu-independent-evaluation",
            "checks": len(report["cases"]),
        },
        "evaluation-primary",
    )
    same(packet["metrics"], values["evaluation_metrics"], "evaluation-metrics")
    same(
        report["metrics"],
        {"checks": len(report["cases"]), **values["evaluation_metrics"]},
        "evaluation-metrics",
    )
    controlled, native, budget = (
        decode(obj(refs[name])) for name in ("contracts", "native", "budget")
    )
    same(controlled["scope"], EVALUATION_CONTRACT_SCOPE, "evaluation-controlled-scope")
    evaluation_gate.checked_cases(controlled, groups["controlled"])
    evaluation_gate.checked_cases(native, groups["native"])
    subset(
        native,
        {
            "scope": "native-frozen-evaluation-component-not-full-M07",
            **{
                k: values[k]
                for k in (
                    "candidate_reference",
                    "evaluation_reference",
                    "dataset_reference",
                    "source_fingerprint",
                    "image_id",
                )
            },
            "evaluation_policy_digest": values["evaluation_policy"],
            "metrics": values["evaluation_metrics"],
        },
        "evaluation-native",
    )
    evaluation_gate.check_budget(
        budget,
        values["image_id"],
        values["holdout"],
        values["source_fingerprint"],
        packet["started_at"],
    )
    claims = budget["concurrent_claims"]
    same(
        report["input_digests"]["budget_policy"],
        budget["budget_policy_digest"],
        "evaluation-budget-policy",
    )
    same(
        claims,
        dict(
            schema_version=1,
            diagnostic_only=True,
            complete=True,
            attempts=holdout_budget.LIMIT,
            claimed_slots=list(range(2, holdout_budget.LIMIT + 1)),
            rejection_codes={"holdout_budget_exhausted": 1},
            invalid_receipts=0,
        ),
        "evaluation-budget-claims",
    )
    for observed in (report, packet):
        same(
            observed["diagnostics"],
            {"holdout_concurrency": claims},
            "evaluation-budget-diagnostics",
        )
    need(
        timestamp(report["started_at"])
        <= timestamp(packet["started_at"])
        <= min(timestamp(native["observed_at"]), timestamp(budget["observed_at"]))
        and max(timestamp(native["observed_at"]), timestamp(budget["observed_at"]))
        <= timestamp(packet["finished_at"])
        <= timestamp(report["finished_at"]),
        "evaluation-time",
    )
    expected = {prefix + ":" + name for prefix, names in groups.items() for name in names} | {
        "signed-materials-reconciliation"
    }
    same(
        {c["id"]: [c["expected"], c["actual"]] for c in report["cases"]},
        {name: ["pass", "pass"] for name in expected},
        "evaluation-cases",
    )


def primary(gate, report, obj, values):
    for field in {"primary_materials", "review_primary"} & report["artifact_hashes"].keys():
        manifest = decode(obj(report["artifact_hashes"][field]))
        need(isinstance(manifest, dict) and 0 < len(manifest) <= 5000, "primary-manifest")
        for reference in manifest.values():
            obj(reference)
    if gate in PRIMARY:
        packet = decode(obj(report["artifact_hashes"][PRIMARY[gate]]))
        subset(packet, {"status": "pass", "cases": report["cases"]}, "primary-outcomes")
        subset(report["artifact_hashes"], packet.get("artifact_hashes", {}), "primary-artifacts")
        subset(report["input_digests"], packet.get("input_digests", {}), "primary-inputs")
        if gate == "M01":
            subset(
                packet["inventory"],
                dict(
                    source_dirty=False,
                    source_revision=values["source_revision"],
                    source_fingerprint=values["source_fingerprint"],
                ),
                "foundation-source",
            )
            subset(
                report["input_digests"],
                {k: digest(canonical(packet[k])) for k in ("inventory", "materials")},
                "foundation-inputs",
            )
        elif gate == "M02":
            subset(
                packet,
                dict(
                    source_sha256=values["source"],
                    source_lock_digest=values["data_lock"],
                    policy_digest=values["policy"],
                    rows=report["metrics"]["rows"],
                ),
                "data-primary",
            )
        elif gate == "M03":
            subset(
                packet,
                dict(
                    source_sha256=values["source"],
                    source_lock_digest=values["data_lock"],
                    candidate_reference=values["candidate_reference"],
                    dataset_reference=values["dataset_reference"],
                ),
                "integrity-candidate",
            )
            same(
                packet["storage_inputs"]["config_digest"],
                report["input_digests"]["storage_config"],
                "integrity-storage",
            )
            same(packet["execution"]["image_id"], values["image_id"], "integrity-image")
        elif gate == "M04":
            need(packet["dataset_reference"] == values["dataset_reference"], "access-dataset")
        elif gate == "M07":
            evaluation_primary(report, packet, obj, values)
        elif gate == "M05":
            subset(
                packet,
                {k: values[k] for k in ("candidate_reference", "model_sha256")},
                "isolation-candidate",
            )
            subset(
                packet["serving_under_fault"],
                dict(bundle_sha256=values["release_subject"], model_sha256=values["model"]),
                "isolation-subject",
            )
        elif gate == "M06":
            from mlsecops.reproducibility_offline import verify

            verify(report, packet, obj, values)
        elif gate == "M22":
            need(
                packet["scope"] == "M22-absolute-matrix-and-frozen-review"
                and type(report["metrics"]["independent_challenges"]) is int
                and report["metrics"]["independent_challenges"] >= 2,
                "independent-challenges",
            )
    if gate == "M10":
        subset(
            report["metrics"],
            dict(
                actual_release_authorization="inconclusive",
                actual_sequence=0,
                controlled_sequence=1,
            ),
            "promotion-mode",
        )
        packet = decode(obj(report["artifact_hashes"]["promotion_primary"]))
        actual = packet["actual"]["request"]
        subset(
            actual,
            dict(
                proposal_reference=values["proposal_reference"],
                policy_reference=values["policy_reference"],
                assurance_reference=None,
                approval_reference=None,
            ),
            "actual-denial-request",
        )
        need(
            digest(canonical(packet["actual_policy"])) == values["policy_reference"],
            "actual-policy",
        )
        control = packet["controlled"]
        need(
            object_id(control["subject"]) != values["release_subject"]
            and object_id(control["request"]["proposal_reference"]) != values["proposal_reference"],
            "controlled-subject",
        )
        same(control["first"], control["retry"], "controlled-retry")
        subset(
            control["first"],
            dict(
                subject_sha256=control["subject"],
                proposal_reference=control["request"]["proposal_reference"],
                sequence=1,
                release_ready=False,
                state="recorded-not-activated",
            ),
            "controlled-transition",
        )
        subset(
            packet,
            dict(
                scope="T13-pre-promotion-mechanism-actual-refusal-separate-controlled-authorization"
            ),
            "promotion-scope",
        )
        same(packet["actual"]["before"], packet["actual"]["after"], "promotion-state")
        same(packet["actual"]["after"]["head"]["sequence"], 0, "actual-sequence")
        same(packet["controlled"]["committed"]["head"]["sequence"], 1, "controlled-sequence")
        subset(
            packet,
            dict(actual_subject=values["release_subject"], actual_model=values["model"]),
            "promotion-subject",
        )
        need(
            packet["actual"]["reason"] == "release_assurance_required"
            and digest(canonical(packet["actual_proposal"])) == values["proposal_reference"],
            "promotion-refusal",
        )


def evidence_text(raw):
    text = raw.decode("utf-8")
    need(
        text.strip() and not any(pattern.search(text) for pattern in SENSITIVE),
        "empty-or-sensitive",
    )
    return text


def coverage(raw, modules):
    document = decode(raw)
    need(document["meta"]["branch_coverage"] is True, "branch-measurement")
    need(
        isinstance(modules, list)
        and "mlsecops/final_evidence.py" in modules
        and len(set(modules)) == len(modules),
        "coverage-scope",
    )
    files = {name.replace("\\", "/"): item for name, item in document["files"].items()}
    need(len(files) == len(document["files"]), "coverage-duplicate-path")
    for module in modules:
        need(re.fullmatch(r"(?:mlsecops|scripts)/[\w/]+\.py", module), "coverage-path")
        item = files[module]
        executed, missing = (item[k] for k in ("executed_branches", "missing_branches"))
        arcs = [tuple(arc) for arc in executed + missing]
        need(
            all(len(a) == 2 and all(type(n) is int for n in a) for a in arcs)
            and len(set(arcs)) == len(arcs),
            "coverage-arcs",
        )
        subset(
            item["summary"],
            dict(
                num_branches=len(arcs),
                covered_branches=len(executed),
                missing_branches=len(missing),
            ),
            "coverage-counts",
        )
        need(arcs and 100 * len(executed) >= 95 * len(arcs), "branch-threshold")


def images(refs, obj, values, latest, packages):
    from scripts import image_audit as audit

    def read(ref):
        return decode(obj(ref), audit.LIMIT)

    before = read(refs["runtime_before"])
    same(before, read(refs["runtime_after"]), "runtime-changed")
    src = {k: values[k] for k in ("source_revision", "source_fingerprint")}
    subset(before, src, "inventory-source")
    subset(
        before["controller_profile"], {**src, "image_id": values["image_id"]}, "controller-source"
    )
    need(
        before["workspace_id"]
        and before["cluster_uid"]
        and before["pods"]
        and {"workspace", "kind-node", "tracking-pg", "tracking-server"}
        <= {c["role"] for c in before["containers"]},
        "runtime-inventory",
    )
    report = read(refs["image_audit"])
    policy = {
        **audit.POLICY,
        "id": "observed-runtime-images-v1",
        "scope": [*audit.POLICY["scope"], "owned-runtime"],
    }
    subset(
        report,
        dict(
            **src,
            scope="observed-runtime-image-audit-only",
            status="pass",
            source_dirty=False,
            release_ready=False,
            policy=policy,
            policy_digest=digest(canonical(policy)),
            scanner_images=dict(syft=audit.SYFT_IMAGE, grype=audit.GRYPE_IMAGE),
            detection_control="pass",
            wolfi_detection_control="pass",
        ),
        "image-policy",
    )
    clock = timestamp(report["completed_at"])
    need(timestamp(report["started_at"]) <= clock <= latest, "image-time")
    control = read(report["detection_control_digest"])
    audit.detection_control(control, report["control_observation"]["exit_code"], clock)
    db = audit.database(control, clock)
    control = read(report["wolfi_detection_control_digest"])
    audit.wolfi_detection_control(control, report["wolfi_control_observation"]["exit_code"], clock)
    same(audit.database(control, clock), db, "control-db")
    for kind in audit.GO_CONTROLS:
        go = report["go_detection_controls"][kind]
        control = read(go["report_digest"])
        audit.go_detection_control(control, go["exit_code"], kind, clock)
        same(audit.database(control, clock), db, "control-db")
        need(go["status"] == "pass", "go-control")
    components = report["components"]
    targets = before["targets"]
    names = {t["name"] for t in targets}
    references = {t["reference"] for t in targets}
    need(
        values["image_id"] in references
        and len(names) == len(references) == len(targets)
        and names.isdisjoint({"worker", "storage", "tracking"})
        and {c["image_id"] for c in before["containers"]} <= references,
        "runtime-targets",
    )
    need(
        {p["image_id"] for p in before["pods"]}
        <= {t["config_id"] for t in targets} | {t["reference"].split("@")[-1] for t in targets},
        "pod-coverage",
    )
    need(
        sorted(c["name"] for c in components) == sorted(names | {"worker", "storage", "tracking"}),
        "scan-targets",
    )
    counts = audit.image_scope.coverage(before, components)
    need(counts["status"] == "pass", "runtime-coverage")
    same(report["runtime_scope"], counts, "coverage-claim")
    findings = set()
    for c in components:
        if c["name"] in audit.POLICY["scope"]:
            same(c["coverage_profile"], c["name"], "application-coverage")
        if c["name"] == "worker":
            same(c["runtime_image_id"], values["image_id"], "worker-image")
        subset(
            c,
            dict(
                status="pass",
                scan_executed=True,
                sbom_validated=True,
                diagnostic_only=False,
                scanner_exit_code=0,
            ),
            "scan-status",
        )
        required = packages[c["distro"] + "/" + c["coverage_profile"]]
        need(
            isinstance(required, list)
            and required
            and all(isinstance(p, str) and p for p in required),
            "package-scope",
        )
        result = audit.assess(
            read(c["sbom_digest"]),
            read(c["report_digest"]),
            c["image_config_id"],
            set(required),
            0,
            clock,
            distro=c["distro"],
        )
        subset(c, result, "scan-replay")
        same(result["database"], db, "scan-db")
        findings.update(f["id"] for f in result["findings"])
    same(report["vulnerability_count"], len(findings), "scan-count")


def challenges(report, obj, owner_key, reviewer):
    from scripts.absolute_poisoning import matrix as prescribed_matrix

    refs = report["artifact_hashes"]

    def signed(name, kind, public):
        return release_policy.checked(decode(obj(refs[name])), kind, public)

    intake = signed("review_intake", "m22-intake", owner_key)
    need(intake["reviewer_key"] == reviewer, "challenge-reviewer")
    freeze = release_policy.checked(intake["freeze"], "m22-freeze", reviewer)
    need(freeze["reviewer"] != intake["owner"], "challenge-owner")
    binding = freeze["binding"]
    subset(
        binding,
        dict(
            campaign_id=intake["campaign_id"],
            revision=report["source_revision"],
            primary_sha256=refs["primary_materials"],
            policy_sha256=report["policy_digest"],
        ),
        "challenge-subject",
    )
    subset(report["input_digests"], binding["inputs"], "challenge-inputs")
    subset(
        binding["inputs"],
        {k: report["input_digests"][k] for k in BINDINGS["M22"].split()},
        "challenge-candidate",
    )
    matrix = decode(obj(binding["matrix_report_sha256"]))
    same(matrix["input_digests"], binding["inputs"], "challenge-matrix")
    families = {"label-flip", "backdoor"}
    names = {c["id"] for c in prescribed_matrix()}
    records = matrix["records"]
    need(
        len(records) == len(names)
        and {r["id"] for r in records} == names
        and all(r["metrics"]["status"] == "pass" for r in records),
        "challenge-matrix-cases",
    )
    same(
        sorted(c["id"] for c in report["cases"]),
        sorted(names | {"review-" + family for family in families}),
        "challenge-final-cases",
    )
    methods = freeze["files"]
    same(
        sorted(methods),
        sorted(f + ext for f in families for ext in (".md", ".json")),
        "challenge-methods",
    )
    need(len(set(methods.values())) == 4, "duplicate-method")
    for ref in methods.values():
        evidence_text(obj(ref))
    observed = signed("review_observations", "m22-observations", owner_key)
    run_files = decode(obj(refs["review_primary"]))
    subset(run_files, methods, "executed-challenges")
    approval = release_policy.checked(
        decode(obj(run_files["methods.dsse.json"])), "m22-methods", reviewer
    )
    subset(
        approval,
        dict(intake_sha256=refs["review_intake"], matches_frozen_methods=True),
        "reviewed-methods",
    )
    subset(
        observed,
        dict(intake_sha256=refs["review_intake"], primary_sha256=refs["review_primary"]),
        "challenge-observation",
    )
    decision = signed("review_decision", "m22-decision", reviewer)
    same(decision["observations_sha256"], digest(canonical(observed)), "challenge-decision")
    dates = [
        freeze["frozen_at"],
        intake["received_at"],
        approval["checked_at"],
        observed["finished_at"],
        decision["decided_at"],
        report["finished_at"],
    ]
    stamps = list(map(timestamp, dates))
    need(stamps == sorted(stamps), "challenge-time")
    runs = observed["outcomes"]
    need(
        {r["run_id"] for r in runs}.isdisjoint(r["run_id"] for r in records), "challenge-run-reused"
    )
    need(
        len(runs) == 2
        and {r["id"] for r in runs} == {"review-" + f for f in families}
        and len({r["run_id"] for r in runs}) == 2
        and all(r["metrics"]["status"] == "pass" for r in runs),
        "challenge-runs",
    )
    same(sorted(decision["findings"]), sorted(families), "challenge-families")
    for f in decision["findings"].values():
        subset(f, dict(decision="pass", hard_boundary_bypass=False), "challenge-finding")
        evidence_text(obj(f["result_md_sha256"]))


def retained(index, reports, obj, values):
    # M13/M15 public wrappers deliberately keep observations in separate private admissions.
    same(sorted(index["retained"]), ["M13", "M15"], "private-admissions")
    for gate, ref in index["retained"].items():
        admission = decode(obj(ref))
        observation = decode(obj(admission["private_observation"]))
        subset(
            observation,
            dict(
                scope="actual-candidate-kubernetes-inference",
                source_dirty=False,
                source={
                    k: values[k] for k in ("source_revision", "source_fingerprint", "image_id")
                },
            ),
            "private-source-" + gate,
        )
        subset(
            observation,
            {
                k: values[k]
                for k in (
                    "candidate_reference",
                    "proposal_reference",
                    "model_sha256",
                    "subject_sha256",
                )
            },
            "private-candidate-" + gate,
        )
        need(
            timestamp(reports[gate]["started_at"])
            <= timestamp(observation["started_at"])
            <= timestamp(observation["finished_at"])
            <= timestamp(reports[gate]["finished_at"]),
            "private-time-" + gate,
        )
        for table in (admission["retained_packets"], observation["artifact_hashes"]):
            need(isinstance(table, dict) and table, "private-artifacts-" + gate)
            for reference in table.values():
                obj(reference)


def links(reports, freeze, obj, keys):
    artifacts = {g: r["artifact_hashes"] for g, r in reports.items()}
    proposal = freeze["evidence/release-native.json"]
    for g, field in (
        ("M10", "actual_proposal_report"),
        ("M16", "proposal_packet"),
        ("M17", "proposal_packet"),
        ("M19", "proposal"),
        ("M23", "candidate-outage-proposal_sha256"),
    ):
        same(artifacts[g][field], proposal, "proposal-capture-" + g)
    same(
        decode(obj(artifacts["M10"]["promotion_primary"]))["input_files"],
        freeze,
        "promotion-capture",
    )
    for g in ("M17", "M19"):
        same(artifacts[g]["demo"], freeze["storage-demo.json"], "demo-capture-" + g)
    same(artifacts["M17"]["public_keys"], digest(canonical(keys)), "recovery-keys")
    inventory_artifacts = artifacts["M19"]
    # The standalone collector pins the file including LF. Delivery additionally
    # pins all four original files and the canonical registry used by M17.
    if {"proposal_packet", "source_trust", "delivery_source"} & inventory_artifacts.keys():
        same(inventory_artifacts["public_keys"], digest(canonical(keys)), "inventory-keys")
        same(inventory_artifacts["proposal_packet"], proposal, "inventory-proposal")
        same(inventory_artifacts["source_trust"], freeze["storage-trust.json"], "inventory-trust")
        owner = decode(obj(inventory_artifacts["delivery_source"]))
        fleet_inputs = decode(obj(inventory_artifacts["fleet_inputs"]))
        same(fleet_inputs["delivery"], owner, "inventory-fleet-owner")
        same(owner["files"], freeze, "inventory-source-files")
        same(owner["owner"]["proposal_pin"], proposal, "inventory-owner-proposal")
        same(owner["storage_sha256"], inventory_artifacts["storage_marker"], "inventory-storage")
    else:
        same(inventory_artifacts["public_keys"], freeze["trusted-keys.json"], "inventory-keys")
    inventory = decode(obj(artifacts["M19"]["primary"]))
    need(
        inventory["schema_version"] == 2
        and digest(canonical(inventory["fleet"])) == artifacts["M19"]["fleet"],
        "inventory-fleet",
    )
    authority = artifacts["M20"]
    same(artifacts["M04"]["authority"], authority[PRIMARY["M20"]], "access-authority")
    for field in ("access", "controller", "isolation"):
        same(artifacts["M04"][field], authority[field], "authority-components")
    for field, ref in (
        ("access", artifacts["M04"][PRIMARY["M04"]]),
        ("isolation", authority["isolation"]),
    ):
        same(artifacts["M05"][field], digest(canonical(decode(obj(ref)))), "fault-components")


def governance(root, index, plan, reports, obj, values, keys, policy, latest):
    reviewer = plan["reviewer_key"]
    public = decode64(reviewer)
    need(
        len(public) == 32
        and public not in {decode64(key) for key in keys.values()}
        and public not in {decode64(role["public_key"]) for role in policy["identities"].values()},
        "reviewer-separation",
    )
    refs = index["governance"]
    same(
        sorted(refs),
        sorted(
            (
                *REVIEWS,
                *CARDS,
                "coverage",
                "image_audit",
                "runtime_before",
                "runtime_after",
                "review",
            )
        ),
        "governance-inventory",
    )
    snapshot = decode(obj(refs["runtime_before"]))
    access = decode(obj(reports["M04"]["artifact_hashes"][PRIMARY["M04"]]))
    same(access["cluster_namespace_uid"], snapshot["cluster_uid"], "cluster-identity")
    foundation = decode(obj(reports["M01"]["artifact_hashes"][PRIMARY["M01"]]))
    need(
        {p["image_id"] for p in foundation["pods"]} <= {p["image_id"] for p in snapshot["pods"]}
        and {i["image_id"] for i in foundation["images"].values()}
        <= {t["reference"] for t in snapshot["targets"]},
        "foundation-inventory",
    )
    checked_at("M22-review", challenges, reports["M22"], obj, keys["approver"], reviewer)
    checked_at("images", images, refs, obj, values, latest, plan["image_packages"])
    checked_at("coverage", coverage, obj(refs["coverage"]), plan["modules"])
    review = release_policy.checked(decode(obj(refs["review"])), "final-evidence-review", reviewer)
    subset(
        review,
        dict(
            scope="local-cpu",
            decision="pass",
            plan=index["plan"],
            reports=index["reports"],
            retained=index["retained"],
            source_revision=values["source_revision"],
            subject_sha256=values["release_subject"],
            model_sha256=values["model"],
            governance={k: v for k, v in refs.items() if k != "review"},
        ),
        "review-subject",
    )
    reviewed = timestamp(review["reviewed_at"])
    need(
        all(timestamp(r["finished_at"]) <= reviewed for r in reports.values())
        and reviewed <= latest,
        "review-time",
    )
    for path in CARDS:
        evidence_text(pinned(safe_child(root, path), refs[path]))
    for kind in REVIEWS:
        record = decode(obj(refs[kind]))
        subset(
            record,
            dict(kind=kind, subject_sha256=values["release_subject"], decision="pass"),
            "review-record-" + kind,
        )
        evidence_text(record["observation"].encode())
        attachments = record["evidence"]
        need(isinstance(attachments, list) and attachments, "review-evidence-" + kind)
        for ref in attachments:
            need(bool(obj(ref)), "review-empty-" + kind)
        if kind == "retention":
            backup = reports["M17"]["artifact_hashes"]["backup_id"]
            retained = decode(obj(record["inventory"]))
            subset(
                retained,
                dict(subject_sha256=values["release_subject"], backup_id=backup),
                "retention-backup",
            )
            need(
                timestamp(retained["observed_at"])
                <= reviewed
                < timestamp(retained["retain_until"]),
                "retention-window",
            )
        if kind == "expiry":
            need(
                values["proposal_issued_at"]
                <= values["captured_at"]
                < values["proposal_expires_at"]
                and record["proposal_expires_at"] == values["proposal_expires_at"],
                "expiry-observation",
            )
        if kind == "teardown":
            before, after = (decode(obj(record[k])) for k in ("before", "after"))
            for snapshot in (before, after):
                subset(
                    snapshot,
                    dict(workspace_id=decode(obj(refs["runtime_before"]))["workspace_id"]),
                    "teardown-workspace",
                )
            need(
                timestamp(before["observed_at"]) < timestamp(after["observed_at"]) <= reviewed
                and isinstance(before["owned"], list)
                and before["owned"]
                and after["owned"] == [],
                "teardown-observations",
            )


def external(state, path, name):
    ref = os.environ.get(name)
    if not ref:
        raise Missing(name + "-required")
    return decode(pinned(safe_child(state, path), ref)), ref


def published_report(state, gate, pin):
    """Accept original bytes or the exact report_sha256 projection printed by delivery."""
    object_id(pin)
    path = safe_child(state, "evidence/" + gate + ".json")
    if not path.exists():
        raise Missing("report-missing")
    raw = bounded_read(path, 16 * LIMIT)
    evidence_text(raw)
    report = decode(raw)
    if "report_sha256" in report:
        same(report.pop("report_sha256"), pin, "published-receipt")
        raw = canonical(report) + b"\n"
    need(digest(raw) == pin, "report-digest")
    return report


def delivery_gap(state, result):
    """Read an existing delivery_candidate receipt, including partial historical runs."""
    receipt, ref = checked_at(
        "delivery", external, state, "evidence/delivery-candidate.json", "M18_DELIVERY_SHA256"
    )
    pins = receipt["reports"]
    need(isinstance(pins, dict) and pins and pins.keys() <= set(CHILDREN), "delivery-gates")
    need(receipt["release_ready"] is False, "delivery-mode")
    candidate = receipt["candidate"]
    revision = candidate["source_revision"]
    need(isinstance(revision, str) and re.fullmatch(r"[a-f0-9]{40}", revision), "delivery-revision")
    pinned_values = {
        k: object_id(candidate[k])
        for k in (
            "source_fingerprint",
            "candidate_reference",
            "evaluation_reference",
            "qualified_candidate_subject",
            "qualified_candidate_model",
            "proposal_reference",
        )
    }
    image = candidate["image_id"]
    need(isinstance(image, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", image), "delivery-image")
    object_id(receipt["proposal_packet"])
    known = {
        **pinned_values,
        "image": image,
        "image_id": image,
        "worker_image": image,
        "source_revision": revision,
        **{
            k: pinned_values["qualified_candidate_model"]
            for k in ("model", "model_digest", "model_sha256", "qualified_model")
        },
        **{
            k: pinned_values["qualified_candidate_subject"]
            for k in ("release_subject", "subject_sha256", "qualified_subject")
        },
    }
    result.update(
        scope="delivery-receipt-gap-map",
        artifact_hashes={"delivery_receipt": ref},
        diagnostics=dict(
            delivery_source_revision=revision,
            receipt_matched=[],
            missing_receipts=[],
            unavailable=[],
        ),
    )
    diag = result["diagnostics"]
    failed = False
    for gate in CHILDREN:
        if gate not in pins:
            diag["missing_receipts"].append(gate)
            continue
        try:
            r = checked_at(gate, published_report, state, gate, pins[gate])
            subset(
                r,
                dict(
                    schema_version=1,
                    gate=gate,
                    source_revision=revision,
                    status="pass",
                    exit_code=0,
                    profile="local-cpu",
                ),
                "delivery-header",
            )
            need(
                r.get("source_dirty", False) is False and r.get("release_ready", False) is False,
                "delivery-dirty-or-authorized",
            )
            inputs = r["input_digests"]
            fields = {"source_fingerprint", *BINDINGS[gate].split()} & known.keys()
            subset(inputs, {k: known[k] for k in fields}, "delivery-candidate")
            if gate in {"M16", "M17"}:
                same(
                    r["artifact_hashes"]["proposal_packet"],
                    receipt["proposal_packet"],
                    "delivery-proposal",
                )
            diag["receipt_matched"].append(gate)
            result["artifact_hashes"][gate] = pins[gate]
        except (Missing, Invalid) as e:
            diag["unavailable"].append(gate)
            result["residual_risks"].append(gate + "/" + str(e).removeprefix(gate + "/"))
            failed |= isinstance(e, Invalid)
    result["metrics"]["matched_delivery_receipts"] = len(diag["receipt_matched"])
    raise (Invalid if failed else Missing)("full-pinned-evidence-required")


def clean(root, revision, fingerprint):
    need(
        command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and source_fingerprint(root) == fingerprint
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
        "checkout-changed",
    )


def qualify(root, state, result):
    result.update(
        scope="frozen-candidate-synthetic-lab",
        release_ready=False,
        production_authorized=False,
        residual_risks=[],
        metrics={"required_gates": len(CHILDREN), "verified_gates": 0},
    )

    def inspect():
        if not os.environ.get("M18_INDEX_SHA256") and os.environ.get("M18_DELIVERY_SHA256"):
            delivery_gap(state, result)
        index, index_ref = checked_at("index", external, state, INDEX, "M18_INDEX_SHA256")
        plan, plan_ref = checked_at(
            "plan", external, state, "evidence/M18-plan.json", "M18_PLAN_SHA256"
        )
        revision = result["source_revision"]
        fingerprint = result["input_digests"]["source_fingerprint"]
        header = dict(schema_version=1, source_revision=revision, source_fingerprint=fingerprint)
        subset(index, {**header, "plan": plan_ref}, "index-source")
        subset(plan, header, "plan-source")
        same(sorted(plan["cases"]), sorted(CHILDREN), "plan-gates")
        need(
            isinstance(index["reports"], dict) and index["reports"].keys() <= set(CHILDREN),
            "index-gates",
        )
        result["artifact_hashes"].update(owner_index=index_ref, frozen_plan=plan_ref)
        checked_at("source", clean, root, revision, fingerprint)
        values, keys, policy = checked_at(
            "freeze", frozen, root, state, index, revision, fingerprint
        )
        same(values["policy"], result["policy_digest"], "candidate-policy")
        result["input_digests"].update(
            {
                k: values[k]
                for k in (
                    "candidate_reference",
                    "evaluation_reference",
                    "dataset_reference",
                    "data_lock",
                    "model",
                    "release_subject",
                    "proposal_reference",
                    "image_id",
                )
            }
        )
        latest = timestamp(result["started_at"])
        reports, verified = {}, set()

        def obj(ref):
            return blob(state, ref, 64 * LIMIT)

        def child(g):
            if g not in index["reports"]:
                raise Missing("report-pin-missing")
            r = published_report(state, g, index["reports"][g])
            refs = check_gate(g, r, values, latest, plan["cases"][g])
            same(
                digest(canonical(sorted(refs))),
                object_id(plan["artifacts"][g]),
                "artifact-inventory",
            )
            if g in {"M02", "M03"}:
                same(
                    {c["id"]: c["actual"] for c in r["cases"] if c["expected"] == "reject"},
                    plan["rejections"][g],
                    "negative-observations",
                )
            for ref in refs.values():
                if ref not in verified:
                    obj(ref)
                    verified.add(ref)
            primary(g, r, obj, values)
            return r

        failed = False
        for gate in CHILDREN:
            try:
                reports[gate] = checked_at(gate, child, gate)
                result["artifact_hashes"][gate] = index["reports"][gate]
            except (Missing, Invalid) as e:
                result["residual_risks"].append(str(e))
                failed |= isinstance(e, Invalid)
        result["metrics"]["verified_gates"] = len(reports)
        if len(reports) != len(CHILDREN):
            raise (Invalid if failed else Missing)("incomplete-child-evidence")
        checked_at("links", links, reports, index["freeze"], obj, keys)
        checked_at("retained", retained, index, reports, obj, values)
        checked_at(
            "governance", governance, root, index, plan, reports, obj, values, keys, policy, latest
        )
        checked_at("source", clean, root, revision, fingerprint)
        result.update(
            status="pass",
            exit_code=0,
            source_dirty=False,
            cases=[dict(id=g, expected="pass", actual="pass", status="pass") for g in CHILDREN],
            residual_risks=[
                "Synthetic lab acceptance only; owner pin provenance and reviewer identity require independent custody.",
                "Release assurance, current policy validity and explicit promotion approval remain separate.",
            ],
        )
        result["metrics"]["checks"] = len(CHILDREN)

    try:
        checked_at("M18", inspect)
    except (Missing, Invalid) as e:
        result["residual_risks"].append(str(e))
        result.update(
            status="fail" if isinstance(e, Invalid) else "inconclusive",
            exit_code=1 if isinstance(e, Invalid) else 2,
        )
    result["finished_at"] = now()
    return result
