"""Hosted T13 mechanism qualification on an existing proposal and a separate signed control."""

import os
import subprocess
import time
import uuid
from contextlib import ExitStack
from pathlib import Path

from mlsecops import (
    promotion_controller,
    promotion_state,
    release_bundle,
    signing,
    storage,
    storage_bootstrap,
    storage_restore,
    trust_authority,
)
from mlsecops.canary_native_evidence import read_pinned
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
from mlsecops.release_reader import document
from mlsecops.security_event_config import Registry
from scripts import promotion_entrypoint_native as cli
from scripts import promotion_qualification, security_event_audit_fixture, serving_native
from scripts.material_bundle_native import release_snapshot
from scripts.release_reader_native import disposable
from scripts.restore_negative_native import history
from scripts.serving_output_native import source, verified_materials

SCOPE = "T13-pre-promotion-mechanism-actual-refusal-separate-controlled-authorization"
ENV = "local-cpu"
NEGATIVES = {
    "foreign-publisher": "untrusted_key",
    "missing-report": "storage_object_missing",
    "mismatched-subject": "release_authorization_context_mismatch",
    "proposal-alias-swap": "release_authorization_context_mismatch",
    "signed-model-substitution": "release_subject_binding",
    "trainer-self-approval": "untrusted_key",
    "publisher-self-approval": "untrusted_key",
    "unknown-schema": "release_approval_schema",
    "foreign-environment-replay": "release_policy_context_mismatch",
    "wrong-approval-environment": "release_authorization_context_mismatch",
    "wrong-approval-policy": "release_authorization_context_mismatch",
    "wrong-issuer": "release_authorization_context_mismatch",
    "missing-approval": "release_approval_required",
}


def require(condition):
    if not condition:
        raise Rejected("promotion_gate_evidence_mismatch")


def pins_from_owner():
    files = {
        "evidence/release-native.json": "M10_RELEASE_REPORT_SHA256",
        "storage-demo.json": "M10_STORAGE_DEMO_SHA256",
        "trusted-keys.json": "M10_KEYS_SHA256",
        "storage-trust.json": "M10_TRUST_SHA256",
    }
    if not all(os.environ.get(key) for key in files.values()):
        raise Rejected("promotion_gate_owner_pins_required")
    return {path: storage.object_id(os.environ[key]) for path, key in files.items()}


def negative_inputs(fixture, config, request, retain):
    """Each invocation changes one signed input or the operator environment."""
    auth = fixture.fixture
    manifest = release_bundle.index(
        fixture.arguments["package"]["envelope"], auth.bundle.materials.public
    )
    publisher = auth.bundle.materials.key
    keys = auth.authorities.keys

    def changed(case, field, payload, kind, key):
        ref = retain(signing.sign(payload, kind, key))
        return case, config, {**request, field + "_reference": ref}

    yield changed("foreign-publisher", "proposal", manifest, "model-release", keys["assessor"])
    # Model a mutable alias resolving to a second valid signed descriptor.
    # The original approvals and pinned environment are submitted unchanged.
    yield changed(
        "proposal-alias-swap",
        "proposal",
        {**manifest, "release_id": uuid.uuid4().hex},
        "model-release",
        publisher,
    )
    missing = digest(b"T13 intentionally absent report")
    assurance = {**auth.assurance, "reports": {**auth.assurance["reports"], "M22": missing}}
    yield changed("missing-report", "assurance", assurance, "release-assurance", keys["assessor"])
    alternate = {**manifest["materials"], "model": manifest["materials"]["model-card"]}
    yield changed(
        "signed-model-substitution",
        "proposal",
        {**manifest, "materials": alternate},
        "model-release",
        publisher,
    )
    trainer = auth.authorities.directory / "untrusted-trainer.pem"
    signing.create_key(trainer)
    yield changed(
        "trainer-self-approval",
        "approval",
        {**auth.approval, "issuer": "trainer"},
        "release-approval",
        trainer,
    )
    yield changed(
        "publisher-self-approval", "approval", auth.approval, "release-approval", publisher
    )
    for case, field, value in (
        ("mismatched-subject", "subject_sha256", request["proposal_reference"]),
        ("unknown-schema", "schema_version", 99),
        ("wrong-approval-policy", "policy_sha256", request["policy_reference"]),
        ("wrong-approval-environment", "environment", "foreign"),
        ("wrong-issuer", "issuer", "trainer"),
    ):
        yield changed(
            case, "approval", {**auth.approval, field: value}, "release-approval", keys["approver"]
        )
    context = config["context"]
    foreign = {**context, "policy": {**context["policy"], "environment": "foreign"}}
    yield "foreign-environment-replay", {**config, "context": foreign}, request
    yield "missing-approval", config, {**request, "approval_reference": None}


def snapshot(models):
    reader = models / "storage-clients/serving"
    return dict(
        head=promotion_state.state(reader, ENV),
        events=history(reader),
        objects=sorted(release_snapshot(reader)),
    )


def denied(root, directory, models, config, request, reason):
    before = snapshot(models)
    started = time.time_ns() // 1_000_000
    try:
        promotion_controller.submit(config, request)
    except Rejected as error:
        observed_reason = str(error)
        require(observed_reason == reason)
    else:
        raise Rejected("promotion_gate_negative_bypass")
    first_end = time.time_ns() // 1_000_000
    after_parent = snapshot(models)
    require(canonical(after_parent) == canonical(before))
    second_start = time.time_ns() // 1_000_000
    response = cli.invoke(root, directory, config, request, denied=True)
    finished = time.time_ns() // 1_000_000
    after = snapshot(models)
    require(canonical(after) == canonical(before))
    return dict(
        reason=observed_reason,
        request=request,
        cli=response,
        before=before,
        after_parent=after_parent,
        after=after,
        windows=[[started, first_end], [second_start, finished]],
    )


def check_audit(primary, *, registry_root, registry_pin, proposal, windows):
    require(len(primary["incidents"]) == len(windows) == 2)
    registry = Registry(
        primary["registry"],
        trusted_root=registry_root,
        expected_sha256=registry_pin,
        clock_ms=windows[0][0],
    )
    require(windows[0][1] <= windows[1][0])
    for seq, (incident, (start, end)) in enumerate(
        zip(primary["incidents"], windows, strict=True), 1
    ):
        event = registry.verify(incident["envelope"], clock_ms=incident["ingested_at_ms"])
        receipt = registry.receipt(incident["receipt"], event)
        value = event.document()
        require(
            (
                value["kind"],
                value["reason"],
                value["bundle_sha256"],
                value["asset_sha256"],
                value["sequence"],
            )
            == ("promotion.denied", "authorization", proposal, proposal, seq)
            and incident["late"] is False
            and receipt["late"] is False
            and start
            <= value["occurred_at_ms"]
            <= value["observed_at_ms"]
            <= receipt["ingested_at_ms"]
            == incident["ingested_at_ms"]
            and receipt["ingested_at_ms"] <= receipt["routed_at_ms"] <= end
        )


def actual_refusal(root, models, authority, trust_root, args, report):
    client = models / "storage-clients/promoter"
    request = cli.stage(client, args)
    require(
        request["proposal_reference"] == report["proposal_reference"]
        and request["assurance_reference"] is None
        and request["approval_reference"] is None
    )
    with security_event_audit_fixture.live() as audit:
        config = cli.configuration(
            client, authority / "storage-clients/promoter", args, trust_root, audit.audit_config
        )
        result = denied(
            root, models / "cli-denial", models, config, request, "release_assurance_required"
        )
        status, page = audit.exchange("GET", "/incidents/0")
        require(status == 200 and page["next_offset"] is None)
        pins = read_json(audit.audit_config)
        primary = dict(registry=read_json(Path(pins["registry_file"])), incidents=page["incidents"])
        check_audit(
            primary,
            registry_root=pins["registry_root"],
            registry_pin=pins["registry_sha256"],
            proposal=request["proposal_reference"],
            windows=result["windows"],
        )
        return dict(
            **result,
            audit=primary,
            registry_root=pins["registry_root"],
            registry_pin=pins["registry_sha256"],
        )


def check_transition(request, subject, before, first, committed, retry, repeated, selection, proof):
    reference = digest(canonical(selection))
    expected = {"environment": ENV, "release_ready": False}
    require(
        canonical(before["head"]) == canonical({**expected, "sequence": 0, "request_sha256": None})
        and before["events"] == []
    )
    require(
        canonical(first) == canonical(retry)
        and canonical(committed) == canonical(repeated)
        and canonical(committed["head"])
        == canonical({**expected, "sequence": 1, "request_sha256": reference})
        and len(committed["events"]) == 1
    )
    event = committed["events"][0]
    require(
        event["environment"] == ENV
        and event["sequence"] == 1
        and type(event["sequence"]) is int
        and event["request_sha256"] == reference
        and event["previous_sha256"] is None
    )
    require(
        first["state"] == "recorded-not-activated"
        and first["environment"] == ENV
        and first["release_ready"] is False
        and type(first["sequence"]) is int
        and first["sequence"] == 1
        and first["request_sha256"] == reference
        and first["subject_sha256"] == subject
        and first["proposal_reference"] == request["proposal_reference"]
    )
    proof_ref = digest(canonical(proof))
    require(
        set(committed["objects"]) == set(before["objects"]) | {reference, proof_ref}
        and selection["authorization_reference"] == proof_ref
        and selection["proposal_reference"] == request["proposal_reference"]
        and selection["subject_sha256"] == proof["decision"]["subject_sha256"] == subject
        and all(
            digest(canonical(proof[k + "_envelope"])) == request[k + "_reference"]
            for k in ("policy", "assurance", "approval")
        )
    )


def authorized_transition(root, models, config, request, *, directory, proposal_reference, subject):
    """Exercise an already staged, independently authorized first selection in owned SQL."""
    reader = models / "storage-clients/serving"
    require(
        Path(config["storage_client"]).resolve() == (models / "storage-clients/promoter").resolve()
        and request["proposal_reference"] == storage.object_id(proposal_reference)
    )
    descriptor = document(reader, proposal_reference, 1024 * 1024)
    require(digest(signing.decode64(descriptor["payload"])) == storage.object_id(subject))
    before = snapshot(models)
    require(
        canonical(before["head"])
        == canonical(dict(environment=ENV, sequence=0, request_sha256=None, release_ready=False))
        and before["events"] == []
    )
    first = cli.invoke(root, directory / "accept", config, request)
    committed = snapshot(models)
    retry = cli.invoke(root, directory / "retry", config, request)
    repeated = snapshot(models)
    selection = document(reader, first["request_sha256"], 65536)
    proof = document(reader, selection["authorization_reference"], 4 * 1024 * 1024)
    check_transition(request, subject, before, first, committed, retry, repeated, selection, proof)
    return dict(
        request=request,
        subject=subject,
        before=before,
        first=first,
        committed=committed,
        retry=retry,
        repeated=repeated,
        selection=selection,
        proof=proof,
    )


def matrix(root, models, authority, fixture):
    args = fixture.arguments
    client = models / "storage-clients/promoter"
    request = cli.stage(client, args)
    cases, mutations = {}, {}
    with security_event_audit_fixture.live() as audit:
        config = cli.configuration(
            client,
            authority / "storage-clients/promoter",
            args,
            fixture.trust_fixture.public,
            audit.audit_config,
        )

        def retain(envelope):
            ref = storage.put(client, "releases", canonical(envelope))
            mutations[ref] = envelope
            return ref

        for case, settings, inputs in negative_inputs(fixture, config, request, retain):
            cases[case] = denied(root, models / case, models, settings, inputs, NEGATIVES[case])
            cases[case]["environment"] = settings["context"]["policy"]["environment"]
        require(cases.keys() == NEGATIVES.keys())
    # A fresh collector gives the positive its own verified initial heartbeat window.
    with security_event_audit_fixture.live() as audit:
        config = {**config, "security_audit_config": str(audit.audit_config.resolve())}
        transition = authorized_transition(
            root,
            models,
            config,
            request,
            directory=models,
            proposal_reference=digest(canonical(args["package"]["envelope"])),
            subject=fixture.fixture.approval["subject_sha256"],
        )
    return dict(
        **transition,
        negatives=cases,
        mutations=mutations,
        trusted_root=args["trusted_root"],
        proposal=args["package"]["envelope"],
    )


def qualify(root, state):
    cli.hosted()
    pins = pins_from_owner()
    try:
        return capture(root, state, pins)
    except (Rejected, OSError, subprocess.TimeoutExpired):
        raise
    except Exception:
        # Collector startup, subprocess and SQL driver errors can contain private paths.
        raise Rejected("promotion_gate_capture_failed") from None


def capture(root, state, pins):
    root, state = root.resolve(), state.resolve()
    image = "trusted-mlsecops:dev"
    expected = source(root, image)
    original = storage_bootstrap.validate(state)
    ledger = storage_restore.ledger(original["name"])
    inputs = {name: decode(read_pinned(safe_child(state, name), pin)) for name, pin in pins.items()}
    report, demo, public = (
        inputs[key]
        for key in ("evidence/release-native.json", "storage-demo.json", "trusted-keys.json")
    )
    context, verified, package, publisher = verified_materials(root, state, expected)
    model = digest(verified["model"])
    require(
        verified["subject_sha256"] == report["subject_sha256"]
        and model == report["model_sha256"]
        and digest(canonical(package["envelope"])) == report["proposal_reference"]
        and publisher == public["approver"]
        and context["trust"] == inputs["storage-trust.json"]
        and context["candidate_reference"]
        == demo["candidate"]["candidate_reference"]
        == demo["evaluation"]["candidate_reference"]
        and context["evaluation_reference"] == demo["evaluation_reference"]
        and model == demo["candidate"]["metadata"]["model_digest"]
        and verified["manifest"]["release_id"] == report["campaign_id"]
    )
    policy = read_json(
        safe_child(state, f"release-proposals/{report['campaign_id']}/policy-envelope.json")
    )
    args = dict(
        package=package,
        policy_envelope=policy,
        assurance_envelope=None,
        approval_envelope=None,
        reports={},
        context=context,
        trusted_root=public["trust"],
        expected_policy=report["policy_sha256"],
        expected_serving_image=expected["image_id"],
    )
    campaign = uuid.uuid4().hex
    started = now()
    with ExitStack() as stack:
        cls = promotion_qualification.PromotionAdmissionContracts
        cls.setUpClass()
        stack.callback(cls.tearDownClass)
        fx = cls()
        stack.callback(lambda: require(fx.doCleanups()))
        fx.setUp()
        serving_native.bind_model(
            fx, expected["image_id"], verified["model"], demo["evaluation"]["report"]
        )
        require(
            publisher != fx.fixture.bundle.materials.public
            and verified["subject_sha256"] != fx.fixture.approval["subject_sha256"]
            and model == digest(fx.fixture.bundle.materials.fixture.model)
        )
        authority = stack.enter_context(disposable(root, state, campaign, "trust", 15445))
        trust_authority.install(authority, ENV, fx.trust_fixture.public)
        trust_authority.update(authority, args["expected_policy"], fx.trust_fixture.key)
        with disposable(root, state, campaign, "actual", 15444) as actual:
            promotion_state.install(actual)
            promotion_state.configure(actual, ENV, args["expected_policy"])
            refusal = actual_refusal(root, actual, authority, fx.trust_fixture.public, args, report)
        trust_authority.update(authority, fx.arguments["expected_policy"], fx.trust_fixture.key)
        with disposable(root, state, campaign, "control", 15444) as control:
            promotion_state.install(control)
            promotion_state.configure(control, ENV, fx.arguments["expected_policy"])
            controlled = matrix(root, control, authority, fx)
    require(
        not any(path.exists() for path in (actual, control, authority))
        and storage_bootstrap.validate(state) == original
        and storage_restore.ledger(original["name"]) == ledger
        and source(root, image) == expected
        and all(digest(bounded_read(safe_child(state, n))) == pin for n, pin in pins.items())
    )
    require(
        refusal["before"]["events"] == [] and refusal["before"]["head"]["request_sha256"] is None
    )
    packet = dict(
        schema_version=1,
        scope=SCOPE,
        source=expected,
        input_files=pins,
        actual_subject=verified["subject_sha256"],
        actual_model=model,
        actual_proposal=package["envelope"],
        actual_policy=policy,
        actual_policy_root=public["trust"],
        actual=refusal,
        controlled=controlled,
    )
    path = safe_child(state, "evidence/M10-promotion-primary.json")
    outcomes = {
        "actual-signed-proposal": verified["subject_sha256"],
        "actual-candidate-denied": refusal["reason"],
        "actual-signed-denials-delivered": len(refusal["audit"]["incidents"]),
        "actual-durable-sequence": refusal["after"]["head"]["sequence"],
        **{f"controlled-{k}": v["reason"] for k, v in controlled["negatives"].items()},
        "controlled-recorded-sequence": controlled["first"]["sequence"],
        "controlled-repeat-same-request": controlled["retry"]["request_sha256"],
    }
    targets = {
        "actual-signed-proposal": report["subject_sha256"],
        "actual-candidate-denied": "release_assurance_required",
        "actual-signed-denials-delivered": 2,
        "actual-durable-sequence": 0,
        **{f"controlled-{k}": v for k, v in NEGATIVES.items()},
        "controlled-recorded-sequence": 1,
        "controlled-repeat-same-request": controlled["first"]["request_sha256"],
    }
    require(canonical(outcomes) == canonical(targets))
    cases = [dict(id=k, expected=v, actual=outcomes[k], status="pass") for k, v in targets.items()]
    write_json(path, packet)
    return dict(
        status="pass",
        started_at=started,
        source_dirty=False,
        cases=cases,
        checks=len(cases),
        input_digests={
            **expected,
            "release_subject": report["subject_sha256"],
            "model": model,
            "candidate_reference": context["candidate_reference"],
            "evaluation_reference": context["evaluation_reference"],
            "proposal_reference": report["proposal_reference"],
            "promotion_policy": args["expected_policy"],
            "policy_reference": refusal["request"]["policy_reference"],
        },
        artifact_hashes={
            "promotion_primary": digest(bounded_read(path)),
            "actual_proposal_report": pins["evidence/release-native.json"],
        },
        metrics={
            "actual_release_authorization": "inconclusive",
            "actual_sequence": refusal["after"]["head"]["sequence"],
            "controlled_sequence": controlled["committed"]["head"]["sequence"],
            "controlled_negative_cases": len(controlled["negatives"]),
        },
        limitations=[
            "Actual proposal has no signed assurance or approval. Positive and retry use an independent controlled subject and authorities."
        ],
    )
