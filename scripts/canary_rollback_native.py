"""Hosted T19 recovery drill. Only disposable stores receive controlled release approvals."""

import asyncio
import copy
import re
import secrets
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from mlsecops import (
    audit_event,
    audit_snapshot,
    load_measurement,
    manual_review,
    promotion_state,
    release_bundle,
    release_policy,
    release_reader,
    release_rollback,
    security_event_config,
    serving_http,
    signing,
    storage,
    trust,
    trust_authority,
)
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    write_json,
)
from mlsecops.datasets import generate, validate_features
from mlsecops.load_golden import Golden
from mlsecops.load_probe import listen
from mlsecops.sandbox import resolve_image
from mlsecops.security_events import hexadecimal
from mlsecops.worker import train
from scripts import promotion_entrypoint_native as promoter
from scripts import security_event_audit_fixture, serving_native
from scripts.kube_approval_fixture import renew
from scripts.kube_rollback_native import variant
from scripts.promotion_qualification import PromotionAdmissionContracts
from scripts.release_reader_native import disposable

SCOPE = "controlled-signed-approvals-disposable-host-recovery"
ENV = "local-cpu"
NS = 1_000_000_000
STEPS = (
    "initial_trust",
    "select_a",
    "healthy_a",
    "select_b",
    "healthy_b",
    "revoke_b",
    "denied_b",
    "rollback_a",
    "restored_a",
    "reject_rollback_b",
    "revoke_a",
    "denied_a",
    "manual",
    "final_head",
)


def require(value):
    if not value:
        raise Rejected("canary_rollback_evidence")


def sha(obj):
    return digest(canonical(obj))


def stamp():
    return {"mono_ns": time.monotonic_ns(), "wall_ns": time.time_ns()}


def case_id(campaign, head):
    return sha({"campaign": campaign, "revoked_selection": head, "action": "manual-review"})


def completed(models, sequence):
    """Read the closed server journal, independently of the client's response label."""
    result = []
    for chunk in audit_snapshot.read_closed(models / f"serving-{sequence}" / "audit"):
        for line in chunk.splitlines():
            event = audit_event.checked(decode(line)["event"])
            if event["stage"] == "response_completed" and event["status"] == 200:
                require(event["route"] == "predict")
                ctx = event["context"]
                require(ctx["kind"] == "release-selection" and ctx["schema_version"] == 2)
                result.append(
                    {
                        "request_id": event["request_id"],
                        **{
                            k: ctx[k]
                            for k in (
                                "selection_sha256",
                                "authorization_sha256",
                                "approval_sha256",
                                "bundle_sha256",
                                "model_sha256",
                            )
                        },
                    }
                )
    return result


def releases(fixture, image, features):
    """Independent Python reference scores from each export. No serving output used as a golden."""
    first = train(
        {"action": "train", "train": generate(rows=1000), "seed": 17, "features": features}
    )
    serving_native.bind_model(fixture, image, signing.decode64(first["model"]), first)
    a = copy.deepcopy(fixture.arguments)
    renew(fixture, image)
    model_b, scores_b = variant(fixture, image, features)
    require(first["model_digest"] != model_b)
    return a, fixture.arguments, {"a": first["python_scores"][0], "b": scores_b[0]}


def rollback_args(a, prior, current, key):
    policy = release_policy.checked(a["policy_envelope"], "promotion-policy", a["trusted_root"])
    original = release_policy.checked(
        a["approval_envelope"], "release-approval", policy["identities"]["approver"]["public_key"]
    )
    intent = {
        "from_sequence": current["sequence"],
        "from_request_sha256": current["request_sha256"],
        "target_request_sha256": prior["request_sha256"],
    }
    approval = {
        **original,
        "schema_version": 2,
        "action": "rollback",
        "rollback": intent,
        "issued_at": int(time.time()),
        "sequence": current["sequence"] + 1,
    }
    return {**a, "approval_envelope": signing.sign(approval, "release-approval", key)}


def select(root, models, authority, args, trust_root):
    receipt = promoter.controlled(root, models, authority, args, trust_root)
    client = models / "storage-clients/serving"
    selection = release_reader.document(client, receipt["request_sha256"], 65536)
    proof = release_reader.document(
        client, selection["authorization_reference"], 4 * release_policy.MAX_DOCUMENT
    )
    with storage.connect(client) as db:
        event = db.execute(
            "SELECT request_sha256, previous_sha256, floor(extract(epoch FROM recorded_at))::bigint "
            "FROM ml_promotion.events WHERE environment = %s AND sequence = %s",
            (ENV, receipt["sequence"]),
        ).fetchone()
    require(event is not None)
    return {
        "receipt": receipt,
        "selection": selection,
        "authorization": proof,
        "head": promotion_state.state(client, ENV),
        "event": {"request_sha256": event[0], "previous_sha256": event[1], "sql_second": event[2]},
    }


def publish_trust(authority, fixture, policy, revoked):
    key, public = fixture.trust_fixture.key, fixture.trust_fixture.public
    stored = trust_authority.update(authority, policy, key, revoked_artifacts=revoked)
    envelope, clock = trust_authority.read(authority / "storage-clients/serving", ENV, public)
    require(sha(envelope) == stored["document_sha256"])
    return {"envelope": envelope, "sql_second": clock}


@contextmanager
def endpoint(models, authority, args, public, sequence):
    directory = models / f"serving-{sequence}"
    directory.mkdir(mode=0o700)
    audit = directory / "audit"
    audit.mkdir(mode=0o700)
    token = secrets.token_hex(32)
    credential = directory / "token"
    atomic_write(credential, token.encode())
    config = {
        k: args[k] for k in ("context", "trusted_root", "expected_policy", "expected_serving_image")
    }
    config.update(
        storage_client=str(models / "storage-clients/serving"),
        trust_client=str(authority / "storage-clients/serving"),
        trust_root=public,
        minimum_sequence=sequence,
        minimum_trust_version=1,
        token_file=str(credential),
        audit_directory=str(audit),
    )
    path = directory / "config.json"
    write_json(path, config)
    # configured() builds the production Reader and Docker-backed Engine. Lifespan owns teardown.
    with listen(serving_http.configured(path)) as port:
        yield port, token, credential


def predict(target, body, selection):
    port, token, _ = target
    status, response = asyncio.run(load_measurement.request(port, token, body))
    return dict(
        path="/v1/predict",
        payload_sha256=digest(body),
        selection_sha256=selection,
        status=status,
        response=response,
    )


def wait_denied(target, golden, selection):
    attempts = []
    deadline = time.monotonic() + 65
    while len(attempts) < 140 and time.monotonic() < deadline:
        start = stamp()
        value = predict(target, golden.body, selection)
        attempts.append(dict(start=start, end=stamp(), value=value))
        if value["status"] == 503:
            check_http(value, golden, selection, set(), unavailable=True)
            return attempts
        require(value["status"] == 200 and golden.valid(value["response"]))
        time.sleep(0.5)
    raise Rejected("canary_rollback_revocation_unobserved")


def reject_rollback(root, models, authority, public, args):
    client = models / "storage-clients/promoter"
    request = dict(
        schema_version=1,
        proposal_reference=sha(args["package"]["envelope"]),
        policy_reference=sha(args["policy_envelope"]),
        assurance_reference=sha(args["assurance_envelope"]),
        approval_reference=storage.put(client, "releases", canonical(args["approval_envelope"])),
    )
    with security_event_audit_fixture.live() as audit:
        config = promoter.configuration(
            client, authority / "storage-clients/promoter", args, public, audit.audit_config
        )
        before = promotion_state.state(client, ENV)
        try:
            promoter.promotion_controller.submit(config, request)
        except Rejected as error:
            refusal_code = str(error)
            require(refusal_code == "trust_artifact_revoked")
        else:
            raise Rejected("canary_revoked_target_admitted")
        require(canonical(before) == canonical(promotion_state.state(client, ENV)))
        status, first = audit.exchange("GET", "/incidents/0")
        require(status == 200 and len(first["incidents"]) == 1)
        start = stamp()
        outcome = promoter.invoke(root, models / "denied-rollback", config, request, denied=True)
        end = stamp()
        after = promotion_state.state(client, ENV)
        status, page = audit.exchange("GET", "/incidents/0")
        require(
            status == 200
            and len(page["incidents"]) == 2
            and page["incidents"][:1] == first["incidents"]
        )
        registry = read_json(audit.directory / "collector.json")
        return dict(
            before=before,
            after=after,
            request=request,
            refusal_code=refusal_code,
            approval=args["approval_envelope"],
            start=start,
            end=end,
            outcome=outcome,
            incident=page["incidents"][1],
            registry=dict(
                root=registry["registry_root"],
                pin=registry["registry_sha256"],
                envelope=read_json(registry["registry_file"]),
            ),
        )


def manual(root, state, target, case, body):
    port, _, credential = target

    def invoke(args, content=None):
        p = subprocess.run(
            [sys.executable, "-m", "mlsecops.manual_review", "--state", str(state), *args],
            cwd=root,
            input=content,
            capture_output=True,
            timeout=20,
            check=False,
        )
        if p.returncode or p.stderr:
            raise Rejected("canary_rollback_manual_cli")
        return decode(p.stdout, 4096)

    before = invoke(["list"])
    submitted = invoke(
        ["submit", "--case-sha256", case, "--port", str(port), "--token-file", str(credential)],
        body,
    )
    return {
        "before": before,
        "submitted": submitted,
        "after": invoke(["list"]),
        "payload_sha256": digest(body),
    }


def drill(root, state, image, campaign, features):
    promoter.hosted()
    hexadecimal(campaign, 32)
    validate_features(features, max_rows=1)
    root, state = Path(root).resolve(), Path(state).resolve()
    image = resolve_image(image)
    events = {}

    def record(name, fn, *args):
        start = stamp()
        value = fn(*args)
        events[name] = {"start": start, "end": stamp(), "value": value}
        return value

    with (
        disposable(root, state, campaign, "rollback-models", 15448) as models,
        disposable(root, state, campaign, "rollback-trust", 15449) as authority,
        ExitStack() as cleanup,
    ):
        PromotionAdmissionContracts.setUpClass()
        cleanup.callback(PromotionAdmissionContracts.tearDownClass)
        fixture = PromotionAdmissionContracts()
        cleanup.callback(lambda: require(fixture.doCleanups()))
        fixture.setUp()
        a, b, scores = releases(fixture, image, features)
        public, policy = fixture.trust_fixture.public, a["expected_policy"]
        promotion_state.install(models)
        promotion_state.configure(models, ENV, policy)
        trust_authority.install(authority, ENV, public)
        record("initial_trust", publish_trust, authority, fixture, policy, [])
        proposals = {"a": a["package"]["envelope"], "b": b["package"]["envelope"]}
        manifests = {
            label: release_bundle.index(env, fixture.fixture.bundle.materials.public)
            for label, env in proposals.items()
        }
        goldens = {
            label: Golden.from_expected(
                dict(
                    features=features,
                    scores=[scores[label]],
                    model=m["materials"]["model"],
                    bundle=sha(m),
                )
            )
            for label, m in manifests.items()
        }
        body = goldens["a"].body
        prior = record("select_a", select, root, models, authority, a, public)["receipt"]
        with endpoint(models, authority, a, public, 1) as target:
            healthy = record("healthy_a", predict, target, body, prior["request_sha256"])
            check_http(healthy, goldens["a"], prior["request_sha256"], set(), unavailable=False)
        current = record("select_b", select, root, models, authority, b, public)["receipt"]
        with endpoint(models, authority, b, public, 2) as target:
            healthy = record("healthy_b", predict, target, body, current["request_sha256"])
            check_http(healthy, goldens["b"], current["request_sha256"], set(), unavailable=False)
            record("revoke_b", publish_trust, authority, fixture, policy, [goldens["b"].model])
            record("denied_b", wait_denied, target, goldens["b"], current["request_sha256"])
        rollback = rollback_args(a, prior, current, fixture.fixture.authorities.keys["approver"])
        restored = record("rollback_a", select, root, models, authority, rollback, public)[
            "receipt"
        ]
        with endpoint(models, authority, rollback, public, 3) as target:
            healthy = record("restored_a", predict, target, body, restored["request_sha256"])
            check_http(healthy, goldens["a"], restored["request_sha256"], set(), unavailable=False)
            recovery_ns(events)
            negative = rollback_args(
                b, current, restored, fixture.fixture.authorities.keys["approver"]
            )
            record("reject_rollback_b", reject_rollback, root, models, authority, public, negative)
            record("revoke_a", publish_trust, authority, fixture, policy, [goldens["a"].model])
            record("denied_a", wait_denied, target, goldens["a"], restored["request_sha256"])
            record(
                "manual",
                manual,
                root,
                models,
                target,
                case_id(campaign, restored["request_sha256"]),
                body,
            )
        record("final_head", promotion_state.state, models / "storage-clients/serving", ENV)
        packet = dict(
            schema_version=1,
            scope=SCOPE,
            campaign=campaign,
            image=image,
            policy_root=a["trusted_root"],
            trust_root=public,
            proposals=proposals,
            features=features,
            scores=scores,
            events=events,
            completed_http=[completed(models, i) for i in (1, 2, 3)],
        )
        replay(packet)
    require(not models.exists() and not authority.exists())
    return packet


def timeline(events):
    require_fields(events, STEPS)
    clocks = []
    for phase in STEPS:
        event = events[phase]
        require_fields(event, ("start", "end", "value"))
        clocks.append(event["start"])
        if phase in ("denied_b", "denied_a"):
            attempts = event["value"]
            require(type(attempts) is list and 1 <= len(attempts) <= 140)
            for row in attempts:
                require_fields(row, ("start", "end", "value"))
                clocks.extend((row["start"], row["end"]))
        elif phase == "reject_rollback_b":
            clocks.extend((event["value"]["start"], event["value"]["end"]))
        clocks.append(event["end"])
    previous = origin = None
    for clock in clocks:
        require_fields(clock, ("mono_ns", "wall_ns"))
        require(all(type(n) is int and 0 < n < 2**63 for n in clock.values()))
        if previous is not None:
            require(all(clock[k] >= previous[k] for k in clock))
            # Same host throughout. Detect a shortened unsigned monotonic timeline.
            require(
                abs((clock["wall_ns"] - origin["wall_ns"]) - (clock["mono_ns"] - origin["mono_ns"]))
                <= 100_000_000
            )
        else:
            origin = clock
        previous = clock


def check_selection(event, manifest_envelope, root, image, seq, rollback):
    value = event["value"]
    require_fields(value, ("receipt", "selection", "authorization", "head", "event"))
    receipt, selection, proof = (value[k] for k in ("receipt", "selection", "authorization"))
    reference = sha(selection)
    promotion_state.request(canonical(selection))
    require_fields(
        proof,
        (
            "schema_version",
            "policy_envelope",
            "assurance_envelope",
            "approval_envelope",
            "reports",
            "decision",
        ),
    )
    require(
        type(proof["schema_version"]) is int
        and proof["schema_version"] == 1
        and sha(proof) == selection["authorization_reference"]
    )
    sql = value["event"]
    require_fields(sql, ("request_sha256", "previous_sha256", "sql_second"))
    clock = sql["sql_second"]
    require(
        sql["request_sha256"] == reference
        and type(clock) is int
        and event["start"]["wall_ns"] // NS <= clock <= event["end"]["wall_ns"] // NS
    )
    policy = release_policy.verify_policy(
        proof["policy_envelope"],
        trusted_root=root,
        expected_policy=selection["policy_sha256"],
        environment=ENV,
        clock=clock,
    )
    manifest = release_bundle.index(
        manifest_envelope, policy["identities"]["publisher"]["public_key"]
    )
    release_policy.window(manifest, clock)
    subject, proposal = sha(manifest), sha(manifest_envelope)
    assurance = release_policy.checked(
        proof["assurance_envelope"],
        "release-assurance",
        policy["identities"]["assessor"]["public_key"],
    )
    approval = release_policy.checked(
        proof["approval_envelope"],
        "release-approval",
        policy["identities"]["approver"]["public_key"],
    )
    release_policy.window(assurance, clock)
    release_policy.window(approval, clock)
    require(
        manifest["serving_image"] == image
        and manifest["environment"] == ENV
        and manifest["materials"]["preprocessing"] == manifest["materials"]["model"]
    )
    require(manifest["sequence"] == (1 if rollback is not None else seq))
    require(
        all(
            d["subject_sha256"] == subject
            and d["policy_sha256"] == selection["policy_sha256"]
            and d["environment"] == ENV
            for d in (assurance, approval)
        )
    )
    require(
        sha(assurance) == approval["assurance_sha256"] and assurance["reports"] == proof["reports"]
    )
    require(
        type(approval["sequence"]) is int
        and approval["sequence"] == seq
        and selection["sequence"] == seq
        and selection["environment"] == ENV
        and selection["subject_sha256"] == subject
        and selection["proposal_reference"] == proposal
        and all(selection[k] == approval[k] for k in ("issued_at", "expires_at"))
    )
    if rollback is None:
        require(approval["action"] == "promote" and approval["schema_version"] == 1)
    else:
        require(
            rollback == release_rollback.intent(approval, manifest["sequence"])
            and approval["schema_version"] == 2
        )
    head = dict(environment=ENV, sequence=seq, request_sha256=reference, release_ready=False)
    decision = dict(
        schema_version=approval["schema_version"],
        subject_sha256=subject,
        policy_sha256=selection["policy_sha256"],
        assurance_sha256=sha(assurance),
        approval_sha256=sha(approval),
        environment=ENV,
        sequence=seq,
        expires_at=approval["expires_at"],
        authorization_valid=True,
        state="authorized-not-activated",
        release_ready=False,
    )
    if rollback is not None:
        decision["rollback"] = rollback
    require(canonical(proof["decision"]) == canonical(decision))
    require(canonical(value["head"]) == canonical(head))
    require(
        canonical(receipt)
        == canonical(
            {
                **head,
                "state": "recorded-not-activated",
                "subject_sha256": subject,
                "proposal_reference": proposal,
                "trust": receipt["trust"],
            }
        )
    )
    return manifest, reference


def replay(record):
    """Replay an owner-pinned private record; embedded fixture public keys are not independent pins."""
    try:
        return _replay(record)
    except (KeyError, TypeError, IndexError, ValueError, OverflowError) as exc:
        raise Rejected("canary_rollback_evidence") from exc


def recovery_ns(events):
    elapsed = events["restored_a"]["end"]["mono_ns"] - events["revoke_b"]["start"]["mono_ns"]
    require(0 <= elapsed <= 120 * NS)
    return elapsed


def _replay(record):
    require_fields(
        record,
        (
            "schema_version",
            "scope",
            "campaign",
            "image",
            "policy_root",
            "trust_root",
            "features",
            "scores",
            "proposals",
            "events",
            "completed_http",
        ),
    )
    require(
        len(canonical(record)) <= 1024 * 1024
        and type(record["schema_version"]) is int
        and record["schema_version"] == 1
        and record["scope"] == SCOPE
    )
    campaign = hexadecimal(record["campaign"], 32)
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", record["image"]) is not None)
    events = record["events"]
    timeline(events)
    require_fields(record["proposals"], ("a", "b"))
    require_fields(record["scores"], ("a", "b"))
    validate_features(record["features"], max_rows=1)
    signed_trust = previous = None
    goldens, references = {}, []
    completed_http = []
    seen = set()
    for seq, (label, selection, trust_phase, healthy) in enumerate(
        (
            ("a", "select_a", "initial_trust", "healthy_a"),
            ("b", "select_b", "initial_trust", "healthy_b"),
            ("a", "rollback_a", "revoke_b", "restored_a"),
        ),
        1,
    ):
        step = events[selection]
        rollback = (
            None
            if seq < 3
            else {
                "from_sequence": 2,
                "from_request_sha256": references[1],
                "target_request_sha256": references[0],
            }
        )
        manifest, ref = check_selection(
            step, record["proposals"][label], record["policy_root"], record["image"], seq, rollback
        )
        require(
            step["value"]["event"]["previous_sha256"] == (references[-1] if references else None)
        )
        golden = Golden.from_expected(
            dict(
                features=record["features"],
                scores=[record["scores"][label]],
                model=manifest["materials"]["model"],
                bundle=sha(manifest),
            )
        )
        goldens[label] = golden
        if seq == 2:
            require(golden.model != goldens["a"].model and golden.bundle != goldens["a"].bundle)
        references.append(ref)
        grant = events[trust_phase]["value"]["envelope"]
        receipt = step["value"]["receipt"]
        require(
            canonical(receipt["trust"])
            == canonical({"version": 1 if seq < 3 else 2, "document_sha256": sha(grant)})
        )
        require(
            step["value"]["selection"]["policy_sha256"]
            == events["select_a"]["value"]["selection"]["policy_sha256"]
        )
        http = events[healthy]["value"]
        check_http(http, golden, ref, seen, unavailable=False)
        successful = [http]
        if seq > 1:
            refusal = events["denied_b" if seq == 2 else "denied_a"]["value"]
            successful.extend(attempt["value"] for attempt in refusal[:-1])
        completed_http.append(
            [
                dict(
                    request_id=item["response"]["request_id"],
                    selection_sha256=ref,
                    authorization_sha256=step["value"]["selection"]["authorization_reference"],
                    approval_sha256=step["value"]["authorization"]["decision"]["approval_sha256"],
                    bundle_sha256=golden.bundle,
                    model_sha256=golden.model,
                )
                for item in successful
            ]
        )
        require(events[healthy]["end"]["wall_ns"] // NS < step["value"]["selection"]["expires_at"])
    require(canonical(completed_http) == canonical(record["completed_http"]))
    policy = events["select_a"]["value"]["selection"]["policy_sha256"]
    for version, phase in enumerate(("initial_trust", "revoke_b", "revoke_a"), 1):
        step = events[phase]
        value = step["value"]
        require_fields(value, ("sql_second", "envelope"))
        clock = value["sql_second"]
        require(
            type(clock) is int
            and step["start"]["wall_ns"] // NS <= clock <= step["end"]["wall_ns"] // NS
        )
        signed_trust = trust.validate(value["envelope"], record["trust_root"], ENV, clock)
        artifacts = [goldens["b"].model, goldens["a"].model][: version - 1]
        require(
            signed_trust["version"] == version
            and signed_trust["promotion_policy_sha256"] == policy
            and signed_trust["revoked_artifacts"] == sorted(artifacts)
            and signed_trust["revoked_keys"] == []
            and step["start"]["wall_ns"] // NS <= signed_trust["issued_at"] <= clock
        )
        if previous is not None:
            trust.successor(previous, signed_trust)
        previous = signed_trust
    for label, phase, index in (("b", "denied_b", 1), ("a", "denied_a", 2)):
        attempts = events[phase]["value"]
        for i, attempt in enumerate(attempts):
            check_http(
                attempt["value"],
                goldens[label],
                references[index],
                seen,
                unavailable=i == len(attempts) - 1,
            )
        selected = events["select_b" if label == "b" else "rollback_a"]["value"]["selection"]
        # An expired selection cannot establish that revocation caused the 503.
        require(events[phase]["end"]["wall_ns"] // NS < selected["expires_at"])
    elapsed = recovery_ns(events)
    fallback = events["manual"]["value"]
    reason = check_denial(
        events["reject_rollback_b"]["value"], events, references, record["policy_root"]
    )
    require(
        events["manual"]["end"]["wall_ns"] // NS
        < events["rollback_a"]["value"]["selection"]["expires_at"]
    )
    item = {"case_sha256": case_id(campaign, references[2]), "status": manual_review.PENDING}
    require(
        fallback
        == {
            "before": [],
            "submitted": item,
            "after": [item],
            "payload_sha256": digest(goldens["a"].body),
        }
    )
    require(
        canonical(events["final_head"]["value"]) == canonical(events["rollback_a"]["value"]["head"])
    )
    return dict(
        scope=SCOPE,
        release_ready=False,
        campaign=campaign,
        recovery_ns=elapsed,
        from_request_sha256=references[1],
        target_request_sha256=references[0],
        restored_request_sha256=references[2],
        restored_bundle=goldens["a"].bundle,
        restored_model=goldens["a"].model,
        refusal_statuses=[
            events[k]["value"][-1]["value"]["status"] for k in ("denied_b", "denied_a")
        ],
        refusal_attempts=[len(events[k]["value"]) for k in ("denied_b", "denied_a")],
        rejected_rollback_event=reason,
        pending_case_sha256=item["case_sha256"],
    )


def check_denial(value, events, refs, root):
    require_fields(
        value,
        (
            "before",
            "after",
            "request",
            "approval",
            "start",
            "end",
            "outcome",
            "incident",
            "registry",
            "refusal_code",
        ),
    )
    b = events["select_b"]["value"]
    head = events["rollback_a"]["value"]["head"]
    require(canonical(value["before"]) == canonical(head) == canonical(value["after"]))
    require(value["refusal_code"] == "trust_artifact_revoked")
    require(
        canonical(value["outcome"]) == canonical({"status": "rejected", "release_ready": False})
    )
    proof, selection = b["authorization"], b["selection"]
    clock = value["start"]["wall_ns"] // NS
    policy = release_policy.verify_policy(
        proof["policy_envelope"],
        trusted_root=root,
        expected_policy=selection["policy_sha256"],
        environment=ENV,
        clock=clock,
    )
    public = policy["identities"]["approver"]["public_key"]
    old = release_policy.checked(proof["approval_envelope"], "release-approval", public)
    approval = release_policy.checked(value["approval"], "release-approval", public)
    release_policy.window(approval, clock)
    intent = {"from_sequence": 3, "from_request_sha256": refs[2], "target_request_sha256": refs[1]}
    require(
        canonical(approval)
        == canonical(
            {
                **old,
                "schema_version": 2,
                "sequence": 4,
                "action": "rollback",
                "issued_at": approval["issued_at"],
                "rollback": intent,
            }
        )
    )
    require(approval["issued_at"] >= events["restored_a"]["end"]["wall_ns"] // NS)
    require(release_rollback.intent(approval, 2) == intent)
    proposal = selection["proposal_reference"]
    require(
        value["request"]
        == dict(
            schema_version=1,
            proposal_reference=proposal,
            approval_reference=sha(value["approval"]),
            policy_reference=sha(proof["policy_envelope"]),
            assurance_reference=sha(proof["assurance_envelope"]),
        )
    )
    registry = value["registry"]
    require_fields(registry, ("envelope", "root", "pin"))
    start, end = (value[k]["wall_ns"] // 1_000_000 for k in ("start", "end"))
    auth = security_event_config.Registry(
        registry["envelope"],
        trusted_root=registry["root"],
        expected_sha256=registry["pin"],
        clock_ms=end,
    )
    incident = value["incident"]
    require_fields(incident, ("envelope", "receipt", "ingested_at_ms", "late"))
    event = auth.verify(incident["envelope"], clock_ms=incident["ingested_at_ms"])
    receipt = auth.receipt(incident["receipt"], event)
    doc = event.document()
    require(
        doc["kind"] == "promotion.denied"
        and doc["reason"] == "trust"
        and doc["asset_sha256"] == doc["bundle_sha256"] == proposal
        and start
        <= doc["occurred_at_ms"]
        <= doc["observed_at_ms"]
        <= receipt["ingested_at_ms"]
        <= receipt["routed_at_ms"]
        <= end
        and receipt["ingested_at_ms"] == incident["ingested_at_ms"]
        and receipt["late"] is incident["late"]
    )
    return doc["event_id"]


def check_http(http, golden, ref, seen, *, unavailable):
    require_fields(http, ("path", "payload_sha256", "selection_sha256", "status", "response"))
    require(
        http["path"] == "/v1/predict"
        and http["payload_sha256"] == digest(golden.body)
        and http["selection_sha256"] == ref
        and type(http["status"]) is int
    )
    reply = http["response"]
    identifier = hexadecimal(reply["request_id"], 32)
    require(identifier not in seen)
    seen.add(identifier)
    if unavailable:
        require(
            http["status"] == 503
            and canonical(reply)
            == canonical(
                {
                    "schema_version": 1,
                    "request_id": identifier,
                    "error": {"code": "model_unavailable"},
                }
            )
        )
    else:
        require(http["status"] == 200 and golden.valid(reply))
