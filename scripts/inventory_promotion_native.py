"""Submit authenticated inventory failures against the already selected controlled release."""

from mlsecops import promotion_state, release_policy, signing, storage
from mlsecops.contracts import Rejected, canonical, decode, read_json, require_fields
from scripts import canary_rollback_native as drill
from scripts import promotion_entrypoint_native as promoter
from scripts import security_event_audit_fixture


def rejected_report(fault, finding, base):
    return {
        **base,
        "status": "fail",
        "exit_code": 1,
        "cases": [
            dict(id="M19-" + fault, status="fail", expected="reconciled", actual=finding["reason"])
        ],
        "artifact_hashes": {k: finding[k] for k in ("graph", "snapshot")},
    }


def capture(models, authority, fixture, args, public, findings):
    client = models / "storage-clients/promoter"
    read_client = models / "storage-clients/serving"
    base = decode(args["reports"]["M19"])
    proofs = {}
    for fault, finding in findings.items():
        report = rejected_report(fault, finding, base)
        report_pin = storage.put(client, "releases", canonical(report))
        assessor = fixture.fixture
        # bind_model already re-signed the controlled approval to these exact materials.
        old_assurance = release_policy.checked(
            args["assurance_envelope"], "release-assurance", assessor.authorities.public["assessor"]
        )
        assurance = {**old_assurance, "reports": {**old_assurance["reports"], "M19": report_pin}}
        old_approval = release_policy.checked(
            args["approval_envelope"], "release-approval", assessor.authorities.public["approver"]
        )
        approval = {**old_approval, "assurance_sha256": drill.sha(assurance)}
        signed = {}
        for role, kind, doc in (
            ("assessor", "assurance", assurance),
            ("approver", "approval", approval),
        ):
            signed[kind] = signing.sign(doc, "release-" + kind, assessor.authorities.keys[role])
        request = dict(
            schema_version=1,
            proposal_reference=drill.sha(args["package"]["envelope"]),
            policy_reference=drill.sha(args["policy_envelope"]),
            **{
                k + "_reference": storage.put(client, "releases", canonical(v))
                for k, v in signed.items()
            },
        )
        with security_event_audit_fixture.live() as audit:
            config = promoter.configuration(
                client, authority / "storage-clients/promoter", args, public, audit.audit_config
            )
            before = promotion_state.state(read_client, drill.ENV)
            start = drill.stamp()
            try:
                promoter.promotion_controller.submit(config, request)
            except Rejected as error:
                drill.require(str(error) == "release_gate_not_accepted")
            else:
                raise Rejected("M19_invalid_inventory_promoted")
            end = drill.stamp()
            after = promotion_state.state(read_client, drill.ENV)
            status, page = audit.exchange("GET", "/incidents/0")
            drill.require(status == 200 and len(page["incidents"]) == 1 and before == after)
            cfg = read_json(audit.directory / "collector.json")
            proofs[fault] = dict(
                base=base,
                report=report,
                request=request,
                **signed,
                before=before,
                after=after,
                start=start,
                end=end,
                incident=page["incidents"][0],
                registry=dict(
                    root=cfg["registry_root"],
                    pin=cfg["registry_sha256"],
                    envelope=read_json(cfg["registry_file"]),
                ),
            )
    return proofs


def replay(proofs, findings, durable):
    selected = durable["events"]["select_a"]["value"]
    original = selected["authorization"]
    head = selected["head"]
    require_fields(proofs, findings)
    ids = set()
    previous = durable["events"]["healthy_a"]["end"]
    for fault, finding in findings.items():
        item = proofs[fault]
        report = item["report"]
        clock = item["start"]["wall_ns"] // drill.NS
        policy = release_policy.verify_policy(
            original["policy_envelope"],
            trusted_root=durable["policy_root"],
            expected_policy=selected["selection"]["policy_sha256"],
            environment=drill.ENV,
            clock=clock,
        )
        signatures = {}
        for kind, role in (("assurance", "assessor"), ("approval", "approver")):
            key = policy["identities"][role]["public_key"]
            old = release_policy.checked(original[kind + "_envelope"], "release-" + kind, key)
            new = release_policy.checked(item[kind], "release-" + kind, key)
            release_policy.window(new, clock)
            expected = (
                {**old, "reports": {**old["reports"], "M19": drill.sha(report)}}
                if kind == "assurance"
                else {**old, "assurance_sha256": drill.sha(signatures["assurance"])}
            )
            drill.require(canonical(expected) == canonical(new))
            signatures[kind] = new
        req = dict(
            schema_version=1,
            proposal_reference=selected["selection"]["proposal_reference"],
            policy_reference=drill.sha(original["policy_envelope"]),
            assurance_reference=drill.sha(item["assurance"]),
            approval_reference=drill.sha(item["approval"]),
        )
        drill.require(
            canonical(item["request"]) == canonical(req)
            and canonical(head) == canonical(item["before"]) == canonical(item["after"])
        )
        drill.require(drill.sha(item["base"]) == original["reports"]["M19"])
        expected_report = rejected_report(fault, finding, item["base"])
        manifest = signing.verify(
            durable["proposals"]["a"],
            "model-release",
            policy["identities"]["publisher"]["public_key"],
        )
        drill.require(
            report["gate"] == "M19"
            and report["input_digests"]
            == dict(release_subject=drill.sha(manifest), model=manifest["materials"]["model"])
            and canonical(expected_report) == canonical(report)
            and report["source_revision"] == manifest["source_commit"]
            and report["policy_digest"] == manifest["materials"]["evaluation_policy"]
        )
        clocks = [
            previous,
            item["start"],
            item["end"],
            durable["events"]["select_b"]["start"],
        ]
        drill.require(
            all(
                [p[k] for p in clocks] == sorted(p[k] for p in clocks)
                for k in ("mono_ns", "wall_ns")
            )
        )
        previous = item["end"]
        identity = drill.check_incident(item, req["proposal_reference"], "authorization")
        drill.require(identity not in ids)
        ids.add(identity)
    return sorted(ids)
