import re
from datetime import datetime

from mlsecops import release_bundle, release_policy, release_rollback, signing
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.storage import object_id


def bound(envelope, kind, role, policy, release, clock, fields, *, schema_version=1):
    if envelope is None:
        raise Rejected(f"{kind.replace('-', '_')}_required")
    identity = policy["identities"][role]
    payload = release_policy.checked(envelope, kind, identity["public_key"])
    require_fields(
        payload,
        (
            "schema_version",
            "issuer",
            "subject_sha256",
            "environment",
            "policy_sha256",
            "issued_at",
            "expires_at",
            *fields,
        ),
    )
    expected = {
        "schema_version": schema_version,
        "issuer": identity["issuer"],
        "subject_sha256": release["subject_sha256"],
        "environment": policy["environment"],
        "policy_sha256": digest(canonical(policy)),
    }
    if canonical({name: payload[name] for name in expected}) != canonical(expected):
        raise Rejected("release_authorization_context_mismatch")
    issued, expires = release_policy.window(payload, clock, 3600)
    if issued < max(release["manifest"]["issued_at"], policy["issued_at"]) or expires > min(
        policy["expires_at"], release["manifest"]["expires_at"]
    ):
        raise Rejected("release_authorization_time_binding")
    return payload


def verify_reports(reports, assurance, release, policy):
    if (
        not isinstance(reports, dict)
        or set(reports) != set(policy["required_gates"])
        or not isinstance(assurance["reports"], dict)
        or set(assurance["reports"]) != set(reports)
    ):
        raise Rejected("release_gate_set_incomplete")
    if (
        any(
            not isinstance(content, bytes) or not 0 < len(content) <= release_policy.MAX_DOCUMENT
            for content in reports.values()
        )
        or sum(len(content) for content in reports.values()) > 8 * release_policy.MAX_DOCUMENT
    ):
        raise Rejected("release_reports_size_limit")
    for gate, content in reports.items():
        if digest(content) != object_id(assurance["reports"][gate]):
            raise Rejected("release_gate_report_digest")
        report = decode(content, release_policy.MAX_DOCUMENT)
        if not isinstance(report, dict):
            raise Rejected("release_gate_report_schema")
        expected = {
            "schema_version": 1,
            "gate": gate,
            "status": "pass",
            "exit_code": 0,
            "profile": policy["environment"],
            "source_revision": release["manifest"]["source_commit"],
            "source_dirty": False,
            "policy_digest": release["manifest"]["materials"]["evaluation_policy"],
        }
        if canonical({name: report.get(name) for name in expected}) != canonical(expected):
            raise Rejected("release_gate_not_accepted")
        inputs = report.get("input_digests")
        if (
            not isinstance(inputs, dict)
            or inputs.get("release_subject") != release["subject_sha256"]
            or inputs.get("model") != release["manifest"]["materials"]["model"]
        ):
            raise Rejected("release_gate_subject_binding")
        cases, artifacts = report.get("cases"), report.get("artifact_hashes")
        if (
            not isinstance(cases, list)
            or not 1 <= len(cases) <= 5000
            or not isinstance(artifacts, dict)
            or not 1 <= len(artifacts) <= 2048
        ):
            raise Rejected("release_gate_evidence_missing")
        seen = set()
        for case in cases:
            require_fields(case, ("id", "status", "expected", "actual"))
            identifier = case["id"]
            if (
                not isinstance(identifier, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", identifier) is None
                or identifier in seen
                or case["status"] != "pass"
                or canonical(case["expected"]) != canonical(case["actual"])
            ):
                raise Rejected("release_gate_case_not_accepted")
            seen.add(identifier)
        for reference in artifacts.values():
            object_id(reference)
        try:
            started, finished = (
                datetime.fromisoformat(report[name]) for name in ("started_at", "finished_at")
            )
            if (
                started.tzinfo is None
                or finished.tzinfo is None
                or not release["manifest"]["issued_at"]
                <= started.timestamp()
                <= finished.timestamp()
                <= assurance["issued_at"]
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError, OverflowError):
            raise Rejected("release_gate_time_binding") from None


def verify(
    *,
    package,
    policy_envelope,
    assurance_envelope,
    approval_envelope,
    reports,
    context,
    trusted_root,
    expected_policy,
    expected_serving_image,
    clock,
):
    policy = release_policy.verify_policy(
        policy_envelope,
        trusted_root=trusted_root,
        expected_policy=expected_policy,
        environment=context["policy"]["environment"],
        clock=clock,
    )
    excluded = {signing.decode64(context["trust"][role]) for role in ("curator", "evaluator")}
    if (
        signing.decode64(policy["identities"]["approver"]["public_key"]) in excluded
        or signing.decode64(trusted_root) in excluded
    ):
        raise Rejected("release_approval_authority_not_separated")
    release = release_bundle.verify(
        package,
        context=context,
        publisher_public=policy["identities"]["publisher"]["public_key"],
        expected_serving_image=expected_serving_image,
        clock=clock,
    )
    if (
        release["manifest"]["issuer"] != policy["identities"]["publisher"]["issuer"]
        or release["quality_component"] != "pass"
    ):
        raise Rejected("release_publisher_or_quality_rejected")
    assurance = bound(
        assurance_envelope, "release-assurance", "assessor", policy, release, clock, ("reports",)
    )
    verify_reports(reports, assurance, release, policy)
    version = 1
    if approval_envelope is not None:
        signed = release_policy.checked(
            approval_envelope, "release-approval", policy["identities"]["approver"]["public_key"]
        )
        version = signed.get("schema_version")
        if type(version) is not int or version not in (1, 2):
            raise Rejected("release_approval_schema")
    approval = bound(
        approval_envelope,
        "release-approval",
        "approver",
        policy,
        release,
        clock,
        ("assurance_sha256", "sequence", "action", *(("rollback",) if version == 2 else ())),
        schema_version=version,
    )
    if (
        approval["assurance_sha256"] != digest(canonical(assurance))
        or type(approval["sequence"]) is not int
        or version == 1
        and (
            approval["action"] != "promote"
            or approval["sequence"] != release["manifest"]["sequence"]
        )
    ):
        raise Rejected("release_approval_binding")
    rollback = (
        release_rollback.intent(approval, release["manifest"]["sequence"]) if version == 2 else None
    )
    if (
        approval["issued_at"] < assurance["issued_at"]
        or approval["expires_at"] > assurance["expires_at"]
    ):
        raise Rejected("release_approval_time_binding")
    return {
        "schema_version": version,
        "subject_sha256": release["subject_sha256"],
        "policy_sha256": expected_policy,
        "assurance_sha256": digest(canonical(assurance)),
        "approval_sha256": digest(canonical(approval)),
        "environment": policy["environment"],
        "sequence": approval["sequence"],
        "expires_at": approval["expires_at"],
        "authorization_valid": True,
        "state": "authorized-not-activated",
        "release_ready": False,
        **({"rollback": rollback} if rollback is not None else {}),
    }
