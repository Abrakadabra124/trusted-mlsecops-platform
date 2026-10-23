import os
import re
import sys
import uuid
from pathlib import Path

DIAGNOSTIC_MODULES = (
    "scripts.serving_output_native",
    "scripts.serving_output_probe",
    "scripts.candidate_serving_native",
    "scripts.serving_native",
    "scripts.serving_pause_native",
    "scripts.serving_outage_native",
    "scripts.serving_privacy_probe",
    "scripts.audit_correlation_probe",
    "scripts.audit_evidence_probe",
    "scripts.candidate_serving_reader",
    "mlsecops.storage_bootstrap",
    "mlsecops.storage",
    "mlsecops.serving",
    "mlsecops.serving_worker",
    "mlsecops.serving_runtime",
    "mlsecops.trust",
    "mlsecops.release_bundle",
    "mlsecops.release_policy",
    "mlsecops.contracts",
)


def failure_locations(error):
    root = Path(__file__).resolve().parents[1]
    allowed = {root / (module.replace(".", "/") + ".py"): module for module in DIAGNOSTIC_MODULES}
    locations = []
    trace = error.__traceback__
    while trace is not None:
        module = allowed.get(Path(trace.tb_frame.f_code.co_filename).resolve())
        if module is not None:
            locations.append({"module": module, "line": trace.tb_lineno})
        trace = trace.tb_next
    return locations[-16:]


def source(root, image):
    from mlsecops.contracts import Rejected
    from mlsecops.inventory import command, source_fingerprint
    from mlsecops.sandbox import resolve_image

    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("serving_output_source_dirty")
    return {
        "image_id": resolve_image(image),
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "source_fingerprint": source_fingerprint(root),
    }


def qualified(root, state, image, port, observer, campaign=None):
    from scripts.candidate_serving_native import qualify

    options = {} if campaign is None else {"campaign_id": campaign}
    return qualify(
        root,
        state,
        image,
        trust_port=port,
        privacy_observer=observer,
        publish_report=False,
        **options,
    )


def verified_materials(root, state, expected):
    import math
    import time

    from mlsecops import release_bundle
    from mlsecops.contracts import read_json, safe_child
    from scripts.candidate_serving_reader import bind_proposal

    report, source_trust, public = (
        read_json(safe_child(state, name))
        for name in ("evidence/release-native.json", "storage-trust.json", "trusted-keys.json")
    )
    package = release_bundle.load(
        safe_child(state, "storage-clients/serving"),
        report["proposal_reference"],
        publisher_public=public["approver"],
    )
    context, verified = bind_proposal(
        report,
        package,
        policy=read_json(root / "policies/local-cpu.json"),
        source_trust=source_trust,
        publisher_public=public["approver"],
        expected=expected,
        clock=math.ceil(time.time()),
    )
    return context, verified, package, public["approver"]


def verified_subject(root, state, expected):
    from mlsecops.contracts import canonical, digest

    context, verified, package, _ = verified_materials(root, state, expected)
    return {
        "proposal_reference": digest(canonical(package["envelope"])),
        "subject_sha256": verified["subject_sha256"],
        "model_sha256": digest(verified["model"]),
        "candidate_reference": context["candidate_reference"],
        "evaluation_reference": context["evaluation_reference"],
    }


def verify_packet(root, state, expected, campaign, result):
    import math
    import time

    from mlsecops import audit_evidence, audit_snapshot, release_policy, signing
    from mlsecops.contracts import (
        Rejected,
        canonical,
        digest,
        read_json,
        require_fields,
        safe_child,
    )
    from scripts import audit_correlation_probe
    from scripts.candidate_serving_reader import KIND

    if (
        type(campaign) is not str
        or re.fullmatch("[a-f0-9]{32}", campaign) is None
        or result["campaign_id"] != campaign
    ):
        raise Rejected("serving_output_campaign")
    context, verified, package, publisher = verified_materials(root, state, expected)
    destination = safe_child(state, f"serving-qualifications/{campaign}")
    public = read_json(safe_child(destination, "public.json"))
    require_fields(public, ("qualification",))
    public = public["qualification"]
    if signing.decode64(public) in {
        signing.decode64(value)
        for value in (publisher, context["trust"]["curator"], context["trust"]["evaluator"])
    }:
        raise Rejected("serving_output_qualification_key")
    envelope = read_json(safe_child(destination, "permit.json"))
    permit = release_policy.checked(envelope, KIND, public)
    fixed = {
        "schema_version": 1,
        "purpose": KIND,
        "campaign_id": campaign,
        "environment": context["policy"]["environment"],
        "proposal_sha256": digest(canonical(package["envelope"])),
        "subject_sha256": verified["subject_sha256"],
        "model_sha256": digest(verified["model"]),
        **expected,
    }
    require_fields(permit, (*fixed, "issued_at", "expires_at"))
    if (
        canonical({key: permit[key] for key in fixed}) != canonical(fixed)
        or digest(canonical(permit)) != result["qualification_permit_sha256"]
        or result["proposal_reference"] != fixed["proposal_sha256"]
        or result["subject_sha256"] != fixed["subject_sha256"]
        or result["model_sha256"] != fixed["model_sha256"]
        or any(
            result[field] != context[field]
            for field in ("candidate_reference", "evaluation_reference")
        )
    ):
        raise Rejected("serving_output_permit_binding")
    release_policy.window(permit, math.ceil(time.time()), maximum=600)
    bound = audit_correlation_probe.candidate(package, context, envelope, public, publisher)
    summary = audit_evidence.verify(
        audit_snapshot.load_packet(safe_child(destination, "audit-evidence")),
        binding={"campaign_id": campaign, "source": expected},
        expected_context=bound,
    )
    if any(
        canonical(result["runtime"][key]) != canonical(value)
        for key, value in (
            ("audit_evidence", summary),
            ("http_correlation", summary["correlation"]),
            ("public_audit_window", summary["public"]),
        )
    ):
        raise Rejected("serving_output_packet_binding")
    return summary


def failure_diagnostic(state, campaign):
    import math

    from mlsecops.contracts import Rejected, bounded_read, decode, safe_child

    result = {
        "scope": "serving-failure-diagnostic-not-acceptance",
        "status": "fail",
        "release_ready": False,
        "locations": [],
    }
    try:
        if re.fullmatch("[a-f0-9]{32}", campaign) is None:
            raise Rejected("diagnostic_campaign")
        path = safe_child(state, f"serving-qualifications/{campaign}/failure-location.json")
        locations = decode(bounded_read(path, 16384))
        if type(locations) is list and len(locations) <= 16:
            for location in locations:
                if (
                    type(location) is dict
                    and set(location) == {"module", "line"}
                    and location["module"] in DIAGNOSTIC_MODULES
                    and type(location["line"]) is int
                    and 1 <= location["line"] <= 100000
                ):
                    result["locations"].append(location)
    except (Rejected, OSError, ValueError, TypeError):
        pass
    reasons = {
        "trust_refreshed_or_lease_changed_during_outage",
        "http_response_invalid",
        "ml_response_after_deadline_or_denial",
        "unexpected_http_status",
        "missing_outage_phase",
        "first_http_503_exceeds_60_seconds",
    }
    for name, filename in (
        ("outage", "http-outage.json"),
        ("paused", "http-paused-query.json"),
        ("expiry", "http-expiring-query.json"),
    ):
        try:
            if re.fullmatch("[a-f0-9]{32}", campaign) is None:
                raise Rejected("diagnostic_campaign")
            path = safe_child(state, f"serving-qualifications/{campaign}/{filename}")
            trace = decode(bounded_read(path, 262144))
            if not isinstance(trace, dict):
                raise Rejected("diagnostic_schema")
        except (Rejected, OSError, ValueError, TypeError):
            trace = {}
        status = trace.get("status")
        result[name] = {
            "status": status if status in ("pass", "fail", "inconclusive") else "unavailable"
        }
        assessment = trace.get("assessment", {})
        if isinstance(assessment, dict):
            failures = assessment.get("failures", [])
            result[name]["failures"] = sorted(
                reason for reason in reasons if isinstance(failures, list) and reason in failures
            )
            delay = assessment.get("first_503_seconds")
            result[name]["first_503_seconds"] = (
                delay
                if type(delay) in (int, float) and math.isfinite(delay) and 0 <= delay <= 600
                else None
            )
        denial = trace.get("denial", {})
        if isinstance(denial, dict):
            code = denial.get("http_status")
            result[name]["http_status"] = code if type(code) is int and code in (200, 503) else None
            for field in (
                "connected_read_entered",
                "libpq_query_active_at_denial",
                "read_finished_at_denial",
                "response_valid",
                "generation_fenced",
            ):
                value = denial.get(field)
                result[name][field] = value if type(value) is bool else None
    return result


def run(root, state, image, port):
    from mlsecops import worker_transport
    from mlsecops.contracts import Rejected, canonical, now
    from mlsecops.privacy_evidence import checked_candidate
    from scripts.serving_output_probe import observe

    expected = source(root, image)
    subject = verified_subject(root, state, expected)
    campaign = uuid.uuid4().hex
    started = now()
    try:
        envelope = worker_transport.capture(
            [
                sys.executable,
                "-m",
                "scripts.serving_output_native",
                "--child",
                "--campaign",
                campaign,
                "--state",
                str(state),
                "--image",
                expected["image_id"],
                "--trust-port",
                str(port),
                "--confirm-disposable",
            ],
            timeout=570,
            canonical_output=True,
        )
    except Rejected:
        print(canonical(failure_diagnostic(state, campaign)).decode(), flush=True)
        raise
    result = observe(envelope, expected)
    if result["campaign_id"] != campaign:
        raise Rejected("serving_output_campaign")
    checked_candidate(
        canonical(result),
        expected_source=expected,
        expected_subject=subject,
        started_at=started,
        observed_at=now(),
    )
    owned_cases = ("current-private-receipt-admitted", "closed-audit-primary-packet-reverified")
    if any(name in result["cases"] for name in owned_cases):
        raise Rejected("serving_output_parent_case_reserved")
    verify_packet(root, state, expected, campaign, result)
    if source(root, image) != expected:
        raise Rejected("serving_output_source_changed")
    result["cases"].extend(owned_cases)
    return result


def main(arguments=None):
    failure_path = None
    try:
        from mlsecops.process_privacy import enforce

        enforce()
        from argparse import SUPPRESS

        from mlsecops import storage_bootstrap, storage_pki
        from mlsecops.contracts import Rejected, canonical, safe_child, write_json
        from mlsecops.private_cli import Arguments

        parser = Arguments(
            prog="serving-output", description="Owned serving lifecycle output observation"
        )
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--confirm-disposable", action="store_true", required=True)
        parser.add_argument("--image", default="trusted-mlsecops:dev")
        parser.add_argument("--trust-port", type=int, default=15446)
        parser.add_argument("--child", action="store_true", help=SUPPRESS)
        parser.add_argument("--campaign", help=SUPPRESS)
        options = parser.parse_args(arguments)
        if (
            os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        ):
            raise Rejected("serving_output_disposable_hosted_runner_required")
        if (
            options.child
            and (options.campaign is None or re.fullmatch("[a-f0-9]{32}", options.campaign) is None)
            or not options.child
            and options.campaign is not None
        ):
            raise Rejected("serving_output_campaign")
        storage_pki.workspace_id(options.state)
        output = None
        if not options.child:
            output = safe_child(options.state, "evidence/candidate-serving.json")
            write_json(
                output,
                {
                    "status": "inconclusive",
                    "release_ready": False,
                    "native_cleanup": "unconfirmed-on-forced-stop",
                },
            )
        storage_bootstrap.validate(options.state)
        root = Path(__file__).resolve().parents[1]
        if options.child:
            from scripts.serving_output_probe import produce

            failure_path = safe_child(
                options.state, f"serving-qualifications/{options.campaign}/failure-location.json"
            )
            result = produce(
                lambda observer: qualified(
                    root,
                    options.state,
                    options.image,
                    options.trust_port,
                    observer,
                    options.campaign,
                )
            )
        else:
            result = run(root, options.state, options.image, options.trust_port)
            write_json(output, result)
        sys.stdout.write(canonical(result).decode() + "\n")
        sys.stdout.flush()
        return 0
    except KeyboardInterrupt:
        print("serving_output_cancelled", file=sys.stderr)
        return 130
    except Exception as error:
        if failure_path is not None:
            try:
                write_json(failure_path, failure_locations(error))
            except (OSError, ValueError, TypeError, Rejected):
                pass
        print("serving_output_rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
