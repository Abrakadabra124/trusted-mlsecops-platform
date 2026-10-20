import os
import re
import sys
import uuid
from pathlib import Path


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


def run(root, state, image, port):
    from mlsecops import worker_transport
    from mlsecops.contracts import Rejected, canonical, now
    from mlsecops.privacy_evidence import checked_candidate
    from scripts.serving_output_probe import observe

    expected = source(root, image)
    subject = verified_subject(root, state, expected)
    campaign = uuid.uuid4().hex
    started = now()
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
    except Exception:
        print("serving_output_rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
