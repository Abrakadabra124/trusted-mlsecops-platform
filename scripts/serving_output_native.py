import os
import sys
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


def qualified(root, state, image, port, observer):
    from scripts.candidate_serving_native import qualify

    return qualify(
        root, state, image, trust_port=port, privacy_observer=observer, publish_report=False
    )


def verified_subject(root, state, expected):
    import math
    import time

    from mlsecops import release_bundle
    from mlsecops.contracts import canonical, digest, read_json, safe_child
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
    return {
        "proposal_reference": digest(canonical(package["envelope"])),
        "subject_sha256": verified["subject_sha256"],
        "model_sha256": digest(verified["model"]),
        "candidate_reference": context["candidate_reference"],
        "evaluation_reference": context["evaluation_reference"],
    }


def run(root, state, image, port):
    from mlsecops import worker_transport
    from mlsecops.contracts import Rejected, canonical, now
    from mlsecops.privacy_evidence import checked_candidate
    from scripts.serving_output_probe import observe

    expected = source(root, image)
    subject = verified_subject(root, state, expected)
    started = now()
    envelope = worker_transport.capture(
        [
            sys.executable,
            "-m",
            "scripts.serving_output_native",
            "--child",
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
    if source(root, image) != expected:
        raise Rejected("serving_output_source_changed")
    checked_candidate(
        canonical(result),
        expected_source=expected,
        expected_subject=subject,
        started_at=started,
        observed_at=now(),
    )
    if "current-private-receipt-admitted" in result["cases"]:
        raise Rejected("serving_output_parent_case_reserved")
    result["cases"].append("current-private-receipt-admitted")
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
        options = parser.parse_args(arguments)
        if (
            os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        ):
            raise Rejected("serving_output_disposable_hosted_runner_required")
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
                    root, options.state, options.image, options.trust_port, observer
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
