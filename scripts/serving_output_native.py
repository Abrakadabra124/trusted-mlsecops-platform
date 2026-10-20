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


def run(root, state, image, port):
    from mlsecops import worker_transport
    from mlsecops.contracts import Rejected
    from scripts.serving_output_probe import observe

    expected = source(root, image)
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
