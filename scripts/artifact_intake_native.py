import argparse
import subprocess
from pathlib import Path
from unittest.mock import patch

from mlsecops import artifact_intake, sandbox
from mlsecops.contracts import Rejected, canonical, digest, now, write_json
from mlsecops.datasets import generate
from mlsecops.inventory import source_fingerprint
from mlsecops.signing import decode64


def qualify(image, content=None):
    identifier = sandbox.resolve_image(image)
    if content is None:
        trained, _ = sandbox.run_worker(
            identifier,
            {"action": "train", "train": generate(rows=1000), "seed": 17, "features": [[0.5] * 6]},
        )
        content = decode64(trained["model"])
    cases = []

    def inspect(payload, executor=sandbox.run_worker):
        return artifact_intake.inspect_candidate(
            payload, digest(payload), identifier, identifier, executor
        )

    cases.append({"id": "clean-isolated-intake", "status": "pass", "report": inspect(content)})
    try:
        inspect(b"\x80\x04N.")
    except artifact_intake.IntakeFailure as error:
        if error.report["status"] != "fail" or error.report["origin"] != "worker":
            raise Rejected("intake_native_unsafe_result") from None
        cases.append({"id": "renamed-pickle-rejected", "status": "pass", "report": error.report})
    else:
        raise Rejected("intake_native_unsafe_accepted")

    original = subprocess.Popen
    for name, program, reason in (
        ("deadline", "import time; time.sleep(30)", "scanner_timeout"),
        ("crash", "raise SystemExit(19)", "scanner_crash"),
    ):
        names = []

        def fault(arguments, *args, **kwargs):
            if arguments[:2] == ["docker", "run"]:
                owned = arguments[arguments.index("--name") + 1]
                if not owned.startswith("trusted-ml-worker-") or arguments[-4] != identifier:
                    raise Rejected("intake_native_fault_scope")
                names.append(owned)
                arguments = [*arguments[:-3], "python", "-c", program]
            return original(arguments, *args, **kwargs)

        def executor(reference, request):
            with patch.object(sandbox.subprocess, "Popen", side_effect=fault):
                return sandbox.run_worker(reference, request, timeout=3)

        try:
            inspect(content, executor)
        except artifact_intake.IntakeFailure as error:
            report = error.report
            if (
                report["status"] != "inconclusive"
                or report["reason"] != reason
                or report["approved_outputs"]
                or len(names) != 1
            ):
                raise Rejected("intake_native_fault_result") from None
            remaining = subprocess.run(
                ["docker", "ps", "-aq", "--filter", "name=^/" + names[0] + "$"],
                capture_output=True,
                timeout=30,
                check=True,
            )
            if remaining.stdout.strip():
                raise Rejected("intake_native_fault_cleanup")
            cases.append(
                {"id": name, "status": "pass", "report": report, "owned_container_removed": True}
            )
        else:
            raise Rejected("intake_native_fault_accepted")
    cases.append({"id": "clean-after-faults", "status": "pass", "report": inspect(content)})
    return {
        "schema_version": 1,
        "status": "pass",
        "observed_at": now(),
        "scope": "native-docker-intake-component-not-full-M21",
        "source_fingerprint": source_fingerprint(Path(__file__).resolve().parents[1]),
        "image_id": identifier,
        "cases": cases,
        "release_ready": False,
        "limitations": [
            "Crash/deadline are explicit replacement-process injections in owned network-none containers",
            "No claim of scanner exploit detection or native Kubernetes fault injection",
            "Full M21 acceptance and release integration remain separate",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Native isolated intake and failure qualification")
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    parser.add_argument(
        "--output", type=Path, default=Path(".runtime/evidence/artifact-intake-native.json")
    )
    arguments = parser.parse_args()
    result = qualify(arguments.image)
    write_json(arguments.output, result)
    print(canonical(result).decode())


if __name__ == "__main__":
    main()
