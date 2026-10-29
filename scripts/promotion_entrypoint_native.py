"""Hosted-only CLI integration: controlled positive and actual-candidate refusal."""

import argparse
import os
import subprocess
import sys
import time
import uuid
from contextlib import suppress
from pathlib import Path

from mlsecops import promotion_controller, release_bundle, release_policy, storage
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.storage_bootstrap import validate
from scripts import release_native, release_reader_native
from scripts.candidate_lineage_native import KNOWN_OWNERS, OWNERS
from scripts.material_bundle_native import release_snapshot


def configuration(client, trust_client, arguments, trust_root):
    return {
        "schema_version": 1,
        "storage_client": str(Path(client).resolve()),
        "trust_client": str(Path(trust_client).resolve()),
        **{
            k: arguments[k]
            for k in ("context", "trusted_root", "expected_policy", "expected_serving_image")
        },
        "trust_root": trust_root,
        "minimum_trust_version": 1,
    }


def invoke(root, directory, config, request, *, denied=False):
    directory.mkdir(parents=True, exist_ok=False)
    config_path, request_path = directory / "config.json", directory / "request.json"
    write_json(config_path, config)
    write_json(request_path, request)
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "mlsecops.promotion_controller",
            "--config",
            str(config_path),
            "--request",
            str(request_path),
        ],
        cwd=root,
        capture_output=True,
        timeout=90,
        check=False,
    )
    if denied:
        if process.returncode != 1 or process.stdout or process.stderr != b"promotion_rejected\n":
            raise Rejected("promotion_cli_expected_refusal")
        return {"status": "rejected", "release_ready": False}
    if process.returncode or process.stderr:
        raise Rejected("promotion_cli_failed")
    result = decode(process.stdout, 65536)
    if (
        result.get("state") != "recorded-not-activated"
        or result.get("release_ready") is not False
        or type(result.get("sequence")) is not int
        or result["sequence"] < 1
    ):
        raise Rejected("promotion_cli_invalid_receipt")
    storage.object_id(result["request_sha256"])
    write_json(directory / "receipt.json", result)
    return result


def controlled(root, models, authority, arguments, trust_root):
    """All-pass documents here are existing controlled fixtures, never actual acceptance."""
    client = models / "storage-clients/promoter"
    policy = release_policy.checked(
        arguments["policy_envelope"], "promotion-policy", arguments["trusted_root"]
    )
    reference = release_bundle.publish(
        client,
        arguments["package"],
        context=arguments["context"],
        publisher_public=policy["identities"]["publisher"]["public_key"],
        expected_serving_image=arguments["expected_serving_image"],
        clock=int(time.time()),
    )
    request = {"schema_version": 1, "proposal_reference": reference}
    for kind in ("policy", "assurance", "approval"):
        request[kind + "_reference"] = storage.put(
            client, "releases", canonical(arguments[kind + "_envelope"])
        )
    for content in arguments["reports"].values():
        storage.put(client, "releases", content)
    config = configuration(client, authority / "storage-clients/promoter", arguments, trust_root)
    campaign = safe_child(models, "evidence/promotion-cli-" + uuid.uuid4().hex)
    first = invoke(root, campaign / "first", config, request)
    repeated = invoke(root, campaign / "repeat", config, request)
    if first != repeated or first["proposal_reference"] != reference:
        raise Rejected("promotion_cli_repeat_mismatch")
    return first


def hosted():
    if (
        sys.platform != "linux"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise Rejected("promotion_hosted_runner_required")


def qualify(root, state, image):
    hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    marker = validate(state)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint = source_fingerprint(root)
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("promotion_native_dirty_source")
    started = now()
    proposal = release_native.qualify(root, state, image)
    campaign = safe_child(state, "release-proposals/" + proposal["campaign_id"])
    policy_envelope = read_json(campaign / "policy-envelope.json")
    demo, public = (read_json(state / name) for name in ("storage-demo.json", "trusted-keys.json"))
    context = {
        "candidate_reference": demo["candidate"]["candidate_reference"],
        "evaluation_reference": demo["evaluation_reference"],
        "policy": read_json(root / "policies/local-cpu.json"),
        "trust": read_json(state / "storage-trust.json"),
        "expected": proposal["source"],
        "owners": OWNERS,
        "known_owners": KNOWN_OWNERS,
    }
    client = safe_child(state, "storage-clients/promoter")
    # No trust request is reachable for missing assurance; both clients are still role checked.
    arguments = {
        "context": context,
        "trusted_root": public["trust"],
        "expected_policy": proposal["policy_sha256"],
        "expected_serving_image": proposal["source"]["image_id"],
    }
    config = configuration(client, client, arguments, public["trust"])
    request = {
        "schema_version": 1,
        "proposal_reference": proposal["proposal_reference"],
        "policy_reference": storage.put(client, "releases", canonical(policy_envelope)),
        "assurance_reference": None,
        "approval_reference": None,
    }
    before = release_snapshot(state / "storage-clients/serving")
    try:
        promotion_controller.submit(config, request)
    except Rejected as error:
        if str(error) != "release_assurance_required":
            raise Rejected("promotion_actual_denial_reason") from None
    else:
        raise Rejected("promotion_actual_denial_bypass")
    invoke(root, campaign / "promotion-cli-refusal", config, request, denied=True)
    if release_snapshot(state / "storage-clients/serving") != before:
        raise Rejected("promotion_refusal_wrote_objects")
    reader = release_reader_native.qualify(root, state, image, promotion_entrypoint=True)
    if (
        reader["status"] != "pass"
        or reader["release_ready"] is not False
        or "controlled-promotion-CLI-exact-retry" not in reader["cases"]
    ):
        raise Rejected("promotion_controlled_reader_incomplete")
    if (
        validate(state)["container_id"] != marker["container_id"]
        or source_fingerprint(root) != fingerprint
        or command(["git", "-C", str(root), "rev-parse", "HEAD"]) != revision
        or command(["git", "-C", str(root), "status", "--porcelain"])
    ):
        raise Rejected("promotion_native_source_changed")
    return {
        "schema_version": 1,
        "scope": "promotion-CLI-controlled-positive-actual-candidate-refusal-not-full-M10",
        "status": "pass",
        "full_M10": "inconclusive",
        "release_ready": False,
        "started_at": started,
        "finished_at": now(),
        "source_revision": revision,
        "source_fingerprint": fingerprint,
        "source_dirty": False,
        "actual_candidate": context["candidate_reference"],
        "actual_proposal": proposal["proposal_reference"],
        "actual_model": proposal["model_sha256"],
        "request_digest": digest(canonical(request)),
        "actual_outcome": "release_assurance_required",
        "cases": [
            "actual-candidate-parent-denial",
            "actual-candidate-CLI-denial",
            "refusal-no-write",
        ]
        + reader["cases"],
        "reader": reader,
        "limitations": [
            "Controlled positive reports are not actual candidate acceptance",
            "Credential-scoped host CLI; OS/Kubernetes promoter isolation remains separate",
            "No actual production promotion or full M10/M12/M18 acceptance",
        ],
    }


def main(arguments=None):
    parser = argparse.ArgumentParser(
        description="Hosted disposable promotion entrypoint qualification"
    )
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    options = parser.parse_args(arguments)
    output = None
    try:
        hosted()
        validate(options.state)
        output = safe_child(options.state, "evidence/promotion-entrypoint.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        report = qualify(Path(__file__).resolve().parents[1], options.state, options.image)
        write_json(output, report)
        print(canonical({**report, "cases": len(report["cases"])}).decode())
        return 0
    except (Exception, KeyboardInterrupt) as error:
        if output is not None:
            with suppress(Rejected, OSError):
                write_json(
                    output,
                    {
                        "status": "inconclusive"
                        if isinstance(error, KeyboardInterrupt)
                        else "fail",
                        "release_ready": False,
                    },
                )
        print("promotion_entrypoint_native_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
