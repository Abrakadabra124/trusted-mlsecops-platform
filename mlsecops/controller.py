import argparse
import os
import sys
from pathlib import Path

from mlsecops import storage, storage_pipeline
from mlsecops.contracts import Rejected, canonical, read_json, require_fields
from mlsecops.controller_api import TARGETS
from mlsecops.controller_worker import run, validate_profile
from mlsecops.inventory import source_fingerprint


def process_state(role):
    import resource

    observation = {
        "uid": os.geteuid(),
        "sql_role": role,
        "api_token_present": Path("/api/token").is_file(),
        "signer_present": Path("/signer/key.pem").is_file(),
        "host_socket_present": Path("/var/run/docker.sock").exists(),
        "model_parser_loaded": any(name in sys.modules for name in ("onnx", "onnxruntime")),
        "peak_memory_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    if (
        observation["uid"] != 65532
        or not observation["api_token_present"]
        or observation["signer_present"] != (role == "scorer")
        or observation["host_socket_present"]
        or observation["model_parser_loaded"]
    ):
        raise Rejected("controller_process_boundary_mismatch")
    return observation


def execute(request):
    require_fields(
        request,
        ("schema_version", "role", "profile", "trust", "dataset_reference", "candidate_reference"),
    )
    if (
        type(request["schema_version"]) is not int
        or request["schema_version"] != 1
        or request["role"] not in TARGETS
    ):
        raise Rejected("controller_request_invalid")
    require_fields(request["trust"], ("curator", "evaluator", "source_approval_digest"))
    profile = request["profile"]
    validate_profile(profile)
    root = Path(__file__).resolve().parents[1]
    if source_fingerprint(root) != profile["source_fingerprint"]:
        raise Rejected("controller_source_fingerprint_mismatch")
    role = request["role"]
    process_state(role)
    client = Path("/client")
    if read_json(client / "connection.json")["role"] != role:
        raise Rejected("controller_sql_identity_mismatch")
    policy = read_json(root / "policies/local-cpu.json")

    def worker(image, payload):
        if image != profile["image_id"]:
            raise Rejected("controller_worker_profile_mismatch")
        return run(profile, role, payload)

    if role == "publisher":
        storage.object_id(request["dataset_reference"])
        if request["candidate_reference"] is not None:
            raise Rejected("controller_request_invalid")
        result = storage_pipeline.train(
            client,
            request["dataset_reference"],
            policy,
            profile["image_id"],
            request["trust"],
            worker,
            {name: profile[name] for name in ("source_fingerprint", "source_revision")},
        )
    else:
        storage.object_id(request["candidate_reference"])
        if request["dataset_reference"] is not None:
            raise Rejected("controller_request_invalid")
        result = storage_pipeline.evaluate(
            client,
            request["candidate_reference"],
            policy,
            profile["image_id"],
            request["trust"],
            Path("/signer/key.pem"),
            worker,
        )
    return {
        "role": role,
        "status": "controller-preview-unapproved",
        "result": result,
        "release_ready": False,
        "process": process_state(role),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Role-scoped ML controller, never a model execution process"
    )
    parser.add_argument("--request", type=Path, required=True)
    arguments = parser.parse_args()
    print(canonical(execute(read_json(arguments.request))).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
