import copy
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import storage_bootstrap, storage_restore
from mlsecops.contracts import Rejected, canonical, write_json


def qualify():
    cases = []
    image_id = "sha256:" + "a" * 64

    def rejected(name, operation, reason):
        try:
            operation()
        except Rejected as error:
            if str(error) != reason:
                raise Rejected(f"storage_image_wrong_rejection:{name}:{error}") from None
        else:
            raise Rejected(f"storage_image_bypass:{name}")
        cases.append({"id": name, "status": "pass"})

    if storage_bootstrap.image_reference(None) != storage_bootstrap.IMAGE:
        raise Rejected("storage_image_default_changed")
    if storage_bootstrap.image_reference(image_id) != image_id:
        raise Rejected("storage_image_exact_id_rejected")
    cases.append({"id": "explicit-image-default-and-candidate", "status": "pass"})
    for name, invalid in (
        ("tag", "trusted-mlsecops:storage-candidate"),
        ("registry-digest", "postgres@" + image_id),
        ("short-digest", "sha256:abc"),
        ("upper-digest", image_id.upper()),
        ("option", "--privileged"),
        ("boolean", True),
        ("list", []),
        ("empty", ""),
    ):
        rejected(
            name,
            lambda invalid=invalid: storage_bootstrap.image_reference(invalid),
            "storage_experimental_image_invalid",
        )
        with patch.object(storage_bootstrap.storage_pki, "initialize") as initialize:
            rejected(
                name + ":before-bootstrap",
                lambda invalid=invalid: storage_bootstrap.bootstrap(
                    Path("missing"), experimental_image_id=invalid
                ),
                "storage_experimental_image_invalid",
            )
            if initialize.called:
                raise Rejected("storage_image_invalid_reached_mutation")
        with patch.object(storage_restore, "read_backup") as read_backup:
            rejected(
                name + ":before-restore",
                lambda invalid=invalid: storage_restore.restore(
                    Path.cwd(),
                    Path("missing"),
                    Path("unused"),
                    {},
                    experimental_image_id=invalid,
                ),
                "storage_experimental_image_invalid",
            )
            if read_backup.called:
                raise Rejected("storage_image_invalid_reached_restore")
    with tempfile.TemporaryDirectory(prefix="storage-image-policy-") as temporary:
        state = Path(temporary).resolve()
        with (
            patch.object(storage_bootstrap.storage_pki, "workspace_id", return_value="b" * 32),
            patch.object(
                storage_bootstrap.storage_pki, "validate", return_value={"certificates": {}}
            ),
            patch.object(storage_bootstrap, "bounded_read", return_value=b"certificate"),
        ):
            baseline, files = storage_bootstrap.specification(state, 15439)
            candidate, candidate_files = storage_bootstrap.specification(
                state, 15439, experimental_image_id=image_id
            )
            if (
                baseline["image"] != storage_bootstrap.IMAGE
                or candidate["image"] != image_id
                or baseline["config_digest"] == candidate["config_digest"]
                or candidate_files != files
            ):
                raise Rejected("storage_image_spec_binding_invalid")
            cases.append({"id": "image-bound-config-identical-tls", "status": "pass"})
            write_json(state / "storage.json", candidate)
            with patch.object(storage_bootstrap, "inspect") as inspect:
                rejected(
                    "default-cannot-adopt-candidate-marker",
                    lambda: storage_bootstrap.validate(state),
                    "storage_identity_changed",
                )
                if inspect.called:
                    raise Rejected("storage_candidate_marker_reached_default_runtime")
                other = copy.deepcopy(candidate)
                other["image"] = "sha256:" + "c" * 64
                write_json(state / "storage.json", other)
                rejected(
                    "marker-cannot-select-another-image",
                    lambda: storage_bootstrap.validate(state, experimental_image_id=image_id),
                    "storage_identity_changed",
                )
            marker = {
                **candidate,
                "container_id": "container",
                "network_id": "network",
                "volume_created_at": "created",
            }
            write_json(state / "storage.json", marker)
            labels = {
                storage_bootstrap.WORKSPACE_LABEL: candidate["workspace_id"],
                storage_bootstrap.CONFIG_LABEL: candidate["config_digest"],
            }
            ports = {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "15439"}]}
            container = {
                "Id": "container",
                "Image": image_id,
                "Config": {"Labels": labels, "Image": image_id, "User": "999:999"},
                "HostConfig": {
                    "ReadonlyRootfs": True,
                    "Privileged": False,
                    "CapAdd": [],
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges"],
                    "Memory": 512 * 1024 * 1024,
                    "MemorySwap": 512 * 1024 * 1024,
                    "NanoCpus": 1_000_000_000,
                    "PidsLimit": 64,
                    "PortBindings": ports,
                },
                "NetworkSettings": {"Networks": {candidate["network"]: {}}, "Ports": ports},
                "State": {"Running": True},
                "Mounts": [
                    {
                        "Type": "volume",
                        "Name": candidate["volume"],
                        "Destination": storage_bootstrap.MOUNT,
                    }
                ],
            }
            resources = {
                "container": container,
                "network": {
                    "Id": "network",
                    "Labels": labels,
                    "Internal": False,
                    "Driver": "bridge",
                },
                "volume": {"Labels": labels, "CreatedAt": "created"},
            }
            with patch.object(
                storage_bootstrap, "inspect", side_effect=lambda kind, name: resources[kind]
            ):
                if storage_bootstrap.validate(state, experimental_image_id=image_id) != marker:
                    raise Rejected("storage_candidate_actual_binding_failed")
                cases.append({"id": "actual-candidate-container-binding", "status": "pass"})
                container["Image"] = "sha256:" + "c" * 64
                rejected(
                    "actual-image-differs-from-config-reference",
                    lambda: storage_bootstrap.validate(state, experimental_image_id=image_id),
                    "storage_container_policy_changed",
                )
            fresh = state / "fresh"
            fresh.mkdir()
            for name, details in (
                ("foreign-id", {"Id": "other", "Os": "linux", "Architecture": "amd64"}),
                ("foreign-os", {"Id": image_id, "Os": "windows", "Architecture": "amd64"}),
                ("foreign-arch", {"Id": image_id, "Os": "linux", "Architecture": "arm64"}),
            ):
                with (
                    patch.object(storage_bootstrap.storage_pki, "initialize"),
                    patch.object(storage_bootstrap, "specification", return_value=(candidate, {})),
                    patch.object(
                        storage_bootstrap,
                        "inspect",
                        side_effect=lambda kind, name, required=True: (
                            details if kind == "image" else None
                        ),
                    ),
                    patch.object(storage_bootstrap.socket, "socket"),
                    patch.object(storage_bootstrap, "docker") as docker,
                ):
                    rejected(
                        name + ":before-resources",
                        lambda: storage_bootstrap.bootstrap(fresh, experimental_image_id=image_id),
                        "storage_experimental_image_identity_invalid",
                    )
                    if docker.called:
                        raise Rejected("storage_foreign_image_created_resources")
            for image_name, image_override in (("baseline", None), ("candidate", image_id)):
                with (
                    patch.object(storage_bootstrap.storage_pki, "initialize"),
                    patch.object(storage_bootstrap, "specification", return_value=(candidate, {})),
                    patch.object(
                        storage_bootstrap,
                        "inspect",
                        side_effect=lambda kind, name, required=True: (
                            {"Id": image_id, "Os": "linux", "Architecture": "amd64"}
                            if kind == "image"
                            else None
                        ),
                    ),
                    patch.object(
                        storage_bootstrap.shutil,
                        "disk_usage",
                        return_value=SimpleNamespace(free=16 * 1024**3),
                    ),
                    patch.object(storage_bootstrap.socket, "socket"),
                    patch.object(storage_bootstrap, "docker") as docker,
                ):

                    def stop_before_container(arguments, *args, **kwargs):
                        if arguments[0] == "create":
                            raise Rejected("contract_stop_before_container")

                    docker.side_effect = stop_before_container
                    rejected(
                        image_name + ":bootstrap-commands",
                        lambda: storage_bootstrap.bootstrap(
                            fresh, experimental_image_id=image_override
                        ),
                        "contract_stop_before_container",
                    )
                    runs = [
                        call.args[0] for call in docker.call_args_list if call.args[0][0] == "run"
                    ]
                    stages = [
                        call.kwargs.get("failure_stage")
                        for call in docker.call_args_list
                        if call.args[0][0] == "run"
                    ]
                    if stages != ["volume_prepare", "initdb"]:
                        raise Rejected("storage_bootstrap_stage_diagnostics_missing")
                    create = docker.call_args.args[0]
                    helper, initdb = runs
                    if "--user" not in helper or helper[helper.index("--user") + 1] != "0:0":
                        raise Rejected("storage_volume_preparer_not_explicit_root")
                    for arguments in (initdb, create):
                        if arguments[arguments.index("--user") + 1] != "999:999":
                            raise Rejected("storage_runtime_user_changed")
                        if "--cap-add" in arguments:
                            raise Rejected("storage_runtime_capabilities_added")
                    if (
                        helper[helper.index("--cap-add") + 1] != "CHOWN"
                        or helper[helper.index("--network") + 1] != "none"
                        or "--rm" not in helper
                        or "--read-only" not in helper
                        or helper[helper.index("--cap-drop") + 1] != "ALL"
                        or "no-new-privileges" not in helper
                    ):
                        raise Rejected("storage_volume_preparer_unconfined")
                    cases.append({"id": image_name + ":explicit-bootstrap-users", "status": "pass"})
    for stage in (None, "volume_prepare", "initdb"):
        with patch.object(
            storage_bootstrap.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                ["docker"], 1, stdout=b"private-output", stderr=b"private-secret"
            ),
        ):
            rejected(
                f"sanitized-docker-failure:{stage}",
                lambda: storage_bootstrap.docker(["run"], failure_stage=stage),
                f"storage_docker_failed:{stage or 'run'}",
            )
    return {
        "status": "pass",
        "scope": "storage-image-contracts-only",
        "checks": len(cases),
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
