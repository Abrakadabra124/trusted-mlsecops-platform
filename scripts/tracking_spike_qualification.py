import copy
import tempfile
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, read_json, write_json
from scripts import tracking_spike


def qualify():
    cases = []
    image = {
        "Id": "sha256:" + "a" * 64,
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {"User": "65532:65532", "Labels": {tracking_spike.LABEL: "materials"}},
    }

    def rejected(name, operation):
        try:
            operation()
        except Rejected:
            cases.append({"id": name, "status": "pass"})
        else:
            raise Rejected("tracking_orchestration_bypass:" + name)

    for name, mutate in (
        ("mutable-id", lambda value: value.update(Id="latest")),
        ("foreign-os", lambda value: value.update(Os="windows")),
        ("foreign-architecture", lambda value: value.update(Architecture="arm64")),
        ("root-user", lambda value: value["Config"].update(User="0")),
        ("foreign-materials", lambda value: value["Config"].update(Labels={})),
    ):
        invalid = copy.deepcopy(image)
        mutate(invalid)
        with (
            patch.object(tracking_spike, "command", return_value=canonical([invalid]).decode()),
            patch.object(tracking_spike, "materials", return_value="materials"),
        ):
            rejected(name, lambda: tracking_spike.inspect_image(Path.cwd()))
    with (
        patch.object(tracking_spike, "command", return_value=canonical([image]).decode()),
        patch.object(tracking_spike, "materials", return_value="materials"),
    ):
        if tracking_spike.inspect_image(Path.cwd()) != image["Id"]:
            raise Rejected("tracking_orchestration_valid_image_failed")
        cases.append({"id": "exact-nonroot-image", "status": "pass"})
    with tempfile.TemporaryDirectory(prefix="tracking-contract-") as directory:
        root = Path(directory)
        output = root / ".runtime/evidence/tracking-spike.json"
        write_json(output, {"status": "pass"})
        with (
            patch.object(tracking_spike, "inspect_image", side_effect=Rejected("foreign")),
            patch.object(tracking_spike, "initialize") as initialize,
        ):
            rejected(
                "foreign-before-state-clears-pass", lambda: tracking_spike.qualify(root, "worker")
            )
            if initialize.called or read_json(output)["status"] != "inconclusive":
                raise Rejected("tracking_orchestration_stale_pass")
    observed = {
        "Id": "container-id",
        "Image": image["Id"],
        "Config": {"Image": image["Id"], "Labels": {tracking_spike.RUN_LABEL: "owned"}},
    }
    for name, mutate in (
        ("cleanup-foreign-reference", lambda value: value["Config"].update(Image="foreign")),
        ("cleanup-foreign-actual-image", lambda value: value.update(Image="foreign")),
        ("cleanup-foreign-owner", lambda value: value["Config"].update(Labels={})),
    ):
        invalid = copy.deepcopy(observed)
        mutate(invalid)
        with patch.object(
            tracking_spike, "command", return_value=canonical([invalid]).decode()
        ) as command:
            rejected(name, lambda: tracking_spike.dispose("name", image["Id"], "owned"))
            if command.call_count != 1:
                raise Rejected("tracking_cleanup_crossed_ownership")
    with patch.object(
        tracking_spike, "command", side_effect=[canonical([observed]).decode(), "", ""]
    ) as command:
        tracking_spike.dispose("name", image["Id"], "owned")
        if command.call_args_list[1].args[0] != ["docker", "rm", "--force", "container-id"]:
            raise Rejected("tracking_cleanup_not_exact_id")
        cases.append({"id": "only-owned-id-removed-then-checked", "status": "pass"})
    with patch.object(
        tracking_spike, "command", side_effect=[canonical([observed]).decode(), "", "remaining"]
    ):
        rejected("cleanup-incomplete", lambda: tracking_spike.dispose("name", image["Id"], "owned"))
    return {
        "status": "pass",
        "scope": "tracking-orchestration-contracts",
        "checks": len(cases),
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
