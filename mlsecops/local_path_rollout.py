"""Reconcile the default provisioner of the already owned kind cluster."""

import re
from copy import deepcopy
from pathlib import Path

from mlsecops import local_path_pin as pin
from mlsecops.cluster import NODE, validate_cluster
from mlsecops.contracts import Rejected, decode
from mlsecops.inventory import command
from scripts.image_audit_contract import LOCAL_PATH_CONFIG
from scripts.local_path_pvc import controller, deployment, patch_spec, ready

STOCK = "kindest/local-path-provisioner:v20260820-69b56db7"


def verify_published(state, uid, spec):
    target = pin.PUBLISHED_REFERENCE
    if controller(spec)["image"] != target:
        raise Rejected("local_path_published_spec_mismatch")
    result = ready(state, uid, spec, pin.PUBLISHED_CONFIG)
    details = decode(command(["docker", "exec", NODE, "crictl", "inspecti", target]).encode())[
        "status"
    ]
    if (
        details["id"] != pin.PUBLISHED_CONFIG
        or not isinstance(details.get("repoDigests"), list)
        or target not in details["repoDigests"]
    ):
        raise Rejected("local_path_published_cri_mismatch")
    return {**result, "registry_reference": target}


def ensure(state):
    validate_cluster(state)
    target = pin.PUBLISHED_REFERENCE
    if not isinstance(target, str) or not re.fullmatch(
        re.escape(pin.REPOSITORY) + r"@sha256:[a-f0-9]{64}", target
    ):
        raise Rejected("local_path_publication_pin_missing")
    original = deployment(state)
    if not original:
        raise Rejected("local_path_controller_missing")
    uid, old = original["metadata"]["uid"], original["spec"]
    container = controller(old)
    if container["image"] == target:
        return {**verify_published(state, uid, old), "changed": False}
    if container["image"] not in (STOCK, "docker.io/" + STOCK):
        raise Rejected("local_path_bootstrap_baseline_unrecognized")
    ready(state, uid, old, LOCAL_PATH_CONFIG)
    new = deepcopy(old)
    controller(new).update(image=target, imagePullPolicy="IfNotPresent")
    try:
        patch_spec(state, uid, old, new)
        return {**verify_published(state, uid, new), "changed": True}
    except (Exception, KeyboardInterrupt):
        # A timeout can arrive after the API accepted the patch. Read the live object first.
        current = deployment(state)
        if not current or current["metadata"]["uid"] != uid or current["spec"] not in (old, new):
            raise Rejected("local_path_restore_ownership_changed")
        if current["spec"] == new:
            patch_spec(state, uid, new, old)
        ready(state, uid, old, LOCAL_PATH_CONFIG)
        raise


if __name__ == "__main__":
    from mlsecops.contracts import canonical

    print(canonical(ensure(Path(".runtime"))).decode())
