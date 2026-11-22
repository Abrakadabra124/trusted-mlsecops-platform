"""Exercise etcd replacement and rollback only on the job's disposable kind node."""

import json
import os
import re
import sys
import time
from pathlib import Path
from subprocess import TimeoutExpired

from mlsecops import cluster
from mlsecops.contracts import Rejected, decode, digest
from mlsecops.inventory import command
from mlsecops.kube_worker import image_config, image_manifest
from mlsecops.storage_bootstrap import docker
from scripts.ci_campaign_producer import run_owner
from scripts.ci_consumer_recovery import Recovery
from scripts.kube_trust_native import hosted

STATE = Path(".runtime")
MANIFEST = "/etc/kubernetes/manifests/etcd.yaml"
ENDPOINT = "https://127.0.0.1:2379"
PKI = "/etc/kubernetes/pki/etcd"


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def scanned_config(target):
    report = json.loads(Path(f"../scans/{target}.grype.json").read_bytes())
    config = report["source"]["target"]["imageID"]
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", config), "invalid_scanned_config")
    return config


def node_json(*args):
    return decode(docker(["exec", cluster.NODE, "crictl", *args], timeout=10).stdout)


def loaded_candidate_manifest(tag, config):
    listing = docker(
        ["exec", cluster.NODE, "ctr", "-n", "k8s.io", "images", "ls", f'name=="{tag}"']
    ).stdout.decode()
    targets = []
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] == tag:
            targets.append(fields[2])
    require(len(targets) == 1, "candidate_image_target_missing_or_ambiguous")
    manifest, document = image_manifest(targets[0])
    require(document.get("config", {}).get("digest") == config, "kind_loaded_config_mismatch")
    require(image_config(config) == config, "invalid_loaded_candidate_config")
    return manifest


def verify_candidate_ref(live, tag, manifest, config):
    ref = live["imageRef"]
    image_id = live.get("imageId")
    if image_id:
        require(image_id == config, "etcd_running_config_mismatch")
    if ref == tag:
        # A mutable CRI display name needs the image ID recorded for this running container.
        require(image_id == config, "candidate_tag_without_matching_container_image_id")
        return
    match = re.fullmatch(r"(?:[a-zA-Z0-9./:_-]+@)?(sha256:[0-9a-f]{64})", ref)
    if re.fullmatch(r"[0-9a-f]{64}", ref):
        identifier = "sha256:" + ref
    else:
        require(match, "invalid_candidate_runtime_ref")
        identifier = match[1]
    # Some CRI refs identify the config directly. Its bytes were verified before the swap.
    if identifier != config:
        running_manifest, document = image_manifest(identifier)
        require(
            running_manifest == manifest and document.get("config", {}).get("digest") == config,
            "etcd_running_manifest_mismatch",
        )


def endpoint_status(image, config, candidate_manifest):
    pod = decode(
        cluster.kubectl(
            STATE,
            ["get", "pod", f"etcd-{cluster.NODE}", "-n", "kube-system", "-o", "json"],
            timeout=10,
        ).stdout
    )
    [spec] = pod["spec"]["containers"]
    [status] = pod.get("status", {}).get("containerStatuses", [])
    require(
        pod["spec"]["nodeName"] == cluster.NODE
        and spec["name"] == status["name"] == "etcd"
        and spec["image"] == image
        and (candidate_manifest is None or spec["imagePullPolicy"] == "Never")
        and status.get("ready")
        and "running" in status["state"],
        "etcd_pod_not_ready",
    )
    cid = status["containerID"].removeprefix("containerd://")
    live = node_json("inspect", cid)["status"]
    require(
        live["id"] == cid and live["state"] == "CONTAINER_RUNNING", "etcd_container_not_running"
    )
    if candidate_manifest is None:
        observed = node_json("inspecti", live["imageRef"])["status"]["id"]
        require(observed == config, "etcd_running_config_mismatch")
    else:
        verify_candidate_ref(live, image, candidate_manifest, config)
    [row] = node_json(
        "exec",
        cid,
        "etcdctl",
        f"--endpoints={ENDPOINT}",
        f"--cacert={PKI}/ca.crt",
        f"--cert={PKI}/healthcheck-client.crt",
        f"--key={PKI}/healthcheck-client.key",
        "--command-timeout=4s",
        "endpoint",
        "status",
        "-w",
        "json",
    )
    status = row["Status"]
    leader, member = status["leader"], status["header"]["member_id"]
    require(
        row["Endpoint"] == ENDPOINT
        and status["version"] == "3.6.17"
        and not status.get("errors")
        and type(leader) is int
        and type(member) is int
        and 0 < leader == member < 2**64,
        "etcd_endpoint_status_mismatch",
    )
    return cid, (status["header"]["cluster_id"], member), live["imageRef"]


def wait_etcd(phase, image, config, candidate_manifest=None):
    deadline = time.monotonic() + 150
    while True:
        try:
            cid, identity, ref = endpoint_status(image, config, candidate_manifest)
            evidence = (
                f" imageRef={ref} manifest={candidate_manifest}" if candidate_manifest else ""
            )
            print(
                f"{phase}: version=3.6.17 config={config} container={cid} leader={identity[1]}{evidence}",
                flush=True,
            )
            return identity
        except (Rejected, KeyError, ValueError, TimeoutExpired) as error:
            if time.monotonic() >= deadline:
                raise Rejected(f"{phase}_etcd_not_ready") from error
            time.sleep(3)


def configmap(phase, uid=None):
    name = f"etcd-adoption-{phase}"
    args = (
        ["get", "configmap", name]
        if uid
        else ["create", "configmap", name, f"--from-literal=written={phase}"]
    )
    obj = decode(cluster.kubectl(STATE, [*args, "-n", "default", "-o", "json"]).stdout)
    observed = obj["metadata"]["uid"]
    require(
        observed and (uid is None or observed == uid) and obj["data"] == {"written": phase},
        "configmap_identity_or_content_changed",
    )
    print(f"{args[0]} ConfigMap {name} uid={observed}", flush=True)
    return observed


def install_manifest(content):
    # Kubelet ignores dotfiles. Rename within the watched directory so it always sees a complete Pod.
    docker(
        [
            "exec",
            "-i",
            cluster.NODE,
            "sh",
            "-ec",
            'umask 077; cat > "$1/.etcd-adoption.tmp"; mv -f "$1/.etcd-adoption.tmp" "$1/etcd.yaml"',
            "install",
            "/etc/kubernetes/manifests",
        ],
        content=content,
    )


def exercise():
    baseline = os.environ["BASELINE"].replace("@", ":3.6.17-0@")
    official, candidate = scanned_config("baseline"), scanned_config("candidate")
    require(official != candidate, "candidate_equals_baseline")
    identity = wait_etcd("baseline", baseline, official)
    before = configmap("baseline")
    configmap("baseline", before)
    tag = "localhost/etcd-candidate:" + candidate.removeprefix("sha256:")
    command(["docker", "tag", candidate, tag])
    command(
        ["kind", "load", "docker-image", "--name", cluster.NAME, "--nodes", cluster.NODE, tag],
        timeout=180,
    )
    manifest = loaded_candidate_manifest(tag, candidate)

    original = docker(["exec", cluster.NODE, "cat", MANIFEST]).stdout
    backup = STATE / "etcd-adoption-original.yaml"
    backup.write_bytes(original)
    patch = [
        {"op": "test", "path": "/spec/containers/0/name", "value": "etcd"},
        {"op": "test", "path": "/spec/containers/0/image", "value": baseline},
        {"op": "replace", "path": "/spec/containers/0/image", "value": tag},
        {"op": "add", "path": "/spec/containers/0/imagePullPolicy", "value": "Never"},
    ]
    patched = cluster.kubectl(
        STATE,
        [
            "patch",
            "--local",
            "-f",
            str(backup),
            "--type=json",
            "-p",
            json.dumps(patch),
            "-o",
            "yaml",
        ],
    ).stdout
    after = None
    try:
        install_manifest(patched)
        require(
            wait_etcd("candidate", tag, candidate, manifest) == identity, "candidate_member_changed"
        )
        configmap("baseline", before)
        after = configmap("candidate")
        configmap("candidate", after)
    finally:
        install_manifest(original)
        require(
            docker(["exec", cluster.NODE, "cat", MANIFEST]).stdout == original,
            "manifest_restore_mismatch",
        )
        require(wait_etcd("rollback", baseline, official) == identity, "rollback_member_changed")
        configmap("baseline", before)
        if after is not None:
            configmap("candidate", after)
        print(f"Restored original manifest sha256={digest(original)}", flush=True)
    return candidate


def main(action):
    hosted()
    owner, revision = run_owner(), os.environ["GITHUB_SHA"]
    if action == "cleanup":
        witness = Recovery(STATE)
        require(
            witness.record["run_owner"] == owner and witness.record["source"] == revision,
            "wrong_cluster_run",
        )
        if witness.record["cluster"] and not witness.record["cluster"]["observed"]:
            witness.observe_cluster(STATE)
        witness.delete_cluster()
        print("Verified kind cluster and recorded node absent.")
        return
    require(action == "run", "unknown_adoption_action")
    witness = Recovery.begin(STATE, owner, revision)
    witness.arm_cluster()
    try:
        cluster.bootstrap(STATE, etcd_qualification=True)
    finally:
        witness.observe_cluster(STATE)
    cluster.validate_cluster(STATE)
    [node] = command(["kind", "get", "nodes", "--name", cluster.NAME]).splitlines()
    require(node == cluster.NODE, "expected_one_control_plane")
    config = exercise()
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as stream:
            print(f"config_id={config}", file=stream)


if __name__ == "__main__":
    main(sys.argv[1])
