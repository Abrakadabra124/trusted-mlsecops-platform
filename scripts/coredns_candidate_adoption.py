"""Switch two CoreDNS replicas only inside the hosted job's owned kind cluster."""

import copy
import json
import os
import re
import sys
import time
from pathlib import Path

from mlsecops import cluster
from mlsecops.contracts import Rejected
from mlsecops.inventory import command
from mlsecops.kube_worker import ImageContentNotFound, image_config, image_document
from scripts import kube_coredns_probe as probe
from scripts.ci_campaign_producer import run_owner
from scripts.ci_consumer_recovery import Recovery
from scripts.etcd_candidate_adoption import (
    loaded_candidate_manifest,
    node_json,
    verify_candidate_ref,
)
from scripts.image_audit import file_hash
from scripts.image_coredns_dependency import SOURCE_ELF, candidate_tag
from scripts.kube_trust_native import hosted

STATE = Path(".runtime")


def replica(pod, status, image, config, manifest, elf):
    uid = pod["metadata"]["uid"]
    if not uid or not any(
        c["type"] == "Ready" and c["status"] == "True" for c in pod["status"]["conditions"]
    ):
        raise Rejected("coredns_replica_not_ready")
    match = re.fullmatch(r"containerd://([0-9a-f]{64})", status["containerID"])
    if not match:
        raise Rejected("coredns_container_id")
    cid = match[1]
    inspected = node_json("inspect", cid)
    live, pid = inspected["status"], inspected["info"]["pid"]
    if not (
        live["id"] == cid
        and live["state"] == "CONTAINER_RUNNING"
        and live["metadata"]["name"] == "coredns"
        and live["labels"]["io.kubernetes.pod.uid"] == uid
        and type(pid) is int
        and pid > 1
    ):
        raise Rejected("coredns_running_container_mismatch")
    if image == probe.COREDNS_SPEC_IMAGE:
        probe.verify_upstream(status, live)
    else:
        verify_candidate_ref(live, image, manifest, config)
        pod_ref = status["imageID"].removeprefix("docker-pullable://")
        if pod_ref != live["imageRef"]:
            verify_candidate_ref({**live, "imageRef": pod_ref}, image, manifest, config)
    exe = f"/proc/{pid}/exe"
    if command(["docker", "exec", cluster.NODE, "sha256sum", exe]) != f"{elf}  {exe}":
        raise Rejected("coredns_running_elf_mismatch")
    again = node_json("inspect", cid)
    if again["status"] != live or again["info"]["pid"] != pid:
        raise Rejected("coredns_container_changed_during_hash")
    print(
        f"pod_uid={uid} container={cid} imageRef={live['imageRef']} config={config} elf_sha256={elf}",
        flush=True,
    )
    return cid


def wait_backends(uids):
    deadline = time.monotonic() + 45
    while True:
        slices = probe.get(STATE, "endpointslices", "-l", "kubernetes.io/service-name=kube-dns")
        serving = [
            e.get("targetRef", {}).get("uid")
            for s in slices["items"]
            for e in s["endpoints"]
            if e.get("conditions", {}).get("ready") is not False
        ]
        if set(serving) == uids:
            return
        if time.monotonic() >= deadline:
            raise Rejected("coredns_service_backends_mismatch")
        time.sleep(1)


def verify_phase(phase, image, config, manifest, elf):
    print(f"Checking {phase} replicas", flush=True)
    pods = probe.ready_replicas(STATE, image, "Never" if phase == "candidate" else None)
    uids = {pod["metadata"]["uid"] for pod, _ in pods}
    if len(pods) != 2 or len(uids) != 2:
        raise Rejected("coredns_expected_two_replicas")
    containers = {replica(pod, status, image, config, manifest, elf) for pod, status in pods}
    if len(containers) != 2:
        raise Rejected("coredns_expected_two_containers")
    if image == probe.COREDNS_SPEC_IMAGE:
        try:
            descriptor = image_document(manifest)
        except ImageContentNotFound as missing:
            # Both live containers already proved the pinned repoDigest and config via CRI.
            print(f"{phase} upstream_manifest_absent={missing} verifying_config_blob", flush=True)
        else:
            if descriptor.get("config", {}).get("digest") != config:
                raise Rejected("coredns_upstream_config_mismatch")
        if image_config(config) != config:
            raise Rejected("coredns_upstream_config_mismatch")
    wait_backends(uids)
    print(
        f"{phase} ready=2 image={image} manifest={manifest} config={config} {probe.service_answer(STATE)}",
        flush=True,
    )


def switch(uid, before, after):
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/spec/template", "value": before},
        {"op": "replace", "path": "/spec/template", "value": after},
    ]
    cluster.kubectl(
        STATE,
        [
            "patch",
            "deployment/coredns",
            "-n",
            "kube-system",
            "--type=json",
            "-p",
            json.dumps(patch),
        ],
    )


def exercise(tag, config, manifest, elf):
    upstream = (probe.COREDNS_SPEC_IMAGE, probe.COREDNS_CONFIG, probe.COREDNS_MANIFEST, SOURCE_ELF)
    verify_phase("baseline", *upstream)
    deployment = probe.get(STATE, "deployment/coredns")
    uid = deployment["metadata"]["uid"]
    original = deployment["spec"]["template"]
    candidate = copy.deepcopy(original)
    [container] = [c for c in candidate["spec"]["containers"] if c["name"] == "coredns"]
    if container["image"] != probe.COREDNS_SPEC_IMAGE:
        raise Rejected("coredns_unexpected_base")
    container.update(image=tag, imagePullPolicy="Never")
    try:
        switch(uid, original, candidate)
        verify_phase("candidate", tag, config, manifest, elf)
    finally:
        current = probe.get(STATE, "deployment/coredns")
        if current["metadata"]["uid"] != uid:
            raise Rejected("coredns_deployment_replaced")
        if current["spec"]["template"] != original:
            switch(uid, candidate, original)
        restored = probe.get(STATE, "deployment/coredns")
        if restored["metadata"]["uid"] != uid or restored["spec"]["template"] != original:
            raise Rejected("coredns_template_restore_mismatch")
        verify_phase("rollback", *upstream)


def main(action):
    hosted()
    owner, revision = run_owner(), os.environ["GITHUB_SHA"]
    if action == "cleanup":
        witness = Recovery(STATE)
        if witness.record["run_owner"] != owner or witness.record["source"] != revision:
            raise Rejected("wrong_cluster_run")
        if witness.record["cluster"] and not witness.record["cluster"]["observed"]:
            witness.observe_cluster(STATE)
        witness.delete_cluster()
        handles = list((witness.record["cluster"] or {}).get("containers", {}))
        print(f"cluster_absent={cluster.NAME} recorded_nodes_absent={handles}", flush=True)
        return
    config, elf = os.environ["QUALIFIED_CONFIG"], os.environ["QUALIFIED_ELF"]
    if (
        action != "run"
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", config)
        or config == probe.COREDNS_CONFIG
        or not re.fullmatch(r"[0-9a-f]{64}", elf)
        or elf == SOURCE_ELF
    ):
        raise Rejected("invalid_coredns_qualification_outputs")
    witness = Recovery.begin(STATE, owner, revision)
    witness.arm_cluster()
    try:
        cluster.bootstrap(STATE)
    finally:
        witness.observe_cluster(STATE)
    cluster.validate_cluster(STATE)
    if len(witness.record["cluster"]["containers"]) != 1 or command(
        ["kind", "get", "nodes", "--name", cluster.NAME]
    ).splitlines() != [cluster.NODE]:
        raise Rejected("expected_one_control_plane")
    tag = candidate_tag(config)
    archive = Path(os.environ["RUNNER_TEMP"]) / "coredns-dependency/candidate.tar"
    if file_hash(archive) != os.environ["QUALIFIED_ARCHIVE_SHA256"]:
        raise Rejected("coredns_archive_changed_before_kind_load")
    command(
        [
            "kind",
            "load",
            "image-archive",
            "--name",
            cluster.NAME,
            "--nodes",
            cluster.NODE,
            str(archive),
        ],
        timeout=180,
    )
    exercise(tag, config, loaded_candidate_manifest(tag, config), elf)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="ascii") as stream:
        print(f"live_config={config}", file=stream)


if __name__ == "__main__":
    main(sys.argv[1])
