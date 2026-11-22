"""Disposable hosted PVC qualification after the same-job static gate for this image ID."""

import argparse
import copy
import os
import platform
import re
import signal
import subprocess
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from uuid import UUID, uuid4

from mlsecops.cluster import NODE, kubectl
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.inventory import command
from mlsecops.kube_storage import matches
from mlsecops.kube_storage_resources import CLASS as RETAIN_CLASS
from mlsecops.kube_worker import pod_spec, verify_running_image
from mlsecops.sandbox import resolve_image
from scripts.image_audit_contract import LOCAL_PATH_CONFIG as STOCK_ID
from scripts.local_path_pvc_images import ID, ROOT, aliases, loaded, need, owned_node

NS = "ml-control"  # bootstrap-owned, restricted admission, default-deny networking
SYSTEM = "local-path-storage"
DEP = "local-path-provisioner"
DRIVER = "rancher.io/local-path"
LABEL = "trusted-mlsecops/pvc-probe"
TYPES = {
    "Pod": "pods",
    "PersistentVolumeClaim": "persistentvolumeclaims",
    "StorageClass": "storageclasses",
}


def get(state, resource, name, namespace=None):
    ns = ["-n", namespace] if namespace else []
    data = kubectl(state, ["get", resource, name, *ns, "--ignore-not-found", "-o", "json"]).stdout
    return decode(data) if data.strip() else None


def wait(check, reason, seconds=90):
    end = time.monotonic() + seconds
    while True:
        result = check()
        if result:
            return result
        if time.monotonic() >= end:
            raise Rejected("local_path_" + reason)
        time.sleep(1)


def deployment(state):
    return get(state, "deployment", DEP, SYSTEM)


def retained(state):
    cls = get(state, "sc", RETAIN_CLASS)
    if cls:
        need(cls.get("reclaimPolicy") == "Retain", "retain_class_policy")
    volumes = decode(kubectl(state, ["get", "pv", "-o", "json"]).stdout)["items"]
    protected = sorted(
        (v["metadata"]["uid"], v["spec"])
        for v in volumes
        if v["spec"].get("storageClassName") == RETAIN_CLASS
    )
    settings = {k: v for k, v in (cls or {}).items() if k != "metadata"}
    return digest(canonical([cls["metadata"]["uid"] if cls else None, settings, protected]))


def controller(spec):
    (only,) = spec["template"]["spec"]["containers"]
    need(only["name"] == DEP, "unexpected_controller")
    return only


def parent_of(item, kind):
    (owner,) = [o for o in item["metadata"]["ownerReferences"] if o.get("controller")]
    need(owner["kind"] == kind, "controller_owner")
    return owner


def ready(state, uid, spec, config):
    kubectl(
        state,
        [
            "rollout",
            "status",
            "deployment/" + DEP,
            "-n",
            SYSTEM,
            "--timeout=120s",
            "--request-timeout=125s",
        ],
        timeout=135,
    )
    dep = deployment(state)
    status = dep["status"]
    need(
        dep["metadata"]["uid"] == uid
        and dep["spec"] == spec
        and spec["replicas"] == 1
        and status["observedGeneration"] == dep["metadata"]["generation"]
        and all(
            status.get(k) == 1 for k in ("updatedReplicas", "availableReplicas", "readyReplicas")
        ),
        "rollout_state",
    )
    items = decode(
        kubectl(state, ["get", "pods", "-n", SYSTEM, "-l", "app=" + DEP, "-o", "json"]).stdout
    )
    (pod,) = [p for p in items["items"] if not p["metadata"].get("deletionTimestamp")]
    rs_owner = parent_of(pod, "ReplicaSet")
    rs = get(state, "rs", rs_owner["name"], SYSTEM)
    need(
        rs["metadata"]["uid"] == rs_owner["uid"] and parent_of(rs, "Deployment")["uid"] == uid,
        "rollout_owner",
    )
    (actual,) = pod["spec"]["containers"]
    (running,) = pod["status"]["containerStatuses"]
    need(
        all(actual[k] == controller(spec)[k] for k in ("name", "image", "imagePullPolicy"))
        and pod["spec"].get("nodeName") == NODE
        and pod["status"]["phase"] == "Running"
        and running["name"] == DEP
        and running["ready"] is True
        and "running" in running["state"],
        "controller_not_ready",
    )
    return {
        "deployment_uid": uid,
        "pod_uid": pod["metadata"]["uid"],
        "image": actual["image"],
        "pull_policy": actual["imagePullPolicy"],
        "imageID": verify_running_image(pod, config),
        "config_id": config,
        "spec_sha256": digest(canonical(spec)),
    }


def patch_spec(state, uid, before, after):
    operations = [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/spec", "value": before},
    ]
    for field in ("image", "imagePullPolicy"):
        operations.append(
            {
                "op": "replace",
                "path": "/spec/template/spec/containers/0/" + field,
                "value": controller(after)[field],
            }
        )
    kubectl(
        state,
        [
            "patch",
            "deployment",
            DEP,
            "-n",
            SYSTEM,
            "--type=json",
            "-p",
            canonical(operations).decode(),
        ],
    )


@contextmanager
def rollout(state, original, ref, config, evidence):
    uid, old = original["metadata"]["uid"], original["spec"]
    new = copy.deepcopy(old)
    controller(new).update(image=ref, imagePullPolicy="Never")
    try:
        patch_spec(state, uid, old, new)
        evidence["candidate"] = ready(state, uid, new, config)
        yield new
    finally:
        # The apiserver may have accepted a patch whose response timed out.
        for attempt in range(2):
            try:
                current = deployment(state)
                need(current["metadata"]["uid"] == uid, "restore_uid_changed")
                if current["spec"] != old:
                    actual = controller(current["spec"])
                    need(
                        all(actual[f] == controller(new)[f] for f in ("image", "imagePullPolicy")),
                        "restore_foreign_controller",
                    )
                    patch_spec(state, uid, current["spec"], old)
                evidence["restored"] = ready(state, uid, old, STOCK_ID)
                break
            except (Rejected, subprocess.TimeoutExpired):
                if attempt:
                    raise


def location(claim):
    meta = claim["metadata"]
    uid = str(UUID(meta["uid"]))
    need(
        meta["uid"] == uid
        and meta["namespace"] == NS
        and re.fullmatch(r"lp-[a-z0-9-]{1,48}", meta["name"]),
        "claim_identity",
    )
    name = "pvc-" + uid
    return name, f"{ROOT}/{name}_{NS}_{meta['name']}"


def check_pv(claim, volume):
    name, path = location(claim)
    spec, meta = volume["spec"], volume["metadata"]
    sources = [spec[key]["path"] for key in ("hostPath", "local") if key in spec]
    need(
        meta["name"] == name
        and meta["annotations"].get("pv.kubernetes.io/provisioned-by") == DRIVER
        and spec["storageClassName"] == claim["spec"]["storageClassName"]
        and spec["persistentVolumeReclaimPolicy"] == "Delete"
        and sources == [path]
        and all(
            spec["claimRef"].get(k) == claim["metadata"][k] for k in ("uid", "name", "namespace")
        ),
        "volume_binding",
    )


def directory(claim):
    # The probe only observes the literal, UUID-derived child on the validated kind node.
    # An unavailable node, an inaccessible parent or a dangling symlink cannot prove absence.
    _, path = location(claim)
    script = """
set -eu
[ "$(realpath -e /var)" = /var ] && [ -x /var ] || exit 2
if [ -L "$1" ]; then exit 2; fi
if [ -e "$1" ]; then [ -d "$1" ] && [ -x "$1" ] || exit 2; fi
if [ -L "$2" ]; then exit 2; fi
if [ -d "$2" ]; then echo present; elif [ ! -e "$2" ]; then echo absent; else exit 2; fi
"""
    observed = command(["docker", "exec", NODE, "sh", "-c", script, "probe", ROOT, path])
    need(observed in {"present", "absent"}, "directory_observation")
    return observed


def consumer(name, image, writer):
    spec = pod_spec(image, "default", [], memory="128Mi")
    spec["volumes"] = [{"name": "data", "persistentVolumeClaim": {"claimName": name}}]
    spec["activeDeadlineSeconds"] = 240
    spec["containers"][0].update(
        command=["python", "-I", "-B", "-c", "import time; time.sleep(240)"],
        workingDir="/data",
        volumeMounts=[
            {"name": "data", "mountPath": "/data", **({} if writer else {"readOnly": True})}
        ],
    )
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name + ("-write" if writer else "-read"), "namespace": NS},
        "spec": spec,
    }


@contextmanager
def owned(state, doc, token, retries, reclaim=None):
    meta = doc["metadata"]
    resource, name, ns = TYPES[doc["kind"]], meta["name"], meta.get("namespace")
    meta["labels"] = {LABEL: token}

    def lookup():
        return get(state, resource, name, ns)

    need(lookup() is None, "resource_exists")
    uid = None
    created = None

    def cleanup():
        nonlocal uid, created
        current = lookup()
        if current is not None:
            identity = current["metadata"]
            need(
                identity.get("labels", {}).get(LABEL) == token
                and (uid is None or uid == identity["uid"]),
                "cleanup_foreign_resource",
            )
            uid, created = identity["uid"], current
            if reclaim:
                reclaim(current, False)
            endpoint = f"/api/v1/namespaces/{ns}" if ns else "/apis/storage.k8s.io/v1"
            options = {
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "preconditions": {"uid": identity["uid"]},
            }
            kubectl(state, ["delete", f"--raw={endpoint}/{resource}/{name}", "-f", "-"], options)
            wait(lambda: lookup() is None, "resource_cleanup")
        if reclaim and (current or created):
            reclaim(current or created, True)

    try:
        created = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], doc).stdout)
        need(
            created["metadata"]["labels"][LABEL] == token and created["metadata"]["name"] == name,
            "create_identity",
        )
        uid = created["metadata"]["uid"]
        yield created
    finally:
        try:
            cleanup()
        except Exception:
            # Retry after restoring the stock controller, keeping the class until PV cleanup.
            retries.append(cleanup)
            raise


def run_consumer(state, name, worker, worker_id, marker, writer, token, binding, retries):
    pod = consumer(name, worker, writer)
    with owned(state, pod, token, retries) as created:
        pod_name = created["metadata"]["name"]

        def running():
            item = get(state, "pod", pod_name, NS)
            need(
                item["metadata"]["uid"] == created["metadata"]["uid"]
                and item["status"].get("phase") not in ("Failed", "Succeeded"),
                "consumer_failed",
            )
            statuses = item["status"].get("containerStatuses", [])
            return item if len(statuses) == 1 and statuses[0]["ready"] else None

        item = wait(running, "consumer_deadline", 150)
        need(
            item["spec"]["nodeName"] == NODE
            and matches(pod["spec"], item["spec"])
            and not any(
                item["spec"].get(k)
                for k in (
                    "hostNetwork",
                    "hostPID",
                    "hostIPC",
                    "initContainers",
                    "ephemeralContainers",
                )
            ),
            "consumer_spec",
        )
        verify_running_image(item, worker_id)
        binding()
        code = (
            "import os,sys; f=open('marker','xb'); f.write(sys.argv[1].encode()); "
            "f.flush(); os.fsync(f.fileno()); f.close()"
            if writer
            else "import os; f=os.open('marker',os.O_RDONLY|os.O_NOFOLLOW); print(os.read(f,37).decode())"
        )
        data = kubectl(
            state,
            [
                "exec",
                pod_name,
                "-n",
                NS,
                "-c",
                "worker",
                "--",
                "python",
                "-I",
                "-B",
                "-c",
                "import os; os.chdir('/data'); " + code,
                *([marker] if writer else []),
            ],
        ).stdout
        if not writer:
            need(data == (marker + "\n").encode(), "marker_mismatch")
        return item["metadata"]["uid"]


def exercise(state, token, worker, worker_id, evidence, retries):
    name, marker = "lp-" + token, str(uuid4())
    sc = {
        "apiVersion": "storage.k8s.io/v1",
        "kind": "StorageClass",
        "metadata": {"name": name},
        "provisioner": DRIVER,
        "reclaimPolicy": "Delete",
        "volumeBindingMode": "WaitForFirstConsumer",
    }
    pvc = {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": name, "namespace": NS},
        "spec": {
            "storageClassName": name,
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": "16Mi"}},
        },
    }

    def reclaim(claim, deleted):
        pv_name, _ = location(claim)
        need(
            claim["spec"]["storageClassName"] == name
            and claim["spec"].get("volumeName", pv_name) == pv_name,
            "cleanup_foreign_binding",
        )
        if not deleted:
            volume = get(state, "pv", pv_name)
            if volume:
                check_pv(claim, volume)
                need(
                    volume["metadata"]["uid"] == evidence.get("pv_uid", volume["metadata"]["uid"]),
                    "replaced_volume",
                )
            return
        evidence["pvc_deleted"] = True
        wait(lambda: get(state, "pv", pv_name) is None, "pv_cleanup")
        evidence["pv_deleted"] = True
        wait(lambda: directory(claim) == "absent", "backing_cleanup")
        evidence["reclaimed"] = True

    def class_guard(current, deleted):
        if not deleted:
            need(
                get(state, "pvc", name, NS) is None
                and (
                    not evidence.get("pvc_uid")
                    or get(state, "pv", "pvc-" + evidence["pvc_uid"]) is None
                ),
                "class_still_in_use",
            )

    with owned(state, sc, token, retries, class_guard) as created_sc:
        need(
            all(
                created_sc[k] == sc[k]
                for k in ("provisioner", "reclaimPolicy", "volumeBindingMode")
            )
            and not created_sc.get("parameters"),
            "class_settings",
        )
        with owned(state, pvc, token, retries, reclaim) as claim:
            uid = claim["metadata"]["uid"]
            evidence["pvc_uid"] = uid
            pv_name, path = location(claim)
            need(
                claim["spec"]["storageClassName"] == name
                and not claim["spec"].get("volumeName")
                and get(state, "pv", pv_name) is None
                and directory(claim) == "absent",
                "preexisting_volume",
            )

            def binding():
                current = get(state, "pvc", name, NS)
                need(
                    current["metadata"]["uid"] == uid
                    and current["status"]["phase"] == "Bound"
                    and current["spec"]["volumeName"] == pv_name,
                    "claim_binding",
                )
                volume = get(state, "pv", pv_name)
                check_pv(current, volume)
                need(
                    volume["status"]["phase"] == "Bound" and directory(current) == "present",
                    "volume_state",
                )
                need(
                    evidence.setdefault("pv_uid", volume["metadata"]["uid"])
                    == volume["metadata"]["uid"],
                    "remount_binding",
                )
                evidence["pvc_bound"] = True

            evidence["backing_path"] = path
            for writer, key in ((True, "writer_uid"), (False, "reader_uid")):
                evidence[key] = run_consumer(
                    state, name, worker, worker_id, marker, writer, token, binding, retries
                )
                binding()  # Same bound PVC/PV after the preceding Pod has actually disappeared.
            need(evidence["writer_uid"] != evidence["reader_uid"], "reused_consumer")
            evidence["remount_verified"] = True


def qualify(state, image_id, evidence):
    need(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and platform.system() == "Linux"
        and platform.machine() == "x86_64",
        "hosted_only",
    )
    need(ID.fullmatch(image_id) and image_id != STOCK_ID, "candidate_id")
    evidence.update(owned_node(state))
    need(
        command(["docker", "image", "inspect", "--format", "{{.Id}}", image_id]) == image_id,
        "host_candidate",
    )
    original = deployment(state)
    uid, spec = original["metadata"]["uid"], original["spec"]
    need(
        re.fullmatch(
            r"(?:docker\.io/)?kindest/local-path-provisioner[:@].+", controller(spec)["image"]
        ),
        "stock_reference",
    )
    evidence["baseline"] = ready(state, uid, spec, STOCK_ID)
    token = uuid4().hex
    worker_id = resolve_image("trusted-mlsecops:dev")
    protected = retained(state)
    repos = ["docker.io/library/lp-worker-" + token, "docker.io/library/lp-controller-" + token]
    with ExitStack() as images:

        def verify_alias_cleanup():
            evidence["aliases_removed"] = all(not aliases(repo) for repo in repos)

        images.callback(verify_alias_cleanup)
        worker = images.enter_context(loaded(repos[0], worker_id))
        ref = images.enter_context(loaded(repos[1], image_id))
        retries = []
        try:
            with rollout(state, original, ref, image_id, evidence) as candidate_spec:
                exercise(state, token, worker, worker_id, evidence, retries)
                evidence["candidate_after_reclaim"] = ready(state, uid, candidate_spec, image_id)
        finally:
            # Callbacks were collected in pod, PVC, class order. Run all even if one fails.
            with ExitStack() as recovery:

                def verify_retained():
                    need(retained(state) == protected, "retained_storage_changed")
                    evidence["retain_inventory_sha256"] = protected
                    name = "lp-" + token
                    evidence["resources_absent"] = all(
                        get(state, kind, key, ns) is None
                        for kind, key, ns in (
                            ("sc", name, None),
                            ("pvc", name, NS),
                            ("pod", name + "-write", NS),
                            ("pod", name + "-read", NS),
                        )
                    )

                recovery.callback(verify_retained)
                for cleanup in reversed(retries):
                    recovery.callback(cleanup)


def public_report(evidence, reason):
    baseline = evidence.get("baseline", {})
    candidate = evidence.get("candidate", {})
    restored = evidence.get("restored", {})
    runtime = re.search(r"sha256:[0-9a-f]{64}$", candidate.get("imageID", ""))
    cleanup = bool(
        restored.get("config_id") == STOCK_ID
        and evidence.get("pvc_deleted")
        and evidence.get("pv_deleted")
        and evidence.get("reclaimed")
        and evidence.get("aliases_removed")
        and evidence.get("resources_absent")
        and evidence.get("retain_inventory_sha256")
    )
    complete = bool(
        cleanup
        and runtime
        and baseline.get("config_id") == STOCK_ID
        and evidence.get("pvc_bound")
        and evidence.get("remount_verified")
        and evidence.get("candidate_after_reclaim")
    )
    return {
        "schema_version": 1,
        "scope": "disposable-local-path-pvc",
        "status": "pass" if complete and reason is None else "inconclusive",
        "release_ready": False,
        "deployment_uid": baseline.get("deployment_uid"),
        "baseline_config_id": baseline.get("config_id"),
        "candidate_config_id": candidate.get("config_id"),
        "candidate_runtime_digest": runtime.group() if runtime else None,
        "restored_stock_config_id": restored.get("config_id"),
        "pvc_bound": bool(evidence.get("pvc_bound")),
        "remount_verified": bool(evidence.get("remount_verified")),
        "pvc_deleted": bool(evidence.get("pvc_deleted")),
        "pv_deleted": bool(evidence.get("pv_deleted")),
        "backing_directory_absent": bool(evidence.get("reclaimed")),
        "cleanup_verified": cleanup,
        "reason": reason if reason or complete else "local_path_evidence_incomplete",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args(argv)
    evidence = {}
    reason = None

    def interrupted(*_):
        raise Rejected("local_path_interrupted")

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        qualify(Path(".runtime"), args.image_id, evidence)
    except (
        Rejected,
        OSError,
        ValueError,
        LookupError,
        AttributeError,
        KeyboardInterrupt,
        TypeError,
        subprocess.SubprocessError,
    ) as error:
        reason = (
            str(error)
            if isinstance(error, Rejected) and re.fullmatch(r"[a-z0-9_:]{1,120}", str(error))
            else "local_path_operation_failed"
        )
    finally:
        signal.signal(signal.SIGTERM, previous)
    report = public_report(evidence, reason)
    print(canonical(report).decode(), flush=True)
    return int(report["status"] != "pass")


if __name__ == "__main__":
    raise SystemExit(main())
