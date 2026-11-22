"""Import disposable aliases on the already validated kind node, without retagging host images."""

import re
import subprocess
import tempfile
from contextlib import contextmanager

from mlsecops.cluster import NAME, NODE, kubectl, validate_cluster
from mlsecops.contracts import Rejected, decode
from mlsecops.inventory import command
from mlsecops.kube_worker import image_config

ID = re.compile(r"sha256:[a-f0-9]{64}")
ROOT = "/var/local-path-provisioner"


def need(condition, reason):
    if not condition:
        raise Rejected("local_path_" + reason)


def owned_node(state):
    marker = validate_cluster(state)
    need(command(["kind", "get", "nodes", "--name", NAME]).splitlines() == [NODE], "kind_nodes")
    (node,) = decode(kubectl(state, ["get", "nodes", "-o", "json"]).stdout)["items"]
    (host,) = decode(command(["docker", "inspect", NODE]).encode())
    ips = {n["IPAddress"] for n in host["NetworkSettings"]["Networks"].values()}
    need(
        host["Config"]["Labels"].get("io.x-k8s.kind.cluster") == NAME
        and host["State"]["Running"] is True
        and node["metadata"]["name"] == NODE
        and any(
            a["type"] == "InternalIP" and a["address"] in ips for a in node["status"]["addresses"]
        )
        and any(
            c["type"] == "Ready" and c["status"] == "True" for c in node["status"]["conditions"]
        ),
        "node_identity",
    )
    for mount in host["Mounts"]:
        dest = mount["Destination"].rstrip("/")
        if mount["Type"] == "bind":
            need(
                not (ROOT == dest or ROOT.startswith(dest + "/") or dest.startswith(ROOT + "/")),
                "host_bind",
            )
    return {"cluster_namespace_uid": marker["namespace_uid"], "node_uid": node["metadata"]["uid"]}


CTR = ["docker", "exec", NODE, "ctr", "-n", "k8s.io", "images"]


def aliases(repo):
    return [
        r
        for r in command([*CTR, "ls", "-q"]).splitlines()
        if r.startswith((repo + ":", repo + "@"))
    ]


def descriptor(name):
    rows = [
        line.split()
        for line in command([*CTR, "ls", "name==" + name]).splitlines()
        if line.split()[:1] == [name]
    ]
    need(len(rows) == 1 and len(rows[0]) >= 3 and ID.fullmatch(rows[0][2]), "image_descriptor")
    return rows[0][2]


@contextmanager
def loaded(repo, config):
    # --base-name filters archived references. --index-name installs our unique tag
    # even when the build left an untagged config in the runner's Docker store.
    tag = repo + ":test"
    need(not aliases(repo), "alias_exists")
    owned = {tag}
    try:
        with tempfile.TemporaryFile() as archive:
            subprocess.run(
                ["docker", "image", "save", config],
                stdout=archive,
                stderr=subprocess.PIPE,
                check=True,
                timeout=180,
            )
            archive.seek(0)
            subprocess.run(
                [
                    "docker",
                    "exec",
                    "-i",
                    NODE,
                    *CTR[3:],
                    "import",
                    "--local",
                    "--base-name",
                    repo,
                    "--index-name",
                    tag,
                    "--platform",
                    "linux/amd64",
                    "-",
                ],
                stdin=archive,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
                timeout=180,
            )
        image = descriptor(tag)
        need(image_config(image) == config, "imported_descriptor")
        ref = repo + "@" + image
        if ref not in aliases(repo):
            owned.add(ref)
            command([*CTR, "tag", tag, ref])
        for name in (tag, ref):
            cri = decode(command(["docker", "exec", NODE, "crictl", "inspecti", name]).encode())
            need(cri["status"]["id"] == config, "imported_config")
        yield ref
    finally:
        for alias in owned.intersection(aliases(repo)):
            need(image_config(descriptor(alias)) == config, "cleanup_foreign_image")
            command([*CTR, "rm", alias])
        need(not aliases(repo), "alias_cleanup")
