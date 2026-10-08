import argparse
import errno
import ipaddress
import os
import socket
import time
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, read_json, write_json

LABELS = Path("/tmp/boundary-labels.json")
READY = Path("/tmp/boundary-ready.json")
STOP = Path("/tmp/boundary-stop")
PROTECTED = (
    "/client/client.key",
    "/client/client.crt",
    "/client/connection.json",
    "/api/token",
    "/signer/key.pem",
    "/source/key.pem",
    "/source/client.key",
    "/app/.runtime/keys/evaluator.pem",
    "/app/.runtime/approved/holdout.json",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/docker.sock",
    "/etc/kubernetes/admin.conf",
    LABELS.as_posix(),
)


def read_attempt(location):
    try:
        with Path(location).open("rb") as source:
            source.read(1)
        return "readable"
    except OSError as error:
        return {errno.ENOENT: "ENOENT", errno.EACCES: "EACCES", errno.EPERM: "EPERM"}.get(
            error.errno, "unexpected-error"
        )


def paths(node_pid):
    if type(node_pid) is not int or not 1 < node_pid < 2**31:
        raise Rejected("boundary_invalid_node_pid")
    return [
        *PROTECTED,
        *(f"/proc/{node_pid}/{name}" for name in ("mem", "environ", "cmdline")),
        *(f"/proc/{node_pid}/root{path}" for path in PROTECTED),
    ]


def network(address, port):
    try:
        valid = ipaddress.ip_address(address) in ipaddress.ip_network("10.79.0.0/16")
    except ValueError:
        valid = False
    if not valid or type(port) is not int or port not in (443, 5432):
        raise Rejected("boundary_target_outside_owned_services")
    try:
        with socket.create_connection((address, port), timeout=3):
            return "connected"
    except TimeoutError:
        return "timeout"
    except OSError:
        return "unexpected-error"


def worker(node_pid, sql_address, api_address):
    return {
        "schema_version": 1,
        "uid": os.geteuid(),
        "pid_namespace": os.readlink("/proc/self/ns/pid"),
        "reads": {path: read_attempt(path) for path in paths(node_pid)},
        "sql": network(sql_address, 5432),
        "api": network(api_address, 443),
    }


def witness_observation(request):
    from mlsecops import storage, storage_dataset
    from mlsecops.controller import process_state
    from mlsecops.controller_api import Client
    from mlsecops.inventory import source_fingerprint
    from mlsecops.signing import encode64, load_key

    root = Path(__file__).resolve().parents[1]
    if request["profile"]["source_fingerprint"] != source_fingerprint(root):
        raise Rejected("boundary_witness_source_stale")
    process = process_state("scorer")
    if (
        network(request["sql_address"], 5432) != "connected"
        or network(request["api_address"], 443) != "connected"
    ):
        raise Rejected("boundary_witness_endpoint_unavailable")
    if Client("scorer").request("pods").get("kind") != "PodList":
        raise Rejected("boundary_witness_api_unavailable")
    with storage.connect(Path("/client")) as connection:
        if connection.execute(
            "SELECT current_user, ssl, version FROM pg_stat_ssl WHERE pid=pg_backend_pid();"
        ).fetchone() != ("ml_scorer", True, "TLSv1.3"):
            raise Rejected("boundary_witness_sql_identity")
    splits, _, _ = storage_dataset.read_dataset(
        Path("/client"),
        request["dataset_reference"],
        read_json(root / "policies/local-cpu.json"),
        request["trust"]["curator"],
        request["trust"]["source_approval_digest"],
        ("holdout",),
    )
    labels = [row["label"] for row in splits["holdout"]]
    key = load_key(Path("/signer/key.pem"))
    if encode64(key.public_key().public_bytes_raw()) != request["trust"]["evaluator"]:
        raise Rejected("boundary_witness_signer_mismatch")
    report = {
        "schema_version": 1,
        "role": "scorer",
        "status": "pass",
        "process": process,
        "pid_namespace": os.readlink("/proc/self/ns/pid"),
        "pid": os.getpid(),
        "holdout_rows": len(labels),
        "checks": [
            "sql-connected",
            "api-connected",
            "api-authenticated",
            "sql-authenticated-tls",
            "verified-holdout-readable",
            "trusted-signer-readable",
        ],
    }
    return labels, key, report


def witness(request):
    labels, key, before = witness_observation(request)
    write_json(LABELS, labels)
    if read_json(LABELS) != labels:
        raise Rejected("boundary_witness_labels_unavailable")
    write_json(READY, before)
    started = time.monotonic()
    while not STOP.exists():
        if time.monotonic() - started > 210:
            raise Rejected("boundary_witness_deadline")
        time.sleep(0.5)
    after_labels, after_key, after = witness_observation(request)
    if (
        after_labels != labels
        or read_json(LABELS) != labels
        or after_key.public_key().public_bytes_raw() != key.public_key().public_bytes_raw()
        or after["pid_namespace"] != before["pid_namespace"]
    ):
        raise Rejected("boundary_witness_state_changed")
    return {"before": before, "after": after}


def main():
    parser = argparse.ArgumentParser(description="Bounded live worker/scorer access probes")
    parser.add_argument("action", choices=("worker", "witness"))
    parser.add_argument("--request", type=Path)
    parser.add_argument("--node-pid", type=int)
    parser.add_argument("--sql-address")
    parser.add_argument("--api-address")
    arguments = parser.parse_args()
    try:
        if arguments.action == "witness":
            report = witness(read_json(arguments.request))
        else:
            report = worker(arguments.node_pid, arguments.sql_address, arguments.api_address)
        print(canonical(report).decode())
        return 0
    except (Rejected, OSError):
        print(canonical({"status": "fail", "reason": "boundary_probe_failed"}).decode())
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
