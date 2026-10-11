import argparse
import copy
import socket
import ssl
import urllib.error
import uuid
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from mlsecops.bootstrap import initialize
from mlsecops.contracts import Rejected, canonical, decode, digest, now, read_json, write_json
from mlsecops.inventory import command, source_fingerprint
from mlsecops.qualification import qualify as qualify_worker
from scripts import tracking_service
from scripts.tracking_client import Client, configure_access, publish, read_back
from scripts.tracking_config import CONFIG_LABEL, LABEL
from scripts.tracking_records import export_records


def boundary_contracts(state, spec):
    observed = tracking_service.verify(state, spec)
    cases = []
    original_inspect = tracking_service.inspect
    for name, mutate in (
        ("foreign-owner", lambda item: item["Config"]["Labels"].pop(LABEL)),
        ("foreign-config", lambda item: item["Config"]["Labels"].pop(CONFIG_LABEL)),
        ("foreign-image", lambda item: item.update(Image="sha256:" + "b" * 64)),
        ("root-user", lambda item: item["Config"].update(User="0")),
        ("writable-root", lambda item: item["HostConfig"].update(ReadonlyRootfs=False)),
        ("privileged", lambda item: item["HostConfig"].update(Privileged=True)),
        ("extra-capability", lambda item: item["HostConfig"].update(CapAdd=["SYS_ADMIN"])),
        ("missing-cap-drop", lambda item: item["HostConfig"].update(CapDrop=[])),
        ("missing-no-new-privileges", lambda item: item["HostConfig"].update(SecurityOpt=[])),
        ("unbounded-memory", lambda item: item["HostConfig"].update(Memory=0)),
        ("unbounded-processes", lambda item: item["HostConfig"].update(PidsLimit=0)),
        (
            "public-port",
            lambda item: item["HostConfig"]["PortBindings"]["5000/tcp"][0].update(HostIp="0.0.0.0"),
        ),
        ("missing-live-port", lambda item: item["NetworkSettings"].update(Ports={"5000/tcp": []})),
        ("extra-network", lambda item: item["NetworkSettings"]["Networks"].update(foreign={})),
        (
            "extra-mount",
            lambda item: item["Mounts"].append({"Type": "bind", "Destination": "/host"}),
        ),
        (
            "writable-secrets",
            lambda item: next(
                mount for mount in item["Mounts"] if mount["Destination"] == "/config"
            ).update(RW=True),
        ),
    ):
        invalid = copy.deepcopy(observed["server"])
        mutate(invalid)

        def replacement(kind, name, required=True):
            if kind == "container" and name == tracking_service.names(spec)["server"]:
                return invalid
            return original_inspect(kind, name, required)

        with patch.object(tracking_service, "inspect", side_effect=replacement):
            try:
                tracking_service.verify(state, spec)
            except Rejected:
                cases.append("contract-" + name)
            else:
                raise Rejected("tracking_boundary_contract_bypass:" + name)
    return cases


def qualify(root, worker_image):
    state = root / ".runtime/tracking-service"
    output = root / ".runtime/evidence/tracking-service.json"
    write_json(output, {"status": "inconclusive", "release_ready": False, "started_at": now()})
    first = tracking_service.up(root, state, 15445)
    receipt_before = read_json(state / "resources.json")
    second = tracking_service.up(root, state, 15445)
    if first["identity"] != second["identity"] or receipt_before != read_json(
        state / "resources.json"
    ):
        raise Rejected("tracking_bootstrap_not_idempotent")
    spec = read_json(state / "configuration.json")
    cases = ["idempotent-native-bootstrap", "https-health-with-ca-hostname-check"]
    cases.extend(boundary_contracts(state, spec))
    for name, context, hostname in (
        ("unknown-ca", ssl.create_default_context(), "localhost"),
        (
            "wrong-hostname",
            ssl.create_default_context(cafile=str(state / "ca.crt")),
            "wrong.invalid",
        ),
    ):
        try:
            with socket.create_connection(("127.0.0.1", 15445), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname=hostname):
                    pass
        except ssl.SSLCertVerificationError:
            cases.append("https-" + name + "-denied")
        else:
            raise Rejected("tracking_tls_bypass:" + name)
    sql_result = tracking_service.docker(
        ["exec", "-i", tracking_service.names(spec)["server"], "python", "-"],
        (root / "scripts/tracking_sql_probe.py").read_bytes(),
        timeout=60,
    )
    sql_report = decode(sql_result.stdout)
    if sql_report.get("status") != "pass" or sql_report["checks"] != 16:
        raise Rejected("tracking_database_qualification_failed")
    cases.extend(sql_report["cases"])
    training_state = root / ".runtime/tracking-service-runs" / uuid.uuid4().hex
    initialize(root, training_state)
    training = qualify_worker(root, training_state, worker_image)
    records = export_records(training, read_json(root / "policies/local-cpu.json"))
    credentials = read_json(state / "credentials.json")
    clients = {
        role: Client(first["endpoint"], state / "ca.crt", role, credentials[role])
        for role in ("admin", "publisher", "reader", "foreign")
    }
    clients[None] = Client(first["endpoint"], state / "ca.crt")
    experiment = configure_access(clients["admin"], credentials, "release-risk-" + uuid.uuid4().hex)
    tracked = []
    for index, record in enumerate(records):
        receipt = publish(clients["publisher"], experiment, record)
        read_back(clients["reader"], receipt, record)
        cases.append(f"publish-read-back-{index}")
        for role, status in ((None, 401), ("foreign", 403)):
            clients[role].request("GET", receipt["artifact_path"], expected=status)
            clients[role].request(
                "PUT", receipt["artifact_path"], content=b"tamper", expected=status
            )
            cases.extend(
                [f"artifact-read-{role}-{index}-denied", f"artifact-write-{role}-{index}-denied"]
            )
        clients["reader"].request("PUT", receipt["artifact_path"], content=b"tamper", expected=403)
        clients["foreign"].request(
            "GET",
            "/api/2.0/mlflow/runs/get?" + urlencode({"run_id": receipt["run_id"]}),
            expected=403,
        )
        clients["publisher"].request(
            "POST",
            "/api/2.0/mlflow/runs/log-parameter",
            {"run_id": receipt["run_id"], "key": "input_digest", "value": "tamper"},
            expected=400,
        )
        clients["publisher"].request(
            "POST", "/api/2.0/mlflow/runs/delete", {"run_id": receipt["run_id"]}, expected=403
        )
        cases.extend(
            [
                f"reader-write-{index}-denied",
                f"foreign-run-{index}-denied",
                f"overwrite-input-{index}-denied",
                f"publisher-delete-{index}-denied",
            ]
        )
        tracked.append(receipt)
    if len({item["run_id"] for item in tracked}) != 3:
        raise Rejected("tracking_runs_reused")
    clients["publisher"].request(
        "PATCH",
        "/api/2.0/mlflow/users/update-admin",
        {"username": "publisher", "is_admin": True},
        expected=403,
    )
    cases.append("publisher-self-admin-denied")
    tracking_service.stop(state)
    tracking_service.up(root, state, 15445)
    if receipt_before != read_json(state / "resources.json"):
        raise Rejected("tracking_restart_changed_resources")
    for index, (receipt, record) in enumerate(zip(tracked, records, strict=True)):
        read_back(clients["reader"], receipt, record)
        clients["foreign"].request("GET", receipt["artifact_path"], expected=403)
        cases.extend([f"postgres-artifact-restart-{index}", f"restart-foreign-{index}-denied"])
    report = {
        "status": "pass",
        "scope": "persistent-postgresql-tls-tracking-not-full-M06",
        "release_ready": False,
        "checks": len(cases),
        "cases": cases,
        "completed_at": now(),
        "image_id": spec["image"],
        "postgres_image_id": receipt_before["pg_image"],
        "configuration_digest": spec["config_digest"],
        "endpoint": first["endpoint"],
        "worker_checks": len(training["cases"]),
        "training_metrics": training["metrics"],
        "worker_image": training["runs"][0]["image_id"],
        "tracking_runs": tracked,
        "source_fingerprint": source_fingerprint(root),
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "source_dirty": bool(command(["git", "-C", str(root), "status", "--porcelain"])),
        "record_digests": [digest(canonical(record)) for record in records],
    }
    write_json(output, report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker-image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        print(canonical(qualify(root, arguments.worker_image)).decode())
        return 0
    except (Rejected, OSError, urllib.error.URLError) as error:
        result = {
            "status": "inconclusive",
            "release_ready": False,
            "reason": str(error) if isinstance(error, Rejected) else type(error).__name__,
            "completed_at": now(),
        }
        write_json(root / ".runtime/evidence/tracking-service.json", result)
        print(canonical(result).decode())
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
