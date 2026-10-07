import argparse
import io
import shutil
import socket
import subprocess
import sys
import tarfile
import time
from pathlib import Path

from mlsecops import storage_pki
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.storage_schema import DATABASE, SCHEMA_VERSION, migration_sql, roles_sql

IMAGE = (
    "postgres:18.6-bookworm@sha256:9551dd5bf356409a21b31248f49b33bba9bb1877365f3a7e933aecd9af3cf52d"
)
WORKSPACE_LABEL = "org.trusted-mlsecops.workspace"
CONFIG_LABEL = "org.trusted-mlsecops.storage-config"
MOUNT = "/var/lib/postgresql"
PGDATA = f"{MOUNT}/18/docker"
LIMITS = [
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--cpus",
    "1",
    "--memory",
    "512m",
    "--memory-swap",
    "512m",
    "--pids-limit",
    "64",
    "--ulimit",
    "nofile=256:256",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=999,gid=999,mode=700",
]


def docker(arguments, content=None, timeout=60, check=True):
    try:
        result = subprocess.run(
            ["docker", *arguments], input=content, capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Rejected("storage_docker_unavailable") from error
    if len(result.stdout) > 2 * 1024 * 1024 or len(result.stderr) > 2 * 1024 * 1024:
        raise Rejected("storage_docker_output_limit")
    if check and result.returncode:
        raise Rejected(f"storage_docker_failed:{arguments[0]}")
    return result


def inspect(kind, name, required=True):
    result = docker([kind, "inspect", name], check=False)
    if result.returncode:
        if required:
            raise Rejected(f"storage_resource_missing:{kind}")
        return None
    value = decode(result.stdout)
    if not isinstance(value, list) or len(value) != 1:
        raise Rejected("storage_inspect_invalid")
    return value[0]


def configuration():
    allowed = ",".join(f"ml_{role}" for role in storage_pki.ROLES)
    hba = (
        "local all postgres peer\n"
        "local all all reject\n"
        f"hostssl {DATABASE} {allowed} 0.0.0.0/0 cert\n"
        f"hostssl {DATABASE} {allowed} ::/0 cert\n"
        "host all all 0.0.0.0/0 reject\n"
        "host all all ::/0 reject\n"
    ).encode()
    settings = {
        "listen_addresses": "'*'",
        "unix_socket_directories": "'/tmp'",
        "unix_socket_permissions": "0700",
        "ssl": "on",
        "ssl_min_protocol_version": "'TLSv1.3'",
        "ssl_max_protocol_version": "'TLSv1.3'",
        "ssl_cert_file": f"'{MOUNT}/tls/server.crt'",
        "ssl_key_file": f"'{MOUNT}/tls/server.key'",
        "ssl_ca_file": f"'{MOUNT}/tls/ca.crt'",
        "hba_file": f"'{MOUNT}/tls/pg_hba.conf'",
        "max_connections": "32",
        "shared_buffers": "64MB",
        "work_mem": "4MB",
        "maintenance_work_mem": "32MB",
        "temp_file_limit": "32MB",
        "max_wal_size": "256MB",
        "statement_timeout": "5s",
        "lock_timeout": "2s",
        "idle_in_transaction_session_timeout": "10s",
        "log_statement": "'none'",
        "log_min_messages": "warning",
        "log_min_error_statement": "panic",
        "log_error_verbosity": "terse",
        "logging_collector": "off",
    }
    config = "\n".join(f"{key} = {value}" for key, value in settings.items()).encode() + b"\n"
    return {"postgresql.conf": config, "pg_hba.conf": hba}


def specification(state, port):
    identity = storage_pki.workspace_id(state)
    pki = storage_pki.validate(state)
    if type(port) is not int or not 1024 <= port <= 65535:
        raise Rejected("storage_port_invalid")
    files = configuration()
    for name in ("ca.crt", "server.crt", "server.key"):
        files[name] = bounded_read(safe_child(state, f"storage-pki/{name}"), 4096)
    fingerprint = digest(
        canonical(
            {
                "image": IMAGE,
                "port": port,
                "configuration": {
                    name: digest(content) for name, content in configuration().items()
                },
                "certificates": pki["certificates"],
            }
        )
    )
    name = f"tml-{identity[:12]}-storage"
    return {
        "schema_version": 1,
        "workspace_id": identity,
        "config_digest": fingerprint,
        "name": name,
        "volume": f"{name}-data",
        "network": f"{name}-net",
        "image": IMAGE,
        "port": port,
    }, files


def owned(observed, spec, kind):
    labels = (
        observed["Config"].get("Labels", {}) if kind == "container" else observed.get("Labels", {})
    )
    if (
        labels.get(WORKSPACE_LABEL) != spec["workspace_id"]
        or labels.get(CONFIG_LABEL) != spec["config_digest"]
    ):
        raise Rejected(f"storage_ownership_or_config_mismatch:{kind}")


def validate(state):
    marker = read_json(safe_child(state, "storage.json"))
    spec, _ = specification(state, marker.get("port"))
    if any(marker.get(key) != value for key, value in spec.items()):
        raise Rejected("storage_identity_changed")
    container = inspect("container", spec["name"])
    network = inspect("network", spec["network"])
    volume = inspect("volume", spec["volume"])
    for kind, observed in (("container", container), ("network", network), ("volume", volume)):
        owned(observed, spec, kind)
    host = container["HostConfig"]
    if (
        container["Id"] != marker.get("container_id")
        or network["Id"] != marker.get("network_id")
        or volume["CreatedAt"] != marker.get("volume_created_at")
        or container["Config"]["Image"] != IMAGE
        or container["Config"]["User"] != "999:999"
        or network["Internal"]
        or network["Driver"] != "bridge"
        or not host["ReadonlyRootfs"]
        or host["Privileged"]
        or host["CapAdd"]
        or host["CapDrop"] != ["ALL"]
        or "no-new-privileges" not in host["SecurityOpt"]
        or host["Memory"] != 512 * 1024 * 1024
        or host["MemorySwap"] != host["Memory"]
        or host["NanoCpus"] != 1_000_000_000
        or host["PidsLimit"] != 64
        or host["PortBindings"]
        != {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(spec["port"])}]}
        or set(container["NetworkSettings"]["Networks"]) != {spec["network"]}
        or [
            (mount["Type"], mount.get("Name"), mount["Destination"])
            for mount in container["Mounts"]
        ]
        != [("volume", spec["volume"], MOUNT)]
    ):
        raise Rejected("storage_container_policy_changed")
    if (
        container["State"]["Running"]
        and container["NetworkSettings"]["Ports"] != host["PortBindings"]
    ):
        raise Rejected("storage_actual_port_binding_missing")
    return marker


def admin(name, statement, database=DATABASE, timeout=30):
    result = docker(
        [
            "exec",
            "--user",
            "999:999",
            "-i",
            name,
            "psql",
            "-X",
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
            "-h",
            "/tmp",
            "-U",
            "postgres",
            "-d",
            database,
        ],
        statement.encode(),
        timeout=timeout,
    )
    return result.stdout.decode().strip()


def migrate(name):
    admin(name, roles_sql(), "postgres")
    exists = admin(name, "SELECT 1 FROM pg_database WHERE datname = 'mlsecops';", "postgres")
    if exists != "1":
        admin(name, "CREATE DATABASE mlsecops OWNER ml_owner TEMPLATE template0;", "postgres")
    script = migration_sql()
    checksum = digest(script.encode())
    exists = admin(name, "SELECT to_regclass('ml.schema_migrations');")
    if not exists:
        admin(
            name,
            f"BEGIN;\n{script}\nINSERT INTO ml.schema_migrations VALUES ({SCHEMA_VERSION}, '{checksum}');\nCOMMIT;",
        )
    if (
        admin(name, "SELECT version || ':' || sha256 FROM ml.schema_migrations ORDER BY version;")
        != f"{SCHEMA_VERSION}:{checksum}"
    ):
        raise Rejected("storage_migration_history_mismatch")
    return {"version": SCHEMA_VERSION, "sha256": checksum}


def export_clients(state, port):
    for role in storage_pki.ROLES:
        directory = safe_child(state, f"storage-clients/{role}")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        files = {
            "ca.crt": bounded_read(safe_child(state, "storage-pki/ca.crt"), 4096),
            "client.crt": bounded_read(safe_child(state, f"storage-pki/ml_{role}.crt"), 4096),
            "client.key": bounded_read(safe_child(state, f"storage-pki/ml_{role}.key"), 4096),
        }
        files["connection.json"] = (
            canonical(
                {
                    "schema_version": 1,
                    "role": role,
                    "host": "127.0.0.1",
                    "port": port,
                    "certificates": {
                        name: digest(content)
                        for name, content in files.items()
                        if name.endswith(".crt")
                    },
                }
            )
            + b"\n"
        )
        for name, content in files.items():
            path = safe_child(directory, name)
            if path.exists():
                if bounded_read(path, 4096) != content:
                    raise Rejected("storage_client_changed_explicit_rotation_required")
            else:
                atomic_write(path, content)


def verify_configuration(state, name):
    _, files = specification(state, read_json(safe_child(state, "storage.json"))["port"])
    for filename, content in files.items():
        observed = (
            docker(["exec", "--user", "999:999", name, "sha256sum", f"{MOUNT}/tls/{filename}"])
            .stdout.decode()
            .split()[0]
        )
        if observed != digest(content):
            raise Rejected("storage_live_config_changed")
    observed = admin(
        name,
        "SELECT current_setting('server_version_num') || ':' || current_setting('data_checksums');",
    )
    if observed != "180006:on":
        raise Rejected("storage_server_version_or_checksums_invalid")
    if admin(name, "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL;") != "0":
        raise Rejected("storage_hba_invalid")


def bootstrap(state, port=15439):
    state = Path(state).resolve()
    if shutil.disk_usage(state).free < 8 * 1024**3:
        raise Rejected("storage_disk_headroom_insufficient")
    storage_pki.initialize(state)
    spec, files = specification(state, port)
    marker_path = safe_child(state, "storage.json")
    if marker_path.exists():
        marker = validate(state)
        if marker["port"] != port:
            raise Rejected("storage_port_change_requires_migration")
        docker(["start", spec["name"]])
    else:
        try:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", port))
        except OSError as error:
            raise Rejected("storage_loopback_port_unavailable") from error
        if any(
            inspect(kind, spec[key], required=False)
            for kind, key in (("container", "name"), ("volume", "volume"), ("network", "network"))
        ):
            raise Rejected("storage_partial_or_unowned_resources_require_recovery")
        docker(["pull", IMAGE], timeout=300)
        labels = [
            "--label",
            f"{WORKSPACE_LABEL}={spec['workspace_id']}",
            "--label",
            f"{CONFIG_LABEL}={spec['config_digest']}",
        ]
        docker(["volume", "create", *labels, spec["volume"]])
        docker(["network", "create", *labels, spec["network"]])
        mount = ["--mount", f"type=volume,source={spec['volume']},target={MOUNT}"]
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as output:
            for name, content in files.items():
                entry = tarfile.TarInfo(f"tls/{name}")
                entry.size, entry.mode, entry.uid, entry.gid = len(content), 0o600, 999, 999
                output.addfile(entry, io.BytesIO(content))
        docker(
            [
                "run",
                "--rm",
                "-i",
                "--network",
                "none",
                *LIMITS,
                "--cap-add",
                "CHOWN",
                *labels,
                *mount,
                "--entrypoint",
                "sh",
                IMAGE,
                "-eu",
                "-c",
                f"umask 077; mkdir -p {MOUNT}/18; tar --no-same-owner -xf - -C {MOUNT}; chown -R 999:999 {MOUNT}",
            ],
            archive.getvalue(),
        )
        docker(
            [
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "999:999",
                *LIMITS,
                *labels,
                *mount,
                "--entrypoint",
                "initdb",
                IMAGE,
                "-D",
                PGDATA,
                "--auth-local=peer",
                "--auth-host=reject",
                "--encoding=UTF8",
                "--locale=C.UTF-8",
                "--data-checksums",
            ],
            timeout=120,
        )
        docker(
            [
                "create",
                "--name",
                spec["name"],
                "--network",
                spec["network"],
                "--user",
                "999:999",
                *LIMITS,
                *labels,
                *mount,
                "--publish",
                f"127.0.0.1:{port}:5432",
                "--log-opt",
                "max-size=5m",
                "--log-opt",
                "max-file=2",
                "--entrypoint",
                "postgres",
                IMAGE,
                "-D",
                PGDATA,
                "-c",
                f"config_file={MOUNT}/tls/postgresql.conf",
            ]
        )
        marker = {
            **spec,
            "container_id": inspect("container", spec["name"])["Id"],
            "network_id": inspect("network", spec["network"])["Id"],
            "volume_created_at": inspect("volume", spec["volume"])["CreatedAt"],
        }
        write_json(marker_path, marker)
        docker(["start", spec["name"]])
    deadline = time.monotonic() + 30
    while True:
        try:
            if admin(spec["name"], "SELECT 1;", "postgres", timeout=5) == "1":
                break
        except Rejected:
            if time.monotonic() >= deadline:
                raise Rejected("storage_startup_deadline") from None
        time.sleep(0.25)
    migration = migrate(spec["name"])
    validate(state)
    verify_configuration(state, spec["name"])
    export_clients(state, port)
    from mlsecops.storage import connect

    with connect(safe_child(state, "storage-clients/ingestor")) as connection:
        if connection.execute("SELECT current_user;").fetchone() != ("ml_ingestor",):
            raise Rejected("storage_client_identity_mismatch")
    return {
        "observed_at": now(),
        "container_id": marker["container_id"],
        "image": IMAGE,
        "port": port,
        "migration": migration,
        "status": "ready",
        "scope": "storage-component",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--port", type=int, default=15439)
    arguments = parser.parse_args()
    try:
        result = bootstrap(arguments.state, arguments.port)
        write_json(arguments.state / "evidence/storage-bootstrap.json", result)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        print(f"Storage bootstrap rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
