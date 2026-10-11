import argparse
import io
import socket
import ssl
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, digest, now, read_json, write_json
from mlsecops.storage_bootstrap import admin, docker, inspect
from scripts.tracking_config import (
    CONFIG_LABEL,
    LABEL,
    PG_IMAGE,
    ROLES,
    configuration,
    initialize,
    validate,
)
from scripts.tracking_spike import inspect_image

PG_MOUNT = "/var/lib/postgresql"


def names(spec):
    prefix = "tml-track-" + spec["identity"][:12]
    return {
        key: prefix + "-" + key
        for key in ("pg", "server", "network", "edge", "data", "config", "artifacts")
    }


def labels(spec):
    return [
        "--label",
        LABEL + "=" + spec["identity"],
        "--label",
        CONFIG_LABEL + "=" + spec["config_digest"],
    ]


def limits(memory, pids, uid):
    return [
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--cpus",
        "1",
        "--memory",
        str(memory),
        "--memory-swap",
        str(memory),
        "--pids-limit",
        str(pids),
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size=128m,uid={uid},gid={uid},mode=700",
        "--log-opt",
        "max-size=2m",
        "--log-opt",
        "max-file=2",
    ]


def owned(observed, spec, kind):
    observed_labels = (
        observed["Config"].get("Labels", {}) if kind == "container" else observed.get("Labels", {})
    )
    if (
        observed_labels.get(LABEL) != spec["identity"]
        or observed_labels.get(CONFIG_LABEL) != spec["config_digest"]
    ):
        raise Rejected("tracking_service_foreign_resource:" + kind)


def mounts(spec, role):
    resources = names(spec)
    return (
        [(resources["data"], PG_MOUNT, True)]
        if role == "pg"
        else [(resources["config"], "/config", False), (resources["artifacts"], "/artifacts", True)]
    )


def verify(state, spec, *, require_current_certificates=True):
    validate(state, spec, require_current_certificates=require_current_certificates)
    resources = names(spec)
    receipt = read_json(state / "resources.json")
    for key in ("network", "edge"):
        network = inspect("network", resources[key])
        owned(network, spec, "network")
        if (
            network["Id"] != receipt[key]
            or network["Internal"] != (key == "network")
            or network["Driver"] != "bridge"
        ):
            raise Rejected("tracking_service_network_changed")
    for key in ("data", "config", "artifacts"):
        volume = inspect("volume", resources[key])
        owned(volume, spec, "volume")
        if (
            volume["CreatedAt"] != receipt[key]
            or volume["Driver"] != "local"
            or volume.get("Options")
        ):
            raise Rejected("tracking_service_volume_changed")
    observed = {}
    for role, uid, memory, pids in (
        ("pg", 999, 512 * 1024**2, 64),
        ("server", 65532, 2 * 1024**3, 128),
    ):
        current = inspect("container", resources[role])
        owned(current, spec, "container")
        host = current["HostConfig"]
        ports = (
            {}
            if role == "pg"
            else {"5000/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(spec["port"])}]}
        )
        if (
            current["Id"] != receipt[role]
            or current["Image"] != receipt[role + "_image"]
            or current["Config"]["Image"] != receipt[role + "_image"]
            or current["Config"]["User"] != f"{uid}:{uid}"
            or not host["ReadonlyRootfs"]
            or host["Privileged"]
            or host["CapAdd"]
            or host["CapDrop"] != ["ALL"]
            or "no-new-privileges" not in host["SecurityOpt"]
            or host["Memory"] != memory
            or host["MemorySwap"] != memory
            or host["PidsLimit"] != pids
            or host["NanoCpus"] != 1_000_000_000
            or host["PortBindings"] != ports
            or set(current["NetworkSettings"]["Networks"])
            != (
                {resources["network"]}
                if role == "pg"
                else {resources["network"], resources["edge"]}
            )
            or (
                role == "server"
                and current["State"]["Running"]
                and current["NetworkSettings"]["Ports"] != ports
            )
            or sorted(
                (mount["Name"], mount["Destination"], mount["RW"])
                for mount in current["Mounts"]
                if mount["Type"] == "volume"
            )
            != sorted(mounts(spec, role))
            or len(current["Mounts"]) != len(mounts(spec, role))
        ):
            raise Rejected("tracking_service_container_policy_changed:" + role)
        observed[role] = current
    return observed


def seed_volume(spec, volume, files, uid, image):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as output:
        for name, content in files.items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(content), 0o600
            output.addfile(entry, io.BytesIO(content))
    docker(
        [
            "run",
            "--rm",
            "-i",
            "--network",
            "none",
            *limits(256 * 1024**2, 32, 0),
            "--cap-add",
            "CHOWN",
            *labels(spec),
            "--mount",
            f"type=volume,source={volume},target=/seed",
            "--entrypoint",
            "sh",
            image,
            "-eu",
            "-c",
            f"umask 077; chmod 700 /seed; tar --no-same-owner -xf - -C /seed; chown -R {uid}:{uid} /seed",
        ],
        archive.getvalue(),
    )


def wait_postgres(name):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            if admin(name, "SELECT 1;", "postgres", timeout=5) == "1":
                return
        except Rejected:
            time.sleep(0.5)
    raise Rejected("tracking_postgres_not_ready")


def wait_https(state, spec):
    context = ssl.create_default_context(cafile=str(state / "ca.crt"))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
    )
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            with opener.open(f"https://127.0.0.1:{spec['port']}/health", timeout=2) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(0.5)
    raise Rejected("tracking_https_not_ready")


def up(root, state, port):
    spec = initialize(state, inspect_image(root), port)
    resources = names(spec)
    if (state / "resources.json").exists():
        verify(state, spec)
        docker(["start", resources["pg"]])
        wait_postgres(resources["pg"])
        docker(["start", resources["server"]])
    else:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
        for kind, key in (
            ("network", "network"),
            ("network", "edge"),
            *(("volume", key) for key in ("data", "config", "artifacts")),
            ("container", "pg"),
            ("container", "server"),
        ):
            if inspect(kind, resources[key], required=False):
                raise Rejected("tracking_partial_resources_require_recovery")
        if not inspect("image", PG_IMAGE, required=False):
            docker(["pull", PG_IMAGE], timeout=300)
        postgres = inspect("image", PG_IMAGE)
        if postgres["Os"] != "linux" or postgres["Architecture"] != "amd64":
            raise Rejected("tracking_postgres_platform_invalid")
        pg_image = postgres["Id"]
        docker(["network", "create", "--internal", *labels(spec), resources["network"]])
        docker(["network", "create", *labels(spec), resources["edge"]])
        for key in ("data", "config", "artifacts"):
            docker(["volume", "create", *labels(spec), resources[key]])
        files = configuration(state, spec)
        seed_volume(
            spec,
            resources["data"],
            {"config/" + name: content for name, content in files["postgres"].items()},
            999,
            pg_image,
        )
        seed_volume(spec, resources["config"], files["server"], 65532, pg_image)
        seed_volume(spec, resources["artifacts"], {}, 65532, pg_image)
        pg_mount = ["--mount", f"type=volume,source={resources['data']},target={PG_MOUNT}"]
        docker(
            [
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "999:999",
                *labels(spec),
                *limits(512 * 1024**2, 64, 999),
                *pg_mount,
                "--entrypoint",
                "initdb",
                pg_image,
                "-D",
                PG_MOUNT + "/18/docker",
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
                resources["pg"],
                "--network",
                resources["network"],
                "--network-alias",
                "tracking-pg",
                "--user",
                "999:999",
                *labels(spec),
                *limits(512 * 1024**2, 64, 999),
                *pg_mount,
                "--entrypoint",
                "postgres",
                pg_image,
                "-D",
                PG_MOUNT + "/18/docker",
                "-c",
                "config_file=" + PG_MOUNT + "/config/postgresql.conf",
            ]
        )
        docker(["start", resources["pg"]])
        wait_postgres(resources["pg"])
        for role in ROLES:
            admin(
                resources["pg"],
                f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION; CREATE DATABASE {role} OWNER {role} TEMPLATE template0;",
                "postgres",
            )
            admin(resources["pg"], f"REVOKE ALL ON DATABASE {role} FROM PUBLIC;", "postgres")
            admin(resources["pg"], "REVOKE ALL ON SCHEMA public FROM PUBLIC;", role)
        docker(
            [
                "create",
                "--name",
                resources["server"],
                "--network",
                resources["edge"],
                "--user",
                "65532:65532",
                *labels(spec),
                *limits(2 * 1024**3, 128, 65532),
                "--mount",
                f"type=volume,source={resources['config']},target=/config,readonly",
                "--mount",
                f"type=volume,source={resources['artifacts']},target=/artifacts",
                "--publish",
                f"127.0.0.1:{port}:5000",
                spec["image"],
                "/app/server.py",
            ]
        )
        docker(["network", "connect", resources["network"], resources["server"]])
        receipt = {
            "network": inspect("network", resources["network"])["Id"],
            "edge": inspect("network", resources["edge"])["Id"],
            "pg_image": pg_image,
            "server_image": spec["image"],
            **{key: inspect("container", resources[key])["Id"] for key in ("pg", "server")},
            **{
                key: inspect("volume", resources[key])["CreatedAt"]
                for key in ("data", "config", "artifacts")
            },
        }
        write_json(state / "resources.json", receipt)
        docker(["start", resources["server"]])
    wait_https(state, spec)
    verify(state, spec)
    for role, files in configuration(state, spec).items():
        container_role = "pg" if role == "postgres" else "server"
        prefix = PG_MOUNT + "/config" if role == "postgres" else "/config"
        for name, content in files.items():
            actual = (
                docker(["exec", resources[container_role], "sha256sum", prefix + "/" + name])
                .stdout.decode()
                .split()[0]
            )
            if actual != digest(content):
                raise Rejected("tracking_live_configuration_changed")
    return {
        "status": "pass",
        "scope": "persistent-local-tracking-bootstrap-not-M06",
        "release_ready": False,
        "endpoint": f"https://127.0.0.1:{port}",
        "identity": spec["identity"],
        "completed_at": now(),
        "image_id": spec["image"],
        "postgres_image": PG_IMAGE,
    }


def stop(state):
    spec = read_json(state / "configuration.json")
    observed = verify(state, spec, require_current_certificates=False)
    for role in ("server", "pg"):
        docker(["stop", "--time", "20", observed[role]["Id"]])
    if any(
        container["State"]["Running"]
        for container in verify(state, spec, require_current_certificates=False).values()
    ):
        raise Rejected("tracking_stop_incomplete")
    return {
        "status": "pass",
        "scope": "owned-containers-stopped-volumes-retained",
        "release_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Private persistent tracking lab; no release authority"
    )
    parser.add_argument("action", choices=("up", "status", "stop"))
    parser.add_argument("--port", type=int, default=15445)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    state = root / ".runtime/tracking-service"
    try:
        if arguments.action == "up":
            result = up(root, state, arguments.port)
        elif arguments.action == "stop":
            result = stop(state)
        else:
            observed = verify(state, read_json(state / "configuration.json"))
            result = {
                "status": "pass",
                "scope": "container-configuration-only",
                "running": {role: item["State"]["Running"] for role, item in observed.items()},
                "release_ready": False,
            }
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        print(
            canonical(
                {
                    "status": "inconclusive",
                    "release_ready": False,
                    "reason": str(error) if isinstance(error, Rejected) else type(error).__name__,
                }
            ).decode()
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
