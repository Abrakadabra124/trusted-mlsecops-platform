import copy
import errno
import io
from pathlib import Path
from unittest.mock import patch

from mlsecops import boundary_probe
from mlsecops.contracts import Rejected, canonical


def qualify():
    cases = []

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"boundary_probe_contract_failed:{name}")
        cases.append({"id": name, "status": "pass"})

    def rejected(name, operation):
        try:
            operation()
        except Rejected:
            confirmed(name, True)
        else:
            confirmed(name, False)

    for number, expected in (
        (errno.ENOENT, "ENOENT"),
        (errno.EACCES, "EACCES"),
        (errno.EPERM, "EPERM"),
        (errno.EIO, "unexpected-error"),
    ):
        with patch.object(Path, "open", side_effect=OSError(number, "private diagnostic")):
            confirmed(f"read-errno:{number}", boundary_probe.read_attempt("/probe") == expected)
    with patch.object(Path, "open", return_value=io.BytesIO(b"private-canary")):
        confirmed("readable-is-not-denied", boundary_probe.read_attempt("/probe") == "readable")
    with patch.object(Path, "open", return_value=io.BytesIO()):
        confirmed(
            "empty-readable-is-not-denied", boundary_probe.read_attempt("/probe") == "readable"
        )
    for value in (True, 0, 1, -1, "123", 2**31):
        rejected(f"invalid-node-pid:{value!r}", lambda value=value: boundary_probe.paths(value))
    paths = boundary_probe.paths(54321)
    confirmed("unique-paths", len(paths) == len(set(paths)))
    confirmed(
        "modern-credentials-and-proc",
        all(
            path in paths
            for path in (
                "/api/token",
                "/client/client.key",
                "/signer/key.pem",
                "/proc/54321/mem",
                "/proc/54321/environ",
                "/proc/54321/cmdline",
                "/proc/54321/root/signer/key.pem",
                "/proc/54321/root/tmp/boundary-labels.json",
            )
        ),
    )
    for address, port in (
        ("example.com", 443),
        ("127.0.0.1", 443),
        ("10.78.0.2", 443),
        ("10.79.0.2", 22),
        ("10.79.0.2", True),
        ("::1", 5432),
    ):
        with patch("socket.create_connection") as connection:
            rejected(
                f"invalid-target:{address}:{port}", lambda: boundary_probe.network(address, port)
            )
            confirmed(f"no-connect:{address}:{port}", not connection.called)
    with patch("socket.create_connection") as connection:
        confirmed(
            "connected-is-not-denied", boundary_probe.network("10.79.0.1", 443) == "connected"
        )
        confirmed("bounded-connect", connection.call_args.kwargs == {"timeout": 3})
    with patch("socket.create_connection", side_effect=TimeoutError):
        confirmed("timeout", boundary_probe.network("10.79.0.2", 5432) == "timeout")
    with patch("socket.create_connection", side_effect=ConnectionRefusedError):
        confirmed(
            "refused-is-not-denied", boundary_probe.network("10.79.0.2", 5432) == "unexpected-error"
        )
    from mlsecops.boundary_qualification import isolated_spec, node_process
    from mlsecops.kube_worker import pod_spec

    expected = pod_spec("pinned", "evaluator", ["probe"], memory="256Mi")
    observed = {"spec": copy.deepcopy(expected)}
    confirmed("observed-isolation-positive", isolated_spec(expected, observed))
    for field in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"):
        invalid = copy.deepcopy(observed)
        invalid["spec"][field] = True
        confirmed(f"observed-isolation-denied:{field}", not isolated_spec(expected, invalid))
    for field in ("initContainers", "ephemeralContainers"):
        invalid = copy.deepcopy(observed)
        invalid["spec"][field] = [{"name": "extra"}]
        confirmed(f"observed-extra-container-denied:{field}", not isolated_spec(expected, invalid))
    pod = {
        "metadata": {"uid": "owned-pod"},
        "status": {
            "containerStatuses": [
                {
                    "state": {"running": {"startedAt": "now"}},
                    "containerID": "containerd://" + "a" * 64,
                }
            ]
        },
    }
    inspected = {
        "status": {
            "state": "CONTAINER_RUNNING",
            "metadata": {"name": "worker"},
            "labels": {
                "io.kubernetes.pod.uid": "owned-pod",
                "io.kubernetes.pod.namespace": "ml-scorer",
            },
        },
        "info": {"pid": 54321},
    }
    with patch(
        "mlsecops.boundary_qualification.command", side_effect=[canonical(inspected), "pid:[123]"]
    ):
        confirmed("observed-node-pid-positive", node_process(pod)["node_pid"] == 54321)
    for name, keys, value in (
        ("wrong-pod", ("status", "labels", "io.kubernetes.pod.uid"), "another-pod"),
        ("wrong-namespace", ("status", "labels", "io.kubernetes.pod.namespace"), "ml-eval"),
        ("not-running", ("status", "state"), "CONTAINER_EXITED"),
        ("wrong-container", ("status", "metadata", "name"), "another-container"),
        ("invalid-pid", ("info", "pid"), True),
    ):
        invalid = copy.deepcopy(inspected)
        target = invalid
        for key in keys[:-1]:
            target = target[key]
        target[keys[-1]] = value
        with patch("mlsecops.boundary_qualification.command", return_value=canonical(invalid)):
            rejected(f"observed-node-pid-denied:{name}", lambda: node_process(pod))
    return {
        "status": "pass",
        "scope": "boundary-probe-unit-only",
        "checks": len(cases),
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
