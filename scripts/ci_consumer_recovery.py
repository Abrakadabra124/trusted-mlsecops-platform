"""Exact-ID consumer recovery shared by the live driver and its outer cleanup CLI."""

from mlsecops import cluster, storage_pki
from mlsecops import storage_bootstrap as sql
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.security_events import hexadecimal

DIRECTORY = "ci-consumer-native"
RECORD = DIRECTORY + "/recovery.json"
KUBE = DIRECTORY + "/kubeconfig"
KIND_LABEL = "io.x-k8s.kind.cluster"
CLEANUP_STAGES = {
    "sql": {"unavailable", "none", "baseline", "identity", "stop", "post_stop"},
    "cluster": {
        "unavailable",
        "none",
        "baseline",
        "identity",
        "volume_check",
        "delete",
        "volume_delete",
        "post_absence",
    },
}


def cleanup_diagnostics(value):
    value = value if isinstance(value, dict) else {}
    return {
        kind: code if type(code := value.get(kind)) is str and code in allowed else "unavailable"
        for kind, allowed in CLEANUP_STAGES.items()
    }


def need(value):
    if not value:
        raise Rejected("consumer_recovery_rejected")


def containers(*filters):
    args = ["ps", "--all", "--quiet", "--no-trunc"]
    for value in filters:
        args += ["--filter", value]
    ids = sql.docker(args).stdout.decode().splitlines()
    need(len(ids) == len(set(ids)))
    return {hexadecimal(handle): sql.inspect("container", handle) for handle in ids}


def cluster_inventory():
    rows = containers("label=" + KIND_LABEL + "=" + cluster.NAME)
    rows.update(containers("name=^/" + cluster.NODE + "$"))
    for row in rows.values():
        need(row["Name"] == "/" + cluster.NODE)
        need(row["Config"]["Labels"].get(KIND_LABEL) == cluster.NAME)
        need(row["Config"]["Labels"].get("io.x-k8s.kind.role") == "control-plane")
    need(len(rows) <= 1)
    return rows


def ordered_mounts(identities):
    # Order is not ownership. Keep every dictionary field and duplicate entry,
    # including in legacy witnesses, without rewriting the stored identities.
    return {
        handle: {**row, "mounts": sorted(row["mounts"], key=canonical)}
        for handle, row in identities.items()
    }


def identity(rows):
    return ordered_mounts(
        {
            handle: {
                "id": row["Id"],
                "name": row["Name"],
                "labels": row["Config"]["Labels"],
                "mounts": row["Mounts"],
            }
            for handle, row in rows.items()
        }
    )


def volumes():
    return set(sql.docker(["volume", "ls", "--quiet"]).stdout.decode().splitlines())


def volume_identity(name):
    row = sql.inspect("volume", name)
    return {key: row[key] for key in ("Name", "CreatedAt", "Driver", "Labels", "Options")}


def node_volumes(row):
    return {m["Name"] for m in row["Mounts"] if m["Type"] == "volume"}


def sql_inventory(spec):
    rows = containers("label=" + sql.WORKSPACE_LABEL + "=" + spec["workspace_id"])
    rows.update(containers("name=^/" + spec["name"] + "$"))
    for row in rows.values():
        sql.owned(row, spec, "container")
    return rows


class Recovery:
    def __init__(self, producer):
        self.producer = producer
        self.path = safe_child(producer, RECORD)
        self.record = read_json(self.path)
        need(self.record["workspace_id"] == storage_pki.workspace_id(producer))

    @classmethod
    def begin(cls, producer, run_owner, source):
        need(not cluster_inventory())
        need(cluster.NAME not in cluster.command(["kind", "get", "clusters"]).splitlines())
        directory = safe_child(producer, DIRECTORY)
        directory.mkdir(mode=0o700, exist_ok=False)
        write_json(
            directory / "recovery.json",
            dict(
                schema_version=1,
                workspace_id=storage_pki.workspace_id(producer),
                run_owner=run_owner,
                source=source,
                baseline_empty=True,
                sql=None,
                cluster=None,
                cleanup={"sql": False, "cluster": False},
            ),
        )
        return cls(producer)

    def save(self):
        write_json(self.path, self.record)
        need(read_json(self.path) == self.record)

    def arm_sql(self, state):
        need(self.record["sql"] is None)
        need(not (state / "storage.json").exists())
        storage_pki.initialize(state)
        spec, _ = sql.specification(state, 15440)
        need(spec["workspace_id"] != self.record["workspace_id"])
        need(not sql_inventory(spec))
        for kind in ("volume", "network"):
            result = sql.docker([kind, "ls", "--quiet", "--filter", "name=" + spec[kind]])
            need(not result.stdout.strip())
        self.record["sql"] = dict(spec=spec, observed=False, containers={})
        self.save()

    def observe_sql(self):
        entry = self.record["sql"]
        rows = sql_inventory(entry["spec"])
        entry.update(containers=identity(rows), observed=True)
        self.save()

    def arm_cluster(self):
        need(self.record["cluster"] is None and not cluster_inventory())
        self.record["cluster"] = dict(
            observed=False, containers={}, volumes={}, volume_baseline=sorted(volumes())
        )
        self.save()

    def observe_cluster(self, state):
        rows = cluster_inventory()
        entry = self.record["cluster"]
        owned_volumes = {}
        for handle, row in rows.items():
            for name in node_volumes(row):
                need(name not in entry["volume_baseline"])
                need(set(containers("volume=" + name)) == {handle})
                owned_volumes[name] = dict(container=handle, identity=volume_identity(name))
        entry.update(containers=identity(rows), volumes=owned_volumes, observed=True)
        self.save()
        # Copy before the file materializer exits, even when bootstrap failed.
        path = safe_child(state, "kubeconfig")
        if path.exists():
            atomic_write(safe_child(self.producer, KUBE), bounded_read(path, 1024 * 1024))

    def stop_sql(self):
        self._cleanup_stage = "baseline"
        need(self.record["baseline_empty"] is True)
        entry = self.record["sql"]
        if entry is None:  # No SQL creation was armed by this invocation.
            return
        self._cleanup_stage = "identity"
        need(entry["observed"] is True)
        rows = sql_inventory(entry["spec"])
        expected = ordered_mounts(entry["containers"])
        need(identity(rows) == expected)
        failures = []
        for handle, row in rows.items():
            try:
                if row["State"]["Running"]:
                    self._cleanup_stage = "stop"
                    sql.docker(["stop", "--time", "20", handle])
                self._cleanup_stage = "identity"
                current = sql.inspect("container", handle)
                need(identity({handle: current}) == {handle: expected[handle]})
                self._cleanup_stage = "post_stop"
                need(current["State"]["Running"] is False)
            except Exception:
                failures.append(self._cleanup_stage)
        if failures:
            self._cleanup_stage = failures[0]
        need(not failures)
        self._cleanup_stage = "identity"
        final = sql_inventory(entry["spec"])
        need(identity(final) == expected)
        self._cleanup_stage = "post_stop"
        need(all(row["State"]["Running"] is False for row in final.values()))

    def delete_cluster(self):
        self._cleanup_stage = "baseline"
        need(self.record["baseline_empty"] is True)
        entry = self.record["cluster"]
        self._cleanup_stage = "identity"
        rows = cluster_inventory()
        if entry is None:
            need(not rows)
        else:
            need(entry["observed"] is True)
            # A recorded live ID must not disappear merely by changing its name/labels.
            rows.update({k: v for k, v in containers().items() if k in entry["containers"]})
            observed = identity(rows)
            expected = ordered_mounts(entry["containers"])
            need(all(expected.get(k) == v for k, v in observed.items()))
            self._cleanup_stage = "volume_check"
            present = volumes()
            for row in rows.values():
                need(node_volumes(row) <= present)
            for name, volume in entry["volumes"].items():
                if name in present:
                    need(volume_identity(name) == volume["identity"])
                    users = {volume["container"]} if volume["container"] in rows else set()
                    need(set(containers("volume=" + name)) == users)
            self._cleanup_stage = "delete"
            for handle in rows:
                # Never kind delete --name: deletion addresses only recorded Docker IDs.
                sql.docker(["rm", "--force", handle])
            self._cleanup_stage = "post_absence"
            need(not cluster_inventory())
            need(not (containers().keys() & entry["containers"].keys()))
            for name, volume in entry["volumes"].items():
                self._cleanup_stage = "volume_check"
                if name in volumes():
                    need(volume_identity(name) == volume["identity"])
                    need(not containers("volume=" + name))
                    self._cleanup_stage = "volume_delete"
                    sql.docker(["volume", "rm", name])
            self._cleanup_stage = "post_absence"
            need(not (volumes() & entry["volumes"].keys()))
        self._cleanup_stage = "post_absence"
        need(cluster.NAME not in cluster.command(["kind", "get", "clusters"]).splitlines())

    def cleanup(self):
        result = {"sql": False, "cluster": False}
        diagnostics = {}
        for kind, action in (("sql", self.stop_sql), ("cluster", self.delete_cluster)):
            self._cleanup_stage = "unavailable"
            try:
                action()
                result[kind] = True
                diagnostics[kind] = "none"
            except Exception:
                # A failed side must never prevent attempting the other side.
                diagnostics[kind] = self._cleanup_stage
        self.record["cleanup"] = result
        self.record["cleanup_diagnostics"] = cleanup_diagnostics(diagnostics)
        self.save()
        return result
