"""Private fixed-phase consumer ownership; unchanged exact-ID Recovery primitives."""

import re
from pathlib import Path

from mlsecops import (
    ci_transfer,
    cluster,
    kube_storage,
    release_policy,
    storage_bootstrap,
    storage_pki,
)
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.security_events import hexadecimal
from scripts import ci_consumer_recovery as recovery
from scripts import serving_campaign as campaign
from scripts.serving_retention import live_source

DIRECTORY = "ci-serving-recovery"
PHASES = ("M13", "M14", "M15")
NAMES = ("SQL", *PHASES)
STATES = {"unused", "starting", "active", "retiring", "retired"}


def need(value):
    if not value:
        raise Rejected("ci_serving_recovery_rejected")


def binding(run_owner, source):
    require_fields(run_owner, ("repository", "run_id", "run_attempt", "producer_job"))
    require_fields(source, campaign.delivery.SOURCE)
    need(run_owner["repository"] == ci_transfer.REPOSITORY)
    for field in ("run_id", "run_attempt"):
        release_policy.integer(run_owner[field])
    need(
        type(run_owner["producer_job"]) is str
        and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", run_owner["producer_job"]) is not None
    )
    hexadecimal(source["source_revision"], 40)
    hexadecimal(source["source_fingerprint"])
    need(type(source["image_id"]) is str and source["image_id"].startswith("sha256:"))
    hexadecimal(source["image_id"][7:])
    return decode(canonical(dict(run_owner=run_owner, source=source)))


class Lifecycle:
    @classmethod
    def begin(cls, producer, state, *, run_owner, source):
        producer, state = Path(producer).resolve(), Path(state).resolve()
        owner = binding(run_owner, source)
        directory = safe_child(producer, DIRECTORY)
        need(not directory.is_relative_to(state) and not state.is_relative_to(directory))
        identity = storage_pki.workspace_id(state)
        need(identity != storage_pki.workspace_id(producer))
        directory.mkdir(mode=0o700, exist_ok=False)
        original = bounded_read(safe_child(producer, "workspace.json"))
        consumer = bounded_read(safe_child(state, "workspace.json"))
        atomic_write(directory / "workspace.json", original)
        atomic_write(directory / "consumer-workspace.json", consumer)
        for name in NAMES:
            path = safe_child(directory, name)
            path.mkdir(mode=0o700)
            atomic_write(path / "workspace.json", original if name == "SQL" else consumer)
            recovery.Recovery.begin(path, **owner)
        write_json(
            directory / "lifecycle.json",
            dict(
                schema_version=1,
                **owner,
                consumer_path=str(state),
                consumer_workspace_id=identity,
                source_sql=None,
                sql="unused",
                phases=dict.fromkeys(PHASES, "unused"),
                pending=None,
                closed=False,
                cleanup=None,
            ),
        )
        return cls.load(producer, **owner)

    @classmethod
    def load(cls, producer, *, run_owner, source):
        result = cls()
        result.producer = Path(producer).resolve()
        result.directory = safe_child(result.producer, DIRECTORY)
        result.owner = binding(run_owner, source)
        result._reload()
        return result

    def _reload(self):
        names = {p.name for p in self.directory.iterdir()}
        required = {"workspace.json", "consumer-workspace.json", "lifecycle.json"}
        need(required <= names <= required | set(NAMES))
        need(
            bounded_read(safe_child(self.directory, "workspace.json"))
            == bounded_read(safe_child(self.producer, "workspace.json"))
        )
        record = read_json(safe_child(self.directory, "lifecycle.json"))
        require_fields(
            record,
            (
                "schema_version",
                "run_owner",
                "source",
                "consumer_path",
                "consumer_workspace_id",
                "source_sql",
                "sql",
                "phases",
                "pending",
                "closed",
                "cleanup",
            ),
        )
        need(type(record["schema_version"]) is int and record["schema_version"] == 1)
        need(canonical({k: record[k] for k in self.owner}) == canonical(self.owner))
        need(type(record["closed"]) is bool and record["sql"] in {"unused", "starting", "ready"})
        require_fields(record["phases"], PHASES)
        need(all(value in STATES for value in record["phases"].values()))
        need(record["pending"] in (None, ["M13", "M14"], ["M14", "M15"]))
        consumer = decode(bounded_read(safe_child(self.directory, "consumer-workspace.json")))
        need(consumer["workspace_id"] == hexadecimal(record["consumer_workspace_id"], 32))
        self.record = record

    def _save(self):
        path = safe_child(self.directory, "lifecycle.json")
        write_json(path, self.record)
        need(canonical(read_json(path)) == canonical(self.record))

    def _state(self, state):
        state = Path(state).resolve()
        need(str(state) == self.record["consumer_path"])
        need(
            bounded_read(safe_child(state, "workspace.json"))
            == bounded_read(safe_child(self.directory, "consumer-workspace.json"))
        )
        return state

    def _witness(self, name):
        need(name in NAMES)
        path = safe_child(self.directory, name)
        need({p.name for p in path.iterdir()} == {"workspace.json", recovery.DIRECTORY})
        need({p.name for p in safe_child(path, recovery.DIRECTORY).iterdir()} == {"recovery.json"})
        expected = "workspace.json" if name == "SQL" else "consumer-workspace.json"
        need(
            bounded_read(safe_child(path, "workspace.json"))
            == bounded_read(safe_child(self.directory, expected))
        )
        witness = recovery.Recovery(path)
        need(canonical({k: witness.record[k] for k in self.owner}) == canonical(self.owner))
        need(witness.record["cluster" if name == "SQL" else "sql"] is None)
        return witness

    def _open(self):
        self._reload()
        need(self.record["closed"] is False and self.record["pending"] is None)
        for name in NAMES:
            self._witness(name)

    def _live_sql(self, state, source_pin):
        state = self._state(state)
        need(source_pin == self.record["source_sql"])
        live_source(state, source_pin)
        entry = self._witness("SQL").record["sql"]
        need(entry is not None and entry["observed"] is True)
        need(entry["spec"]["workspace_id"] == self.record["consumer_workspace_id"])
        rows = recovery.sql_inventory(entry["spec"])
        need(recovery.identity(rows) == recovery.ordered_mounts(entry["containers"]))
        marker = campaign.delivery.pinned(state / "storage.json", source_pin)
        need(
            list(rows) == [marker["container_id"]]
            and marker["workspace_id"] == self.record["consumer_workspace_id"]
        )

    def bootstrap_sql(self, state):
        self._open()
        state = self._state(state)
        need(self.record["sql"] == "unused")
        # PKI is caller-prepared: arm_sql revalidates it, never generates new keys here.
        storage_pki.validate(state)
        self.record["sql"] = "starting"
        self._save()
        witness = self._witness("SQL")
        witness.arm_sql(state)
        try:
            storage_bootstrap.bootstrap(state, port=15440)
        finally:
            witness.observe_sql()
        pin = digest(bounded_read(safe_child(state, "storage.json")))
        self.record["source_sql"] = pin
        self._live_sql(state, pin)
        self.record["sql"] = "ready"
        self._save()
        self._live_sql(state, pin)
        return pin

    def _bootstrap_cluster(self, state, phase, source_pin):
        self._live_sql(state, source_pin)
        need(self.record["phases"][phase] == "unused")
        self.record["phases"][phase] = "starting"
        self._save()
        witness = self._witness(phase)
        witness.arm_cluster()
        try:
            cluster.bootstrap(state)
        finally:
            # Docker observation needs no consumer config; retain no credentials.
            witness.observe_cluster(witness.producer)

    def start(self, state, source_pin):
        self._open()
        state = self._state(state)
        need(
            self.record["sql"] == "ready"
            and all(v == "unused" for v in self.record["phases"].values())
        )
        self._bootstrap_cluster(state, "M13", source_pin)
        kube_storage.bootstrap(state)
        self._live_sql(state, source_pin)
        self.record["phases"]["M13"] = "active"
        self._save()

    def _retire(self, state, phase, source_pin):
        self._live_sql(state, source_pin)
        self.record["phases"][phase] = "retiring"
        self._save()
        self._witness(phase).delete_cluster()
        self._live_sql(state, source_pin)
        self.record["phases"][phase] = "retired"
        self._save()

    def transition(self, state, phase, source_pin):
        self._open()
        state = self._state(state)
        need(phase in PHASES[:-1])
        offset = PHASES.index(phase)
        successor = PHASES[offset + 1]
        need(self.record["phases"][phase] == "active")
        need(all(self.record["phases"][g] == "retired" for g in PHASES[:offset]))
        need(all(self.record["phases"][g] == "unused" for g in PHASES[offset + 1 :]))
        self._live_sql(state, source_pin)
        self.record["pending"] = [phase, successor]
        self._save()
        archive = safe_child(state, "ci-serving-retired")
        archive.mkdir(mode=0o700, exist_ok=True)
        packet = campaign.transition(
            state,
            safe_child(archive, phase),
            source_pin,
            delete=lambda: self._retire(state, phase, source_pin),
            bootstrap=lambda: self._bootstrap_cluster(state, successor, source_pin),
        )
        self._live_sql(state, source_pin)
        self.record["phases"][successor] = "active"
        self.record["pending"] = None
        self._save()
        return packet

    def cleanup(self):
        self._reload()
        result = dict.fromkeys((*reversed(PHASES), "SQL"), False)
        unarmed = []
        for name in reversed(PHASES):
            try:
                witness = self._witness(name)
                if witness.record["cluster"] is None:
                    unarmed.append((name, witness))
                else:
                    witness.delete_cluster()
                    result[name] = True
            except Exception:
                pass
        # Empty-phase witnesses must check absence after the active phase retires.
        for name, witness in unarmed:
            try:
                witness.delete_cluster()
                result[name] = True
            except Exception:
                pass
        try:
            self._witness("SQL").stop_sql()
            result["SQL"] = True
        except Exception:
            pass
        self.record["closed"] = True
        self.record["cleanup"] = result
        self._save()
        return result
