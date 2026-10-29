"""External hosted fault coordinator; no authority rights enter serving Pods."""

from mlsecops import kube_storage, kube_trust, trust_authority
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, decode, digest
from mlsecops.kube_serving_lifecycle import FAULTS
from scripts.kube_trust_native import scale


def progress(raw, fault):
    if len(raw) > 65536 or fault not in FAULTS:
        raise Rejected("serving_fault_progress_bound")
    phases = []
    for line in raw.splitlines():
        value = decode(line, 65536)
        if not isinstance(value, dict):
            raise Rejected("serving_fault_progress_schema")
        if value.get("event") == "trust-fault":
            phase = value.get("phase")
            if value != {"event": "trust-fault", "phase": phase, "fault": fault}:
                raise Rejected("serving_fault_progress_binding")
            phases.append(phase)
            if phases != ["ready", "denied"][: len(phases)]:
                raise Rejected("serving_fault_progress_order")
        elif value.get("status") not in {"pass", "fail"}:
            raise Rejected("serving_fault_progress_schema")
    return phases


def acknowledge(state, pod, phase, fault):
    if phase not in {"ready", "denied"} or fault not in FAULTS:
        raise Rejected("serving_fault_ack_invalid")
    # The caller verifies the live owned Pod UID/spec/image immediately before
    # this operator action. Fixed synthetic control data only, never a key.
    program = (
        "import os,sys; from pathlib import Path; "
        f"p=Path('/tmp/mlsecops-trust-{phase}.json'); "
        "t=p.with_suffix('.pending'); f=t.open('xb'); "
        "f.write(sys.stdin.buffer.read(1024)); f.close(); os.rename(t,p)"
    )
    kubectl(
        state,
        ["exec", "-i", pod, "-n", "ml-serving", "-c", "worker", "--", "python", "-c", program],
        {"phase": phase, "fault": fault},
    )


class Coordinator:
    def __init__(self, state, fault, policy, key, model):
        if fault not in FAULTS:
            raise Rejected("serving_fault_kind")
        self.state, self.fault, self.policy, self.key, self.model = state, fault, policy, key, model
        self.marker = self.document = self.uid = None
        self.changed = False
        self.phases = []

    def __enter__(self):
        if self.fault == "outage":
            self.marker = kube_trust.validate(self.state)
            self.document = next(
                d for d in kube_trust.desired(self.state) if d["kind"] == "StatefulSet"
            )
            self.uid = self.marker["resources"][kube_storage.reference(self.document)]
        return self

    def __call__(self, phase):
        if [*self.phases, phase] != ["ready", "denied"][: len(self.phases) + 1]:
            raise Rejected("serving_fault_operator_order")
        if phase == "ready":
            if self.fault == "outage":
                self.changed = True
                scale(self.state, self.document, self.uid, 0)
                kubectl(
                    self.state,
                    [
                        "wait",
                        "--for=delete",
                        "pod/postgres-0",
                        "-n",
                        kube_trust.NAMESPACE,
                        "--timeout=60s",
                    ],
                    timeout=75,
                )
            elif self.fault == "policy-change":
                self.changed = True
                trust_authority.update(
                    self.state,
                    digest(b"controlled-policy-transition"),
                    self.key,
                    backend=kube_trust.binding,
                )
            else:
                trust_authority.update(
                    self.state,
                    self.policy,
                    self.key,
                    revoked_artifacts=[self.model],
                    backend=kube_trust.binding,
                )
        else:
            self.restore()
        self.phases.append(phase)

    def restore(self):
        if not self.changed:
            return
        if self.fault == "outage":
            observed = kube_storage.get(self.state, self.document)
            if (observed or {}).get("spec", {}).get("replicas") == 0:
                scale(self.state, self.document, self.uid, 1)
            kubectl(
                self.state,
                [
                    "rollout",
                    "status",
                    "statefulset/postgres",
                    "-n",
                    kube_trust.NAMESPACE,
                    "--timeout=180s",
                ],
                timeout=210,
            )
            restored = kube_trust.validate(self.state)
            if restored["volume_uid"] != self.marker["volume_uid"]:
                raise Rejected("serving_fault_authority_volume_changed")
        else:
            trust_authority.update(self.state, self.policy, self.key, backend=kube_trust.binding)
        self.changed = False

    def __exit__(self, *error):
        self.restore()
