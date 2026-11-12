"""Hosted-only audit proof using real Pods, mTLS, persistent journals and network denial."""

import time
import uuid
from contextlib import contextmanager

from mlsecops import kube_promotion, kube_security_events, kube_storage
from mlsecops import kube_security_resources as resources
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, canonical, decode
from mlsecops.kube_worker import job_document, pod_spec, verify_running_image, wait_job
from mlsecops.storage_pki import workspace_id
from scripts.kube_promotion_snapshot import read as ledger
from scripts.kube_trust_native import hosted

HEALTH = """
import time
from mlsecops import security_event_admission as admission
from mlsecops.contracts import Rejected, canonical
from mlsecops.process_privacy import enforce
enforce()
deadline = time.monotonic() + 40
while True:
    try:
        admission.Configured('/security/audit.json').check('a' * 64)
        healthy = True
    except Rejected:
        healthy = False
    if healthy is EXPECTED:
        print(canonical({'healthy': healthy, 'release_ready': False}).decode())
        break
    if time.monotonic() >= deadline:
        raise SystemExit(1)
    time.sleep(0.5)
"""
READ = """
import os, time
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.process_privacy import enforce
enforce()
SETUP
deadline = time.monotonic() + 3
while True:
    try:
        document = store.snapshot()
        break
    except Rejected as error:
        if str(error) not in ('artifact_unavailable', 'security_store_unavailable', 'security_store_busy') or time.monotonic() >= deadline:
            raise
        time.sleep(0.03)
if len(document['records']) > 32:
    raise SystemExit(1)
records = []
for item in document['records']:
    observed = item.get('ingested_at_ms', item.get('queued_at_ms'))
    event = store.registry.verify(item['envelope'], clock_ms=observed)
    records.append({'id': event.document()['event_id'], 'kind': event.document()['kind'],
                    'envelope': digest(canonical(item['envelope'])),
                    'receipt': None if item['receipt'] is None else digest(canonical(item['receipt']))})
heartbeats = {}
for stream in document.get('telemetry', {}).get('streams', []):
    heartbeat = stream['heartbeat']
    if heartbeat is not None:
        value = store.registry.heartbeat(heartbeat['envelope'], clock_ms=heartbeat['ingested_at_ms'])
        heartbeats[store.registry.producer(stream['producer_id']).role] = value['sequence']
permissions = {name: oct(os.stat(os.path.join(store.root, name)).st_mode & 0o777) for name in ('identity', 'state')}
permissions['directory'] = oct(os.stat(store.root).st_mode & 0o777)
print(canonical({'pin': store.pin, 'records': records, 'heartbeats': heartbeats, 'permissions': permissions}).decode())
"""
COLLECTOR = READ.replace(
    "SETUP",
    "from mlsecops.security_event_server import configured\nstore = configured('/security/collector.json')[0].collector.store",
)
PROMOTER = READ.replace(
    "SETUP",
    "from mlsecops.security_event_admission import emitter\nstore = emitter('/security/audit.json').store",
)
SERVING = READ.replace(
    "SETUP",
    "from mlsecops.security_event_delivery import configured\n"
    "store = configured('/security/producer.json').store\n"
    "if store.registry.producer(store.producer_id).role != 'serving':\n"
    "    raise SystemExit(1)",
)


def job(state, profile, code, *, worker=False, serving=False):
    hosted()
    if type(worker) is not bool or type(serving) is not bool or worker and serving:
        raise Rejected("audit_native_role_conflict")
    namespace, account = (
        ("ml-train", "trainer")
        if worker
        else ("ml-serving", "serving")
        if serving
        else ("ml-promoter", "promoter")
    )
    spec = pod_spec(profile["image"], account, [], memory="256Mi")
    spec["containers"][0]["command"] = ["python", "-c", code]
    if serving:
        spec = resources.serving_spec(spec)
    elif not worker:
        spec = resources.promoter_spec(spec)
    name = "audit-proof-" + uuid.uuid4().hex
    document = job_document(name, namespace, spec, 90)
    document["metadata"]["labels"][resources.WORKSPACE] = workspace_id(state)
    created = []
    try:
        observed = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
        created.append((document, observed["metadata"]["uid"]))
        kube_storage.verify_resource(document, observed, created[0][1])
        terminal, pod, _ = wait_job(state, namespace, name, 90)
        kube_security_events.pod_spec(spec, pod["spec"])
        verify_running_image(pod, profile["image_id"])
        statuses = pod.get("status", {}).get("containerStatuses", [])
        code = (
            statuses[0].get("state", {}).get("terminated", {}).get("exitCode")
            if len(statuses) == 1
            else None
        )
        if (
            terminal["type"] != "Complete"
            or type(code) is not int
            or code != 0
            or pod["metadata"]["ownerReferences"][0]["uid"] != created[0][1]
        ):
            raise Rejected("audit_native_job_failed")
        content = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-n",
                namespace,
                "-c",
                "worker",
                "--limit-bytes=65537",
            ],
        ).stdout
        return decode(content, 65536)
    finally:
        kube_promotion.cleanup(state, created, namespace=namespace)


def health(state, profile, expected=True):
    if job(state, profile, HEALTH.replace("EXPECTED", repr(expected))) != {
        "healthy": expected,
        "release_ready": False,
    }:
        raise Rejected("audit_native_health_receipt")


def collector(state, marker):
    document = resources.deployment(marker["workspace_id"], marker["profile"]["image"], "collector")
    uid = kube_security_events.live(state, document, marker)
    pods = decode(
        kubectl(
            state, ["get", "pods", "-n", resources.NAMESPACE, "-l", "app=collector", "-o", "json"]
        ).stdout
    )["items"]
    if len(pods) != 1 or pods[0]["metadata"]["uid"] != uid:
        raise Rejected("audit_native_collector_changed")
    content = kubectl(
        state,
        [
            "exec",
            pods[0]["metadata"]["name"],
            "-n",
            resources.NAMESPACE,
            "-c",
            "worker",
            "--",
            "python",
            "-c",
            COLLECTOR,
        ],
    ).stdout
    return decode(content, 65536)


@contextmanager
def outage(state, workspace):
    document = resources.resource(
        "CiliumNetworkPolicy",
        "audit-outage-" + uuid.uuid4().hex,
        workspace,
        resources.NAMESPACE,
        spec={
            "endpointSelector": {"matchLabels": {resources.ACCOUNT: "collector"}},
            "ingressDeny": [{"fromEntities": ["all"]}],
        },
    )
    created = []
    try:
        observed = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
        created.append((document, observed["metadata"]["uid"]))
        kube_storage.verify_resource(document, observed, created[0][1])
        yield
    finally:
        kube_promotion.cleanup(state, created, namespace=resources.NAMESPACE)


def restart(state, marker, role):
    document = kube_security_events.runtime(marker, role)
    before = kube_security_events.live(state, document, marker)
    kube_storage.verify_resource(
        document,
        kube_storage.get(state, document),
        marker["resources"][kube_storage.reference(document)],
    )
    args = ["deployment/" + document["metadata"]["name"], "-n", document["metadata"]["namespace"]]
    kubectl(state, ["rollout", "restart", *args])
    kubectl(state, ["rollout", "status", *args, "--timeout=180s"], timeout=210)
    after = kube_security_events.live(state, document, marker)
    if after == before:
        raise Rejected("audit_native_pod_not_replaced")
    kube_security_events.validate(state, profile=marker["profile"])
    return {"before": before, "after": after}


def identity_receipts(before, after, inbox):
    previous = before["records"]
    records = after["records"]
    added = records[len(previous) :]
    added_ids = {r["id"] for r in added}
    received = {r["id"]: r for r in inbox["records"]}
    if (
        before["pin"] != after["pin"]
        or records[: len(previous)] != previous
        or not added
        or len(added_ids) != len(added)
        or added_ids.intersection(r["id"] for r in previous)
        or len(received) != len(inbox["records"])
        or any(
            r["kind"] != "identity.denied" or r["receipt"] is None or received.get(r["id"]) != r
            for r in added
        )
    ):
        raise Rejected("audit_native_http_receipt")
    return len(added)


def qualify(root, state, config, request, image):
    hosted()
    marker = kube_security_events.validate(state)
    profile = marker["profile"]
    cases = []

    def confirmed(name, condition):
        if not condition:
            print(canonical({"case": name, "status": "fail"}).decode(), flush=True)
            raise Rejected("audit_native_case:" + name)
        cases.append(name)
        print(canonical({"case": name, "status": "pass"}).decode(), flush=True)

    health(state, profile)
    confirmed("fresh-signed-audit-over-kubernetes-mtls", True)
    serving = job(state, profile, SERVING, serving=True)
    confirmed(
        "serving-outbox-is-distinct-from-trust-observer",
        serving["pin"] == marker["pins"]["serving"]
        and marker["pins"]["serving"] != marker["pins"]["trust"]
        and marker["volumes"]["serving"] != marker["volumes"]["trust"]
        and serving["records"] == [],
    )
    replacement = job(state, profile, SERVING, serving=True)
    confirmed(
        "serving-probe-replacement-retains-private-outbox",
        replacement == serving
        and serving["permissions"] == {"directory": "0o700", "identity": "0o600", "state": "0o600"},
    )
    worker = """
import os, socket
from mlsecops.contracts import canonical
if os.path.exists('/security') or os.path.exists('/audit'):
    raise SystemExit(1)
try:
    with socket.create_connection((ADDRESS, 8443), timeout=2):
        raise SystemExit(1)
except OSError:
    print(canonical({'audit_mounts': False, 'tcp_access': False}).decode())
""".replace("ADDRESS", repr(marker["address"]))
    confirmed(
        "worker-has-no-audit-mounts-or-network",
        job(state, profile, worker, worker=True) == {"audit_mounts": False, "tcp_access": False},
    )
    before = ledger(state)
    with outage(state, marker["workspace_id"]):
        health(state, profile, False)
        refused = kube_promotion.invoke(root, state, config, request, image)
        confirmed(
            "actual-promoter-refuses-on-collector-network-outage", refused["status"] == "rejected"
        )
        confirmed("audit-outage-does-not-change-model-or-promotion-ledger", ledger(state) == before)
        pending = job(state, profile, PROMOTER)
        unconfirmed = {r["id"]: r for r in pending["records"] if r["receipt"] is None}
        confirmed("actual-denial-remains-in-durable-outbox", bool(unconfirmed))
    health(state, profile)
    recovered = job(state, profile, PROMOTER)
    recovered_records = {r["id"]: r for r in recovered["records"]}
    confirmed(
        "original-pending-events-recover-with-signed-receipts",
        all(
            r["id"] in recovered_records
            and recovered_records[r["id"]]["envelope"] == r["envelope"]
            and recovered_records[r["id"]]["receipt"] is not None
            for r in unconfirmed.values()
        ),
    )
    inbox = collector(state, marker)
    accepted = {r["id"]: r for r in inbox["records"]}
    confirmed(
        "independent-collector-readback-matches-promoter",
        all(accepted.get(key) == recovered_records[key] for key in unconfirmed),
    )
    replacement = restart(state, marker, "collector")
    health(state, profile)
    restarted = collector(state, marker)
    current = {r["id"]: r for r in restarted["records"]}
    confirmed(
        "collector-pod-replacement-keeps-identity-and-receipts",
        restarted["pin"] == inbox["pin"]
        and all(current.get(key) == value for key, value in accepted.items()),
    )
    confirmed(
        "persistent-state-remains-private-after-pod-replacement",
        restarted["permissions"]
        == recovered["permissions"]
        == {"directory": "0o700", "identity": "0o600", "state": "0o600"},
    )
    old_sequence = restarted["heartbeats"].get("trust", 0)
    observer = restart(state, marker, "trust")
    deadline = time.monotonic() + 45
    while True:
        observed = collector(state, marker)["heartbeats"].get("trust", 0)
        if observed > old_sequence or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    confirmed(
        "observer-pod-replacement-preserves-heartbeat-counter",
        old_sequence > 0 and observed > old_sequence,
    )
    health(state, profile)
    return {
        "cases": cases,
        "collector_replacement": replacement,
        "observer_replacement": observer,
        "trust_heartbeat_before": old_sequence,
        "trust_heartbeat_after": observed,
        "source_fingerprint": profile["source_fingerprint"],
        "image_id": profile["image_id"],
        "release_ready": False,
    }
