"""Hosted-only audit proof using real Pods, mTLS, persistent journals and network denial."""

import time
import uuid
from contextlib import contextmanager

from mlsecops import (
    kube_promotion,
    kube_security_events,
    kube_serving_handoff,
    kube_serving_service,
    kube_storage,
)
from mlsecops import kube_security_resources as resources
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, canonical, decode
from mlsecops.kube_worker import job_document, pod_spec, verify_running_image, wait_job
from mlsecops.storage_pki import workspace_id
from scripts.kube_promotion_snapshot import read as ledger
from scripts.kube_trust_native import hosted

READBACK_BYTES = kube_serving_service.READBACK_BYTES
PRIVATE_READBACK_BYTES = 8 * 1024 * 1024

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
from mlsecops.security_event_ledger import MAX_RECORDS as COLLECTOR_RECORDS
from mlsecops.security_event_outbox import MAX_RECORDS as PRODUCER_RECORDS
from mlsecops.process_privacy import enforce
enforce()
deadline = time.monotonic() + 3
setup_complete = False
while True:
    if time.monotonic() >= deadline:
        raise Rejected('security_readback_deadline')
    try:
        if not setup_complete:
            # Fixed source snippets retain their multiline READ.replace interface.
            exec('''SETUP''')
            setup_complete = True
        if time.monotonic() >= deadline:
            raise Rejected('security_readback_deadline')
        document = store.snapshot()
        if time.monotonic() >= deadline:
            raise Rejected('security_readback_deadline')
        break
    except Rejected as error:
        transient = ('artifact_unavailable', 'security_store_unavailable', 'security_store_busy') if setup_complete else ('security_store_busy',)
        remaining = deadline - time.monotonic()
        if str(error) not in transient or remaining <= 0:
            raise
        time.sleep(min(0.03, remaining))
if len(document['records']) > min(COLLECTOR_RECORDS, PRODUCER_RECORDS):
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

# Separate private interface. Preserve READ/COLLECTOR/PROMOTER hash projections.
# Store.snapshot already validates the complete journal; never serialize the store,
# its configuration, signing keys, TLS material, tokens or diagnostic output.
PRIVATE_READ = (
    READ[: READ.index("records = []")]
    + """
private = canonical({'pin': store.pin, 'snapshot': document})
if len(private) + 1 > 8 * 1024 * 1024:
    raise Rejected('security_private_readback_limit')
print(private.decode())
"""
)
PRIVATE_PROMOTER = PRIVATE_READ.replace(
    "SETUP",
    "from mlsecops.security_event_admission import emitter\nstore = emitter('/security/audit.json').store",
)
PRIVATE_COLLECTOR = PRIVATE_READ.replace(
    "SETUP",
    "from mlsecops.security_event_server import configured\nstore = configured('/security/collector.json')[0].collector.store",
)


def job(state, profile, code, *, worker=False, serving=False, private_readback=False):
    hosted()
    if (
        type(private_readback) is not bool
        or private_readback
        and (worker or serving or code != PRIVATE_PROMOTER)
    ):
        raise Rejected("audit_private_readback_role")
    if type(worker) is not bool or type(serving) is not bool or worker and serving:
        raise Rejected("audit_native_role_conflict")
    if serving and kube_serving_service.directory(state).exists():
        raise Rejected("audit_serving_owner_present")
    if serving:
        kube_serving_handoff.require_probe_slot(state)
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
        if private_readback and (
            type(observed.get("metadata", {}).get("uid")) is not str
            or not observed["metadata"]["uid"]
        ):
            raise Rejected("audit_private_job_uid")
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
        if private_readback:

            def check_pod():
                metadata = pod["metadata"]
                if (
                    type(metadata.get("uid")) is not str
                    or not metadata["uid"]
                    or len(metadata["ownerReferences"]) != 1
                    or metadata["ownerReferences"][0].get("kind") != "Job"
                    or metadata["ownerReferences"][0].get("controller") is not True
                ):
                    raise Rejected("audit_private_pod_uid")
                current = decode(
                    kubectl(
                        state, ["get", "pod", metadata["name"], "-n", namespace, "-o", "json"]
                    ).stdout
                )
                if (
                    current.get("metadata", {}).get("uid") != metadata["uid"]
                    or current["metadata"].get("ownerReferences") != metadata["ownerReferences"]
                    or current["metadata"].get("deletionTimestamp")
                ):
                    raise Rejected("audit_private_pod_changed")

            check_pod()
        limit = PRIVATE_READBACK_BYTES if private_readback else READBACK_BYTES
        content = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-n",
                namespace,
                "-c",
                "worker",
                f"--limit-bytes={limit + 1}",
            ],
        ).stdout
        if private_readback:
            check_pod()
        return decode(content, limit)
    finally:
        kube_promotion.cleanup(state, created, namespace=namespace)
        if serving:
            kube_serving_handoff.wait_pods_absent(state)


def private_outbox(state, profile):
    """Owned bounded private read; the temporary Job is removed even on rejection."""
    return job(state, profile, PRIVATE_PROMOTER, private_readback=True)


def private_collector(state, marker):
    """Read the complete journal only while the same validated collector UID owns it."""
    hosted()
    document = resources.deployment(marker["workspace_id"], marker["profile"]["image"], "collector")
    uid = kube_security_events.live(state, document, marker)
    if type(uid) is not str or not uid:
        raise Rejected("audit_private_collector_uid")
    pods = decode(
        kubectl(
            state, ["get", "pods", "-n", resources.NAMESPACE, "-l", "app=collector", "-o", "json"]
        ).stdout
    )["items"]
    if len(pods) != 1 or pods[0]["metadata"].get("uid") != uid:
        raise Rejected("audit_private_collector_changed")
    # exec has no logs limit flag; the fixed program bounds serialization before
    # stdout, and the host independently bounds decode. Nothing is printed here.
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
            PRIVATE_COLLECTOR,
        ],
    ).stdout
    if kube_security_events.live(state, document, marker) != uid:
        raise Rejected("audit_private_collector_changed")
    return decode(content, PRIVATE_READBACK_BYTES)


def serving_readback(state, profile):
    """Read the retained journal inside its verified owner when HTTP already exists."""
    hosted()
    if not kube_serving_service.directory(state).exists():
        return {
            "mode": "probe",
            "pod_uid": None,
            "snapshot": job(state, profile, SERVING, serving=True),
        }
    marker = kube_serving_service.validate(state)
    if marker["profile"] != profile:
        raise Rejected("audit_serving_profile_changed")
    before = kube_serving_service.pod(state, marker)["metadata"]["uid"]
    snapshot = kube_serving_service.execute(state, SERVING)
    if kube_serving_service.pod(state, marker)["metadata"]["uid"] != before:
        raise Rejected("audit_serving_owner_changed")
    return {"mode": "service", "pod_uid": before, "snapshot": snapshot}


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
    return decode(content, READBACK_BYTES)


@contextmanager
def outage(state, workspace, *, owned=None):
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
    created = [] if owned is None else owned
    if created:
        raise Rejected("audit_native_fault_already_owned")
    try:
        observed = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
        created.append((document, observed["metadata"]["uid"]))
        kube_storage.verify_resource(document, observed, created[0][1])
        yield
    finally:
        kube_promotion.cleanup(state, list(created), namespace=resources.NAMESPACE)
        created.clear()


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
    serving_owner = serving_readback(state, profile)
    serving = serving_owner["snapshot"]
    confirmed(
        "serving-outbox-is-distinct-from-trust-observer",
        serving["pin"] == marker["pins"]["serving"]
        and marker["pins"]["serving"] != marker["pins"]["trust"]
        and marker["volumes"]["serving"] != marker["volumes"]["trust"]
        and (serving_owner["mode"] == "service" or serving["records"] == []),
    )
    replacement = serving_readback(state, profile)
    confirmed(
        "same-serving-owner-retains-private-outbox"
        if serving_owner["mode"] == "service"
        else "serving-probe-replacement-retains-private-outbox",
        replacement == serving_owner
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
        "serving_owner": {name: serving_owner[name] for name in ("mode", "pod_uid")},
        "trust_heartbeat_before": old_sequence,
        "trust_heartbeat_after": observed,
        "source_fingerprint": profile["source_fingerprint"],
        "image_id": profile["image_id"],
        "release_ready": False,
    }
