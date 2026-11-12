"""Bounded read-only observer diagnostics tied to one owned container instance."""

from mlsecops import kube_security_events as audit
from mlsecops import kube_security_resources as resources
from mlsecops import kube_storage as storage
from mlsecops import security_trust_events as source
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, canonical, decode


def pod(state, marker, role):
    document = audit.runtime(marker, role)
    storage.verify_resource(
        document, storage.get(state, document), marker["resources"][storage.reference(document)]
    )
    uid = audit.live(state, document, marker)
    namespace = document["metadata"]["namespace"]
    name = document["metadata"]["name"]
    items = decode(
        kubectl(state, ["get", "pods", "-n", namespace, "-l", "app=" + name, "-o", "json"]).stdout
    )["items"]
    if len(items) != 1 or items[0]["metadata"]["uid"] != uid:
        raise Rejected("kube_observer_pod_changed")
    instance(items[0])
    return items[0]


def instance(document):
    values = document.get("status", {}).get("containerStatuses", [])
    if (
        len(values) != 1
        or values[0].get("name") != "worker"
        or not values[0].get("state", {}).get("running")
        or type(values[0].get("restartCount")) is not int
        or values[0]["restartCount"] < 0
        or type(values[0].get("containerID")) is not str
        or not values[0]["containerID"]
    ):
        raise Rejected("kube_observer_container_unavailable")
    return document["metadata"]["uid"], values[0]["containerID"], values[0]["restartCount"]


def read(state, marker, role, arguments, *, limit=65536):
    before = pod(state, marker, role)
    namespace, _ = resources.identity(role)
    result = kubectl(
        state,
        [arguments[0], before["metadata"]["name"], "-n", namespace, "-c", "worker", *arguments[1:]],
    ).stdout
    if instance(pod(state, marker, role)) != instance(before):
        raise Rejected("kube_observer_container_changed")
    if len(result) > limit:
        raise Rejected("kube_observer_readback_limit")
    return result, instance(before)


def execute(state, marker, role, code, *, limit=65536):
    content, identity = read(state, marker, role, ["exec", "--", "python", "-c", code], limit=limit)
    return decode(content, limit), identity


def history(state, marker):
    code = (
        "from mlsecops.security_trust_events import read; "
        "from mlsecops.contracts import canonical; "
        "print(canonical(read('/client', " + repr(marker["context"]["environment"]) + ")).decode())"
    )
    return execute(state, marker, "trust", code, limit=source.MAX_HISTORY_BYTES)[0]


def success(state, marker, pin):
    content, identity = read(state, marker, "trust", ["logs", "--tail=100", "--limit-bytes=65537"])
    expected = canonical(
        dict(state="trust_observer_first_success", config_sha256=pin, release_ready=False)
    )
    if expected not in content.splitlines():
        raise Rejected("kube_observer_first_success_missing")
    return identity


SNAPSHOT = """
import time
from mlsecops.contracts import Rejected, canonical, digest
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
BODY
"""


def outbox(state, marker, *, count=None):
    if count is not None and (type(count) is not int or not 0 <= count <= 1024):
        raise Rejected("kube_observer_prefix_count")
    code = SNAPSHOT.replace(
        "SETUP",
        "from mlsecops.security_event_delivery import configured\nstore = configured('/security/producer.json').store",
    )
    code = code.replace(
        "BODY",
        """
if store.registry.producer(document['producer_id']).role != 'trust':
    raise Rejected('kube_observer_producer_role')
count = COUNT
if count is None:
    count = len(document['records'])
if count > len(document['records']):
    raise Rejected('kube_observer_outbox_truncated')
heartbeat = document['heartbeat']
sequence = 0 if heartbeat is None else store.registry.heartbeat(heartbeat, clock_ms=document['updated_at_ms'])['sequence']
print(canonical(dict(pin=store.pin, producer_id=document['producer_id'], count=count,
    prefix_sha256=digest(canonical([item['envelope'] for item in document['records'][:count]])),
    heartbeat=sequence)).decode())
""".replace("COUNT", repr(count)),
    )
    return execute(state, marker, "trust", code)[0]


def collector(state, marker):
    code = SNAPSHOT.replace(
        "SETUP",
        "from mlsecops.security_event_server import configured\nstore = configured('/security/collector.json')[0].collector.store",
    )
    code = code.replace(
        "BODY",
        """
matches = []
for item in document['telemetry']['streams']:
    if store.registry.producer(item['producer_id']).role == 'trust':
        heartbeat = item['heartbeat']
        matches.append(0 if heartbeat is None else store.registry.heartbeat(heartbeat['envelope'], clock_ms=heartbeat['ingested_at_ms'])['sequence'])
if len(matches) != 1:
    raise Rejected('kube_observer_collector_stream')
print(canonical(dict(pin=store.pin, heartbeat=matches[0])).decode())
""",
    )
    return execute(state, marker, "collector", code)[0]
