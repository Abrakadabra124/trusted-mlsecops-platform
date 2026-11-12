"""Hosted proof of an actual root rotation and retained observer state, without model approval."""

import copy

from mlsecops import kube_observer_readback as io
from mlsecops import kube_security_events as audit
from mlsecops import kube_security_rotation as operator
from mlsecops import kube_trust, trust_authority, trust_root_store, trust_rotation
from mlsecops.contracts import Rejected, canonical, digest, read_json, safe_child
from scripts import kube_root_rotation as rotation
from scripts import kube_security_native as security
from scripts.kube_promotion_snapshot import read as model_snapshot
from scripts.kube_trust_native import hosted


def qualify(state, old_key):
    hosted()
    print(canonical(dict(stage="observer-rotation-preparation")).decode(), flush=True)
    before_marker = audit.validate(state)
    models = model_snapshot(state)
    _, current = trust_authority.current(state, backend=kube_trust.binding)
    package = rotation.prepare(current, old_key, safe_child(state, "keys/observer-next-root.pem"))
    next_root = trust_rotation.authorization(package, current["root_public"])["next_root"]
    cases = []

    def refused(label, candidate, target):
        try:
            operator.update(state, candidate, next_root=target)
        except Rejected:
            if read_json(safe_child(audit.directory(state), "resources.json")) != before_marker:
                raise Rejected("kube_observer_negative_changed_marker")
            audit.validate(state)
            cases.append(label)
        else:
            raise Rejected("kube_observer_negative_accepted")

    refused("uncommitted-root-refused", package, next_root)
    trust_root_store.migrate(state, backend=kube_trust.binding)
    rotated = trust_root_store.rotate(
        state,
        package,
        current_root=current["root_public"],
        next_root=next_root,
        backend=kube_trust.binding,
    )
    if rotated["state"] != "rotated-not-activated" or rotated["release_ready"] is not False:
        raise Rejected("kube_observer_rotation_receipt")
    bad = copy.deepcopy(package)
    bad["acceptance"]["signatures"] = []
    refused("forged-acceptance-refused", bad, next_root)
    refused("wrong-next-root-refused", package, current["root_public"])
    result = operator.update(state, package, next_root=next_root)
    print(canonical(dict(stage="observer-rotation-transition", **result)).decode(), flush=True)
    marker = audit.validate(state, authority_root=next_root)
    instance = io.instance(io.pod(state, marker, "trust"))
    if operator.update(state, package, next_root=next_root) != dict(
        reused=True, release_ready=False
    ):
        raise Rejected("kube_observer_retry_not_reused")
    if io.instance(io.pod(state, marker, "trust")) != instance:
        raise Rejected("kube_observer_retry_restarted")
    # Real read-only SQL reader still rejects the retired root. Continuity of
    # operator metadata must not authorize an old root for a fresh ML decision.
    code = """
from mlsecops import trust_authority
from mlsecops.contracts import Rejected, canonical, digest
environment, old, new = CONTEXT
try:
    trust_authority.read('/client', environment, old)
except Rejected as error:
    if str(error) != 'trust_authority_missing_or_foreign':
        raise
else:
    raise Rejected('old_root_accepted')
envelope, clock = trust_authority.read('/client', environment, new)
print(canonical(dict(old_root_refused=True, new_root_verified=True, document_sha256=digest(canonical(envelope)))).decode())
""".replace("CONTEXT", repr((current["environment"], current["root_public"], next_root)))
    reader = io.execute(state, marker, "trust", code)[0]
    if reader["document_sha256"] != digest(canonical(package["document"])):
        raise Rejected("kube_observer_reader_head")
    read = security.READ.replace(
        "SETUP",
        "from mlsecops.security_event_delivery import configured\nstore = configured('/security/producer.json').store",
    )
    read = read.replace(
        "    records.append(",
        "    if event.document()['kind'] != 'trust.revoked' or event.document()['reason'] != 'key' "
        "or event.document()['asset_sha256'] != "
        + repr(reader["document_sha256"])
        + ":\n        continue\n    records.append(",
    )
    outbox = io.execute(state, marker, "trust", read)[0]
    collector = security.collector(state, marker)
    delivered = [
        item
        for item in outbox["records"]
        if item["kind"] == "trust.revoked"
        and item["receipt"] is not None
        and item in collector["records"]
    ]
    if len(delivered) != 1 or model_snapshot(state) != models:
        raise Rejected("kube_observer_delivery_or_model_snapshot")
    return dict(
        status="pass",
        release_ready=False,
        transition=result,
        reader=reader,
        receipt_matches=len(delivered),
        retry_without_restart=True,
        model_ledger_unchanged=True,
        cases=[
            *cases,
            "old-root-reader-refused",
            "new-root-reader-verified",
            "owned-observer-replaced",
            "retained-outbox",
            "new-process-first-check",
            "independent-collector-receipt",
            "retry-no-restart",
        ],
        limitations=[
            "Controlled authority transition only; not candidate admission or full M11/M23/R1",
            "Interrupted updates remain fail-closed and require operator recovery",
        ],
    )
