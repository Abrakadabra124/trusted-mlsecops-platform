from mlsecops import audit_evidence, audit_snapshot
from mlsecops.contracts import Rejected
from scripts import audit_export_probe


def retain(source, destination, ledger, *, binding, expected_context):
    snapshot = audit_snapshot.capture_closed(source)
    observed = []
    public = audit_export_probe.exercise(
        source, observer=lambda chunks, payload: observed.append((chunks, payload))
    )
    if len(observed) != 1 or observed[0][0] != snapshot[1]:
        raise Rejected("audit_evidence_export_snapshot")
    content = audit_evidence.create(
        snapshot[0], snapshot[1], ledger.snapshot(), observed[0][1], binding=binding
    )
    summary = audit_evidence.verify(content, binding=binding, expected_context=expected_context)
    if summary["public"] != public or audit_snapshot.capture_closed(source) != snapshot:
        raise Rejected("audit_evidence_source_changed")
    audit_snapshot.store_packet(destination, content)
    if audit_snapshot.load_packet(destination) != content:
        raise Rejected("audit_evidence_retained_readback")
    return summary
