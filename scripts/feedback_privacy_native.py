"""Actual M13 request -> ordinary feedback CLI -> quarantine and closed SQL logs."""

import secrets
import sys

from mlsecops import audit_evidence, audit_snapshot, feedback, signing, storage_snapshot
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    require_fields,
    safe_child,
)
from scripts import feedback_native, source_sql_privacy
from scripts.kube_trust_native import hosted

SUMMARY = {
    "schema_version": 1,
    "status": "pass",
    "scope": "actual-feedback-cli-privacy-not-full-M13",
    "release_ready": False,
    "successful_commands": 3,
    "rejected_commands": 8,
    "submitted_records": 1,
    "quarantine_rows_added": 1,
    "retry_unchanged": True,
    "protected_tables_unchanged": True,
    "promotion_unchanged": True,
    "rejections_unchanged": True,
    "direct_database_denials": 15,
    "source_service_windows": 1,
    "detected_service_leak_controls": 1,
    "retained_reverified": True,
}


def checked(value):
    if canonical(value) != canonical(SUMMARY):
        raise Rejected("feedback_privacy_summary")
    return dict(SUMMARY)


def directory(state, report):
    return safe_child(state, "evidence/privacy/" + report["privacy_campaign_id"] + "/feedback")


def source(state, report):
    raw = audit_snapshot.load_packet(
        safe_child(state, "evidence/privacy/" + report["privacy_campaign_id"] + "/audit-evidence")
    )
    if digest(raw) != report["native"]["audit"]["packet_sha256"]:
        raise Rejected("feedback_privacy_audit_binding")
    packet = decode(raw, audit_snapshot.MAX_PACKET)
    first = audit_evidence.checked_outcome(packet["http_outcomes"][0])
    if packet["binding"] != {
        "campaign_id": report["privacy_campaign_id"],
        "source": report["source"],
    } or (first["exchange"], first["route"], first["status"], first["admitted"]) != (
        1,
        "predict",
        200,
        True,
    ):
        raise Rejected("feedback_privacy_http_binding")
    return {
        "schema_version": 1,
        "model_sha256": report["model_sha256"],
        "bundle_sha256": report["subject_sha256"],
        "records": [{"request_id": first["request_id"], "row_index": 0, "label": 1}],
    }


def check_output(value, needles, expected):
    require_fields(value, ("returncode", "stdout", "stderr"))
    if type(value["returncode"]) is not int or any(
        type(value[key]) is not bytes for key in ("stdout", "stderr")
    ):
        raise Rejected("feedback_privacy_output_shape")
    if any(needle in value[key] for needle in needles for key in ("stdout", "stderr")):
        raise Rejected("feedback_privacy_output_canary")
    wanted = (
        {"returncode": 1, "stdout": b"", "stderr": b"feedback_rejected\n"}
        if expected is None
        else {"returncode": 0, "stdout": canonical(expected) + b"\n", "stderr": b""}
    )
    if value != wanted:
        raise Rejected("feedback_privacy_output_contract")


def verify(proof, source):
    require_fields(
        proof,
        (
            "input",
            "needles",
            "quarantine",
            "outputs",
            "after_rejections",
            "promotion_after_rejections",
            "service_identity",
            "service",
        ),
    )
    if proof["input"] != source:
        raise Rejected("feedback_privacy_input_binding")
    needles = tuple(signing.decode64(value) for value in proof["needles"])
    if (
        len(needles) != 9
        or len(set(needles)) != 9
        or any(not 1 <= len(value) <= 4096 for value in needles)
    ):
        raise Rejected("feedback_privacy_canaries")
    result = feedback_native.verify_record(proof["quarantine"], source)
    if (
        result["submitted_records"] != 1
        or proof["after_rejections"] != proof["quarantine"]["final"]
        or proof["promotion_after_rejections"] != proof["quarantine"]["promotion_after"]
    ):
        raise Rejected("feedback_privacy_rejection_mutation")
    receipt = feedback.receipt(feedback.document(canonical(source)))
    if type(proof["outputs"]) is not list or len(proof["outputs"]) != 11:
        raise Rejected("feedback_privacy_output_inventory")
    for index, item in enumerate(proof["outputs"]):
        require_fields(item, ("returncode", "stdout", "stderr"))
        check_output(
            {
                "returncode": item["returncode"],
                **{key: signing.decode64(item[key]) for key in ("stdout", "stderr")},
            },
            needles,
            receipt if index < 3 else None,
        )
    return needles


def reverify(state, report):
    destination = directory(state, report)
    raw = bounded_read(destination / "privacy.json", 1024 * 1024)
    proof = decode(raw, 1024 * 1024)
    needles = verify(proof, source(state, report))
    source_sql_privacy.reverify(
        destination / "source-service", proof["service_identity"], needles, proof["service"]
    )
    expected = report["feedback_privacy"]
    require_fields(expected, ("summary", "proof_sha256"))
    checked(expected["summary"])
    if digest(raw) != expected["proof_sha256"] or canonical(proof) != raw:
        raise Rejected("feedback_privacy_retained_changed")
    return dict(SUMMARY)


def qualify(state, report):
    hosted()
    actual = source(state, report)
    destination = directory(state, report)
    destination.mkdir(mode=0o700)
    marker, secret = secrets.token_hex(16), secrets.token_hex(32)
    needles = tuple(
        value.encode()
        for value in (
            actual["records"][0]["request_id"],
            marker,
            secret,
            marker + "@example.invalid",
            "https://private.invalid/" + marker,
            "0.3183098861837907",
            digest(marker.encode()),
            "private-file-" + marker,
            "synthetic-person-" + marker,
        )
    )
    window = source_sql_privacy.Window(state, destination / "source-service", needles)
    outputs = []
    receipt = feedback.receipt(feedback.document(canonical(actual)))

    def execute(arguments, expected=receipt):
        result = storage_snapshot.binary_streams(
            [sys.executable, "-m", "mlsecops.feedback", *arguments], output_limit=4096, timeout=30
        )
        check_output(result, needles, expected)
        outputs.append(
            {
                "returncode": result["returncode"],
                **{key: signing.encode64(result[key]) for key in ("stdout", "stderr")},
            }
        )
        return expected

    proof = feedback_native.qualify_record(state, destination, actual, invoke=execute)
    ingestor, curator = (
        str((state / ("storage-clients/" + role)).resolve()) for role in ("ingestor", "curator")
    )
    payloads = (
        canonical({**actual, "private": [value.decode() for value in needles]}),
        canonical({**actual, "records": [{**actual["records"][0], "label": marker}]}),
        canonical({**actual, "records": actual["records"] * 2}),
        ('{"private":"' + secret).encode(),
        marker.encode() + b"x" * feedback.MAX_BYTES,
    )
    for index, payload in enumerate(payloads):
        path = destination / ("private-file-" + marker + "-" + str(index) + ".json")
        atomic_write(path, payload)
        execute(["submit", "--client", ingestor, "--file", str(path)], None)
    execute(
        ["submit", "--client", ingestor, "--file", str(destination / ("missing-" + marker))], None
    )
    execute(["submit", "--client", curator, "--file", str(destination / "submission.json")], None)
    execute(["inspect", "--client", curator, "--reference", marker], None)
    value = {
        "input": actual,
        "needles": [signing.encode64(item) for item in needles],
        "quarantine": proof,
        "outputs": outputs,
        "after_rejections": feedback_native.ledger(state),
        "promotion_after_rejections": feedback_native.promotion_snapshot(state),
        "service_identity": window.pinned,
        "service": window.close(),
    }
    verify(value, actual)
    raw = canonical(value)
    atomic_write(destination / "privacy.json", raw)
    result = {"summary": dict(SUMMARY), "proof_sha256": digest(raw)}
    reverify(state, {**report, "feedback_privacy": result})
    return result
