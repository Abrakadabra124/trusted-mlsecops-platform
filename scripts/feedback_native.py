"""Actual prediction feedback -> existing SQL quarantine, without dataset approval."""

import sys

import psycopg
from psycopg import sql

from mlsecops import feedback, intake, storage, storage_bootstrap, storage_snapshot
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.release_policy import checked
from mlsecops.signing import encode64
from mlsecops.storage_schema import TABLES
from scripts.kube_promotion_snapshot import read as promotion_snapshot
from scripts.kube_trust_native import hosted


def fixture(packet):
    response = packet["http"][0]["response"]
    return {
        "schema_version": 1,
        "model_sha256": response["model_sha256"],
        "bundle_sha256": response["bundle_sha256"],
        "records": [
            {"request_id": response["request_id"], "row_index": index, "label": 1}
            for index in range(10)
        ],
    }


def directory(state, campaign):
    return safe_child(state, "evidence/monitoring/" + campaign + "/feedback")


def ledger(state):
    owner = storage_bootstrap.validate(state)["container_id"]
    return storage_snapshot.validate_ledger(
        decode(storage_bootstrap.admin(owner, storage_snapshot.ledger_sql()))
    )


def cli(arguments):
    raw = storage_snapshot.binary_command(
        [sys.executable, "-m", "mlsecops.feedback", *arguments], output_limit=4096, timeout=30
    )
    value = decode(raw, 4096)
    if raw != canonical(value) + b"\n":
        raise Rejected("feedback_cli_output")
    return value


def denials(state, reference, content):
    cases = [
        (
            "ingestor",
            "insert-" + table,
            sql.SQL("INSERT INTO ml.{} (sha256,payload) VALUES (%s,%s)").format(
                sql.Identifier(table)
            ),
            (reference, content),
        )
        for table in TABLES
        if table != "quarantine"
    ]
    cases += [
        (
            role,
            "read-quarantine",
            sql.SQL("SELECT payload FROM ml.quarantine WHERE sha256=%s"),
            (reference,),
        )
        for role in ("publisher", "scorer", "serving", "promoter")
    ]
    cases += [
        (
            "curator",
            "insert-quarantine",
            sql.SQL("INSERT INTO ml.quarantine (sha256,payload) VALUES (%s,%s)"),
            (reference, content),
        ),
        (
            "ingestor",
            "update-quarantine",
            sql.SQL("UPDATE ml.quarantine SET payload=%s WHERE sha256=%s"),
            (content, reference),
        ),
        (
            "ingestor",
            "delete-quarantine",
            sql.SQL("DELETE FROM ml.quarantine WHERE sha256=%s"),
            (reference,),
        ),
    ]
    observed = {}
    for role, name, statement, parameters in cases:
        try:
            with storage.connect(state / ("storage-clients/" + role)) as connection:
                connection.execute(statement, parameters)
        except psycopg.Error as error:
            if error.sqlstate != "42501":
                raise Rejected("feedback_database_wrong_denial") from None
            observed[role + ":" + name] = error.sqlstate
        else:
            raise Rejected("feedback_database_permission_granted")
    return observed


def verify(proof, packet):
    require_fields(
        proof,
        (
            "input",
            "stored",
            "receipt",
            "retry",
            "inspection",
            "before",
            "after",
            "after_retry",
            "final",
            "promotion_before",
            "promotion_after",
            "denials",
            "dataset_refused",
            "label_refused",
        ),
    )
    record = feedback.document(canonical(fixture(packet)))
    receipt = feedback.receipt(record)
    if (
        proof["input"] != fixture(packet)
        or canonical(proof["stored"]) != canonical(record)
        or any(proof[key] != receipt for key in ("receipt", "retry", "inspection"))
    ):
        raise Rejected("feedback_evidence_binding")
    for key in ("before", "after", "after_retry", "final"):
        storage_snapshot.validate_ledger(proof[key])
    before, after = proof["before"], proof["after"]
    if (
        any(before[table] != after[table] for table in TABLES if table != "quarantine")
        or after["quarantine"]["rows"] != before["quarantine"]["rows"] + 1
        or after["quarantine"]["bytes"] != before["quarantine"]["bytes"] + len(canonical(record))
        or after["quarantine"]["sha256"] == before["quarantine"]["sha256"]
        or proof["after_retry"] != after
        or proof["final"] != after
        or proof["promotion_before"] != proof["promotion_after"]
    ):
        raise Rejected("feedback_nonquarantine_mutation")
    expected = {"ingestor:insert-" + table for table in TABLES if table != "quarantine"}
    expected.update(
        role + ":read-quarantine" for role in ("publisher", "scorer", "serving", "promoter")
    )
    expected.update(
        ("curator:insert-quarantine", "ingestor:update-quarantine", "ingestor:delete-quarantine")
    )
    if (
        proof["denials"] != dict.fromkeys(expected, "42501")
        or proof["dataset_refused"] is not True
        or proof["label_refused"] is not True
    ):
        raise Rejected("feedback_authority_evidence")
    return {
        **receipt,
        "status": "pass",
        "quarantine_rows_added": 1,
        "retry_unchanged": True,
        "protected_tables_unchanged": True,
        "promotion_unchanged": True,
        "direct_database_denials": len(expected),
        "packet_sha256": digest(canonical(proof)),
    }


def reverify(state, campaign, summary, packet):
    content = bounded_read(directory(state, campaign) / "proof.json", 1024 * 1024)
    proof = decode(content, 1024 * 1024)
    result = verify(proof, packet)
    if result != summary:
        raise Rejected("feedback_retained_changed")
    return result


def qualify(state, result):
    hosted()
    campaign = result["monitoring_campaign_id"]
    packet = read_json(safe_child(state, "evidence/monitoring/" + campaign + "/packet.json"))[
        "packet"
    ]
    destination = directory(state, campaign)
    source = fixture(packet)
    write_json(destination / "submission.json", source)
    record = feedback.document(canonical(source))
    wanted = feedback.receipt(record)
    ingestor, curator = (
        str((state / ("storage-clients/" + name)).resolve()) for name in ("ingestor", "curator")
    )
    before, promotion_before = ledger(state), promotion_snapshot(state)
    arguments = ["submit", "--client", ingestor, "--file", str(destination / "submission.json")]
    receipt = cli(arguments)
    after = ledger(state)
    retry = cli(arguments)
    after_retry = ledger(state)
    inspected = cli(["inspect", "--client", curator, "--reference", wanted["record_sha256"]])
    stored = feedback.read(curator, wanted["record_sha256"])
    denied = denials(state, wanted["record_sha256"], canonical(record))
    refused = []
    for operation in (
        lambda: intake.validate_submission(
            canonical(record), "operator-feedback", "feedback", {}, state
        ),
        lambda: checked(record, "monitor-labels", encode64(b"p" * 32)),
    ):
        try:
            operation()
        except Rejected:
            refused.append(True)
        else:
            raise Rejected("feedback_accepted_as_authority")
    proof = {
        "input": source,
        "stored": stored,
        "receipt": receipt,
        "retry": retry,
        "inspection": inspected,
        "before": before,
        "after": after,
        "after_retry": after_retry,
        "final": ledger(state),
        "promotion_before": promotion_before,
        "promotion_after": promotion_snapshot(state),
        "denials": denied,
        "dataset_refused": refused[0],
        "label_refused": refused[1],
    }
    summary = verify(proof, packet)
    write_json(destination / "proof.json", proof)
    return reverify(state, campaign, summary, packet)
