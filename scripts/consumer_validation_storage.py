"""Import authenticated original validation bytes into an owned consumer SQL target."""

import secrets
from pathlib import Path

from mlsecops import storage
from mlsecops.contracts import Rejected, bounded_read, canonical, digest, safe_child
from mlsecops.security_events import hexadecimal
from scripts import ci_candidate_transfer as bridge
from scripts import ci_validation_transfer as companion
from scripts import consumer_candidate_storage as candidate

MAX_RECEIPT_BYTES = 64 * 1024


def _need(value):
    if not value:
        raise Rejected("consumer_validation_storage_rejected")


def _target(state, workspace, storage_pin):
    target = candidate._target(state, workspace, storage_pin)
    # The approved target checks curator/promoter/serving, but not publisher.
    parameters, materials = storage.connection_materials(
        safe_child(state, "storage-clients/publisher")
    )
    _need(
        (parameters["user"], parameters["host"], parameters["hostaddr"], parameters["port"])
        == ("ml_publisher", "127.0.0.1", "127.0.0.1", target["marker"]["port"])
    )
    _need(
        materials["ca.crt"] == target["pki_files"]["ca.crt"] == target["pki"]["certificates"]["ca"]
    )
    _need(materials["client.crt"] == target["pki_files"]["ml_publisher.crt"])
    _need(materials["client.key"] == target["pki_files"]["ml_publisher.key"])
    target["clients"]["publisher"] = materials
    return target


def _inventory(client, reference, role):
    with storage.connect(client) as connection:
        _need(connection.execute("SELECT current_user;").fetchone() == (role,))
        rows = connection.execute(
            "SELECT sha256 FROM ml.validation ORDER BY sha256 LIMIT %s;", (2,)
        ).fetchall()
    refs = [storage.object_id(row[0]) for row in rows]
    # One expected object or an empty namespace; never fetch unknown payloads.
    _need(refs in ([], [reference]))
    return refs


def _receipt(path, document):
    _need(len(canonical(document)) + 1 <= MAX_RECEIPT_BYTES)
    return candidate._receipt(path, document)


def _fresh(root, state, owner, context):
    values, current = bridge._fresh(root, state, owner)
    bridge._window(context, values, current)


def import_validation(
    root,
    state,
    envelope,
    *,
    key,
    freeze_pin,
    freeze,
    expected,
    run_owner,
    phase,
    expected_context,
    ciphertext_pin,
    expected_workspace_id,
    storage_pin,
):
    """Import inside an existing candidate context; all arguments/receipts stay private.

    Caller owns SQL and its cleanup. Post observations never claim completion;
    only a successful return follows all receipt I/O, temporary-file cleanup and
    final target/freshness checks. A failed postcheck cannot roll back a commit.
    """
    try:
        root, state = Path(root), Path(state)
        owner = bridge._authority(key, freeze_pin, freeze, expected, run_owner, phase)
        _need(type(expected_context) is dict)
        context = expected_context.copy()
        hexadecimal(expected_workspace_id, 32)
        storage.object_id(storage_pin)
        with companion.materialize(
            root,
            state,
            envelope,
            key=key,
            **owner,
            phase=phase,
            expected_context=context,
            ciphertext_pin=ciphertext_pin,
        ) as (path, validation):
            raw = bounded_read(path, companion.MAX_VALIDATION_BYTES)
            reference = validation["validation_sha256"]
            companion._validation(
                raw, dict(sha256=reference, bytes=validation["bytes"], rows=validation["rows"])
            )
            target = _target(state, expected_workspace_id, storage_pin)
            curator = safe_child(state, "storage-clients/curator")
            publisher = safe_child(state, "storage-clients/publisher")
            before = _inventory(curator, reference, "ml_curator")
            _need(_inventory(publisher, reference, "ml_publisher") == before)
            if before:
                _need(storage.get(publisher, "validation", reference) == raw)
            relative = "evidence/consumer-validation/" + secrets.token_hex(16)
            directory = safe_child(state, relative)
            directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            observation = dict(
                schema_version=1,
                status="observation",
                accepted=False,
                authority=owner,
                phase=phase,
                validation=validation,
                workspace_id=expected_workspace_id,
                storage_pin=storage_pin,
                target_sha256=digest(canonical(target)),
                ciphertext_sha256=ciphertext_pin,
                release_ready=False,
            )
            pre_pin = _receipt(
                directory / "pre.json", observation | dict(stage="preflight", inventory=before)
            )
            # Include target inspection and pre-receipt latency before the INSERT.
            _need(_target(state, expected_workspace_id, storage_pin) == target)
            _fresh(root, state, owner, context)
            _need(storage.put(curator, "validation", raw) == reference)
            _need(_inventory(publisher, reference, "ml_publisher") == [reference])
            _need(storage.get(publisher, "validation", reference) == raw)
            _need(_inventory(curator, reference, "ml_curator") == [reference])
            _need(_target(state, expected_workspace_id, storage_pin) == target)
            _fresh(root, state, owner, context)
            post_pin = _receipt(
                directory / "post.json",
                observation | dict(stage="postflight", pre_sha256=pre_pin, inventory=[reference]),
            )
        # Includes post write/readback/hash AND companion context cleanup.
        # No receipt declares pass; no further receipt I/O follows these checks.
        _need(_target(state, expected_workspace_id, storage_pin) == target)
        _fresh(root, state, owner, context)
        return dict(
            status="pass",
            validation_sha256=reference,
            workspace_id=expected_workspace_id,
            storage_pin=storage_pin,
            pre_receipt=relative + "/pre.json",
            pre_sha256=pre_pin,
            post_receipt=relative + "/post.json",
            post_sha256=post_pin,
            handling="private",
            release_ready=False,
        )
    except candidate.FAILURES:
        raise Rejected("consumer_validation_storage_rejected") from None
