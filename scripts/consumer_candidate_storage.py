"""Import only the original release closure into independently pinned consumer SQL."""

import secrets
from pathlib import Path

import psycopg

from mlsecops import (
    ci_transfer,
    material_bundle,
    release_bundle,
    signing,
    storage,
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
    safe_child,
)
from mlsecops.security_events import hexadecimal
from scripts import ci_candidate_transfer as bridge
from scripts import frozen_candidate_transfer as transfer
from scripts.candidate_serving_reader import bind_proposal

FAILURES = (*bridge.FAILURES, psycopg.Error)
ROLES = ("promoter", "serving", "curator")


def _need(condition):
    if not condition:
        raise Rejected("consumer_candidate_storage_rejected")


def _candidate(root, state, owner):
    values, current = bridge._fresh(root, state, owner)
    files, index, manifest = transfer.checked_files(
        lambda name, limit: bounded_read(safe_child(state, name), limit),
        **{k: owner[k] for k in ("freeze_pin", "freeze", "expected")},
    )
    keys = decode(files["trusted-keys.json"])
    report = decode(files[transfer.delivery.PROPOSAL])
    campaign = hexadecimal(report["campaign_id"], 32)
    _need(campaign == manifest["release_id"])
    directory = "release-proposals/" + campaign + "/"
    _need(
        bounded_read(safe_child(state, directory + "report.json"))
        == files[transfer.delivery.PROPOSAL]
    )
    _need(
        bounded_read(safe_child(state, directory + "policy-envelope.json"))
        == canonical(decode(files[transfer.CAS + index["policy_reference"]]))
    )
    _need(
        signing.encode64(
            signing.load_key(safe_child(state, "keys/trust.pem")).public_key().public_bytes_raw()
        )
        == keys["trust"]
    )
    refs = manifest["materials"]
    capsule = decode(files[transfer.CAS + refs["capsule"]])
    descriptors = material_bundle._index(capsule, keys["approver"])["objects"]
    package = dict(
        envelope=decode(files[transfer.CAS + owner["expected"]["proposal_reference"]]),
        capsule=dict(
            envelope=capsule,
            objects={
                (row["namespace"], row["sha256"]): files[transfer.CAS + row["sha256"]]
                for row in descriptors
            },
        ),
        documents={name: files[transfer.CAS + refs[name]] for name in release_bundle.DOCUMENTS},
    )
    context, verified = bind_proposal(
        report,
        package,
        policy=decode(bounded_read(safe_child(root, "policies/local-cpu.json"))),
        source_trust=decode(files["storage-trust.json"]),
        publisher_public=keys["approver"],
        expected={k: owner["expected"][k] for k in transfer.delivery.SOURCE},
        clock=current,
    )
    arguments = dict(
        context=context,
        publisher_public=keys["approver"],
        expected_serving_image=values["image_id"],
        clock=current,
    )
    contents = [
        canonical(package["envelope"]),
        canonical(capsule),
        *package["documents"].values(),
        *package["capsule"]["objects"].values(),
    ]
    return package, arguments, verified, {digest(raw): raw for raw in contents}


def _target(state, expected_workspace_id, storage_pin):
    marker_raw = bounded_read(safe_child(state, "storage.json"))
    _need(digest(marker_raw) == storage_pin)
    _need(storage_pki.workspace_id(state) == expected_workspace_id)
    workspace_pin = digest(bounded_read(safe_child(state, "workspace.json")))
    pki = storage_pki.validate(state)
    marker = storage_bootstrap.validate(state)  # Real Docker labels/IDs/policy/bindings.
    _need(marker == decode(marker_raw))
    observed = storage_bootstrap.inspect("container", marker["name"])
    storage_bootstrap.owned(observed, marker, "container")
    _need(observed["Id"] == marker["container_id"] and observed["State"]["Running"] is True)
    _need(
        observed["NetworkSettings"]["Ports"]
        == {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(marker["port"])}]}
    )
    _need(
        observed["NetworkSettings"]["Networks"][marker["network"]]["NetworkID"]
        == marker["network_id"]
    )
    pki_files = {
        name + "." + suffix: digest(
            bounded_read(safe_child(state, "storage-pki/" + name + "." + suffix), 4096)
        )
        for name in storage_pki.IDENTITIES
        for suffix in ("crt", "key")
    }
    clients = {}
    for role in ROLES:
        parameters, materials = storage.connection_materials(
            safe_child(state, "storage-clients/" + role)
        )
        _need(
            (parameters["user"], parameters["host"], parameters["hostaddr"], parameters["port"])
            == ("ml_" + role, "127.0.0.1", "127.0.0.1", marker["port"])
        )
        _need(materials["ca.crt"] == pki_files["ca.crt"] == pki["certificates"]["ca"])
        _need(materials["client.crt"] == pki_files["ml_" + role + ".crt"])
        _need(materials["client.key"] == pki_files["ml_" + role + ".key"])
        clients[role] = materials
    _need(bounded_read(safe_child(state, "storage.json")) == marker_raw)
    _need(digest(bounded_read(safe_child(state, "workspace.json"))) == workspace_pin)
    return dict(
        storage_pin=storage_pin,
        workspace_id=expected_workspace_id,
        workspace_pin=workspace_pin,
        marker=marker,
        pki=pki,
        pki_files=pki_files,
        clients=clients,
        image_id=observed["Image"],
        started_at=observed["State"]["StartedAt"],
    )


def _inventory(client, objects):
    # SELECT only bounded keys first. Unknown payloads are never fetched. This
    # does not lock out another writer; the caller serializes this owned import.
    with storage.connect(client) as connection:
        _need(connection.execute("SELECT current_user;").fetchone() == ("ml_promoter",))
        rows = connection.execute(
            "SELECT sha256 FROM ml.releases ORDER BY sha256 LIMIT %s;", (len(objects) + 1,)
        ).fetchall()
    refs = [storage.object_id(row[0]) for row in rows]
    _need(len(refs) == len(set(refs)) and set(refs) <= objects.keys())
    for reference in refs:
        _need(storage.get(client, "releases", reference) == objects[reference])
    return sorted(refs)


def _receipt(path, document):
    raw = canonical(document) + b"\n"
    atomic_write(path, raw)
    _need(bounded_read(path) == raw)
    return digest(raw)


def import_candidate(
    root, state, *, freeze_pin, freeze, expected, run_owner, expected_workspace_id, storage_pin
):
    """Import the original package after caller bootstrap; never provision or promote.

    Use inside the live file-adapter context with trusted external workspace and
    storage marker pins. Only fixed owned clients are used. Caller owns SQL/native
    cleanup. Partial inserts remain append-only and can resume with exact bytes.
    """
    try:
        root, state = Path(root), Path(state)
        owner = dict(freeze_pin=freeze_pin, freeze=freeze, expected=expected, run_owner=run_owner)
        transfer.authority(**owner, clock=bridge._now())
        owner = decode(canonical(owner))
        _need(owner["run_owner"]["repository"] == ci_transfer.REPOSITORY)
        hexadecimal(expected_workspace_id, 32)
        storage.object_id(storage_pin)
        package, arguments, verified, objects = _candidate(root, state, owner)
        target = _target(state, expected_workspace_id, storage_pin)
        promoter = safe_child(state, "storage-clients/promoter")
        serving = safe_child(state, "storage-clients/serving")
        inventory = _inventory(promoter, objects)
        relative = "evidence/consumer-storage/" + secrets.token_hex(16)
        directory = safe_child(state, relative)
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        pre_pin = _receipt(
            directory / "pre.json",
            dict(
                schema_version=1,
                authority=owner,
                target=target,
                inventory=inventory,
                status="preflight",
            ),
        )
        errors = []
        stage = "before-publication"
        try:
            _need(_target(state, expected_workspace_id, storage_pin) == target)
            # Native inspection can block. Check the original window after it,
            # immediately before the ordinary publisher can make its first INSERT.
            _, current = bridge._fresh(root, state, owner)
            arguments["clock"] = current
            stage = "publication"
            reference = release_bundle.publish(promoter, package, **arguments)
            _need(reference == owner["expected"]["proposal_reference"])
            stage = "serving-readback"
            _, current = bridge._fresh(root, state, owner)
            arguments["clock"] = current
            _need(
                release_bundle.load(
                    serving, reference, publisher_public=arguments["publisher_public"]
                )
                == package
            )
            _need(release_bundle.read(serving, reference, **arguments) == verified)
        except FAILURES:
            errors.append(stage)
        after, remaining = None, None
        try:
            bridge._fresh(root, state, owner)
            observed = _target(state, expected_workspace_id, storage_pin)
            _need(observed == target)
            after = observed
            remaining = _inventory(promoter, objects)
            _need(errors or remaining == sorted(objects))
            bridge._fresh(root, state, owner)
        except FAILURES:
            errors.append("postflight")
        status = "fail" if errors else "pass"
        post_pin = _receipt(
            directory / "post.json",
            dict(
                schema_version=1,
                authority=owner,
                pre_sha256=pre_pin,
                status=status,
                target=after,
                inventory=remaining,
                failure_stages=errors,
            ),
        )
        _need(not errors)
        # A receipt is an earlier observation, not permission to outlive the
        # original window. Do no more receipt I/O after these final checks.
        _need(_target(state, expected_workspace_id, storage_pin) == target)
        bridge._fresh(root, state, owner)
        return dict(
            status=status,
            proposal_reference=reference,
            workspace_id=expected_workspace_id,
            storage_pin=storage_pin,
            pre_receipt=relative + "/pre.json",
            pre_sha256=pre_pin,
            post_receipt=relative + "/post.json",
            post_sha256=post_pin,
            handling="private",
            release_ready=False,
        )
    except FAILURES:
        raise Rejected("consumer_candidate_storage_rejected") from None
