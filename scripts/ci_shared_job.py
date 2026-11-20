"""Hosted cross-job M11/M12 consumer. All returned evidence is private and runner-local."""

import os
import secrets
from contextlib import contextmanager

from mlsecops import storage_pki
from mlsecops.contracts import Rejected, atomic_write, canonical, safe_child, write_json
from scripts import ci_consumer_native as driver
from scripts import m18_shared_retention as retention

LOCAL = ".runtime/ci-shared-job"


def require(value, reason):
    if not value:
        raise Rejected("ci_shared_job_" + reason)


def identity(root, run_owner, source):
    driver.hosted()
    actual = driver.run_owner()
    require(actual["producer_job"] == "shared", "job")
    require(canonical(run_owner) == canonical(actual | {"producer_job": "producer"}), "run")
    require(
        driver.source(root, driver.IMAGE) == source
        and source["source_revision"] == os.environ.get("GITHUB_SHA"),
        "source",
    )
    return actual


@contextmanager
def private_outputs(local):
    before = dict(os.environ)
    with driver.private_output(local, "shared-job"):
        try:
            for name in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
                path = safe_child(local, name.lower() + ".private")
                atomic_write(path, b"")
                os.environ[name] = str(path)
            yield
        finally:
            os.environ.clear()
            os.environ.update(before)


def clean_witness(local, actual, source):
    witness = driver.recovery.Recovery(local)
    require(
        canonical(witness.record["run_owner"]) == canonical(actual)
        and witness.record["source"] == source,
        "cleanup_owner",
    )
    result = witness.cleanup()
    require(canonical(result) == canonical(dict(sql=True, cluster=True)), "cleanup")
    return result


def authorize(root, source_api, run_owner, source):
    from scripts.ci_campaign_guard import authorize as authorize_campaign

    authorize_campaign(
        root, source_api=source_api, job="shared", run_owner=run_owner, source=source
    )
    return identity(root, run_owner, source)


def cleanup(root, *, source_api, run_owner, source):
    """Repeat exact-ID cleanup from this runner's independent durable witness."""
    actual = authorize(root, source_api, run_owner, source)
    return clean_witness(safe_child(root, LOCAL), actual, source)


def run(root, *, source_api, api, trust_key_path, key, trusted_public, run_owner, source):
    """Consume the signed shared packet; return replay inputs only after the view closes."""
    # Both closed maps contain only scalars. Pin the caller's expectations across I/O.
    run_owner, source = run_owner.copy(), source.copy()
    actual = authorize(root, source_api, run_owner, source)
    from scripts.ci_campaign_handoff import open_consumer

    local = safe_child(root, LOCAL)
    local.mkdir(mode=0o700, parents=True, exist_ok=False)
    # This independent marker identifies the recovery directory, never a signing authority.
    write_json(
        local / "workspace.json",
        dict(product="trusted-mlsecops", schema_version=1, workspace_id=secrets.token_hex(16)),
    )
    with private_outputs(local):
        witness = driver.recovery.Recovery.begin(local, actual, source)
        try:
            with open_consumer(
                root,
                job="shared",
                api=api,
                trust_key_path=trust_key_path,
                key=key,
                trusted_public=trusted_public,
                run_owner=run_owner,
                source=source,
            ) as (state, prepared, record, packets):
                owner, origin = record["owner"], record["origin"]
                require(
                    canonical(owner["run_owner"]) == canonical(run_owner)
                    and {k: owner["expected"][k] for k in driver.transfer.delivery.SOURCE}
                    == source,
                    "frozen_owner",
                )
                require(packets.keys() == {"candidate-shared"}, "packets")
                packet = packets["candidate-shared"]
                require(
                    packet["context"]["phase"] == "M11-M12"
                    and prepared["manifest_sha256"] == packet["manifest_sha256"]
                    and prepared["ciphertext_sha256"] == packet["ciphertext_sha256"],
                    "phase",
                )
                workspace = storage_pki.workspace_id(state)
                require(
                    prepared["workspace_id"] == workspace
                    and len({workspace, witness.record["workspace_id"], origin["workspace_id"]})
                    == 3,
                    "workspace",
                )
                summary = driver.projection()
                with driver.pins(owner["freeze"]):
                    info = driver.consumer(
                        root, local, state, prepared, owner, packet, witness, summary, origin
                    )
            try:
                os.lstat(state)
            except FileNotFoundError:
                pass
            else:
                raise Rejected("ci_shared_job_context_exit")
            cleaned = clean_witness(local, actual, source)
            destination = safe_child(local, driver.recovery.DIRECTORY + "/retained")
            arguments = info["arguments"]
            require(
                canonical({k: arguments[k] for k in owner}) == canonical(owner), "retained_owner"
            )
            replay = retention.replay(root, destination, index_pin=info["index_pin"], **arguments)
            require(
                replay["release_ready"] is False
                and canonical(replay["receipt"]) == canonical(info["receipt"]),
                "replay",
            )
            identity(root, run_owner, source)
            return dict(
                destination=destination,
                index_pin=info["index_pin"],
                arguments=arguments,
                replay=replay,
                origin=origin,
                consumer_offline=info["consumer_offline"],
                cleanup_owner=actual,
                cleanup=cleaned,
                gate_counts=summary["gate_counts"],
                release_ready=False,
            )
        except BaseException as primary:
            # The ordinary driver cleans failures before context exit. Also cover failed
            # materialization, context exit and replay with the persistent local witness.
            try:
                clean_witness(local, actual, source)
            except BaseException:
                primary.add_note("shared_job_cleanup_unverified")
            raise
