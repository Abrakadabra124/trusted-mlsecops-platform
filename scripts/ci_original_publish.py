"""Publish once from the already prepared original producer. CLI: publish.

The operator supplies CANDIDATE_JOURNAL_RELEASE (descriptor JSON),
CANDIDATE_JOURNAL_PUBLIC, CANDIDATE_JOURNAL_KEY_FILE and the separate
CANDIDATE_ORIGIN_RELEASE descriptor out of band.
"""

import os
import stat
import sys
from contextlib import ExitStack, closing
from pathlib import Path

from mlsecops import controller_intake, key_files, signing
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    safe_child,
)
from scripts import ci_campaign_journal as journal
from scripts import ci_campaign_publish as campaign
from scripts import ci_private_assets as store
from scripts import ci_source_image_native as image
from scripts import install_ci_tools
from scripts.ci_asset_http import Client as PrivateClient
from scripts.ci_campaign_source import Client as PublicClient
from scripts.ci_primary_job import _directory
from scripts.ci_serving_job import private_process


def _need(ok):
    if not ok:
        raise Rejected("original_publish_refused")


def _tools(state):
    folder = safe_child(state, "bin")
    _directory(folder)
    seen = set()
    for path in folder.iterdir():
        _need(path.name in install_ci_tools.TOOLS)
        info = path.lstat()
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and os.access(path, os.X_OK))
        if os.name == "posix":
            _need(info.st_uid == os.geteuid() and not info.st_mode & 0o022)
        seen.add(path.name)
    _need(seen == install_ci_tools.TOOLS.keys())
    os.environ["PATH"] = str(folder) + os.pathsep + os.environ["PATH"]


def _signer(root, path):
    path = Path(path)
    _need(
        path.is_absolute() and path == path.resolve(strict=True) and not path.is_relative_to(root)
    )
    _directory(path.parent, private=True)
    if os.name == "posix":
        for ancestor in path.parent.parents:
            info = ancestor.stat()
            _need(info.st_uid in (0, os.geteuid()))
            _need(not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX)
    key_files.validate(path.lstat())
    return path


def _cluster(state, binding, marker):
    owner = campaign.cluster_owner
    record = owner.recovery.Recovery(safe_child(state, owner.WITNESS)).record
    image.same(record, dict(workspace_id=marker["workspace_id"], baseline_empty=True, sql=None))
    _need(canonical({name: record[name] for name in binding}) == canonical(binding))
    image.same(record["cluster"], dict(observed=True))
    return record


def _prepared(root, state, binding):
    marker = campaign.storage_bootstrap.validate(state)
    image.same(
        read_json(state / "evidence/storage-bootstrap.json"),
        dict(status="ready", container_id=marker["container_id"]),
    )
    inputs = read_json(state / "evidence/ci-producer-inputs.json")
    image.same(inputs, dict(workspace=marker["workspace_id"]))
    start = controller_intake.pinned(state / controller_intake.START, inputs["start"])
    current = controller_intake.owner(root, state)
    image.same(
        current,
        dict(
            workspace=marker["workspace_id"],
            container=marker["container_id"],
            revision=binding["source"]["source_revision"],
            fingerprint=binding["source"]["source_fingerprint"],
        ),
    )
    _need(canonical(start["owner"]) == canonical(current))
    capture = read_json(state / controller_intake.CAPTURE)
    demo = read_json(state / "storage-demo.json")
    image.same(capture, dict(start=inputs["start"], release_ready=False))
    image.same(
        capture["subject"],
        dict(
            dataset_reference=demo["dataset"]["dataset_reference"],
            candidate_reference=demo["candidate"]["candidate_reference"],
            evaluation_reference=demo["evaluation_reference"],
        ),
    )
    cluster = _cluster(state, binding, marker)
    image.same(cluster["cleanup"], dict(sql=True, cluster=True))
    image.same(
        campaign.storage_bootstrap.inspect("container", marker["container_id"])["State"],
        dict(Running=True),
    )
    return marker, canonical(cluster["cluster"])


def _cleanup(state, binding, marker, cluster, primary):
    # A failure on one side must not bypass the identity checks on the other.
    try:
        _need(canonical(_cluster(state, binding, marker)["cluster"]) == cluster)
        campaign.cluster_owner.cleanup(state)
    except BaseException:
        primary.add_note("producer_cluster_cleanup_unconfirmed")
    try:
        _need(canonical(campaign.storage_bootstrap.validate(state)) == canonical(marker))
        campaign.recovery.stop_owned(state)
        campaign.receipt.offline_pin(state)
        _need(canonical(campaign.storage_bootstrap.validate(state)) == canonical(marker))
    except BaseException:
        primary.add_note("producer_sql_cleanup_unconfirmed")


def _confirmed(public, storage, last, tip, recovered):
    _need(recovered["complete"] is True and canonical(recovered["tip"]) == canonical(tip))
    closed = recovered["checkpoint"]
    _need(canonical(closed) == last and canonical(closed["storage"]) == canonical(storage))
    _need(journal._public(public) == closed["issuer"]["public"])
    return closed


def _origin(release, journal_id, owner):
    require_fields(release, ("repository_id", "release_id", "target_commitish", "name"))
    image.same(
        release,
        dict(
            repository_id=store.REPOSITORY_ID,
            name=f"ci-origin-{owner['run_id']}-{owner['run_attempt']}",
        ),
    )
    _need(store._number(release["release_id"]) != journal_id)
    store._hex(release["target_commitish"], 40)
    return release.copy()


def _live(root, source_api, api, closed, public, key, binding):
    raw = store.fetch_control(api, closed["storage"]["expected"])
    _need(digest(raw) == closed["issuer"]["control_sha256"])
    record = campaign.control.read(raw, trusted_public=public, key=key, **binding)
    _need(digest(canonical(record["storage"])) == closed["issuer"]["storage_sha256"])
    campaign.guard.authorize(root, job="producer", source_api=source_api, **binding)
    now = campaign.bridge._now()
    store._open(record["storage"])
    for row in record["packets"].values():
        context = row["context"]
        _need(context["issued_at"] <= now <= context["expires_at"] - 600)


def publish(
    root,
    *,
    source_api,
    api,
    key,
    image_receipt,
    descriptor,
    origin_release,
    trusted_public,
    key_path,
):
    """Return only the verified producer public key. Preserve ordinary errors for trusted callers."""
    # Closing normally restores fds/env without replacing the original failure or its cleanup notes.
    with closing(ExitStack()) as scope:
        scope.enter_context(private_process())
        from scripts.ci_origin_backup import copy_originals, put_witness
        from scripts.ci_tip_witness import seal

        root = Path(root)
        _need(os.environ["GITHUB_JOB"] == "producer")
        _need(root == Path.cwd() == Path(os.environ["GITHUB_WORKSPACE"]) and root == root.resolve())
        source_image = image.receipt(image_receipt, os.environ)
        source = {k: source_image[k] for k in ("source_revision", "source_fingerprint", "image_id")}
        binding = dict(run_owner=campaign.producer.run_owner(), source=source)
        campaign.guard.authorize(root, job="producer", source_api=source_api, **binding)
        image.owner_record(root, os.environ, create=False)
        state = safe_child(root, ".runtime")
        _directory(root)
        _directory(state)
        _tools(state)
        descriptor = journal._binding(descriptor, binding["run_owner"], source, trusted_public)[
            "journal"
        ]
        origin_release = _origin(origin_release, descriptor["release_id"], binding["run_owner"])
        _need(type(key) is bytes and len(key) == 32)
        signer = _signer(root, key_path)
        _need(
            signing.encode64(signing.load_key(signer).public_key().public_bytes_raw())
            == trusted_public
        )
        campaign.producer.require_unproposed(state)
        marker, cluster = _prepared(root, state, binding)
        params = dict(journal=descriptor, trusted_public=trusted_public, key=key, **binding)
        # Only this invocation may unwind the original SQL. A concurrent loser
        # must never stop the winner's container before its freeze claim exists.
        safe_child(state, "ci-original-publish-claim").mkdir(mode=0o700)
        try:
            append = journal.publisher(api, key_path=signer, **params)
            tip = last = None

            def checkpoint(value):
                nonlocal tip, last
                tip = append(value)
                last = canonical(value)

            # Recheck the local owner after the private release preflight.
            _need(canonical(campaign.storage_bootstrap.validate(state)) == canonical(marker))
            _need(canonical(_cluster(state, binding, marker)["cluster"]) == cluster)
            public, storage = campaign.publish_original(
                root,
                state,
                source_api=source_api,
                api=api,
                key=key,
                checkpoint=checkpoint,
                **binding,
            )
            image.same(tip, dict(step=len(journal.STAGES)))
            recovered = journal.recover(api, expected_tip=tip.copy(), **params)
            _need(canonical(campaign.storage_bootstrap.validate(state)) == canonical(marker))
            closed = _confirmed(public, storage, last, tip, recovered)
            _need(
                len({origin_release["release_id"], descriptor["release_id"], storage["release_id"]})
                == 3
            )
            # copy_originals returns only after comparing every retained byte and
            # rechecking full membership in the independently pinned release.
            _need(
                copy_originals(api, release=origin_release, checkpoint=closed, key=key, **binding)
                is None
            )
            witness = seal(
                tip,
                journal_release=descriptor,
                origin_release=origin_release,
                trusted_public=trusted_public,
                key=key,
                key_path=signer,
                **binding,
            )
            put_witness(api, witness, release=origin_release, checkpoint=closed, **binding)
            _live(root, source_api, api, closed, public, key, binding)
            return public
        except BaseException as primary:
            _cleanup(state, binding, marker, cluster, primary)
            raise


def main(arguments=None):
    try:
        _need((sys.argv[1:] if arguments is None else arguments) == ["publish"])
        env = os.environ
        _need("CANDIDATE_STORE_READ" not in env and env.get("GITHUB_JOB") == "producer")
        public_token, private_token = (
            env.pop("CANDIDATE_PUBLIC_TOKEN"),
            env.pop("CANDIDATE_STORE_WRITE"),
        )
        _need(public_token != private_token)
        public = publish(
            Path.cwd(),
            source_api=PublicClient(public_token),
            api=PrivateClient(private_token, write=True),
            key=signing.decode64(journal._public(env.pop("CANDIDATE_TRANSFER_KEY"))),
            image_receipt=decode(env.pop("SOURCE_IMAGE_RECEIPT").encode(), 4096),
            descriptor=decode(env.pop("CANDIDATE_JOURNAL_RELEASE").encode(), 4096),
            origin_release=decode(env.pop("CANDIDATE_ORIGIN_RELEASE").encode(), 4096),
            trusted_public=env.pop("CANDIDATE_JOURNAL_PUBLIC"),
            key_path=env.pop("CANDIDATE_JOURNAL_KEY_FILE"),
        )
    except (Exception, KeyboardInterrupt, SystemExit):
        print("original_publish=refused")
        return 1
    print("original_publish=pass")
    print("producer_public=" + public)
    return 0


if __name__ == "__main__":
    sys.exit(main())
