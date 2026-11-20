"""Prepare the original hosted producer's live SQL state for publish_original.

Run `python -B -m scripts.ci_original_bootstrap prepare` after image receipt.
Supply CANDIDATE_PUBLIC_TOKEN, CANDIDATE_TRUST_FILE and SOURCE_IMAGE_RECEIPT.
In a separate publish or recovery step, prepend "$GITHUB_WORKSPACE/.runtime/bin"
to PATH. A CLI process cannot export its PATH to the next step.

If cluster cleanup is unconfirmed, retain .runtime and use the ordinary
`python -B -m scripts.ci_producer_cluster cleanup` on the same hosted producer.
It reopens the durable witness, verifies ownership and checks actual absence.
"""

import os
import subprocess
import sys
from contextlib import ExitStack, closing
from pathlib import Path

from mlsecops import bootstrap, controller_intake, key_files, storage, storage_pki
from mlsecops import storage_bootstrap as sql
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    decode,
    digest,
    read_json,
    safe_child,
    write_json,
)
from scripts import ci_campaign_guard as guard
from scripts import ci_campaign_producer as producer
from scripts import ci_producer_cluster as cluster_owner
from scripts import ci_source_image_native as native
from scripts import install_ci_tools
from scripts import m17_recovery_native as recovery
from scripts import shared_serving_receipt as receipt
from scripts.ci_campaign_source import Client as PublicClient
from scripts.ci_serving_job import private_process

ERROR_CLASSES = (
    Rejected,
    subprocess.CalledProcessError,
    subprocess.TimeoutExpired,
    OSError,
    KeyboardInterrupt,
    SystemExit,
    RuntimeError,
    KeyError,
    ValueError,
    TypeError,
)


def _need(condition):
    if not condition:
        raise Rejected("original_bootstrap_refused")


def _report(state, gate, source):
    report = read_json(safe_child(state, f"evidence/{gate}.json"))
    native.same(
        report,
        dict(
            gate=gate,
            profile="local-cpu",
            status="pass",
            exit_code=0,
            source_dirty=False,
            source_revision=source["source_revision"],
        ),
    )
    inputs = report["input_digests"]
    native.same(inputs, dict(source_fingerprint=source["source_fingerprint"]))
    if gate != "M02":
        native.same(inputs, dict(worker_image=source["image_id"]))
    return inputs


def _gate(root, state, gate, source, **inputs):
    output = safe_child(state, f"evidence/{gate}.json")
    subprocess.run(
        [
            sys.executable,
            "-B",
            "-W",
            "error",
            "-m",
            "mlsecops.acceptance",
            "--gate",
            gate,
            "--state",
            str(state),
            "--output",
            str(output),
        ],
        cwd=root,
        env=dict(os.environ, **inputs),
        check=True,
    )
    return _report(state, gate, source)


def _evaluate(root, state, workspace, source, progress):
    inputs = safe_child(state, "evidence/ci-producer-inputs.json")
    write_json(inputs, dict(workspace=workspace))
    for gate in ("M01", "M02"):
        progress["stage"] = gate
        _gate(root, state, gate, source)
    progress["stage"] = "M21_start"
    start = controller_intake.begin(root, state)
    _need(start == digest(bounded_read(safe_child(state, controller_intake.START))))
    write_json(inputs, dict(workspace=workspace, start=start))
    progress["stage"] = "M07"
    evaluated = _gate(
        root,
        state,
        "M07",
        source,
        M21_START_SHA256=start,
        M07_FRESH_WORKSPACE_ID=workspace,
        R1_SCOPED_TRAINING="1",
    )
    # M07 itself runs M03 and trains the scoped candidate. Reconcile the original
    # controller capture with the demo that release_native will actually consume.
    progress["stage"] = "subject_readback"
    demo = read_json(safe_child(state, "storage-demo.json"))
    refs = dict(
        dataset_reference=demo["dataset"]["dataset_reference"],
        candidate_reference=demo["candidate"]["candidate_reference"],
        evaluation_reference=demo["evaluation_reference"],
    )
    native.same(_report(state, "M03", source), refs)
    native.same(evaluated, refs)
    captured = read_json(safe_child(state, controller_intake.CAPTURE))
    native.same(captured, dict(start=start))
    native.same(captured["subject"], refs)


def _bootstrap(root, *, source_api, trust_key_path, image_receipt):
    _need(os.environ.get("GITHUB_JOB") == "producer")
    _need(root == Path.cwd() == Path(os.environ["GITHUB_WORKSPACE"]) and root == root.resolve())
    image = native.receipt(image_receipt, os.environ)
    source = {k: image[k] for k in ("source_revision", "source_fingerprint", "image_id")}
    owner = producer.run_owner()

    def authorize():
        guard.authorize(root, job="producer", source_api=source_api, run_owner=owner, source=source)

    authorize()
    native.owner_record(root, os.environ, create=False)
    trust = Path(trust_key_path)
    _need(
        trust.is_absolute()
        and not trust.is_relative_to(root)
        and trust == trust.resolve(strict=True)
    )
    key_files.validate(trust.lstat())
    state = safe_child(root, ".runtime")
    _need(not state.exists() or not any(state.iterdir()))
    # The transfer left an empty .runtime. Claim this attempt outside it so
    # initialize can check the fresh directory and import the original trust key.
    temporary = native.owner_path(root, os.environ).parent
    claim = safe_child(temporary, f"original-bootstrap-{owner['run_id']}-{owner['run_attempt']}")
    claim.mkdir(mode=0o700, exist_ok=False)
    bootstrap.initialize(root, state, trust_key_path=trust)
    workspace = storage_pki.workspace_id(state)
    progress = dict(
        code="original_bootstrap_failed",
        stage="capacity",
        cluster_cleanup_unconfirmed=False,
        sql_cleanup_unconfirmed=False,
    )
    cluster_pending, sql_pending = False, False
    marker = None
    try:
        capacity = read_json(safe_child(state, "inventory.json"))
        _need(
            capacity["docker_cpus"] >= 4
            and capacity["docker_memory_bytes"] >= 15 * 1024**3
            and capacity["disk_free_bytes"] >= 12 * 1024**3
        )
        progress["stage"] = "tools"
        install_ci_tools.main()
        os.environ["PATH"] = str(safe_child(state, "bin")) + os.pathsep + os.environ["PATH"]
        progress["stage"] = "cluster_start"
        cluster_pending = True
        cluster_owner.start(root, state)
        progress["stage"] = "sql_start"
        sql_pending = True
        ready = sql.bootstrap(state)
        marker = sql.validate(state)
        native.same(marker, dict(workspace_id=workspace))
        native.same(ready, dict(status="ready", container_id=marker["container_id"]))
        write_json(safe_child(state, "evidence/storage-bootstrap.json"), ready)
        _evaluate(root, state, workspace, source, progress)
        progress["stage"] = "cluster_cleanup"
        cluster_pending = False  # A failed deletion acknowledgement goes to owned recovery.
        cluster_owner.cleanup(state)
        progress["stage"] = "source_readback"
        authorize()
        progress["stage"] = "sql_readback"
        _need(sql.validate(state) == marker)
        with storage.connect(safe_child(state, "storage-clients/publisher")) as connection:
            _need(connection.execute("SELECT current_user").fetchone() == ("ml_publisher",))
        producer.require_unproposed(state)
        return dict(state=state, run_owner=owner, source=source)
    except BaseException as primary:
        progress["cluster_cleanup_unconfirmed"] = progress["stage"] == "cluster_cleanup"
        if cluster_pending:
            try:
                cluster_owner.cleanup(state)
            except BaseException:
                progress["cluster_cleanup_unconfirmed"] = True
        if progress["cluster_cleanup_unconfirmed"]:
            primary.add_note("producer_cluster_cleanup_unconfirmed")
        if sql_pending:
            try:
                current = sql.validate(state)
                _need(
                    current["workspace_id"] == workspace and (marker is None or current == marker)
                )
                recovery.stop_owned(state)
                receipt.offline_pin(state)
            except BaseException:
                progress["sql_cleanup_unconfirmed"] = True
                primary.add_note("producer_sql_cleanup_unconfirmed")
        # Neither exception messages, custom class names nor arbitrary notes go on disk.
        try:
            _need(storage_pki.workspace_id(state) == workspace)
            progress["exception_class"] = next(
                (cls.__name__ for cls in ERROR_CLASSES if isinstance(primary, cls)), "OtherError"
            )
            write_json(
                safe_child(state, "evidence/original-bootstrap-error.private.json"), progress
            )
        except BaseException:
            primary.add_note("producer_private_diagnostic_unavailable")
        raise


def prepare(root, *, source_api, trust_key_path, image_receipt):
    """Return state, run_owner and source for publish_original in this same checkout."""
    # Close the isolation scope normally: the trusted caller retains the original
    # exception and cleanup notes, while inherited environment and fds stay private.
    with closing(ExitStack()) as scope:
        scope.enter_context(private_process())
        prepared = _bootstrap(
            Path(root),
            source_api=source_api,
            trust_key_path=trust_key_path,
            image_receipt=image_receipt,
        )
        tool_path = os.environ["PATH"]
    # publish_original rechecks cluster cleanup with kind in this same process.
    os.environ["PATH"] = tool_path
    return prepared


def main(arguments=None):
    try:
        _need((sys.argv[1:] if arguments is None else arguments) == ["prepare"])
        prepare(
            Path.cwd(),
            source_api=PublicClient(os.environ.pop("CANDIDATE_PUBLIC_TOKEN")),
            trust_key_path=os.environ.pop("CANDIDATE_TRUST_FILE"),
            image_receipt=decode(os.environ.pop("SOURCE_IMAGE_RECEIPT").encode(), limit=4096),
        )
    except (Exception, KeyboardInterrupt, SystemExit):
        print("original_bootstrap=refused")
        return 1
    print("original_bootstrap=pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
