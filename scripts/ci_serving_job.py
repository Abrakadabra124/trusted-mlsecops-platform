"""Hosted receiver for the original producer's frozen M13/M14/M15 candidate."""

import os
import secrets
import sys
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout

from mlsecops import storage_pki
from mlsecops.contracts import Rejected, canonical, require_fields, safe_child, write_json
from scripts import ci_campaign_handoff as handoff
from scripts import ci_serving_native as native

LOCAL = ".runtime/ci-serving-job"
# Clients carry their credentials in memory. Child processes only need the runner
# identity, tool paths and ordinary OS settings, never the workflow's secrets.
RUNNER_ENV = frozenset(
    """HOME PATH USER LOGNAME SHELL TMPDIR TMP TEMP LANG LC_ALL TZ VIRTUAL_ENV
    RUNNER_TEMP RUNNER_ENVIRONMENT RUNNER_OS RUNNER_ARCH ImageOS
    GITHUB_ACTIONS GITHUB_WORKSPACE GITHUB_REPOSITORY GITHUB_REPOSITORY_ID
    GITHUB_EVENT_NAME GITHUB_REF GITHUB_WORKFLOW_REF GITHUB_WORKFLOW_SHA
    GITHUB_SHA GITHUB_JOB GITHUB_RUN_ID GITHUB_RUN_ATTEMPT""".split()
)
COMMAND_FILES = (
    "GITHUB_OUTPUT",
    "GITHUB_ENV",
    "GITHUB_PATH",
    "GITHUB_STATE",
    "GITHUB_STEP_SUMMARY",
)


@contextmanager
def private_process():
    before = dict(os.environ)
    inherited = {k: os.environ[k] for k in RUNNER_ENV if k in os.environ}
    with open(os.devnull, "w", encoding="utf-8") as sink, ExitStack() as restore:
        sys.stdout.flush()
        sys.stderr.flush()
        for fd in (1, 2):
            original = os.dup(fd)
            restore.callback(os.close, original)
            restore.callback(os.dup2, original, fd)
            os.dup2(sink.fileno(), fd)
        restore.enter_context(redirect_stdout(sink))
        restore.enter_context(redirect_stderr(sink))
        try:
            os.environ.clear()
            os.environ.update(inherited)
            os.environ.update(dict.fromkeys(COMMAND_FILES, os.devnull))
            yield
        except BaseException as primary:
            # Private reader exceptions may contain paths or raw API responses.
            error = (
                KeyboardInterrupt()
                if isinstance(primary, KeyboardInterrupt)
                else Rejected("ci_serving_job_failed")
            )
            if "serving_cleanup_unverified" in getattr(primary, "__notes__", ()):
                error.add_note("serving_cleanup_unverified")
            raise error from None
        finally:
            os.environ.clear()
            os.environ.update(before)


def admit(root, source_api, run_owner, source):
    from scripts.ci_campaign_guard import authorize

    authorize(root, source_api=source_api, job="serving", run_owner=run_owner, source=source)
    return run_owner | {"producer_job": "serving"}


def cleanup(root, *, source_api, run_owner, source):
    """Repeat re-observation on the same runner from its independent local journal."""
    with private_process():
        actual = admit(root, source_api, run_owner, source)
        progress = {}
        native.recover(safe_child(root, LOCAL), source, actual, progress)
        return progress["cleanup"]


def run(root, *, source_api, api, trust_key_path, key, trusted_public, run_owner, source):
    """Return a private replay receipt. Caller supplies independent public and private clients."""
    run_owner, source = run_owner.copy(), source.copy()
    with private_process():
        actual = admit(root, source_api, run_owner, source)
        local = safe_child(root, LOCAL)
        local.mkdir(mode=0o700, parents=True, exist_ok=False)
        write_json(
            local / "workspace.json",
            dict(product="trusted-mlsecops", schema_version=1, workspace_id=secrets.token_hex(16)),
        )
        progress = dict(gate_counts={}, cleanup={})
        with native.cleanup_on_error(local, source, actual, progress):
            with handoff.open_consumer(
                root,
                job="serving",
                api=api,
                trust_key_path=trust_key_path,
                key=key,
                trusted_public=trusted_public,
                run_owner=run_owner,
                source=source,
            ) as (state, prepared, record, packets):
                owner, origin = record["owner"], record["origin"]
                signed_owner = canonical(owner)
                upstream_pins = record["reports"].copy()
                native.need(canonical(owner["run_owner"]) == canonical(run_owner))
                native.need(
                    {k: owner["expected"][k] for k in native.transfer.delivery.SOURCE} == source
                )
                require_fields(packets, handoff.JOBS["serving"])
                sealed = {k.removesuffix("-serving"): v for k, v in packets.items()}
                candidate = sealed["candidate"]
                native.need(
                    prepared["manifest_sha256"] == candidate["manifest_sha256"]
                    and prepared["ciphertext_sha256"] == candidate["ciphertext_sha256"]
                )
                workspace = storage_pki.workspace_id(state)
                native.need(
                    workspace == prepared["workspace_id"]
                    and len({workspace, storage_pki.workspace_id(local), origin["workspace_id"]})
                    == 3
                )
                with native.cleanup_on_error(local, source, actual, progress):
                    destination, index_pin, arguments = native.consumer(
                        root,
                        local,
                        state,
                        prepared,
                        owner,
                        sealed,
                        key,
                        progress,
                        origin,
                        None,  # Only a same-job caller has a locally observed producer SQL pin.
                        record["reports"],
                        cleanup_owner=actual,
                    )
                    native.need(
                        native.shared_serving_receipt.offline_pin(state)
                        == progress["consumer_offline"]
                    )
            native.need(not os.path.lexists(state))
            native.recover(local, source, actual, progress)
            native.need(canonical({k: arguments[k] for k in owner}) == signed_owner)
            native.need({k: arguments["report_pins"][k] for k in upstream_pins} == upstream_pins)
            replay = native.exporter.replay(root, destination, index_pin=index_pin, **arguments)
            native.need(replay["release_ready"] is False)
            native.need(native.driver.source(root, native.driver.IMAGE) == source)
            return dict(
                destination=destination,
                index_pin=index_pin,
                arguments=arguments,
                replay=replay,
                origin=origin,
                consumer_offline=progress["consumer_offline"],
                cleanup_owner=actual,
                cleanup=progress["cleanup"],
                gate_counts=progress["gate_counts"],
                release_ready=False,
            )
