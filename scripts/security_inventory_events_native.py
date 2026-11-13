"""Actual trained candidate SQL reads and controlled graph faults on hosted CI."""

import copy
import os
import subprocess
import sys
import time
from pathlib import Path

from mlsecops import candidate_lineage, security_event_delivery
from mlsecops import security_inventory_evidence as evidence
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.private_cli import Arguments
from mlsecops.sandbox import resolve_image
from mlsecops.storage_bootstrap import validate
from scripts import security_event_audit_fixture as audit_fixture
from scripts import security_source_capture
from scripts.asset_graph_fixture import ENVIRONMENT, fixture
from scripts.asset_graph_fixture import OWNERS as GRAPH_OWNERS
from scripts.candidate_lineage_native import KNOWN_OWNERS, OWNERS, metadata_snapshot


def retain_primary(path, packet, **expectations):
    """Persist terminal primary and existing owner inputs, then reread both.

    The sidecar is not new authority. A later owner must pin its canonical hash
    from the successful public summary before using its expected parameters.
    """
    checked = evidence.verify(packet, **expectations)
    binding = dict(
        schema_version=1,
        scope="inventory-owner-inputs-not-new-authority",
        expected=copy.deepcopy(expectations),
    )
    if len(canonical(binding)) > 16384:
        raise Rejected("inventory_binding_size")
    binding_path = Path(path).with_suffix(".bindings.json")
    write_json(path, packet)
    write_json(binding_path, binding)
    retained = read_json(path)
    retained_binding = read_json(binding_path)
    if canonical(retained_binding) != canonical(binding):
        raise Rejected("inventory_binding_readback_mismatch")
    result = evidence.verify(retained, **expectations)
    if result != checked or canonical(retained) != canonical(packet):
        raise Rejected("inventory_primary_readback_mismatch")
    return {**result, "binding_sha256": digest(canonical(binding))}


def capture_delivery(fx, emitter, *, collector_snapshot=None):
    """Capture in memory using the shared helper; fixture still owns removal."""
    incidents = security_source_capture.read_incidents(fx)
    fx.stop()
    return security_source_capture.capture_delivery(
        fx,
        [emitter()],
        incidents=incidents,
        collector_snapshot=collector_snapshot,
    )


def qualify(state, image):
    if (
        sys.platform != "linux"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise Rejected("inventory_security_hosted_required")
    root, state = Path(__file__).resolve().parents[1], Path(state).resolve()
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("inventory_security_dirty_source")
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint = source_fingerprint(root)
    marker = validate(state)
    before_sql = metadata_snapshot(state)
    demo, trust = (
        read_json(safe_child(state, name)) for name in ("storage-demo.json", "storage-trust.json")
    )
    image_id = resolve_image(image)
    expected = dict(image_id=image_id, source_fingerprint=fingerprint, source_revision=revision)
    context = dict(
        candidate_reference=demo["candidate"]["candidate_reference"],
        evaluation_reference=demo["evaluation_reference"],
        policy=read_json(root / "policies/local-cpu.json"),
        trust=trust,
        expected=expected,
        owners=OWNERS,
        known_owners=KNOWN_OWNERS,
    )
    candidate = dict(
        metadata_client=str(safe_child(state, "storage-clients/publisher")),
        review_client=str(safe_child(state, "storage-clients/promoter")),
        context=context,
    )
    # Existing SQL candidate only. This collects finite bindings, never trains.
    projection = candidate_lineage.collect(
        candidate["metadata_client"], candidate["review_client"], **context
    )
    bindings = dict(
        candidate_reference=context["candidate_reference"],
        evaluation_reference=context["evaluation_reference"],
        model_sha256=next(
            asset["sha256"] for asset in projection["graph"]["assets"] if asset["kind"] == "model"
        ),
        **expected,
    )
    methods = {name: digest(bounded_read(root / name)) for name in evidence.METHODS}
    cases, durations, observations = [], [], []

    def check(name, condition):
        if not condition:
            raise Rejected("inventory_security_case:" + name)
        cases.append(name)

    with audit_fixture.live() as fx:
        producer = decode(fx.audit_config.read_bytes())
        producer["schema_version"] = 1
        fx.write("inventory-producer.json", canonical(producer))
        producer_path = str(fx.directory / "inventory-producer.json")

        def emitter():
            return security_event_delivery.configured(producer_path)

        def records():
            return emitter().store.snapshot()["records"]

        def observe(case_id, mode, request, *, accepted, bad_pin=False):
            body = canonical(request)
            fx.write("inventory-request.json", body)
            config = dict(
                schema_version=1,
                mode=mode,
                request_file=str(fx.directory / "inventory-request.json"),
                request_sha256="0" * 64 if bad_pin else digest(body),
                producer_config=producer_path,
            )
            fx.write("inventory-config.json", canonical(config))
            before_records = records()
            started_at = fx.now()
            started = time.monotonic_ns()
            result = subprocess.run(
                [
                    sys.executable,
                    "-W",
                    "error",
                    "-m",
                    "mlsecops.security_inventory_events",
                    "--config",
                    str(fx.directory / "inventory-config.json"),
                ],
                cwd=root,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                timeout=30,
                check=False,
                env={**os.environ, "PYTHONUTF8": "1"},
            )
            elapsed = time.monotonic_ns() - started
            finished_at = fx.now()
            durations.append(elapsed / 1_000_000_000)
            after_records = records()
            event_id = None
            if len(after_records) == len(before_records) + 1:
                record = after_records[-1]
                event_id = fx.registry.verify(
                    record["envelope"], clock_ms=record["queued_at_ms"]
                ).document()["event_id"]
            observations.append(
                dict(
                    case_id=case_id,
                    subject_kind="controlled-graph" if mode == "graph" else "actual-sql-candidate",
                    subject_sha256=digest(body)
                    if mode == "graph"
                    else request["context"]["candidate_reference"],
                    request_sha256=digest(body),
                    configured_request_sha256=config["request_sha256"],
                    candidate_request=None
                    if mode == "graph"
                    else copy.deepcopy(
                        {
                            key: request["context"][key]
                            for key in ("candidate_reference", "evaluation_reference", "expected")
                        }
                    ),
                    graph_request=copy.deepcopy(request) if mode == "graph" else None,
                    decision="verified" if accepted else "inventory_security_rejected",
                    returncode=result.returncode,
                    started_at_ms=started_at,
                    finished_at_ms=finished_at,
                    elapsed_ns=elapsed,
                    before_count=len(before_records),
                    after_count=len(after_records),
                    event_id=event_id,
                )
            )
            if accepted:
                check(
                    "separate-observer-cli-success", result.returncode == 0 and result.stderr == b""
                )
                value = decode(result.stdout)
                check(
                    "no-release-authority-or-payload-output",
                    value["state"] == "verified"
                    and value["release_ready"] is False
                    and value["full_M19"] == "inconclusive"
                    and set(value)
                    == {"state", "subject_sha256", "scope", "full_M19", "release_ready"},
                )
                return value
            check(
                "private-cli-refusal",
                result.returncode == 1
                and result.stdout == b""
                and result.stderr == b"inventory_security_rejected\n",
            )
            return None

        result = observe("candidate-valid", "candidate", candidate, accepted=True)
        check(
            "actual-trained-candidate-verified-without-event",
            result["subject_sha256"] == context["candidate_reference"] and records() == [],
        )
        altered = copy.deepcopy(candidate)
        altered["context"]["expected"]["source_revision"] = "0" * 40
        observe("candidate-source-mismatch", "candidate", altered, accepted=False)
        check(
            "actual-sql-candidate-build-mismatch-has-receipt",
            len(records()) == 1 and records()[0]["receipt"] is not None,
        )
        fx.stop()
        altered["context"]["expected"] = {**expected, "image_id": "sha256:" + "f" * 64}
        observe("candidate-image-mismatch-offline", "candidate", altered, accepted=False)
        pending = records()[-1]
        check(
            "offline-mismatch-durable-before-delivery",
            len(records()) == 2 and pending["receipt"] is None,
        )
        before = records()
        observe("candidate-blocked-pending", "candidate", altered, accepted=False)
        check("pending-outage-prevents-another-observation", records() == before)
        fx.start()
        retry_start, retry_mono = fx.now(), time.monotonic_ns()
        delivered = emitter().retry()
        retry_elapsed, retry_end = time.monotonic_ns() - retry_mono, fx.now()
        retry = dict(
            pending_record=copy.deepcopy(pending),
            started_at_ms=retry_start,
            finished_at_ms=retry_end,
            elapsed_ns=retry_elapsed,
            delivered=delivered,
        )
        check("same-outbox-retry-delivered-one-event", delivered == 1)
        check(
            "original-envelope-preserved-after-restart",
            records()[-1]["envelope"] == pending["envelope"]
            and records()[-1]["receipt"] is not None,
        )
        observe("candidate-valid-after-retry", "candidate", candidate, accepted=True)
        check("valid-candidate-retry-adds-no-event", len(records()) == 2)
        missing = copy.deepcopy(candidate)
        missing["context"]["candidate_reference"] = "0" * 64
        observe("candidate-missing", "candidate", missing, accepted=False)
        check("missing-sql-object-not-invented-mismatch", len(records()) == 2)

        graph, snapshot, revoked = fixture()
        graph_request = dict(
            document=graph,
            snapshot=snapshot,
            revoked=revoked,
            trusted_owners=GRAPH_OWNERS,
            environment=ENVIRONMENT,
        )
        observe("graph-valid", "graph", graph_request, accepted=True)
        graph_subjects = []
        for reason in ("digest", "owner", "dangling", "cycle"):
            request = copy.deepcopy(graph_request)
            if reason == "digest":
                request["snapshot"]["deployments"][0]["model_sha256"] = "f" * 64
            elif reason == "owner":
                request["document"]["assets"][0]["owner"] = "private-canary"
            elif reason == "dangling":
                request["snapshot"]["deployments"].pop()
            else:
                asset = request["document"]["assets"][0]
                asset["dependencies"] = [dict(asset_id=asset["asset_id"], sha256=asset["sha256"])]
                request["snapshot"]["graph_sha256"] = digest(canonical(request["document"]))
            graph_subjects.append(digest(canonical(request)))
            observe("graph-" + reason, "graph", request, accepted=False)
        before = records()
        observe("candidate-request-pin", "candidate", candidate, accepted=False, bad_pin=True)
        check("operator-request-pin-refusal-without-event", records() == before)
        check("six-actual-source-decisions-retained", len(before) == 6)
        reasons, subjects, identities = [], [], []
        for record in before:
            event = fx.registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
            fx.registry.receipt(record["receipt"], event)
            value = event.document()
            check(
                "authenticated-inventory-route-" + str(value["sequence"]),
                event.route == "security.inventory"
                and value["kind"] == "inventory.mismatch"
                and value["bundle_sha256"] is None,
            )
            reasons.append(value["reason"])
            subjects.append(value["asset_sha256"])
            identities.append(value["event_id"])
        check(
            "bounded-reasons-and-source-subjects",
            reasons == ["digest", "digest", "digest", "owner", "dangling", "cycle"]
            and subjects == [context["candidate_reference"]] * 2 + graph_subjects
            and len(set(identities)) == 6,
        )
        check("private-input-not-in-outbox", b"private-canary" not in canonical(before))
        check("exact-receipt-retry-idempotent", emitter().retry() == 0 and records() == before)
        bundle = capture_delivery(fx, emitter)
        expected_root, expected_pin = fx.fx.publics["root"], fx.registry.sha256
    check(
        "collector-process-port-and-private-state-cleanup",
        fx.process is None and not fx.directory.exists(),
    )
    after_sql, after_marker = metadata_snapshot(state), validate(state)
    check(
        "source-sql-unchanged-and-owned",
        after_sql == before_sql and after_marker["container_id"] == marker["container_id"],
    )
    check(
        "runtime-source-and-image-unchanged",
        source_fingerprint(root) == fingerprint
        and resolve_image(image) == image_id
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    check(
        "inventory-methods-unchanged",
        methods == {name: digest(bounded_read(root / name)) for name in evidence.METHODS},
    )
    packet = dict(
        schema_version=1,
        scope=evidence.SCOPE,
        source=revision,
        fingerprint=fingerprint,
        methods=methods,
        bindings=bindings,
        observations=observations,
        bundle=bundle,
        retry=retry,
        cleanup=dict(
            collector_process_stopped=True,
            collector_port_closed=True,
            fixture_removed=True,
            confirmed_at_ms=fx.now(),
        ),
        sql=dict(
            before=before_sql,
            after=after_sql,
            owned_container_before=marker["container_id"],
            owned_container_after=after_marker["container_id"],
            source_sql_cleanup="caller-owned-not-performed",
        ),
    )
    retained = retain_primary(
        safe_child(state, "evidence/security-inventory-primary.json"),
        packet,
        expected_source=revision,
        expected_fingerprint=fingerprint,
        expected_methods=methods,
        expected_candidate=bindings,
        expected_root=expected_root,
        expected_pin=expected_pin,
    )
    return dict(
        source=revision,
        fingerprint=fingerprint,
        cases=cases,
        status="pass",
        release_ready=False,
        candidate_reference=context["candidate_reference"],
        max_cli_seconds=max(durations),
        scope=evidence.SCOPE,
        primary_sha256=retained["primary_sha256"],
        binding_sha256=retained["binding_sha256"],
    )


def main(arguments=None):
    parser = Arguments()
    parser.add_argument("--state", required=True)
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    try:
        options = parser.parse_args(arguments)
        print(canonical(qualify(options.state, options.image)).decode())
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("inventory_security_native_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
