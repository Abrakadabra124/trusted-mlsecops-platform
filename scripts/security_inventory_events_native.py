"""Actual trained candidate SQL reads and controlled graph faults on hosted CI."""

import argparse
import copy
import os
import subprocess
import sys
import time
from pathlib import Path

from mlsecops import security_event_delivery
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json, safe_child
from mlsecops.inventory import command, source_fingerprint
from mlsecops.sandbox import resolve_image
from mlsecops.storage_bootstrap import validate
from scripts import security_event_audit_fixture as audit_fixture
from scripts.asset_graph_fixture import ENVIRONMENT, fixture
from scripts.asset_graph_fixture import OWNERS as GRAPH_OWNERS
from scripts.candidate_lineage_native import KNOWN_OWNERS, OWNERS, metadata_snapshot


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
    cases, durations = [], []

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

        def observe(mode, request, *, accepted, bad_pin=False):
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
            started = time.monotonic()
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
            durations.append(time.monotonic() - started)
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

        result = observe("candidate", candidate, accepted=True)
        check(
            "actual-trained-candidate-verified-without-event",
            result["subject_sha256"] == context["candidate_reference"] and records() == [],
        )
        altered = copy.deepcopy(candidate)
        altered["context"]["expected"]["source_revision"] = "0" * 40
        observe("candidate", altered, accepted=False)
        check(
            "actual-sql-candidate-build-mismatch-has-receipt",
            len(records()) == 1 and records()[0]["receipt"] is not None,
        )
        fx.stop()
        altered["context"]["expected"] = {**expected, "image_id": "sha256:" + "f" * 64}
        observe("candidate", altered, accepted=False)
        pending = records()[-1]
        check(
            "offline-mismatch-durable-before-delivery",
            len(records()) == 2 and pending["receipt"] is None,
        )
        before = records()
        observe("candidate", altered, accepted=False)
        check("pending-outage-prevents-another-observation", records() == before)
        fx.start()
        check("same-outbox-retry-delivered-one-event", emitter().retry() == 1)
        check(
            "original-envelope-preserved-after-restart",
            records()[-1]["envelope"] == pending["envelope"]
            and records()[-1]["receipt"] is not None,
        )
        observe("candidate", candidate, accepted=True)
        check("valid-candidate-retry-adds-no-event", len(records()) == 2)
        missing = copy.deepcopy(candidate)
        missing["context"]["candidate_reference"] = "0" * 64
        observe("candidate", missing, accepted=False)
        check("missing-sql-object-not-invented-mismatch", len(records()) == 2)

        graph, snapshot, revoked = fixture()
        graph_request = dict(
            document=graph,
            snapshot=snapshot,
            revoked=revoked,
            trusted_owners=GRAPH_OWNERS,
            environment=ENVIRONMENT,
        )
        observe("graph", graph_request, accepted=True)
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
            observe("graph", request, accepted=False)
        before = records()
        observe("candidate", candidate, accepted=False, bad_pin=True)
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
    check(
        "collector-process-port-and-private-state-cleanup",
        fx.process is None and not fx.directory.exists(),
    )
    check(
        "source-sql-unchanged-and-owned",
        metadata_snapshot(state) == before_sql
        and validate(state)["container_id"] == marker["container_id"],
    )
    check(
        "runtime-source-and-image-unchanged",
        source_fingerprint(root) == fingerprint
        and resolve_image(image) == image_id
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    return dict(
        source=revision,
        fingerprint=fingerprint,
        cases=cases,
        status="pass",
        release_ready=False,
        candidate_reference=context["candidate_reference"],
        max_cli_seconds=max(durations),
        scope="actual-candidate-sql-and-controlled-graph-not-full-M19-M23",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    options = parser.parse_args()
    print(canonical(qualify(options.state, options.image)).decode())
