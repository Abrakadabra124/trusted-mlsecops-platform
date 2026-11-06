"""Real HTTP and SQL trust for controlled signer transitions, never actual ML assurance."""

import argparse
import copy
import sys
import time
import uuid
from contextlib import suppress
from pathlib import Path

import psycopg

from mlsecops import (
    promotion,
    promotion_state,
    release_key_rotation,
    release_key_store,
    release_policy,
    release_reader,
    serving,
    storage_bootstrap,
    storage_snapshot,
    trust,
    trust_authority,
)
from mlsecops.contracts import Rejected, canonical, digest, now, safe_child, write_json
from mlsecops.datasets import FEATURES
from mlsecops.inventory import command, source_fingerprint
from mlsecops.sandbox import resolve_image
from scripts import promotion_qualification as fixtures
from scripts import release_signer_fixture, release_signer_probe, serving_native
from scripts.release_reader_native import disposable


def snapshot(state):
    marker = storage_bootstrap.validate(state)
    with storage_snapshot.snapshot(marker["name"], include_promotion=True) as observed:
        return {field: observed[field] for field in ("tables", "promotion")}


def qualify(root, state, image):
    state = Path(state).resolve()
    original = snapshot(state)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("signer_serving_source_dirty")
    fingerprint = source_fingerprint(root)
    image = resolve_image(image)
    started, campaign = now(), uuid.uuid4().hex
    cases, transitions, workers, retired = [], {}, set(), set()

    def confirmed(label, condition):
        case = {
            "id": label,
            "status": "pass" if condition is True else "fail",
            "expected": True,
            "actual": condition,
        }
        if case["status"] != "pass":
            print(canonical({"case": label, "status": "fail"}).decode(), flush=True)
            raise Rejected("signer_serving_invariant")
        cases.append(case)
        print(canonical({"case": label, "status": "pass"}).decode(), flush=True)

    def rejected(label, operation, reason):
        try:
            operation()
        except Rejected as error:
            confirmed(label, str(error) == reason)
        else:
            confirmed(label, False)

    fixtures.PromotionAdmissionContracts.setUpClass()
    fixture = fixtures.PromotionAdmissionContracts()
    try:
        fixture.setUp()
        features, scores = serving_native.bind_real_runtime(fixture, image)
        model = digest(fixture.fixture.bundle.materials.fixture.model)
        body = {
            "schema_version": 1,
            "instances": [dict(zip(FEATURES, row, strict=True)) for row in features],
        }
        with (
            disposable(root, state, campaign, "signer-models", 15444) as models,
            disposable(root, state, campaign, "signer-trust", 15445) as authority,
        ):
            promoter, client = (
                models / "storage-clients/promoter",
                models / "storage-clients/serving",
            )
            trust_client = authority / "storage-clients/serving"
            public, key = fixture.trust_fixture.public, fixture.trust_fixture.key
            promotion_state.install(models)
            release_key_store.migrate(models)
            promotion_state.configure(models, "local-cpu", fixture.arguments["expected_policy"])
            trust_authority.install(authority, "local-cpu", public)
            online = trust_authority.update(authority, fixture.arguments["expected_policy"], key)

            def lease():
                return trust.Lease(
                    lambda: trust_authority.read(trust_client, "local-cpu", public),
                    trusted_root=public,
                    environment="local-cpu",
                    minimum_version=online["version"],
                )

            def options():
                return copy.deepcopy(
                    {
                        field: fixture.arguments[field]
                        for field in (
                            "context",
                            "trusted_root",
                            "expected_policy",
                            "expected_serving_image",
                        )
                    }
                )

            def reader(configuration, sequence):
                return release_reader.Reader(
                    client, **configuration, trust_lease=lease(), minimum_sequence=sequence
                )

            def golden(label, request, subject):
                status, result = request("/v1/predict", body)
                confirmed(label + "-http-200", status == 200)
                confirmed(
                    label + "-model-and-subject",
                    result["model_sha256"] == model and result["bundle_sha256"] == subject,
                )
                predictions = result["predictions"]
                confirmed(
                    label + "-prediction-shape",
                    len(predictions) == len(scores)
                    and all(
                        item["decision"] == "score"
                        and type(item["score"]) in (int, float)
                        and 0 <= item["score"] <= 1
                        for item in predictions
                    ),
                )
                error = max(
                    abs(float(item["score"]) - float(score))
                    for item, score in zip(predictions, scores, strict=True)
                )
                confirmed(label + "-golden-1e-6", error <= 1e-6)
                return error

            selection = promotion.promote(promoter, trust_lease=lease(), **fixture.arguments)
            confirmed(
                "initial-controlled-release-recorded-not-ready", selection["release_ready"] is False
            )
            for role in release_policy.ROLES:
                print(canonical({"stage": "live-release-signer-" + role}).decode(), flush=True)
                before_options = options()
                head = {field: selection[field] for field in ("sequence", "request_sha256")}
                old = serving.Engine(reader(before_options, head["sequence"]))
                with serving_native.site(old) as old_http:
                    before_error = golden(role + "-before", old_http, selection["subject_sha256"])
                    old_worker = old.worker.container
                    workers.add(old_worker)
                    package = release_signer_fixture.prepare(
                        fixture, image, role=role, head=head, clock=int(time.time())
                    )
                    verified = release_key_rotation.verify(
                        package,
                        trusted_root=fixture.arguments["trusted_root"],
                        expected_policy=before_options["expected_policy"],
                        head=head,
                        environment="local-cpu",
                        clock=int(time.time()),
                    )
                    retired.add(verified["previous_key"])

                    def revoke():
                        nonlocal online
                        online = trust_authority.update(
                            authority,
                            fixture.arguments["expected_policy"],
                            key,
                            revoked_keys=[verified["previous_key"]],
                        )
                        return online

                    trace = release_signer_probe.observe_refusal(old_http, body, revoke)
                    confirmed(
                        role + "-online-policy-denies-old-handoff", old_http("/readyz")[0] == 503
                    )
                    rejected(
                        role + "-cold-before-store-policy-change",
                        reader(before_options, head["sequence"]).load,
                        "trust_policy_changed",
                    )
                    old.drain()
                    confirmed(
                        role + "-old-worker-removed",
                        not command(
                            [
                                "docker",
                                "container",
                                "ls",
                                "--all",
                                "--quiet",
                                "--filter",
                                f"id={old_worker}",
                            ]
                        ),
                    )
                    rotation = release_key_store.rotate(
                        models,
                        package,
                        trusted_root=fixture.arguments["trusted_root"],
                        expected_policy=before_options["expected_policy"],
                        environment="local-cpu",
                        lease=lease(),
                    )
                    confirmed(
                        role + "-rotation-preserves-head-not-ready",
                        rotation["head"] == head and rotation["release_ready"] is False,
                    )
                    rejected(
                        role + "-old-config-after-store",
                        reader(before_options, head["sequence"]).load,
                        "serving_head_binding",
                    )
                    rejected(
                        role + "-new-policy-with-old-selection",
                        reader(options(), head["sequence"]).load,
                        "serving_selection_binding",
                    )
                    before_denial = snapshot(models)
                    missing = {
                        gate: content
                        for gate, content in fixture.arguments["reports"].items()
                        if gate != "M22"
                    }
                    rejected(
                        role + "-missing-M22-not-approved",
                        lambda: promotion.promote(
                            promoter,
                            trust_lease=lease(),
                            **{**fixture.arguments, "reports": missing},
                        ),
                        "release_gate_set_incomplete",
                    )
                    confirmed(
                        role + "-denied-release-no-journal-write", snapshot(models) == before_denial
                    )
                    next_selection = promotion.promote(
                        promoter, trust_lease=lease(), **fixture.arguments
                    )
                    confirmed(
                        role + "-new-selection-with-new-subject",
                        next_selection["sequence"] == head["sequence"] + 1
                        and next_selection["subject_sha256"] != selection["subject_sha256"]
                        and next_selection["release_ready"] is False,
                    )
                    confirmed(
                        role + "-no-auto-reactivation",
                        old_http("/v1/predict", body)[0] == 503 and old_http("/readyz")[0] == 503,
                    )
                    fresh = serving.Engine(reader(options(), next_selection["sequence"]))
                    with serving_native.site(fresh) as new_http:
                        after_error = golden(
                            role + "-after", new_http, next_selection["subject_sha256"]
                        )
                        workers.add(fresh.worker.container)
                        confirmed(
                            role + "-explicit-new-worker", fresh.worker.container != old_worker
                        )
                        confirmed(
                            role + "-old-instance-remains-fenced",
                            old_http("/v1/predict", body)[0] == 503,
                        )
                    selection = next_selection
                    transitions[role] = {
                        "trace": trace,
                        "rotation": rotation,
                        "selection": selection,
                        "before_golden_error": before_error,
                        "after_golden_error": after_error,
                        "retired_key_sha256": verified["previous_key"],
                        "successor_key_sha256": verified["next_key"],
                        "model_sha256": model,
                        "release_ready": False,
                    }
                confirmed(
                    role + "-worker-cleanup",
                    all(
                        not command(
                            [
                                "docker",
                                "container",
                                "ls",
                                "--all",
                                "--quiet",
                                "--filter",
                                f"id={identifier}",
                            ]
                        )
                        for identifier in workers
                    ),
                )
            final = snapshot(models)
            tables = final["promotion"]["tables"]
            confirmed(
                "final-three-rotations-four-events",
                tables["policy_rotations"]["rows"] == 3
                and tables["events"]["rows"] == 4
                and tables["heads"]["rows"] == 1,
            )
            _, current = trust_authority.current(authority)
            payload = trust.validate(current["envelope"], public, "local-cpu", int(time.time()))
            confirmed(
                "all-retired-keys-stay-revoked",
                payload["version"] == 4
                and payload["revoked_keys"] == sorted(retired)
                and payload["promotion_policy_sha256"] == fixture.arguments["expected_policy"],
            )
            history = digest(canonical(final))
        confirmed("owned-databases-removed", not models.exists() and not authority.exists())
        confirmed(
            "source-state-and-revision-unchanged",
            snapshot(state) == original
            and source_fingerprint(root) == fingerprint
            and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
            and not command(["git", "-C", str(root), "status", "--porcelain"]),
        )
    finally:
        fixture.doCleanups()
        fixtures.PromotionAdmissionContracts.tearDownClass()
    return {
        "schema_version": 1,
        "scope": "controlled-release-signer-live-trust-and-HTTP-not-full-M11",
        "status": "pass",
        "release_ready": False,
        "campaign_id": campaign,
        "source_revision": revision,
        "source_fingerprint": fingerprint,
        "source_dirty": False,
        "image_id": image,
        "started_at": started,
        "finished_at": now(),
        "cases": cases,
        "transitions": transitions,
        "model_snapshot_sha256": history,
        "model_sha256": model,
        "workers_removed": len(workers),
        "limitations": [
            "Real SQL, signatures, ONNX worker and HTTP; controlled release reports",
            "No actual independent M22 assurance or production release approval",
            "Full candidate-bound M11/M18/R1 remain incomplete",
        ],
    }


def main(arguments=None):
    parser = argparse.ArgumentParser(description="Disposable live release signer qualification")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--worker-image", required=True)
    parser.add_argument("--confirm-disposable", action="store_true", required=True)
    options = parser.parse_args(arguments)
    output = None
    try:
        storage_bootstrap.validate(options.state)
        output = safe_child(options.state, "evidence/release-key-serving.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        report = qualify(Path(__file__).resolve().parents[1], options.state, options.worker_image)
        write_json(output, report)
        print(canonical({**report, "cases": len(report["cases"])}).decode())
        return 0
    except (Rejected, psycopg.Error, OSError, KeyError, TypeError, ValueError, RuntimeError):
        if output is not None:
            with suppress(Rejected, OSError):
                write_json(output, {"status": "fail", "release_ready": False})
        print("Live signer qualification failed; inspect the last scoped stage", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
