import argparse
import shutil
import sys
import uuid
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path

import psycopg

from mlsecops import (
    bootstrap,
    promotion,
    promotion_state,
    release_reader,
    storage,
    storage_bootstrap,
    storage_restore,
    trust,
    trust_authority,
)
from mlsecops.contracts import Rejected, canonical, decode, digest, now, safe_child, write_json
from mlsecops.inventory import command, source_fingerprint
from mlsecops.sandbox import resolve_image
from scripts import serving_native


@contextmanager
def disposable(root, state, campaign, suffix, port):
    relative = f"evidence/reader-{campaign}-{suffix}"
    destination = safe_child(state, relative)
    if destination.exists():
        raise Rejected("reader_target_exists")
    bootstrap.initialize(root, destination)
    owned = None
    try:
        try:
            storage_bootstrap.bootstrap(destination, port)
        except Exception:
            if not safe_child(destination, "storage.json").is_file():
                raise Rejected("reader_bootstrap_cleanup_unconfirmed") from None
            owned = storage_bootstrap.validate(destination)
            raise
        owned = storage_bootstrap.validate(destination)
        yield destination
    finally:
        if owned is not None:
            if safe_child(state, relative) != destination:
                raise Rejected("reader_cleanup_path")
            observed = storage_bootstrap.validate(destination)
            if (
                destination.resolve().parent != (state / "evidence").resolve()
                or destination.is_symlink()
                or any(
                    observed[field] != owned[field]
                    for field in ("container_id", "workspace_id", "network_id", "volume")
                )
            ):
                raise Rejected("reader_cleanup_ownership")
            storage_bootstrap.docker(["rm", "--force", observed["container_id"]])
            storage_bootstrap.docker(["network", "rm", observed["network_id"]])
            storage_bootstrap.docker(["volume", "rm", observed["volume"]])
            queries = (
                [
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--no-trunc",
                    "--filter",
                    f"id={observed['container_id']}",
                ],
                ["network", "ls", "--quiet", "--filter", f"id={observed['network_id']}"],
                ["volume", "ls", "--quiet", "--filter", f"name=^{observed['volume']}$"],
            )
            if any(storage_bootstrap.docker(query).stdout.strip() for query in queries):
                raise Rejected("reader_cleanup_unconfirmed")
            shutil.rmtree(destination)


def qualify(root, state, image=None):
    from scripts import promotion_qualification as fixtures

    state = Path(state).resolve()
    source = storage_bootstrap.validate(state)
    original_ledger = storage_restore.ledger(source["name"])
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("reader_source_dirty")
    fingerprint = source_fingerprint(root)
    campaign = uuid.uuid4().hex
    started = now()
    cases = []
    runtime = None
    if image is not None:
        image = resolve_image(image)

    def confirmed(label, condition=True):
        if not condition:
            print(canonical({"case": label, "status": "fail"}).decode(), flush=True)
            raise Rejected("reader_case_failed:" + label)
        cases.append(label)
        print(canonical({"case": label, "status": "pass"}).decode(), flush=True)

    def rejected(label, operation, code):
        try:
            operation()
        except Rejected as error:
            if str(error) != code:
                raise Rejected("reader_wrong_denial:" + label) from None
            confirmed(label)
        else:
            raise Rejected("reader_negative_bypass:" + label)

    fixtures.PromotionAdmissionContracts.setUpClass()
    fixture = fixtures.PromotionAdmissionContracts()
    try:
        fixture.setUp()
        golden = serving_native.bind_real_runtime(fixture, image) if image is not None else None
        with (
            disposable(root, state, campaign, "models", 15444) as models,
            disposable(root, state, campaign, "trust", 15445) as authority,
            ExitStack() as services,
        ):
            promoter = models / "storage-clients/promoter"
            serving = models / "storage-clients/serving"
            trust_client = authority / "storage-clients/serving"
            public, key = fixture.trust_fixture.public, fixture.trust_fixture.key
            policy = fixture.arguments["expected_policy"]
            promotion_state.install(models)
            promotion_state.configure(models, "local-cpu", policy)
            trust_authority.install(authority, "local-cpu", public)
            trust_authority.update(authority, policy, key)

            def lease():
                return trust.Lease(
                    lambda: trust_authority.read(trust_client, "local-cpu", public),
                    trusted_root=public,
                    environment="local-cpu",
                    minimum_version=1,
                )

            options = {
                name: fixture.arguments[name]
                for name in ("context", "trusted_root", "expected_policy", "expected_serving_image")
            }
            reader = release_reader.Reader(
                serving, **options, trust_lease=lease(), minimum_sequence=1
            )
            rejected("empty-head-denied", reader.load, "release_invalid_integer")
            receipt = promotion.promote(promoter, trust_lease=lease(), **fixture.arguments)
            confirmed("controlled-signed-fixture-recorded", not receipt["release_ready"])
            before = storage_restore.ledger(storage_bootstrap.validate(models)["name"])
            loaded = reader.load()
            confirmed(
                "real-TLS-current-head-verified",
                loaded.request_sha256 == receipt["request_sha256"]
                and loaded.subject_sha256 == receipt["subject_sha256"]
                and loaded.sequence == 1,
            )
            confirmed(
                "exact-immutable-model-bytes",
                loaded.model == fixture.fixture.bundle.materials.fixture.model
                and loaded.model_sha256 == digest(loaded.model),
            )
            confirmed("not-runtime-ready", loaded.release_ready is False)
            confirmed("current-check-signed-online-trust", reader.check(loaded)["version"] == 1)
            confirmed("repeat-load-same-content", reader.load() == loaded)
            rejected(
                "old-object-not-current-after-reload",
                lambda: reader.check(loaded),
                "serving_release_not_current",
            )
            loaded = reader.current
            confirmed(
                "reader-performs-no-writes",
                storage_restore.ledger(storage_bootstrap.validate(models)["name"]) == before,
            )
            rejected(
                "promoter-not-serving-identity",
                lambda: release_reader.Reader(
                    promoter, **options, trust_lease=lease(), minimum_sequence=1
                ).load(),
                "serving_storage_identity",
            )
            rejected(
                "external-sequence-floor-enforced",
                lambda: release_reader.Reader(
                    serving, **options, trust_lease=lease(), minimum_sequence=2
                ).load(),
                "serving_sequence_replay",
            )
            if image is not None:
                runtime_reader = release_reader.Reader(
                    serving, **options, trust_lease=lease(), minimum_sequence=1
                )
                http, body, runtime = serving_native.check_http(
                    services, runtime_reader, golden, confirmed, rejected
                )
            trust_authority.update(authority, policy, key, revoked_artifacts=[loaded.model_sha256])
            if image is not None:
                confirmed("actual-revocation-http-503", http("/v1/predict", body)[0] == 503)
                confirmed("actual-revocation-readiness-503", http("/readyz")[0] == 503)
            rejected(
                "model-revocation-denies-existing-handoff",
                lambda: reader.check(loaded),
                "trust_artifact_revoked",
            )
            rejected("model-revocation-denies-new-load", reader.load, "trust_artifact_revoked")
            selection = decode(storage.get(serving, "releases", loaded.request_sha256))
            proof = decode(storage.get(serving, "releases", selection["authorization_reference"]))
            proof["assurance_envelope"] = None
            selection.update(
                sequence=2,
                authorization_reference=storage.put(promoter, "releases", canonical(proof)),
            )
            reference = storage.put(promoter, "releases", canonical(selection))
            with storage.connect(promoter) as connection:
                observed = connection.execute(
                    "SELECT ml_promotion.record_selection(%s)", (reference,)
                ).fetchone()
            confirmed("structural-SQL-selection-is-not-authorization", observed == (reference,))
            rejected(
                "missing-assurance-denies-native-reader", reader.load, "release_assurance_required"
            )
            confirmed("failed-load-has-no-current", reader.current is None)
        confirmed("owned-test-workspaces-removed", not models.exists() and not authority.exists())
    finally:
        fixture.doCleanups()
        fixtures.PromotionAdmissionContracts.tearDownClass()
    confirmed(
        "source-state-and-checkout-unchanged",
        storage_bootstrap.validate(state)["container_id"] == source["container_id"]
        and storage_restore.ledger(source["name"]) == original_ledger
        and source_fingerprint(root) == fingerprint
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    return {
        "schema_version": 1,
        "scope": "serving-HTTP-ONNX-TLS-controlled-fixture-not-full-M12"
        if image is not None
        else "release-reader-real-TLS-SQL-controlled-signed-fixture-not-M12",
        "status": "pass",
        "release_ready": False,
        "full_M12": "inconclusive",
        "campaign_id": campaign,
        "source_revision": revision,
        "source_dirty": False,
        "source_fingerprint": fingerprint,
        "started_at": started,
        "finished_at": now(),
        "cases": cases,
        "runtime": runtime,
        "limitations": [
            "All-pass gate reports are controlled contract fixtures, not actual ML acceptance",
            "HTTP/ONNX execution only when an explicit worker image is supplied; not actual ML acceptance",
            "Current source ML security failures remain blocking",
        ],
    }


def main(arguments=None):
    parser = argparse.ArgumentParser(description="Disposable signed release reader qualification")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--confirm-disposable", action="store_true", required=True)
    parser.add_argument("--worker-image")
    options = parser.parse_args(arguments)
    output = None
    try:
        storage_bootstrap.validate(options.state)
        output = safe_child(options.state, "evidence/release-reader-qualification.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        result = qualify(Path(__file__).resolve().parents[1], options.state, options.worker_image)
        write_json(output, result)
        print(canonical({**result, "cases": len(result["cases"])}).decode())
        return 0
    except (Rejected, psycopg.Error, OSError, KeyError, TypeError, ValueError, RuntimeError):
        if output is not None:
            with suppress(Rejected, OSError):
                write_json(output, {"status": "fail", "release_ready": False})
        print(
            canonical({"status": "fail", "reason": "release_reader_native_rejected"}).decode(),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
