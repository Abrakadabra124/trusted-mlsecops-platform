"""T25 controlled contracts. External transports are replaced by the existing signed fixtures."""

import copy
import os
import runpy
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import acceptance, release_authorization, security_events, signing
from mlsecops import inventory_gate as gate
from mlsecops.contracts import Rejected, canonical, decode, digest, write_json
from mlsecops.signing import decode64
from scripts import canary_candidate_native_qualification as candidate_tests
from scripts import canary_rollback_native as recovery
from scripts import canary_rollback_native_qualification as fixture
from scripts import inventory_deployment_native as native
from scripts import inventory_promotion_native as admission
from scripts import security_events_qualification as events


def controlled_denials(models, authority, fixture, args, public, findings):
    """Exercise real signatures and release admission over in-memory CAS and collector transports."""
    rows = {}
    objects = {}

    def put(_client, table, content):
        assert table == "releases"
        pin = digest(content)
        objects[pin] = content
        return pin

    @contextmanager
    def collector():
        fx = events.EventContracts("runTest")
        fx.setUp()
        try:
            with TemporaryDirectory() as temp:
                directory = Path(temp)

                def submit(_config, request):
                    stamps = recovery.stamp()
                    clock = stamps["wall_ns"] // 1_000_000
                    fx.document.update(issued_at_ms=clock - 500, expires_at_ms=clock + 180000)
                    registry = fx.registry_for(clock=clock)
                    base = decode(objects[request["assurance_reference"]])
                    assure = decode(decode64(base["payload"]))
                    reports = {**args["reports"], "M19": objects[assure["reports"]["M19"]]}
                    try:
                        release_authorization.verify(
                            **{
                                **args,
                                "reports": reports,
                                "assurance_envelope": base,
                                "approval_envelope": decode(objects[request["approval_reference"]]),
                            },
                            clock=clock // 1000,
                        )
                    except Rejected as error:
                        assert str(error) == "release_gate_not_accepted"
                        event = fx.event(
                            "promotion.denied",
                            "promoter",
                            reason="authorization",
                            occurred_at_ms=clock,
                            observed_at_ms=clock,
                            asset_sha256=request["proposal_reference"],
                            bundle_sha256=request["proposal_reference"],
                        )
                        signed = signing.sign(event, "security-event", fx.keys["promoter"])
                        value = registry.verify(signed, clock_ms=clock)
                        receipt = security_events.delivered(
                            value,
                            registry.sha256,
                            ingested_at_ms=clock,
                            routed_at_ms=clock,
                            late=False,
                        )
                        rows["incident"] = dict(
                            envelope=signed,
                            receipt=signing.sign(
                                receipt, "security-event-receipt", fx.keys["receipt"]
                            ),
                            ingested_at_ms=clock,
                            late=False,
                        )
                        write_json(
                            directory / "registry.json",
                            signing.sign(fx.document, "security-event-config", fx.keys["root"]),
                        )
                        write_json(
                            directory / "collector.json",
                            dict(
                                registry_file=str(directory / "registry.json"),
                                registry_sha256=registry.sha256,
                                registry_root=fx.publics["root"],
                            ),
                        )
                        raise

                with patch.object(
                    admission.promoter.promotion_controller, "submit", side_effect=submit
                ):
                    yield SimpleNamespace(
                        directory=directory,
                        audit_config=directory / "audit.json",
                        exchange=lambda *_: (200, dict(incidents=[rows["incident"]])),
                    )
        finally:
            fx.doCleanups()

    with (
        patch.object(admission.storage, "put", side_effect=put),
        patch.object(admission.security_event_audit_fixture, "live", collector),
    ):
        return admission.capture(models, authority, fixture, args, public, findings)


class DatasetRollback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = {
            k: dict(reason=k, graph="a" * 64, snapshot="b" * 64)
            for k in ("owner", "cycle", "dangling", "digest")
        }

        class DatasetDrill(fixture.SignedDrill):
            dataset_mode = True

            @staticmethod
            def inventory_head(*args):
                cls.proofs = controlled_denials(*args, cls.findings)

        DatasetDrill.setUpClass()
        cls.packet = DatasetDrill.packet

    def test_dataset_only_revocation_blocks_historical_target_under_same_policy(self):
        result = recovery.replay(self.packet, revoke_datasets=True)
        first, second = [
            decode(decode64(self.packet["proposals"][role]["payload"]))["materials"]
            for role in ("a", "b")
        ]
        self.assertNotEqual(first["split_manifest"], second["split_manifest"])
        self.assertEqual(result["refusal_statuses"], [503, 503])
        proof = self.packet["events"]["reject_rollback_b"]["value"]
        self.assertEqual(proof["refusal_code"], "trust_artifact_revoked")
        self.assertEqual(proof["before"], proof["after"])
        self.assertEqual(self.packet["events"]["restored_a"]["value"]["status"], 200)
        with self.assertRaises(Rejected):
            recovery.replay(self.packet)
        self.assertEqual(len(admission.replay(self.proofs, self.findings, self.packet)), 4)

    def test_signed_denials_cannot_be_relabelled_or_swapped(self):
        for change in (
            "head",
            "snapshot",
            "reason",
            "receipt",
            "approval",
            "base",
            "time",
            "missing",
        ):
            proofs = copy.deepcopy(self.proofs)
            item = proofs["owner"]
            if change == "head":
                item["after"]["sequence"] += 1
            if change == "snapshot":
                item["report"]["artifact_hashes"]["snapshot"] = "0" * 64
            if change == "reason":
                proofs["owner"] = proofs["cycle"]
            if change == "receipt":
                item["incident"]["receipt"] = proofs["cycle"]["incident"]["receipt"]
            if change == "approval":
                item["approval"] = proofs["cycle"]["approval"]
            if change == "base":
                item["base"]["scope"] = "forged"
            if change == "time":
                item["start"]["wall_ns"] -= 10**9
            if change == "missing":
                del proofs["digest"]
            with self.subTest(change=change), self.assertRaises(Rejected):
                admission.replay(proofs, self.findings, self.packet)

    def test_wrong_signed_release_and_lease_overrun_rejected(self):
        record = copy.deepcopy(self.packet)
        record["proposals"]["b"] = record["proposals"]["a"]
        with self.assertRaises(Rejected):
            recovery.replay(record, revoke_datasets=True)
        record = copy.deepcopy(self.packet)

        # Extend only the final HTTP denial and its successors; all signed SQL/approval times stay valid.
        def extend(value):
            if isinstance(value, dict):
                if set(value) == {"mono_ns", "wall_ns"}:
                    for k in value:
                        value[k] += 61 * recovery.NS
                else:
                    for child in value.values():
                        extend(child)
            if isinstance(value, list):
                for child in value:
                    extend(child)

        for name in ("denied_a", "manual", "final_head"):
            extend(record["events"][name])
        with self.assertRaises(Rejected) as refused:
            recovery.replay(record, revoke_datasets=True)
        self.assertEqual(str(refused.exception.__cause__), "M19_dataset_lease_exceeded")


class Acceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidate_tests.ActualCandidate.setUpClass()
        cls.addClassCleanup(candidate_tests.ActualCandidate.doClassCleanups)

    def setUp(self):
        fx = candidate_tests.ActualCandidate()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        self.root, self.state = fx.root, fx.state
        demo = self.state / "storage-demo.json"
        obj = decode(demo.read_bytes())
        obj["dataset"]["dataset_id"] = obj["candidate"]["metadata"]["dataset_id"]
        write_json(demo, obj)
        with fx.open(revoke_dataset=True) as (engine, golden, binding, revoke):
            loaded = engine.reader.load()
            self.ancestor = obj["dataset"]["dataset_id"]
            observed = dict(
                permit_sha256=loaded.permit_sha256,
                subject_sha256=loaded.subject_sha256,
                model_sha256=golden.model,
                image_id=fx.source["image_id"],
                evaluation_policy_sha256=gate.digest(canonical(fx.context["policy"])),
            )
            revoke()
            with self.assertRaisesRegex(Rejected, "trust_artifact_revoked"):
                engine.reader.load()
        record = dict(
            traffic=dict(
                candidate=binding,
                campaign=fx.campaign,
                goldens=dict(candidate=dict(body=golden.body.decode())),
                started_at="2026-01-01T00:00:00+00:00",
                finished_at="2026-01-01T00:00:01+00:00",
                journals=dict(candidate="b" * 64, stable="a" * 64),
                recovery=dict(start_ns=1, candidate=[dict(end_ns=60 * 10**9 + 1)]),
            ),
            reader_refusal="trust_artifact_revoked",
            observation=observed,
            inventory_source_sha256=digest(
                (
                    self.state
                    / "evidence"
                    / ("canary-native-" + fx.campaign)
                    / "inventory-source.json"
                ).read_bytes()
            ),
        )
        owner = dict(
            source={k: v for k, v in fx.source.items() if k != "image_id"},
            proposal_pin=fx.pin,
            methods="1" * 64,
            runner=dict(GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1"),
        )
        env = {k: digest((self.state / path).read_bytes()) for k, path in gate.OWNER_FILES.items()}
        self.enterContext(patch.dict(os.environ, {**env, **owner["runner"]}))
        self.enterContext(patch.object(gate.canary_rollout_native, "hosted"))
        self.enterContext(
            patch.object(gate.canary_rollout_native, "capture_inputs", return_value=owner)
        )
        fx.marker.return_value = dict(container_id="owned", workspace_id="owned")
        self.inspect = self.enterContext(
            patch.object(
                gate.storage_bootstrap, "inspect", return_value={"State": {"Running": False}}
            )
        )
        self.enterContext(
            patch.object(acceptance, "command", return_value=fx.source["source_revision"])
        )
        self.enterContext(
            patch.object(
                acceptance, "source_fingerprint", return_value=fx.source["source_fingerprint"]
            )
        )
        self.enterContext(patch.object(native.rollout, "traffic", return_value=record))
        self.transport = self.enterContext(
            patch.object(
                gate.canary_native_evidence,
                "replay",
                return_value=dict(
                    requests=800,
                    primary_traffic_sha256="2" * 64,
                    candidate=binding["candidate_reference"],
                    model=golden.model,
                    release_subject=golden.bundle,
                ),
            )
        )
        self.enterContext(
            patch.object(
                gate.canary_rollback_native,
                "replay",
                return_value=dict(rejected_rollback_event="c" * 64),
            )
        )
        self.enterContext(
            patch.object(gate.inventory_promotion_native, "replay", return_value=["a" * 64] * 4)
        )
        self.enterContext(
            patch.object(
                native.inventory_promotion_native, "capture", return_value={"controlled": True}
            )
        )

        def drill(
            _root, _state, _image, campaign, features, *, revoke_datasets, check_inventory_head
        ):
            self.assertTrue(revoke_datasets)
            check_inventory_head(*(None,) * 5)
            return dict(
                image=fx.source["image_id"],
                campaign=campaign,
                features=features,
                events=dict(initial_trust=dict(start=dict(wall_ns=1800000000 * 10**9))),
            )

        self.enterContext(patch.object(native.canary_rollback_native, "drill", side_effect=drill))
        self.packet = native.capture(self.root, self.state)

    def seal(self, packet):
        path = self.state / gate.PACKET
        write_json(path, packet)
        self.enterContext(patch.dict(os.environ, M19_PRIMARY_SHA256=digest(path.read_bytes())))

    def report(self):
        return acceptance.report("M19", "local-cpu", self.root, self.state)

    def test_normal_gate_only_reports_measured_scopes(self):
        self.seal(self.packet)
        out = self.report()
        self.assertEqual(
            (out["scope"], out["status"], out["exit_code"], out["release_ready"]),
            (gate.SCOPE, "inconclusive", 2, False),
        )
        self.assertEqual(out["metrics"]["checks"], 9)
        self.assertEqual(out["metrics"]["dataset_denial_ns"], 60 * 10**9)
        self.assertEqual(len(out["metrics"]["expected"]), 5)
        self.assertEqual(out["metrics"]["actual"], out["metrics"]["expected"])
        self.assertEqual(len(out["metrics"]["fixture"]["actual"]), 10)
        self.assertEqual(self.transport.call_args.kwargs["revoked_dataset"], self.ancestor)
        self.inspect.assert_called_once_with("container", "owned")

    def test_resealed_foreign_graph_summary_and_late_denial_fail_closed(self):
        for field in (
            "observation",
            "graph",
            "snapshot",
            "storage",
            "scope",
            "source",
            "deadline",
            "summary",
            "version",
            "reader",
            "clock",
        ):
            record = copy.deepcopy(self.packet)
            if field == "observation":
                record["observation"]["permit_sha256"] = "0" * 64
            if field == "graph":
                record["graph"]["assets"][0]["owner"] = "platform-owner"
            if field == "snapshot":
                record["snapshot"]["deployments"] = []
            if field == "storage":
                record["storage_sha256"] = "a" * 64
            if field == "scope":
                record["durable"]["campaign"] = "b" * 32
            if field == "source":
                record["inventory_source_sha256"] = "0" * 64
            if field == "deadline":
                record["traffic"]["recovery"]["candidate"][0]["end_ns"] += 1
            if field == "summary":
                record = {"cases": 9}
            if field == "version":
                record["schema_version"] = True
            if field == "reader":
                record["reader_refusal"] = "qualification_expired"
            if field == "clock":
                record["durable"]["events"]["initial_trust"]["start"]["wall_ns"] = 1
            self.seal(record)
            with self.subTest(field=field):
                self.assertEqual(self.report()["exit_code"], 1)

    def test_missing_inputs_foreign_keys_live_storage_or_source_refused(self):
        self.assertEqual(self.report()["exit_code"], 2)
        self.seal(self.packet)
        for var in gate.OWNER_FILES:
            with self.subTest(var=var), patch.dict(os.environ, {var: "f" * 64}):
                self.assertEqual(self.report()["exit_code"], 1)
        with patch.dict(os.environ, M19_KEYS_SHA256=""):
            self.assertEqual(self.report()["exit_code"], 2)
        with self.assertRaises(Rejected):
            gate.inputs(self.root, self.root)
        with patch.object(acceptance, "command", return_value="f" * 39):
            self.assertEqual(self.report()["exit_code"], 1)
        self.inspect.return_value = {"State": {"Running": True}}
        self.assertEqual(self.report()["exit_code"], 1)

    def test_capture_cli_freezes_bytes_and_redacts_exceptions(self):
        from contextlib import redirect_stdout
        from io import StringIO

        path = self.root / "outputs"
        with patch.dict(os.environ, GITHUB_OUTPUT=str(path)):
            self.assertEqual(native.main(self.root), 0)
        self.assertEqual(
            path.read_text().strip(), "sha256=" + digest((self.state / gate.PACKET).read_bytes())
        )
        with (
            patch.object(native, "capture", side_effect=RuntimeError("sensitive")),
            redirect_stdout(StringIO()) as out,
        ):
            self.assertEqual(native.main(self.root), 1)
        self.assertNotIn("sensitive", out.getvalue())
        with (
            patch.dict(os.environ, M19_KEYS_SHA256=""),
            redirect_stdout(StringIO()),
            self.assertRaises(SystemExit) as refused,
        ):
            runpy.run_path(native.__file__, run_name="__main__")
        self.assertEqual(refused.exception.code, 1)
