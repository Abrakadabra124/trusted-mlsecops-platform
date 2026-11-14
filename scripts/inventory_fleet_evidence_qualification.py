"""Controlled four-deployment replay contracts."""

import copy
import os
import time
import unittest
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from mlsecops import inventory_fleet as evidence
from mlsecops import model, prediction_protocol, release_bundle, serving, signing, storage
from mlsecops.contracts import Rejected, canonical, decode, digest, write_json
from scripts import canary_rollback_native as drill
from scripts import inventory_fleet_native as native
from scripts import serving_http_qualification as http
from scripts.kube_rollback_native import variant


class Observations(unittest.TestCase):
    def test_fixture_is_not_an_observation(self):
        from mlsecops.inventory_fleet import reconcile
        from scripts.asset_graph_fixture import fixture

        graph, snapshot, _ = fixture()
        with self.assertRaises(Rejected):
            reconcile({}, dict(graph=graph, snapshot=snapshot))


class FourDeployments(unittest.TestCase):
    """Run capture and replay with signed packages, real Engine, ASGI requests and closed journals."""

    @classmethod
    def setUpClass(cls):
        stack = ExitStack()
        cls.addClassCleanup(stack.close)
        fx = drill.PromotionAdmissionContracts()
        fx.setUpClass()
        stack.callback(fx.tearDownClass)
        fx.setUp()
        stack.callback(fx.doCleanups)
        cls.root = Path(stack.enter_context(TemporaryDirectory()))
        cls.state = cls.root / ".runtime"
        cls.campaign = "c" * 32
        bundle = fx.fixture.bundle
        policy = bundle.materials.context["policy"]
        expected = bundle.materials.context["expected"]
        src = {k: v for k, v in expected.items() if k != "image_id"}
        cls.owner = dict(
            source=src,
            runner=dict(GITHUB_RUN_ID="1", GITHUB_RUN_ATTEMPT="1"),
            methods="e" * 64,
            proposal_pin="a" * 64,
        )
        image = expected["image_id"]
        features = [[0.1] * 6]
        write_json(cls.root / "policies/local-cpu.json", policy)
        write_json(cls.state / "storage-trust.json", bundle.materials.context["trust"])
        key = cls.state / native.materials.KEY
        public = signing.create_key(key)
        reports, packages = {}, {}
        for label, seq in (("previous", 1), ("current", 2), ("independent", 1)):
            bundle.attributes.update(sequence=seq, release_id=evidence.sha(label)[:32])
            if label == "current":
                variant(fx, image, features)
            else:
                drill.dataset_release(fx, image, features, 24017 if label == "previous" else 73039)
            package = copy.deepcopy(fx.arguments["package"])
            manifest = release_bundle.index(package["envelope"], bundle.materials.public)
            ref = evidence.sha(package["envelope"])
            reports[label] = dict(
                scope="release-proposal-and-authorization-denial-not-full-M10",
                status="pass",
                release_ready=False,
                source_dirty=False,
                source=expected,
                campaign_id=manifest["release_id"],
                subject_sha256=evidence.sha(manifest),
                model_sha256=manifest["materials"]["model"],
                proposal_reference=ref,
            )
            packages[ref] = package
        keys = dict(
            approver=bundle.materials.public, curator=bundle.materials.fixture.public["curator"]
        )
        cls.files = {"evidence/release-native.json": reports["current"], "trusted-keys.json": keys}
        cls.owner["proposal_pin"] = digest(canonical(reports["current"]) + b"\n")
        inputs = dict(reports=reports, qualification_root=public)
        path = cls.state / native.materials.FILE
        write_json(path, inputs)
        stack.enter_context(
            patch.dict(os.environ, M19_FLEET_INPUTS_SHA256=digest(path.read_bytes()))
        )
        cls.arguments = dict(
            inputs=inputs,
            files=cls.files,
            owner=cls.owner,
            campaign=cls.campaign,
            policy=policy,
            features=features,
        )
        patches = stack.enter_context(ExitStack())

        def replace(obj, name, **opts):
            return patches.enter_context(patch.object(obj, name, **opts))

        replace(native.rollout, "hosted")
        replace(storage, "connection_parameters", return_value={"user": "ml_serving"})
        replace(release_bundle, "load", side_effect=lambda _, ref, **kw: packages[ref])
        replace(native, "disposable", return_value=nullcontext(cls.state))
        replace(native.trust_authority, "install")
        versions = []

        def update(_, policy, key, *, revoked_artifacts):
            clock = int(time.time())
            payload = dict(
                schema_version=1,
                version=len(versions) + 1,
                environment="local-cpu",
                issued_at=clock,
                expires_at=clock + 3600,
                promotion_policy_sha256=policy,
                revoked_keys=[],
                revoked_artifacts=revoked_artifacts,
            )
            versions.append(signing.sign(payload, "trust-policy", key))
            return dict(
                version=len(versions), document_sha256=evidence.sha(versions[-1]), reused=False
            )

        replace(native.trust_authority, "update", side_effect=update)
        replace(
            native.trust_authority, "read", side_effect=lambda *_: (versions[-1], int(time.time()))
        )

        def reference(image, request, timeout):
            runtime, scan = model.session(prediction_protocol.validate_request(request))
            scores = model.predict(runtime, request["features"])
            return prediction_protocol.response(request, scores, scan), {"image_id": image}

        replace(native.sandbox, "run_worker", side_effect=reference)
        workers = {}

        def worker(content, image):
            runtime, _ = model.session(content)
            identifier = f"{len(workers) + 1:064x}"
            session = identifier[-32:]
            instance = Mock(
                image=image,
                container=identifier,
                binding=dict(session_id=session, model_sha256=digest(content)),
            )
            instance.predict.side_effect = lambda features: model.predict(runtime, features)
            workers[identifier] = instance
            return instance

        replace(serving, "Worker", side_effect=worker)
        replace(
            native.storage_bootstrap,
            "inspect",
            side_effect=lambda kind, id: dict(
                State=dict(Running=True), Id=id, Image=workers[id].image
            ),
        )
        replace(native.serving_runtime, "verify_container")
        sites = {}

        @contextmanager
        def endpoint(engine, path):
            # Keep the actual ASGI app, access counters, journal and reader behind the fake port.
            from mlsecops import serving_access, serving_audit, serving_http

            harness = http.ServingHttpContracts()
            harness.token = "e" * 64
            access = serving_access.Access(
                dict(
                    schema_version=1,
                    clients=[
                        dict(
                            token=harness.token,
                            principal_id="a" * 32,
                            requests_per_second=1000,
                            burst=1000,
                            max_in_flight=4,
                        )
                    ],
                )
            )
            journal = serving_audit.Journal(path)
            journal.start()
            with ExitStack() as life:
                life.callback(journal.close, timeout=5)
                life.callback(engine.close)
                engine.activate()
                harness.app = serving_http.create_app(engine, clients=access, audit=journal)
                port = 32000 + len(sites)
                sites[port] = harness
                yield (port, harness.token), access

        replace(native.rollout, "endpoint", side_effect=endpoint)

        async def request(port, token, body):
            status, reply, _ = await sites[port].invoke(body=decode(body))
            return status, reply

        replace(native.rollout.load_measurement, "request", side_effect=request)
        cls.packet = native.capture(cls.root, cls.state, cls.owner, cls.files, cls.campaign)
        patches.close()

    def verify(self, packet):
        return evidence.replay(self.state, packet, **self.arguments)

    def test_full_graph_from_primary_http_and_sql_materials(self):
        graph, snapshot, ancestor, expected, denials = self.verify(self.packet)
        self.assertEqual(
            (len(graph["assets"]), len(snapshot["deployments"]), len(expected)), (17, 4, 10)
        )
        self.assertEqual(set(denials), {"primary", "previous", "canary"})
        self.assertEqual(
            set(evidence.gate.refusals(graph, snapshot, ancestor)),
            {"dangling", "cycle", "owner", "digest"},
        )

    def test_lease_boundary_measured_from_before_sql_write(self):
        packet = self.packet
        ob = copy.deepcopy(packet["deployments"]["previous"])
        gold_args = self.arguments
        binding, trace, golden = evidence.source(
            packet["sources"]["previous"],
            gold_args["inputs"]["reports"]["previous"],
            self.files["trusted-keys.json"],
            gold_args["inputs"]["qualification_root"],
            self.campaign,
            self.owner["source"],
            gold_args["policy"],
            packet["finished"]["wall_ns"] // 10**9,
            "previous",
        )
        directory = self.state / ("evidence/M19-fleet-" + self.campaign)
        for suffix, clock in (("end_ns", "mono_ns"), ("wall_end_ns", "wall_ns")):
            ob["after"][suffix] = packet["start"][clock] + 60 * 10**9
        finished = {k: v + 61 * 10**9 for k, v in packet["finished"].items()}

        def verify():
            return evidence.probes(
                "previous",
                ob,
                golden,
                trace,
                binding,
                directory,
                packet["start"],
                packet["committed"],
                finished,
                60 * 10**9,
            )

        self.assertEqual(verify(), 60 * 10**9)
        for suffix in ("wall_end_ns", "end_ns"):
            ob["after"][suffix] += 1
            with self.subTest(suffix=suffix), self.assertRaises(Rejected):
                verify()
            ob["after"][suffix] -= 1

    def test_normal_post_cleanup_gate_accepts_only_the_pinned_full_capture(self):
        from datetime import UTC, datetime

        from mlsecops import acceptance
        from mlsecops import inventory_gate as gate
        from scripts import inventory_deployment_native as capture

        state, root = self.state, self.root
        graph, snapshot, ancestor, _, _ = self.verify(self.packet)
        report = self.files["evidence/release-native.json"]
        item = self.packet["sources"]["current"]
        current = self.packet["deployments"]["primary"]["loaded"]
        stamp = datetime.now(UTC).isoformat()
        traffic = dict(
            campaign=self.campaign,
            candidate=dict(
                current | item["projection"]["bindings"],
                proposal_reference=report["proposal_reference"],
                source_evidence_sha256="c" * 64,
            ),
            recovery=dict(start_ns=1000, candidate=[dict(end_ns=2000)]),
            goldens=dict(
                candidate=dict(
                    body=canonical({"instances": [dict.fromkeys(native.FEATURES, 0.1)]}).decode()
                )
            ),
            started_at=stamp,
            finished_at=stamp,
            journals=dict(candidate="a" * 64, stable="b" * 64),
        )
        source = {k: item[k] for k in ("proposal", "projection")}
        path = state / "evidence" / ("canary-native-" + self.campaign) / "inventory-source.json"
        write_json(path, source)
        single = dict(
            traffic=traffic,
            observation=current,
            reader_refusal="trust_artifact_revoked",
            inventory_source_sha256=digest(path.read_bytes()),
        )
        files = {
            **self.files,
            "storage-demo.json": dict(
                candidate=dict(metadata=dict(dataset_id=ancestor["sha256"])),
                dataset=dict(
                    dataset_id=ancestor["sha256"],
                    dataset_reference=item["projection"]["bindings"]["dataset_reference"],
                ),
            ),
        }
        for name, value in files.items():
            write_json(state / name, value)
        env = {k: digest((state / path).read_bytes()) for k, path in gate.OWNER_FILES.items()}
        owner = {**self.owner, "runner": dict(GITHUB_RUN_ID="foreign", GITHUB_RUN_ATTEMPT="1")}
        # A foreign capture owner must still fail with all file pins refreshed.
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {**env, **self.owner["runner"]}))

            def replace(obj, field, **opts):
                return stack.enter_context(patch.object(obj, field, **opts))

            replace(native.rollout, "hosted")
            replace(native.rollout, "capture_inputs", return_value=self.owner)
            replace(gate.storage_bootstrap, "validate", return_value=dict(container_id="owned"))
            replace(gate.storage_bootstrap, "inspect", return_value={"State": {"Running": False}})
            replace(acceptance, "command", return_value=owner["source"]["source_revision"])
            replace(
                acceptance, "source_fingerprint", return_value=owner["source"]["source_fingerprint"]
            )
            replace(capture.uuid, "uuid4", return_value=Mock(hex=self.campaign))
            replace(native, "capture", return_value=self.packet)
            replace(native.rollout, "traffic", return_value=single)
            replace(capture.inventory_promotion_native, "capture", return_value={"events": 4})

            def durable(
                root, state, image, campaign, features, *, revoke_datasets, check_inventory_head
            ):
                check_inventory_head(*(None,) * 5)
                return dict(
                    campaign=campaign,
                    image=current["image_id"],
                    features=features,
                    events=dict(initial_trust=dict(start=dict(wall_ns=time.time_ns()))),
                )

            replace(drill, "drill", side_effect=durable)
            replace(drill, "replay", return_value=dict(rejected_rollback_event="e" * 64))
            replace(capture.inventory_promotion_native, "replay", return_value=["c" * 64] * 4)
            replace(
                gate.canary_native_evidence,
                "replay",
                return_value=dict(
                    requests=800,
                    primary_traffic_sha256="e" * 64,
                    candidate=traffic["candidate"]["candidate_reference"],
                    model=current["model_sha256"],
                    release_subject=current["subject_sha256"],
                ),
            )
            record = capture.capture(root, state)
            self.assertEqual((record["graph"], record["snapshot"]), (graph, snapshot))
            path = state / gate.PACKET
            write_json(path, record)
            stack.enter_context(
                patch.dict(os.environ, M19_PRIMARY_SHA256=digest(path.read_bytes()))
            )
            result = acceptance.report("M19", "local-cpu", root, state)
            self.assertEqual(
                (result["scope"], result["status"], result["exit_code"], result["release_ready"]),
                (evidence.SCOPE, "pass", 0, False),
            )
            self.assertEqual(result["metrics"]["checks"], 14)
            self.assertEqual(result["input_digests"]["release_subject"], current["subject_sha256"])
            with patch.object(native.rollout, "capture_inputs", return_value=owner):
                self.assertEqual(acceptance.report("M19", "local-cpu", root, state)["exit_code"], 1)
            for pin, code in (("", 2), ("0" * 64, 1)):
                with patch.dict(os.environ, M19_FLEET_INPUTS_SHA256=pin):
                    self.assertEqual(
                        acceptance.report("M19", "local-cpu", root, state)["exit_code"], code
                    )

    def test_resealed_foreign_or_incomplete_observations_refused(self):
        for fault in (
            "fixture",
            "same-worker",
            "same-session",
            "same-port",
            "history",
            "journal",
            "lease",
            "role",
            "wrong-root",
            "trust",
            "healthy",
            "cold",
            "old-readback",
            "policy",
            "owner",
            "admissions",
            "schema",
            "late-independent",
        ):
            packet = copy.deepcopy(self.packet)
            deployments = packet["deployments"]
            prev = deployments["previous"]
            if fault == "fixture":
                del deployments["previous"]
            if fault == "same-worker":
                prev["container"] = deployments["canary"]["container"]
            if fault == "same-session":
                prev["session"] = deployments["canary"]["session"]
            if fault == "same-port":
                prev["port"] = deployments["canary"]["port"]
            if fault == "history":
                deployments["primary"]["activation_ns"] = prev["history"]["end_ns"] - 1
            if fault == "journal":
                prev["journal"] = deployments["independent"]["journal"]
            if fault == "lease":
                packet["start"]["mono_ns"] -= 61 * 10**9
            if fault == "role":
                packet["sources"]["current"] = packet["sources"]["independent"]
            if fault == "wrong-root":
                packet["roster"] = packet["before"]
            if fault == "trust":
                packet["after"] = packet["before"]
            if fault == "healthy":
                prev["healthy"] = deployments["independent"]["healthy"]
            if fault == "cold":
                prev["reader_result"] = "qualification_expired"
            if fault == "old-readback":
                prev["trust_readback"]["document_sha256"] = evidence.sha(packet["before"])
            if fault == "policy":
                prev["loaded"]["evaluation_policy_sha256"] = "0" * 64
            if fault == "owner":
                packet["owner"]["runner"]["GITHUB_RUN_ID"] = "2"
            if fault == "admissions":
                prev["admissions"][0] += 1
            if fault == "schema":
                prev["after"]["reply"]["schema_version"] = True
            if fault == "late-independent":
                deployments["independent"]["after"] = deployments["independent"]["healthy"]
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                self.verify(packet)
