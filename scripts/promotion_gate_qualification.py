"""Controlled signed M10 cases with the ordinary submission verifier and in-memory transport."""

import copy
import os
import tempfile
import unittest
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops import acceptance, security_events, signing
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    write_json,
)
from scripts import promotion_controller_qualification as contracts
from scripts import promotion_gate_native as gate
from scripts import security_events_qualification


def journal(head=None):
    return dict(
        head=dict(
            environment="local-cpu",
            sequence=int(head is not None),
            request_sha256=head,
            release_ready=False,
        ),
        events=[]
        if head is None
        else [
            dict(
                environment="local-cpu",
                sequence=1,
                request_sha256=head,
                previous_sha256=None,
                epoch="123",
            )
        ],
        objects=[],
    )


class MatrixContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        contracts.SubmissionContracts.setUpClass()
        cls.addClassCleanup(contracts.SubmissionContracts.tearDownClass)

    def setup_submission(self):
        fx = contracts.SubmissionContracts()
        self.addCleanup(fx.doCleanups)
        fx.setUp()
        return fx

    def test_each_single_fault_rejected_by_normal_controller_then_valid_retry(self):
        fx = self.setup_submission()

        def retain(envelope):
            content = canonical(envelope)
            ref = digest(content)
            fx.values[ref] = content
            return ref

        observed = {}
        for case, config, request in gate.negative_inputs(
            fx.fixture, fx.config, fx.request, retain
        ):
            with self.subTest(case=case), self.assertRaises(Rejected) as denied:
                fx.submit(config, request)
            observed[case] = str(denied.exception)
            self.assertIsNone(fx.fixture.head)
            self.assertFalse(fx.writes)
        self.assertEqual(observed, gate.NEGATIVES)
        self.assertTrue(
            {
                "foreign-publisher",
                "missing-report",
                "mismatched-subject",
                "proposal-alias-swap",
                "trainer-self-approval",
                "unknown-schema",
                "foreign-environment-replay",
            }.issubset(observed)
        )
        first = fx.submit()
        self.assertEqual(first, fx.submit())
        selection = decode(fx.values[first["request_sha256"]])
        self.assertEqual(selection["subject_sha256"], fx.fixture.fixture.approval["subject_sha256"])

    def test_stage_preserves_proposal_reference_and_never_synthesizes_authority(self):
        fx = self.setup_submission()
        args = fx.fixture.arguments
        client = fx.config["storage_client"]
        for supplied in (True, False):
            inputs = (
                args
                if supplied
                else {**args, "assurance_envelope": None, "approval_envelope": None, "reports": {}}
            )
            with self.subTest(supplied=supplied):
                request = gate.cli.stage(client, inputs)
                self.assertEqual(
                    request,
                    fx.request
                    if supplied
                    else {**fx.request, "assurance_reference": None, "approval_reference": None},
                )
                if not supplied:
                    with self.assertRaisesRegex(Rejected, "release_assurance_required"):
                        fx.submit(request=request)
                    self.assertIsNone(fx.fixture.head)

    def controlled_matrix(self):
        fx = self.setup_submission()
        models = Path(fx.config["storage_client"]).parents[1]
        # The SQL identity is an established transport boundary in SubmissionContracts.
        fx.config["storage_client"] = str(models / "storage-clients/promoter")

        def observe(_models):
            result = journal(fx.fixture.head)
            result["objects"] = sorted(fx.values)
            return result

        def invoke(_root, _path, config, request, denied=False):
            if denied:
                with self.assertRaises(Rejected):
                    fx.submit(config, request)
                return dict(status="rejected", release_ready=False)
            return fx.submit(config, request)

        with (
            patch.object(gate.storage, "put", side_effect=lambda c, t, b: fx.put(str(c), t, b)),
            patch.object(gate.cli, "stage", return_value=fx.request),
            patch.object(gate.cli, "configuration", return_value=fx.config),
            patch.object(gate.cli, "invoke", side_effect=invoke),
            patch.object(gate, "snapshot", side_effect=observe),
            patch.object(
                gate.security_event_audit_fixture,
                "live",
                side_effect=lambda: nullcontext(SimpleNamespace(audit_config=Path("fixture"))),
            ),
        ):
            return gate.matrix(Path.cwd(), models, models, fx.fixture)

    def test_whole_matrix_and_durable_readback_with_controlled_transports(self):
        record = self.controlled_matrix()
        self.assertEqual(set(record["negatives"]), set(gate.NEGATIVES))
        self.assertEqual(len(record["committed"]["events"]), 1)
        for key, fields, bad in (
            ("repeated", ("head", "sequence"), True),
            ("committed", ("events",), []),
            ("before", ("events",), record["committed"]["events"]),
            ("first", ("proposal_reference",), record["subject"]),
            ("selection", ("proposal_reference",), record["subject"]),
            ("proof", ("decision", "subject_sha256"), "f" * 64),
        ):
            damaged = copy.deepcopy(record)
            target = damaged[key]
            for field in fields[:-1]:
                target = target[field]
            target[fields[-1]] = bad
            with self.subTest(key=key), self.assertRaises(Rejected):
                gate.check_transition(
                    *(
                        damaged[k]
                        for k in (
                            "request",
                            "subject",
                            "before",
                            "first",
                            "committed",
                            "retry",
                            "repeated",
                            "selection",
                            "proof",
                        )
                    )
                )

    def promotion_evidence(self, values, keys, freeze, proposal, policy):
        control = self.controlled_matrix()
        audit = ActualContracts()
        audit.setUp()
        self.addCleanup(audit.doCleanups)
        source = {k: values[k] for k in ("source_fingerprint", "source_revision", "image_id")}
        before = journal()
        request = {k: values[k] for k in ("proposal_reference", "policy_reference")} | {
            "schema_version": 1,
            "approval_reference": None,
            "assurance_reference": None,
        }
        actual = dict(
            before=before,
            after=before,
            after_parent=before,
            request=request,
            reason="release_assurance_required",
            cli={"status": "rejected", "release_ready": False},
            windows=audit.windows,
            registry_pin=audit.fx.registry.sha256,
            registry_root=audit.fx.publics["root"],
            audit=audit.primary
            | {
                "incidents": [
                    audit.incident(i, proposal=request["proposal_reference"]) for i in (1, 2)
                ]
            },
        )
        packet = dict(
            schema_version=1,
            scope=gate.SCOPE,
            source=source,
            input_files=freeze,
            actual_policy_root=keys["trust"],
            actual_subject=values["release_subject"],
            actual_model=values["model"],
            actual_policy=policy,
            actual_proposal=proposal,
            actual=actual,
            controlled=control,
        )
        outcomes = {
            "actual-signed-proposal": values["release_subject"],
            "actual-candidate-denied": actual["reason"],
            "actual-signed-denials-delivered": 2,
            "actual-durable-sequence": 0,
            "controlled-recorded-sequence": 1,
            "controlled-repeat-same-request": control["first"]["request_sha256"],
            **{"controlled-" + k: v for k, v in gate.NEGATIVES.items()},
        }
        return packet, dict(
            cases=[dict(id=k, expected=v, actual=v, status="pass") for k, v in outcomes.items()],
            metrics=dict(
                checks=len(outcomes),
                actual_release_authorization="inconclusive",
                actual_sequence=0,
                controlled_sequence=1,
                controlled_negative_cases=len(gate.NEGATIVES),
            ),
        )

    def test_offline_promotion_replays_original_reports_signed_audit_and_idempotent_control(self):
        from mlsecops import final_evidence
        from mlsecops.contracts import now
        from scripts import m18_promotion_replay

        state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        proposal, policy = {"test": "original proposal"}, {"test": "original policy"}

        def hash_json(doc):
            return digest(canonical(doc))

        keys = {"trust": "controlled-policy-root"}
        values = {
            k: hash_json(k) for k in ("source_fingerprint", *final_evidence.BINDINGS["M10"].split())
        }
        values.update(
            source_revision="a" * 40,
            image_id="sha256:" + hash_json("image"),
            policy=hash_json("local policy"),
            proposal_reference=hash_json(proposal),
            policy_reference=hash_json(policy),
        )
        source = {k: values[k] for k in ("source_fingerprint", "source_revision", "image_id")}
        frozen_path = state / "evidence/release-native.json"
        write_json(
            frozen_path, {"source": source, "proposal_reference": values["proposal_reference"]}
        )
        freeze = {"evidence/release-native.json": digest(bounded_read(frozen_path))}
        packet, observations = self.promotion_evidence(values, keys, freeze, proposal, policy)
        control = packet["controlled"]
        report = dict(
            schema_version=1,
            gate="M10",
            source_dirty=False,
            profile="local-cpu",
            source_revision=source["source_revision"],
            policy_digest=values["policy"],
            redaction_version=1,
            status="pass",
            exit_code=0,
            release_ready=False,
            started_at=now(),
            finished_at=now(),
            residual_risks=["Controlled fixture"],
            input_digests={
                k: values[k]
                for k in ("source_fingerprint", *final_evidence.BINDINGS["M10"].split())
            },
            **observations,
        )

        def verify():
            path = state / "evidence/M10-promotion-primary.json"
            write_json(path, packet)
            report["artifact_hashes"] = {
                "actual_proposal_report": freeze["evidence/release-native.json"],
                "promotion_primary": digest(bounded_read(path)),
            }
            path = state / "evidence/M10.json"
            write_json(path, report)
            m18_promotion_replay.verify(state, values, freeze, keys, digest(bounded_read(path)))

        verify()
        for ref in report["artifact_hashes"].values():
            final_evidence.blob(state, ref)
        for target, change in (
            (control["negatives"]["missing-approval"], {"reason": "untrusted_key"}),
            (control, {"retry": {"state": "recorded"}}),
            (packet, {"actual_policy_root": "foreign"}),
        ):
            with patch.dict(target, change), self.assertRaises(Rejected):
                verify()

    def test_separately_authorized_path_refuses_foreign_pin_or_nonempty_head_before_cli(self):
        fx = self.setup_submission()
        models = Path(fx.config["storage_client"]).parent
        config = {**fx.config, "storage_client": str(models / "storage-clients/promoter")}
        subject = fx.fixture.fixture.approval["subject_sha256"]
        for pin, value, state in (
            (fx.request["proposal_reference"], "a" * 64, journal()),
            ("f" * 64, subject, journal()),
            (fx.request["proposal_reference"], subject, journal("b" * 64)),
        ):
            with (
                self.subTest(pin=pin, subject=value),
                patch.object(gate, "snapshot", return_value=state),
                patch.object(gate.cli, "invoke") as cli,
                self.assertRaises(Rejected),
            ):
                gate.authorized_transition(
                    Path.cwd(),
                    models,
                    config,
                    fx.request,
                    directory=models,
                    proposal_reference=pin,
                    subject=value,
                )
            cli.assert_not_called()


class ActualContracts(unittest.TestCase):
    def setUp(self):
        fx = security_events_qualification.EventContracts()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        self.fx = fx
        self.proposal = "7" * 64
        self.windows = [[1999, 2010], [2020, 2030]]
        self.primary = dict(
            registry=signing.sign(fx.document, "security-event-config", fx.keys["root"]),
            incidents=[self.incident(i) for i in (1, 2)],
        )

    def incident(self, seq, *, proposal=None, route=None):
        fx = self.fx
        clock = 2000 if seq == 1 else 2020
        value = fx.event(
            "promotion.denied",
            "promoter",
            reason="authorization",
            sequence=seq,
            occurred_at_ms=clock,
            observed_at_ms=clock,
            bundle_sha256=proposal or self.proposal,
            asset_sha256=proposal or self.proposal,
        )
        envelope = signing.sign(value, "security-event", fx.keys["promoter"])
        event = fx.registry.verify(envelope, clock_ms=clock)
        delivery = security_events.delivered(
            event,
            fx.registry.sha256,
            ingested_at_ms=clock,
            routed_at_ms=route or clock + 1,
            late=False,
        )
        return dict(
            envelope=envelope,
            ingested_at_ms=clock,
            late=False,
            receipt=signing.sign(delivery, "security-event-receipt", fx.keys["receipt"]),
        )

    def verify(self):
        gate.check_audit(
            self.primary,
            registry_root=self.fx.publics["root"],
            registry_pin=self.fx.registry.sha256,
            proposal=self.proposal,
            windows=self.windows,
        )

    def test_real_signatures_cannot_cover_future_delivery_or_wrong_subject_sequence(self):
        self.verify()
        for altered in (
            self.incident(2, route=2031),
            self.incident(2, proposal="8" * 64),
            self.incident(1),
        ):
            with (
                patch.dict(self.primary, incidents=[self.primary["incidents"][0], altered]),
                self.assertRaises(Rejected),
            ):
                self.verify()
        with patch.dict(self.primary, incidents=[]), self.assertRaises(Rejected):
            self.verify()

    def test_offline_refusal_requires_two_signed_incidents_and_unchanged_parent_and_cli_history(
        self,
    ):
        from scripts.m18_promotion_replay import verify_refusal

        history = journal()
        packet = dict(
            before=history,
            after_parent=history,
            after=history,
            cli={"status": "rejected", "release_ready": False},
            reason="release_assurance_required",
            audit=self.primary,
            registry_root=self.fx.publics["root"],
            registry_pin=self.fx.registry.sha256,
            windows=self.windows,
            request={"proposal_reference": self.proposal},
        )
        verify_refusal(packet, self.proposal)
        for change in (
            {"after_parent": journal("a" * 64)},
            {"cli": {"status": "pass", "release_ready": True}},
            {"reason": "unrelated_denial"},
            {"windows": [self.windows[0], self.windows[0]]},
            {"registry_pin": "f" * 64},
        ):
            with (
                self.subTest(keys=list(change)),
                patch.dict(packet, change),
                self.assertRaises(Rejected),
            ):
                verify_refusal(packet, self.proposal)

    def test_native_actual_refusal_retains_verified_signed_pair(self):
        fx = self.fx
        registry_file = fx.directory / "registry.json"
        write_json(registry_file, self.primary["registry"])
        audit_config = fx.directory / "audit.json"
        write_json(
            audit_config,
            dict(
                registry_file=str(registry_file),
                registry_root=fx.publics["root"],
                registry_sha256=fx.registry.sha256,
            ),
        )
        audit = SimpleNamespace(
            audit_config=audit_config,
            exchange=lambda *_: (200, dict(incidents=self.primary["incidents"], next_offset=None)),
        )
        request = dict(
            proposal_reference=self.proposal, assurance_reference=None, approval_reference=None
        )
        with (
            patch.object(gate.cli, "stage", return_value=request),
            patch.object(gate.cli, "configuration"),
            patch.object(
                gate.security_event_audit_fixture, "live", return_value=nullcontext(audit)
            ),
            patch.object(gate, "snapshot", return_value=journal()),
            patch.object(
                gate.promotion_controller,
                "submit",
                side_effect=Rejected("release_assurance_required"),
            ),
            patch.object(
                gate.cli, "invoke", return_value=dict(status="rejected", release_ready=False)
            ),
            patch.object(
                gate.time, "time_ns", side_effect=[t * 1000000 for win in self.windows for t in win]
            ),
        ):
            result = gate.actual_refusal(
                Path("."),
                fx.directory,
                fx.directory,
                fx.publics["root"],
                {},
                dict(proposal_reference=self.proposal),
            )
        self.assertEqual(result["audit"], self.primary)
        self.assertEqual(result["before"], result["after"])

    def test_unexpected_success_reason_or_writes_fail_closed(self):
        for exception, changes in (
            (None, []),
            (Rejected("wrong"), []),
            (Rejected("expected"), [journal(), journal("a" * 64)]),
            (Rejected("expected"), [journal(), journal(), journal("a" * 64)]),
        ):
            with (
                self.subTest(error=exception, changes=len(changes)),
                patch.object(gate.promotion_controller, "submit", side_effect=exception),
                patch.object(gate, "snapshot", side_effect=changes or [journal()]),
                patch.object(gate.cli, "invoke"),
                self.assertRaises(Rejected),
            ):
                gate.denied(None, None, None, {}, {}, "expected")


class GateContracts(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name)
        self.root = Path(gate.__file__).resolve().parents[1]
        self.model = b"controlled model"
        self.subject = "b" * 64
        self.fixture_subject = "c" * 64
        self.report = dict(
            proposal_reference=digest(canonical({})),
            subject_sha256=self.subject,
            model_sha256=digest(self.model),
            campaign_id="a" * 32,
            policy_sha256="e" * 64,
        )
        self.demo = {
            "candidate": {
                "candidate_reference": "1" * 64,
                "metadata": {"model_digest": digest(self.model)},
            },
            "evaluation_reference": "2" * 64,
            "evaluation": {"candidate_reference": "1" * 64, "report": {}},
        }
        self.expected = dict(
            source_revision="3" * 40, source_fingerprint="4" * 64, image_id="sha256:" + "5" * 64
        )
        files = {
            "M10_RELEASE_REPORT_SHA256": ("evidence/release-native.json", self.report),
            "M10_STORAGE_DEMO_SHA256": ("storage-demo.json", self.demo),
            "M10_KEYS_SHA256": ("trusted-keys.json", {"trust": "public", "approver": "publisher"}),
            "M10_TRUST_SHA256": ("storage-trust.json", {}),
        }
        env = {}
        for key, (name, data) in files.items():
            path = self.state / name
            write_json(path, data)
            env[key] = digest(bounded_read(path))
        self.enterContext(patch.dict(os.environ, env))
        write_json(
            self.state / "release-proposals" / self.report["campaign_id"] / "policy-envelope.json",
            {},
        )
        for name in ("storage.json", "workspace.json"):
            write_json(self.state / name, {})

    def run_native(self, *, mutated_source=False, cleanup_error=False):
        class Owned:
            def __init__(inner, root, state, campaign, name, port):
                inner.path = state / name

            def __enter__(inner):
                inner.path.mkdir()
                return inner.path

            def __exit__(inner, *exc):
                inner.path.rmdir()
                if cleanup_error and inner.path.name == "trust":
                    raise Rejected("cleanup_unconfirmed")

        fixture = Mock()
        fixture.fixture.approval = {"subject_sha256": self.fixture_subject}
        fixture.fixture.bundle.materials.fixture.model = self.model
        fixture.arguments = {"expected_policy": "a" * 64}
        verify = (
            dict(
                candidate_reference=self.demo["candidate"]["candidate_reference"],
                evaluation_reference=self.demo["evaluation_reference"],
                trust={},
            ),
            dict(
                model=self.model,
                manifest=dict(release_id=self.report["campaign_id"]),
                subject_sha256=self.subject,
            ),
            {"envelope": {}},
            "publisher",
        )
        refuse = dict(
            reason="release_assurance_required",
            before=journal(),
            after=journal(),
            audit=dict(incidents=[{}, {}]),
            request=dict(policy_reference="6" * 64),
        )
        control = dict(
            first=dict(sequence=1, request_sha256="f" * 64),
            retry=dict(request_sha256="f" * 64),
            committed=journal("f" * 64),
            negatives={k: dict(reason=v) for k, v in gate.NEGATIVES.items()},
        )
        with ExitStack() as stack:
            for obj, name, kwargs in (
                (gate.cli, "hosted", {}),
                (
                    gate,
                    "source",
                    dict(side_effect=[self.expected, {} if mutated_source else self.expected]),
                ),
                (gate.storage_bootstrap, "validate", dict(return_value={"name": "db"})),
                (gate.storage_restore, "ledger", dict(return_value={})),
                (gate, "verified_materials", dict(return_value=verify)),
                (
                    gate.promotion_qualification,
                    "PromotionAdmissionContracts",
                    dict(return_value=fixture),
                ),
                (gate.serving_native, "bind_model", {}),
                (gate.trust_authority, "install", {}),
                (gate.trust_authority, "update", {}),
                (gate.promotion_state, "install", {}),
                (gate.promotion_state, "configure", {}),
                (gate, "disposable", dict(new=Owned)),
                (gate, "actual_refusal", dict(return_value=refuse)),
                (gate, "matrix", dict(return_value=control)),
            ):
                stack.enter_context(patch.object(obj, name, **kwargs))
            return gate.qualify(self.root, self.state)

    def test_gate_report_uses_actual_subject_model_and_private_packet_digest(self):
        result = self.run_native()
        packet = self.state / "evidence/M10-promotion-primary.json"
        self.assertEqual(
            result["artifact_hashes"]["promotion_primary"], digest(bounded_read(packet))
        )
        self.assertEqual(result["input_digests"]["release_subject"], self.subject)
        self.assertEqual(result["input_digests"]["model"], digest(self.model))
        self.assertEqual(result["metrics"]["actual_release_authorization"], "inconclusive")
        self.assertTrue(all(c["actual"] == c["expected"] for c in result["cases"]))
        self.assertFalse(
            any(
                p.exists()
                for p in [self.state / "actual", self.state / "control", self.state / "trust"]
            )
        )
        for filename in ("workspace.json", "storage.json"):
            self.assertTrue((self.state / filename).exists())

    def test_unavailable_or_substituted_pins_and_cleanup_failure_never_issue_report(self):
        with (
            patch.object(gate.cli, "hosted"),
            patch.object(gate, "capture", side_effect=RuntimeError("private-path")),
            self.assertRaisesRegex(Rejected, "^promotion_gate_capture_failed$"),
        ):
            gate.qualify(self.root, self.state)
        with (
            patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(Rejected, "owner_pins_required"),
        ):
            gate.pins_from_owner()
        with patch.dict(os.environ, M10_STORAGE_DEMO_SHA256="e" * 64), self.assertRaises(Rejected):
            self.run_native()
        with self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"):
            self.run_native(cleanup_error=True)
        with self.assertRaises(Rejected):
            self.run_native(mutated_source=True)
        self.assertFalse((self.state / "evidence/M10-promotion-primary.json").exists())

    def test_normal_acceptance_dispatch_scopes_pass_and_refuses_unavailable_or_different_source(
        self,
    ):
        evidence = self.run_native()
        with (
            patch.object(acceptance, "command", return_value=self.expected["source_revision"]),
            patch.object(
                acceptance, "source_fingerprint", return_value=self.expected["source_fingerprint"]
            ),
        ):
            for value, status, exit_code in (
                (evidence, "pass", 0),
                (Rejected("promotion_gate_owner_pins_required"), "inconclusive", 2),
                (
                    {
                        **evidence,
                        "input_digests": {**evidence["input_digests"], "source_revision": "f" * 40},
                    },
                    "fail",
                    1,
                ),
            ):
                with (
                    self.subTest(status=status),
                    patch.object(gate, "qualify", side_effect=[value]),
                ):
                    result = acceptance.report("M10", "local-cpu", self.root, self.state)
                self.assertEqual(
                    (
                        result["status"],
                        result["exit_code"],
                        result["release_ready"],
                        result["scope"],
                    ),
                    (status, exit_code, False, gate.SCOPE),
                )
            with patch.object(gate, "qualify") as runner:
                result = acceptance.report("M10", "local-cpu", self.root, self.state / "absent")
                runner.assert_not_called()
                self.assertEqual(result["exit_code"], 2)

    def test_native_reads_head_events_and_objects_using_serving_identity(self):
        reader = self.state / "storage-clients/serving"
        with (
            patch.object(gate.promotion_state, "state", return_value=journal()["head"]) as head,
            patch.object(gate, "history", return_value=[]) as events,
            patch.object(gate, "release_snapshot", return_value={"b", "a"}) as objects,
        ):
            self.assertEqual(gate.snapshot(self.state), {**journal(), "objects": ["a", "b"]})
            head.assert_called_once_with(reader, gate.ENV)
            events.assert_called_once_with(reader)
            objects.assert_called_once_with(reader)


if __name__ == "__main__":
    unittest.main()
