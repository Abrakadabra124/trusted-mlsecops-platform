"""Real original signatures/transfer, private file preparation only; no infrastructure."""

import copy
import os
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mlsecops import bootstrap, release_bundle, signing, storage, storage_pki
from mlsecops.contracts import Rejected, atomic_write, bounded_read, canonical, decode, digest
from scripts import ci_candidate_transfer as bridge
from scripts import ci_candidate_transfer_qualification as fixtures
from scripts import consumer_candidate_state as adapter
from scripts import m12_pinned_native, shared_serving_native


class ConsumerStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.fixtures.fixtures.FinalEvidenceContracts.setUpClass()
        cls.addClassCleanup(fixtures.fixtures.fixtures.FinalEvidenceContracts.tearDownClass)

    def setUp(self):
        self.fixture = fixtures.CandidateTransferTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.source = self.fixture.root, self.fixture.state
        fx = self.fixture.fixture.fx
        self.campaign = release_bundle.index(fx.package["envelope"], fx.keys["approver"])[
            "release_id"
        ]
        # Model the native producer's ORIGINAL report shape before sealing.
        fx.proposal["campaign_id"] = self.campaign
        self.repinned_report(fx.proposal)
        self.key_path = fx.release.authorities.keys["root"]
        self.key_bytes = bounded_read(self.key_path)
        self.foreign_key = fx.release.authorities.keys["publisher"]
        self.sealed = self.fixture.seal()
        self.enterContext(patch.object(storage, "connect", side_effect=AssertionError("no SQL")))
        self.enterContext(
            patch.object(bootstrap, "initialize", side_effect=AssertionError("no bootstrap"))
        )
        self.enterContext(
            patch.object(signing, "create_key", side_effect=AssertionError("no key mint"))
        )
        self.enterContext(patch.object(signing, "sign", side_effect=AssertionError("no signing")))
        self.enterContext(patch("subprocess.run", side_effect=AssertionError("no processes")))
        self.enterContext(patch("subprocess.Popen", side_effect=AssertionError("no processes")))

    def repinned_report(self, report):
        fixture = self.fixture.fixture
        pin = fixture.fx.pinfile("evidence/release-native.json", report)
        self.fixture.authority["freeze"]["evidence/release-native.json"] = pin
        fixture.index["freeze"] = self.fixture.authority["freeze"].copy()
        self.fixture.authority["freeze_pin"] = fixture.fx.pinfile(
            bridge.transfer.RECEIPT, fixture.index
        )

    def materialize(self, **changes):
        result = self.sealed
        arguments = (
            dict(
                trust_key_path=self.key_path,
                key=fixtures.KEY,
                phase=self.fixture.phase,
                **copy.deepcopy(self.fixture.authority),
                expected_context=result["context"],
                ciphertext_pin=result["ciphertext_sha256"],
                manifest_pin=result["manifest_sha256"],
            )
            | changes
        )
        return adapter.materialize(self.root, result["envelope"], **arguments)

    @contextmanager
    def intercept_view(self, callback):
        ordinary = bridge.materialize

        @contextmanager
        def intercepted(*args, **kwargs):
            with ordinary(*args, **kwargs) as (state, summary):
                callback(state)
                yield state, summary

        with patch.object(bridge, "materialize", intercepted):
            yield

    def removed(self):
        self.fixture.no_temporary_state()
        self.assertEqual(bounded_read(self.key_path), self.key_bytes)
        self.assertEqual(
            digest(bounded_read(self.source / "evidence/release-native.json")),
            self.fixture.authority["freeze"]["evidence/release-native.json"],
        )

    def test_exact_original_bytes_and_consumer_owner_contracts(self):
        initial = {}

        def remember(state):
            initial.update(
                (p.relative_to(state).as_posix(), bounded_read(p))
                for p in state.rglob("*")
                if p.is_file()
            )

        with self.intercept_view(remember), self.materialize() as (state, summary):
            marker = storage_pki.workspace_id(state)
            self.assertRegex(marker, r"^[0-9a-f]{32}$")
            self.assertEqual(summary["workspace_id"], marker)
            self.assertEqual(summary["campaign_id"], self.campaign)
            self.assertFalse(summary["storage_imported"])
            self.assertFalse(summary["release_ready"])
            self.assertEqual(summary["handling"], "private")
            self.assertEqual(bounded_read(state / "keys/trust.pem"), self.key_bytes)
            public = signing.encode64(
                signing.load_key(state / "keys/trust.pem").public_key().public_bytes_raw()
            )
            self.assertEqual(public, decode(initial["trusted-keys.json"])["trust"])
            report = f"release-proposals/{self.campaign}/report.json"
            policy = f"release-proposals/{self.campaign}/policy-envelope.json"
            self.assertEqual(bounded_read(state / report), initial["evidence/release-native.json"])
            index = decode(initial[bridge.transfer.RECEIPT])
            self.assertEqual(
                bounded_read(state / policy),
                canonical(decode(initial[bridge.transfer.CAS + index["policy_reference"]])),
            )
            added = {"workspace.json", "keys/trust.pem", report, policy}
            self.assertEqual(
                {p.relative_to(state).as_posix() for p in state.rglob("*") if p.is_file()},
                initial.keys() | added,
            )
            for name, raw in initial.items():
                self.assertEqual(bounded_read(state / name), raw)
            pins = self.fixture.authority["freeze"]
            source = self.fixture.fixture.fx.source
            env = dict(
                GITHUB_RUN_ID="123456",
                GITHUB_RUN_ATTEMPT="1",
                GITHUB_JOB="consumer",
                M11_PROPOSAL_SHA256=pins["evidence/release-native.json"],
                M12_PROPOSAL_SHA256=pins["evidence/release-native.json"],
                M11_DEMO_SHA256=pins["storage-demo.json"],
            )
            with (
                patch.dict(os.environ, env, clear=True),
                patch.object(
                    m12_pinned_native.cluster,
                    "validate_cluster",
                    return_value=dict(workspace_id=marker, namespace_uid="owned-cluster"),
                ),
                patch.object(m12_pinned_native, "source", return_value=source),
            ):
                m12 = m12_pinned_native.owner(
                    self.root, state, source["image_id"], pins["evidence/release-native.json"]
                )
                self.assertEqual(
                    shared_serving_native.owner(self.root, state, source["image_id"]), m12
                )
                self.assertEqual(m12["workspace"], marker)
                self.assertEqual(m12["proposal_sha256"], pins["evidence/release-native.json"])
        self.assertFalse(state.exists())
        self.removed()

    def test_foreign_malformed_missing_and_wrong_algorithm_private_keys_rejected(self):
        malformed = self.root / "malformed.pem"
        atomic_write(malformed, b"private-invalid-sentinel")
        wrong = self.root / "wrong-algorithm.pem"
        atomic_write(
            wrong,
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        for key in (self.foreign_key, malformed, wrong, self.root / "missing.pem"):
            with (
                self.subTest(key=key.name),
                self.assertRaisesRegex(Rejected, "^consumer_candidate_state_rejected$"),
            ):
                with self.materialize(trust_key_path=key):
                    self.fail("bad key yielded state")
            self.removed()

    def test_tampered_or_missing_closure_rejected_inside_live_context(self):
        for delete in (False, True):

            def corrupt(state):
                path = state / (
                    bridge.transfer.CAS + self.fixture.authority["expected"]["proposal_reference"]
                )
                if delete:
                    path.unlink()
                else:
                    atomic_write(path, bounded_read(path) + b" ")

            with self.subTest(delete=delete), self.intercept_view(corrupt):
                with self.assertRaisesRegex(Rejected, "^consumer_candidate_state_rejected$"):
                    with self.materialize():
                        self.fail("changed closure yielded state")
            self.removed()

    def test_foreign_workspace_keys_credentials_and_empty_directories_refused(self):
        for name in (
            "workspace.json",
            "keys/trust.pem",
            "storage.json",
            "storage-clients/promoter/connection.json",
            "kubeconfig",
            "release-proposals/old/report.json",
            "foreign-empty/",
        ):

            def foreign(state):
                path = state / name
                if name.endswith("/"):
                    path.mkdir()
                else:
                    atomic_write(path, b"foreign-owned-sentinel")

            with self.subTest(name=name), self.intercept_view(foreign):
                with self.assertRaisesRegex(Rejected, "^consumer_candidate_state_rejected$"):
                    with self.materialize():
                        self.fail("foreign workspace yielded")
            self.removed()

    def test_report_campaign_must_be_valid_and_equal_signed_release_id(self):
        original = self.fixture.fixture.fx.proposal
        for campaign in (None, "../escape", "f" * 32):
            with self.subTest(campaign=campaign):
                self.repinned_report(original | {"campaign_id": campaign})
                self.sealed = self.fixture.seal()
                with self.assertRaisesRegex(Rejected, "^consumer_candidate_state_rejected$"):
                    with self.materialize():
                        self.fail("campaign mismatch yielded")
                self.removed()

    def test_wrong_owner_freeze_source_and_candidate_pins_never_yield(self):
        original = self.fixture.authority
        for changes in (
            dict(run_owner=original["run_owner"] | {"run_attempt": 2}),
            dict(freeze=original["freeze"] | {"storage-demo.json": "a" * 64}),
            dict(expected=original["expected"] | {"source_revision": "a" * 40}),
            dict(expected=original["expected"] | {"candidate_reference": "a" * 64}),
        ):
            with self.subTest(changes=list(changes)), self.assertRaises(Rejected):
                with self.materialize(**changes):
                    self.fail("foreign authority yielded")
            self.removed()

    def test_partial_write_error_cleans_every_owned_file_preserving_caller_key(self):
        real_write = adapter.atomic_write
        for failed in ("workspace.json", "trust.pem", "report.json", "policy-envelope.json"):

            def failing(path, content):
                real_write(path, content)
                if path.name == failed:
                    raise OSError("private-error-must-not-escape")

            with self.subTest(failed=failed), patch.object(adapter, "atomic_write", failing):
                with self.assertRaisesRegex(Rejected, "^consumer_candidate_state_rejected$"):
                    with self.materialize():
                        self.fail("partial write yielded")
            self.removed()

    def test_readback_mismatch_refused_and_cleaned(self):
        real_read = adapter.bounded_read

        def altered(path, *args):
            raw = real_read(path, *args)
            return raw + b" " if Path(path).name == "report.json" else raw

        with patch.object(adapter, "bounded_read", altered):
            with self.assertRaisesRegex(Rejected, "^consumer_candidate_state_rejected$"):
                with self.materialize():
                    self.fail("readback mutation yielded")
        self.removed()

    def test_window_expiring_during_preparation_is_not_extended(self):
        real_write = adapter.atomic_write
        expires = self.fixture.fixture.fx.values["proposal_expires_at"]

        def delayed(path, content):
            real_write(path, content)
            if path.name == "policy-envelope.json":
                self.fixture.clock = expires - 599

        with patch.object(adapter, "atomic_write", delayed):
            with self.assertRaisesRegex(Rejected, "^consumer_candidate_state_rejected$"):
                with self.materialize():
                    self.fail("expired window yielded")
        self.removed()

    def test_consumer_error_propagates_and_context_cannot_be_reused(self):
        context = self.materialize()
        error = RuntimeError("caller failure")
        with self.assertRaises(RuntimeError) as caught:
            with context as (state, _):
                raise error
        self.assertIs(caught.exception, error)
        self.assertFalse(state.exists())
        with self.assertRaises((AttributeError, RuntimeError)):
            with context:
                self.fail("reused context yielded")
        self.removed()

    def test_another_call_gets_fresh_workspace_and_original_proposal(self):
        with self.materialize() as (first, one):
            report = bounded_read(first / "evidence/release-native.json")
        with self.materialize() as (second, two):
            self.assertNotEqual(first, second)
            self.assertNotEqual(one["workspace_id"], two["workspace_id"])
            self.assertEqual(one["campaign_id"], two["campaign_id"])
            self.assertEqual(bounded_read(second / "evidence/release-native.json"), report)
        self.assertFalse(first.exists())
        self.assertFalse(second.exists())
        self.removed()

    def test_materializer_cleanup_failure_remains_visible(self):
        ordinary = bridge.TemporaryDirectory
        failure = OSError("owned staging cleanup failed")

        @contextmanager
        def failing_cleanup(*args, **kwargs):
            # Real owned fixture cleanup completes even if the assertion fails;
            # inject the exit error only afterwards, without leaking test state.
            with ordinary(*args, **kwargs) as directory:
                yield directory
            raise failure

        with patch.object(bridge, "TemporaryDirectory", failing_cleanup):
            with self.assertRaises(OSError) as caught:
                with self.materialize() as (state, _):
                    self.assertTrue((state / "keys/trust.pem").is_file())
        self.assertIs(caught.exception, failure)
        self.assertFalse(state.exists())
        self.removed()


if __name__ == "__main__":
    unittest.main()
