"""Exercise both consumers with one signed controlled candidate and ordinary private readers."""

import secrets
import unittest
from contextlib import contextmanager
from copy import deepcopy
from unittest.mock import patch

from mlsecops import release_bundle, signing
from mlsecops.contracts import Rejected, bounded_read, canonical, digest
from scripts import candidate_lineage_qualification as lineage
from scripts import ci_campaign_control as control
from scripts import ci_campaign_handoff as handoff
from scripts import ci_candidate_transfer as bridge
from scripts import ci_private_assets_qualification as store_fixture
from scripts import ci_upstream_transfer_qualification as upstream_fixture
from scripts import ci_validation_transfer as validation
from scripts import frozen_candidate_transfer as transfer

KEY = bytes(range(32))


class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        upstream_fixture.UpstreamTransferTests.setUpClass()
        cls.addClassCleanup(upstream_fixture.UpstreamTransferTests.doClassCleanups)

    def setUp(self):
        fixture = upstream_fixture.UpstreamTransferTests()
        rows = canonical(
            [dict(entity_id=i + 1000, label=i % 2, features=[0.5] * 6) for i in range(32)]
        )
        with patch.object(
            lineage.CandidateLineageContracts, "split_contents", {"validation": rows}, create=True
        ):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root = fixture.root
        self.owner = owner = fixture.owner
        owner["run_owner"].update(producer_job="producer", run_id=123)
        self.source = {k: owner["expected"][k] for k in transfer.delivery.SOURCE}
        fx = fixture.fx
        self.trust = fx.release.authorities.keys["root"]
        campaign = release_bundle.index(fx.package["envelope"], fx.keys["approver"])["release_id"]
        fx.proposal["campaign_id"] = campaign
        owner["freeze"][transfer.delivery.PROPOSAL] = fx.pinfile(
            transfer.delivery.PROPOSAL, fx.proposal
        )
        fixture.fixture.index["freeze"] = owner["freeze"].copy()
        owner["freeze_pin"] = fx.pinfile(transfer.RECEIPT, fixture.fixture.index)
        self.origin = dict(workspace_id="a" * 32, container_id="c" * 64, offline_pin="e" * 64)
        self.reports = fixture.reports
        packets = {
            name: bridge.seal(
                fixture.root, fixture.state, **owner, key=KEY, phase=control.PHASES[name]
            )
            for name in ("candidate-shared", "candidate-serving")
        }
        packets["upstream-serving"] = fixture.seal()
        retained = validation.retain(fixture.root, fixture.state, rows, **owner)
        packets["validation-serving"] = validation.seal(
            fixture.root, fixture.state, retained, **owner, key=KEY, phase="M13"
        )
        self.api = store_fixture.StoreAPI()
        journal = []
        self.public, self.receipt = handoff.publish(
            self.api,
            owner=owner,
            reports=self.reports,
            origin=self.origin,
            packets=packets,
            key=KEY,
            checkpoint=journal.append,
        )
        self.journal = journal
        self.assertEqual(journal[-1]["storage"], self.receipt)
        self.api.downloads.clear()

    def downloaded(self):
        return [
            self.api.assets[identifier]["name"].removesuffix(".bin")
            for identifier, _ in self.api.downloads
        ]

    def view(self, job, **overrides):
        args = dict(
            job=job,
            key=KEY,
            trusted_public=self.public,
            source=self.source,
            trust_key_path=self.trust,
            run_owner=self.owner["run_owner"],
            api=self.api,
        )
        return handoff.open_consumer(self.root, **(args | overrides))

    def test_two_separate_workspaces_read_the_same_frozen_candidate(self):
        ids = set()
        for job, names in (
            ("shared", ["candidate-shared"]),
            ("serving", ["candidate-serving", "upstream-serving", "validation-serving"]),
        ):
            self.api.downloads.clear()
            with self.view(job) as (state, prepared, record, packets):
                self.assertEqual(record["owner"], self.owner)
                self.assertEqual(record["origin"], self.origin)
                self.assertEqual(self.downloaded(), ["producer-control", *names])
                self.assertEqual(set(packets), set(names))
                self.assertFalse(prepared["storage_imported"])
                ids.add(prepared["workspace_id"])
                if job == "serving":
                    for gate, pin in self.reports.items():
                        transfer.final.published_report(state, gate, pin)
                    value = packets["validation-serving"]
                    with validation.materialize(
                        self.root,
                        state,
                        value["envelope"],
                        key=KEY,
                        **record["owner"],
                        phase="M13",
                        expected_context=value["context"],
                        ciphertext_pin=value["ciphertext_sha256"],
                    ) as (path, _):
                        self.assertTrue(bounded_read(path))
            self.assertFalse(state.exists())
        self.assertEqual(len(ids), 2)

    def test_foreign_job_or_public_key_refuses_before_packet_download(self):
        for job, override, expected in (
            ("other", {}, []),
            ("shared", {"trusted_public": "invalid"}, ["producer-control"]),
        ):
            self.api.downloads.clear()
            with self.assertRaises(Rejected), self.view(job, **override):
                self.fail("refusal required")
            self.assertEqual(self.downloaded(), expected)

    def test_packet_substitution_and_callback_failure_remove_consumer_state(self):
        identifier = self.receipt["assets"]["validation-serving"]["id"]
        raw = self.api.contents[identifier]
        self.api.contents[identifier] = raw[:-1] + bytes([raw[-1] ^ 1])
        with self.assertRaises(Rejected), self.view("serving"):
            self.fail("foreign ciphertext accepted")
        with self.assertRaisesRegex(RuntimeError, "controlled"), self.view("shared") as (state, *_):
            raise RuntimeError("controlled")
        self.assertFalse(state.exists())

    def test_receiver_refuses_reused_workspace_and_mismatched_upstream_readback(self):
        with (
            patch.object(
                handoff.consumer_candidate_state.secrets,
                "token_hex",
                return_value=self.origin["workspace_id"],
            ),
            self.assertRaisesRegex(Rejected, "campaign_consumer_workspace"),
            self.view("shared"),
        ):
            self.fail("producer workspace reused")
        materialize = handoff.upstream.materialize

        @contextmanager
        def mismatch(*args, **kwargs):
            with materialize(*args, **kwargs) as (view, summary):
                yield view, summary | {"reports": {}}

        with (
            patch.object(handoff.upstream, "materialize", mismatch),
            self.assertRaisesRegex(Rejected, "campaign_consumer_upstream"),
            self.view("serving"),
        ):
            self.fail("unverified receipts accepted")
        self.assertFalse(list((self.root / ".runtime/ci-candidate-transfers").glob("*")))

    def test_invalid_source_is_rejected_before_private_repository_read(self):
        for field, value in (
            ("source_revision", "x" * 40),
            ("image_id", "sha256:bad"),
            ("source_fingerprint", 0),
        ):
            with (
                self.assertRaises(Rejected),
                self.view("shared", source=self.source | {field: value}),
            ):
                self.fail("invalid source")
            self.assertEqual(self.downloaded(), [])

    def test_publisher_without_signing_callback_cannot_report_success(self):
        with (
            patch.object(handoff.store, "publish", return_value=self.receipt),
            self.assertRaisesRegex(Rejected, "campaign_control_missing"),
        ):
            handoff.publish(
                self.api,
                owner=self.owner,
                reports={},
                origin=self.origin,
                packets={},
                key=KEY,
                checkpoint=list().append,
            )

    def test_preupload_journal_verifies_control_after_expiry_without_admitting_a_consumer(self):
        retained = self.journal[-2]
        self.assertIsNotNone(retained["issuer"])
        self.assertNotIn("producer-control", retained["storage"]["assets"])
        raw = self.api.contents[self.receipt["assets"]["producer-control"]["id"]]
        args = dict(key=KEY, run_owner=self.owner["run_owner"], source=self.source)
        with patch("time.time", return_value=self.receipt["expires_at"] + 20):
            self.assertTrue(control.verify_retained_control(raw, retained, **args))
            self.assertTrue(control.verify_retained_control(raw, self.journal[-1], **args))
            with self.assertRaises(Rejected):
                control.retained_identity(raw, retained, **args)
            with patch.object(
                bridge, "_now", side_effect=AssertionError("historical reader consulted live clock")
            ):
                self.assertEqual(
                    control.retained_identity(raw, self.journal[-1], **args),
                    dict(owner=self.owner, origin=self.origin, reports=self.reports),
                )
            with self.assertRaises(Rejected), self.view("serving"):
                self.fail("expired campaign admitted")
        for changed in (
            self.journal[0],
            retained | {"issuer": retained["issuer"] | {"public": "wrong"}},
            retained | {"storage": retained["storage"] | {"private_head": "0" * 40}},
        ):
            with self.assertRaises(Rejected):
                control.verify_retained_control(raw, changed, **args)
        with self.assertRaises(Rejected):
            control.verify_retained_control(raw[:-1], retained, **args)

    def test_missing_checkpoint_refuses_before_asset_mutation(self):
        with self.assertRaisesRegex(Rejected, "campaign_checkpoint_missing"):
            handoff.publish(
                None,
                owner=self.owner,
                reports={},
                origin=self.origin,
                packets={},
                key=KEY,
                checkpoint=None,
            )

    def test_authenticated_historical_identity_still_requires_valid_ordinary_authority(self):
        journal = deepcopy(self.journal[-1])
        pin = journal["storage"]["assets"][handoff.store.CONTROL]
        args = dict(key=KEY, run_owner=self.owner["run_owner"], source=self.source)
        record = control.read(self.api.contents[pin["id"]], trusted_public=self.public, **args)
        path = self.root / "historical-issuer-fixture.pem"
        journal["issuer"]["public"] = signing.create_key(path)
        aad = control.binding(args["run_owner"], self.source)
        for changes in (
            dict(origin=self.origin | {"workspace_id": "foreign"}),
            dict(owner=self.owner | {"freeze": None}),
            dict(owner=self.owner | {"run_owner": args["run_owner"] | {"run_attempt": 2}}),
            dict(
                owner=self.owner
                | {"expected": self.owner["expected"] | {"source_revision": "0" * 40}}
            ),
            dict(reports=self.reports | {"M03": "bad pin"}),
        ):
            signed = canonical(signing.sign(record | changes, control.KIND, path))
            nonce = secrets.token_bytes(12)
            raw = control.MAGIC + nonce + control.cipher(KEY).encrypt(nonce, signed, aad)
            pin.update(size=len(raw), sha256=digest(raw))
            journal["issuer"]["control_sha256"] = pin["sha256"]
            self.assertTrue(control.verify_retained_control(raw, journal, **args))
            with self.subTest(field=next(iter(changes))), self.assertRaises(Rejected):
                control.retained_identity(raw, journal, **args)
