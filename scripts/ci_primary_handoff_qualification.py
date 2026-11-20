"""Post-teardown transport tests. Native resource observations and private HTTPS are controlled."""

import copy
import shutil
import unittest
from unittest.mock import patch

from mlsecops.contracts import Rejected
from mlsecops.signing import create_key as primary_create_key
from mlsecops.signing import sign as primary_sign
from scripts import ci_primary_handoff as primary
from scripts import ci_serving_retention_qualification as serving
from scripts import ci_shared_job_qualification as shared


class SharedTransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        shared.RetainedFlowTests.setUpClass()
        cls.addClassCleanup(shared.RetainedFlowTests.doClassCleanups)

    def setUp(self):
        self.fx = shared.RetainedFlowTests()
        self.addCleanup(self.fx.doCleanups)
        self.fx.setUp()
        self.result = self.fx.execute()
        self.context = dict(role="shared", run_owner=shared.RUN, source=self.fx.source)
        self.keys = dict(key=bytes(range(32)))
        self.expected = dict(owner=self.fx.owner, origin=shared.ORIGIN)
        self.packet, self.public = self.seal()

    def seal(self):
        return primary.seal(self.fx.root, self.result, **self.context, **self.keys)

    def restore(self, **changes):
        args = dict(**self.context, **self.keys, **self.expected, trusted_public=self.public)
        return primary.replay(self.fx.root, self.packet, **(args | changes))

    def test_replays_after_source_result_directory_is_gone(self):
        from scripts import ci_primary_store as store
        from scripts import ci_primary_store_qualification as remote

        api = remote.ReleaseAPI()
        release = remote.RELEASE | {"name": f"ci-primary-{shared.RUN['run_id']}-1"}
        api.release.update(name=release["name"], tag_name=release["name"])
        target = self.context | {"release": release}
        receipt = store.put(api, self.packet, **target)
        self.assertNotIn(self.result["index_pin"].encode(), self.packet)
        del self.packet
        runtime = self.fx.root / ".runtime"
        self.assertTrue(self.result["destination"].resolve().is_relative_to(runtime.resolve()))
        shutil.rmtree(runtime)
        self.assertFalse(runtime.exists())
        self.packet = store.get_unverified(api, **target)
        self.assertEqual(self.packet, store.get(api, receipt, **target))
        self.assertEqual(self.restore(), self.result["replay"])
        self.assertEqual(list(runtime.iterdir()), [])

    def test_wrong_job_origin_freeze_issuer_or_channel_key(self):
        for change in (
            dict(role="serving"),
            dict(origin=shared.ORIGIN | {"workspace_id": "0" * 32}),
            dict(owner=self.fx.owner | {"freeze_pin": "0" * 64}),
            dict(run_owner=shared.RUN | {"run_attempt": 2}),
            dict(trusted_public="a" * 44),
            dict(key=bytes(reversed(range(32)))),
        ):
            with self.subTest(field=next(iter(change))), self.assertRaises(Rejected):
                self.restore(**change)

    def test_damage_refused_before_cas_import(self):
        self.packet = self.packet[:-1] + bytes([self.packet[-1] ^ 1])
        with patch.object(primary.carrier, "unpack") as unpack, self.assertRaises(Rejected):
            self.restore()
        unpack.assert_not_called()

    def test_unfinished_or_foreign_job_cannot_export(self):
        for change in (
            dict(cleanup_owner=shared.RUN),
            dict(cleanup={"cluster": True, "sql": False}),
            dict(gate_counts={"M11": True, "M12": 1}),
            dict(release_ready=True),
            dict(role_leak="extra"),
        ):
            with self.subTest(field=next(iter(change))), self.assertRaises(Rejected):
                primary.seal(self.fx.root, self.result | change, **self.context, **self.keys)

    def test_original_replay_digest_must_match_imported_semantics(self):
        self.result["replay"]["receipt"]["unobserved"] = True
        self.packet, self.public = self.seal()
        with self.assertRaises(Rejected):
            self.restore()


class ServingTransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        serving.ServingExportTests.setUpClass()
        cls.addClassCleanup(serving.ServingExportTests.doClassCleanups)

    def test_serving_evidence_restores_without_live_resources(self):
        fx = serving.ServingExportTests()
        self.addCleanup(fx.doCleanups)
        fx.setUp()
        fx.owner["run_owner"] = shared.RUN.copy()
        captured = fx.retain()
        args = fx.owner
        source = {
            k: args["expected"][k] for k in ("image_id", "source_fingerprint", "source_revision")
        }
        shape = dict(role="serving", run_owner=shared.RUN, source=source, key=b"e" * 32)
        result = dict(
            destination=fx.destination,
            index_pin=captured["index_pin"],
            arguments=args,
            replay=fx.replay(captured),
            origin=shared.ORIGIN,
            consumer_offline="9" * 64,
            cleanup_owner=shared.RUN | {"producer_job": "serving"},
            cleanup=dict.fromkeys(("M13", "M14", "M15", "SQL"), True),
            gate_counts=dict.fromkeys(("M13", "M14", "M15"), 1),
            release_ready=False,
        )
        # The native fixture forbids re-signing models. Only the transport receives a new issuer.
        with (
            patch.object(primary.signing, "create_key", primary_create_key),
            patch.object(primary.signing, "sign", primary_sign),
        ):
            packet, public = primary.seal(fx.root, result, **shape)
        owner = {
            k: copy.deepcopy(args[k]) for k in ("freeze_pin", "freeze", "expected", "run_owner")
        }
        shutil.rmtree(fx.state)
        shutil.rmtree(fx.destination)
        self.assertEqual(
            primary.replay(
                fx.root, packet, **shape, owner=owner, origin=shared.ORIGIN, trusted_public=public
            ),
            result["replay"],
        )
