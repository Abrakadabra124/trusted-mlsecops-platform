"""Terminal caller with signed remote checkpoints and two receiver-signed primaries."""

import unittest
from copy import deepcopy
from functools import partial
from unittest.mock import Mock, patch

from mlsecops import final_evidence as final
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical
from scripts import ci_campaign_handoff_qualification as campaign
from scripts import ci_campaign_journal as journal
from scripts import ci_campaign_journal_qualification as journal_fixture
from scripts import ci_campaign_terminal_qualification as terminal
from scripts import ci_primary_carrier_qualification as carrier_fixture
from scripts import ci_private_assets as assets
from scripts import ci_terminal_primary as verifier


class TerminalPrimaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        campaign.HandoffTests.setUpClass()
        cls.addClassCleanup(campaign.HandoffTests.doClassCleanups)
        cls.fx = campaign.HandoffTests()
        cls.addClassCleanup(cls.fx.doCleanups)
        cls.fx.setUp()

    def setUp(self):
        from scripts import ci_primary_handoff as primary
        from scripts import ci_primary_store_qualification as remote

        fx = self.fx
        self.caller = terminal.TerminalTests()
        self.caller.setUp()
        self.caller.private = deepcopy(fx.api)
        self.caller.private.mutations.clear()
        rows = self.caller.rows
        sha = fx.source["source_revision"]
        del rows[terminal.BASE + "/commits/" + terminal.SOURCE["source_revision"]]
        rows[terminal.BASE + "/commits/" + sha] = {"sha": sha}
        for row in (rows[terminal.ATTEMPT], rows[terminal.RUN], *rows[terminal.JOB_LIST]["jobs"]):
            row.update(head_sha=sha, conclusion="success")

        self.durable = {
            stem: fx.api.contents[pin["id"]] for stem, pin in fx.receipt["assets"].items()
        }
        self.read = Mock(side_effect=lambda stem, limit: self.durable[stem])
        self.binding = dict(run_owner=fx.owner["run_owner"], source=fx.source)
        self.api = remote.ReleaseAPI()
        self.release = remote.RELEASE | {"release_id": 701}
        self.api.release["id"] = 701
        self.api.next_id = 500
        self.enterContext(patch.object(remote, "PATH", assets._endpoint(self.release)))
        self.keys = {}
        self.replayed = []
        self.cas = carrier_fixture.CarrierTests()
        self.addCleanup(self.cas.doCleanups)
        self.cas.setUp()
        self.primary = primary
        for role in verifier.ROLES:
            self.install(role)

    def install(self, role, *, origin=None, upstream=None):
        fx, cas, primary = self.fx, self.cas, self.primary
        args = cas.authority(role) | fx.owner
        scope = primary.ROLES[role]
        record = cas.record(role)
        if role == "shared":
            record.update(args)
        else:
            args["report_pins"].update(fx.reports if upstream is None else upstream)
            record["authority"] = args
        pin = final.retain(cas.source, canonical(record) + b"\n")
        receipt = dict(reports=args["report_pins"])
        result = dict(
            receipt=receipt,
            release_ready=False,
            scope=scope.SCOPE,
            classification=record["classification"],
        )

        # The semantic reader is the component boundary. Real handoff verifies
        # the signature, restores the archive, and compares the reader result.
        def read_restored(root, destination, *, index_pin, **authority):
            self.assertEqual((root, index_pin, authority), (fx.root, pin, args))
            self.assertEqual(final.blob(destination, pin), canonical(record) + b"\n")
            self.replayed.append(role)
            return result

        self.enterContext(patch.object(scope, "replay", read_restored))
        observed = dict(
            destination=cas.source,
            index_pin=pin,
            arguments=args,
            replay=result,
            release_ready=False,
            origin=fx.origin if origin is None else origin,
            consumer_offline=cas.one,
            cleanup_owner=self.binding["run_owner"] | {"producer_job": role},
            cleanup=dict.fromkeys(primary.CLEANUP[role], True),
            gate_counts=dict.fromkeys(primary.GATES[role], 1),
        )
        packet, public = primary.seal(
            cas.root, observed, role=role, key=campaign.KEY, **self.binding
        )
        self.api.rows[:] = [row for row in self.api.rows if row["name"] != role + ".bin"]
        self.api.install(role + ".bin", packet)
        self.keys[role] = dict(job_id=11 if role == "shared" else 12, public=public)

    def callback(self, **changes):
        params = dict(
            api=self.api,
            release=self.release,
            key=campaign.KEY,
            receiver_keys=self.keys,
            read_asset=self.read,
        )
        return verifier.replayer(self.fx.root, **(params | changes))

    def clean(self, callback=None, **changes):
        base = dict(
            source=self.fx.source,
            replay_retained=callback or self.callback(),
            read_journal=lambda **kw: dict(
                checkpoint=self.fx.journal[-1], complete=True, tip=terminal.TIP
            ),
        )
        return self.caller.clean(**(base | changes))

    def refused(self, **changes):
        with self.assertRaises(Rejected):
            self.clean(**changes)
        self.assertEqual(self.caller.private.mutations, [])

    def test_cleanup_from_archives_routes_reads_and_mutations_to_separate_clients(self):
        from scripts import ci_origin_backup as backup

        args = dict(
            source_api=self.caller.public_api,
            reader_api=self.api,
            writer_api=self.caller.private,
            **self.binding,
            journal_release=journal_fixture.PIN.copy(),
            origin_release=dict(self.release, release_id=702, name="ci-origin-123-1"),
            primary_release=self.release,
            journal_public="out-of-band",
            receiver_keys=self.keys,
            key=campaign.KEY,
            expected_tip=terminal.TIP,
            expected_jobs=terminal.JOBS,
        )
        with (
            patch.object(
                journal,
                "recover",
                return_value=dict(complete=True, tip=terminal.TIP, checkpoint=self.fx.journal[-1]),
            ) as recover,
            patch.object(backup, "reader", return_value=self.read) as reader,
        ):
            for change in (dict(origin_release=self.release), dict(reader_api=self.caller.private)):
                with self.subTest(field=next(iter(change))), self.assertRaises(Rejected):
                    verifier.cleanup_from_archives(self.fx.root, **(args | change))
            recover.assert_not_called()
            working_id = self.fx.journal[-1]["storage"]["release_id"]
            with self.assertRaises(Rejected):
                verifier.cleanup_from_archives(
                    self.fx.root,
                    **(
                        args
                        | dict(origin_release=dict(args["origin_release"], release_id=working_id))
                    ),
                )
            reader.assert_not_called()
            self.assertEqual(self.caller.private.mutations, [])
            verifier.cleanup_from_archives(self.fx.root, **args)
            reader.assert_called_once_with(
                self.api,
                release=args["origin_release"],
                checkpoint=self.fx.journal[-1],
                **self.binding,
            )
            self.assertIs(recover.call_args.args[0], self.api)
            self.assertEqual(recover.call_args.kwargs["expected_tip"], terminal.TIP)
            self.assertIsNone(self.caller.private.release)
            self.assertIsNone(self.caller.private.tag)

    def test_remote_anchored_terminal_cleanup_after_expiry(self):
        remote = journal_fixture.JournalAPI()
        path = self.fx.root / "terminal-journal-fixture.pem"
        params = dict(
            journal=journal_fixture.PIN, trusted_public=signing.create_key(path), key=campaign.KEY
        )
        append = journal.publisher(remote, key_path=path, **params, **self.binding)
        tips = [append(row) for row in self.fx.journal]
        recover = partial(journal.recover, remote, **params)
        callback = self.callback()
        self.keys["shared"]["public"] = self.keys["serving"]["public"]
        self.release["release_id"] = self.fx.receipt["release_id"]
        with patch("time.time", return_value=self.fx.receipt["expires_at"] + 100):
            self.refused(callback=callback, read_journal=recover, expected_tip=tips[-2])
            self.assertIsNone(self.clean(callback, read_journal=recover, expected_tip=tips[-1]))
        self.assertIsNone(self.caller.private.release)
        self.assertEqual(self.replayed, ["shared", "serving"])
        self.assertEqual(
            [call.args for call in self.read.call_args_list[:5]],
            [(stem, len(self.durable[stem])) for stem in (assets.CONTROL, *assets.PACKETS)],
        )
        self.assertEqual(self.read.call_count, 10)
        self.assertEqual(self.caller.private.downloads, [])
        self.assertEqual(len(self.api.rows), 2)

    def test_only_successful_exact_jobs_with_independent_keys_can_replay(self):
        for job in self.caller.rows[terminal.JOB_LIST]["jobs"]:
            with patch.dict(job, conclusion="skipped"):
                self.refused()
        for role in verifier.ROLES:
            for changes in (
                dict(job_id=99),
                dict(public=self.fx.public),
                dict(public=self.keys["serving" if role == "shared" else "shared"]["public"]),
            ):
                with (
                    self.subTest(role=role, field=next(iter(changes))),
                    patch.dict(self.keys[role], changes),
                ):
                    self.refused()
        self.refused(
            callback=self.callback(
                release=self.release | {"release_id": self.fx.receipt["release_id"]}
            )
        )
        self.read.assert_not_called()
        self.assertEqual(self.api.calls, [])

    def test_each_original_asset_must_be_independently_read_and_pinned(self):
        for stem, raw in self.durable.items():
            for bad in (raw[:-1], b"!" + raw[1:], raw[:-1] + bytes([raw[-1] ^ 1]), bytearray(raw)):
                with self.subTest(stem=stem), patch.dict(self.durable, {stem: bad}):
                    self.refused()
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.caller.private.downloads, [])

    def test_wrong_receiver_signature_origin_or_signed_upstream_report_blocks_cleanup(self):
        with patch.dict(self.keys["shared"], public=signing.encode64(bytes(range(32)))):
            self.refused()
        self.install("serving", origin=self.fx.origin | {"workspace_id": "0" * 32})
        self.refused()
        self.assertEqual(self.replayed, ["shared"])
        for gate in self.fx.reports:
            self.replayed.clear()
            self.install("serving", upstream=self.fx.reports | {gate: "0" * 64})
            self.refused()
            self.assertEqual(self.replayed, ["shared", "serving"])

    def test_private_release_pin_and_second_reader_failure_block_cleanup(self):
        self.refused(callback=self.callback(release=self.release | {"target_commitish": "0" * 40}))
        self.api.rows.pop()
        self.refused()
        self.install("serving")
        with patch.object(
            self.primary.ROLES["serving"],
            "replay",
            side_effect=Rejected("controlled reader refusal"),
        ):
            self.refused()
