"""Independent refusal and shared-snapshot contracts. No live SQL, listener or worker."""

import copy
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops.contracts import Rejected, digest
from scripts import restore_negative_native as native


class ArchiveFaults(unittest.TestCase):
    def test_restored_serving_client_rejects_redirected_port_and_foreign_credentials(self):
        from mlsecops.contracts import write_json

        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            marker = {"port": 15440}
            original = {"ca.crt": b"ca", "ml_serving.crt": b"crt", "ml_serving.key": b"key"}
            (target / "storage-pki").mkdir()
            for name, value in original.items():
                (target / "storage-pki" / name).write_bytes(value)
            client = target / "storage-clients/serving"
            client.mkdir(parents=True)
            for name, owned in native.CLIENT_FILES.items():
                (client / name).write_bytes(original[owned])
            config = dict(
                schema_version=1,
                role="serving",
                port=15440,
                host="127.0.0.1",
                certificates={
                    name: digest((client / name).read_bytes()) for name in ("ca.crt", "client.crt")
                },
            )
            write_json(client / "connection.json", config)
            with native.target_client(target, marker) as pinned:
                self.assertNotEqual(pinned, client)
                self.assertEqual((pinned / "client.key").read_bytes(), b"key")
                (client / "client.key").write_bytes(b"foreign")
                self.assertEqual((pinned / "client.key").read_bytes(), b"key")
            self.assertFalse(pinned.exists())
            with self.assertRaises(Rejected), native.target_client(target, marker):
                self.fail()
            (client / "client.key").write_bytes(b"key")
            write_json(client / "connection.json", dict(config, port=15439))
            with self.assertRaises(Rejected), native.target_client(target, marker):
                self.fail()

    def setUp(self):
        self.model = b"controlled-model\0"
        self.pin = digest(self.model)
        self.row = self.pin.encode() + b"\t\\\\x" + self.model.hex().encode() + b"\t"
        self.dump = b"PGDMP-" + self.row + b"1700000000\n" + self.pin.encode()

    def test_actual_copy_row_is_corrupted_or_replaced_with_valid_unrelated_cas_row(self):
        for case in ("corrupt", "missing"):
            changed, row = native.archive_fault(self.dump, self.pin, case)
            self.assertEqual(len(changed), len(self.dump))
            self.assertTrue(changed.startswith(b"PGDMP-"))
            self.assertTrue(changed.endswith(self.pin.encode()))
            self.assertEqual(row["before"], self.pin)
            self.assertEqual(row["occurrences"], 1)
            self.assertNotEqual(row["after"], self.pin)
            self.assertEqual(row["lookup_after"], self.pin if case == "corrupt" else row["after"])
            self.assertNotIn(self.row, changed)
            self.assertIn(row["lookup_after"].encode() + b"\t", changed)

    def test_digest_mentions_and_wrong_payload_do_not_identify_a_model_row(self):
        for dump in (self.pin.encode(), self.dump.replace(self.model.hex().encode(), b"6162")):
            with self.assertRaises(Rejected):
                native.archive_fault(dump, self.pin, "missing")

    def test_refuses_wrong_reason_and_unexpected_success(self):
        for fn in (lambda: None, lambda: native.require(False)):
            with self.assertRaises(Rejected):
                native.refusal(fn, "trust_key_revoked")

    def test_nonhosted_seed_never_touches_source(self):
        with (
            patch.object(native.promoter, "hosted", side_effect=Rejected("host")),
            patch.object(native.storage_bootstrap, "validate") as validate,
        ):
            with (
                self.assertRaisesRegex(Rejected, "host"),
                native.seeded(
                    ".",
                    ".",
                    "tag",
                    "a" * 32,
                    bind_candidate=native.serving_native.bind_real_runtime,
                ),
            ):
                self.fail()
            validate.assert_not_called()

    def test_candidate_binder_is_required_by_keyword_before_any_setup(self):
        with patch.object(native.promoter, "hosted", side_effect=AssertionError("entered setup")):
            for positional in ((), (native.serving_native.bind_real_runtime,)):
                with self.subTest(positional=bool(positional)), self.assertRaises(TypeError):
                    with native.seeded(".", ".", "tag", "a" * 32, *positional):
                        self.fail()


class SharedSnapshot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import json
        import time
        from contextlib import ExitStack, contextmanager, nullcontext
        from datetime import UTC, datetime
        from unittest.mock import MagicMock, Mock

        from mlsecops import model, promotion_recovery, signing, storage_schema
        from mlsecops.contracts import decode, write_json

        cls.campaign = "7" * 32
        cls.image = "sha256:" + "f" * 64
        with ExitStack() as st:
            root = Path(st.enter_context(TemporaryDirectory())).resolve()
            src, dst, authority = [root / k for k in ("source", "dest", "trust")]
            (authority / "evidence").mkdir(parents=True)
            policy = {"controlled": "approval recovery"}
            write_json(root / "policies/local-cpu.json", policy)
            public = {k: signing.create_key(src / "keys" / (k + ".pem")) for k in signing.ROLES}
            write_json(src / "trusted-keys.json", public)

            def marker(c, port):
                return dict(
                    workspace_id=c * 32,
                    container_id=c * 64,
                    network_id=c * 64,
                    volume=f"tml-{c * 12}-storage-data",
                    port=port,
                )

            source, target = marker("a", 15439), marker("b", 15440)
            refs, db_rows, values, trust_docs = [], [], {}, []
            conn = MagicMock()
            conn.__enter__.return_value = conn

            def current_second():
                return int(time.time())

            db_rows.append(("other", 1, "5" * 64, None, f"{current_second()}.000000"))

            def execute(q, params=()):
                if "ORDER BY environment" in q:
                    return Mock(fetchall=lambda: sorted(db_rows))
                if "record_selection" in q:
                    (ref,) = params
                    seq = decode(values[ref])["sequence"]
                    db_rows.append(
                        (
                            native.ENV,
                            seq,
                            ref,
                            refs[-1] if refs else None,
                            f"{current_second()}.000000",
                        )
                    )
                    refs.append(ref)
                    row = (ref,)
                elif "LEFT JOIN ml_promotion.events" in q:
                    row = (
                        len(refs),
                        refs[-1],
                        fixture.arguments["expected_policy"],
                        refs[-1],
                        current_second(),
                    )
                elif "clock_timestamp()" in q:
                    row = (current_second(),)
                elif "SELECT sequence, request_sha256 FROM ml_promotion.heads" in q:
                    row = (len(refs), refs[-1])
                else:
                    assert "SELECT request_sha256 FROM ml_promotion.events" in q
                    row = (refs[params[1] - 1],)
                return Mock(fetchone=lambda: row)

            conn.execute.side_effect = execute

            def stub(obj, name, **kw):
                return st.enter_context(patch.object(obj, name, **kw))

            def update(store, policy_sha, key, *, revoked_keys):
                clock = current_second()
                doc = dict(
                    schema_version=1,
                    environment=native.ENV,
                    version=len(trust_docs) + 1,
                    promotion_policy_sha256=policy_sha,
                    issued_at=clock,
                    expires_at=clock + 1800,
                    revoked_keys=list(revoked_keys),
                    revoked_artifacts=[],
                )
                env = signing.sign(doc, "trust-policy", key)
                trust_docs.append(env)
                return dict(document_sha256=native.sha(env))

            def controlled(root, state, authority, args, public):
                from mlsecops import promotion

                lease = native.trust.Lease(
                    lambda: (trust_docs[-1], current_second()),
                    trusted_root=public,
                    minimum_version=1,
                    environment=native.ENV,
                )
                return promotion.promote("promoter", **args, trust_lease=lease, audit=Mock())

            def get(client, table, ref):
                if (
                    client not in ("promoter", dst / "storage-clients/serving")
                    or table != "releases"
                ):
                    raise AssertionError("foreign CAS client")
                return values[ref]

            def put(client, table, content):
                assert client == "promoter" and table == "releases"
                values[digest(content)] = content
                return digest(content)

            @contextmanager
            def site(engine):
                # Exercise the normal Reader, authorization, Engine startup and real ONNX session;
                # replace the container transport and HTTP wire at their boundaries.
                def worker(content, image):
                    runtime, _ = model.session(content)
                    return Mock(
                        image=image,
                        binding={"model_sha256": digest(content)},
                        predict=lambda rows: model.predict(runtime, rows),
                    )

                import asyncio

                from mlsecops import serving_audit, serving_http
                from scripts.serving_http_qualification import ServingHttpContracts

                engine.worker_factory = worker
                with TemporaryDirectory() as temp, asyncio.Runner() as runner:
                    journal = serving_audit.Journal(Path(temp) / "audit.jsonl")
                    journal.start()
                    wire = ServingHttpContracts()
                    wire.token = "c" * 64
                    wire.app = serving_http.create_app(engine, wire.token, audit=journal)
                    lifespan = wire.app.router.lifespan_context(wire.app)
                    try:
                        runner.run(lifespan.__aenter__())
                        try:

                            def request(path, body=None):
                                status, response, _ = runner.run(
                                    wire.invoke(
                                        body=decode(body) if body else None,
                                        path=path,
                                        method="POST" if body else "GET",
                                    )
                                )
                                return status, response

                            yield request
                        finally:
                            runner.run(lifespan.__aexit__(None, None, None))
                    finally:
                        journal.close(timeout=5)

            stub(native.promoter, "hosted")
            stub(native, "resolve_image", return_value=cls.image)
            stub(native, "disposable", return_value=nullcontext(authority))
            stub(native, "target_client", return_value=nullcontext(dst / "storage-clients/serving"))
            stub(native.promotion_state, "install")
            stub(native.promotion_state, "configure")
            stub(native.trust_authority, "install")
            stub(native.trust_authority, "update", side_effect=update)
            stub(
                native.trust_authority,
                "read",
                side_effect=lambda *a: (trust_docs[-1], current_second()),
            )
            stub(
                native.storage_bootstrap,
                "validate",
                side_effect=lambda s: source if s == src else target,
            )
            stub(native.storage_bootstrap, "inspect", return_value={"State": {"Running": False}})
            stub(native.storage, "connect", return_value=conn)
            stub(
                native.storage,
                "connection_parameters",
                side_effect=lambda p: {"user": "ml_promoter" if p == "promoter" else "ml_serving"},
            )
            stub(native.storage, "get", side_effect=get)
            stub(native.storage, "put", side_effect=put)
            stub(native.promoter, "controlled", side_effect=controlled)
            stub(native.serving_native, "site", side_effect=site)
            # Track the fixture used by seeded so simulated SQL can return its configured policy.
            fixture = native.PromotionAdmissionContracts()
            stub(native, "PromotionAdmissionContracts", wraps=type(fixture), return_value=fixture)
            bind_candidate = native.serving_native.bind_real_runtime
            stub(
                native.serving_native,
                "bind_real_runtime",
                side_effect=AssertionError("implicit binder"),
            )
            with native.seeded(
                root, src, cls.image, cls.campaign, bind_candidate=bind_candidate
            ) as seed:
                m = seed.model
                payload = values[m]
                archive = (
                    b"PGDMP-data"
                    + m.encode()
                    + b"\t\\\\x"
                    + payload.hex().encode()
                    + b"\t2026-01-01\n"
                )

                def entry(items):
                    return dict(
                        rows=len(items),
                        bytes=sum(map(len, items)),
                        sha256=digest(b"\n".join(items)),
                        invalid=0,
                    )

                tables = {table: entry([]) for table in storage_schema.TABLES}
                tables["releases"] = entry(list(values.values()))
                ledger = dict(
                    migration=promotion_recovery.migration(),
                    tables=dict(
                        authorities=entry([b"authority"]),
                        heads=entry([b"head"]),
                        events=entry([json.dumps(row).encode() for row in sorted(db_rows)]),
                    ),
                )
                timestamp = datetime.now(UTC).isoformat()
                statement = dict(
                    schema_version=2,
                    format="postgres-custom-data-only",
                    started_at=timestamp,
                    completed_at=timestamp,
                    source_workspace=source["workspace_id"],
                    image=native.storage_backup.IMAGE,
                    migration=native.storage_backup.migration(),
                    policy_digest=native.sha(policy),
                    trusted_keys_digest=native.sha(public),
                    archive=dict(name="data.dump", sha256=digest(archive), bytes=len(archive)),
                    tables=tables,
                    promotion=ledger,
                )
                cls.pin = native.sha(statement)
                directory = src / "backups" / cls.pin
                write_json(
                    directory / "manifest.json",
                    signing.sign(statement, "storage-backup", src / "keys/trust.pem"),
                )
                (directory / "data.dump").write_bytes(archive)
                write_json(
                    dst / "recovery.json",
                    dict(
                        schema_version=2,
                        backup_id=cls.pin,
                        source_workspace=source["workspace_id"],
                        target_workspace=target["workspace_id"],
                        container_id=target["container_id"],
                        port=target["port"],
                        restored_at=timestamp,
                        elapsed_seconds=1.5,
                        tables=tables,
                        promotion=ledger,
                        status="storage-restored-not-release-ready",
                        release_ready=False,
                    ),
                )
                cls.record = seed.verify_restored(dst, cls.pin)
                cls.archive_bytes = (directory / "data.dump").read_bytes()
                if cls.archive_bytes != archive:
                    raise AssertionError("owner archive modified")
                from scripts.model_contract_qualification import ModelContractTests

                cls.expected_model = digest(ModelContractTests.content)
                cls.expected_features = ModelContractTests.features[:1]
                cls.expected_score = ModelContractTests.trained["python_scores"][0]

    def replay(self, r, **kw):
        return native.replay(
            r, **dict({"backup_id": self.pin, "campaign": self.campaign, "image": self.image}, **kw)
        )

    def test_offline_signed_history_and_refusals_survive_cleanup(self):
        result = self.replay(self.record)
        self.assertEqual(result["approved_sequences"], [1, 2])
        self.assertEqual(result["model_sha256"], self.expected_model)
        self.assertEqual(self.record["features"], self.expected_features)
        self.assertEqual(self.record["expected_score"], self.expected_score)
        self.assertEqual(result["source_workspace"], "a" * 32)
        self.assertEqual(result["target_workspace"], "b" * 32)
        self.assertEqual(
            (result["healthy_status"], result["cold_ready_status"], result["cold_predict_status"]),
            (200, 503, 503),
        )
        self.assertEqual(result["verified_clock"], self.record["healthy"]["verified_clock"])
        self.assertEqual(set(result["archive_refusals"]), {"corrupt", "missing"})
        self.assertFalse(result["release_ready"])

    def test_owner_run_and_backup_pins_are_external(self):
        for arg, val in (
            ("backup_id", "9" * 64),
            ("campaign", "8" * 32),
            ("image", "sha256:" + "a" * 64),
        ):
            with self.subTest(arg=arg), self.assertRaises(Rejected):
                self.replay(self.record, **{arg: val})

    def test_replay_regenerates_both_faults_from_retained_archive_after_cleanup(self):
        self.assertEqual(
            self.replay(self.record, archive_bytes=self.archive_bytes), self.replay(self.record)
        )
        with self.assertRaises(Rejected):
            self.replay(self.record, archive_bytes=self.archive_bytes + b"x")
        for case in ("corrupt", "missing"):
            r = copy.deepcopy(self.record)
            r["archive"]["cases"][case]["archive_sha256"] = "f" * 64
            with self.subTest(case=case), self.assertRaises(Rejected):
                self.replay(r, archive_bytes=self.archive_bytes)

    def test_changed_expected_score_and_matching_prediction_break_presnapshot_golden_pin(self):
        r = copy.deepcopy(self.record)
        r["expected_score"] = 0.25
        r["healthy"]["predict"]["response"]["predictions"][0]["score"] = 0.25
        with self.assertRaises(Rejected):
            self.replay(r)

    def test_rehashing_foreign_approvals_clocks_targets_or_refusals_does_not_authorize(self):
        def stale_reply(r):
            r["negative"]["predict"] = r["healthy"]["predict"]

        cases = (
            lambda r: r["events"][1].update(previous_sha256=None),
            lambda r: r["receipts"][0].update(subject_sha256=r["receipts"][1]["subject_sha256"]),
            lambda r: r["healthy"]["response"].update(model_sha256="a" * 64),
            lambda r: r["healthy"]["predict"]["response"]["predictions"][0].update(score=0.0),
            lambda r: r["healthy"]["predict"].update(payload_sha256="4" * 64),
            lambda r: r["healthy"]["verified_clock"].update(monotonic_ns=1),
            lambda r: r["healthy"].update(verified_clock=r["healthy"]["start_clock"]),
            lambda r: r["negative"]["startup"].update(phase="worker-start"),
            lambda r: r["negative"]["response"].update(predictions=[]),
            lambda r: r["negative"].update(cold_reader="storage_object_missing"),
            stale_reply,
            lambda r: r.update(revoked=r["initial"]),
            lambda r: r["negative"]["predict"]["response"].update(
                request_id=r["healthy"]["response"]["request_id"]
            ),
            lambda r: r["archive"]["cases"]["missing"]["row"].update(
                lookup_after=r["healthy"]["response"]["model_sha256"]
            ),
            lambda r: r["archive"]["cases"]["missing"].update(target_created=True),
            lambda r: r["target"].update(network_id=r["source"]["network_id"]),
            lambda r: r["final_head"].update(request_sha256=r["events"][0]["request_sha256"]),
        )
        for idx, change in enumerate(cases):
            with self.subTest(idx=idx):
                r = copy.deepcopy(self.record)
                change(r)
                self.assertNotEqual(native.sha(r), native.sha(self.record))
                with self.assertRaises(Rejected):
                    self.replay(r)
