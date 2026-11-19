"""Offline SQL/native-boundary contracts; real PKI, AES, signatures and ordinary readers."""

import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import psycopg

from mlsecops import release_bundle, signing, storage, storage_bootstrap, storage_pki
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    write_json,
)
from scripts import ci_candidate_transfer_qualification as fixtures
from scripts import consumer_candidate_state
from scripts import consumer_candidate_storage as importer

ORDINARY_STORAGE = {
    name: getattr(storage, name) for name in ("connect", "put", "get", "connection_parameters")
}


class Database:
    """Only the actual schema's releases INSERT/SELECT contract, transaction per connection.

    This is a psycopg boundary fixture, not a SQL server. Unknown SQL or namespaces
    fail tests. Ordinary storage.put/get and release publish/read are not mocked.
    """

    def __init__(self):
        self.rows = {}
        self.writes = 0
        self.connections = 0
        self.fail_at = None
        self.after_write = lambda: None
        self.read_change = lambda key, raw: raw
        self.role_change = lambda role: role
        self.before_inventory = lambda: None

    def connect(self, **parameters):
        self.connections += 1
        if parameters["host"] != "127.0.0.1" or parameters["port"] != 15440:
            raise AssertionError("SQL must address new consumer loopback port")
        return Connection(self, parameters["user"])


class Connection:
    def __init__(self, database, role):
        self.database, self.role = database, role
        self.rows = database.rows.copy()
        self.result = []

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        if kind is None:
            self.database.rows = self.rows

    def execute(self, query, parameters=None):
        query = query if isinstance(query, str) else query.as_string()
        if query == "SELECT current_user;":
            self.result = [(self.database.role_change(self.role),)]
        elif query == "SELECT sha256 FROM ml.releases ORDER BY sha256 LIMIT %s;":
            if self.role != "ml_promoter":
                raise AssertionError("inventory must use promoter")
            self.database.before_inventory()
            self.rows = self.database.rows.copy()
            self.result = [(key,) for key in sorted(self.rows)[: parameters[0]]]
        elif query == 'SELECT payload FROM "ml"."releases" WHERE sha256 = %s':
            if self.role not in ("ml_promoter", "ml_serving"):
                raise AssertionError("unauthorized reader")
            key = parameters[0]
            self.result = (
                [] if key not in self.rows else [(self.database.read_change(key, self.rows[key]),)]
            )
        elif (
            query
            == 'INSERT INTO "ml"."releases" (sha256, payload) VALUES (%s, %s) ON CONFLICT DO NOTHING'
        ):
            if self.role != "ml_promoter":
                raise AssertionError("unauthorized writer")
            self.database.writes += 1
            if self.database.writes == self.database.fail_at:
                raise psycopg.OperationalError("PRIVATE-SQL-DETAIL")
            key, raw = parameters
            if digest(raw) != key or not 0 < len(raw) <= 50 * 1024**2:
                raise psycopg.errors.CheckViolation("digest/size constraint")
            self.rows.setdefault(key, raw)
            self.database.after_write()
            self.result = []
        else:
            raise AssertionError("unapproved SQL statement")
        return self

    def fetchone(self):
        return self.result[0] if self.result else None

    def fetchall(self):
        return self.result


class ConsumerStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.fixtures.fixtures.FinalEvidenceContracts.setUpClass()
        cls.addClassCleanup(fixtures.fixtures.fixtures.FinalEvidenceContracts.tearDownClass)

    def setUp(self):
        self.fx = fixtures.CandidateTransferTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        original = self.fx.fixture.fx
        self.package = original.package
        self.campaign = release_bundle.index(self.package["envelope"], original.keys["approver"])[
            "release_id"
        ]
        original.proposal["campaign_id"] = self.campaign
        pin = original.pinfile("evidence/release-native.json", original.proposal)
        self.fx.authority["freeze"]["evidence/release-native.json"] = pin
        self.fx.fixture.index["freeze"] = self.fx.authority["freeze"].copy()
        self.fx.authority["freeze_pin"] = original.pinfile(
            fixtures.transfer.RECEIPT, self.fx.fixture.index
        )
        sealed = self.fx.seal()
        self.root = self.fx.root
        self.state, summary = self.enterContext(
            consumer_candidate_state.materialize(
                self.root,
                sealed["envelope"],
                trust_key_path=original.release.authorities.keys["root"],
                key=fixtures.KEY,
                phase=self.fx.phase,
                **self.fx.authority,
                expected_context=sealed["context"],
                ciphertext_pin=sealed["ciphertext_sha256"],
                manifest_pin=sealed["manifest_sha256"],
            )
        )
        self.workspace = summary["workspace_id"]
        # File-only equivalent of caller bootstrap inputs. No bootstrap function,
        # Docker process or socket is executed by qualification.
        storage_pki.initialize(self.state)
        spec, _ = storage_bootstrap.specification(self.state, 15440)
        self.marker = spec | dict(
            container_id="a" * 64, network_id="b" * 64, volume_created_at="2026-11-20T00:00:00Z"
        )
        write_json(self.state / "storage.json", self.marker)
        self.storage_pin = digest(bounded_read(self.state / "storage.json"))
        storage_bootstrap.export_clients(self.state, 15440)
        labels = {
            storage_bootstrap.WORKSPACE_LABEL: self.workspace,
            storage_bootstrap.CONFIG_LABEL: spec["config_digest"],
        }
        ports = {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "15440"}]}
        self.resources = {
            "container": dict(
                Id=self.marker["container_id"],
                Image="sha256:" + "c" * 64,
                Config=dict(Labels=labels, Image=storage_bootstrap.IMAGE, User="999:999"),
                HostConfig=dict(
                    ReadonlyRootfs=True,
                    Privileged=False,
                    CapAdd=[],
                    CapDrop=["ALL"],
                    SecurityOpt=["no-new-privileges"],
                    Memory=512 * 1024**2,
                    MemorySwap=512 * 1024**2,
                    NanoCpus=1_000_000_000,
                    PidsLimit=64,
                    PortBindings=ports,
                ),
                NetworkSettings=dict(
                    Networks={spec["network"]: {"NetworkID": self.marker["network_id"]}},
                    Ports=ports,
                ),
                State=dict(Running=True, StartedAt="2026-11-20T00:01:00Z"),
                Mounts=[
                    dict(Type="volume", Name=spec["volume"], Destination=storage_bootstrap.MOUNT)
                ],
            ),
            "network": dict(
                Id=self.marker["network_id"], Labels=labels, Internal=False, Driver="bridge"
            ),
            "volume": dict(Labels=labels, CreatedAt=self.marker["volume_created_at"]),
        }
        self.native_calls = []
        self.enterContext(patch.object(storage_bootstrap, "docker", self.docker))
        # The broad signed M18 fixture leaves its promotion in-memory storage
        # patches active. Restore the real functions above our driver boundary.
        for name, function in ORDINARY_STORAGE.items():
            self.enterContext(patch.object(storage, name, function))
        self.db = Database()
        self.enterContext(patch.object(psycopg, "connect", self.db.connect))
        for name in ("bootstrap", "migrate", "admin"):
            self.enterContext(
                patch.object(
                    storage_bootstrap, name, side_effect=AssertionError("no provisioning/admin")
                )
            )
        self.enterContext(patch.object(signing, "sign", side_effect=AssertionError("no signing")))
        self.enterContext(patch("subprocess.run", side_effect=AssertionError("no processes")))
        self.enterContext(patch("subprocess.Popen", side_effect=AssertionError("no processes")))
        self.enterContext(patch("socket.socket", side_effect=AssertionError("no network")))

    def docker(self, arguments, **options):
        kind, operation, name = arguments
        if (
            operation != "inspect"
            or name
            != self.marker[{"container": "name", "network": "network", "volume": "volume"}[kind]]
        ):
            raise AssertionError("unexpected Docker boundary")
        self.native_calls.append(kind)
        return SimpleNamespace(
            returncode=0, stdout=canonical([copy.deepcopy(self.resources[kind])]), stderr=b""
        )

    def import_candidate(self, **changes):
        arguments = (
            copy.deepcopy(self.fx.authority)
            | dict(expected_workspace_id=self.workspace, storage_pin=self.storage_pin)
            | changes
        )
        return importer.import_candidate(self.root, self.state, **arguments)

    def expected_rows(self):
        contents = [
            canonical(self.package["envelope"]),
            canonical(self.package["capsule"]["envelope"]),
            *self.package["documents"].values(),
            *self.package["capsule"]["objects"].values(),
        ]
        return {digest(raw): raw for raw in contents}

    def refused_before_writes(self, **changes):
        before = self.db.rows.copy()
        with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
            self.import_candidate(**changes)
        self.assertEqual(self.db.writes, 0)
        self.assertEqual(self.db.rows, before)

    def test_real_publish_read_receipts_and_same_byte_repeat(self):
        first = self.import_candidate()
        self.assertEqual(first["status"], "pass")
        self.assertEqual(
            first["proposal_reference"], self.fx.authority["expected"]["proposal_reference"]
        )
        self.assertEqual(first["workspace_id"], self.workspace)
        self.assertEqual(first["storage_pin"], self.storage_pin)
        self.assertFalse(first["release_ready"])
        self.assertEqual(self.db.rows, self.expected_rows())
        self.assertEqual(
            release_bundle.load(
                self.state / "storage-clients/serving",
                first["proposal_reference"],
                publisher_public=self.fx.fixture.fx.keys["approver"],
            ),
            self.package,
        )
        for phase in ("pre", "post"):
            raw = bounded_read(self.state / first[phase + "_receipt"])
            self.assertEqual(digest(raw), first[phase + "_sha256"])
        pre = decode(bounded_read(self.state / first["pre_receipt"]))
        post = decode(bounded_read(self.state / first["post_receipt"]))
        self.assertEqual(pre["target"], post["target"])
        self.assertEqual(pre["inventory"], [])
        self.assertEqual(post["inventory"], sorted(self.expected_rows()))
        second = self.import_candidate()
        self.assertEqual(self.db.rows, self.expected_rows())
        self.assertNotEqual(first["post_receipt"], second["post_receipt"])
        self.assertTrue({"container", "network", "volume"} <= set(self.native_calls))

    def test_native_foreign_ids_labels_binding_and_stopped_container_before_writes(self):
        original = copy.deepcopy(self.resources)
        mutations = [
            lambda r: r["container"].update(Id="d" * 64),
            lambda r: r["network"].update(Id="d" * 64),
            lambda r: r["volume"].update(CreatedAt="foreign"),
            lambda r: r["container"]["Config"]["Labels"].update(
                {storage_bootstrap.WORKSPACE_LABEL: "f" * 32}
            ),
            lambda r: r["container"]["HostConfig"]["PortBindings"]["5432/tcp"][0].update(
                HostPort="15439"
            ),
            lambda r: r["container"]["NetworkSettings"]["Networks"][self.marker["network"]].update(
                NetworkID="f" * 64
            ),
            lambda r: r["container"]["State"].update(Running=False),
        ]
        for position, mutate in enumerate(mutations):
            with self.subTest(position=position):
                self.resources = copy.deepcopy(original)
                mutate(self.resources)
                self.refused_before_writes()

    def test_copied_old_clients_and_wrong_port_ca_key_and_role_before_writes(self):
        paths = {
            name: bounded_read(self.state / "storage-clients/promoter" / name)
            for name in ("connection.json", "ca.crt", "client.crt", "client.key")
        }
        for field, value in (
            ("port", 15439),
            ("host", storage_pki.CLUSTER_HOST),
            ("role", "curator"),
        ):
            with self.subTest(field=field):
                config = decode(paths["connection.json"]) | {field: value}
                write_json(self.state / "storage-clients/promoter/connection.json", config)
                self.refused_before_writes()
        for name, raw in paths.items():
            atomic_write(self.state / "storage-clients/promoter" / name, raw)
        for name in ("ca.crt", "client.crt", "client.key"):
            with self.subTest(name=name):
                atomic_write(self.state / "storage-clients/promoter" / name, paths[name] + b"\n")
                self.refused_before_writes()
                atomic_write(self.state / "storage-clients/promoter" / name, paths[name])

    def test_marker_pins_pki_and_frozen_owner_before_writes(self):
        self.refused_before_writes(expected_workspace_id="f" * 32)
        self.refused_before_writes(storage_pin="f" * 64)
        self.refused_before_writes(
            expected=self.fx.authority["expected"] | {"candidate_reference": "f" * 64}
        )
        self.refused_before_writes(
            run_owner=self.fx.authority["run_owner"] | {"repository": "foreign/repo"}
        )
        write_json(
            self.state / "storage-pki/identity.json",
            {"schema_version": 1, "workspace_id": "f" * 32},
        )
        self.refused_before_writes()

    def test_foreign_existing_data_and_wrong_bytes_fail_without_delete(self):
        self.db.rows[digest(b"foreign")] = b"foreign"
        self.refused_before_writes()
        key = next(iter(self.expected_rows()))
        self.db.rows = {key: b"corrupt"}
        self.refused_before_writes()

    def test_partial_write_failure_retains_subset_and_can_resume_same_candidate(self):
        self.db.fail_at = 3
        with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
            self.import_candidate()
        self.assertGreater(len(self.db.rows), 0)
        self.assertLess(len(self.db.rows), len(self.expected_rows()))
        post = decode(
            bounded_read(next((self.state / "evidence/consumer-storage").glob("*/post.json")))
        )
        self.assertEqual(post["status"], "fail")
        self.assertEqual(post["inventory"], sorted(self.db.rows))
        self.db.fail_at = None
        self.assertEqual(self.import_candidate()["status"], "pass")
        self.assertEqual(self.db.rows, self.expected_rows())

    def test_changes_after_write_are_detected_and_leave_no_success_receipt(self):
        self.db.after_write = lambda: self.resources["container"]["State"].update(Running=False)
        with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
            self.import_candidate()
        self.assertGreater(self.db.writes, 0)
        post = decode(
            bounded_read(next((self.state / "evidence/consumer-storage").glob("*/post.json")))
        )
        self.assertEqual(post["status"], "fail")
        self.assertIsNone(post["target"])

    def test_stale_original_and_corrupt_frozen_bytes_before_writes(self):
        self.fx.clock = self.fx.fixture.fx.values["proposal_expires_at"] - 599
        self.refused_before_writes()
        self.fx.clock = self.fx.fixture.clock
        path = self.state / "evidence/release-native.json"
        atomic_write(path, bounded_read(path) + b" ")
        self.refused_before_writes()

    def test_old_valid_clients_with_self_consistent_cert_pins_are_not_new_state_clients(self):
        old = self.root / "old-client-fixture"
        old.mkdir()
        write_json(
            old / "workspace.json",
            dict(product="trusted-mlsecops", schema_version=1, workspace_id="e" * 32),
        )
        storage_pki.initialize(old)
        storage_bootstrap.export_clients(old, 15440)
        for role in ("promoter", "serving", "curator"):
            directory = self.state / "storage-clients" / role
            saved = {p.name: bounded_read(p) for p in directory.iterdir()}
            with self.subTest(role=role):
                for name in saved:
                    atomic_write(
                        directory / name, bounded_read(old / "storage-clients" / role / name)
                    )
                self.refused_before_writes()
                for name, raw in saved.items():
                    atomic_write(directory / name, raw)

    def test_self_consistent_foreign_client_certificate_and_wrong_current_user(self):
        directory = self.state / "storage-clients/promoter"
        config = decode(bounded_read(directory / "connection.json"))
        certificate = bounded_read(self.state / "storage-pki/ml_curator.crt")
        atomic_write(directory / "client.crt", certificate)
        write_json(
            directory / "connection.json",
            config | {"certificates": config["certificates"] | {"client.crt": digest(certificate)}},
        )
        self.refused_before_writes()
        atomic_write(
            directory / "client.crt", bounded_read(self.state / "storage-pki/ml_promoter.crt")
        )
        write_json(directory / "connection.json", config)
        self.db.role_change = lambda role: "ml_curator"
        self.refused_before_writes()

    def test_pre_receipt_readback_failure_never_writes_sql(self):
        ordinary = importer.bounded_read

        def corrupted(path, *args):
            raw = ordinary(path, *args)
            return raw + b" " if path.name == "pre.json" else raw

        with patch.object(importer, "bounded_read", corrupted):
            self.refused_before_writes()

    def test_post_receipt_readback_failure_rejects_without_deleting_committed_objects(self):
        ordinary = importer.bounded_read

        def corrupted(path, *args):
            raw = ordinary(path, *args)
            return raw + b" " if path.name == "post.json" else raw

        with patch.object(importer, "bounded_read", corrupted):
            with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
                self.import_candidate()
        self.assertEqual(self.db.rows, self.expected_rows())

    def test_receipt_write_failure_rejects_before_publication(self):
        ordinary = importer.atomic_write

        def unavailable(path, raw):
            if path.name == "pre.json":
                raise OSError("PRIVATE-FILESYSTEM-DETAIL")
            return ordinary(path, raw)

        with patch.object(importer, "atomic_write", unavailable):
            self.refused_before_writes()

    def test_state_changed_after_pre_receipt_is_refused_before_publication(self):
        ordinary = importer.atomic_write

        def changed(path, raw):
            ordinary(path, raw)
            if path.name == "pre.json":
                marker = self.state / "workspace.json"
                ordinary(marker, bounded_read(marker) + b" ")

        with patch.object(importer, "atomic_write", changed):
            self.refused_before_writes()
        post = decode(
            bounded_read(next((self.state / "evidence/consumer-storage").glob("*/post.json")))
        )
        self.assertEqual(post["status"], "fail")
        self.assertIn("before-publication", post["failure_stages"])

    def test_client_material_changed_after_writes_refused_even_when_parameters_still_valid(self):
        config = self.state / "storage-clients/curator/connection.json"
        original = bounded_read(config)
        self.db.after_write = lambda: atomic_write(config, original + b" ")
        with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
            self.import_candidate()
        self.assertEqual(self.db.rows, self.expected_rows())
        post = decode(
            bounded_read(next((self.state / "evidence/consumer-storage").glob("*/post.json")))
        )
        self.assertEqual(post["status"], "fail")
        self.assertIsNone(post["target"])

    def test_bad_publication_receipt_and_corrupt_sql_readback_reject(self):
        ordinary = release_bundle.publish

        def wrong_reference(*args, **kwargs):
            ordinary(*args, **kwargs)
            return "f" * 64

        with patch.object(release_bundle, "publish", wrong_reference):
            with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
                self.import_candidate()
        self.assertEqual(self.db.rows, self.expected_rows())
        # A same-candidate repeat also refuses corrupted database bytes, not only
        # unknown references. No INSERT is reached on this second invocation.
        writes = self.db.writes
        self.db.read_change = lambda key, raw: raw + b"changed"
        with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
            self.import_candidate()
        self.assertEqual(self.db.writes, writes)

    def test_serving_readback_and_incomplete_post_inventory_cannot_succeed(self):
        ordinary = release_bundle.read

        def changed(client, *args, **kwargs):
            result = ordinary(client, *args, **kwargs)
            return result | {"subject_sha256": "f" * 64} if client.name == "serving" else result

        with patch.object(release_bundle, "read", changed):
            with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
                self.import_candidate()
        self.assertEqual(self.db.rows, self.expected_rows())

        # Simulate an outside change after successful publication/readback but
        # before the final bounded SELECT. The importer never issues DELETE.
        def disappear():
            if self.db.writes > writes:
                self.db.rows.pop(next(iter(self.db.rows)))

        writes = self.db.writes
        self.db.before_inventory = disappear
        with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
            self.import_candidate()
        self.assertEqual(len(self.db.rows), len(self.expected_rows()) - 1)

    def test_expiry_during_publication_fails_postflight_without_renewal(self):
        expires = self.fx.fixture.fx.values["proposal_expires_at"]
        self.db.after_write = lambda: setattr(self.fx, "clock", expires - 599)
        with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
            self.import_candidate()
        self.assertEqual(self.db.rows, self.expected_rows())
        post = decode(
            bounded_read(next((self.state / "evidence/consumer-storage").glob("*/post.json")))
        )
        self.assertEqual(post["status"], "fail")
        self.assertIn("postflight", post["failure_stages"])

    def test_expiry_during_last_native_preflight_prevents_all_sql_writes(self):
        ordinary = self.docker
        expires = self.fx.fixture.fx.values["proposal_expires_at"]

        def delayed(arguments, **options):
            result = ordinary(arguments, **options)
            # Each target check has three validate inspections plus the actual
            # running/network check. The second check follows the pre receipt.
            if len(self.native_calls) == 8:
                self.fx.clock = expires - 599
            return result

        with patch.object(storage_bootstrap, "docker", delayed):
            self.refused_before_writes()

    def test_expiry_during_last_inventory_cannot_return_success(self):
        expires = self.fx.fixture.fx.values["proposal_expires_at"]

        def delayed():
            if self.db.writes:
                self.fx.clock = expires - 599

        self.db.before_inventory = delayed
        with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
            self.import_candidate()
        self.assertEqual(self.db.rows, self.expected_rows())

    def test_changed_consumer_report_policy_and_trust_key_before_writes(self):
        foreign = bounded_read(self.fx.fixture.fx.release.authorities.keys["publisher"])
        for name, replacement in (
            (f"release-proposals/{self.campaign}/report.json", None),
            (f"release-proposals/{self.campaign}/policy-envelope.json", None),
            ("keys/trust.pem", foreign),
        ):
            path = self.state / name
            original = bounded_read(path)
            with self.subTest(name=name):
                try:
                    atomic_write(path, original + b" " if replacement is None else replacement)
                    self.refused_before_writes()
                finally:
                    atomic_write(path, original)

    def test_expiry_during_post_receipt_io_cannot_return_accepted_receipt(self):
        ordinary = importer.atomic_write
        expires = self.fx.fixture.fx.values["proposal_expires_at"]

        def delayed(path, raw):
            ordinary(path, raw)
            if path.name == "post.json":
                self.fx.clock = expires - 599

        with patch.object(importer, "atomic_write", delayed):
            with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
                self.import_candidate()
        self.assertEqual(self.db.rows, self.expected_rows())
        # The file records the earlier observation. Without a successful API
        # return, neither its pass field nor its locally recoverable hash is an
        # accepted receipt. No rewrite creates yet another unchecked I/O window.
        post = decode(
            bounded_read(next((self.state / "evidence/consumer-storage").glob("*/post.json")))
        )
        self.assertEqual(post["status"], "pass")

    def test_target_changed_during_post_receipt_io_cannot_return_accepted_receipt(self):
        ordinary = importer.atomic_write
        marker = self.state / "workspace.json"
        original = bounded_read(marker)

        def changed(path, raw):
            ordinary(path, raw)
            if path.name == "post.json":
                ordinary(marker, original + b" ")

        with patch.object(importer, "atomic_write", changed):
            with self.assertRaisesRegex(Rejected, "^consumer_candidate_storage_rejected$"):
                self.import_candidate()
        self.assertEqual(storage_pki.workspace_id(self.state), self.workspace)
        self.assertEqual(self.db.rows, self.expected_rows())
        post = decode(
            bounded_read(next((self.state / "evidence/consumer-storage").glob("*/post.json")))
        )
        self.assertEqual(post["status"], "pass")


if __name__ == "__main__":
    unittest.main()
