"""Real signed/AES/PKI and storage contracts; simulated Docker and psycopg only."""

import copy
import importlib
import importlib.util
import io
import time
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from unittest.mock import patch

import psycopg

from mlsecops import ci_transfer, storage, storage_bootstrap
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    write_json,
)
from scripts import candidate_lineage_qualification as lineage
from scripts import ci_validation_transfer as companion
from scripts import consumer_candidate_storage as candidate
from scripts import consumer_candidate_storage_qualification as fixtures

KEY = bytes(range(32))  # Public fixture vector, not a deployment key.
PRIVATE = "private-validation-fixture-detail"


class Database:
    def __init__(self):
        self.rows, self.reads, self.queries = {}, [], []
        self.writes = 0
        self.fail_write = False
        self.after_write = lambda: None
        self.before_inventory = lambda: None
        self.read_change = lambda role, raw: raw
        self.role_change = lambda role: role
        self.inventory_override = None

    def connect(self, **parameters):
        assert (parameters["host"], parameters["hostaddr"], parameters["port"]) == (
            "127.0.0.1",
            "127.0.0.1",
            15440,
        )
        assert parameters["user"] in ("ml_curator", "ml_publisher")
        return Connection(self, parameters["user"])


class Connection:
    def __init__(self, database, role):
        self.database, self.role = database, role
        self.rows, self.result = database.rows.copy(), []

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        if kind is None:
            self.database.rows = self.rows

    def execute(self, query, parameters=None):
        query = query if isinstance(query, str) else query.as_string()
        self.database.queries.append(query)
        if query == "SELECT current_user;":
            self.result = [(self.database.role_change(self.role),)]
        elif query == "SELECT sha256 FROM ml.validation ORDER BY sha256 LIMIT %s;":
            assert parameters == (2,)
            self.database.before_inventory()
            self.rows = self.database.rows.copy()
            self.result = self.database.inventory_override
            if self.result is None:
                self.result = [(key,) for key in sorted(self.rows)[:2]]
        elif query == 'SELECT payload FROM "ml"."validation" WHERE sha256 = %s':
            key = parameters[0]
            self.database.reads.append((self.role, key))
            self.result = (
                []
                if key not in self.rows
                else [(self.database.read_change(self.role, self.rows[key]),)]
            )
        elif (
            query
            == 'INSERT INTO "ml"."validation" (sha256, payload) VALUES (%s, %s) ON CONFLICT DO NOTHING'
        ):
            assert self.role == "ml_curator"
            self.database.writes += 1
            if self.database.fail_write:
                raise psycopg.OperationalError(PRIVATE)
            key, raw = parameters
            assert key == digest(raw)
            self.rows.setdefault(key, raw)
            self.database.after_write()
            self.result = []
        else:
            raise AssertionError("unexpected SQL: " + query)
        return self

    def fetchone(self):
        return self.result[0] if self.result else None

    def fetchall(self):
        return self.result


class ValidationStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ConsumerStorageTests.setUpClass()
        cls.addClassCleanup(fixtures.ConsumerStorageTests.doClassCleanups)

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("scripts.consumer_validation_storage"),
            "validation SQL importer is not implemented",
        )
        self.importer = importlib.import_module("scripts.consumer_validation_storage")
        self.raw = canonical(
            [
                dict(entity_id=index + 1000, features=[0.5] * 6, label=index % 2)
                for index in range(32)
            ]
        )
        self.pin = digest(self.raw)
        self.fx = fixtures.ConsumerStorageTests()
        with patch.object(
            lineage.CandidateLineageContracts,
            "split_contents",
            {"validation": self.raw},
            create=True,
        ):
            self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.root, self.state = self.fx.root, self.fx.state
        self.owner = copy.deepcopy(self.fx.fx.authority)
        self.packet = companion.retain(self.root, self.state, self.raw, **self.owner)
        self.sealed = companion.seal(
            self.root, self.state, self.packet, key=KEY, **self.owner, phase="M13"
        )
        self.enterContext(
            patch.object(time, "time_ns", side_effect=lambda: int(self.fx.fx.clock * 10**9))
        )
        self.db = Database()
        self.enterContext(patch.object(psycopg, "connect", self.db.connect))

    def call(self, **changes):
        arguments = dict(
            key=KEY,
            **self.owner,
            phase="M13",
            expected_context=self.sealed["context"],
            ciphertext_pin=self.sealed["ciphertext_sha256"],
            expected_workspace_id=self.fx.workspace,
            storage_pin=self.fx.storage_pin,
        )
        envelope = changes.pop("envelope", self.sealed["envelope"])
        return self.importer.import_validation(
            self.root, self.state, envelope, **(arguments | changes)
        )

    def rejected(self, **changes):
        with self.assertRaisesRegex(Rejected, "^consumer_validation_storage_rejected$"):
            self.call(**changes)
        self.assertFalse(list((self.root / ".runtime/ci-validation-transfers").glob("*")))

    def no_write(self, **changes):
        self.rejected(**changes)
        self.assertEqual(self.db.writes, 0)

    def test_bad_ciphertext_key_pin_context_and_material_before_sql(self):
        bad = self.sealed["envelope"][:-1] + bytes([self.sealed["envelope"][-1] ^ 1])
        for changes in (
            dict(envelope=bad),
            dict(key=b"x" * 32),
            dict(ciphertext_pin="f" * 64),
            dict(expected_context=self.sealed["context"] | {"phase": "validation-M14"}),
            dict(phase="M11-M12"),
            dict(expected_context=[]),
        ):
            with self.subTest(changes=list(changes)):
                self.no_write(**changes)
        packet = decode(self.packet)
        packet["validation"] = "e30="
        raw = canonical(packet)
        context = self.sealed["context"] | {"payload_sha256": digest(raw)}
        envelope = ci_transfer.seal(raw, key=KEY, context=context)
        self.no_write(envelope=envelope, expected_context=context, ciphertext_pin=digest(envelope))
        self.assertFalse(self.db.queries)

    def test_wrong_owner_source_workspace_and_storage_pin_before_sql(self):
        revision = self.owner["expected"]["source_revision"]
        foreign_revision = ("0" if revision[0] != "0" else "1") + revision[1:]
        self.assertNotEqual(foreign_revision, revision)
        for changes in (
            dict(run_owner=self.owner["run_owner"] | {"run_attempt": 2}),
            dict(expected=self.owner["expected"] | {"candidate_reference": "f" * 64}),
            dict(expected=self.owner["expected"] | {"source_revision": foreign_revision}),
            dict(freeze_pin="f" * 64),
            dict(expected_workspace_id="f" * 32),
            dict(storage_pin="f" * 64),
        ):
            with self.subTest(changes=list(changes)):
                self.no_write(**changes)
        self.assertFalse(self.db.queries)

    def test_foreign_sql_id_labels_bindings_and_stopped_container(self):
        original = copy.deepcopy(self.fx.resources)
        for change in (
            lambda row: row.update(Id="f" * 64),
            lambda row: row["Config"]["Labels"].update(
                {storage_bootstrap.WORKSPACE_LABEL: "f" * 32}
            ),
            lambda row: row["NetworkSettings"]["Ports"]["5432/tcp"][0].update(HostPort="15439"),
            lambda row: row["State"].update(Running=False),
        ):
            self.fx.resources = copy.deepcopy(original)
            change(self.fx.resources["container"])
            self.no_write()
        self.assertFalse(self.db.queries)

    def test_wrong_publisher_and_curator_endpoint_or_role(self):
        for role in ("publisher", "curator"):
            path = self.state / "storage-clients" / role / "connection.json"
            raw = bounded_read(path)
            for key, value in (
                ("port", 15439),
                ("host", "models.ml-data.svc.cluster.local"),
                ("role", "serving"),
            ):
                with self.subTest(role=role, key=key):
                    write_json(path, decode(raw) | {key: value})
                    self.no_write()
                    atomic_write(path, raw)
        self.assertFalse(self.db.queries)

    def test_self_consistent_foreign_publisher_cert_key_and_ca(self):
        directory = self.state / "storage-clients/publisher"
        original = {
            name: bounded_read(directory / name)
            for name in ("connection.json", "client.crt", "ca.crt", "client.key")
        }
        for name in ("client.crt", "ca.crt", "client.key"):
            with self.subTest(name=name):
                foreign = original[name] + b"\n"
                atomic_write(directory / name, foreign)
                config = decode(original["connection.json"])
                if name in config["certificates"]:
                    config["certificates"][name] = digest(foreign)
                    write_json(directory / "connection.json", config)
                self.no_write()
                for filename, raw in original.items():
                    atomic_write(directory / filename, raw)
        self.assertFalse(self.db.queries)

    def test_publisher_hostaddr_is_bound_even_with_correct_host(self):
        original = storage.connection_materials

        def changed(path, **options):
            parameters, materials = original(path, **options)
            if path.name == "publisher":
                parameters["hostaddr"] = "127.0.0.2"
            return parameters, materials

        with patch.object(storage, "connection_materials", changed):
            self.no_write()
        self.assertFalse(self.db.queries)

    def test_wrong_server_current_user_for_both_clients(self):
        for role in ("ml_curator", "ml_publisher"):
            self.db.role_change = lambda actual: "ml_serving" if actual == role else actual
            self.no_write()

    def test_foreign_namespace_keys_are_bounded_and_never_read(self):
        foreign = digest(b"foreign")
        self.db.rows = {foreign: b"foreign"}
        self.no_write()
        self.assertEqual(self.db.reads, [])
        self.assertEqual(self.db.rows, {foreign: b"foreign"})
        for refs in ([(self.pin,), (self.pin,)], [("invalid",)], [(self.pin,), (foreign,)]):
            self.db.inventory_override = refs
            self.no_write()
        self.assertEqual(self.db.reads, [])

    def test_existing_expected_sha_with_wrong_bytes_is_not_overwritten(self):
        self.db.rows = {self.pin: b"corrupt"}
        self.no_write()
        self.assertEqual(self.db.rows, {self.pin: b"corrupt"})

    def test_real_companion_storage_roundtrip_receipts_and_idempotency(self):
        frozen = {name: bounded_read(self.state / name) for name in self.owner["freeze"]}
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            first = self.call()
            second = self.call()
        self.assertEqual(output.getvalue() + errors.getvalue(), "")
        self.assertEqual(self.db.rows, {self.pin: self.raw})
        self.assertNotEqual(first["pre_receipt"], second["pre_receipt"])
        for result in (first, second):
            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["validation_sha256"], self.pin)
            self.assertEqual(result["workspace_id"], self.fx.workspace)
            self.assertEqual(result["storage_pin"], self.fx.storage_pin)
            self.assertEqual(result["handling"], "private")
            self.assertFalse(result["release_ready"])
            for phase in ("pre", "post"):
                raw = bounded_read(self.state / result[phase + "_receipt"])
                self.assertEqual(digest(raw), result[phase + "_sha256"])
                self.assertLessEqual(len(raw), self.importer.MAX_RECEIPT_BYTES)
                receipt = decode(raw)
                self.assertEqual(receipt["status"], "observation")
                self.assertFalse(receipt["accepted"])
                self.assertNotIn(self.raw.decode(), raw.decode())
        self.assertIn(("ml_publisher", self.pin), self.db.reads)
        self.assertEqual(frozen, {name: bounded_read(self.state / name) for name in frozen})
        self.assertFalse(list((self.root / ".runtime/ci-validation-transfers").glob("*")))

    def test_write_failure_is_private_and_retry_uses_same_bytes(self):
        self.db.fail_write = True
        self.rejected()
        self.assertEqual(self.db.rows, {})
        self.db.fail_write = False
        self.assertEqual(self.call()["status"], "pass")
        self.assertEqual(self.db.rows, {self.pin: self.raw})

    def test_committed_write_and_bad_publisher_readback_never_pass(self):
        self.db.read_change = lambda role, raw: b"corrupt" if role == "ml_publisher" else raw
        self.rejected()
        self.assertEqual(self.db.rows, {self.pin: self.raw})
        self.db.read_change = lambda role, raw: raw
        self.assertEqual(self.call()["status"], "pass")

    def test_wrong_put_digest_and_disappearing_post_inventory_reject(self):
        ordinary = storage.put

        def wrong(*args):
            ordinary(*args)
            return "f" * 64

        with patch.object(storage, "put", wrong):
            self.rejected()
        self.db.before_inventory = lambda: self.db.rows.clear()
        self.rejected()

    def test_target_and_publisher_changes_after_write_reject(self):
        original = copy.deepcopy(self.fx.resources)
        key = self.state / "storage-clients/publisher/client.key"
        raw = bounded_read(key)
        for change in (
            lambda: self.fx.resources["container"]["State"].update(StartedAt="foreign-restart"),
            lambda: atomic_write(key, raw + b"\n"),
        ):
            self.db.rows = {}
            self.fx.resources = copy.deepcopy(original)
            atomic_write(key, raw)
            self.db.after_write = change
            self.rejected()
            self.assertEqual(self.db.rows, {self.pin: self.raw})

    def test_expiry_during_pre_inventory_blocks_sql_write(self):
        expires = self.fx.fx.fixture.fx.values["proposal_expires_at"]
        self.db.before_inventory = lambda: setattr(self.fx.fx, "clock", expires - 599)
        self.no_write()

    def test_expiry_during_put_rejects_committed_original_bytes(self):
        expires = self.fx.fx.fixture.fx.values["proposal_expires_at"]
        self.db.after_write = lambda: setattr(self.fx.fx, "clock", expires - 599)
        self.rejected()
        self.assertEqual(self.db.rows, {self.pin: self.raw})

    def test_pre_receipt_io_failure_or_owner_change_blocks_write(self):
        original = candidate._receipt

        def changed(path, document):
            result = original(path, document)
            self.fx.resources["container"]["State"]["Running"] = False
            return result

        with patch.object(candidate, "_receipt", side_effect=OSError(PRIVATE)):
            self.no_write()
        with patch.object(candidate, "_receipt", changed):
            self.no_write()

    def test_post_receipt_io_failure_keeps_original_bytes_but_rejects(self):
        original = candidate._receipt

        def failed(path, document):
            result = original(path, document)
            if path.name == "post.json":
                raise OSError(PRIVATE)
            return result

        with patch.object(candidate, "_receipt", failed):
            self.rejected()
        self.assertEqual(self.db.rows, {self.pin: self.raw})

    def test_final_checks_follow_all_receipt_io_and_no_file_claims_pass(self):
        original = candidate._receipt
        clock = self.fx.fx.clock
        original_resources = copy.deepcopy(self.fx.resources)
        expires = self.fx.fx.fixture.fx.values["proposal_expires_at"]
        for change in (
            lambda: setattr(self.fx.fx, "clock", expires - 599.99),
            lambda: self.fx.resources["container"]["State"].update(Running=False),
            lambda: atomic_write(
                self.state / "workspace.json", bounded_read(self.state / "workspace.json") + b" "
            ),
        ):
            self.fx.fx.clock = clock
            self.fx.resources = copy.deepcopy(original_resources)

            def changed(path, document):
                result = original(path, document)
                if path.name == "post.json":
                    change()
                return result

            with patch.object(candidate, "_receipt", changed):
                self.rejected()
        for path in (self.state / "evidence/consumer-validation").glob("*/post.json"):
            receipt = decode(bounded_read(path))
            self.assertEqual(receipt["status"], "observation")
            self.assertFalse(receipt["accepted"])

    def test_receipt_size_is_bounded_before_write(self):
        with patch.object(self.importer, "MAX_RECEIPT_BYTES", 1):
            self.no_write()
        self.assertEqual(list((self.state / "evidence/consumer-validation").glob("*/*.json")), [])

    def test_all_three_exact_phase_companions_import_unchanged_validation(self):
        for phase in ("M13", "M14", "M15"):
            sealed = companion.seal(
                self.root, self.state, self.packet, key=KEY, **self.owner, phase=phase
            )
            result = self.call(
                phase=phase,
                envelope=sealed["envelope"],
                expected_context=sealed["context"],
                ciphertext_pin=sealed["ciphertext_sha256"],
            )
            self.assertEqual(result["status"], "pass")
        self.assertEqual(self.db.rows, {self.pin: self.raw})

    def test_exact_inner_boundary_and_fractional_expiry(self):
        expires = self.fx.fx.fixture.fx.values["proposal_expires_at"]
        self.fx.fx.clock = expires - 600
        self.assertEqual(self.call()["status"], "pass")
        writes = self.db.writes
        self.fx.fx.clock += 0.01
        self.rejected()
        self.assertEqual(self.db.writes, writes)

    def test_companion_cleanup_latency_is_included_in_final_checks(self):
        original = companion.materialize
        expires = self.fx.fx.fixture.fx.values["proposal_expires_at"]

        @contextmanager
        def delayed(*args, **kwargs):
            with original(*args, **kwargs) as value:
                yield value
            self.fx.fx.clock = expires - 599.99

        with patch.object(companion, "materialize", delayed):
            self.rejected()
        self.assertEqual(self.db.rows, {self.pin: self.raw})

    def test_staged_validation_mutation_before_sql_is_revalidated(self):
        original = companion.materialize

        @contextmanager
        def corrupted(*args, **kwargs):
            with original(*args, **kwargs) as (path, summary):
                atomic_write(path, self.raw + b" ")
                yield path, summary

        with patch.object(companion, "materialize", corrupted):
            self.no_write()

    def test_source_mismatch_after_write_rejects_without_rewriting_original(self):
        original = companion.transfer.final.clean

        def changed(*args):
            if self.db.writes:
                raise Rejected(PRIVATE)
            return original(*args)

        with patch.object(companion.transfer.final, "clean", changed):
            self.rejected()
        self.assertEqual(self.db.rows, {self.pin: self.raw})

    def test_foreign_post_inventory_is_not_fetched_or_removed(self):
        foreign = digest(b"foreign")

        def changed():
            if self.db.writes:
                self.db.rows[foreign] = b"foreign"

        self.db.before_inventory = changed
        self.rejected()
        self.assertEqual(self.db.rows, {self.pin: self.raw, foreign: b"foreign"})
        self.assertNotIn(foreign, [key for role, key in self.db.reads])


if __name__ == "__main__":
    unittest.main()
