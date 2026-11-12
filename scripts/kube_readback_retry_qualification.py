"""Execute generated readbacks with controlled contention; no cluster or private store."""

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops import kube_observer_readback as observer
from mlsecops import process_privacy
from mlsecops.contracts import Rejected, decode
from scripts import kube_security_native as native


class ReadbackRetryContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ("identity", "state"):
            (self.root / name).write_bytes(b"private-readback-canary")
        self.programs = [
            (
                "READ",
                native.READ.replace(
                    "SETUP",
                    "from mlsecops.security_event_delivery import configured\nstore = configured('/security/producer.json').store",
                ),
                "delivery",
                "serving",
            ),
            ("SERVING", native.SERVING, "delivery", "serving"),
            ("COLLECTOR", native.COLLECTOR, "server", "collector"),
            ("PROMOTER", native.PROMOTER, "admission", "promoter"),
        ]
        for action in (observer.outbox, observer.collector):
            with patch.object(observer, "execute", return_value=({}, None)) as execute:
                action("state", {})
            self.programs.append(
                (
                    "SNAPSHOT-" + action.__name__,
                    execute.call_args.args[3],
                    "delivery" if action is observer.outbox else "server",
                    "trust",
                )
            )

    def prepare(self, program):
        self.clock = 0.0
        self.output = io.StringIO()
        self.document = {
            "records": [],
            "producer_id": "producer",
            "heartbeat": None,
            "updated_at_ms": 0,
            "telemetry": {"streams": [{"producer_id": "producer", "heartbeat": None}]},
        }
        self.snapshot = Mock(side_effect=lambda: self.document)
        self.producer = SimpleNamespace(role=program[3])
        self.store = SimpleNamespace(
            root=self.root,
            pin="a" * 64,
            producer_id="producer",
            registry=SimpleNamespace(producer=lambda _: self.producer),
            snapshot=self.snapshot,
        )
        self.configured_value = (
            (SimpleNamespace(collector=SimpleNamespace(store=self.store)), 1234)
            if program[2] == "server"
            else SimpleNamespace(store=self.store)
        )
        self.configured = Mock(return_value=self.configured_value)
        self.delays = []

    def sleep(self, delay):
        self.assertGreater(delay, 0)
        self.assertLessEqual(delay, 0.03)
        self.delays.append(delay)
        self.clock += delay

    def execute(self, program):
        target = {
            "delivery": "mlsecops.security_event_delivery.configured",
            "server": "mlsecops.security_event_server.configured",
            "admission": "mlsecops.security_event_admission.emitter",
        }[program[2]]
        with (
            patch(target, self.configured),
            patch.object(process_privacy, "enforce"),
            patch("time.monotonic", side_effect=lambda: self.clock),
            patch("time.sleep", side_effect=self.sleep),
            redirect_stdout(self.output),
        ):
            exec(compile(program[1], "<generated-readback>", "exec"), {})
        result = decode(self.output.getvalue().encode(), native.READBACK_BYTES)
        self.assertEqual(result["pin"], "a" * 64)
        self.assertNotIn("private-readback-canary", self.output.getvalue())
        return result

    def test_setup_busy_once_recovers_in_generated_readbacks(self):
        for program in self.programs:
            with self.subTest(program=program[0]):
                self.prepare(program)
                self.configured.side_effect = [
                    Rejected("security_store_busy"),
                    self.configured_value,
                ]
                try:
                    result = self.execute(program)
                except Rejected as error:
                    self.fail(f"transient setup contention escaped: {error}")
                self.assertTrue(result)
                self.assertEqual(self.configured.call_count, 2)
                self.assertEqual(self.snapshot.call_count, 1)
                self.assertEqual(self.delays, [0.03])

    def test_permanent_setup_failures_propagate_without_projection_or_retry(self):
        for program in self.programs:
            for error in (
                Rejected("security_store_identity"),
                Rejected("security_store_pin"),
                Rejected("artifact_unavailable"),
                Rejected("security_store_unavailable"),
                ValueError("invalid configuration"),
                OSError("unavailable configuration"),
            ):
                with self.subTest(program=program[0], error=str(error)):
                    self.prepare(program)
                    self.configured.side_effect = error
                    with self.assertRaises(type(error)) as caught:
                        self.execute(program)
                    self.assertIs(caught.exception, error)
                    self.assertEqual(self.output.getvalue(), "")
                    self.assertEqual(self.configured.call_count, 1)
                    self.assertEqual(self.snapshot.call_count, 0)
                    self.assertEqual(self.delays, [])

    def test_setup_busy_exhaustion_never_projects_success(self):
        for program in self.programs:
            with self.subTest(program=program[0]):
                self.prepare(program)

                def busy(_):
                    self.clock += 1.5
                    raise Rejected("security_store_busy")

                self.configured.side_effect = busy
                with self.assertRaisesRegex(Rejected, "security_store_busy"):
                    self.execute(program)
                self.assertEqual(self.configured.call_count, 2)
                self.assertEqual(self.snapshot.call_count, 0)
                self.assertEqual(self.output.getvalue(), "")

    def test_setup_and_snapshot_share_one_three_second_budget(self):
        for program in self.programs:
            with self.subTest(program=program[0]):
                self.prepare(program)

                def configure(_):
                    if self.configured.call_count == 1:
                        self.clock += 2
                        raise Rejected("security_store_busy")
                    return self.configured_value

                def snapshot():
                    self.clock += 1
                    raise Rejected("security_store_busy")

                self.configured.side_effect = configure
                self.snapshot.side_effect = snapshot
                with self.assertRaisesRegex(Rejected, "security_store_busy"):
                    self.execute(program)
                self.assertEqual(self.configured.call_count, 2)
                self.assertEqual(self.snapshot.call_count, 1)
                self.assertEqual(self.output.getvalue(), "")

    def test_existing_snapshot_transient_failures_still_recover(self):
        for program in self.programs:
            for reason in (
                "security_store_busy",
                "artifact_unavailable",
                "security_store_unavailable",
            ):
                with self.subTest(program=program[0], reason=reason):
                    self.prepare(program)
                    self.snapshot.side_effect = [Rejected(reason), self.document]
                    self.execute(program)
                    self.assertEqual(self.snapshot.call_count, 2)
                    self.assertEqual(self.delays, [0.03])

    def test_permanent_snapshot_failure_is_not_retried(self):
        for program in self.programs:
            with self.subTest(program=program[0]):
                self.prepare(program)
                error = Rejected("security_store_identity")
                self.snapshot.side_effect = error
                with self.assertRaises(Rejected) as caught:
                    self.execute(program)
                self.assertIs(caught.exception, error)
                self.assertEqual(self.snapshot.call_count, 1)
                self.assertEqual(self.output.getvalue(), "")
                self.assertEqual(self.delays, [])

    def test_retry_does_not_start_after_scheduler_exhausts_budget(self):
        for program in self.programs:
            with self.subTest(program=program[0]):
                self.prepare(program)

                def configure(_):
                    if self.configured.call_count == 1:
                        self.clock = 2.99
                        raise Rejected("security_store_busy")
                    return self.configured_value

                def delayed_sleep(delay):
                    self.clock += delay + 0.02

                self.configured.side_effect = configure
                with patch.object(self, "sleep", side_effect=delayed_sleep):
                    with self.assertRaises(Rejected):
                        self.execute(program)
                self.assertEqual(self.configured.call_count, 1)
                self.assertEqual(self.snapshot.call_count, 0)
                self.assertEqual(self.output.getvalue(), "")

    def test_successful_setup_cannot_start_snapshot_after_deadline(self):
        for program in self.programs:
            with self.subTest(program=program[0]):
                self.prepare(program)

                def configure(_):
                    self.clock = 3.0
                    return self.configured_value

                self.configured.side_effect = configure
                with self.assertRaises(Rejected):
                    self.execute(program)
                self.assertEqual(self.snapshot.call_count, 0)
                self.assertEqual(self.output.getvalue(), "")

    def test_successful_snapshot_after_deadline_is_not_a_pass(self):
        for program in self.programs:
            with self.subTest(program=program[0]):
                self.prepare(program)

                def snapshot():
                    self.clock = 3.0
                    return self.document

                self.snapshot.side_effect = snapshot
                with self.assertRaises(Rejected):
                    self.execute(program)
                self.assertEqual(self.output.getvalue(), "")

    def test_recovered_setup_still_rejects_foreign_producer_role(self):
        for program in self.programs:
            if program[0] not in ("SERVING", "SNAPSHOT-outbox"):
                continue
            with self.subTest(program=program[0]):
                self.prepare(program)
                self.producer.role = "foreign"
                self.configured.side_effect = [
                    Rejected("security_store_busy"),
                    self.configured_value,
                ]
                expected = SystemExit if program[0] == "SERVING" else Rejected
                with self.assertRaises(expected) as caught:
                    self.execute(program)
                if program[0] == "SNAPSHOT-outbox":
                    self.assertEqual(str(caught.exception), "kube_observer_producer_role")
                self.assertEqual(self.configured.call_count, 2)
                self.assertEqual(self.output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
