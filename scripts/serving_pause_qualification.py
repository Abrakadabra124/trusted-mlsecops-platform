import io
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, read_json
from scripts import serving_pause_native as pause


class ServingPauseContracts(unittest.TestCase):
    def setUp(self):
        self.owned = {"container_id": "a" * 64, "port": 15449}
        self.connection = Mock()
        self.connection.__enter__ = Mock(return_value=self.connection)
        self.connection.__exit__ = Mock(return_value=False)

    def test_foreign_port_is_rejected_before_connect_or_pause(self):
        with (
            patch.object(pause.storage_bootstrap, "validate", return_value=self.owned),
            patch.object(pause, "command") as command,
            self.assertRaises(Rejected),
        ):
            with pause.injection("owned", 15450, "client"):
                self.fail("foreign port accepted")
        command.assert_not_called()

    def test_connected_read_is_retained_until_unpause_even_on_exception(self):
        actions = []

        def command(arguments, **keywords):
            actions.append(arguments)
            return "true" if len(actions) == 2 else "false"

        with (
            patch.object(pause.storage_bootstrap, "validate", return_value=self.owned),
            patch.object(pause.storage, "connect", return_value=self.connection),
            patch.object(pause, "command", side_effect=command),
            self.assertRaisesRegex(RuntimeError, "test failure"),
        ):
            with pause.injection("owned", 15449, "client") as probe:

                def operation():
                    with pause.storage.connect("client") as connection:
                        self.assertFalse(probe.entered.is_set())
                        self.assertFalse(probe.finished.is_set())
                        connection.execute("SELECT fixture")
                        self.assertTrue(probe.entered.is_set())
                    return 7

                self.assertEqual(probe.run(operation), 7)
                self.assertTrue(probe.finished.is_set())
                raise RuntimeError("test failure")
        self.assertEqual([item[1] for item in actions], ["pause", "inspect", "unpause", "inspect"])
        self.assertTrue(all(item[-1] == self.owned["container_id"] for item in actions))
        self.connection.execute.assert_called_once_with("SELECT fixture")

    def test_unrelated_thread_and_client_are_not_paused(self):
        with (
            patch.object(pause.storage_bootstrap, "validate", return_value=self.owned),
            patch.object(pause.storage, "connect", return_value=self.connection),
            patch.object(pause, "command") as command,
        ):
            with pause.injection("owned", 15449, "client") as probe:
                with pause.storage.connect("client"):
                    pass
                probe.run(lambda: pause.storage.connect("other").__enter__())
                self.assertFalse(probe.entered.is_set())
        command.assert_not_called()

    def test_changed_owner_prevents_unpause_of_unverified_target(self):
        probe = pause.PausedQuery("client", self.owned)
        probe.attempted = True
        with (
            patch.object(pause.storage_bootstrap, "validate", return_value={}),
            patch.object(pause, "command") as command,
            self.assertRaisesRegex(Rejected, "pause_authority_identity_changed"),
        ):
            probe.restore("owned")
        command.assert_not_called()

    def test_connection_finishing_after_context_exit_cannot_pause_authority(self):
        entered, release = threading.Event(), threading.Event()
        failures = []

        def connect(client):
            entered.set()
            release.wait(3)
            return self.connection

        with (
            patch.object(pause.storage_bootstrap, "validate", return_value=self.owned),
            patch.object(pause.storage, "connect", side_effect=connect),
            patch.object(pause, "command", return_value="true") as command,
        ):
            with pause.injection("owned", 15449, "client") as probe:

                def operation():
                    try:
                        with pause.storage.connect("client") as connection:
                            connection.execute("SELECT fixture")
                    except Rejected as failure:
                        failures.append(str(failure))

                thread = threading.Thread(target=lambda: probe.run(operation))
                thread.start()
                self.assertTrue(entered.wait(1))
            release.set()
            thread.join(3)
            self.assertFalse(thread.is_alive())
            command.assert_not_called()
            self.assertEqual(failures, ["pause_injection_closed"])

    def test_query_activity_is_required_not_only_open_connection(self):
        probe = pause.PausedQuery("client", self.owned)
        self.assertFalse(probe.active())
        probe.connection = self.connection
        self.connection.info.transaction_status = pause.TransactionStatus.IDLE
        self.assertFalse(probe.active())
        self.connection.info.transaction_status = pause.TransactionStatus.ACTIVE
        self.assertTrue(probe.active())

    def test_trace_requires_unfinished_read_and_restores_before_drain(self):
        for early_finish, query_active in ((False, True), (True, True), (False, False)):
            with (
                self.subTest(early_finish=early_finish),
                tempfile.TemporaryDirectory() as directory,
            ):
                probe = Mock(entered=threading.Event(), finished=threading.Event())
                probe.active.return_value = query_active
                probe.entered.set()
                if early_finish:
                    probe.finished.set()
                restored = []

                @contextmanager
                def injection(*arguments):
                    try:
                        yield probe
                    finally:
                        restored.append(True)
                        probe.finished.set()

                engine = Mock(lock=threading.Lock(), generation=threading.Event())
                engine.generation.set()
                engine.identity.return_value = {"model_sha256": "a" * 64, "bundle_sha256": "b" * 64}
                engine.worker.container = "old"
                engine.reader.trust.observation.side_effect = [
                    {
                        "sequence": 1,
                        "monotonic": time.monotonic(),
                        "deadline": time.monotonic() + 60,
                    },
                    {"sequence": 2},
                ]

                def drain():
                    self.assertTrue(restored)
                    engine.worker = None

                def activate():
                    engine.worker = Mock(container="new")

                def confirmed(name, condition):
                    if not condition:
                        raise Rejected(name)

                engine.drain.side_effect = drain
                engine.activate.side_effect = activate
                request = Mock(side_effect=[(200, {}), (503, {}), (503, {}), (503, {}), (200, {})])
                output = Path(directory) / "trace.json"
                with (
                    patch.object(pause, "injection", injection),
                    patch.object(pause, "response_valid", return_value=True),
                    patch.object(pause, "command", return_value=""),
                    redirect_stdout(io.StringIO()),
                ):
                    arguments = dict(
                        authority="owned",
                        port=15449,
                        client="client",
                        expected=[],
                        output=output,
                        confirmed=confirmed,
                    )
                    if early_finish or not query_active:
                        with self.assertRaisesRegex(Rejected, "HTTP-denial-before-completion"):
                            pause.exercise(engine, request, {}, **arguments)
                    else:
                        pause.exercise(engine, request, {}, **arguments)
                self.assertTrue(restored)
                self.assertEqual(
                    read_json(output)["status"],
                    "inconclusive" if early_finish or not query_active else "pass",
                )


if __name__ == "__main__":
    unittest.main()
