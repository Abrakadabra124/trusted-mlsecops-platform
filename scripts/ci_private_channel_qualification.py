"""Failure-first contracts for the private hosted canary, never production keys."""

import base64
import io
import os
import tempfile
import unittest
import urllib.error
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, digest
from scripts import ci_private_channel as channel

KEY = bytes(range(32))
SHA = "a" * 40
FP = "b" * 64
ENV = {
    "GITHUB_ACTIONS": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "GITHUB_REPOSITORY": "Abrakadabra124/trusted-mlsecops-ci-private",
    "GITHUB_REPOSITORY_ID": "1465012664",
    "GITHUB_SHA": SHA,
    "GITHUB_RUN_ID": "12345",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_REF": "refs/heads/qualify/private-channel-native",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_JOB": "producer",
}


def metadata():
    return dict(
        id=1465012664,
        full_name=ENV["GITHUB_REPOSITORY"],
        private=True,
        visibility="private",
        fork=False,
        owner={"login": "Abrakadabra124"},
    )


def run_record():
    return dict(
        id=12345,
        run_attempt=1,
        head_sha=SHA,
        head_branch="qualify/private-channel-native",
        event="workflow_dispatch",
        path=".github/workflows/private-channel.yml",
        repository={"id": 1465012664},
        head_repository={"id": 1465012664},
    )


class FakeAPI:
    def __init__(self):
        self.repo = metadata()
        self.run = run_record()
        self.commit = {"sha": SHA}
        self.rows = []
        self.calls = []
        self.remains = False

    def __call__(self, method, path, *, absent=False):
        self.calls.append((method, path))
        base = "repos/" + ENV["GITHUB_REPOSITORY"]
        if path == base:
            return self.repo
        if "/commits/" in path:
            return self.commit
        if path == base + "/actions/runs/12345":
            return self.run
        if path.endswith("/artifacts?per_page=100"):
            return dict(total_count=len(self.rows), artifacts=self.rows.copy())
        if "/actions/artifacts/" in path:
            wanted = int(path.rsplit("/", 1)[1])
            found = next((r for r in self.rows if r["id"] == wanted), None)
            if method == "DELETE":
                if not self.remains:
                    self.rows = [r for r in self.rows if r["id"] != wanted]
                return {}
            return found
        raise AssertionError("unhandled fixture API")


def artifact():
    return dict(
        id=901,
        name="private-channel-12345-1",
        size_in_bytes=2048,
        expired=False,
        workflow_run=dict(
            id=12345,
            repository_id=1465012664,
            head_repository_id=1465012664,
            head_sha=SHA,
            head_branch="qualify/private-channel-native",
        ),
    )


class ChannelTests(unittest.TestCase):
    def guard(self, api=None, env=None, **kw):
        return channel.guard(
            FakeAPI() if api is None else api,
            ENV if env is None else env,
            head=SHA,
            dirty=False,
            platform="linux",
            **kw,
        )

    def test_private_live_guard_and_public_source_are_distinct(self):
        api = FakeAPI()
        self.assertEqual(self.guard(api), (12345, 1))
        self.assertIn(
            ("GET", "repos/Abrakadabra124/trusted-mlsecops-platform/commits/" + SHA), api.calls
        )

    def test_public_renamed_recreated_forked_and_foreign_owner_refuse(self):
        for change in (
            {"private": False},
            {"private": 1},
            {"id": 2},
            {"id": True},
            {"visibility": "public"},
            {"fork": True},
            {"fork": 0},
            {"full_name": "foreign/repo"},
            {"owner": {"login": "other"}},
        ):
            api = FakeAPI()
            api.repo.update(change)
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.guard(api)

    def test_wrong_environment_or_source_refuses(self):
        for key, value in (
            ("GITHUB_REPOSITORY", "Abrakadabra124/trusted-mlsecops-platform"),
            ("GITHUB_REPOSITORY_ID", "2"),
            ("GITHUB_RUN_ID", "012345"),
            ("GITHUB_RUN_ATTEMPT", "0"),
            ("GITHUB_ACTIONS", "false"),
            ("RUNNER_ENVIRONMENT", "self-hosted"),
            ("GITHUB_SHA", "d" * 40),
            ("GITHUB_REF", "refs/pull/1/merge"),
            ("GITHUB_EVENT_NAME", "pull_request"),
        ):
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.guard(env=ENV | {key: value})
        for options in ({"head": "c" * 40}, {"dirty": True}, {"platform": "win32"}):
            kw = dict(head=SHA, dirty=False, platform="linux") | options
            with self.subTest(options=options), self.assertRaises(Rejected):
                channel.guard(FakeAPI(), ENV, **kw)
        api = FakeAPI()
        api.commit["sha"] = "f" * 40
        with self.assertRaises(Rejected):
            self.guard(api)

    def test_wrong_run_attempt_or_workflow_refuses(self):
        for key, value in (
            ("id", 1),
            ("run_attempt", 2),
            ("head_sha", "e" * 40),
            ("path", "foreign.yml"),
            ("event", "push"),
            ("head_branch", "main"),
            ("repository", {"id": 2}),
            ("head_repository", {"id": 2}),
        ):
            api = FakeAPI()
            api.run[key] = value
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.guard(api)

    def test_key_is_strict_and_never_printed(self):
        self.assertEqual(channel.key(base64.b64encode(KEY).decode()), KEY)
        for value in ("", "bad", "A" * 44, " " + base64.b64encode(KEY).decode(), None):
            with self.subTest(value=value), self.assertRaises(Rejected):
                channel.key(value)

    def test_real_crypto_roundtrip_and_negative_campaign(self):
        sealed = channel.produce(KEY, ENV, FP)
        self.assertEqual(set(sealed), {"envelope", "context", "pin"})
        self.assertEqual(sealed["context"]["repository"], ENV["GITHUB_REPOSITORY"])
        self.assertEqual(digest(sealed["envelope"]), sealed["pin"])
        result = channel.consume(
            sealed["envelope"],
            key=KEY,
            context=sealed["context"],
            pin=sealed["pin"],
            environment=ENV,
            fingerprint=FP,
        )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["negative_checks"], 7)
        self.assertFalse(result["release_ready"])

    def test_receiver_refuses_wrong_external_authority(self):
        sealed = channel.produce(KEY, ENV, FP)
        for field, value in (
            ("run_id", 12346),
            ("run_attempt", 2),
            ("source_revision", "e" * 40),
            ("source_fingerprint", "e" * 64),
            ("phase", "foreign"),
            ("repository", "Abrakadabra124/trusted-mlsecops-platform"),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                channel.consume(
                    sealed["envelope"],
                    key=KEY,
                    context=sealed["context"] | {field: value},
                    pin=sealed["pin"],
                    environment=ENV,
                    fingerprint=FP,
                )

    def test_artifact_precheck_and_exact_cleanup(self):
        api = FakeAPI()
        api.rows = [artifact()]
        self.assertEqual(channel.artifact_check(api, ENV, 901), artifact())
        self.assertEqual(channel.cleanup(api, ENV), 1)
        self.assertEqual(api.rows, [])
        self.assertEqual(channel.cleanup(api, ENV), 0)
        self.assertEqual(
            [x for x in api.calls if x[0] == "DELETE"],
            [("DELETE", "repos/" + ENV["GITHUB_REPOSITORY"] + "/actions/artifacts/901")],
        )

    def test_foreign_oversized_expired_or_wrong_attempt_artifact_is_never_deleted(self):
        for change in (
            {"id": True},
            {"name": "private-channel-12345-2"},
            {"size_in_bytes": 65537},
            {"size_in_bytes": 0},
            {"expired": True},
            {"workflow_run": artifact()["workflow_run"] | {"id": 2}},
            {"workflow_run": artifact()["workflow_run"] | {"head_sha": "f" * 40}},
        ):
            api = FakeAPI()
            api.rows = [artifact() | change]
            with self.subTest(change=change), self.assertRaises(Rejected):
                channel.cleanup(api, ENV)
            self.assertFalse(any(x[0] == "DELETE" for x in api.calls))

    def test_cleanup_error_or_still_present_cannot_be_success(self):
        api = FakeAPI()
        api.rows = [artifact()]
        api.remains = True
        with self.assertRaises(Rejected):
            channel.cleanup(api, ENV)
        with self.assertRaises(OSError):
            channel.cleanup(lambda *a, **kw: (_ for _ in ()).throw(OSError("fixture")), ENV)

    def test_duplicate_or_malformed_artifact_list_refuses(self):
        for rows in ([artifact(), artifact()], [None]):
            api = FakeAPI()
            api.rows = rows
            with self.subTest(rows=rows), self.assertRaises(Rejected):
                channel.cleanup(api, ENV)

    def test_cli_failure_is_closed(self):
        output = io.StringIO()
        with (
            patch.dict(os.environ, ENV, clear=True),
            patch.object(channel, "execute", side_effect=OSError("PRIVATE_NEEDLE")),
            redirect_stdout(output),
        ):
            self.assertEqual(channel.main(["producer"]), 1)
        self.assertNotIn("PRIVATE_NEEDLE", output.getvalue())
        self.assertIn('"status":"inconclusive"', output.getvalue())

    def test_receiver_size_type_and_negative_campaign_regression(self):
        sealed = channel.produce(KEY, ENV, FP)
        options = dict(
            key=KEY, context=sealed["context"], pin=sealed["pin"], environment=ENV, fingerprint=FP
        )
        for envelope in (b"", b"x" * 65537, bytearray(sealed["envelope"])):
            with self.subTest(kind=type(envelope)), self.assertRaises(Rejected):
                channel.consume(envelope, **options)
        # If a future reader erroneously accepts a mutation, the campaign fails.
        with (
            patch.object(channel.ci_transfer, "open", return_value=channel.PAYLOAD),
            self.assertRaises(Rejected),
        ):
            channel.consume(sealed["envelope"], **options)

    def test_integer_range_and_artifact_mismatch(self):
        with self.assertRaises(Rejected):
            channel.number(str(2**53))
        api = FakeAPI()
        api.rows = [artifact()]
        original = api.__call__

        def wrong_id(method, path, **kw):
            value = original(method, path, **kw)
            return value | {"id": 902} if path.endswith("/901") else value

        with self.assertRaises(Rejected):
            channel.artifact_check(wrong_id, ENV, 901)

    def test_http_status_limits_no_redirect_and_absence(self):
        path = "repos/" + channel.REPOSITORY
        with patch.dict(os.environ, {"GH_TOKEN": "test-token"}):
            for status, raw, method, expected in (
                (200, b'{"ok":true}', "GET", {"ok": True}),
                (204, b"", "DELETE", {}),
            ):
                response = Mock(status=status)
                response.read.return_value = raw
                opener = Mock()
                opener.open.return_value.__enter__ = Mock(return_value=response)
                opener.open.return_value.__exit__ = Mock(return_value=False)
                with patch.object(channel.urllib.request, "build_opener", return_value=opener):
                    self.assertEqual(channel.request(method, path), expected)
                    self.assertEqual(response.read.call_args.args, (1024 * 1024 + 1,))
                    self.assertEqual(opener.open.call_args.kwargs, {"timeout": 30})
            for status, raw in (
                (200, b"x" * (1024 * 1024 + 1)),
                (202, b"{}"),
                (200, b"invalid-json"),
            ):
                response = Mock(status=status)
                response.read.return_value = raw
                opener = Mock()
                opener.open.return_value.__enter__ = Mock(return_value=response)
                opener.open.return_value.__exit__ = Mock(return_value=False)
                with (
                    patch.object(channel.urllib.request, "build_opener", return_value=opener),
                    self.assertRaises(Rejected),
                ):
                    channel.request("GET", path)
            for method, code, absent, passes in (
                ("GET", 404, True, True),
                ("GET", 404, False, False),
                ("GET", 403, True, False),
                ("DELETE", 404, True, False),
            ):
                error = urllib.error.HTTPError(
                    "https://api.github.com/fixture", code, "fixture", {}, io.BytesIO(b"")
                )
                opener = Mock()
                opener.open.side_effect = error
                with patch.object(channel.urllib.request, "build_opener", return_value=opener):
                    if passes:
                        self.assertIsNone(channel.request(method, path, absent=absent))
                    else:
                        with self.assertRaises(Rejected):
                            channel.request(method, path, absent=absent)
            for method, path_bad in (
                ("POST", path),
                ("GET", "https://foreign.invalid"),
                ("GET", "repos/../secret"),
            ):
                with self.assertRaises(Rejected):
                    channel.request(method, path_bad)
            with patch.dict(os.environ, {"GH_TOKEN": "test\ntoken"}), self.assertRaises(Rejected):
                channel.request("GET", path)
        with self.assertRaises(Rejected):
            channel.NoRedirect().redirect_request(
                None, None, 302, None, None, "https://foreign.invalid"
            )

    def test_cli_producer_receiver_and_owned_file_cleanup(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            output = root / "output"
            output.touch()
            environment = ENV | {
                "CHANNEL_AES_KEY": base64.b64encode(KEY).decode(),
                "GITHUB_OUTPUT": str(output),
            }
            stack.enter_context(patch.object(channel.Path, "cwd", return_value=root))
            stack.enter_context(patch.object(channel.sys, "platform", "linux"))
            stack.enter_context(
                patch.object(
                    channel, "command", side_effect=lambda args: "" if "status" in args else SHA
                )
            )
            stack.enter_context(patch.object(channel, "source_fingerprint", return_value=FP))
            api = FakeAPI()
            stack.enter_context(patch.object(channel, "request", api))
            stack.enter_context(patch.dict(os.environ, environment, clear=True))
            self.assertTrue(channel.execute("producer")["ciphertext_prepared"])
            fields = dict(line.split("=", 1) for line in output.read_text().splitlines())
            self.assertNotIn(environment["CHANNEL_AES_KEY"], output.read_text())
            self.assertNotIn("envelope", fields)
            with patch.dict(
                os.environ,
                {
                    "CHANNEL_CONTEXT": fields["context"],
                    "CHANNEL_PIN": fields["pin"],
                    "GITHUB_JOB": "receiver",
                },
            ):
                self.assertEqual(channel.execute("receiver")["negative_checks"], 7)
                self.assertFalse((root / channel.FILE).exists())
            channel.execute("producer")
            with (
                patch.dict(
                    os.environ,
                    {"CHANNEL_CONTEXT": "{}", "CHANNEL_PIN": "0" * 64, "GITHUB_JOB": "receiver"},
                ),
                self.assertRaises(Rejected),
            ):
                channel.execute("receiver")
            self.assertFalse((root / channel.FILE).exists())
            api.rows = [artifact()]
            with patch.dict(os.environ, {"CHANNEL_ARTIFACT_ID": "901", "GITHUB_JOB": "receiver"}):
                self.assertTrue(channel.execute("precheck")["artifact_checked"])
            with patch.dict(os.environ, {"GITHUB_JOB": "cleanup"}):
                self.assertEqual(channel.execute("cleanup")["artifacts_deleted"], 1)
            with self.assertRaises(Rejected):
                channel.execute("bad-mode")

    def test_cli_success_and_bad_arguments_do_not_leak_secret(self):
        output = io.StringIO()
        with (
            patch.dict(os.environ, {"CHANNEL_AES_KEY": "SECRET_CANARY"}),
            patch.object(channel, "execute", return_value={"status": "pass"}),
            redirect_stdout(output),
        ):
            self.assertEqual(channel.main(["cleanup"]), 0)
            self.assertNotIn("CHANNEL_AES_KEY", os.environ)
            self.assertEqual(channel.main([]), 1)
        self.assertNotIn("SECRET_CANARY", output.getvalue())

    def test_cli_wrong_job_refuses_before_network(self):
        with (
            patch.dict(os.environ, ENV | {"GITHUB_JOB": "foreign"}, clear=True),
            patch.object(
                channel, "request", side_effect=AssertionError("network before job guard")
            ) as api,
            patch.object(
                channel, "command", side_effect=lambda args: "" if "status" in args else SHA
            ),
            patch.object(channel.sys, "platform", "linux"),
        ):
            with self.assertRaises(Rejected):
                channel.execute("producer")
            api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
