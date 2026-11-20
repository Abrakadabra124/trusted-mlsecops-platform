"""Offline qualification of the credentialed public reader at its campaign entry points."""

import http.client
import io
import os
import pickle
import subprocess
import sys
import unittest
from collections import deque
from contextlib import redirect_stdout
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import (
    ci_asset_http,
    ci_campaign_guard,
    ci_campaign_image,
    ci_campaign_source,
    ci_source_image_native,
)
from scripts import ci_campaign_terminal_qualification as terminal_cases
from scripts.ci_asset_http_qualification import Wire
from scripts.ci_campaign_guard_qualification import SourceRun

BASE = "repos/Abrakadabra124/trusted-mlsecops-platform"
PRIVATE = "repos/Abrakadabra124/trusted-mlsecops-ci-private"
RUN = BASE + "/actions/runs/3"
ATTEMPT = RUN + "/attempts/1"
JOBS = ATTEMPT + "/jobs?per_page=100"
PUBLIC_TOKEN = "fixture-public-reader"
PRIVATE_TOKEN = "fixture-private-reader"


class PublicReaderTests(unittest.TestCase):
    def setUp(self):
        # Replace only the socket opening. Exercise the actual HTTPS request and response parser.
        self.replies = deque()
        self.requests = []

        def connect(connection):
            wire = Wire(self.replies.popleft() if self.replies else b"")
            self.requests.append((connection.host, connection.timeout, wire.sent))
            connection.sock = wire

        self.enterContext(patch.object(http.client.HTTPSConnection, "connect", connect))
        self.client = ci_campaign_source.Client(PUBLIC_TOKEN)

    def reply(self, body=b"{}", *, status=200, headers=()):
        lines = [f"HTTP/1.1 {status} Fixture", *headers, "", ""]
        self.replies.append("\r\n".join(lines).encode("ascii") + body)

    def check_gets(self, paths):
        self.assertEqual(len(self.requests), len(paths))
        for (host, timeout, wire), path in zip(self.requests, paths, strict=True):
            self.assertEqual(host, "api.github.com")
            self.assertTrue(0 < timeout <= 30)
            line, headers = bytes(wire).split(b"\r\n", 1)
            self.assertEqual(line, f"GET /{path} HTTP/1.1".encode())
            self.assertIn(f"Authorization: Bearer {PUBLIC_TOKEN}\r\n".encode(), headers)
            self.assertNotIn(PRIVATE_TOKEN.encode(), wire)

    def test_real_campaign_and_image_guards_use_the_same_three_reads(self):
        run = SourceRun(self)
        paths = [BASE, run.commit_path, RUN]
        for path in paths * 2:
            self.reply(canonical(run.rows[path]))
        self.assertIsNone(run.authorize(source_api=self.client))
        self.assertEqual(
            ci_source_image_native.guard(
                self.client,
                run.env,
                head=run.source["source_revision"],
                dirty=False,
                platform="linux",
                workflow=ci_campaign_image.WORKFLOW,
            ),
            (3, 1),
        )
        self.check_gets(paths * 2)

    def test_terminal_cleanup_rechecks_public_attempt_before_deleting_private_fixture(self):
        fixture = terminal_cases.TerminalTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        paths = [
            BASE,
            BASE + "/commits/" + terminal_cases.SOURCE["source_revision"],
            terminal_cases.RUN,
            terminal_cases.ATTEMPT,
            terminal_cases.JOB_LIST,
        ]
        for path in paths * 2:
            self.reply(canonical(fixture.rows[path]))
        fixture.clean(source_api=self.client)
        self.check_gets(paths * 2)
        self.assertIsNone(fixture.private.release)
        self.assertIsNone(fixture.private.tag)

    def test_closed_routes_and_canonical_identifiers_before_connection(self):
        for method in (None, "POST", "DELETE", "HEAD", "get", "GET\r\nX: y"):
            with self.subTest(method=method), self.assertRaises(Rejected):
                self.client(method, BASE)
        for path in (
            None,
            "https://api.github.com/" + BASE,
            "/" + BASE,
            "//example.test/" + BASE,
            PRIVATE,
            BASE + "-copy",
            BASE + "/",
            BASE + "/contents/config",
            BASE + "/commits/" + "A" * 40,
            BASE + "/commits/main",
            BASE + "/commits/" + "a" * 41,
            BASE + "/../other",
            BASE + "/actions/artifacts/3",
            RUN + "/artifacts?per_page=100",
            RUN + "/jobs?per_page=100",
            RUN + "?per_page=100",
            RUN + "/attempts/%31",
            RUN + "/attempts/１",
            RUN + "/attempts/01",
            RUN + "/attempts/0",
            RUN + "/attempts/9007199254740992",
            BASE + "/actions/runs/9007199254740992",
            ATTEMPT + "/jobs",
            ATTEMPT + "/jobs?per_page=10",
            JOBS + "&page=2",
            JOBS + "&per_page=100",
            JOBS + "&private_detail=" + PUBLIC_TOKEN,
            JOBS + "#fragment",
            JOBS + "\n",
        ):
            with self.subTest(path=path), self.assertRaises(Rejected) as refusal:
                self.client("GET", path)
            self.assertNotIn(PUBLIC_TOKEN, repr(refusal.exception))
            self.assertNotIn("per_page", repr(refusal.exception))
        self.assertEqual(self.requests, [])
        maximum = BASE + "/actions/runs/9007199254740991/attempts/9007199254740991"
        self.reply(b'{"id":1}')
        self.assertEqual(self.client("GET", maximum), {"id": 1})
        self.check_gets([maximum])

    def test_explicit_tokens_are_separate_and_worker_environment_is_clean(self):
        credentials = dict(GITHUB_TOKEN=PUBLIC_TOKEN, CANDIDATE_ACCESS_TOKEN=PRIVATE_TOKEN)
        self.enterContext(patch.dict(os.environ, credentials, clear=True))
        public = ci_campaign_source.Client(os.environ.pop("GITHUB_TOKEN"))
        private = ci_asset_http.Client(os.environ.pop("CANDIDATE_ACCESS_TOKEN"))
        self.assertEqual(dict(os.environ), {})
        os.environ["UNRELATED_JOB_SECRET"] = "fixture-other"
        with ci_campaign_guard.isolated_environment():
            self.reply(b'{"scope":"public"}')
            self.reply(b'{"scope":"private"}')
            self.assertEqual(public("GET", BASE), {"scope": "public"})
            self.assertEqual(private.json("GET", PRIVATE), {"scope": "private"})
            worker = subprocess.run(
                [
                    sys.executable,
                    "-ISB",
                    "-c",
                    "import os; print(any('fixture-' in v for v in os.environ.values()))",
                ],
                capture_output=True,
                check=True,
                timeout=10,
                text=True,
            )
            self.assertEqual(worker.stdout.strip(), "False")
        for token, wire, other in (
            (PUBLIC_TOKEN, self.requests[0][2], PRIVATE_TOKEN),
            (PRIVATE_TOKEN, self.requests[1][2], PUBLIC_TOKEN),
        ):
            self.assertIn(f"Authorization: Bearer {token}\r\n".encode(), wire)
            self.assertNotIn(other.encode(), wire)
        with self.assertRaises(Rejected):
            private.json("GET", BASE)

    def test_credential_validation_repr_and_worker_serialization(self):
        for value in ("", None, b"token", PUBLIC_TOKEN + "\r\nX: y", "é", "a" * 4097):
            with self.subTest(value_type=type(value)), self.assertRaises(Rejected) as refusal:
                ci_campaign_source.Client(value)
            self.assertNotIn(PUBLIC_TOKEN, repr(refusal.exception))
        with self.assertRaises(TypeError):
            ci_campaign_source.Client()
        self.assertNotIn(PUBLIC_TOKEN, repr(self.client))
        with self.assertRaises(TypeError) as refusal:
            pickle.dumps(self.client)
        self.assertNotIn(PUBLIC_TOKEN, str(refusal.exception))

    def test_refusals_never_forward_redirects_or_expose_response_details(self):
        detail = "detail.test/private?key=" + PUBLIC_TOKEN
        for status in (206, 301, 302, 303, 307, 308, 401, 404, 429, 503):
            self.reply(detail.encode(), status=status, headers=["Location: https://" + detail])
            with self.subTest(status=status), self.assertRaises(Rejected) as refusal:
                self.client("GET", JOBS)
            self.assertNotIn(PUBLIC_TOKEN, repr(refusal.exception))
            self.assertNotIn("per_page", repr(refusal.exception))
        self.check_gets([JOBS] * 10)
        with patch.object(Wire, "sendall", side_effect=TimeoutError(detail)):
            self.reply()
            with self.assertRaises(Rejected) as refusal:
                self.client("GET", JOBS)
        self.assertIsNone(refusal.exception.__context__)
        self.assertNotIn(PUBLIC_TOKEN, repr(refusal.exception))
        self.assertNotIn("per_page", repr(refusal.exception))

    def test_only_complete_bounded_json_objects(self):
        for body, headers in (
            (b"[]", ()),
            (b"null", ()),
            (b"not-json", ()),
            (b'{"id":1,"id":2}', ()),
            (b" " * (1024 * 1024) + b"{}", ()),
            (b"{}", ("Content-Length: 1048577",)),
            (b"{}", ("Content-Length: 3",)),
            (b"{}", ("Content-Encoding: gzip",)),
            (b"{}", ("Transfer-Encoding: chunked", "Content-Length: 2")),
            (b"{}", ("Link: <https://detail.test/private?page=2>; rel=next",)),
        ):
            self.reply(body, headers=headers)
            with self.subTest(headers=headers), self.assertRaises(Rejected) as refusal:
                self.client("GET", JOBS)
            self.assertIsNone(refusal.exception.__context__)
        logs = io.StringIO()
        self.reply(b"2\r\n{}\r\n0\r\n\r\n", headers=["Transfer-Encoding: chunked"])
        with patch.object(http.client.HTTPConnection, "debuglevel", 1), redirect_stdout(logs):
            self.assertEqual(self.client("GET", JOBS), {})
        self.assertEqual(logs.getvalue(), "")
