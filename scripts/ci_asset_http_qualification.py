"""Exercise the real HTTP dispatcher against synthetic response bytes, without sockets."""

import http.client
import io
import traceback
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from mlsecops.contracts import Rejected
from scripts import ci_asset_http as channel

REPO = "repos/Abrakadabra124/trusted-mlsecops-ci-private"
UPLOAD = REPO + "/releases/12/assets"
ASSET = REPO + "/releases/assets/34"
TAG = "ci-candidate-123-1"
TOKEN = "unit_test_token"
CDN = "release-assets.githubusercontent.com"
SIGNED = (
    "https://" + CDN + "/github-production-release-asset/1465012664/abc-123"
    "?sp=r&sig=unit%2Bsignature%3D&response-content-type=application%2Foctet-stream"
)


class Wire:
    """Only the network socket is substituted. http.client formats and parses the messages."""

    def __init__(self, response):
        self.sent = bytearray()
        self.response = response

    def sendall(self, data):
        self.sent.extend(data)

    def makefile(self, mode):
        return io.BytesIO(self.response)

    def close(self):
        pass


class AssetHttpTests(unittest.TestCase):
    def setUp(self):
        self.responses = []
        self.requests = []

        def connect(connection):
            self.assertTrue(self.responses, "unexpected outgoing connection")
            wire = Wire(self.responses.pop(0))
            self.requests.append((connection.host, connection.timeout, wire.sent))
            connection.sock = wire

        self.enterContext(patch.object(http.client.HTTPSConnection, "connect", connect))
        self.reader = channel.Client(TOKEN)
        self.writer = channel.Client(TOKEN, write=True)

    def reply(self, status, body=b"", headers=()):
        lines = [f"HTTP/1.1 {status} Fixture", "Connection: close", *headers]
        self.responses.append(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)

    def test_reader_rejects_every_write_route_before_dispatch(self):
        for method, path, body in (
            ("POST", REPO + "/releases", {"tag_name": TAG}),
            ("DELETE", REPO + "/releases/12", None),
            ("DELETE", ASSET, None),
            ("DELETE", REPO + "/git/refs/tags/" + TAG, None),
        ):
            with self.subTest(path=path), self.assertRaises(Rejected):
                self.reader.json(method, path, body=body)
        with self.assertRaises(Rejected):
            self.reader.upload(UPLOAD, "candidate.bin", b"ciphertext")
        self.assertEqual(self.requests, [])

    def test_only_complete_relative_routes_can_reach_transport(self):
        for path in (
            "https://api.github.com/" + REPO,
            "/" + REPO,
            "//example.org/" + REPO,
            REPO.upper(),
            REPO + "-other",
            REPO + "/",
            REPO + "/contents/workflow",
            REPO + "/../trusted-mlsecops-ci-private",
            REPO + "/releases/tags/../tags/test",
            REPO + "/releases/tags/t%2Fest",
            REPO + "/releases/tags/t%252Fest",
            REPO + "/releases/tags/test#fragment",
            REPO + "/releases/tags/test\r\nX-Test: 1",
            REPO + "/releases/tags/a\\b",
            REPO + "/releases//assets/1",
            ASSET + "?name=a",
            REPO + "/releases/00",
            REPO + "/releases/１２",
            None,
        ):
            with self.subTest(path=path), self.assertRaises(Rejected):
                self.writer.json("GET", path)
        for path in (ASSET, UPLOAD + "?name=other", UPLOAD + "/extra", "/" + UPLOAD):
            with self.subTest(upload=path), self.assertRaises(Rejected):
                self.writer.upload(path, "packet.bin", b"abc")
        for path in (UPLOAD, ASSET + "?name=x", REPO + "/releases/assets/-1", ASSET + "/"):
            with self.subTest(download=path), self.assertRaises(Rejected):
                self.reader.download(path, 32)

    def test_token_flags_and_body_cannot_inject_headers_or_change_method(self):
        for token in ("", "a b", "a\r\nX: ok", "é", "x" * 5000, None):
            with self.subTest(token=repr(token)[:12]), self.assertRaises(Rejected):
                channel.Client(token)
        with self.assertRaises(Rejected):
            channel.Client(TOKEN, write="true")
        for method, path, body, absent in (
            ("PUT", REPO, None, False),
            ("PATCH", ASSET, None, False),
            ("POST", REPO, {}, False),
            ("DELETE", REPO, None, False),
            ("DELETE", REPO + "/git/refs/heads/main", None, False),
            ("get", REPO, None, False),
            ("GET\r\nX: fake", REPO, None, False),
            ("GET", REPO, {}, False),
            ("GET", REPO, None, "yes"),
            ("DELETE", ASSET, None, True),
            ("DELETE", ASSET, {}, False),
            ("POST", REPO + "/releases", None, False),
            ("POST", REPO + "/releases", b"raw", False),
            ("POST", REPO + "/releases", {"tag_name": TAG, "body": object()}, False),
            ("POST", REPO + "/releases", {"tag_name": TAG, "body": ["value"]}, False),
            ("POST", REPO + "/releases", {"tag_name": TAG, "draft": "false"}, False),
            ("POST", REPO + "/releases", {"tag_name": TAG, "body": "é" * 200000}, False),
            ("POST", REPO + "/releases", {"tag_name": TAG, "body": "x" * (1024 * 1024)}, False),
        ):
            with self.subTest(method=method, path=path), self.assertRaises(Rejected):
                self.writer.json(method, path, body=body, absent=absent)

    def test_asset_name_body_and_download_limit_checked_before_connection(self):
        for name in ("", "../x", ".hidden", "a&name=b", "a%2fb", "a/b", "a\r\nb", "é", None):
            with self.subTest(name=name), self.assertRaises(Rejected):
                self.writer.upload(UPLOAD, name, b"a")
        for content in ("abc", b"", bytearray(b"a")):
            with self.subTest(content=content), self.assertRaises(Rejected):
                self.writer.upload(UPLOAD, "asset.bin", content)
        with patch.object(channel, "MAX_ENVELOPE_BYTES", 3):
            with self.assertRaises(Rejected):
                self.writer.upload(UPLOAD, "asset.bin", b"abcd")
        for limit in (0, -1, True, "2", 2**40):
            with self.subTest(limit=limit), self.assertRaises(Rejected):
                self.reader.download(ASSET, limit)

    def test_json_routes_status_and_wire_body(self):
        for path in (
            REPO,
            REPO + "/releases/12",
            REPO + "/releases/tags/" + TAG,
            ASSET,
            REPO + "/git/ref/tags/" + TAG,
        ):
            self.reply(200, b'{"id":12}')
            self.assertEqual(self.reader.json("GET", path), {"id": 12})
            host, timeout, wire = self.requests[-1]
            self.assertEqual(host, "api.github.com")
            self.assertTrue(0 < timeout <= 60)
            self.assertTrue(wire.startswith(f"GET /{path} HTTP/1.1\r\n".encode()))
            self.assertIn(b"\r\nAuthorization: Bearer unit_test_token\r\n", wire)
            self.assertIn(b"\r\nAccept: application/vnd.github+json\r\n", wire)
        self.reply(201, b'{"id":13}')
        self.assertEqual(
            self.writer.json("POST", REPO + "/releases", body={"tag_name": TAG}), {"id": 13}
        )
        wire = self.requests[-1][2]
        self.assertIn(b"\r\nContent-Type: application/json\r\n", wire)
        self.assertEqual(wire.split(b"\r\n\r\n")[1], b'{"tag_name":"ci-candidate-123-1"}')
        for path in (ASSET, REPO + "/releases/12", REPO + "/git/refs/tags/" + TAG):
            self.reply(204)
            self.assertEqual(self.writer.json("DELETE", path), {})

    def test_upload_and_direct_download_use_distinct_origins(self):
        self.reply(201, b'{"id":34}')
        content = b"\x00\xffprivate"
        self.assertEqual(self.writer.upload(UPLOAD, "payload-1.bin", content), {"id": 34})
        host, _, wire = self.requests[-1]
        self.assertEqual(host, "uploads.github.com")
        self.assertTrue(wire.startswith(f"POST /{UPLOAD}?name=payload-1.bin HTTP/1.1\r\n".encode()))
        self.assertIn(b"\r\nContent-Type: application/octet-stream\r\n", wire)
        self.assertIn(b"\r\nAuthorization: Bearer unit_test_token\r\n", wire)
        self.assertEqual(wire.split(b"\r\n\r\n")[1], content)
        self.reply(200, content, [f"Content-Length: {len(content)}"])
        self.assertEqual(self.reader.download(ASSET, len(content)), content)
        host, _, wire = self.requests[-1]
        self.assertEqual(host, "api.github.com")
        self.assertIn(b"\r\nAccept: application/octet-stream\r\n", wire)
        self.assertIn(b"\r\nAuthorization: Bearer unit_test_token\r\n", wire)

    def test_lists_and_head_read_match_the_release_lifecycle(self):
        for path in (
            REPO + "/releases?per_page=20",
            REPO + "/releases?per_page=100",
            UPLOAD + "?per_page=6",
            UPLOAD + "?per_page=7",
        ):
            self.reply(200, b'[{"id":71}]')
            self.assertEqual(self.reader.json("GET", path), [{"id": 71}])
            self.assertTrue(self.requests[-1][2].startswith(f"GET /{path} HTTP/1.1\r\n".encode()))
            self.reply(200, b"{}")
            with self.assertRaises(Rejected):
                self.reader.json("GET", path)
        for branch in ("main", "qualify/store", "_qualify/-store", "a" * 200):
            self.reply(200, b'{"ref":"branch"}')
            self.assertEqual(
                self.reader.json("GET", REPO + "/git/ref/heads/" + branch), {"ref": "branch"}
            )
        for path in (
            REPO + "/releases?per_page=101",
            REPO + "/releases?per_page=100&page=2",
            UPLOAD + "?per_page=6&page=2",
            UPLOAD + "?per_page=7&page=2",
            UPLOAD + "?per_page=8",
            REPO + "/releases?per_page=7",
            REPO + "/git/ref/heads/.",
            REPO + "/git/ref/heads/a//b",
        ):
            with self.subTest(path=path), self.assertRaises(Rejected):
                self.reader.json("GET", path)

    def test_list_with_pagination_link_refuses_even_when_short(self):
        for path in (REPO + "/releases?per_page=20", UPLOAD + "?per_page=7"):
            self.reply(200, b"[]", ['Link: <https://api.github.com/next>; rel="next"'])
            with self.assertRaises(Rejected):
                self.reader.json("GET", path)
            self.assertFalse(self.responses)

    def test_create_only_a_candidate_tag_ref_and_restrict_its_mutation_namespace(self):
        path = REPO + "/git/refs"
        body = {"ref": "refs/tags/" + TAG, "sha": "a" * 40}
        with self.assertRaises(Rejected):
            self.reader.json("POST", path, body=body)
        self.reply(201, b'{"ref":"refs/tags/ci-candidate-123-1"}')
        self.assertEqual(self.writer.json("POST", path, body=body)["ref"], body["ref"])
        self.assertTrue(self.requests[-1][2].startswith(f"POST /{path} HTTP/1.1\r\n".encode()))
        for invalid in (
            body | {"ref": "refs/heads/main"},
            body | {"ref": "refs/tags/v1"},
            body | {"sha": "HEAD"},
            body | {"extra": True},
            {"sha": "a" * 40},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(Rejected):
                self.writer.json("POST", path, body=invalid)
        for tag in ("v1", "ci-candidate-01-1", "ci-candidate-1-a"):
            with self.subTest(tag=tag), self.assertRaises(Rejected):
                self.writer.json("DELETE", REPO + "/git/refs/tags/" + tag)
            with self.subTest(tag=tag), self.assertRaises(Rejected):
                self.writer.json("POST", REPO + "/releases", body={"tag_name": tag})

    def test_process_wide_http_debug_does_not_log_credentials(self):
        logs = io.StringIO()
        with patch.object(http.client.HTTPConnection, "debuglevel", 1), redirect_stdout(logs):
            self.reply(302, headers=["Location: " + SIGNED])
            self.reply(200, b"test")
            self.assertEqual(self.reader.download(ASSET, 4), b"test")
        self.assertNotIn(TOKEN, logs.getvalue())
        self.assertNotIn("unit%2Bsignature", logs.getvalue())

    def test_302_uses_fresh_anonymous_request_and_exact_signed_target(self):
        self.reply(302, headers=["Location: " + SIGNED])
        self.reply(200, b"4\r\npart\r\n0\r\n\r\n", ["Transfer-Encoding: chunked"])
        self.assertEqual(self.reader.download(ASSET, 4), b"part")
        original, redirected = self.requests
        self.assertIn(TOKEN.encode(), original[2])
        host, timeout, wire = redirected
        self.assertEqual(host, CDN)
        self.assertTrue(0 < timeout <= 60)
        target = SIGNED.removeprefix("https://" + CDN)
        self.assertTrue(wire.startswith(f"GET {target} HTTP/1.1\r\n".encode()))
        self.assertNotIn(b"authorization:", wire.lower())
        self.assertNotIn(TOKEN.encode(), wire)
        self.assertNotIn(b"cookie:", wire.lower())

    def test_untrusted_or_ambiguous_locations_never_receive_a_request(self):
        for location in (
            None,
            SIGNED.replace("https:", "http:"),
            SIGNED.replace(CDN, CDN + ".example.org"),
            SIGNED.replace(CDN, "example.org@" + CDN),
            SIGNED.replace(CDN, CDN + "@example.org"),
            SIGNED.replace(CDN, CDN + ":444"),
            SIGNED.replace(CDN, CDN + "."),
            SIGNED.replace(CDN, "raw.githubusercontent.com"),
            SIGNED + "#",
            SIGNED.replace("abc-123", "../foreign"),
            SIGNED.replace("abc-123", "a%2fb"),
            SIGNED.replace("abc-123", "a\\b"),
            SIGNED.replace("abc-123", "a b"),
            SIGNED.replace("&sig=", "&unused="),
            SIGNED + "&sig=other",
            SIGNED.replace("%2B", "%ZX"),
            SIGNED.replace("unit%2Bsignature%3D", ""),
            SIGNED.split("?")[0],
            "//" + CDN + "/x?sig=x",
            "/x?sig=x",
        ):
            with self.subTest(location=location):
                self.reply(302, headers=[] if location is None else ["Location: " + location])
                with self.assertRaises(Rejected):
                    self.reader.download(ASSET, 4)
        self.reply(302, headers=["Location: " + SIGNED, "Location: " + SIGNED])
        with self.assertRaises(Rejected):
            self.reader.download(ASSET, 4)
        self.assertEqual({row[0] for row in self.requests}, {"api.github.com"})

    def test_redirects_and_error_statuses_never_replay_a_write_or_chain_a_download(self):
        for status in (301, 302, 303, 307, 308, 401, 403, 404, 422, 429, 500, 502):
            with self.subTest(status=status):
                self.reply(status, b"private-error", ["Location: " + SIGNED])
                with self.assertRaises(Rejected):
                    self.writer.upload(UPLOAD, "payload.bin", b"ciphertext")
        for operation in (
            lambda: self.reader.json("GET", REPO),
            lambda: self.writer.json("POST", REPO + "/releases", body={"tag_name": TAG}),
            lambda: self.writer.json("DELETE", ASSET),
        ):
            self.reply(302, headers=["Location: " + SIGNED])
            with self.assertRaises(Rejected):
                operation()
        for status in (301, 303, 307, 308, 404, 206):
            self.reply(status, headers=["Location: " + SIGNED])
            with self.assertRaises(Rejected):
                self.reader.download(ASSET, 4)
        self.reply(302, headers=["Location: " + SIGNED])
        self.reply(302, headers=["Location: " + SIGNED])
        with self.assertRaises(Rejected):
            self.reader.download(ASSET, 4)
        self.assertEqual(sum(host == CDN for host, _, _ in self.requests), 1)

    def test_only_explicit_get_404_means_absent(self):
        self.reply(404, b"opaque")
        self.assertIsNone(self.reader.json("GET", ASSET, absent=True))
        for status, absent in ((404, False), (401, True), (403, True), (429, True), (500, True)):
            self.reply(status, b"opaque")
            with self.subTest(status=status), self.assertRaises(Rejected):
                self.reader.json("GET", ASSET, absent=absent)
        for raw in (b"", b"null", b"42", b"not json", b'{"id":1,"id":2}'):
            self.reply(200, raw)
            with self.subTest(raw=raw), self.assertRaises(Rejected):
                self.reader.json("GET", ASSET, absent=True)
        self.reply(201, b"[]")
        with self.assertRaises(Rejected):
            self.writer.upload(UPLOAD, "packet.bin", b"x")

    def test_unexpected_success_code_or_body_framing_cannot_confirm_mutation(self):
        for status, action in (
            (200, lambda: self.writer.json("DELETE", ASSET)),
            (200, lambda: self.writer.upload(UPLOAD, "packet.bin", b"x")),
            (200, lambda: self.writer.json("POST", REPO + "/releases", body={"tag_name": TAG})),
            (201, lambda: self.reader.json("GET", REPO)),
        ):
            self.reply(status, b"{}")
            with self.subTest(status=status), self.assertRaises(Rejected):
                action()
        self.reply(204, b"oops", ["Content-Length: 4"])
        with self.assertRaises(Rejected):
            self.writer.json("DELETE", ASSET)

    def test_response_caps_framing_and_truncation(self):
        for body, headers in (
            (b"abcde", []),
            (b"abcd", ["Content-Length: 5"]),
            (b"x", ["Content-Length: 4"]),
            (b"x", ["Content-Length: -1"]),
            (b"x", ["Content-Length: 1", "Content-Length: 1"]),
            (b"5\r\nabcde\r\n0\r\n\r\n", ["Transfer-Encoding: chunked"]),
            (b"4\r\nxx", ["Transfer-Encoding: chunked"]),
            (b"x", ["Content-Encoding: gzip"]),
            (b"x", ["Transfer-Encoding: chunked", "Content-Length: 1"]),
        ):
            self.reply(200, body, headers)
            with self.subTest(headers=headers), self.assertRaises(Rejected):
                self.reader.download(ASSET, 4)
        self.reply(200, b" " * (1024 * 1024) + b"{}")
        with self.assertRaises(Rejected):
            self.reader.json("GET", REPO)
        self.reply(302, headers=["Location: " + SIGNED])
        self.reply(200, b"abcde")
        with self.assertRaises(Rejected):
            self.reader.download(ASSET, 4)

    def test_transport_errors_do_not_publish_body_token_or_signed_url(self):
        for failure in (TimeoutError(TOKEN), OSError(SIGNED), http.client.BadStatusLine(SIGNED)):
            self.reply(302, headers=["Location: " + SIGNED])
            self.responses.append(b"")
            with patch.object(Wire, "sendall", autospec=True, side_effect=[None, failure]):
                try:
                    self.reader.download(ASSET, 4)
                except Rejected as exc:
                    rendered = "".join(traceback.format_exception(exc))
                else:
                    self.fail("failed download returned data")
            self.assertNotIn(TOKEN, rendered)
            self.assertNotIn("unit%2Bsignature", rendered)


if __name__ == "__main__":
    unittest.main()
