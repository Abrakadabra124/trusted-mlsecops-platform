import unittest
from unittest.mock import Mock, patch

from mlsecops import serving_metrics
from mlsecops.contracts import Rejected
from scripts import serving_metrics_probe as probe


class MetricsProbeContracts(unittest.TestCase):
    def setUp(self):
        self.metrics = serving_metrics.Metrics()
        self.content = self.metrics.render()
        self.counter = b'mlsecops_http_responses_total{outcome="2xx",route="predict"} 0.0'
        self.bucket = b'mlsecops_http_duration_seconds_bucket{le="0.01",route="predict"} 0.0'
        self.headers = [
            ("Cache-Control", "no-store"),
            ("Content-Type", "text/plain; version=0.0.4; charset=utf-8"),
        ]

    def test_fixed_schema_accepts_zero_and_observed_values(self):
        for observed in (False, True):
            if observed:
                self.metrics.observe("predict", "2xx", 0.1)
                self.metrics.observe("other", "aborted", 12.5)
            content = self.metrics.render()
            self.assertEqual(probe.checked(content, ()), {"series": 69, "bytes": len(content)})

    def test_non_bytes_empty_oversize_and_private_canaries_fail(self):
        for content in ("invalid", b"", b" " * 16385, self.content + b"private-canary"):
            with self.subTest(content_type=type(content)):
                with self.assertRaisesRegex(Rejected, "metrics_privacy_output_invalid"):
                    probe.checked(content, (b"private-canary",))

    def test_unknown_duplicate_missing_or_invalid_samples_and_comments_fail(self):
        variants = [
            self.content + b"\xff",
            self.content.replace(b"Observed ASGI", b"unknown ASGI"),
            self.content + b"# private comment\n",
            self.content + b"unexpected_metric 0\n",
            self.content + self.counter + b"\n",
            self.content.replace(self.counter + b"\n", b""),
            self.content.replace(b'route="predict"', b'route="private"', 1),
            self.content.replace(self.counter, self.counter + b" 123"),
            self.content.replace(self.counter, self.counter + b' # {private="value"} 1'),
            self.content.replace(self.bucket, self.bucket[:-3] + b"1.0"),
            self.content.replace(self.counter, self.counter[:-3] + b"1.0"),
            self.content.replace(
                b'mlsecops_http_duration_seconds_count{route="predict"} 0.0',
                b'mlsecops_http_duration_seconds_count{route="predict"} 1.0',
            ),
            self.content.replace(
                b"mlsecops_http_metrics_errors_total 0.0", b"mlsecops_http_metrics_errors_total 1.0"
            ),
        ]
        variants.extend(
            self.content.replace(self.counter, self.counter[:-3] + value)
            for value in (b"NaN", b"+Inf", b"-1", b"0.5", b"not_a_number")
        )
        for index, content in enumerate(variants):
            with self.subTest(index=index):
                with self.assertRaisesRegex(Rejected, "metrics_privacy_schema_invalid"):
                    probe.checked(content, ())

    def test_parser_exemplar_is_not_allowed_even_with_valid_labels(self):
        families = list(probe.text_string_to_metric_families(self.content.decode()))
        families[-1].samples[0] = families[-1].samples[0]._replace(exemplar=object())
        with patch.object(probe, "text_string_to_metric_families", return_value=families):
            with self.assertRaisesRegex(Rejected, "metrics_privacy_schema_invalid"):
                probe.checked(self.content, ())
        with patch.object(probe, "text_string_to_metric_families", return_value=[]):
            with self.assertRaisesRegex(Rejected, "metrics_privacy_schema_invalid"):
                probe.checked(self.content, ())

    def test_hidden_comments_empty_families_and_late_metadata_are_rejected(self):
        lines = self.content.splitlines(keepends=True)
        comments = [line for line in lines if line.startswith(b"#")]
        samples = [line for line in lines if not line.startswith(b"#")]
        for content in (
            self.content + b" # request_id=private_identifier\n",
            self.content
            + b" # HELP private_identity private_identifier\n # TYPE private_identity gauge\n",
            b"".join(samples + comments),
        ):
            with self.subTest(content_length=len(content)):
                with self.assertRaisesRegex(Rejected, "metrics_privacy_schema_invalid"):
                    probe.checked(content, ())

    def test_canaries_credentials_and_unknown_headers_are_rejected(self):
        for header in (
            ("X-Debug-Token", "b" * 64),
            ("X-Unapproved", "unexpected"),
            ("private-canary", "value"),
            ("Date", "private-canary"),
        ):
            request = Mock(return_value=(200, self.headers + [header], self.content))
            request.metrics_credential = "b" * 64
            with self.subTest(header_name=header[0]):
                with self.assertRaises(Rejected):
                    probe.scan(request, (b"private-canary",))

    def test_scrape_checks_identity_status_headers_and_operator_secret(self):
        request = Mock(return_value=(200, self.headers, self.content))
        request.metrics_credential = "b" * 64
        self.assertEqual(probe.scan(request, ())["series"], 69)
        request.assert_called_once_with("/metrics", credential="b" * 64, raw=True)
        for credential in (None, 123, "", "g" * 64, "b" * 63):
            request.metrics_credential = credential
            with self.assertRaisesRegex(Rejected, "metrics_privacy_credential_missing"):
                probe.scan(request, ())
        request.metrics_credential = "b" * 64
        for status, headers, content in (
            (401, self.headers, self.content),
            (200, [], self.content),
            (200, self.headers[:1], self.content),
            (200, self.headers + self.headers[:1], self.content),
            (200, self.headers + self.headers[1:], self.content),
            (200, self.headers + [("date", None)], self.content),
            (200, self.headers + [(None, "date")], self.content),
            (200, self.headers + [("date", "not-a-date")], self.content),
            (200, self.headers + [("date", "x" * 129)], self.content),
            (200, self.headers + [("content-length", "0")], self.content),
            (200, [("cache-control", "public"), self.headers[1]], self.content),
            (200, [self.headers[0], ("content-type", "text/html")], self.content),
        ):
            request.return_value = status, headers, content
            with self.assertRaisesRegex(Rejected, "metrics_privacy_scrape_invalid"):
                probe.scan(request, ())
        request.return_value = 200, self.headers, self.content + b"b" * 64
        with self.assertRaisesRegex(Rejected, "metrics_privacy_output_invalid"):
            probe.scan(request, ())


if __name__ == "__main__":
    unittest.main()
