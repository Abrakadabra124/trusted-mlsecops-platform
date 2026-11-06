"""Privacy around the unmodified ordinary CLI, without in-process admission instrumentation."""

import re
import secrets
import time
from pathlib import Path

from mlsecops import (
    audit_evidence,
    audit_export,
    audit_retention,
    audit_snapshot,
    kube_serving_probe,
    signing,
)
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    write_json,
)
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce
from scripts import audit_correlation_probe, serving_metrics_probe, serving_privacy_probe
from scripts.kube_privacy_diagnostic import location
from scripts.kube_privacy_operator import decoded

MAX_BYTES = 1024 * 1024


def verify_snapshot(snapshot, context, http):
    """Closed bytes + observed outcomes; explicitly NOT independent admission proof."""
    require_fields(snapshot, ("manifest", "segments"))
    saved = audit_snapshot.manifest(decoded(snapshot["manifest"], audit_retention.MAX_MANIFEST))
    if type(snapshot["segments"]) is not list or len(snapshot["segments"]) != len(
        saved["segments"]
    ):
        raise Rejected("cli_privacy_segments")
    chunks = []
    for value, segment in zip(snapshot["segments"], saved["segments"], strict=True):
        chunk = decoded(value, saved["policy"]["segment_bytes"])
        if len(chunk) != segment["size"] or digest(chunk) != segment["sha256"]:
            raise Rejected("cli_privacy_segment_digest")
        chunks.append(chunk)
    if (
        audit_retention.sequences(chunks[0])[0] != 1
        or audit_retention.sequences(chunks[-1])[1] != saved["sequence"]
    ):
        raise Rejected("cli_privacy_sequence")
    public = audit_export.project(chunks)
    if public["status"] != "pass" or public["requests"]["aborted"] != 0:
        raise Rejected("cli_privacy_unfinished_window")
    if context.get("kind") != "release-selection":
        raise Rejected("cli_privacy_requires_release_context")
    correlation = audit_correlation_probe.scan(chunks, context)
    if type(http) is not list or not 1 <= len(http) <= audit_export.MAX_REQUESTS:
        raise Rejected("cli_privacy_http_capacity")
    observed = {}
    for number, row in enumerate(http, 1):
        require_fields(row, ("exchange", "request_id", "route", "status"))
        # Reuse the outcome field/type validator only. No admission is inferred here.
        audit_evidence.checked_outcome({**row, "admitted": False})
        identifier = row["request_id"]
        if row["exchange"] != number or identifier is not None and identifier in observed:
            raise Rejected("cli_privacy_http_duplicate")
        if identifier is not None:
            observed[identifier] = row
    completed = {}
    for chunk in chunks:
        for line in chunk.splitlines():
            event = decode(line)["event"]
            if event["stage"] == "response_completed":
                completed[event["request_id"]] = event
    if any(
        identifier not in observed
        or any(observed[identifier][k] != event[k] for k in ("route", "status"))
        for identifier, event in completed.items()
    ) or any(
        identifier not in completed and row["status"] not in {401, 429, 503}
        for identifier, row in observed.items()
    ):
        raise Rejected("cli_privacy_http_binding")
    return {
        "status": "pass",
        "release_ready": False,
        "independent_admission_observed": False,
        "snapshot_sha256": digest(canonical(snapshot)),
        "correlation": correlation,
        "public": public,
        "observed_responses": len(http),
    }


class Privacy:
    def __init__(self):
        self.needles, self.http, self.outputs = (), [], []
        self.bytes = 0
        self.metrics = None
        self.failed, self.fence_complete = False, False

    def configure(self, directory, config, token):
        self.token = token
        self.quotas = [secrets.token_hex(32), secrets.token_hex(32)]
        self.metrics_token = secrets.token_hex(32)
        clients = {
            "schema_version": 1,
            "clients": [
                {
                    "principal_id": secrets.token_hex(16),
                    "token": value,
                    "requests_per_second": rate,
                    "burst": burst,
                    "max_in_flight": 4,
                }
                for value, rate, burst in [(token, 20, 40), *((v, 1, 1) for v in self.quotas)]
            ],
        }
        principals, metrics = directory / "principals.json", directory / "metrics-token"
        write_json(principals, clients)
        metrics.write_text(self.metrics_token, encoding="ascii")
        metrics.chmod(0o600)
        config.pop("token_file")
        config.update(principals_file=str(principals), metrics_token_file=str(metrics))

    def observe(self, path, status, headers, content):
        if self.failed:
            raise Rejected("cli_privacy_observation_failed")
        # A swallowed observation error must not leave a publishable partial window.
        self.failed = True
        wire = canonical(headers) + content
        self.bytes += len(wire)
        if self.bytes > MAX_BYTES:
            raise Rejected("cli_privacy_output_limit")
        self.outputs.append(wire)
        route = path.split("?", 1)[0]
        if route in {"/livez", "/metrics"}:
            self.failed = False
            return
        value = decode(content, 65536)
        if type(value) is not dict:
            raise Rejected("cli_privacy_response_schema")
        self.http.append(
            {
                "exchange": len(self.http) + 1,
                "request_id": value.get("request_id"),
                "route": {"/v1/predict": "predict", "/readyz": "ready"}.get(route, "other"),
                "status": status,
            }
        )
        self.failed = False

    def exercise(self, request, body, expected):
        cases, response_needles, private_needles = serving_privacy_probe.inputs(body, self.token)
        self.needles = (
            *private_needles,
            *(v.encode() for v in self.quotas),
            self.metrics_token.encode(),
        )
        for path, payload, options, expected_status in cases:
            status, headers, content = request(path, payload, raw=True, **options)
            if status != expected_status:
                raise Rejected("cli_privacy_matrix_status")
            serving_privacy_probe.response_headers(headers, content, private_needles)
            value = decode(content)
            if any(
                needle in canonical(headers) + content + canonical(value)
                for needle in response_needles
            ):
                raise Rejected("cli_privacy_response_canary")
            serving_privacy_probe.response_contract(value, path, status)
        # Per-client burst boundaries do not rely on access to server internals.
        bad = {**body, "private": private_needles[0].decode()}
        start = time.monotonic()
        for credential in self.quotas:
            first, _ = request("/v1/predict", bad, credential=credential)
            second, reply = request("/v1/predict", bad, credential=credential)
            if first != 422 or second != 429 or reply.get("error") != {"code": "client_limited"}:
                raise Rejected("cli_privacy_client_quota")
        if time.monotonic() - start >= 1:
            raise Rejected("cli_privacy_quota_observation_window")
        time.sleep(1.05)
        for credential in self.quotas:
            status, reply = request("/v1/predict", body, credential=credential)
            if status != 200 or reply.get("model_sha256") != expected["model"]:
                raise Rejected("cli_privacy_client_refill")
        request.metrics_credential = self.metrics_token
        self.metrics = serving_metrics_probe.scan(request, self.needles)

    def fenced(self, request, body):
        for path, payload, code in (
            ("/v1/predict", {**body, "private": self.needles[0].decode()}, "model_unavailable"),
            ("/readyz", None, "not_ready"),
        ):
            status, headers, content = request(
                path, payload, raw=True, headers={"X-Request-ID": self.needles[0].decode()}
            )
            reply = decode(content)
            if (
                status != 503
                or set(reply) != {"schema_version", "request_id", "error"}
                or type(reply["schema_version"]) is not int
                or reply["schema_version"] != 1
                or type(reply["request_id"]) is not str
                or re.fullmatch("[a-f0-9]{32}", reply["request_id"]) is None
                or reply["error"] != {"code": code}
            ):
                raise Rejected("cli_privacy_fenced_response")
            serving_privacy_probe.response_headers(headers, content, self.needles)
        self.fence_complete = True

    def closed(self, directory, output, expected):
        if (
            self.failed
            or not self.fence_complete
            or output != b""
            or len(self.needles) != 9
            or self.metrics is None
        ):
            raise Rejected("cli_privacy_lifecycle_incomplete")
        if any(needle in content for content in self.outputs for needle in self.needles):
            raise Rejected("cli_privacy_output_canary")
        serving_privacy_probe.scan_owned_audit(directory, self.needles)
        manifest, chunks = audit_snapshot.capture_closed(directory)
        snapshot = {
            "manifest": signing.encode64(manifest),
            "segments": [signing.encode64(v) for v in chunks],
        }
        checked = verify_snapshot(snapshot, expected["audit_context"], self.http)
        if len(canonical(snapshot)) > MAX_BYTES:
            raise Rejected("cli_privacy_snapshot_limit")
        return {
            "schema_version": 1,
            "status": "pass",
            "release_ready": False,
            "scope": "ordinary-cli-privacy-not-full-M13",
            "canaries": 9,
            "matrix_requests": 12,
            "quota_requests": 6,
            "fenced_requests": 2,
            "cli_output_bytes": 0,
            "metrics": self.metrics,
            "snapshot": snapshot,
            "http": self.http,
            "audit": checked,
        }


def main(arguments=None):
    try:
        enforce()
        parser = Arguments(prog="cli-privacy")
        parser.add_argument("--config", type=Path, required=True)
        parser.add_argument("--request", type=Path, required=True)
        options = parser.parse_args(arguments)
        result = kube_serving_probe.qualify(
            read_json(options.config), read_json(options.request), privacy=Privacy()
        )
        print(canonical(result).decode())
        return 0
    except Exception as error:
        print(
            canonical(
                {
                    "status": "fail",
                    "release_ready": False,
                    "phase": "http",
                    "code": "kubernetes_privacy_rejected",
                    "location": location(error),
                }
            ).decode()
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
