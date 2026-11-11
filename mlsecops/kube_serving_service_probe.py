"""Read-only synthetic HTTP checks inside the existing serving Pod, never a second server."""

import http.client
import time
from pathlib import Path

from mlsecops import kube_serving_probe
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, read_json
from mlsecops.controller_api import Client
from mlsecops.datasets import FEATURES
from mlsecops.process_privacy import enforce


def qualify(expected):
    enforce()
    config = read_json(Path("/config.json"))
    token = bounded_read(config["token_file"], 65).decode("ascii").strip()
    client = Client("serving")
    cases = []

    def check(name, success):
        if not success:
            raise Rejected("kube_serving_service_probe:" + name)
        cases.append(name)

    def request(path, body=None, authenticated=True):
        connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=12)
        try:
            connection.request(
                "POST" if body is not None else "GET",
                path,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    **({"Authorization": "Bearer " + token} if authenticated else {}),
                },
            )
            response = connection.getresponse()
            content = response.read(65537)
            return response.status, decode(content, 65536)
        finally:
            connection.close()

    check("existing-HTTP-process-live", request("/livez", authenticated=False)[0] == 200)
    body = canonical(
        {
            "schema_version": 1,
            "instances": [dict(zip(FEATURES, row, strict=True)) for row in expected["features"]],
        }
    )
    deadline = time.monotonic() + 20
    while True:
        ready = request("/readyz")
        if ready[0] == (200 if expected["ready"] else 503) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    replies = [request("/v1/predict", body) for _ in range(3)]
    maximum = None
    if expected["ready"]:
        check("ready-after-verified-load", ready[0] == 200 and ready[1]["ready"] is True)
        workers = client.request("pods")["items"]
        check("one-inference-worker", len(workers) == 1)
        check("three-successful-predictions", all(status == 200 for status, _ in replies))
        check(
            "exact-model-and-bundle",
            all(
                reply["model_sha256"] == expected["model"]
                and reply["bundle_sha256"] == expected["bundle"]
                for _, reply in replies
            ),
        )
        maximum = max(
            abs(row["score"] - score)
            for _, reply in replies
            for row, score in zip(reply["predictions"], expected["scores"], strict=True)
        )
        check("ONNX-golden-parity", maximum <= 1e-6)
        check(
            "same-worker-after-requests",
            client.request("pods")["items"][0]["metadata"]["uid"] == workers[0]["metadata"]["uid"],
        )
        check("unauthenticated-401", request("/v1/predict", body, False)[0] == 401)
        check("malformed-422", request("/v1/predict", b"{}")[0] == 422)
        check("oversized-413", request("/v1/predict", b"x" * 65537)[0] == 413)
    else:
        check("unapproved-or-revoked-ready-503", ready[0] == 503)
        check("unapproved-or-revoked-predict-503", all(status == 503 for status, _ in replies))
        if expected.get("worker_absent", True):
            check("no-inference-worker", client.request("pods")["items"] == [])
        if "reader_refusal" in expected:
            check(
                "exact-reader-refusal",
                kube_serving_probe.diagnose(config) == "reader-" + expected["reader_refusal"],
            )
    return {
        "cases": cases,
        "max_golden_error": maximum,
        "existing_process": True,
        "release_ready": False,
    }
