import urllib.error
import urllib.request
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, now, read_json
from scripts.tracking_client import Client
from scripts.tracking_config import validate
from scripts.tracking_service import verify


def probe_https(state, spec):
    endpoint = f"https://127.0.0.1:{spec['port']}"
    client = Client(endpoint, state / "ca.crt")
    request = urllib.request.Request(endpoint + "/health", method="GET")
    try:
        with client.opener.open(request, timeout=3) as response:
            body = response.read(65)
            if response.status != 200 or len(body) > 64:
                raise Rejected("tracking_health_response_invalid")
    except urllib.error.HTTPError as error:
        error.close()
        raise Rejected("tracking_health_response_invalid") from error


def diagnose(state):
    result = {
        "schema_version": 1,
        "scope": "read-only-tracking-configuration-and-https-not-auth-or-database-health",
        "read_only": True,
        "release_ready": False,
        "checks": [],
        "runbook": "docs/operations/tracking-troubleshooting.md",
    }
    stage = "configuration"
    try:
        spec = read_json(state / "configuration.json")
        validate(state, spec)
        result["checks"].append({"check": stage, "status": "pass"})
        stage = "resources"
        observed = verify(state, spec)
        if not all(observed[role]["State"]["Running"] for role in ("pg", "server")):
            raise Rejected("tracking_service_stopped")
        result["checks"].append({"check": stage, "status": "pass"})
        stage = "https"
        probe_https(state, spec)
        result["checks"].append({"check": stage, "status": "pass"})
        result["status"] = "pass"
    except (Rejected, OSError, KeyError, TypeError, ValueError) as error:
        unavailable = isinstance(error, OSError) or (
            isinstance(error, Rejected)
            and (str(error).startswith("storage_") or str(error) == "artifact_unavailable")
        )
        result["status"] = "inconclusive" if unavailable else "fail"
        result["checks"].append({"check": stage, "status": result["status"]})
        result["reason"] = stage + ("_unavailable" if unavailable else "_invalid")
    result["completed_at"] = now()
    return result


def main():
    root = Path(__file__).resolve().parents[1]
    result = diagnose(root / ".runtime/tracking-service")
    print(canonical(result).decode())
    return {"pass": 0, "fail": 1, "inconclusive": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
