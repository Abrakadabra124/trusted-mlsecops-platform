import argparse
import tempfile
from pathlib import Path

from mlsecops.contracts import Rejected, atomic_write, canonical
from mlsecops.controller_api import APIError, Client


def probe(role):
    client = Client(role)
    observed = client.request("pods")
    if observed.get("kind") != "PodList" or not isinstance(observed.get("items"), list):
        raise Rejected("controller_api_positive_control_invalid")
    checks = ["real-api-authorized"]
    with tempfile.TemporaryDirectory(dir="/tmp") as directory:
        directory = Path(directory)
        for name in ("ca.crt", "token"):
            with (Path("/api") / name).open("rb") as source:
                atomic_write(directory / name, source.read(16385))
        with (Path("/client") / "ca.crt").open("rb") as source:
            atomic_write(directory / "ca.crt", source.read(16385))
        try:
            Client(role, directory).request("pods")
        except Rejected as error:
            if str(error) != "controller_api_tls_failure":
                raise Rejected("controller_api_wrong_tls_rejection") from error
        else:
            raise Rejected("controller_api_untrusted_ca_accepted")
        checks.append("real-api-wrong-ca-rejected")
        with (Path("/api") / "ca.crt").open("rb") as source:
            atomic_write(directory / "ca.crt", source.read(16385))
        atomic_write(directory / "token", b"a.b.c")
        try:
            Client(role, directory).request("pods")
        except APIError as error:
            if error.status != 401 or error.reason != "Unauthorized":
                raise Rejected("controller_api_wrong_token_rejection") from error
        else:
            raise Rejected("controller_api_invalid_token_accepted")
        checks.append("real-api-invalid-token-rejected")
    if client.request("pods").get("kind") != "PodList":
        raise Rejected("controller_api_positive_control_lost")
    checks.append("real-api-positive-control-after-negatives")
    return {"role": role, "status": "pass", "checks": checks}


def main():
    parser = argparse.ArgumentParser(description="Real controller HTTPS and authentication probes")
    parser.add_argument("--role", choices=("publisher", "scorer"), required=True)
    arguments = parser.parse_args()
    print(canonical(probe(arguments.role)).decode())


if __name__ == "__main__":
    main()
