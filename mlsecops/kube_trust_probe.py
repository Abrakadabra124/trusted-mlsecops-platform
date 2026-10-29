"""Real SQL/TLS reader probe. Output contains only finite case names and versions."""

import socket
import sys
from pathlib import Path

import psycopg

from mlsecops import storage, trust, trust_authority
from mlsecops.contracts import Rejected, canonical
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce as enforce_privacy
from mlsecops.storage_pki import TRUST_HOST


def probe(role, public, policy, version, revoked, *, unavailable=False):
    client = Path("/client")
    parameters = storage.connection_parameters(client)
    if parameters["user"] != f"ml_{role}" or parameters["host"] != TRUST_HOST:
        raise Rejected("trust_probe_identity")
    if unavailable:
        try:
            trust_authority.read(client, "local-cpu", public)
        except trust.Unavailable:
            return {
                "status": "pass",
                "role": role,
                "cases": ["authority-outage-unavailable"],
                "release_ready": False,
            }
        raise Rejected("trust_probe_outage_not_observed")
    envelope, clock = trust_authority.read(client, "local-cpu", public)
    payload = trust.validate(envelope, public, "local-cpu", clock)
    if (
        payload["version"] != version
        or payload["promotion_policy_sha256"] != policy
        or payload["revoked_artifacts"] != revoked
    ):
        raise Rejected("trust_probe_policy_mismatch")
    cases = ["signed-current-policy", "exact-version-and-revocations"]
    for location in (
        "/signer",
        "/api",
        "/source",
        "/app/.runtime",
        "/var/run/docker.sock",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
    ):
        if Path(location).exists():
            raise Rejected("trust_probe_forbidden_mount")
    cases.append("no-signer-api-host-or-source-mount")
    with storage.connect(client) as connection:
        if connection.execute(
            "SELECT ssl, version FROM pg_stat_ssl WHERE pid=pg_backend_pid();"
        ).fetchone() != (True, "TLSv1.3"):
            raise Rejected("trust_probe_tls")
        cases.append("mutual-TLS-1.3")
        for label, statement in (
            ("no-policy-write", "UPDATE ml_trust.settings SET environment=environment WHERE false"),
            ("no-document-delete", "DELETE FROM ml_trust.documents WHERE false"),
            (
                "no-document-insert",
                "INSERT INTO ml_trust.documents SELECT * FROM ml_trust.documents WHERE false",
            ),
            ("no-cas-read", "SELECT payload FROM ml.releases LIMIT 1"),
            ("no-cas-write", "INSERT INTO ml.releases SELECT * FROM ml.releases WHERE false"),
            ("no-owner", "SET LOCAL ROLE ml_owner"),
            ("no-superuser", "SET LOCAL ROLE postgres"),
        ):
            try:
                with connection.transaction(force_rollback=True):
                    connection.execute(statement)
            except psycopg.Error as error:
                if error.sqlstate != "42501":
                    raise Rejected("trust_probe_wrong_sql_denial") from None
            else:
                raise Rejected("trust_probe_sql_bypass")
            cases.append(label)
    for label, changes, reason in (
        (
            "wrong-certificate-role",
            {"user": "ml_serving" if role == "promoter" else "ml_promoter"},
            "certificate authentication failed",
        ),
        (
            "wrong-server-hostname",
            {"host": "wrong.invalid", "hostaddr": socket.gethostbyname(TRUST_HOST)},
            "does not match host name",
        ),
        (
            "no-client-certificate",
            {"sslcert": "", "sslkey": ""},
            "requires a valid client certificate",
        ),
        ("no-plaintext", {"sslmode": "disable"}, "pg_hba.conf rejects connection"),
    ):
        try:
            with psycopg.connect(**{**parameters, **changes}):
                pass
        except psycopg.Error as error:
            if reason not in str(error).lower():
                raise Rejected("trust_probe_wrong_tls_denial") from None
        else:
            raise Rejected("trust_probe_tls_bypass")
        cases.append(label)
    if trust_authority.read(client, "local-cpu", public)[0] != envelope:
        raise Rejected("trust_probe_policy_changed")
    cases.append("policy-unchanged-after-negative-transactions")
    return {
        "status": "pass",
        "role": role,
        "version": version,
        "cases": cases,
        "release_ready": False,
    }


def main(arguments=None):
    try:
        enforce_privacy()
        parser = Arguments(prog="trust-probe")
        parser.add_argument("--role", choices=("promoter", "serving"), required=True)
        parser.add_argument("--root", required=True)
        parser.add_argument("--policy", required=True)
        parser.add_argument("--version", type=int, required=True)
        parser.add_argument("--revoked", action="append", default=[])
        parser.add_argument("--unavailable", action="store_true")
        options = parser.parse_args(arguments)
        print(
            canonical(
                probe(
                    options.role,
                    options.root,
                    options.policy,
                    options.version,
                    options.revoked,
                    unavailable=options.unavailable,
                )
            ).decode()
        )
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("trust_probe_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
