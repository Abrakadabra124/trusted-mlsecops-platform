import argparse
import ipaddress
import socket
from pathlib import Path

import psycopg
from psycopg import sql

from mlsecops import storage
from mlsecops.contracts import Rejected, canonical, digest, read_json
from mlsecops.storage_pki import CLUSTER_HOST, ROLES
from mlsecops.storage_schema import TABLES


def network(address, port):
    target = ipaddress.ip_address(address)
    if not any(
        target in ipaddress.ip_network(cidr) for cidr in ("10.78.0.0/16", "10.79.0.0/16")
    ) or port not in (53, 5432):
        raise Rejected("storage_probe_target_outside_owned_lab")
    try:
        with socket.create_connection((address, port), timeout=3):
            return {"result": "connected"}
    except TimeoutError:
        return {"result": "timeout"}
    except OSError:
        return {"result": "other-error"}


def qualify(directory, role):
    cases = []

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"cluster_storage_probe_failed:{role}:{name}")
        cases.append({"id": f"{role}:{name}", "status": "pass"})

    def denied(parameters, name, reason):
        try:
            with psycopg.connect(**parameters) as connection:
                connection.execute("SELECT 1;")
        except psycopg.Error as error:
            confirmed(name, reason in str(error).lower())
        else:
            raise Rejected(f"cluster_storage_tls_bypass:{reason}")

    confirmed(
        "only-own-bundle",
        set(path.name for path in directory.iterdir())
        == {"ca.crt", "client.crt", "client.key", "connection.json"},
    )
    confirmed("role-binding", read_json(directory / "connection.json")["role"] == role)
    for location in (
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/docker.sock",
        "/app/.runtime",
        "/etc/kubernetes/admin.conf",
        "/source",
    ):
        confirmed(f"absent:{location}", not Path(location).exists())
    with storage.connect(directory) as connection:
        confirmed(
            "authenticated-role",
            connection.execute("SELECT current_user;").fetchone() == (f"ml_{role}",),
        )
        confirmed(
            "tls-1.3",
            connection.execute(
                "SELECT ssl, version FROM pg_stat_ssl WHERE pid=pg_backend_pid();"
            ).fetchone()
            == (True, "TLSv1.3"),
        )

        def statement(name, query, parameters=None, allowed=False):
            try:
                with connection.transaction(force_rollback=True):
                    connection.execute(query, parameters)
            except psycopg.Error as error:
                confirmed(name, not allowed and error.sqlstate == "42501")
            else:
                confirmed(name, allowed)

        for table, (writer, readers) in TABLES.items():
            identifier = sql.Identifier("ml", table)
            payload = canonical(
                {"kind": "transaction-rollback-probe", "role": role, "table": table}
            )
            statement(
                f"read-{table}",
                sql.SQL("SELECT payload FROM {} LIMIT 1").format(identifier),
                allowed=role in (writer, *readers),
            )
            statement(
                f"insert-{table}",
                sql.SQL("INSERT INTO {} (sha256,payload) VALUES (%s,%s)").format(identifier),
                (digest(payload), payload),
                allowed=role == writer,
            )
            for operation, query in (
                ("update", "UPDATE {} SET sha256=sha256 WHERE false"),
                ("delete", "DELETE FROM {} WHERE false"),
                ("truncate", "TRUNCATE {}"),
            ):
                statement(f"{operation}-{table}", sql.SQL(query).format(identifier))
        for name, query in (
            ("no-owner", "SET LOCAL ROLE ml_owner"),
            ("no-superuser", "SET LOCAL ROLE postgres"),
            ("no-ddl", "CREATE TABLE ml.forbidden_probe (identifier integer)"),
            ("no-temp", "CREATE TEMP TABLE forbidden_probe (identifier integer)"),
        ):
            statement(name, query)
    parameters = storage.connection_parameters(directory)
    other = next(value for value in ROLES if value != role)
    denied(
        {**parameters, "user": f"ml_{other}"},
        "certificate-role-mismatch",
        "certificate authentication failed",
    )
    denied(
        {**parameters, "host": "wrong.invalid", "hostaddr": socket.gethostbyname(CLUSTER_HOST)},
        "server-hostname-mismatch",
        "does not match host name",
    )
    denied(
        {**parameters, "sslcert": "", "sslkey": ""},
        "missing-client-certificate",
        "requires a valid client certificate",
    )
    denied({**parameters, "sslmode": "disable"}, "plaintext", "pg_hba.conf rejects connection")
    denied({**parameters, "user": "postgres"}, "superuser-tcp", "pg_hba.conf rejects connection")
    return {"status": "pass", "role": role, "cases": cases, "count": len(cases)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["sql", "network"])
    parser.add_argument("--role", choices=ROLES)
    parser.add_argument("--address")
    parser.add_argument("--port", type=int, default=5432)
    arguments = parser.parse_args()
    result = (
        qualify(Path("/client"), arguments.role)
        if arguments.action == "sql"
        else network(arguments.address, arguments.port)
    )
    print(canonical(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
