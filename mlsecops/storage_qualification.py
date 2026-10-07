import argparse
import sys
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from psycopg import sql

from mlsecops import storage, storage_pki
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    digest,
    now,
    read_json,
    write_json,
)
from mlsecops.storage_bootstrap import admin, bootstrap, inspect, validate
from mlsecops.storage_schema import MAX_BYTES, TABLES


def expired_client(state, directory):
    authority = x509.load_pem_x509_certificate(bounded_read(state / "storage-pki/ca.crt", 4096))
    authority_key = serialization.load_pem_private_key(
        bounded_read(state / "storage-pki/ca.key", 4096), None
    )
    key, original = storage_pki.issue("ml_ingestor", authority_key, authority)
    builder = (
        x509.CertificateBuilder()
        .subject_name(original.subject)
        .issuer_name(original.issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=2))
        .not_valid_after(datetime.now(UTC) - timedelta(days=1))
    )
    for extension in original.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    storage_pki.write_pair(directory, "expired", key, builder.sign(authority_key, hashes.SHA256()))


def qualify(state):
    state = Path(state).resolve()
    marker = validate(state)
    cases = []

    def confirmed(identifier, condition):
        if not condition:
            raise Rejected(f"storage_qualification_failed:{identifier}")
        cases.append({"id": identifier, "status": "pass", "expected": True, "actual": True})

    def statement(identifier, connection, query, parameters=None, expected=None):
        try:
            with connection.transaction(force_rollback=True):
                connection.execute(query, parameters)
        except psycopg.Error as error:
            if error.sqlstate != expected or expected is None:
                raise Rejected(
                    f"storage_qualification_unexpected_sqlstate:{identifier}:{error.sqlstate}"
                ) from None
            cases.append(
                {"id": identifier, "status": "pass", "expected": expected, "actual": error.sqlstate}
            )
        else:
            if expected is not None:
                raise Rejected(f"storage_qualification_permission_bypass:{identifier}")
            confirmed(identifier, True)

    def denied_connection(identifier, parameters, expected):
        try:
            with psycopg.connect(**parameters) as connection:
                connection.execute("SELECT 1;")
        except psycopg.Error as error:
            if not any(text in str(error).lower() for text in expected):
                raise Rejected(
                    f"storage_qualification_wrong_connection_failure:{identifier}"
                ) from None
            cases.append(
                {"id": identifier, "status": "pass", "expected": "reject", "actual": "reject"}
            )
        else:
            raise Rejected(f"storage_qualification_authentication_bypass:{identifier}")

    clients = state / "storage-clients"
    before = read_json(state / "storage-pki/identity.json")
    repeated = bootstrap(state, marker["port"])
    confirmed("bootstrap-preserves-container", repeated["container_id"] == marker["container_id"])
    confirmed(
        "bootstrap-preserves-certificates", before == read_json(state / "storage-pki/identity.json")
    )
    observed = inspect("container", marker["name"])
    confirmed(
        "actual-loopback-port",
        observed["NetworkSettings"]["Ports"]
        == {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(marker["port"])}]},
    )
    fixture_id = uuid.uuid4().hex
    fixtures = {
        table: canonical(
            {"scope": "storage-component-qualification", "run": fixture_id, "table": table}
        )
        for table in TABLES
    }
    created = []
    try:
        for table, (writer, _) in TABLES.items():
            identifier = storage.put(clients / writer, table, fixtures[table])
            created.append((table, identifier))
            confirmed(
                f"{table}:writer-roundtrip-idempotent",
                storage.put(clients / writer, table, fixtures[table]) == identifier
                and storage.get(clients / writer, table, identifier) == fixtures[table],
            )
        for role in storage_pki.ROLES:
            with storage.connect(clients / role) as connection:
                connection.autocommit = True
                observed = connection.execute(
                    "SELECT current_user, ssl, version, bits FROM pg_stat_ssl WHERE pid = pg_backend_pid();"
                ).fetchone()
                confirmed(f"{role}:tls-identity", observed == (f"ml_{role}", True, "TLSv1.3", 256))
                for table, (writer, readers) in TABLES.items():
                    name, content = storage.table_name(table), fixtures[table]
                    identifier = digest(content)
                    can_read, can_write = role in (writer, *readers), role == writer
                    query = sql.SQL("SELECT payload FROM {} WHERE sha256 = %s").format(name)
                    if can_read:
                        confirmed(
                            f"{role}:{table}:read",
                            connection.execute(query, (identifier,)).fetchone() == (content,),
                        )
                    else:
                        statement(
                            f"{role}:{table}:read-denied", connection, query, (identifier,), "42501"
                        )
                    statement(
                        f"{role}:{table}:insert-{'allowed' if can_write else 'denied'}",
                        connection,
                        sql.SQL(
                            "INSERT INTO {} (sha256, payload) VALUES (%s, %s) ON CONFLICT DO NOTHING"
                        ).format(name),
                        (identifier, content),
                        None if can_write else "42501",
                    )
                    for operation, query, parameters in (
                        (
                            "update",
                            sql.SQL("UPDATE {} SET payload = payload WHERE sha256 = %s").format(
                                name
                            ),
                            (identifier,),
                        ),
                        (
                            "delete",
                            sql.SQL("DELETE FROM {} WHERE sha256 = %s").format(name),
                            (identifier,),
                        ),
                        ("truncate", sql.SQL("TRUNCATE {}").format(name), None),
                    ):
                        statement(
                            f"{role}:{table}:{operation}-denied",
                            connection,
                            query,
                            parameters,
                            "42501",
                        )
                for operation, query in (
                    ("owner-impersonation", "SET ROLE ml_owner;"),
                    ("admin-impersonation", "SET ROLE postgres;"),
                    ("create-schema", "CREATE SCHEMA forbidden_probe;"),
                    ("create-temp-table", "CREATE TEMP TABLE forbidden_probe (value integer);"),
                    ("create-role", "CREATE ROLE forbidden_probe;"),
                    ("grant-owner", f"GRANT ml_owner TO ml_{role};"),
                    ("read-server-file", "SELECT pg_read_file('/etc/passwd');"),
                    ("server-command", "COPY (SELECT 1) TO PROGRAM 'true';"),
                ):
                    statement(f"{role}:{operation}-denied", connection, query, expected="42501")
                attributes = connection.execute(
                    "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolconnlimit FROM pg_roles WHERE rolname = current_user;"
                ).fetchone()
                confirmed(
                    f"{role}:bounded-unprivileged-role",
                    attributes == (False, False, False, False, False, 4),
                )
        with storage.connect(clients / "ingestor") as connection:
            connection.autocommit = True
            for identifier, checksum, payload in (
                ("wrong-content-hash", "0" * 64, b"content"),
                ("empty-object", digest(b""), b""),
                ("invalid-object-id", "../bad", b"content"),
                ("oversized-object", digest(b"a" * (MAX_BYTES + 1)), b"a" * (MAX_BYTES + 1)),
            ):
                statement(
                    identifier,
                    connection,
                    "INSERT INTO ml.quarantine (sha256, payload) VALUES (%s, %s);",
                    (checksum, payload),
                    "23514",
                )
            statement(
                "server-owned-timestamp",
                connection,
                "INSERT INTO ml.quarantine (sha256, payload, created_at) VALUES (%s, %s, clock_timestamp());",
                (digest(b"stamp"), b"stamp"),
                "42501",
            )
        parameters = storage.connection_parameters(clients / "ingestor")
        with tempfile.TemporaryDirectory(
            prefix="storage-tls-", dir=state / "evidence"
        ) as temporary:
            directory = Path(temporary)
            authority_key, authority = storage_pki.issue("ca")
            storage_pki.write_pair(directory, "foreign-ca", authority_key, authority)
            storage_pki.write_pair(
                directory,
                "foreign-client",
                *storage_pki.issue("ml_ingestor", authority_key, authority),
            )
            expired_client(state, directory)
            invalid = (
                ("plaintext", {"sslmode": "disable"}, ("no encryption",)),
                ("wrong-hostname", {"host": "wrong.invalid"}, ("does not match host name",)),
                ("wrong-role", {"user": "ml_curator"}, ("certificate authentication failed",)),
                (
                    "no-client-certificate",
                    {"sslcert": "", "sslkey": ""},
                    ("requires a valid client certificate",),
                ),
                (
                    "wrong-server-ca",
                    {"sslrootcert": str(directory / "foreign-ca.crt")},
                    ("certificate verify failed",),
                ),
                (
                    "foreign-client-ca",
                    {
                        "sslcert": str(directory / "foreign-client.crt"),
                        "sslkey": str(directory / "foreign-client.key"),
                    },
                    ("unknown ca", "certificate verify failed"),
                ),
                (
                    "expired-client",
                    {
                        "sslcert": str(directory / "expired.crt"),
                        "sslkey": str(directory / "expired.key"),
                    },
                    ("certificate expired",),
                ),
                ("admin-over-tcp", {"user": "postgres"}, ("pg_hba.conf rejects",)),
                ("other-database", {"dbname": "postgres"}, ("pg_hba.conf rejects",)),
            )
            for identifier, changes, expected in invalid:
                denied_connection(identifier, parameters | changes, expected)
            with storage.connect(clients / "ingestor") as connection:
                confirmed(
                    "positive-control-after-auth-denials",
                    connection.execute("SELECT 1;").fetchone() == (1,),
                )
        for table, (writer, _) in TABLES.items():
            confirmed(
                f"{table}:bytes-unchanged-after-denials",
                storage.get(clients / writer, table, digest(fixtures[table])) == fixtures[table],
            )
    finally:
        for table, identifier in created:
            content = fixtures[table]
            if identifier != digest(content):
                raise Rejected("storage_fixture_cleanup_identity_mismatch")
            admin(
                marker["name"],
                f"DELETE FROM ml.{table} WHERE sha256 = '{identifier}' AND payload = decode('{content.hex()}', 'hex');",
            )
    confirmed(
        "qualification-fixtures-removed",
        all(
            admin(marker["name"], f"SELECT count(*) FROM ml.{table} WHERE sha256 = '{identifier}';")
            == "0"
            for table, identifier in created
        ),
    )
    return {
        "schema_version": 1,
        "observed_at": now(),
        "profile": "local-cpu",
        "scope": "storage-component",
        "status": "pass",
        "cases": cases,
        "checks": len(cases),
        "inputs": {
            "image": marker["image"],
            "migration": repeated["migration"],
            "config_digest": marker["config_digest"],
        },
        "limitations": [
            "Not full M03/M04: training/evaluation still use host filesystem",
            "Local CA and Docker/host administrator remain trusted",
            "DB outbound traffic is not denied; untrusted workers receive no DB credentials",
            "Append-only runtime roles are not WORM storage or an administrator boundary",
            "Restore, container vulnerability scan, SQL storage quota and availability under abuse remain pending",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    arguments = parser.parse_args()
    destination = arguments.state / "evidence/storage-qualification.json"
    try:
        result = qualify(arguments.state)
        write_json(destination, result)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        write_json(
            destination,
            {
                "status": "fail",
                "scope": "storage-component",
                "observed_at": now(),
                "reason": str(error),
            },
        )
        print(f"Storage qualification rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
