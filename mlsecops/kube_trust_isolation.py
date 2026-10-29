"""Read-only native SQL/TLS checks for two explicitly pinned test authorities."""

import psycopg

from mlsecops import storage
from mlsecops.contracts import Rejected, bounded_read, digest
from mlsecops.trust_targets import Target, select


def verify(target, check):
    target = select(target)
    other = Target.MODEL_REVOCATION if target is Target.PRIMARY else Target.PRIMARY
    parameters = storage.connection_parameters("/trust-client", expected_host=target.host)
    check("authority-client-role", parameters["user"], "ml_serving")
    check("authority-client-host", parameters["host"], target.host)
    with psycopg.connect(**parameters) as connection:
        check(
            "authority-mutual-TLS-1.3",
            connection.execute(
                "SELECT ssl, version FROM pg_stat_ssl WHERE pid=pg_backend_pid();"
            ).fetchone(),
            (True, "TLSv1.3"),
        )
        for name, statement in (
            ("no-policy-write", "UPDATE ml_trust.settings SET environment=environment WHERE false"),
            ("no-document-delete", "DELETE FROM ml_trust.documents WHERE false"),
            (
                "no-document-insert",
                "INSERT INTO ml_trust.documents SELECT * FROM ml_trust.documents WHERE false",
            ),
            ("no-owner", "SET LOCAL ROLE ml_owner"),
        ):
            try:
                with connection.transaction(force_rollback=True):
                    connection.execute(statement)
            except psycopg.Error as error:
                check("authority-" + name, error.sqlstate, "42501")
            else:
                raise Rejected("trust_isolation_sql_bypass")
    try:
        # Deliberate negative connection with the current CA/client certificate
        # against the other finite endpoint. Production never uses this route.
        with psycopg.connect(**{**parameters, "host": other.host}):
            pass
    except psycopg.Error as error:
        check("authority-cross-CA-denied", "certificate verify failed" in str(error).lower(), True)
    else:
        raise Rejected("trust_isolation_tls_bypass")
    return {
        "target": target.value,
        "host": target.host,
        "ca_sha256": digest(bounded_read(parameters["sslrootcert"], 4096)),
        "other_target": other.value,
        "cross_ca_denied": True,
    }
