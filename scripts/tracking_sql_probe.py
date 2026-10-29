import json
import socket

import psycopg


def qualify():
    cases = []
    for role in ("tracking_metadata", "tracking_auth"):
        connection = {
            "host": "tracking-pg",
            "port": 5432,
            "user": role,
            "dbname": role,
            "sslmode": "verify-full",
            "sslrootcert": "/config/ca.crt",
            "sslcert": f"/config/{role}.crt",
            "sslkey": f"/config/{role}.key",
            "connect_timeout": 3,
        }
        with psycopg.connect(**connection) as database:
            observed = database.execute(
                "SELECT current_user, current_database(), version FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
            ).fetchone()
            if observed != (role, role, "TLSv1.3"):
                raise AssertionError("role_database_or_tls_changed")
            flags = database.execute(
                "SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication FROM pg_roles WHERE rolname=current_user"
            ).fetchone()
            if flags != (False, False, False, False) or any(
                type(flag) is not bool for flag in flags
            ):
                raise AssertionError("database_role_escalated")
        cases.extend([role + "-tls-positive", role + "-least-privilege"])
        foreign = "tracking_auth" if role == "tracking_metadata" else "tracking_metadata"
        for name, change in (
            ("cross-database", {"dbname": foreign}),
            ("cross-identity", {"user": foreign, "dbname": foreign}),
            ("plaintext", {"sslmode": "disable"}),
            ("missing-client-cert", {"sslcert": "", "sslkey": ""}),
            ("untrusted-ca", {"sslrootcert": "/config/server.crt"}),
            (
                "wrong-hostname",
                {"host": "wrong.invalid", "hostaddr": socket.gethostbyname("tracking-pg")},
            ),
        ):
            try:
                with psycopg.connect(**{**connection, **change}):
                    pass
            except psycopg.OperationalError:
                with psycopg.connect(**connection) as control:
                    if control.execute("SELECT 1").fetchone() != (1,):
                        raise AssertionError("database_positive_control_failed")
                cases.append(role + "-" + name + "-denied")
            else:
                raise AssertionError("database_boundary_bypass:" + name)
    return {
        "status": "pass",
        "scope": "tracking-postgresql-native-boundary",
        "cases": cases,
        "checks": len(cases),
    }


if __name__ == "__main__":
    try:
        print(json.dumps(qualify()))
    except Exception as error:
        print(json.dumps({"status": "fail", "reason": type(error).__name__}))
        raise SystemExit(1) from None
