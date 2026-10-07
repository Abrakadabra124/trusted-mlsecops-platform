from mlsecops.storage_pki import ROLES

DATABASE = "mlsecops"
OWNER = "ml_owner"
SCHEMA_VERSION = 1
TABLES = {
    "quarantine": ("ingestor", ("curator",)),
    "train": ("curator", ("publisher",)),
    "validation": ("curator", ("publisher",)),
    "holdout": ("curator", ("scorer",)),
    "manifests": ("curator", ("publisher", "scorer")),
    "lineage": ("curator", ("publisher", "scorer")),
    "candidates": ("publisher", ("scorer", "promoter")),
    "evaluations": ("scorer", ("promoter",)),
    "releases": ("promoter", ("serving",)),
}
MAX_BYTES = 50 * 1024 * 1024


def roles_sql():
    statements = []
    for name, login in [(OWNER, "NOLOGIN"), *((f"ml_{role}", "LOGIN") for role in ROLES)]:
        statements.append(
            f"""DO $roles$ BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{name}') THEN
                CREATE ROLE {name} {login} NOSUPERUSER NOCREATEDB NOCREATEROLE
                    NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4;
            END IF;
            END $roles$;"""
        )
    return "\n".join(statements)


def migration_sql():
    statements = [
        "REVOKE ALL ON DATABASE mlsecops FROM PUBLIC;",
        "REVOKE ALL ON SCHEMA public FROM PUBLIC;",
        f"SET LOCAL ROLE {OWNER};",
        "CREATE SCHEMA ml;",
        "REVOKE ALL ON SCHEMA ml FROM PUBLIC;",
        "CREATE TABLE ml.schema_migrations (version integer PRIMARY KEY, sha256 text NOT NULL);",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA ml REVOKE ALL ON TABLES FROM PUBLIC;",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA ml REVOKE ALL ON FUNCTIONS FROM PUBLIC;",
    ]
    for role in ROLES:
        statements.extend(
            [
                f"GRANT CONNECT ON DATABASE {DATABASE} TO ml_{role};",
                f"GRANT USAGE ON SCHEMA ml TO ml_{role};",
            ]
        )
    for table, (writer, readers) in TABLES.items():
        statements.extend(
            [
                f"""CREATE TABLE ml.{table} (
                    sha256 text COLLATE "C" PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{{64}}$'),
                    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND {MAX_BYTES}),
                    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                    CHECK (encode(sha256(payload), 'hex') = sha256)
                );""",
                f"GRANT INSERT (sha256, payload) ON ml.{table} TO ml_{writer};",
                f"GRANT SELECT ON ml.{table} TO "
                + ", ".join(f"ml_{role}" for role in (writer, *readers))
                + ";",
            ]
        )
    return "\n".join(statements)
