import os
import re
from pathlib import Path

import psycopg
from psycopg import sql

from mlsecops.contracts import Rejected, bounded_read, digest, read_json, require_fields, safe_child
from mlsecops.storage_pki import ROLES
from mlsecops.storage_schema import DATABASE, MAX_BYTES, TABLES


def connection_parameters(directory):
    directory = Path(directory)
    if directory.is_symlink():
        raise Rejected("storage_client_symlink")
    directory = directory.resolve()
    settings = read_json(safe_child(directory, "connection.json"))
    require_fields(settings, ("schema_version", "role", "host", "port", "certificates"))
    require_fields(settings["certificates"], ("ca.crt", "client.crt"))
    if (
        type(settings.get("schema_version")) is not int
        or settings["schema_version"] != 1
        or settings.get("role") not in ROLES
        or settings.get("host") != "127.0.0.1"
        or type(settings.get("port")) is not int
        or not 1024 <= settings["port"] <= 65535
    ):
        raise Rejected("storage_client_config_invalid")
    for filename, expected in settings["certificates"].items():
        if digest(bounded_read(safe_child(directory, filename), 4096)) != expected:
            raise Rejected("storage_client_certificate_changed")
    key = safe_child(directory, "client.key")
    bounded_read(key, 4096)
    return {
        "dbname": DATABASE,
        "host": settings["host"],
        "hostaddr": settings["host"],
        "port": settings["port"],
        "user": f"ml_{settings['role']}",
        "sslmode": "verify-full",
        "sslrootcert": str(directory / "ca.crt"),
        "sslcert": str(directory / "client.crt"),
        "sslkey": str(key),
        "ssl_min_protocol_version": "TLSv1.3",
        "ssl_max_protocol_version": "TLSv1.3",
        "gssencmode": "disable",
        "connect_timeout": 5,
        "password": "",
        "passfile": os.devnull,
        "application_name": f"trusted-mlsecops-{settings['role']}",
        "options": "-c search_path=pg_catalog -c statement_timeout=5000 -c lock_timeout=2000",
    }


def object_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise Rejected("storage_object_id_invalid")
    return value


def table_name(name):
    if not isinstance(name, str) or name not in TABLES:
        raise Rejected("storage_table_invalid")
    return sql.Identifier("ml", name)


def connect(directory):
    try:
        return psycopg.connect(**connection_parameters(directory))
    except psycopg.Error as error:
        raise Rejected("storage_connection_rejected") from error


def put(directory, table, content):
    if not isinstance(content, bytes) or not 1 <= len(content) <= MAX_BYTES:
        raise Rejected("storage_object_size_invalid")
    identifier = digest(content)
    name = table_name(table)
    try:
        with connect(directory) as connection:
            connection.execute(
                sql.SQL(
                    "INSERT INTO {} (sha256, payload) VALUES (%s, %s) ON CONFLICT DO NOTHING"
                ).format(name),
                (identifier, content),
            )
            observed = connection.execute(
                sql.SQL("SELECT payload FROM {} WHERE sha256 = %s").format(name), (identifier,)
            ).fetchone()
            if observed is None or bytes(observed[0]) != content:
                raise Rejected("storage_write_verification_failed")
    except psycopg.Error as error:
        raise Rejected(f"storage_write_rejected:{error.sqlstate or 'unavailable'}") from error
    return identifier


def get(directory, table, identifier):
    identifier = object_id(identifier)
    name = table_name(table)
    try:
        with connect(directory) as connection:
            observed = connection.execute(
                sql.SQL("SELECT payload FROM {} WHERE sha256 = %s").format(name), (identifier,)
            ).fetchone()
    except psycopg.Error as error:
        raise Rejected(f"storage_read_rejected:{error.sqlstate or 'unavailable'}") from error
    if observed is None:
        raise Rejected("storage_object_missing")
    content = bytes(observed[0])
    if not 1 <= len(content) <= MAX_BYTES or digest(content) != identifier:
        raise Rejected("storage_object_integrity_failed")
    return content
