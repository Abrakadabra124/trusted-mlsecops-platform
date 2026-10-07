import re
import subprocess
import threading
import time
from contextlib import contextmanager

from mlsecops.contracts import Rejected, decode
from mlsecops.storage_schema import DATABASE, TABLES

MAX_ARCHIVE = 256 * 1024 * 1024
MAX_ROWS = 10000


def ledger_sql():
    selections = []
    for table in TABLES:
        selections.append(
            f"""SELECT '{table}' AS name, jsonb_build_object(
                'rows', count(*), 'bytes', coalesce(sum(octet_length(payload)), 0),
                'sha256', encode(sha256(convert_to(coalesce(string_agg(
                    sha256 || ':' || octet_length(payload)::text || ':' || extract(epoch FROM created_at)::text,
                    E'\\n' ORDER BY sha256), ''), 'UTF8')), 'hex'),
                'invalid', count(*) FILTER (WHERE encode(sha256(payload), 'hex') <> sha256)
            ) AS detail FROM ml.{table}"""
        )
    return (
        "SELECT jsonb_object_agg(name, detail) FROM ("
        + " UNION ALL ".join(selections)
        + ") AS entries"
    )


def validate_ledger(value):
    if not isinstance(value, dict) or set(value) != set(TABLES):
        raise Rejected("backup_ledger_tables_invalid")
    for entry in value.values():
        if not isinstance(entry, dict) or set(entry) != {"rows", "bytes", "sha256", "invalid"}:
            raise Rejected("backup_ledger_fields_invalid")
        if (
            type(entry["rows"]) is not int
            or not 0 <= entry["rows"] <= MAX_ROWS
            or type(entry["bytes"]) is not int
            or not 0 <= entry["bytes"] <= MAX_ARCHIVE
            or type(entry["invalid"]) is not int
            or entry["invalid"] != 0
            or not isinstance(entry["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            or (entry["rows"] == 0) != (entry["bytes"] == 0)
        ):
            raise Rejected("backup_ledger_content_invalid")
    if (
        sum(entry["rows"] for entry in value.values()) > MAX_ROWS
        or sum(entry["bytes"] for entry in value.values()) > MAX_ARCHIVE
    ):
        raise Rejected("backup_database_limit")
    return value


@contextmanager
def json_session(arguments, query):
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    captured = []
    reader = threading.Thread(
        target=lambda: captured.append(process.stdout.readline(65537)), daemon=True
    )
    reader.start()
    try:
        process.stdin.write(query.encode())
        process.stdin.flush()
        reader.join(timeout=65)
        if reader.is_alive() or not captured or not captured[0] or len(captured[0]) > 65536:
            raise Rejected("backup_snapshot_unavailable")
        yield decode(captured[0], 65536), process
    finally:
        try:
            process.stdin.close()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            process.wait(timeout=5)
        reader.join(timeout=5)
        if not reader.is_alive():
            process.stdout.close()


@contextmanager
def snapshot(name):
    arguments = [
        "docker",
        "exec",
        "--user",
        "999:999",
        "-i",
        name,
        "psql",
        "-X",
        "-qAt",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        "/tmp",
        "-U",
        "postgres",
        "-d",
        DATABASE,
    ]
    query = (
        "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n"
        "SET LOCAL idle_in_transaction_session_timeout = '180s';\n"
        "SET LOCAL statement_timeout = '60s';\n"
        f"SELECT jsonb_build_object('snapshot', pg_export_snapshot(), 'tables', ({ledger_sql()}));\n"
    )
    with json_session(arguments, query) as (result, process):
        if (
            not isinstance(result, dict)
            or set(result) != {"snapshot", "tables"}
            or not isinstance(result["snapshot"], str)
            or not re.fullmatch(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9]+", result["snapshot"])
        ):
            raise Rejected("backup_snapshot_identity_invalid")
        validate_ledger(result["tables"])
        yield result


def binary_command(arguments, content=None, output_limit=MAX_ARCHIVE, timeout=120):
    process = subprocess.Popen(
        arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    captured = {}
    excessive = threading.Event()

    def read(name, stream, limit):
        value = stream.read(limit + 1)
        captured[name] = value
        if len(value) > limit:
            excessive.set()

    def write():
        try:
            if content:
                process.stdin.write(content)
            process.stdin.close()
        except (OSError, BrokenPipeError):
            pass

    threads = [
        threading.Thread(target=read, args=("stdout", process.stdout, output_limit), daemon=True),
        threading.Thread(target=read, args=("stderr", process.stderr, 65536), daemon=True),
        threading.Thread(target=write, daemon=True),
    ]
    for thread in threads:
        thread.start()
    started = time.monotonic()
    try:
        while process.poll() is None:
            if excessive.is_set() or time.monotonic() - started > timeout:
                raise Rejected("backup_process_limit_or_deadline")
            time.sleep(0.02)
        for thread in threads:
            thread.join(timeout=2)
        if excessive.is_set():
            raise Rejected("backup_process_limit_or_deadline")
        if any(thread.is_alive() for thread in threads):
            raise Rejected("backup_process_incomplete")
        if process.returncode or captured["stderr"]:
            raise Rejected("backup_process_failed_or_warned")
        return captured["stdout"]
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=2)
        if not any(thread.is_alive() for thread in threads):
            process.stdout.close()
            process.stderr.close()
