import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path


class Rejected(ValueError):
    pass


def canonical(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise Rejected("invalid_json_value") from error


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate_json_key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise Rejected("nonfinite_json")


def decode(content, limit=16 * 1024 * 1024):
    if len(content) > limit:
        raise Rejected("document_too_large")
    try:
        return json.loads(content, object_pairs_hook=_unique, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Rejected("invalid_json") from error


def digest(content):
    return hashlib.sha256(content).hexdigest()


def now():
    return datetime.now(UTC).isoformat()


def bounded_read(path, limit=16 * 1024 * 1024):
    path = Path(path)
    if path.is_symlink():
        raise Rejected("symlink_rejected")
    try:
        with path.open("rb") as source:
            content = source.read(limit + 1)
    except OSError as error:
        raise Rejected("artifact_unavailable") from error
    if len(content) > limit:
        raise Rejected("artifact_too_large")
    return content


def read_json(path):
    return decode(bounded_read(path))


def atomic_write(path, content, mode=0o600):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise Rejected("symlink_rejected")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    atomic_write(path, canonical(value) + b"\n")


def require_fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise Rejected("unexpected_fields")


def safe_child(root, name):
    if Path(root).is_symlink():
        raise Rejected("symlink_rejected")
    root = Path(root).resolve()
    if not isinstance(name, str) or not name or "\\" in name:
        raise Rejected("invalid_artifact_path")
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts or ":" in name:
        raise Rejected("invalid_artifact_path")
    candidate = root / relative
    if not candidate.resolve().is_relative_to(root):
        raise Rejected("artifact_path_escape")
    current = candidate
    while current != root:
        if current.is_symlink():
            raise Rejected("symlink_rejected")
        current = current.parent
    return candidate
