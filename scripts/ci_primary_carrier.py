"""Portable private frames for the retained shared and serving CAS directories.

Version 1: eight magic/version bytes, a big-endian uint32 index length, the
original index (including LF), then raw objects in ascending SHA-256 order.
The pinned index supplies every object length. Its logical filenames are never
used as filesystem paths.
The caller supplies the independent pin, protects the bytes in transit and
runs the role's ordinary replay after unpacking.
"""

from io import BytesIO
from pathlib import Path
from struct import Struct
from tempfile import TemporaryDirectory

from mlsecops import final_evidence as final
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    require_fields,
)
from mlsecops.storage import object_id
from scripts import ci_serving_retention as serving
from scripts import frozen_candidate_transfer as transfer
from scripts import m18_shared_retention as shared

MAGIC = b"MLSCAS\x00\x01"
HEADER = Struct(">8sI")


def _objects(raw, role, index_pin):
    """Authenticate and bound the physical inventory before reading any payload."""
    final.need(digest(raw) == object_id(index_pin), "carrier-index-pin")
    if role == "shared":
        retention = shared
        fields = (
            "freeze_pin",
            "freeze",
            "expected",
            "run_owner",
            "report_pins",
            "actual_pin",
            "native_pin",
        )
        max_objects = shared.MAX_FILES + 2
    elif role == "serving":
        retention = serving
        fields = ("authority", "serving_pin")
        max_objects = serving.MAX_OBJECTS
    else:
        raise Rejected("carrier-role")

    record = decode(raw, final.LIMIT)
    require_fields(
        record, ("schema_version", "scope", "classification", "files", "objects", *fields)
    )
    final.subset(
        record,
        dict(schema_version=1, scope=retention.SCOPE, classification=transfer.CLASSIFICATION),
        "carrier-index-type",
    )
    final.need(raw == canonical(record) + b"\n", "carrier-index-encoding")
    files, objects = record["files"], record["objects"]
    final.need(
        isinstance(files, dict) and 0 < len(files) <= retention.MAX_FILES, "carrier-file-count"
    )
    final.need(
        isinstance(objects, dict) and 0 < len(objects) <= max_objects, "carrier-object-count"
    )
    final.need(index_pin not in objects, "carrier-duplicate-index")
    for pin, size in objects.items():
        object_id(pin)
        final.need(type(size) is int and 0 < size <= retention.LIMIT, "carrier-object-size")
    final.need(all(object_id(pin) in objects for pin in files.values()), "carrier-file-reference")
    final.need(len(raw) + sum(objects.values()) <= retention.TOTAL, "carrier-total")
    return sorted(objects.items())


def pack(root, destination, *, role, index_pin) -> bytes:
    """Return a private frame from exactly the index and its named CAS objects."""
    source = serving.location(root, destination)
    raw = bounded_read(source / transfer.CAS / object_id(index_pin), final.LIMIT)
    objects = _objects(raw, role, index_pin)
    with BytesIO() as frame:
        frame.write(HEADER.pack(MAGIC, len(raw)))
        frame.write(raw)
        for pin, size in objects:
            content = final.blob(source, pin, size)
            final.need(len(content) == size, "carrier-object-length")
            frame.write(content)
        return frame.getvalue()


def unpack(root, destination, data, *, role, index_pin) -> None:
    """Restore into a new directory under an existing, trusted private parent."""
    target = serving.location(root, destination)
    final.need(target.parent.is_dir() and not target.exists(), "carrier-destination")
    final.need(
        type(data) is bytes
        and HEADER.size <= len(data) <= HEADER.size + max(shared.TOTAL, serving.TOTAL),
        "carrier-frame-size",
    )
    magic, index_size = HEADER.unpack_from(data)
    offset = HEADER.size + index_size
    final.need(
        magic == MAGIC and 0 < index_size <= final.LIMIT and offset <= len(data), "carrier-header"
    )
    raw = data[HEADER.size : offset]
    objects = _objects(raw, role, index_pin)
    final.need(len(data) == offset + sum(size for _, size in objects), "carrier-frame-length")

    view = memoryview(data)
    with TemporaryDirectory(prefix=".pc-", dir=target.parent) as temporary:
        staging = Path(temporary)
        cas = staging / transfer.CAS
        for pin, size in objects:
            content = view[offset : offset + size]
            final.need(digest(content) == pin, "carrier-object-digest")
            atomic_write(cas / pin, content)
            offset += size
        atomic_write(cas / index_pin, raw)
        # POSIX rename alone can replace a competing empty directory. Claim the
        # name exclusively, then publish the complete evidence tree in one rename.
        target.mkdir(mode=0o700)
        try:
            (staging / "evidence").rename(target / "evidence")
        except BaseException:
            target.rmdir()
            raise
