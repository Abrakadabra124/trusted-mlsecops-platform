import hashlib
import os
import re
import stat
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, decode, require_fields

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORD = 2048
MAX_MANIFEST = 65536


@dataclass(frozen=True)
class Policy:
    segment_bytes: int = 1024 * 1024
    max_segments: int = 16
    rotate_seconds: int = 60
    retain_seconds: int = 300

    def validate(self, budget):
        bounds = (
            (budget, MAX_RECORD, MAX_BYTES),
            (self.segment_bytes, MAX_RECORD, budget),
            (self.max_segments, 1, 64),
            (self.rotate_seconds, 1, 3600),
            (self.retain_seconds, 1, 86400),
        )
        if any(
            type(value) is not int or not lower <= value <= upper for value, lower, upper in bounds
        ):
            raise Rejected("audit_retention_policy")
        return self


def boot_id():
    with open("/proc/sys/kernel/random/boot_id", "rb") as source:
        value = source.read(38).strip().decode("ascii")
    if re.fullmatch("[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}", value) is None:
        raise Rejected("audit_retention_clock")
    return value


def sequences(content):
    offset = 0
    first = previous = None
    while offset < len(content):
        boundary = content.find(b"\n", offset)
        if boundary < 0 or boundary - offset + 1 > MAX_RECORD:
            raise Rejected("audit_spool_record")
        line = content[offset : boundary + 1]
        record = decode(line)
        require_fields(record, ("schema_version", "sequence", "recorded_at_ns", "event"))
        if (
            canonical(record) + b"\n" != line
            or type(record["schema_version"]) is not int
            or record["schema_version"] != 1
            or type(record["sequence"]) is not int
            or not 0 < record["sequence"] < 2**63
            or type(record["recorded_at_ns"]) is not int
            or not 0 <= record["recorded_at_ns"] < 2**63
            or type(record["event"]) is not dict
            or previous is not None
            and record["sequence"] != previous + 1
        ):
            raise Rejected("audit_spool_sequence")
        if first is None:
            first = record["sequence"]
        previous = record["sequence"]
        offset = boundary + 1
    if first is None:
        raise Rejected("audit_spool_record")
    return first, previous


class Clock:
    def __init__(self, anchor=None):
        self.boot = boot_id()
        self.anchor = anchor
        self.previous = None
        self.sample()

    def sample(self):
        current = {"boot": self.boot, "wall": time.time_ns(), "mono": time.monotonic_ns()}
        anchor = current if self.anchor is None else self.anchor
        require_fields(anchor, ("boot", "wall", "mono"))
        if anchor["boot"] != self.boot or any(
            type(sample[key]) is not int or not 0 < sample[key] < 2**63
            for sample in (anchor, current)
            for key in ("wall", "mono")
        ):
            raise Rejected("audit_retention_clock")
        previous = anchor if self.previous is None else self.previous
        if (
            any(current[key] < previous[key] for key in ("wall", "mono"))
            or abs((current["wall"] - anchor["wall"]) - (current["mono"] - anchor["mono"]))
            > 1_000_000_000
        ):
            raise Rejected("audit_retention_clock")
        self.anchor, self.previous = anchor.copy(), current
        return current.copy()


class Spool:
    def __init__(self, path, policy, budget):
        if type(policy) is not Policy:
            raise Rejected("audit_retention_policy")
        self.policy = policy.validate(budget)
        if os.name != "posix":
            raise Rejected("audit_retention_platform")
        self.budget = budget
        self.directory = self.descriptor = None
        self.active = None
        self.segments = []
        self.retained_bytes = self.sequence = self.next_index = 0
        self.manifest = None
        self.released = False
        try:
            path = Path(path)
            if not path.is_absolute():
                raise Rejected("audit_spool_path")
            self.directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._private(os.fstat(self.directory), directory=True)
            self.lease = self._new(".lease", os.urandom(32))
            names = self._names()
            if names == {".lease"}:
                self.clock = Clock()
            else:
                content, identity = self._read("manifest.json", MAX_MANIFEST)
                self.manifest = (content, identity)
                self._load(content)
                self._inventory()
        except BaseException:
            try:
                self.close(clean=False)
            except BaseException:
                pass
            raise Rejected("audit_spool_open") from None

    def _private(self, metadata, *, directory=False):
        valid_kind = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
        if (
            not valid_kind
            or metadata.st_mode & 0o077
            or metadata.st_uid != os.geteuid()
            or not directory
            and metadata.st_nlink != 1
        ):
            raise Rejected("audit_spool_identity")

    def _names(self):
        names = set()
        descriptor = os.open(".", os.O_RDONLY | os.O_DIRECTORY, dir_fd=self.directory)
        try:
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    names.add(entry.name)
                    if len(names) > self.policy.max_segments + 2:
                        raise Rejected("audit_spool_inventory")
        finally:
            os.close(descriptor)
        return names

    def _read(self, name, limit):
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.directory
        )
        try:
            metadata = os.fstat(descriptor)
            self._private(metadata)
            if not 0 <= metadata.st_size <= limit:
                raise Rejected("audit_spool_size")
            content = bytearray()
            while len(content) <= limit:
                chunk = os.read(descriptor, min(65536, limit + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            if len(content) != metadata.st_size:
                raise Rejected("audit_spool_size")
            return bytes(content), [metadata.st_dev, metadata.st_ino]
        finally:
            os.close(descriptor)

    def _new(self, name, content):
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.directory,
        )
        try:
            metadata = os.fstat(descriptor)
            self._private(metadata)
            self._write_all(descriptor, content)
            os.fsync(descriptor)
            os.fsync(self.directory)
            return content, [metadata.st_dev, metadata.st_ino]
        finally:
            os.close(descriptor)

    def _write_all(self, descriptor, content):
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if type(written) is not int or not 1 <= written <= len(content) - offset:
                raise Rejected("audit_spool_write")
            offset += written

    def _load(self, content):
        saved = decode(content, MAX_MANIFEST)
        require_fields(
            saved,
            ("schema_version", "policy", "budget", "clock", "sequence", "next_index", "segments"),
        )
        if (
            canonical(saved) != content
            or type(saved["budget"]) is not int
            or saved["budget"] != self.budget
            or type(saved["schema_version"]) is not int
            or saved["schema_version"] != 1
        ):
            raise Rejected("audit_spool_manifest")
        require_fields(saved["policy"], tuple(asdict(self.policy)))
        previous_policy = Policy(**saved["policy"]).validate(self.budget)
        if previous_policy != self.policy or any(
            type(saved[key]) is not int or not 0 <= saved[key] < 2**63
            for key in ("sequence", "next_index")
        ):
            raise Rejected("audit_spool_manifest")
        require_fields(saved["clock"], ("boot", "wall", "mono"))
        self.clock = Clock(saved["clock"])
        if type(saved["segments"]) is not list or len(saved["segments"]) > self.policy.max_segments:
            raise Rejected("audit_spool_manifest")
        self.sequence, self.next_index = saved["sequence"], saved["next_index"]
        previous_sequence = None
        for segment in saved["segments"]:
            require_fields(segment, ("name", "size", "first", "last", "sha256", "identity"))
            if (
                type(segment["name"]) is not str
                or re.fullmatch("[a-f0-9]{16}\\.jsonl", segment["name"]) is None
                or not 0 < int(segment["name"][:16], 16) <= self.next_index
                or type(segment["sha256"]) is not str
                or re.fullmatch("[a-f0-9]{64}", segment["sha256"]) is None
                or type(segment["size"]) is not int
                or not 0 < segment["size"] <= self.policy.segment_bytes
                or any(type(segment[key]) is not int for key in ("first", "last"))
                or not 0 < segment["first"] <= segment["last"] <= saved["clock"]["mono"]
                or type(segment["identity"]) is not list
                or len(segment["identity"]) != 2
                or any(type(value) is not int or value < 0 for value in segment["identity"])
                or any(other["name"] == segment["name"] for other in self.segments)
            ):
                raise Rejected("audit_spool_manifest")
            first_sequence, last_sequence = self._verify(segment)
            if previous_sequence is not None and first_sequence != previous_sequence + 1:
                raise Rejected("audit_spool_sequence")
            previous_sequence = last_sequence
            self.segments.append(segment)
            self.retained_bytes += segment["size"]
        if self.retained_bytes > self.budget:
            raise Rejected("audit_spool_capacity")
        if previous_sequence is not None and previous_sequence != self.sequence:
            raise Rejected("audit_spool_sequence")

    def _verify(self, segment):
        content, identity = self._read(segment["name"], self.policy.segment_bytes)
        if (
            identity != segment["identity"]
            or len(content) != segment["size"]
            or hashlib.sha256(content).hexdigest() != segment["sha256"]
        ):
            raise Rejected("audit_spool_identity")
        return sequences(content)

    def _inventory(self):
        expected = {".lease", *(segment["name"] for segment in self.segments)}
        if self.manifest is not None:
            expected.add("manifest.json")
        if self._names() != expected or self._read(".lease", 32) != self.lease:
            raise Rejected("audit_spool_inventory")
        if self.manifest is not None and self._read("manifest.json", MAX_MANIFEST) != self.manifest:
            raise Rejected("audit_spool_manifest")

    def _seal(self):
        descriptor, self.descriptor = self.descriptor, None
        if descriptor is not None:
            os.close(descriptor)
        self.active = None

    def maintain(self):
        if self.directory is None:
            raise Rejected("audit_spool_closed")
        now = self.clock.sample()["mono"]
        self._inventory()
        if (
            self.active is not None
            and now >= self.active["first"] + self.policy.rotate_seconds * 10**9
        ):
            self._seal()
        reclaimed = 0
        for segment in tuple(self.segments):
            if segment is self.active or now < segment["last"] + self.policy.retain_seconds * 10**9:
                continue
            self._verify(segment)
            os.unlink(segment["name"], dir_fd=self.directory)
            os.fsync(self.directory)
            self.segments.remove(segment)
            self.retained_bytes -= segment["size"]
            reclaimed += segment["size"]
        return reclaimed

    def write(self, content):
        if self.directory is None:
            raise Rejected("audit_spool_closed")
        if (
            type(content) is not bytes
            or not 0 < len(content) <= MAX_RECORD
            or not content.endswith(b"\n")
        ):
            raise Rejected("audit_spool_record")
        first_sequence, last_sequence = sequences(content)
        if (
            self.sequence >= 2**63 - 1
            or first_sequence != last_sequence
            or first_sequence != self.sequence + 1
        ):
            raise Rejected("audit_spool_sequence")
        now = self.clock.sample()["mono"]
        if self.retained_bytes + len(content) > self.budget:
            raise Rejected("audit_spool_capacity")
        if (
            self.active is not None
            and self.active["size"] + len(content) > self.policy.segment_bytes
        ):
            self._seal()
        if self.active is None:
            if len(self.segments) >= self.policy.max_segments or self.next_index >= 2**63 - 1:
                raise Rejected("audit_spool_capacity")
            self.next_index += 1
            name = f"{self.next_index:016x}.jsonl"
            self.descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self.directory,
            )
            metadata = os.fstat(self.descriptor)
            self._private(metadata)
            os.fsync(self.directory)
            self.hasher = hashlib.sha256()
            self.active = {
                "name": name,
                "size": 0,
                "first": now,
                "last": now,
                "sha256": self.hasher.hexdigest(),
                "identity": [metadata.st_dev, metadata.st_ino],
            }
            self.segments.append(self.active)
        self._write_all(self.descriptor, content)
        os.fsync(self.descriptor)
        completed = self.clock.sample()["mono"]
        self.hasher.update(content)
        self.active.update(
            size=self.active["size"] + len(content), last=completed, sha256=self.hasher.hexdigest()
        )
        self.retained_bytes += len(content)
        self.sequence = last_sequence

    def close(self, *, clean):
        if self.directory is None:
            return
        try:
            self._seal()
            if clean:
                self._inventory()
                for segment in self.segments:
                    self._verify(segment)
                manifest = canonical(
                    {
                        "schema_version": 1,
                        "policy": asdict(self.policy),
                        "budget": self.budget,
                        "clock": self.clock.sample(),
                        "sequence": self.sequence,
                        "next_index": self.next_index,
                        "segments": self.segments,
                    }
                )
                if len(manifest) > MAX_MANIFEST:
                    raise Rejected("audit_spool_manifest")
                self._new(".next", manifest)
                os.replace(
                    ".next", "manifest.json", src_dir_fd=self.directory, dst_dir_fd=self.directory
                )
                os.fsync(self.directory)
                if self._read(".lease", 32) != self.lease:
                    raise Rejected("audit_spool_identity")
                os.unlink(".lease", dir_fd=self.directory)
                self.released = True
                os.fsync(self.directory)
        finally:
            directory, self.directory = self.directory, None
            os.close(directory)
