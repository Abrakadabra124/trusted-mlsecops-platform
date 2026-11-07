"""One-use monitoring epochs in an explicitly provisioned private Linux directory.

Markers survive clean shutdown and crashes. They are not model/label history.
Missing state never initializes itself; an authorized new epoch reports history loss.
"""

import os
import re
import secrets
import stat
import sys
from contextlib import contextmanager
from pathlib import Path

from mlsecops import monitoring, monitoring_alerts
from mlsecops.contracts import Rejected, _parent, canonical, digest
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce as enforce_privacy

MAX_CLAIMS = 1024


def platform():
    if os.name != "posix":
        raise Rejected("monitor_state_platform")


def absolute(value):
    if type(value) is not str or not Path(value).is_absolute():
        raise Rejected("monitor_state_path")
    return value


def private(metadata, *, directory=False):
    if (
        not (stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode))
        or metadata.st_mode & 0o077
        or metadata.st_uid != os.geteuid()
        or not directory
        and metadata.st_nlink != 1
    ):
        raise Rejected("monitor_state_identity")


@contextmanager
def directory(path):
    platform()
    try:
        with _parent(absolute(path)) as (name, options):
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, **options)
            try:
                private(os.fstat(descriptor), directory=True)
                yield descriptor
            finally:
                os.close(descriptor)
    except OSError:
        raise Rejected("monitor_state_unavailable") from None


def create(descriptor, name, content):
    target = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor
    )
    try:
        private(os.fstat(target))
        offset = 0
        while offset < len(content):
            written = os.write(target, content[offset:])
            if written <= 0:
                raise Rejected("monitor_state_write")
            offset += written
        os.fsync(target)
        os.fsync(descriptor)
    finally:
        os.close(target)


def initialize(path):
    platform()
    # No exist_ok or reset: provisioning must be a deliberate first deployment.
    try:
        with _parent(absolute(path)) as (name, options):
            os.mkdir(name, 0o700, **options)
            with directory(path) as descriptor:
                content = secrets.token_hex(32).encode() + b"\n"
                create(descriptor, "identity", content)
            os.fsync(options["dir_fd"])
            return digest(content)
    except OSError:
        raise Rejected("monitor_state_initialization") from None


class Guard:
    def __init__(self, path, pin, role, epoch, reference):
        self.path, self.pin = absolute(path), monitoring.sha256(pin)
        if role not in ("producer", "sink"):
            raise Rejected("monitor_state_role")
        self.role = role
        self.epoch = monitoring_alerts.epoch_id(epoch)
        self.reference = monitoring.sha256(reference)

    def claim(self):
        with directory(self.path) as descriptor:
            import fcntl

            # A pinned directory lock also bounds concurrent inventory/admission.
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            target = os.open(
                "identity", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor
            )
            try:
                private(os.fstat(target))
                identity = os.read(target, 66)
                if (
                    re.fullmatch(rb"[a-f0-9]{64}\n", identity) is None
                    or digest(identity) != self.pin
                ):
                    raise Rejected("monitor_state_pin")
            finally:
                os.close(target)
            count = previous = 0
            with os.scandir(descriptor) as entries:
                for item in entries:
                    if item.name == "identity":
                        continue
                    if re.fullmatch(r"(producer|sink)-[a-f0-9]{32}", item.name) is None:
                        raise Rejected("monitor_state_inventory")
                    private(item.stat(follow_symlinks=False))
                    count += 1
                    previous += int(item.name.startswith(self.role + "-"))
                    if count >= MAX_CLAIMS:
                        raise Rejected("monitor_state_full")
            receipt = {
                "schema_version": 1,
                "state_sha256": self.pin,
                "role": self.role,
                "epoch": self.epoch,
                "reference_sha256": self.reference,
                "previous_epochs": previous,
                "history_unavailable": previous > 0,
            }
            # Even a partially written marker remains consumed after an interrupted write.
            create(descriptor, self.role + "-" + self.epoch, canonical(receipt) + b"\n")
            return receipt


def main(arguments=None):
    try:
        enforce_privacy()
        parser = Arguments(prog="monitoring-state")
        parser.add_argument("--directory", required=True)
        options = parser.parse_args(arguments)
        print(
            canonical(
                {
                    "schema_version": 1,
                    "state_sha256": initialize(options.directory),
                    "release_ready": False,
                }
            ).decode(),
            flush=True,
        )
        return 0
    except (Exception, KeyboardInterrupt) as failure:
        print("monitoring_state_rejected", file=sys.stderr)
        return 130 if isinstance(failure, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
