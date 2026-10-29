"""Hosted Linux cross-UID canary checks; never uses an actual signing secret."""

import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

from mlsecops import key_files
from mlsecops.contracts import Rejected, canonical


def foreign_read(path):
    program = (
        "import json,sys; from pathlib import Path\n"
        "try:\n"
        " value=Path(sys.argv[1]).read_bytes()\n"
        " print(json.dumps({'status':'readable','canary':value==b'SYNTHETIC-CANARY'}))\n"
        "except PermissionError:\n"
        " print(json.dumps({'status':'permission-denied'}))\n"
    )
    result = subprocess.run(
        ["sudo", "-n", "-u", "nobody", "/usr/bin/python3", "-c", program, str(path)],
        capture_output=True,
        check=True,
        timeout=10,
    )
    if result.stderr:
        raise Rejected("key_canary_unexpected_stderr")
    return json.loads(result.stdout)


def qualify():
    if (
        os.name != "posix"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise Rejected("key_canary_requires_disposable_hosted_linux")
    cases = []

    def check(label, actual, expected):
        if canonical(actual) != canonical(expected):
            raise Rejected("key_canary_failed:" + label)
        cases.append({"id": label, "actual": actual, "expected": expected, "status": "pass"})

    with tempfile.TemporaryDirectory(prefix="mlsecops-key-canary-") as temporary:
        root = Path(temporary)
        # Deliberately traversable: prove the FILE mode, not just a private parent.
        root.chmod(0o755)
        control = root / "public-canary"
        control.write_bytes(b"SYNTHETIC-CANARY")
        control.chmod(0o644)
        check(
            "foreign-reader-positive-control",
            foreign_read(control),
            {"status": "readable", "canary": True},
        )
        key = root / "private-canary"
        mask = os.umask(0o022)
        try:
            with key_files.opened(key, create=True) as stream:
                check(
                    "mode-before-first-byte", stat.S_IMODE(os.fstat(stream.fileno()).st_mode), 0o600
                )
                check(
                    "foreign-reader-before-first-byte",
                    foreign_read(key),
                    {"status": "permission-denied"},
                )
                stream.write(b"SYNTHETIC-CANARY")
        finally:
            os.umask(mask)
        check("foreign-reader-after-close", foreign_read(key), {"status": "permission-denied"})
        check("owner-readback", key_files.read(key) == b"SYNTHETIC-CANARY", True)
        check("mode-after-close", stat.S_IMODE(key.stat().st_mode), 0o600)
    return {
        "status": "pass",
        "scope": "hosted-posix-key-file-canary",
        "release_ready": False,
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
