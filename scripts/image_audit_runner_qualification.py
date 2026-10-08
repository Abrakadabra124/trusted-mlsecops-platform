import contextlib
import copy
import io
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, read_json, write_json
from scripts import image_audit


def qualify():
    cases = []
    inspected = {
        "Os": "linux",
        "Architecture": "amd64",
        "Id": "sha256:" + "a" * 64,
        "Size": 1024,
        "RepoDigests": ["anchore/syft@" + image_audit.SYFT_IMAGE.split("@")[1]],
    }
    with patch.object(image_audit, "command", return_value=canonical([inspected]).decode()):
        image_audit.inspect_image(image_audit.SYFT_IMAGE)
    cases.append({"id": "tag-and-repodigest-distinction", "status": "pass"})
    for field, value in (
        ("Os", "windows"),
        ("Architecture", "arm64"),
        ("Id", "old"),
        ("Size", 0),
        ("RepoDigests", []),
    ):
        invalid = copy.deepcopy(inspected)
        invalid[field] = value
        with patch.object(image_audit, "command", return_value=canonical([invalid]).decode()):
            try:
                image_audit.inspect_image(image_audit.SYFT_IMAGE)
            except Rejected:
                pass
            else:
                raise Rejected(f"audit_image_contract_failed:{field}")
        cases.append({"id": f"inspect:{field}", "status": "pass"})
    with tempfile.TemporaryDirectory(prefix="audit-runner-contract-") as temporary:
        root = Path(temporary)
        output = root / ".runtime/evidence/image-audit.json"
        for name, outcome in (
            ("success", {"status": "pass"}),
            ("findings", {"status": "fail"}),
            ("incomplete", {"status": "inconclusive"}),
            ("rejected", Rejected("scanner_failed")),
            ("io-error", OSError("private detail")),
            ("crash", RuntimeError("private detail")),
        ):
            write_json(output, {"status": "pass", "stale": True})
            invocation = (
                {"side_effect": outcome}
                if isinstance(outcome, Exception)
                else {"return_value": outcome}
            )
            with (
                patch.object(image_audit, "audit", **invocation),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                exit_code = image_audit.main(root)
            report = read_json(output)
            if (
                (exit_code == 0) != (name == "success")
                or "stale" in report
                or "private detail" in str(report)
            ):
                raise Rejected(f"audit_cli_contract_failed:{name}")
            cases.append({"id": f"cli:{name}", "status": "pass"})
        for name, value, expected in (
            ("valid", "a" * 64, True),
            ("invalid", "other", False),
            ("missing", None, False),
        ):
            cidfile = root / f"{name}.cid"
            if value:
                cidfile.write_text(value, encoding="ascii")
            calls = []

            def fake_run(arguments, **kwargs):
                calls.append(arguments)
                return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")

            with (
                patch.object(image_audit.subprocess, "run", side_effect=fake_run),
                patch.object(
                    image_audit.subprocess,
                    "Popen",
                    side_effect=subprocess.TimeoutExpired("docker", 1),
                ),
            ):
                try:
                    image_audit.execute(["docker", "run"], root / f"{name}.json", 1, cidfile)
                except Rejected:
                    pass
                else:
                    raise Rejected("audit_timeout_accepted")
            removals = [call for call in calls if call[1:3] == ["rm", "-f"]]
            if removals != ([["docker", "rm", "-f", value]] if expected else []):
                raise Rejected("audit_cleanup_scope_failed")
            cases.append({"id": f"timeout:{name}", "status": "pass"})
        with patch.object(image_audit, "LIMIT", 1024):
            try:
                image_audit.execute(
                    [
                        sys.executable,
                        "-c",
                        "import sys,time; sys.stdout.write('x'*4096); sys.stdout.flush(); time.sleep(5)",
                    ],
                    root / "overflow.json",
                    2,
                )
            except Rejected as error:
                if str(error) != "image_audit_output_too_large":
                    raise Rejected("audit_live_output_limit_failed") from error
            else:
                raise Rejected("audit_live_output_limit_missing")
        cases.append({"id": "live-child-output-limit", "status": "pass"})
        for name, source, expected in (
            ("normal-exit", "print('ok')", 0),
            (
                "deadline",
                "import time; time.sleep(2)",
                "image_audit_command_unavailable_or_timeout",
            ),
            (
                "stderr-limit",
                "import sys; sys.stderr.write('x'*(3*1024*1024))",
                "image_audit_output_too_large",
            ),
        ):
            try:
                actual = image_audit.execute(
                    [sys.executable, "-c", source],
                    root / f"{name}.json",
                    0.3 if name == "deadline" else 2,
                )
            except Rejected as error:
                actual = str(error)
            if actual != expected:
                raise Rejected(f"audit_child_contract_failed:{name}")
            cases.append({"id": f"live-child:{name}", "status": "pass"})
        for name, operation in (
            ("directory-not-file", lambda: image_audit.file_hash(root)),
            ("empty-cache", lambda: image_audit.snapshot(root / "missing")),
        ):
            try:
                operation()
            except Rejected:
                pass
            else:
                raise Rejected(f"audit_filesystem_contract_failed:{name}")
            cases.append({"id": name, "status": "pass"})
        for network in (False, True):
            with (
                patch.object(image_audit.os, "getuid", return_value=1001, create=True),
                patch.object(image_audit.os, "getgid", return_value=1001, create=True),
                patch.object(image_audit, "execute", return_value=0) as executor,
            ):
                image_audit.scanner(
                    root,
                    "unit",
                    image_audit.GRYPE_IMAGE,
                    ["db", "status"],
                    [(root, "/input", False)],
                    network=network,
                )
                arguments = executor.call_args.args[0]
                if (
                    arguments[arguments.index("--network") + 1] != ("bridge" if network else "none")
                    or arguments[arguments.index("--user") + 1] != "1001:1001"
                    or "--read-only" not in arguments
                    or "ALL" not in arguments
                    or "no-new-privileges" not in arguments
                    or "GRYPE_DB_VALIDATE_AGE=true" not in arguments
                    or "GRYPE_DB_VALIDATE_BY_HASH_ON_START=true" not in arguments
                    or not arguments[arguments.index("--mount") + 1].endswith(",readonly")
                ):
                    raise Rejected("audit_scanner_boundary_failed")
            cases.append({"id": f"scanner-arguments:network={network}", "status": "pass"})
        for name, uid, source in (("root", 0, root), ("comma-mount", 1001, root / "a,b")):
            with (
                patch.object(image_audit.os, "getuid", return_value=uid, create=True),
                patch.object(image_audit.os, "getgid", return_value=uid, create=True),
            ):
                try:
                    image_audit.scanner(
                        root, "unit", image_audit.GRYPE_IMAGE, [], [(source, "/input", False)]
                    )
                except Rejected:
                    pass
                else:
                    raise Rejected(f"audit_scanner_negative_failed:{name}")
            cases.append({"id": f"scanner-denial:{name}", "status": "pass"})
    return {
        "status": "pass",
        "scope": "image-audit-runner-contracts",
        "checks": len(cases),
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
