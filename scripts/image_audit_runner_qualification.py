import contextlib
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
    return {
        "status": "pass",
        "scope": "image-audit-runner-contracts",
        "checks": len(cases),
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
