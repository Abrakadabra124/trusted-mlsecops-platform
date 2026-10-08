import contextlib
import copy
import io
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from mlsecops import qualification
from mlsecops.contracts import Rejected, canonical, read_json, write_json
from scripts import image_candidates


def qualify():
    cases = []
    with tempfile.TemporaryDirectory(prefix="candidate-contract-") as temporary:
        root = Path(temporary).resolve()
        output = root / ".runtime/evidence/image-candidate-worker.json"
        write_json(output, {"status": "pass", "old": True})
        with patch.object(image_candidates, "inspect", side_effect=Rejected("missing")):
            try:
                image_candidates.qualify_worker(root)
            except Rejected:
                pass
        result = read_json(output)
        if result["status"] != "inconclusive" or "old" in result:
            raise Rejected("candidate_stale_pass_retained")
        cases.append({"id": "missing-candidate-invalidates-qualification", "status": "pass"})
    image = {
        "Id": "sha256:" + "a" * 64,
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {
            "Labels": {
                "org.trusted-mlsecops.source-fingerprint": "b" * 64,
                "org.trusted-mlsecops.candidate-recipe": "c" * 64,
                "org.trusted-mlsecops.candidate-role": "worker",
            }
        },
    }
    with (
        patch.object(image_candidates, "source_fingerprint", return_value="b" * 64),
        patch.object(image_candidates, "recipe_digest", return_value="c" * 64),
    ):
        result = image_candidates.validate(Path.cwd(), "worker", image)
        if result["image_id"] != image["Id"] or result["release_ready"] is not False:
            raise Rejected("candidate_valid_binding_failed")
        cases.append({"id": "valid-candidate-binding", "status": "pass"})
        for name, mutate in (
            (
                "foreign-source",
                lambda value: value["Config"]["Labels"].update(
                    {"org.trusted-mlsecops.source-fingerprint": "other"}
                ),
            ),
            (
                "foreign-recipe",
                lambda value: value["Config"]["Labels"].update(
                    {"org.trusted-mlsecops.candidate-recipe": "other"}
                ),
            ),
            (
                "foreign-role",
                lambda value: value["Config"]["Labels"].update(
                    {"org.trusted-mlsecops.candidate-role": "storage"}
                ),
            ),
            ("missing-labels", lambda value: value["Config"].update(Labels=None)),
            ("wrong-platform", lambda value: value.update(Os="windows")),
            ("wrong-arch", lambda value: value.update(Architecture="arm64")),
            ("non-digest-id", lambda value: value.update(Id="latest")),
        ):
            invalid = copy.deepcopy(image)
            mutate(invalid)
            try:
                image_candidates.validate(Path.cwd(), "worker", invalid)
            except Rejected:
                pass
            else:
                raise Rejected(f"candidate_binding_bypass:{name}")
            cases.append({"id": name, "status": "pass"})
    with tempfile.TemporaryDirectory(prefix="candidate-build-contract-") as temporary:
        root = Path(temporary).resolve()
        for spec in image_candidates.SPECS.values():
            recipe = root / spec["recipe"]
            recipe.parent.mkdir(parents=True)
            recipe.write_text("FROM scratch\n", encoding="ascii")
        receipts = []

        def command(arguments, **kwargs):
            if arguments[:2] == ["docker", "build"]:
                receipts.append(arguments)
                return ""
            if arguments[:3] == ["docker", "image", "inspect"]:
                observed = copy.deepcopy(image)
                role = next(
                    role
                    for role, spec in image_candidates.SPECS.items()
                    if spec["reference"] == arguments[-1]
                )
                observed["Config"]["Labels"].update(
                    {
                        "org.trusted-mlsecops.candidate-role": role,
                        "org.trusted-mlsecops.candidate-recipe": image_candidates.recipe_digest(
                            root, role
                        ),
                    }
                )
                return canonical([observed]).decode()
            return "revision"

        with (
            patch.object(image_candidates, "command", side_effect=command),
            patch.object(image_candidates, "source_fingerprint", return_value="b" * 64),
        ):
            built = image_candidates.build(root)
            if (
                built["status"] != "pass"
                or len(built["images"]) != 2
                or {call[call.index("--tag") + 1] for call in receipts}
                != {spec["reference"] for spec in image_candidates.SPECS.values()}
            ):
                raise Rejected("candidate_build_scope_invalid")
            cases.append({"id": "build-only-candidate-tags", "status": "pass"})
        with patch.object(
            image_candidates, "source_fingerprint", side_effect=Rejected("missing-source")
        ):
            try:
                image_candidates.build(root)
            except Rejected:
                pass
        if (
            read_json(root / ".runtime/evidence/image-candidate-build.json")["status"]
            != "inconclusive"
        ):
            raise Rejected("candidate_failed_build_retained_pass")
        cases.append({"id": "failed-build-invalidates-old-pass", "status": "pass"})
        for name, changed in (("same-image", False), ("changed-image", True)):
            observed = {
                "image_id": "sha256:" + "a" * 64,
                "recipe_digest": "c" * 64,
                "release_ready": False,
            }
            later = {**observed, "image_id": "other"} if changed else observed
            with (
                patch.object(image_candidates, "inspect", side_effect=[observed, later]),
                patch.object(
                    qualification,
                    "qualify",
                    return_value={"cases": [{"status": "pass"}], "metrics": {}},
                ) as run,
            ):
                try:
                    outcome = image_candidates.qualify_worker(root)["status"]
                except Rejected:
                    outcome = "rejected"
                if (
                    outcome != ("rejected" if changed else "pass")
                    or not run.call_args.args[1].is_relative_to(root / ".runtime/image-candidates")
                    or run.call_args.args[2] != observed["image_id"]
                ):
                    raise Rejected("candidate_qualification_scope_invalid")
            cases.append({"id": f"qualification:{name}", "status": "pass"})
    for action, failed in (("build", False), ("qualify-worker", False), ("build", True)):
        function = "build" if action == "build" else "qualify_worker"
        with (
            patch.object(sys, "argv", ["image_candidates", action]),
            patch.object(
                image_candidates,
                function,
                side_effect=Rejected("controlled") if failed else None,
                return_value={"status": "pass"},
            ),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            if image_candidates.main() != (2 if failed else 0):
                raise Rejected("candidate_cli_status_invalid")
        cases.append({"id": f"cli:{action}:failed={failed}", "status": "pass"})
    return {
        "status": "pass",
        "scope": "candidate-binding-contracts-only",
        "checks": len(cases),
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
