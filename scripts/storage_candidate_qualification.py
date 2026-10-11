import copy
import io
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, read_json, write_json
from scripts import storage_candidate


def qualify():
    cases = []

    def rejected(name, operation, reason):
        try:
            operation()
        except Rejected as error:
            if str(error) != reason:
                raise Rejected(f"candidate_contract_wrong_rejection:{name}:{error}") from None
        else:
            raise Rejected(f"candidate_contract_bypass:{name}")
        cases.append({"id": name, "status": "pass"})

    with tempfile.TemporaryDirectory(prefix="storage-candidate-contract-") as temporary:
        root = Path(temporary).resolve()
        output = root / storage_candidate.REPORT
        write_json(output, {"status": "pass", "old": True})
        with (
            patch.object(storage_candidate, "inspect", side_effect=Rejected("foreign-recipe")),
            patch.object(storage_candidate, "initialize") as initialize,
        ):
            rejected(
                "foreign-image-before-state",
                lambda: storage_candidate.rehearse(root),
                "foreign-recipe",
            )
            if initialize.called or read_json(output)["status"] != "inconclusive":
                raise Rejected("candidate_contract_stale_pass_or_state")
        identities = {
            role: {"image_id": "sha256:" + digit * 64, "recipe_digest": digit * 64}
            for role, digit in (("worker", "a"), ("storage", "b"))
        }
        result = {
            "status": "pass",
            "release_ready": False,
            "checks": 1,
            "source_image": "baseline",
            "target_image": identities["storage"]["image_id"],
            "golden_rows": 1000,
            "golden_max_error": 0.0,
            "storage_restore_seconds": 2,
            "restore_to_golden_seconds": 3,
            "database_profiles": {},
        }
        scenarios = (
            ("valid", None),
            ("failed-recovery", lambda value: value.update(status="fail")),
            ("release-claim", lambda value: value.update(release_ready=True)),
            ("foreign-target", lambda value: value.update(target_image="foreign")),
            ("foreign-source", lambda value: value.update(source_image="foreign")),
            ("changed-image-after-recovery", lambda value: None),
        )
        for name, mutate in scenarios:
            observed = copy.deepcopy(result)
            if mutate:
                mutate(observed)
            with (
                patch.object(
                    storage_candidate,
                    "inspect",
                    side_effect=[
                        identities["worker"],
                        identities["storage"],
                        {} if name == "changed-image-after-recovery" else identities["worker"],
                        identities["storage"],
                    ],
                ),
                patch.object(
                    storage_candidate,
                    "initialize",
                    side_effect=lambda root, state: state.mkdir(parents=True),
                ),
                patch.object(storage_candidate.storage_bootstrap, "bootstrap") as bootstrap,
                patch.object(
                    storage_candidate.storage_bootstrap,
                    "validate",
                    return_value={"image": "baseline"},
                ),
                patch.object(
                    storage_candidate.storage_recovery_qualification,
                    "qualify",
                    return_value=observed,
                ) as recover,
                patch.object(storage_candidate, "dispose") as dispose,
                patch.object(storage_candidate, "command", return_value="revision"),
            ):
                if mutate:
                    rejected(
                        name,
                        lambda: storage_candidate.rehearse(root),
                        "candidate_storage_qualification_binding_invalid",
                    )
                    if dispose.called or read_json(output)["status"] != "inconclusive":
                        raise Rejected("candidate_failure_deleted_evidence_or_retained_pass")
                else:
                    report = storage_candidate.rehearse(root)
                    state = bootstrap.call_args.args[0]
                    if (
                        not state.is_relative_to(root / ".runtime/image-candidates")
                        or bootstrap.call_args.args[1:] != (15442,)
                        or bootstrap.call_args.kwargs
                        or recover.call_args.args[2:] != (identities["worker"]["image_id"], 15443)
                        or recover.call_args.kwargs
                        != {"experimental_image_id": identities["storage"]["image_id"]}
                        or report["release_ready"] is not False
                        or not dispose.called
                    ):
                        raise Rejected("candidate_rehearsal_scope_invalid")
                    cases.append({"id": "fixed-ports-new-source-exact-images", "status": "pass"})
        state = root / ".runtime/image-candidates/cleanup"
        state.mkdir()
        marker = {
            "name": "owned",
            "container_id": "container",
            "network": "net",
            "volume": "volume",
        }
        with (
            patch.object(storage_candidate.storage_bootstrap, "validate", return_value=marker),
            patch.object(storage_candidate.storage_bootstrap, "docker") as docker,
            patch.object(storage_candidate.storage_bootstrap, "inspect", return_value=None),
        ):
            rejected(
                "wrong-cleanup-path",
                lambda: storage_candidate.dispose(root, root, marker),
                "candidate_storage_cleanup_path_invalid",
            )
            rejected(
                "wrong-cleanup-identity",
                lambda: storage_candidate.dispose(root, state, {}),
                "candidate_storage_cleanup_identity_changed",
            )
            if docker.called:
                raise Rejected("candidate_cleanup_crossed_ownership")
            storage_candidate.dispose(root, state, marker)
            if [call.args[0] for call in docker.call_args_list] != [
                ["rm", "--force", "container"],
                ["network", "rm", "net"],
                ["volume", "rm", "volume"],
            ]:
                raise Rejected("candidate_cleanup_scope_invalid")
            cases.append({"id": "only-owned-source-resources-removed", "status": "pass"})
        with (
            patch.object(storage_candidate.storage_bootstrap, "validate", return_value=marker),
            patch.object(storage_candidate.storage_bootstrap, "docker"),
            patch.object(
                storage_candidate.storage_bootstrap, "inspect", return_value={"remaining": True}
            ),
        ):
            rejected(
                "cleanup-not-complete",
                lambda: storage_candidate.dispose(root, state, marker),
                "candidate_storage_cleanup_incomplete",
            )
        for name, error in (
            ("success", None),
            ("rejected", Rejected("denied")),
            ("io", OSError("io")),
        ):
            write_json(output, {"status": "inconclusive", "release_ready": False})
            stdout = io.StringIO()
            with (
                patch.object(
                    storage_candidate, "__file__", str(root / "scripts/storage_candidate.py")
                ),
                patch.object(storage_candidate, "rehearse", return_value=result, side_effect=error),
                redirect_stdout(stdout),
            ):
                exit_code = storage_candidate.main()
            if exit_code != (2 if error else 0):
                raise Rejected("candidate_cli_wrong_exit")
            if error:
                report = read_json(output)
                if (
                    report["status"] != "inconclusive"
                    or report["release_ready"] is not False
                    or report["reason"] != str(error)
                    or "completed_at" not in report
                ):
                    raise Rejected("candidate_cli_failure_report_invalid")
            else:
                report = result
            if stdout.getvalue().strip() != canonical(report).decode():
                raise Rejected("candidate_cli_report_mismatch")
            cases.append({"id": f"cli-{name}", "status": "pass"})
    return {
        "status": "pass",
        "scope": "candidate-storage-orchestration-contracts-only",
        "checks": len(cases),
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
