import copy
import platform
import shutil
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    digest,
    read_json,
    write_json,
)
from mlsecops.datasets import generate, prepare, publish_records, source_approval, verify_dataset
from mlsecops.signing import create_key, decode64, encode64, sign


def qualify(policy):
    if platform.system() != "Linux":
        raise Rejected("integrity_linux_profile_required")
    cases = []

    def confirmed(identifier, condition):
        if not condition:
            raise Rejected(f"dataset_integrity_failed:{identifier}")
        cases.append({"id": identifier, "status": "pass", "expected": True, "actual": True})

    def rejected(identifier, operation, reason):
        try:
            operation()
        except Rejected as error:
            if str(error) != reason:
                raise Rejected(f"dataset_integrity_wrong_rejection:{identifier}:{error}") from None
            cases.append(
                {"id": identifier, "status": "pass", "expected": reason, "actual": str(error)}
            )
        else:
            raise Rejected(f"dataset_integrity_bypass:{identifier}")

    with tempfile.TemporaryDirectory(prefix="dataset-integrity-") as temporary:
        state = Path(temporary)
        (state / "approved").mkdir()
        public = {role: create_key(state / f"keys/{role}.pem") for role in ("curator", "approver")}
        write_json(state / "trusted-keys.json", public)
        identifier = prepare(state, policy)
        splits, manifest = verify_dataset(state, identifier, policy)
        directory = state / "approved" / identifier
        originals = {path.name: bounded_read(path) for path in directory.iterdir()}
        before = {name: digest(content) for name, content in originals.items()}
        confirmed(
            "approved-repeat-readable", verify_dataset(state, identifier, policy)[0] == splits
        )
        confirmed(
            "approved-publish-idempotent",
            publish_records(state, policy, generate(policy["data_seed"], policy["rows"]))
            == identifier,
        )
        for name, original in originals.items():
            path = directory / name
            path.unlink()
            rejected(
                f"missing:{name}",
                lambda: verify_dataset(state, identifier, policy),
                "artifact_unavailable",
            )
            atomic_write(path, original)
            if name != "manifest.json":
                atomic_write(path, original[:-1] + bytes([original[-1] ^ 1]))
                rejected(
                    f"single-byte:{name}",
                    lambda: verify_dataset(state, identifier, policy),
                    "dataset_content_mismatch",
                )
                rejected(
                    f"cannot-republish-over-corruption:{name}",
                    lambda: publish_records(
                        state, policy, generate(policy["data_seed"], policy["rows"])
                    ),
                    "dataset_content_mismatch",
                )
                atomic_write(path, original)
        atomic_write(directory / "validation.json", originals["holdout.json"])
        rejected(
            "swapped-split",
            lambda: verify_dataset(state, identifier, policy),
            "dataset_content_mismatch",
        )
        atomic_write(directory / "validation.json", originals["validation.json"])
        envelope = read_json(directory / "manifest.json")
        changed = copy.deepcopy(envelope)
        signature = decode64(changed["signatures"][0]["sig"])
        changed["signatures"][0]["sig"] = encode64(signature[:-1] + bytes([signature[-1] ^ 1]))
        changed_payload = copy.deepcopy(envelope)
        changed_payload["payload"] = encode64(canonical({**manifest, "seed": 1}))
        for name, invalid, reason in (
            ("manifest-signature-byte", changed, "invalid_signature"),
            ("manifest-unsigned-payload", changed_payload, "invalid_signature"),
            (
                "manifest-wrong-signer",
                sign(manifest, "dataset", state / "keys/approver.pem"),
                "untrusted_key",
            ),
            (
                "manifest-wrong-type",
                sign(manifest, "source", state / "keys/curator.pem"),
                "wrong_payload_type",
            ),
            (
                "manifest-empty-signatures",
                {**envelope, "signatures": []},
                "invalid_signature_count",
            ),
            (
                "manifest-address-binding",
                sign({**manifest, "seed": 1}, "dataset", state / "keys/curator.pem"),
                "dataset_manifest_mismatch",
            ),
        ):
            write_json(directory / "manifest.json", invalid)
            rejected(name, lambda: verify_dataset(state, identifier, policy), reason)
        atomic_write(directory / "manifest.json", originals["manifest.json"])
        approval_path = state / "source-approval.json"
        original_approval = bounded_read(approval_path)
        approval = source_approval(state, policy)
        for name, expires, reason in (
            ("source-expired", "2000-01-01T00:00:00+00:00", "expired_source_approval"),
            (
                "source-version-stale",
                (datetime.now(UTC) + timedelta(days=31)).isoformat(),
                "source_version_mismatch",
            ),
        ):
            write_json(
                approval_path,
                sign({**approval, "expires_at": expires}, "source", state / "keys/curator.pem"),
            )
            rejected(name, lambda: verify_dataset(state, identifier, policy), reason)
        atomic_write(approval_path, original_approval)
        for name, value in (
            ("parent-traversal", "../outside"),
            ("absolute-path", str(directory)),
            ("windows-drive", "C:/outside"),
            ("windows-separator", "..\\outside"),
        ):
            rejected(
                name,
                lambda value=value: verify_dataset(state, value, policy),
                "invalid_artifact_path",
            )
        outside = state / "outside"
        outside.mkdir()
        atomic_write(outside / "train.json", originals["train.json"])
        for name, target, reason in (
            ("split-symlink-outside", outside / "train.json", "artifact_path_escape"),
            ("split-symlink-inside", directory / "holdout.json", "symlink_rejected"),
        ):
            link = directory / "train.json"
            link.unlink()
            link.symlink_to(target)
            rejected(name, lambda: verify_dataset(state, identifier, policy), reason)
            link.unlink()
            atomic_write(link, originals["train.json"])
        manifest_link = directory / "manifest.json"
        atomic_write(outside / "manifest.json", originals["manifest.json"])
        manifest_link.unlink()
        manifest_link.symlink_to(outside / "manifest.json")
        rejected(
            "manifest-symlink",
            lambda: verify_dataset(state, identifier, policy),
            "symlink_rejected",
        )
        manifest_link.unlink()
        atomic_write(manifest_link, originals["manifest.json"])
        directory.rename(outside / identifier)
        directory.symlink_to(outside / identifier, target_is_directory=True)
        rejected(
            "dataset-directory-symlink",
            lambda: verify_dataset(state, identifier, policy),
            "artifact_path_escape",
        )
        directory.unlink()
        (outside / identifier).rename(directory)
        for name, reason in (
            ("signed-object-traversal", "unexpected_dataset_objects"),
            ("signed-wrong-count", "invalid_dataset_object_metadata"),
            ("signed-wrong-digest", "dataset_content_mismatch"),
            ("signed-duplicate-entity", "invalid_or_duplicate_entity"),
            ("signed-cross-split-entity", "cross_split_leakage"),
        ):
            changed = copy.deepcopy(manifest)
            payloads = dict(originals)
            if name == "signed-object-traversal":
                changed["objects"]["../train.json"] = changed["objects"].pop("train.json")
            elif name == "signed-wrong-count":
                changed["objects"]["train.json"]["rows"] = True
            elif name == "signed-wrong-digest":
                changed["objects"]["train.json"]["sha256"] = "0" * 64
            else:
                rows = copy.deepcopy(splits["train"])
                rows[0]["entity_id"] = (
                    rows[1]["entity_id"]
                    if name == "signed-duplicate-entity"
                    else splits["holdout"][0]["entity_id"]
                )
                content = canonical(rows)
                payloads["train.json"] = content
                changed["objects"]["train.json"].update(sha256=digest(content), bytes=len(content))
            bad_id = digest(canonical(changed))
            bad_directory = state / "approved" / bad_id
            bad_directory.mkdir()
            try:
                for filename, content in payloads.items():
                    atomic_write(bad_directory / filename, content)
                write_json(
                    bad_directory / "manifest.json",
                    sign(changed, "dataset", state / "keys/curator.pem"),
                )
                rejected(name, lambda: verify_dataset(state, bad_id, policy), reason)
            finally:
                shutil.rmtree(bad_directory)
        after = {path.name: digest(bounded_read(path)) for path in directory.iterdir()}
        confirmed("original-hashes-unchanged", before == after)
        confirmed(
            "positive-control-after-negatives",
            verify_dataset(state, identifier, policy)[0] == splits,
        )
    return {
        "schema_version": 1,
        "status": "pass",
        "scope": "M03-filesystem-fixtures",
        "policy_digest": digest(canonical(policy)),
        "source_sha256": digest(
            canonical([row for name in ("train", "validation", "holdout") for row in splits[name]])
        ),
        "cases": cases,
        "hashes_before": before,
        "hashes_after": after,
        "platform": platform.system(),
        "python": platform.python_version(),
    }


def main():
    try:
        result = qualify(read_json(Path(__file__).resolve().parents[1] / "policies/local-cpu.json"))
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        print(f"Dataset integrity rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
