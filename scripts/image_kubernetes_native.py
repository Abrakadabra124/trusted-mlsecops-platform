"""Four fixed public image validations. No cluster, application, or release acceptance.

Raw evidence stays in the exclusive job-owned directory. Only project()'s closed
projection is printed. Batch objects and their private paths are never serialized.
"""

import os
import re
import signal
import sys
import traceback
import uuid
from datetime import UTC, datetime
from pathlib import Path

from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    safe_child,
    write_json,
)
from scripts import image_audit as audit
from scripts import image_audit_contract as contract
from scripts import image_kubernetes_aliases as aliases
from scripts import image_kubernetes_scans as scans
from scripts import image_scope
from scripts.ci_consumer_native import private_output
from scripts.image_kubernetes_inventory import INVENTORIES

DIRECTORY = ".runtime/kubernetes-supplemental"
REPOSITORY = "Abrakadabra124/trusted-mlsecops-platform"
SCOPE = "four-public-kubernetes-images-only"
MAX_CONTAINERS = 40  # Four Syft, four original Grype, DB update, three controls, 28 modules.


def need(value):
    if not value:
        raise Rejected("kubernetes_native_rejected")


def owner():
    env = os.environ
    need(
        sys.platform == "linux"
        and all(
            env.get(k) == v
            for k, v in {
                "GITHUB_ACTIONS": "true",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
                "GITHUB_REPOSITORY": REPOSITORY,
                "KUBERNETES_REPOSITORY_VISIBILITY": "public",
                "GITHUB_JOB": "validate",
            }.items()
        )
    )
    need(
        all(
            re.fullmatch(r"[1-9][0-9]{0,19}", env.get(k, ""))
            for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
        )
    )
    need(re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", "")))
    return {
        "repository": REPOSITORY,
        "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": env["GITHUB_RUN_ATTEMPT"],
        "job": env["GITHUB_JOB"],
        "source_revision": env["GITHUB_SHA"],
    }


def prepare(root, ownership):
    state = safe_child(root, DIRECTORY)
    state.parent.mkdir(mode=0o700, exist_ok=True)
    state.mkdir(mode=0o700)  # Never resume or overwrite a prior job's state.
    (state / "run").mkdir(mode=0o700)
    write_json(state / "owner.json", ownership)
    return state


def targets():
    return [
        {
            "name": spec["component"],
            "config_id": config,
            "reference": "registry.k8s.io/" + spec["component"] + "@" + spec["manifest_digest"],
        }
        for config, spec in sorted(INVENTORIES.items(), key=lambda item: item[1]["component"])
    ]


def source(root, ownership):
    need(
        audit.command(["git", "-C", str(root), "rev-parse", "HEAD"]).strip()
        == ownership["source_revision"]
    )
    need(
        not audit.command(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"]
        ).strip()
    )
    return audit.source_fingerprint(root)


def cleanup(state, ownership):
    """Read only owned CIDs, remove exact IDs if needed, then independently list.

    An interrupted batch without a complete return leaves a pending marker. Its
    unknown final attempt cannot be certified merely from the CIDs that survived.
    """
    need(read_json(safe_child(state, "owner.json")) == ownership)
    run = safe_child(state, "run")
    need(run.is_dir())
    # Only host-created receipt locations confer cleanup authority. The scanner
    # can write output-NN/report.json and arbitrary siblings there: NEVER walk it.
    labels = [t["name"] + suffix for t in targets() for suffix in ("-sbom", "-scan")]
    labels += ["db-update", "control-pypi", "control-module", "control-stdlib"]
    labels += [f"kubernetes-modules/module-{index:02d}" for index in range(28)]
    expected = verified = 0
    seen = set()

    def absent(cid):
        path = run / ("cleanup-" + uuid.uuid4().hex + ".json")
        code = audit.execute(
            [
                "docker",
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--quiet",
                "--filter",
                "id=" + cid,
            ],
            path,
            15,
            output_limit=4096,
        )
        raw = bounded_read(path, 4096).strip()
        need(code == 0 and raw in (b"", cid.encode("ascii")))
        return raw == b""

    for label in labels:
        try:
            path = safe_child(run, label + ".cid")
            attempt = safe_child(run, label + ".attempt")
            if not path.exists() and not attempt.exists():
                continue
        except (Rejected, OSError):
            expected += 1
            continue
        expected += 1
        try:
            cid = bounded_read(path, 128).decode("ascii").strip()
            need(re.fullmatch(r"[0-9a-f]{64}", cid) and cid not in seen)
            seen.add(cid)
            if not absent(cid):
                output = run / ("cleanup-" + uuid.uuid4().hex + ".json")
                # The postcondition, not rm's exit alone, decides cleanup.
                audit.execute(["docker", "rm", "-f", cid], output, 30, output_limit=4096)
                need(absent(cid))
            verified += 1
        except (Rejected, OSError, UnicodeError):
            continue  # A bad receipt must not strand the remaining owned containers.
    clean = verified == expected and not (run / "batch.pending").exists()
    return {
        "status": "pass" if clean else "inconclusive",
        "expected": expected,
        "verified": verified,
    }


def scan(run, name, image, arguments, mounts=(), network=False):
    with (run / f"{name}.attempt").open("xb") as marker:
        marker.write(b"attempted\n")
    code, path = audit.scanner(run, name, image, arguments, mounts, network=network)
    need(path == run / f"{name}.json")
    return code, path


def document(path):
    return decode(bounded_read(path, audit.LIMIT), audit.LIMIT)


def project(components, coverage, fingerprint, db_files, cleanup_result):
    """Only reviewed names, enums, bounded integers and computed digests escape."""
    need(coverage == {"status": "pass", "expected_images": 4, "covered_images": 4})
    need(len(components) == 4 and [c["name"] for c in components] == [t["name"] for t in targets()])
    need(re.fullmatch(r"[0-9a-f]{64}", fingerprint))
    public = []
    for component in components:
        need(component["status"] in {"pass", "fail", "inconclusive"})
        counts = {
            severity: component["severity_counts"][severity] for severity in contract.SEVERITIES
        }
        numbers = [
            component["catalogued_packages"],
            component["matches"],
            component["unique_vulnerabilities"],
            *counts.values(),
        ]
        need(all(type(value) is int and 0 <= value <= 1000000 for value in numbers))
        need(sum(counts.values()) == component["matches"])
        public.append(
            {
                "name": component["name"],
                "status": component["status"],
                "packages": component["catalogued_packages"],
                "matches": component["matches"],
                "unique_vulnerabilities": component["unique_vulnerabilities"],
                "severity_counts": counts,
            }
        )
    statuses = {c["status"] for c in components}
    return {
        "schema_version": 1,
        "scope": SCOPE,
        "validation_status": "pass",
        "vulnerability_status": "fail"
        if "fail" in statuses
        else "inconclusive"
        if "inconclusive" in statuses
        else "pass",
        "release_ready": False,
        "source_fingerprint": fingerprint,
        "database_snapshot_digest": digest(canonical(db_files)),
        "controls": {"pypi": "pass", "go_module": "pass", "go_stdlib": "pass"},
        "original_image_scans": 4,
        "supplemental_scans": 28,
        "validation_coverage": dict(coverage),
        "components": public,
        "replay_verified": True,
        "cleanup": cleanup_result,
    }


def failure_context(progress, state, error):
    """Fixed labels only; batch index denotes the last created invocation directory."""
    context = dict(progress)
    if context["phase"] == "supplemental" and state is not None:
        try:
            directory = safe_child(state, "run/kubernetes-modules")
            indices = [i for i in range(28) if safe_child(directory, f"output-{i:02d}").is_dir()]
            context["case_index"] = max(indices) if indices else None
        except (Rejected, OSError):
            context["case_index"] = None
    context["exception_label"] = (
        "contract_rejected"
        if isinstance(error, Rejected)
        else "io_failure"
        if isinstance(error, OSError)
        else "interrupted"
        if isinstance(error, KeyboardInterrupt)
        else "unexpected_failure"
    )
    return context


def validate(root, state, progress=None):
    progress = {} if progress is None else progress
    progress.update(phase="source", case_index=None)
    ownership = read_json(safe_child(state, "owner.json"))
    fingerprint = source(root, ownership)
    run = safe_child(state, "run")
    selected = targets()
    need(len(selected) == 4 and len(aliases.coordinates()) == 28)
    for index, reference in enumerate(
        (audit.SYFT_IMAGE, audit.GRYPE_IMAGE, *(t["reference"] for t in selected))
    ):
        progress.update(phase="pull", case_index=index)
        need(
            audit.execute(
                ["docker", "pull", "--platform", "linux/amd64", reference],
                run / f"pull-{index}.json",
                300,
                output_limit=1024**2,
            )
            == 0
        )
        audit.inspect_image(reference)
    originals = []
    for index, target in enumerate(selected):
        progress.update(phase="inventory", case_index=index)
        name, reference, config = target["name"], target["reference"], target["config_id"]
        details = audit.inspect_image(reference)
        need(details["Id"] == config)
        archive = run / f"{name}.tar"
        need(
            audit.execute(
                ["docker", "image", "save", "--output", str(archive), config],
                run / f"{name}-save.json",
                300,
                output_limit=4096,
            )
            == 0
        )
        need(audit.identity(archive, details) == config)
        code, sbom_path = scan(
            run,
            name + "-sbom",
            audit.SYFT_IMAGE,
            ["docker-archive:/input/image.tar", "-o", "syft-json"],
            [(archive, "/input/image.tar", False)],
        )
        need(type(code) is int and code == 0)
        sbom = document(sbom_path)
        observation = contract.observe_packages(sbom, config)
        need(aliases.resolve(observation, reference) is not None)
        component = {
            "name": name,
            "role": "system",
            "image_config_id": config,
            "runtime_image_id": config,
            "observed_reference": reference,
            "package_observation": observation,
            "catalogued_packages": observation["package_count"],
            "package_binding_validated": True,
            "sbom_validated": False,
            "coverage_profile": "unapproved-system",
            "sbom_digest": audit.file_hash(sbom_path),
        }
        originals.append((component, sbom_path))
    cache = run / "cache"
    progress.update(phase="database", case_index=None)
    cache.mkdir(mode=0o700)
    code, _ = scan(
        run,
        "db-update",
        audit.GRYPE_IMAGE,
        ["db", "update"],
        [(cache, "/cache", True)],
        network=True,
    )
    need(type(code) is int and code == 0)
    db_files = audit.snapshot(cache)
    expected_db = None
    controls = [
        ("pypi", "pkg:pypi/urllib3@1.26.7"),
        *[
            (kind, f"pkg:golang/{package}@{version}")
            for kind, (package, version) in contract.GO_CONTROLS.items()
        ],
    ]
    for index, (kind, purl) in enumerate(controls):
        progress.update(phase="controls", case_index=index)
        code, path = scan(
            run,
            "control-" + kind,
            audit.GRYPE_IMAGE,
            [purl, "--fail-on", "high", "-o", "json"],
            [(cache, "/cache", False)],
        )
        control = document(path)
        if kind == "pypi":
            contract.detection_control(control, code)
            expected_db = contract.database(control, datetime.now(UTC))
        else:
            contract.go_detection_control(control, code, kind)
        need(
            contract.database(control, datetime.now(UTC)) == expected_db
            and audit.snapshot(cache) == db_files
        )
    records = []
    for index, (component, sbom_path) in enumerate(originals):
        progress.update(phase="original", case_index=index)
        code, path = scan(
            run,
            component["name"] + "-scan",
            audit.GRYPE_IMAGE,
            ["sbom:/input/sbom.json", "--fail-on", "high", "-o", "json"],
            [(cache, "/cache", False), (sbom_path, "/input/sbom.json", False)],
        )
        result = contract.assess(
            document(sbom_path),
            document(path),
            component["image_config_id"],
            set(),
            code,
            diagnostic_only=True,
        )
        need(
            result["database"] == expected_db
            and audit.file_hash(sbom_path) == component["sbom_digest"]
            and audit.snapshot(cache) == db_files
        )
        component.update(result, scan_executed=True, report_digest=audit.file_hash(path))
        records.append((component, sbom_path, path, code))
    write_json(run / "original-components.json", [r[0] for r in records])
    progress.update(phase="supplemental", case_index=None)
    (run / "batch.pending").write_bytes(b"attempted\n")
    batch = scans.run_batch(run, cache, expected_db, db_files)
    need(len(scans.read_batch(batch, expected_db)) == 28)
    (run / "batch.pending").unlink()

    def joined():
        return [
            scans.join(
                component, sbom, report, code, batch, component["observed_reference"], expected_db
            )
            for component, sbom, report, code in records
        ]

    progress.update(phase="join", case_index=None)
    components = joined()
    need(all(scans.coverage_valid(c, t) for c, t in zip(components, selected, strict=True)))
    coverage = image_scope.coverage({"targets": selected}, components)
    progress.update(phase="cleanup", case_index=None)
    clean = cleanup(state, ownership)
    need(clean == {"status": "pass", "expected": MAX_CONTAINERS, "verified": MAX_CONTAINERS})
    # Re-read originals and every module after the scanners no longer exist.
    progress.update(phase="replay", case_index=None)
    need(canonical(joined()) == canonical(components))
    need(audit.snapshot(cache) == db_files and source(root, ownership) == fingerprint)
    write_json(run / "joined-components.json", components)
    progress.update(phase="projection", case_index=None)
    return project(components, coverage, fingerprint, db_files, clean)


def main(argv=None, root=None):
    args = list(sys.argv[1:] if argv is None else argv)
    root = Path(__file__).resolve().parents[1] if root is None else root
    result = {
        "schema_version": 1,
        "scope": SCOPE,
        "validation_status": "inconclusive",
        "release_ready": False,
    }
    state, ownership = None, None
    progress = {"phase": "setup", "case_index": None}
    okay = False
    try:
        need(args in (["validate"], ["cleanup"]))
        ownership = owner()
        os.umask(0o077)
        if args == ["validate"]:
            state = prepare(root, ownership)
            with private_output(state, "kubernetes-supplemental"):
                try:
                    result = validate(root, state, progress)
                    okay = True
                except BaseException as error:
                    result.update(failure_context(progress, state, error))
                    traceback.print_exc()  # Only inside the existing FD-private capture.
        else:
            state = safe_child(root, DIRECTORY)
            okay = True
    except BaseException as error:
        result.update(failure_context(progress, state, error))
        okay = False
    finally:
        if state is not None:
            try:
                result["cleanup"] = cleanup(state, ownership)
                okay = okay and result["cleanup"]["status"] == "pass"
            except BaseException as error:
                result["cleanup"] = {"status": "inconclusive", "expected": None, "verified": 0}
                result.setdefault(
                    "exception_label", failure_context(progress, state, error)["exception_label"]
                )
                okay = False
    if not okay:
        result["validation_status"] = "inconclusive"
    if args == ["cleanup"]:
        result["stage"] = "cleanup"
    if ownership is not None:
        result["source_revision"] = ownership["source_revision"]
    print(canonical(result).decode("utf-8"))
    return 0 if okay else 1


def interrupted(signum, frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())
