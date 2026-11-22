"""Attach kubectl-only provenance and current scan evidence to the observed stock node."""

from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, safe_child
from scripts import image_kubernetes_scans as scans
from scripts import image_node_kubectl_inventory as inv
from scripts.image_audit_contract import (
    GO_CONTROLS,
    assess,
    exact_observation_matches,
    observe_packages,
)
from scripts.image_node_openssl import OBSERVATION

QUALIFICATION_SHA = "553c8c26c32058eb812a684ffc24dd2c870d351e5ea9b13f615736909ba700c3"
# SHA-256 of the canonical projection below from that report, excluding all scan outcomes.
SUBJECT_SHA = "ec3ebc2baca74453a0e672e57cda8ce5c911eb5d6be98cd9b7f6dfd7f7923a62"
CLI = "k8s.io/cli-runtime"


def qualified_subject():
    subject = dict(
        node_index=inv.IMAGES["baseline"],
        node_manifest=inv.AMD64,
        node_config=inv.CONFIG,
        path=inv.BINARY,
        observed_elf_sha256=inv.ELF_SHA,
        upstream_sha256=inv.ELF_SHA,
        revision=inv.REVISION,
        inventory_sha256=inv.ROWS_SHA,
        source_proof_sha256=inv.aliases.proof_digest(),
        coordinates=[[m, "v0.36.4"] for m in inv.coordinates()],
    )
    inv.need(digest(canonical(subject)) == SUBJECT_SHA, "qualified_subject_changed")
    return subject


def bind(observed, components):
    hosts = [c["image_id"] for c in observed.get("containers", []) if c["role"] == "kind-node"]
    targets = [t for t in observed["targets"] if inv.CONFIG in (t["reference"], t["config_id"])]
    if not hosts and not targets:
        return None
    inv.need(hosts == [inv.CONFIG], "host_identity")
    inv.need(len(targets) == 1, "target_identity")
    target = targets[0]
    matches = [c for c in components if c["name"] == target["name"]]
    inv.need(
        target["reference"] == inv.CONFIG
        and target["config_id"] in (None, inv.CONFIG)
        and "containerd_reference" not in target
        and len(matches) == 1,
        "target_identity",
    )
    component = matches[0]
    inv.need(
        component["role"] == "system"
        and component["host_roles"] == ["kind-node"]
        and component["coverage_profile"] == "unapproved-system"
        and component["diagnostic_only"] is True
        and component["sbom_validated"] is False
        and component["package_binding_validated"] is True
        and component["scan_executed"] is True
        and component["reason"] == "image_audit_runtime_application_coverage_unapproved"
        and "local_alias" not in component
        and "containerd_export" not in component
        and all(
            component[k] == inv.CONFIG
            for k in ("runtime_image_id", "image_config_id", "observed_reference", "image_id")
        ),
        "component_identity",
    )
    observation = component["package_observation"]
    inv.need(
        observation["image_id"] == inv.CONFIG
        and exact_observation_matches(observation, 878, OBSERVATION),
        "node_inventory",
    )
    rows = sorted((r for r in observation["packages"] if inv.BINARY in r["paths"]), key=canonical)
    subject = qualified_subject()
    inv.need(
        len(rows) == inv.COUNT
        and digest(canonical(rows)) == inv.ROWS_SHA
        and sorted(r["name"] for r in rows if r["version"] == "UNKNOWN")
        == sorted(m for m, _ in subject["coordinates"]),
        "inventory",
    )
    return component, dict(
        scope="stock-node-kubectl-only",
        qualification_run=45053630761,
        qualification_report_sha256=QUALIFICATION_SHA,
        qualified_subject=subject,
        qualified_subject_sha256=SUBJECT_SHA,
        rows=len(rows),
    )


def read_original(run, component, db):
    def read(label, key):
        path = safe_child(run, f"{component['name']}-{label}.json")
        raw = bounded_read(path, scans.LIMIT)
        inv.need(digest(raw) == component[key], "original_changed")
        return decode(raw, scans.LIMIT)

    sbom, raw = read("sbom", "sbom_digest"), read("scan", "report_digest")
    original = assess(
        sbom, raw, inv.CONFIG, set(), component["scanner_exit_code"], diagnostic_only=True
    )
    inv.need(
        original["database"] == db
        and all(component[k] == v for k, v in original.items())
        and component["vulnerability_count"] == original["unique_vulnerabilities"]
        and observe_packages(sbom, inv.CONFIG) == component["package_observation"],
        "original_binding",
    )
    # The normal finding projection has no location. Join the original Syft and Grype IDs.
    ids = {
        p["id"]
        for p in sbom["artifacts"]
        if any(
            inv.BINARY in (loc.get("path"), loc.get("accessPath")) for loc in p.get("locations", [])
        )
    }
    inv.need(len(ids) == inv.COUNT, "original_path_ids")
    return [
        finding
        for hit, finding in zip(raw["matches"], original["findings"], strict=True)
        if hit["artifact"]["id"] in ids
    ]


def attach(report, observed, run, cache, db, db_files, batch):
    """Run before final material and runtime readback. No intermediate write or coverage grant."""
    try:
        binding = bind(observed, report["components"])
        if binding is None:
            return
        component, evidence = binding
        evidence["original_path_findings"] = read_original(run, component, db)
        evidence["original_node_matches"] = component["matches"]
        evidence["original_node_findings_sha256"] = digest(canonical(component["findings"]))
        evidence["supplemental_complete"] = False
        component["kubectl_attribution"] = evidence
        controls = report["go_detection_controls"]
        inv.need(
            set(controls) == set(GO_CONTROLS)
            and all(c["status"] == "pass" for c in controls.values())
            and "kubernetes_supplemental_error" not in report
            and batch is not None
            and batch.directory == run / "kubernetes-modules"
            and report["database_files"] == db_files,
            "current_batch_unavailable",
        )
        evidence["database_sha256"] = db_files["6/vulnerability.db"]
        required = {tuple(pair) for pair in evidence["qualified_subject"]["coordinates"]}
        reused = [r for r in scans.read_batch(batch, db) if (r["module"], r["version"]) in required]
        inv.need(
            sorted((r["module"], r["version"]) for r in reused)
            == sorted(required - {(CLI, "v0.36.4")}),
            "current_eight_incomplete",
        )
        fresh = scans.scan_kubectl_cli_runtime(run, cache, db, db_files)
        results = sorted([*reused, fresh], key=lambda r: r["module"])
        inv.need(
            [(r["module"], r["version"]) for r in results] == sorted(required)
            and all(r["database"] == db for r in results),
            "current_nine_binding",
        )
        joined = scans.joined_result(component, results, diagnostic_only=True)
        evidence.update(scans=results, fresh_purl=fresh["purl"], supplemental_complete=True)
        component.update(joined, vulnerability_count=joined["unique_vulnerabilities"])
    except (Rejected, OSError, KeyError, ValueError, TypeError) as error:
        report["kubectl_attribution_error"] = (
            str(error) if isinstance(error, Rejected) else "kubectl_evidence_unavailable"
        )
