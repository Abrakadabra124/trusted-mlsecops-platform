def compare(components):
    pending = {
        "status": "inconclusive",
        "release_ready": False,
        "reason": "comparison_inputs_incomplete",
    }
    names = {"worker", "storage", "worker-candidate", "storage-candidate"}
    try:
        if (
            len(components) != 4
            or {component["name"] for component in components} != names
            or any(
                component["scan_executed"] is not True
                or not isinstance(component["findings"], list)
                for component in components
            )
            or any(component["database"] != components[0]["database"] for component in components)
        ):
            return pending
        result = {
            "status": "pass",
            "release_ready": False,
            "scope": "comparison-complete-not-security-pass",
        }
        indexed = {component["name"]: component for component in components}
        for role in ("worker", "storage"):
            before, after = indexed[role], indexed[role + "-candidate"]
            baseline = {(finding["id"], finding["package"]) for finding in before["findings"]}
            candidate = {(finding["id"], finding["package"]) for finding in after["findings"]}
            result[role] = {
                "baseline_status": before["status"],
                "candidate_status": after["status"],
                "baseline_packages": before["packages"],
                "candidate_packages": after["packages"],
                "removed": [
                    {"id": identifier, "package": package}
                    for identifier, package in sorted(baseline - candidate)
                ],
                "introduced": [
                    {"id": identifier, "package": package}
                    for identifier, package in sorted(candidate - baseline)
                ],
                "remaining_pairs": len(candidate & baseline),
            }
        return result
    except (KeyError, TypeError):
        return pending
