"""Immutable qualification-only source mount; never part of worker privileges."""

import ast
import re

from mlsecops.contracts import Rejected, bounded_read, canonical, digest

MAX_BYTES = 512 * 1024


def manifest(root, name, workspace, *, entry="kube_privacy_probe"):
    if entry not in {"kube_privacy_probe", "kube_cli_privacy_probe"}:
        raise Rejected("privacy_bundle_entry")
    pending, data = [entry], {"__init__.py": ""}
    while pending:
        module = pending.pop()
        if re.fullmatch(r"[a-z_][a-z_0-9]*", module) is None:
            raise Rejected("privacy_bundle_module")
        filename = module + ".py"
        if filename in data:
            continue
        content = bounded_read(root / "scripts" / filename, MAX_BYTES).decode("utf-8")
        data[filename] = content
        if len(canonical(data)) > MAX_BYTES:
            raise Rejected("privacy_bundle_limit")
        for node in ast.walk(ast.parse(content)):
            if isinstance(node, ast.ImportFrom) and node.module == "scripts":
                pending.extend(value.name for value in node.names)
            elif (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.startswith("scripts.")
            ):
                pending.append(node.module.removeprefix("scripts."))
            elif isinstance(node, ast.Import):
                pending.extend(
                    value.name.removeprefix("scripts.")
                    for value in node.names
                    if value.name.startswith("scripts.")
                )
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "immutable": True,
        "metadata": {
            "name": name,
            "namespace": "ml-serving",
            "labels": {"trusted-mlsecops/workspace": workspace},
            "annotations": {"trusted-mlsecops/qualification-source": digest(canonical(data))},
        },
        "data": data,
    }
