"""Measure an unpublished CoreDNS dependency rebuild against the pinned source image."""

import gzip
import hashlib
import io
import json
import os
import re
import tarfile
from pathlib import Path

from mlsecops.contracts import Rejected
from scripts import image_audit as audit
from scripts.image_audit_contract import (
    COREDNS_CONFIG,
    COREDNS_REFERENCE,
    coredns_inventory_matches,
)
from scripts.image_coredns_pair import scan_image

CAPABILITY = bytes.fromhex("0100000200040000000000000000000000000000")
SOURCE_ELF = "190dccd1d78f0f9df015076457c88cf3e92600667523282de942caaba86d2f59"
UPDATES = {
    "github.com/coredns/coredns": ("v0.0.0-20261021021732-a6fde3fe339c", "v1.15.0+dirty"),
    "github.com/klauspost/compress": ("v1.19.1", "v1.20.2"),
    "golang.org/x/crypto": ("v0.57.0", "v0.59.0"),
    "golang.org/x/mod": ("v0.41.0", "v0.42.0"),
    "golang.org/x/net": ("v0.60.0", "v0.62.0"),
    "golang.org/x/sync": ("v0.23.0", "v0.25.0"),
    "golang.org/x/sys": ("v0.49.0", "v0.50.0"),
    "golang.org/x/term": ("v0.46.0", "v0.48.0"),
    "golang.org/x/text": ("v0.42.0", "v0.44.0"),
    "stdlib": ("go1.27.3", "go1.27.4"),
}
BASELINE = {
    ("GO-2026-6865", "github.com/klauspost/compress", "v1.19.1", "High"),
    ("GO-2026-6860", "golang.org/x/net", "v0.60.0", "High"),
    ("GO-2026-5932", "golang.org/x/crypto", "v0.57.0", "Unknown"),
}


def inventory_matches(observation, config):
    """Reverse just the ten independently fixed versions, then check all 202 original rows."""
    if config == COREDNS_CONFIG or observation["image_id"] != config:
        return False
    rows = []
    for row in observation["packages"]:
        change = UPDATES.get(row["name"])
        if change:
            if row["version"] != change[1]:
                return False
            row = {**row, "version": change[0]}
        rows.append(row)
    return coredns_inventory_matches(
        {**observation, "packages": rows, "image_id": COREDNS_CONFIG}, COREDNS_REFERENCE
    )


def accepted(source, candidate):
    observed = {
        (f["id"], f["package"], f["installed"], f["severity"])
        for f in source
        if f["type"] == "go-module"
    }
    targets = {row[0] for row in BASELINE}
    return (
        BASELINE <= observed
        and candidate["status"] == "pass"
        and not any(f["id"] in targets for f in candidate["findings"])
    )


def read_layer(stream, diff_id, expected_elf):
    """The final change must consist solely of the exact owned, file-capable executable."""
    magic = stream.read(2)
    stream.seek(0)
    reader = gzip.GzipFile(fileobj=stream) if magic == b"\x1f\x8b" else stream
    raw = reader.read(256 * 1024**2 + 1)
    if len(raw) > 256 * 1024**2 or "sha256:" + hashlib.sha256(raw).hexdigest() != diff_id:
        raise Rejected("coredns_diff_id_mismatch")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as layer:
        entries = [m for m in layer if not (m.isdir() and m.name in (".", "./"))]
        if len(entries) != 1:
            raise Rejected("coredns_layer_contents")
        file = entries[0]
        if (
            file.name not in ("coredns", "./coredns")
            or not file.isreg()
            or (file.uid, file.gid, file.mode) != (0, 0, 0o755)
            or file.pax_headers.get("SCHILY.xattr.security.capability") != CAPABILITY.decode()
        ):
            raise Rejected("coredns_file_metadata")
        with layer.extractfile(file) as binary:
            if binary.read(4) != b"\x7fELF":
                raise Rejected("coredns_elf_magic")
            binary.seek(0)
            observed = hashlib.file_digest(binary, "sha256").hexdigest()
    if observed != expected_elf:
        raise Rejected("coredns_elf_mismatch")
    return observed


def archive_readback(path, details, expected):
    if audit.identity(path, details) != details["Id"]:
        raise Rejected("coredns_archive_config_mismatch")
    with tarfile.open(path, "r:") as archive:
        (manifest,) = json.load(archive.extractfile("manifest.json"))
        layers = details["RootFS"]["Layers"]
        if len(layers) != len(manifest["Layers"]):
            raise Rejected("coredns_archive_layer_count")
        last = archive.getmember(manifest["Layers"][-1])
        if not last.isreg():
            raise Rejected("coredns_archive_layer_type")
        with archive.extractfile(last) as stream:
            return read_layer(stream, layers[-1], expected)


def compare(run):
    config = (run / "candidate.id").read_text().strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", config) or config == COREDNS_CONFIG:
        raise Rejected("coredns_candidate_config")
    checksum = (run / "receipt/coredns.sha256").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{64}  /out/coredns", checksum):
        raise Rejected("coredns_candidate_receipt")
    for reference in (COREDNS_REFERENCE, audit.SYFT_IMAGE, audit.GRYPE_IMAGE):
        audit.command(["docker", "pull", "--platform", "linux/amd64", reference], timeout=300)
        audit.inspect_image(reference)
    source = audit.inspect_image(COREDNS_REFERENCE)
    candidate = audit.inspect_image(config)
    layers = candidate["RootFS"]["Layers"]
    if (
        source["Id"] != COREDNS_CONFIG
        or candidate["Id"] != config
        or layers[:-1] != source["RootFS"]["Layers"]
        or candidate["Config"]["User"] != "65532:65532"
        or candidate["Config"]["Entrypoint"] != ["/coredns"]
        or any(
            candidate["Config"].get(k) != source["Config"].get(k)
            for k in ("User", "Entrypoint", "Cmd", "WorkingDir", "Env", "ExposedPorts")
        )
    ):
        raise Rejected("coredns_image_lineage_or_runtime_config")

    cache = run / "cache"
    cache.mkdir(mode=0o700)
    code, _ = audit.scanner(
        run,
        "db-update",
        audit.GRYPE_IMAGE,
        ["db", "update"],
        [(cache, "/cache", True)],
        network=True,
    )
    if code:
        raise Rejected("coredns_db_update")
    before = audit.snapshot(cache)
    db_sha = before["6/vulnerability.db"]
    scans = {}
    for label, ref, details, expected, match in (
        ("source", COREDNS_REFERENCE, source, SOURCE_ELF, coredns_inventory_matches),
        ("candidate", config, candidate, checksum.split()[0], inventory_matches),
    ):
        report = scan_image(run, cache, label, ref, details["Id"], inventory_matches=match)
        print(json.dumps({label: report}, sort_keys=True), flush=True)
        elf = archive_readback(run / f"{label}.tar", details, expected)
        if audit.snapshot(cache) != before:
            raise Rejected("coredns_db_changed")
        print(
            json.dumps(
                {
                    "image": label,
                    "elf_sha256": elf,
                    "capability": CAPABILITY.hex(),
                    "last_diff_id": details["RootFS"]["Layers"][-1],
                    "db_sha256": db_sha,
                }
            ),
            flush=True,
        )
        scans[label] = report
    if scans["source"]["database"] != scans["candidate"]["database"]:
        raise Rejected("coredns_db_descriptor_mismatch")
    return accepted(scans["source"]["findings"], scans["candidate"])


if __name__ == "__main__":
    passed = compare(Path(os.environ["RUNNER_TEMP"]) / "coredns-dependency")
    print(json.dumps({"paired_gate_passed": passed, "release_ready": False}))
    raise SystemExit(0 if passed else 1)
