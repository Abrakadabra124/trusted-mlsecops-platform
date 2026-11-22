"""One hosted, diagnostic Debian update on the stock Kubernetes 1.36.4 node."""

import gzip
import hashlib
import io
import json
import lzma
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
from collections import Counter
from contextlib import contextmanager, nullcontext
from email.parser import Parser
from pathlib import Path, PurePosixPath

from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest
from mlsecops.inventory import command
from scripts import image_audit as audit
from scripts.image_audit_contract import exact_observation_matches
from scripts.image_node_candidate import IMAGES

CONFIG = "sha256:0fa975026f71246c4e4744409d43e2e5884bb6e960851b438e50f455808c16f4"
AMD64 = "kindest/node@sha256:597367624b4748b74b98e4fe2d661cd78063d02ecdaca702fd90572375b83e67"
LAYERS = (
    "sha256:3bad97b3839d8db1c9774f6254920644439a7fe536d760b3c359b8daf771c669",
    "sha256:c4ae34e5be876a124b71c4ff6d469ad0597e95cf80ff7d1d04d5b71aa75e164f",
)
# Complete, path-specific baseline observation from run 45030124975.
OBSERVATION = "cc0a096d336ebfd066edf84620be5f8ff8108cc83e722a1f922f2074df96f684"
CVES = ("CVE-2026-63073", "CVE-2026-75803")
OLD, FIX, NEW = "3.5.6-1~deb13u2", "3.5.7-1~deb13u2", "3.5.9-1~deb13u1"
DEB = {
    "libssl3t64": (2464736, "ffefb9af363e0e4592251b2533eb06453c8e470f7772e40263c4b2129251a6d5"),
    "openssl": (1518324, "faf53a993766c81f94f35b6a31202f0dcd936e1529791790a393aa59f41c0993"),
    "openssl-provider-legacy": (
        322440,
        "67c70904c8d494b4631e136a6bdb692cbb44515757d63c55e7bd1d2016f9f09f",
    ),
}
SNAPSHOT = "https://snapshot.debian.org/archive/debian/20261122T000000Z/"
RELEASE = (140420, "bfacad4ca61899ce20d4a0d439f29339f66541561b67506364efb88e27dee870")
INDEX = (9679304, "be3d7d96a040eda0505c1808cccc67f183bbc05dff0842c50f88e6c396557412")
KEYS = {
    "archive-key-12": (11861, "c2a9a16fde95e037bafd0fa6b7e31f41b4ff1e85851de5558f19a2a2f0e955e2"),
    "archive-key-13": (11861, "6f1d277429dd7ffedcc6f8688a7ad9a458859b1139ffa026d1eeaadcbffb0da7"),
    "release-13": (1384, "4d097bb93f83d731f475c5b92a0c2fcf108cfce1d4932792fca72d00b48d198b"),
}
COPYRIGHT = (2543, "6a7da622fe0637a334d2a8fc470852d2ffb77d9a2b2f930f854e32a41ad6ef35")
LICENSE_PATHS = {name: f"usr/share/doc/{name}/copyright" for name in DEB}
RECIPE = Path(__file__).resolve().parents[1] / "images/candidates/node-openssl/Dockerfile"
LOCAL = "trusted-mlsecops:node-1364-openssl-candidate"


def fetch(url, pin):
    size, checksum = pin
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(size + 1)
    if len(data) != size or digest(data) != checksum:
        raise Rejected("debian_material_mismatch")
    return data


def package_paths(release, index):
    path = "main/binary-amd64/Packages.xz"
    if not re.search(rf"^ {INDEX[1]} +{INDEX[0]} {re.escape(path)}$", release.decode(), re.M):
        raise Rejected("debian_index_binding_invalid")
    matched = {}
    for paragraph in lzma.decompress(index).decode().split("\n\n"):
        name = paragraph.partition("\n")[0].removeprefix("Package: ")
        if name not in DEB:
            continue
        fields = Parser().parsestr(paragraph)
        filename = f"pool/main/o/openssl/{name}_{NEW}_amd64.deb"
        if (
            name in matched
            or fields["Architecture"] != "amd64"
            or fields["Version"] != NEW
            or fields.get("Source", name) != "openssl"
            or fields["Filename"] != filename
            or (int(fields["Size"]), fields["SHA256"]) != DEB[name]
        ):
            raise Rejected("debian_package_binding_invalid")
        matched[name] = filename
    if matched.keys() != DEB.keys():
        raise Rejected("debian_package_set_invalid")
    return matched


def prepare(run, context):
    release = fetch(SNAPSHOT + "dists/trixie/InRelease", RELEASE)
    (run / "InRelease").write_bytes(release)
    with (run / "keys.gpg").open("xb") as keys:
        for name, pin in KEYS.items():
            armor = fetch(f"https://ftp-master.debian.org/keys/{name}.asc", pin)
            keys.write(
                subprocess.check_output(["gpg", "--batch", "--dearmor"], input=armor, timeout=30)
            )
    subprocess.run(
        ["gpgv", "--keyring", "./keys.gpg", "InRelease"], cwd=run, check=True, timeout=30
    )
    index = fetch(SNAPSHOT + "dists/trixie/main/binary-amd64/Packages.xz", INDEX)
    for name, path in package_paths(release, index).items():
        (context / Path(path).name).write_bytes(fetch(SNAPSHOT + path, DEB[name]))


def check_inventory(source, candidate, candidate_id):
    if (
        source["image_id"] != CONFIG
        or candidate["image_id"] != candidate_id
        or candidate_id == CONFIG
        or not exact_observation_matches(source, 878, OBSERVATION)
    ):
        raise Rejected("node_source_inventory_mismatch")
    expected_rows = []
    for package in source["packages"]:
        if package["type"] == "deb" and package["name"] in DEB:
            # Each signed deb installs its own copyright file, absent from the stock observation.
            license_path = "/" + LICENSE_PATHS[package["name"]]
            package = {
                **package,
                "version": NEW,
                "paths": sorted([*package["paths"], license_path]),
            }
        expected_rows.append(package)
    expected = {
        **source,
        "image_id": candidate_id,
        "packages": sorted(expected_rows, key=canonical),
    }
    if not exact_observation_matches(candidate, 878, digest(canonical(expected))):
        raise Rejected("node_package_delta_mismatch")


def target_rows(findings):
    return [f for f in findings if f["package"] in DEB and f["id"] in CVES]


def other_rows(observation):
    return sorted(
        canonical(r)
        for r in observation["packages"]
        if not (r["type"] == "deb" and r["name"] in DEB)
    )


def bounded_delta(left, right):
    difference = Counter(left) - Counter(right)
    sample = [
        {"count": count, "row": decode(row) if len(row) <= 1024 else {"sha256": digest(row)}}
        for row, count in sorted(difference.items())[:8]
    ]
    return {"count": difference.total(), "sample": sample}


def check_findings(source, candidate):
    expected = [
        {
            "package": name,
            "type": "deb",
            "id": cve,
            "installed": OLD,
            "severity": "Critical",
            "fix": {"state": "fixed", "versions": [FIX]},
        }
        for name in DEB
        for cve in CVES
    ]
    if sorted(target_rows(source), key=canonical) != sorted(expected, key=canonical):
        raise Rejected("node_openssl_positive_control_changed")
    if target_rows(candidate):
        raise Rejected("node_openssl_residual_finding")


def check_oci(base, candidate):
    if base["rootfs"] != {"type": "layers", "diff_ids": list(LAYERS)}:
        raise Rejected("node_base_layers_changed")
    layers = candidate["rootfs"]["diff_ids"]
    if (
        candidate["config"] != base["config"]
        or candidate["rootfs"]["type"] != "layers"
        or layers[:-1] != list(LAYERS)
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", layers[-1])
    ):
        raise Rejected("node_runtime_config_or_layers_changed")


def check_license(tar, member):
    size, checksum = COPYRIGHT
    if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.size != size:
        raise Rejected("node_license_type_or_size_mismatch")
    if digest(tar.extractfile(member).read(size + 1)) != checksum:
        raise Rejected("node_license_content_mismatch")


def directory_record(member):
    # Tar's path/owner serialization is already decoded by TarInfo. Retain all
    # other non-time PAX fields, including xattrs, ACLs and filesystem flags.
    times = {
        k: v
        for k, v in member.pax_headers.items()
        if k in {"mtime", "atime", "ctime", "LIBARCHIVE.creationtime"}
    }
    times.setdefault("mtime", str(member.mtime))
    extra = {
        k: v
        for k, v in member.pax_headers.items()
        if k not in times and k not in {"path", "uid", "gid", "uname", "gname", "size"}
    }
    xattrs = {
        k: v for k, v in extra.items() if k.startswith(("SCHILY.xattr.", "LIBARCHIVE.xattr."))
    }
    return {
        "type": "directory",
        "mode": format(stat.S_IMODE(member.mode), "04o"),
        "uid": member.uid,
        "gid": member.gid,
        "xattrs_count": len(xattrs),
        "xattrs_sha256": digest(canonical(xattrs)),
        "pax_sha256": digest(canonical(extra)),
    }, times


def apply_base_layer(state, layer):
    """Apply removals to the lower view before adding entries from this layer."""
    entries, hidden, opaque = {}, set(), set()
    with tarfile.open(fileobj=layer, mode="r|*", bufsize=1024**2) as tar:
        for member in tar:
            path = PurePosixPath(member.name)
            if path.name == ".wh..wh..opq":
                opaque.add(path.parent)
            elif path.name.startswith(".wh."):
                hidden.add(path.with_name(path.name[4:]))
            else:
                if member.isdir():
                    record = directory_record(member)
                else:
                    hidden.add(path)
                    record = ({"type": member.type.decode("ascii")}, {})
                entries[str(path)] = record
    if state and (hidden or opaque):
        ancestors = hidden | opaque
        for name in list(state):
            path = PurePosixPath(name)
            if path in hidden or any(parent in ancestors for parent in path.parents):
                del state[name]
    state.update(entries)


@contextmanager
def verified_layer(archive, name, diff_id):
    with archive.extractfile(name) as blob:
        compressed = blob.peek(2)[:2] == b"\x1f\x8b"
        with gzip.GzipFile(fileobj=blob) if compressed else nullcontext(blob) as stream:
            if "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest() != diff_id:
                raise Rejected("node_layer_diff_id_mismatch")
            stream.seek(0)
            yield stream


def package_files(context):
    directories = {}
    allowed = {
        "var/log/dpkg.log",
        "var/lib/dpkg/status",
        "var/lib/dpkg/status-old",
        "var/lib/dpkg/lock",
        "var/lib/dpkg/lock-frontend",
        "var/lib/dpkg/triggers/Lock",
        "var/lib/dpkg/triggers/Unincorp",
        "etc/ld.so.cache",
        "var/cache/ldconfig/aux-cache",
        "usr/lib/ssl",
    }
    for name in DEB:
        path = context / f"{name}_{NEW}_amd64.deb"
        if (path.stat().st_size, audit.file_hash(path)) != DEB[name]:
            raise Rejected("debian_material_mismatch")
        payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", path], timeout=30)
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as tar:
            licenses = 0
            for member in tar:
                location = str(PurePosixPath(member.name))
                if location == LICENSE_PATHS[name]:
                    check_license(tar, member)
                    licenses += 1
                if member.isdir():
                    attributes, _ = directory_record(member)
                    if directories.setdefault(location, attributes) != attributes:
                        raise Rejected("node_signed_directory_metadata_ambiguous")
                else:
                    allowed.add(location)
            if licenses != 1:
                raise Rejected("node_deb_license_set_mismatch")
        for suffix in ("list", "md5sums", "conffiles", "postinst", "shlibs", "symbols", "triggers"):
            allowed.update(f"var/lib/dpkg/info/{name}{arch}.{suffix}" for arch in ("", ":amd64"))
    return allowed, directories


def check_overlay(layer, allowed, directories, base):
    licenses, seen = [], set()
    errors, samples, reemitted = 0, [], []

    def issue(path, kind, reason, **facts):
        nonlocal errors
        errors += 1
        if len(samples) < 24:
            samples.append({"path": path[:192], "type": kind, "reason": reason, **facts})

    with tarfile.open(fileobj=layer, mode="r|*") as tar:
        for member in tar:
            path = str(PurePosixPath(member.name))
            previous, old_times = base.get(path, (None, {}))
            kind = "directory" if member.isdir() else member.type.decode("ascii")
            if path in seen:
                issue(path, kind, "duplicate")
            seen.add(path)
            if PurePosixPath(path).name.startswith(".wh."):
                issue(path, kind, "whiteout")
            elif member.isdir():
                current, new_times = directory_record(member)
                required = previous if previous is not None else directories.get(path)
                if current != required:
                    issue(
                        path,
                        kind,
                        "directory_metadata",
                        before=previous,
                        after=current,
                        signed=directories.get(path),
                    )
                elif path not in directories and len(reemitted) < 24:
                    reemitted.append(
                        {
                            "path": path[:192],
                            **current,
                            "before_times": old_times,
                            "after_times": new_times,
                        }
                    )
            elif path not in allowed or (previous and previous["type"] == "directory"):
                issue(path, kind, "unexpected_file_or_directory_replacement")
            if path in LICENSE_PATHS.values():
                try:
                    check_license(tar, member)
                except Rejected as error:
                    issue(path, kind, str(error))
                else:
                    licenses.append(path)
    if sorted(licenses) != sorted(LICENSE_PATHS.values()):
        issue("copyright", "set", "node_overlay_license_set_mismatch")
    print(
        json.dumps(
            {
                "overlay_errors": errors,
                "sample": samples,
                "repeated_directories": reemitted,
                "license_readback": [
                    {"path": p, "type": "regular", "size": COPYRIGHT[0], "sha256": COPYRIGHT[1]}
                    for p in sorted(set(licenses))
                ],
            },
            sort_keys=True,
        ),
        flush=True,
    )
    if errors:
        raise Rejected("node_overlay_mismatch")


def verify_archive_overlay(path, config, context):
    ids = config["rootfs"]["diff_ids"]
    with tarfile.open(path, "r:") as archive:
        (entry,) = json.load(archive.extractfile("manifest.json"))
        layers = entry["Layers"]
        if ids[:-1] != list(LAYERS) or len(layers) != len(ids):
            raise Rejected("node_layer_set_mismatch")
        base = {}
        for name, diff_id in zip(layers[:-1], LAYERS, strict=True):
            with verified_layer(archive, name, diff_id) as layer:
                apply_base_layer(base, layer)
        with verified_layer(archive, layers[-1], ids[-1]) as layer:
            check_overlay(layer, *package_files(context), base)


def measure(run, cache, db_files, name, image):
    details = audit.inspect_image(image)
    archive = run / f"{name}.tar"
    command(["docker", "image", "save", "-o", str(archive), details["Id"]], timeout=420)
    config_id = audit.identity(archive, details)
    if config_id != details["Id"]:
        raise Rejected("node_archive_config_mismatch")
    with tarfile.open(archive, "r:") as tar:
        (entry,) = json.load(tar.extractfile("manifest.json"))
        content = tar.extractfile(entry["Config"]).read(1024**2 + 1)
    if "sha256:" + digest(content) != config_id:
        raise Rejected("node_archive_config_mismatch")
    code, path = audit.scanner(
        run,
        name + "-sbom",
        audit.SYFT_IMAGE,
        ["docker-archive:/input/image.tar", "-o", "syft-json"],
        [(archive, "/input/image.tar", False)],
    )
    if code:
        raise Rejected("node_sbom_failed")
    if name == "source":
        archive.unlink()
    sbom_bytes = bounded_read(path, audit.LIMIT)
    sbom = decode(sbom_bytes, audit.LIMIT)
    observation = audit.observe_packages(sbom, config_id)
    code, scan = audit.scanner(
        run,
        name + "-scan",
        audit.GRYPE_IMAGE,
        ["sbom:/input/sbom.json", "--fail-on", "high", "-o", "json"],
        [(cache, "/cache", False), (path, "/input/sbom.json", False)],
    )
    result = audit.assess(
        sbom,
        decode(bounded_read(scan, audit.LIMIT), audit.LIMIT),
        config_id,
        set(),
        code,
        diagnostic_only=True,
    )
    if audit.snapshot(cache) != db_files or audit.file_hash(path) != digest(sbom_bytes):
        raise Rejected("node_scan_input_changed")
    result.update(sbom_sha256=digest(sbom_bytes), grype_sha256=audit.file_hash(scan))
    return decode(content), observation, result


def qualify(run):
    context, cache = run / "debs", run / "cache"
    context.mkdir()
    cache.mkdir()
    prepare(run, context)
    for image in (IMAGES["baseline"], AMD64, audit.SYFT_IMAGE, audit.GRYPE_IMAGE):
        command(["docker", "pull", "--platform", "linux/amd64", image], timeout=360)
    if any(audit.inspect_image(ref)["Id"] != CONFIG for ref in (IMAGES["baseline"], AMD64)):
        raise Rejected("node_baseline_identity_mismatch")
    subprocess.run(
        [
            "docker",
            "buildx",
            "build",
            "--load",
            "--provenance=false",
            "--network=none",
            "--platform=linux/amd64",
            "--no-cache",
            "-f",
            str(RECIPE),
            "-t",
            LOCAL,
            str(context),
        ],
        check=True,
        timeout=600,
    )
    code, _ = audit.scanner(
        run,
        "db-update",
        audit.GRYPE_IMAGE,
        ["db", "update"],
        [(cache, "/cache", True)],
        network=True,
    )
    if code:
        raise Rejected("node_db_update_failed")
    db_files = audit.snapshot(cache)
    base, source_obs, source = measure(run, cache, db_files, "source", CONFIG)
    new, cand_obs, candidate = measure(run, cache, db_files, "candidate", LOCAL)
    for label, config, result, obs in (
        ("source", base, source, source_obs),
        ("candidate", new, candidate, cand_obs),
    ):
        others = other_rows(obs)
        print(
            json.dumps(
                {
                    "role": label,
                    "other_rows": len(others),
                    "other_rows_sha256": digest(b"[" + b",".join(others) + b"]"),
                    **{
                        k: result[k]
                        for k in (
                            "image_id",
                            "database",
                            "scanner_exit_code",
                            "status",
                            "severity_counts",
                            "packages",
                            "package_types",
                            "sbom_sha256",
                            "grype_sha256",
                        )
                    },
                    "diff_ids": config["rootfs"]["diff_ids"],
                    "openssl": target_rows(result["findings"]),
                    "observed": [
                        r for r in obs["packages"] if r["type"] == "deb" and r["name"] in DEB
                    ],
                },
                sort_keys=True,
            ),
            flush=True,
        )
    print(
        json.dumps({"database_files": db_files, "release_ready": False}, sort_keys=True), flush=True
    )
    if source["database"] != candidate["database"]:
        raise Rejected("node_db_descriptor_changed")
    before, after = other_rows(source_obs), other_rows(cand_obs)
    if before != after:
        print(
            json.dumps(
                {
                    "other_rows_removed": bounded_delta(before, after),
                    "other_rows_added": bounded_delta(after, before),
                },
                sort_keys=True,
            ),
            flush=True,
        )
    check_oci(base, new)
    verify_archive_overlay(run / "candidate.tar", new, context)
    check_inventory(source_obs, cand_obs, candidate["image_id"])
    check_findings(source["findings"], candidate["findings"])
    print(
        "Targeted OpenSSL comparison passed. Candidate policy status:",
        candidate["status"],
        flush=True,
    )
    return 0 if candidate["status"] == "pass" else 1


if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
        raise SystemExit("Disposable Linux Actions runner required")
    with tempfile.TemporaryDirectory(prefix="kind-openssl-") as directory:
        raise SystemExit(qualify(Path(directory)))
