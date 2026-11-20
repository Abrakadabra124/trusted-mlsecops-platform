"""Exact public source-only image handoff, before any candidate or secret input."""

import gzip
import hashlib
import re
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, require_fields
from mlsecops.inventory import command, source_fingerprint
from scripts.image_audit import execute

IMAGE = "trusted-mlsecops:dev"
ARCHIVE_LIMIT = 384 * 1024**2
TAR_LIMIT = 2 * 1024**3
CONTEXT_LIMIT = 64 * 1024**2
METADATA_LIMIT = 1024**2
MEMBER_LIMIT = 1024
RECIPES = {
    "Dockerfile": "44dd7a958f02b459ed967ec61aa6c9b88458aef0efadbcc3bbea70b41c10d2f3",
    ".dockerignore": "213fe4f2ab6ee3378ca387862cdee1047cc0620042108f56ffc9b590631c4458",
}
INPUTS = frozenset(
    (*RECIPES, "pyproject.toml", "uv.lock", ".python-version", "policies/local-cpu.json")
)
FILES = frozenset(
    ("owner.json", "image.tar", "image.tar.gz", "image.log", "probe.out", "probe.log", "probe.cid")
)


def need(value):
    if not value:
        raise Rejected("ci_source_image_rejected")


def hexadecimal(value, length):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{" + str(length) + r"}", value) is not None


def file_pin(path, limit):
    path = Path(path)
    need(not path.is_symlink() and not path.parent.is_symlink())
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit)
    hashed, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024**2):
            size += len(chunk)
            need(size <= limit)
            hashed.update(chunk)
    after = path.stat()
    need(
        size == before.st_size
        and all(
            getattr(before, k) == getattr(after, k)
            for k in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        )
    )
    return hashed.hexdigest(), size


def source_contract(root):
    root = Path(root).resolve()
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    need(hexadecimal(revision, 40))
    need(not command(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"]))
    files = command(["git", "-C", str(root), "ls-tree", "-r", "--name-only", "HEAD"]).splitlines()
    selected = sorted(
        p for p in files if p in INPUTS or re.fullmatch(r"mlsecops/[A-Za-z0-9_]+\.py", p)
    )
    need(INPUTS.issubset(selected) and any(p.startswith("mlsecops/") for p in selected))
    for name, expected in RECIPES.items():
        need(digest(bounded_read(root / name, METADATA_LIMIT).replace(b"\r\n", b"\n")) == expected)
    return dict(revision=revision, fingerprint=source_fingerprint(root), files=selected)


def build_context(root, directory, source):
    """Only committed allowlisted files enter Docker; ignored local files never do."""
    archive = directory / "source.tar"
    command(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.eol=lf",
            "archive",
            "--format=tar",
            "--output",
            str(archive),
            source["revision"],
            "--",
            *source["files"],
        ]
    )
    file_pin(archive, CONTEXT_LIMIT)
    target = directory / "context"
    target.mkdir()
    found = set()
    with tarfile.open(archive, "r:") as packed:
        for member in packed:
            if member.isdir():
                need(member.name in ("mlsecops", "policies"))
                continue
            need(member.name in source["files"] and member.name not in found)
            need(member.isfile() and 0 <= member.size <= METADATA_LIMIT)
            content = packed.extractfile(member).read(METADATA_LIMIT + 1)
            need(len(content) == member.size)
            path = target / member.name
            path.parent.mkdir(exist_ok=True)
            with path.open("xb") as output:
                output.write(content)
            found.add(member.name)
    need(found == set(source["files"]))
    need(source_fingerprint(target) == source["fingerprint"])
    for name, expected in RECIPES.items():
        need(digest(bounded_read(target / name, METADATA_LIMIT)) == expected)
    return target


def image_identity(details, source, identifier=None):
    need(type(details) is dict)
    observed = details.get("Id")
    need(type(observed) is str and observed.startswith("sha256:") and hexadecimal(observed[7:], 64))
    need(identifier is None or observed == identifier)
    need(details.get("Os") == "linux" and details.get("Architecture") == "amd64")
    config = details.get("Config")
    need(type(config) is dict and config.get("User") == "65532:65532")
    labels = config.get("Labels")
    need(type(labels) is dict)
    need(labels.get("org.opencontainers.image.revision") == source["revision"])
    need(labels.get("org.trusted-mlsecops.source-fingerprint") == source["fingerprint"])
    return observed


def validate_receipt(receipt, source):
    need(type(receipt) is dict)
    require_fields(
        receipt,
        (
            "schema_version",
            "source_revision",
            "source_fingerprint",
            "image_id",
            "archive_sha256",
            "archive_bytes",
            "tar_sha256",
            "tar_bytes",
        ),
    )
    need(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1)
    need(
        receipt["source_revision"] == source["revision"]
        and hexadecimal(receipt["source_revision"], 40)
    )
    need(
        receipt["source_fingerprint"] == source["fingerprint"]
        and hexadecimal(receipt["source_fingerprint"], 64)
    )
    identifier = receipt["image_id"]
    need(
        type(identifier) is str
        and identifier.startswith("sha256:")
        and hexadecimal(identifier[7:], 64)
    )
    for name, limit in (("archive", ARCHIVE_LIMIT), ("tar", TAR_LIMIT)):
        need(hexadecimal(receipt[name + "_sha256"], 64))
        size = receipt[name + "_bytes"]
        need(type(size) is int and 0 < size <= limit)
    return receipt


def archive_identity(path, receipt):
    """Inspect outer entries without extracting layers into the host filesystem."""
    try:
        with tarfile.open(path, "r:") as archive:
            members = {}
            for member in archive:
                name = member.name
                need(name not in members and len(members) < MEMBER_LIMIT)
                need(
                    not PurePosixPath(name).is_absolute()
                    and ".." not in PurePosixPath(name).parts
                    and "\\" not in name
                )
                if member.isdir():
                    need(name in ("blobs", "blobs/sha256") or hexadecimal(name, 64))
                else:
                    need(member.isfile() and 0 <= member.size <= TAR_LIMIT)
                    need(
                        name in ("manifest.json", "repositories", "index.json", "oci-layout")
                        or re.fullmatch(
                            r"(?:blobs/sha256/[a-f0-9]{64}|[a-f0-9]{64}\.json|[a-f0-9]{64}/(?:VERSION|json|layer.tar))",
                            name,
                        )
                    )
                members[name] = member

            def read(name):
                member = members[name]
                need(member.isfile() and member.size <= METADATA_LIMIT)
                return archive.extractfile(member).read(METADATA_LIMIT + 1)

            manifest = decode(read("manifest.json"))
            need(type(manifest) is list and len(manifest) == 1 and type(manifest[0]) is dict)
            need(manifest[0].get("RepoTags") in (None, []))
            layers = manifest[0]["Layers"]
            need(type(layers) is list and len(layers) > 0 and len(set(layers)) == len(layers))
            need(all(members[name].isfile() for name in layers))
            raw = read(manifest[0]["Config"])
            identifier = "sha256:" + digest(raw)
            config = decode(raw)
            image_identity(
                dict(
                    Id=identifier,
                    Os=config["os"],
                    Architecture=config["architecture"],
                    Config=config["config"],
                ),
                dict(
                    revision=receipt["source_revision"], fingerprint=receipt["source_fingerprint"]
                ),
                receipt["image_id"],
            )
            return identifier
    except (OSError, tarfile.TarError, KeyError, TypeError, AttributeError, ValueError):
        raise Rejected("ci_source_image_archive_invalid") from None


def compress(source, target):
    try:
        with Path(source).open("rb") as input_file, Path(target).open("xb") as output_file:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output_file, mtime=0) as output:
                while chunk := input_file.read(1024**2):
                    output.write(chunk)
                    need(output_file.tell() <= ARCHIVE_LIMIT)
        file_pin(target, ARCHIVE_LIMIT)
    except OSError:
        raise Rejected("ci_source_image_compression_failed") from None


def decompress(source, target):
    try:
        size = 0
        with gzip.open(source, "rb") as input_file, Path(target).open("xb") as output:
            while chunk := input_file.read(1024**2):
                size += len(chunk)
                need(size <= TAR_LIMIT)
                output.write(chunk)
    except (OSError, EOFError):
        raise Rejected("ci_source_image_decompression_failed") from None


def absent_image():
    need(not command(["docker", "image", "ls", "--no-trunc", "--format", "{{.ID}}", IMAGE]))


def classic_store():
    # The ordinary platform pins config IDs. containerd's manifest/index ID is different.
    info = decode(command(["docker", "info", "--format", "{{json .}}"]).encode())
    need(type(info) is dict and info.get("OSType") == "linux" and info.get("Driver") == "overlay2")


def workspace_create(directory, owner):
    directory = Path(directory)
    need(hexadecimal(owner, 64))
    need(
        not directory.is_symlink() and not directory.parent.is_symlink() and not directory.exists()
    )
    directory.mkdir(mode=0o700, parents=True)
    with (directory / "owner.json").open("xb") as output:
        output.write(canonical(dict(schema_version=1, owner=owner)))


def workspace_check(directory, owner):
    directory = Path(directory)
    need(hexadecimal(owner, 64))
    need(not directory.is_symlink() and not directory.parent.is_symlink())
    marker = directory / "owner.json"
    need(marker.is_file())
    file_pin(marker, 1024)
    need(bounded_read(marker, 1024) == canonical(dict(schema_version=1, owner=owner)))


def prepare(root, directory, *, owner):
    root, directory = Path(root).resolve(), Path(directory)
    source = source_contract(root)
    workspace_create(directory, owner)
    classic_store()
    absent_image()
    with tempfile.TemporaryDirectory(prefix="source-build-", dir=directory) as temporary:
        context = build_context(root, Path(temporary), source)
        command(
            [
                "docker",
                "build",
                "--platform",
                "linux/amd64",
                "-t",
                IMAGE,
                "--label",
                "org.opencontainers.image.revision=" + source["revision"],
                "--label",
                "org.trusted-mlsecops.source-fingerprint=" + source["fingerprint"],
                str(context),
            ],
            timeout=900,
        )
    details = decode(command(["docker", "image", "inspect", IMAGE]).encode())
    need(type(details) is list and len(details) == 1)
    identifier = image_identity(details[0], source)
    tar = directory / "image.tar"
    need(execute(["docker", "image", "save", identifier], tar, 300, output_limit=TAR_LIMIT) == 0)
    tar_pin, tar_size = file_pin(tar, TAR_LIMIT)
    receipt = dict(
        schema_version=1,
        source_revision=source["revision"],
        source_fingerprint=source["fingerprint"],
        image_id=identifier,
        tar_sha256=tar_pin,
        tar_bytes=tar_size,
    )
    archive_identity(tar, receipt)
    compressed = directory / "image.tar.gz"
    compress(tar, compressed)
    pin, size = file_pin(compressed, ARCHIVE_LIMIT)
    receipt.update(archive_sha256=pin, archive_bytes=size)
    validate_receipt(receipt, source)
    return receipt


def receive(root, directory, expected, *, owner):
    directory = Path(directory)
    workspace_check(directory, owner)
    need({p.name for p in directory.iterdir()} == {"owner.json", "image.tar.gz"})
    source = source_contract(root)
    receipt = validate_receipt(expected, source)
    compressed, tar = directory / "image.tar.gz", directory / "image.tar"
    need(
        file_pin(compressed, ARCHIVE_LIMIT) == (receipt["archive_sha256"], receipt["archive_bytes"])
    )
    decompress(compressed, tar)
    need(file_pin(tar, TAR_LIMIT) == (receipt["tar_sha256"], receipt["tar_bytes"]))
    need(
        file_pin(compressed, ARCHIVE_LIMIT) == (receipt["archive_sha256"], receipt["archive_bytes"])
    )
    archive_identity(tar, receipt)
    classic_store()
    absent_image()
    command(["docker", "image", "load", "--input", str(tar)], timeout=300)
    details = decode(command(["docker", "image", "inspect", receipt["image_id"]]).encode())
    need(type(details) is list and len(details) == 1)
    identifier = image_identity(details[0], source, receipt["image_id"])
    command(["docker", "image", "tag", identifier, IMAGE])
    probe_name = "trusted-source-image-" + owner
    arguments = [
        "docker",
        "run",
        "--name",
        probe_name,
        "--cidfile",
        str(directory / "probe.cid"),
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65532:65532",
        "--pids-limit",
        "64",
        "--cpus",
        "2",
        "--memory",
        "1g",
        "--memory-swap",
        "1g",
        "--log-driver",
        "none",
        identifier,
        "python",
        "-m",
        "mlsecops.worker",
        "--help",
    ]
    cidfile = directory / "probe.cid"
    try:
        need(execute(arguments, directory / "probe.out", 60, cidfile=cidfile) == 0)
        need(cidfile.is_file())
    finally:
        selected = "name=^/" + probe_name + "$"
        invalid_cid = False
        if cidfile.is_file():
            try:
                container_id = bounded_read(cidfile, 128).decode("ascii").strip()
                need(hexadecimal(container_id, 64))
                selected = "id=" + container_id
            except (Rejected, OSError, UnicodeError):
                invalid_cid = True
        need(
            not command(
                [
                    "docker",
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--no-trunc",
                    "--filter",
                    selected,
                ]
            )
        )
        need(not invalid_cid)
    return receipt


def cleanup(directory, *, owner):
    directory = Path(directory)
    need(not directory.is_symlink() and not directory.parent.is_symlink())
    if not directory.exists():
        return 0
    workspace_check(directory, owner)
    entries = list(directory.iterdir())
    for path in entries:
        need(
            path.name in FILES
            and not path.is_symlink()
            and path.is_file()
            and path.stat().st_nlink == 1
        )
    for path in sorted(entries, key=lambda p: p.name == "owner.json"):
        path.unlink()
    directory.rmdir()
    return len(entries)
