"""Prepare the four Ubuntu package records evidenced in the static Cilium donor bpftool."""

import gzip
import io
import shutil
import struct
import subprocess
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass
from email.parser import Parser
from pathlib import Path

from mlsecops.contracts import Rejected, decode, digest

PACKAGES = {
    "libc6-dev": ("glibc", "2.39-0ubuntu8.3"),
    "libelf-dev": ("elfutils", "0.190-1.1build4"),
    "zlib1g-dev": ("zlib", "1:1.3.dfsg-3.1ubuntu2.1"),
    "libzstd-dev": ("libzstd", "1.5.5+dfsg2-2build1.1"),
}
BINARY_SHA256 = "023276e781975b6e4ca5ab3ac39855f831f6132eb57e6e0b141018e92c2aabed"

_SNAPSHOT = "https://snapshot.ubuntu.com/ubuntu/20241119T165000Z/"
_REGISTRY = "https://quay.io/v2/cilium/cilium-bpftool/"
_MANIFEST = "427a210be922aecbb5162810ef04296b399bb981cca954bbece60b5057e60641"
_CONFIG = "efd788a8bb6cfc8a0dcbf36b97e59a262968b9d3786def94472be794bc591315"
_LAYER = "0fc776aac493b53bb745dee2bf518f10d3f4da3780642f59f74c86f511c1de85"
_DIFF_ID = "d537d9c184bcf2de1b302d3e57eec35080f8bb8c5aa551e9455efc013329ff6c"
_OS_RELEASE = 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n'


@dataclass(frozen=True)
class _Material:
    deb_path: str
    deb_size: int
    deb_sha: str
    archive_name: str
    archive_size: int
    archive_sha: str
    member: str
    member_start: int
    member_sha: str
    object_offset: int
    elf_offset: int
    length: int
    witness_sha: str


# Ubuntu InRelease -> Packages -> DEB and builder/object readback in receipt SHA-256
# 5eb0f575d1045750b2a04df43a494411540448feb48692d7803357ab76351096.
_MATERIALS = {
    "libc6-dev": _Material(
        deb_path="pool/main/g/glibc/libc6-dev_2.39-0ubuntu8.3_amd64.deb",
        deb_size=2164072,
        deb_sha="2fa5027a8251b3aab324ecc5ff9d85215d109ea157d9eb765700b75c4d99c8fc",
        archive_name="libc.a",
        archive_size=6134904,
        archive_sha="6b62accf9b523ffe954cbe797b63d05d31a7d9f1114be1c9db33e020a22ad93f",
        member="strcmp-avx2.o",
        member_start=2813512,
        member_sha="bd49310eccb3a9e09f947cc16b0fd529822221bf83dda1125b22f34f23fa09e2",
        object_offset=96,
        elf_offset=4579696,
        length=1365,
        witness_sha="efe72148f9518493150860e6a0251517444bcbe2dbecb6ed0f629aea8c8f1852",
    ),
    "libelf-dev": _Material(
        deb_path="pool/main/e/elfutils/libelf-dev_0.190-1.1build4_amd64.deb",
        deb_size=68546,
        deb_sha="540ef7d433b642c9333374e9580dd3cc21b1ef9532787d994998b5131ef82ea4",
        archive_name="libelf.a",
        archive_size=300178,
        archive_sha="830e67ec963f31e015f76863394d8313e3b7d5232bab1ce6e5efdf3f684e6019",
        member="gelf_xlate.o",
        member_start=48922,
        member_sha="8d795ea0142d8c7dce6cb1d84ae46f97738ef0c76db99bdfbe7d7bd77695c638",
        object_offset=3104,
        elf_offset=503184,
        length=580,
        witness_sha="904c0d421a2639b726d09357f0404f168599a786c80101c6d62547a45b4830ed",
    ),
    "zlib1g-dev": _Material(
        deb_path="pool/main/z/zlib/zlib1g-dev_1.3.dfsg-3.1ubuntu2.1_amd64.deb",
        deb_size=894070,
        deb_sha="023cbe9dbf0af87f10e54e342c67571874e412b9950d89c6cd7b010be2e67c3c",
        archive_name="libz.a",
        archive_size=147056,
        archive_sha="436f7e661f703c8959b1e7a77b0450fd9b89ccafce9736804665c27f1bfb27b2",
        member="adler32.o",
        member_start=1888,
        member_sha="fea4c2f34474e790bf4c0750864479672439bf25e11ea63605f7886a510c5071",
        object_offset=64,
        elf_offset=3702448,
        length=1716,
        witness_sha="1d238b00ed5d06f8dff6c5817b1e96cd3a2f32c78b824467198c383098f5abce",
    ),
    "libzstd-dev": _Material(
        deb_path="pool/main/libz/libzstd/libzstd-dev_1.5.5+dfsg2-2build1.1_amd64.deb",
        deb_size=363956,
        deb_sha="6c9d2b5677a4677e9ead62f74723bb919113621a8028ed543a4d78952d54d165",
        archive_name="libzstd.a",
        archive_size=964146,
        archive_sha="3b002d21b06091605db4a98c3739b479bd1126bac91b389a9e4a9e75612848ab",
        member="zstd_fast.o",
        member_start=363910,
        member_sha="662bd4f2028eeac0b6ed320c17fb32a49cea4fad9bf655e94c71e094740745f2",
        object_offset=3872,
        elf_offset=3817168,
        length=15001,
        witness_sha="88b9b0dff710b4f9564c954c71f92121dae2140e6677e99feb8e77fb75806eb5",
    ),
}


def _fetch(url: str, size: int, sha: str) -> bytes:
    request = urllib.request.Request(url)
    if "/manifests/" in url:
        request.add_header("Accept", "application/vnd.oci.image.manifest.v1+json")
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(size + 1)
    if len(data) != size or digest(data) != sha:
        raise Rejected(f"material_size_or_sha256_mismatch: {url}")
    return data


def _tar_file(data: bytes, path: str, size: int) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        matches = [m for m in tar if m.name.removeprefix("./") == path]
        if len(matches) != 1 or not matches[0].isreg() or matches[0].size != size:
            raise Rejected(f"tar_member_mismatch: {path}")
        with tar.extractfile(matches[0]) as member:
            return member.read()


def _check_elf(data: bytes, kind: int) -> None:
    if (
        len(data) < 64
        or data[:7] != b"\x7fELF\x02\x01\x01"
        or struct.unpack_from("<HH", data, 16) != (kind, 62)
    ):
        raise Rejected("expected_little_endian_amd64_elf")


def _read_donor() -> bytes:
    manifest = decode(_fetch(f"{_REGISTRY}manifests/sha256:{_MANIFEST}", 480, _MANIFEST))
    config_desc = manifest["config"]
    layers = manifest["layers"]
    if (config_desc["digest"], config_desc["size"]) != ("sha256:" + _CONFIG, 846) or [
        (d["digest"], d["size"]) for d in layers
    ] != [("sha256:" + _LAYER, 2815864)]:
        raise Rejected("bpftool_manifest_descriptor_mismatch")
    config = decode(_fetch(f"{_REGISTRY}blobs/sha256:{_CONFIG}", 846, _CONFIG))
    if (config["os"], config["architecture"]) != ("linux", "amd64") or config["rootfs"] != {
        "type": "layers",
        "diff_ids": ["sha256:" + _DIFF_ID],
    }:
        raise Rejected("bpftool_donor_config_mismatch")
    layer = gzip.decompress(_fetch(f"{_REGISTRY}blobs/sha256:{_LAYER}", 2815864, _LAYER))
    if digest(layer) != _DIFF_ID:
        raise Rejected("bpftool_layer_diff_id_mismatch")
    binary = _tar_file(layer, "usr/local/bin/bpftool", 6767856)
    if digest(binary) != BINARY_SHA256:
        raise Rejected("bpftool_binary_sha256_mismatch")
    _check_elf(binary, 2)
    return binary


def _verify_witness(material: _Material, archive: bytes, donor: bytes) -> None:
    if (len(archive), digest(archive)) != (material.archive_size, material.archive_sha):
        raise Rejected(f"static_archive_mismatch: {material.archive_name}")
    # The four pinned members use short System V ar names. The 60-byte header
    # immediately precedes the object at the recorded start of its payload.
    start = material.member_start
    header = archive[start - 60 : start]
    if (
        not archive.startswith(b"!<arch>\n")
        or header[:16].rstrip() != (material.member + "/").encode("ascii")
        or header[58:] != b"`\n"
        or not header[48:58].strip().isdigit()
    ):
        raise Rejected(f"archive_member_identity_mismatch: {material.member}")
    size = int(header[48:58])
    obj = archive[start : start + size]
    if len(obj) != size or digest(obj) != material.member_sha:
        raise Rejected(f"archive_object_mismatch: {material.member}")
    _check_elf(obj, 1)
    source = obj[material.object_offset : material.object_offset + material.length]
    target = donor[material.elf_offset : material.elf_offset + material.length]
    if len(source) != material.length or digest(source) != material.witness_sha or source != target:
        raise Rejected(f"bpftool_witness_mismatch: {material.member}")


def _installed_stanza(name: str, control: bytes) -> str:
    stanza = control.decode("utf-8").rstrip("\n")
    fields = Parser().parsestr(stanza)
    source, version = PACKAGES[name]
    expected = {"Package": name, "Source": source, "Version": version, "Architecture": "amd64"}
    if (
        "\n\n" in stanza
        or fields.defects
        or "Status" in fields
        or any(fields.get_all(key) != [value] for key, value in expected.items())
    ):
        raise Rejected(f"deb_control_identity_mismatch: {name}")
    return stanza + "\nStatus: install ok installed"


def prepare(run: Path) -> Path:
    """Return a fresh root to mount at /input for a four-coordinate diagnostic scan."""
    run.mkdir(parents=True, exist_ok=True)
    donor = _read_donor()
    stanzas = []
    with tempfile.TemporaryDirectory(dir=run) as tmp:
        for name, material in _MATERIALS.items():
            deb = Path(tmp) / f"{name}.deb"
            deb.write_bytes(
                _fetch(_SNAPSHOT + material.deb_path, material.deb_size, material.deb_sha)
            )
            control = subprocess.check_output(["dpkg-deb", "-f", deb], timeout=30)
            stanzas.append(_installed_stanza(name, control))
            payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", deb], timeout=60)
            path = "usr/lib/x86_64-linux-gnu/" + material.archive_name
            _verify_witness(material, _tar_file(payload, path, material.archive_size), donor)

    root = Path(tempfile.mkdtemp(prefix="bpftool-input-", dir=run))
    try:
        (root / "etc").mkdir()
        (root / "etc/os-release").write_bytes(_OS_RELEASE.encode())
        dpkg = root / "var/lib/dpkg"
        dpkg.mkdir(parents=True)
        (dpkg / "status").write_bytes(("\n\n".join(stanzas) + "\n\n").encode())
    except BaseException:
        shutil.rmtree(root)
        raise
    return root
