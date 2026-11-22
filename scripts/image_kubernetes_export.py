"""Bind a containerd repack to its actual config and ordered rootfs bytes."""

import gzip
import hashlib
import re
import subprocess
import tarfile
import zlib

from mlsecops import kube_worker
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from scripts.image_kubernetes_inventory import INVENTORIES

MAX_BYTES = 4 * 1024**3
METADATA_LIMIT = 1024**2
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
RAW = {"application/vnd.oci.image.layer.v1.tar", "application/vnd.docker.image.rootfs.diff.tar"}
GZIP = {
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}


def need(ok):
    if not ok:
        raise Rejected("kubernetes_export_identity_invalid")


def hash_stream(stream, limit):
    state = hashlib.sha256()
    size = 0
    while chunk := stream.read(1024**2):
        size += len(chunk)
        need(size <= limit)
        state.update(chunk)
    return "sha256:" + state.hexdigest(), size


def verify(path, reference, config_id):
    """Reconcile verified node metadata with the exact Docker-archive view passed to Syft."""
    try:
        need(DIGEST.fullmatch(config_id))
        selected = manifest = None
        if reference == config_id:
            runtime_digest = config_id
            node_config = kube_worker.image_document(config_id)
        else:
            _, runtime_digest = reference.split("@")
            need(DIGEST.fullmatch(runtime_digest))
            selected, manifest = kube_worker.image_manifest(runtime_digest)
            need(manifest["schemaVersion"] == 2 and manifest["config"]["digest"] == config_id)
        need(not path.is_symlink() and path.is_file() and path.stat().st_size <= MAX_BYTES)
        with tarfile.open(path, "r:") as archive:
            members = {}
            for member in archive:
                need(member.name not in members and len(members) < 10000)
                members[member.name] = member

            def read_metadata(name):
                entry = members[name]
                need(entry.isfile() and 0 < entry.size <= METADATA_LIMIT)
                with archive.extractfile(entry) as stream:
                    return stream.read(METADATA_LIMIT + 1)

            images = decode(read_metadata("manifest.json"), METADATA_LIMIT)
            need(type(images) is list and len(images) == 1)
            image = images[0]
            need(image["Config"] == "blobs/sha256/" + config_id[7:])
            raw_config = read_metadata(image["Config"])
            need("sha256:" + digest(raw_config) == config_id)
            config = decode(raw_config, METADATA_LIMIT)
            if manifest is None:
                need(config == node_config)
            else:
                need(len(raw_config) == manifest["config"]["size"])
            need(
                config["os"] == "linux"
                and config["architecture"] == "amd64"
                and config["rootfs"]["type"] == "layers"
            )
            diff_ids = config["rootfs"]["diff_ids"]
            names = image["Layers"]
            need(
                type(diff_ids) is list
                and type(names) is list
                and 0 < len(diff_ids) == len(names) <= 128
            )
            if manifest is not None:
                need(type(manifest["layers"]) is list and len(manifest["layers"]) == len(names))
            blob_ids = []
            remaining = MAX_BYTES
            for index, (name, diff_id) in enumerate(zip(names, diff_ids, strict=True)):
                need(re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name) and DIGEST.fullmatch(diff_id))
                entry = members[name]
                need(entry.isfile())
                with archive.extractfile(entry) as stream:
                    stored, size = hash_stream(stream, MAX_BYTES)
                    need(name == "blobs/sha256/" + stored[7:] and size == entry.size)
                    compressed = stored != diff_id
                    if manifest is not None:
                        layer = manifest["layers"][index]
                        need(
                            layer["digest"] == stored
                            and type(layer["size"]) is int
                            and layer["size"] == size
                        )
                        need(layer["mediaType"] in GZIP | RAW)
                        compressed = layer["mediaType"] in GZIP
                    if compressed:
                        stream.seek(0)
                        with gzip.GzipFile(fileobj=stream) as plain:
                            actual, size = hash_stream(plain, remaining)
                    else:
                        actual = stored
                    need(actual == diff_id and 0 < size <= remaining)
                    remaining -= size
                    blob_ids.append(stored)
        return dict(
            runtime_digest=runtime_digest,
            selected_manifest_digest=selected,
            config_id=config_id,
            diff_ids=diff_ids,
            layer_digests=blob_ids,
        )
    except (
        OSError,
        EOFError,
        tarfile.TarError,
        zlib.error,
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        AttributeError,
        subprocess.TimeoutExpired,
    ):
        raise Rejected("kubernetes_export_identity_invalid") from None


def binding_reference(component, target):
    """Use config authority only for an evidenced local export of this exact observed target."""
    reference = target["reference"]
    proof = component.get("containerd_export")
    if proof is None:
        need("containerd_reference" not in target)
        return reference
    require_fields(
        proof,
        (
            "runtime_digest",
            "selected_manifest_digest",
            "config_id",
            "diff_ids",
            "layer_digests",
            "archive_sha256",
        ),
    )
    config = target["config_id"]
    need(component["name"] == target["name"] and component["observed_reference"] == reference)
    if reference == config:
        need(proof["runtime_digest"] == config and proof["selected_manifest_digest"] is None)
    else:
        need(
            reference.endswith("@" + proof["runtime_digest"])
            and DIGEST.fullmatch(proof["selected_manifest_digest"])
        )
    need(
        component["local_alias"] == target["containerd_reference"]
        and proof["config_id"]
        == config
        == component["runtime_image_id"]
        == component["image_config_id"]
    )
    need(
        re.fullmatch(r"[0-9a-f]{64}", component["archive_digest"])
        and proof["archive_sha256"] == component["archive_digest"]
    )
    diffs, blobs = proof["diff_ids"], proof["layer_digests"]
    need(type(diffs) is list and type(blobs) is list and 0 < len(diffs) == len(blobs) <= 128)
    need(
        all(
            DIGEST.fullmatch(value)
            for value in [
                config,
                proof["runtime_digest"],
                *diffs,
                *blobs,
            ]
        )
    )
    return reference if reference.endswith("@" + INVENTORIES[config]["manifest_digest"]) else config


def evidence_pin(component):
    return digest(
        canonical(
            {
                key: component[key]
                for key in ("observed_reference", "local_alias", "containerd_export")
            }
        )
    )
