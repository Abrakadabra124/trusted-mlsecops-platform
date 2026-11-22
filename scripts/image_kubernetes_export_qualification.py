"""Offline checks of containerd repack identity with actual OCI and layer bytes."""

import gzip
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import kube_worker
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import image_kubernetes_export as export


class ExportIdentityTests(unittest.TestCase):
    def proof(self, fault=None, *, config_only=False):
        layers = [b"first filesystem layer", b"second filesystem layer"]
        blobs = [gzip.compress(layers[0], mtime=0), layers[1]]
        diff_ids = ["sha256:" + digest(raw) for raw in layers]
        config = canonical(
            dict(
                os="linux",
                architecture="arm64" if fault == "arch" else "amd64",
                rootfs=dict(
                    type="layers", diff_ids=diff_ids[::-1] if fault == "diff" else diff_ids
                ),
            )
        )

        def descriptor(raw, media):
            return dict(mediaType=media, size=len(raw), digest="sha256:" + digest(raw))

        config_desc = descriptor(config, "application/vnd.oci.image.config.v1+json")
        rows = [
            descriptor(raw, "application/vnd.oci.image.layer.v1.tar" + suffix)
            for raw, suffix in zip(blobs, ("+gzip", ""), strict=True)
        ]
        if fault == "size":
            rows[0]["size"] += 1
        if fault == "codec":
            rows[0]["mediaType"] += "+unknown"
        manifest = canonical(dict(schemaVersion=2, config=config_desc, layers=rows))
        manifest_id = "sha256:" + digest(manifest)
        child = descriptor(manifest, "application/vnd.oci.image.manifest.v1+json") | {
            "platform": {"os": "linux", "architecture": "amd64"}
        }
        index = canonical(
            dict(schemaVersion=2, manifests=[child, child] if fault == "ambiguous" else [child])
        )
        index_id = "sha256:" + digest(index)
        config_id = config_desc["digest"]
        graph = {index_id: index, manifest_id: manifest, config_id: config}

        def read(identifier):
            raw = graph[identifier]
            self.assertEqual(identifier, "sha256:" + digest(raw))
            return decode(raw)

        def path(identifier):
            return "blobs/sha256/" + identifier[7:]

        entries = {
            path(config_id): config,
            **{path(row["digest"]): blob for row, blob in zip(rows, blobs, strict=True)},
        }
        names = [path(row["digest"]) for row in rows]
        if fault == "blob":
            entries[names[0]] = b"x" * len(blobs[0])
        if fault == "config":
            entries[path(config_id)] = b" " + config
        if fault == "order":
            names.reverse()
        if fault == "count":
            names.pop()
        entries["manifest.json"] = canonical([dict(Config=path(config_id), Layers=names)])
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(kube_worker, "image_document", side_effect=read),
        ):
            archive = Path(tmp) / "local.tar"
            with tarfile.open(archive, "w") as tar:
                for name, raw in entries.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(raw)
                    tar.addfile(info, io.BytesIO(raw))
                if fault == "duplicate":
                    tar.addfile(info, io.BytesIO(raw))
            root_id = manifest_id if fault == "direct" else index_id
            reference = (
                config_id if config_only else "docker.io/library/import-2026-08-26@" + root_id
            )
            proof = export.verify(
                archive, reference, config_id if fault != "pin" else "sha256:" + "1" * 64
            )
        self.assertEqual(proof["runtime_digest"], config_id if config_only else root_id)
        self.assertEqual(proof["selected_manifest_digest"], None if config_only else manifest_id)
        self.assertEqual(proof["config_id"], config_id)
        self.assertEqual(proof["diff_ids"], diff_ids)
        self.assertEqual(proof["layer_digests"], [row["digest"] for row in rows])
        return proof

    def test_selected_index_manifest_config_and_layer_bytes(self):
        self.proof()
        self.proof("direct")

    def test_config_only_binds_actual_ordered_rootfs_without_claiming_a_manifest(self):
        self.proof(config_only=True)
        for fault in ("blob", "diff", "config", "order", "count"):
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                self.proof(fault, config_only=True)

    def test_swapped_descriptor_or_layer_never_confers_config_binding(self):
        for fault in (
            "blob",
            "diff",
            "config",
            "pin",
            "arch",
            "order",
            "count",
            "size",
            "codec",
            "ambiguous",
            "duplicate",
        ):
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                self.proof(fault)
