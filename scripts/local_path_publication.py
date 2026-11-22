"""Publish the measured local-path archive from the reviewed PVC qualification."""

import argparse
import hashlib
import os
import tarfile
from urllib.error import HTTPError

from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts.qualified_publication import (
    API,
    LIMIT,
    MANIFEST_TYPES,
    REPOSITORY,
    QualifiedPublisher,
    is_digest,
    positive,
)


class LocalPathPublisher(QualifiedPublisher):
    COMPONENT = "local-path"
    TAG_PREFIX = "0.0.37-deps-r1-"
    REQUIRE_PUBLIC = True
    WORKFLOW = ".github/workflows/local-path-rebuild.yml"
    BRANCH = "qualify/r1-localpath-pvc"
    EXPECTED_SOURCE = "f6572a0fc07ce38b1dcc4763bf866b5eb8f8fc95"
    WORKFLOW_SHA256 = "c2fce4dbdfbdf2eb6670ca7fe2ffc7c38839ff91a3c45db2e3520d1b617f1f5e"
    RECIPE = "3e5753c1564a4e39ce7639cfadd4baad8a9711d75c901fff9583b8375f3ca558"
    RUN_ID = 45048228181
    JOB_ID = 137287398756
    ARTIFACT_ID = 14764617515
    ZIP_SIZE = 109089777
    ZIP_DIGEST = "sha256:534cc7884248d427665dda2fa6a205de787b036c646f70dcfb784dc828ed5ab5"
    RECEIPT_SHA256 = "355a417a232f82206a217230a6903e151d54b5ca6b03576874eaaeb8501a67bd"
    ARCHIVE_SHA256 = "3dd6a18fad5d4bfc5152dce22c259fdf2c7038225019e622b673c35ab02b1133"
    ARCHIVE_SIZE = 109088256
    CONFIG = "sha256:6a8aed8ef83dc8563559bd755adfc2f9e5f64d5ba3606aa71ad8841a1826434a"
    STOCK_CONFIG = "sha256:c82008e2cd0186ef96bfd05d6b49d3286768fae5bd7a961f70bd485a3785c006"
    ELF = "e424baa965649565de70a5e4549fa88a1fa4242c39dfda32aaadd557c2e41612"
    STOCK_ELF = "2390c3c8cc37ac3cf05bce7148c54fd51d9618001511684c0eb923ddc80b4fa7"
    BINARY = "usr/local/bin/local-path-provisioner"
    ELF_LAYERS = (
        ("a15e1c414b3ac3dde9613e6137487912259a37ab504884aa4fec2a4247c7ea2a", 52605090, STOCK_ELF),
        ("f9c97992ba07b0343ee0b6aea7a94d18ab8222e8845dfb26ad2b98e4b0fa8017", 52174972, ELF),
    )
    STEPS = (
        "Set up job",
        "Run actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
        "Run astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7",
        "Verify the source and scanner contracts",
        "Build the candidate for linux/amd64",
        "Measure the built image and stock image on one database",
        "Prepare the isolated cluster and test consumer",
        "Require an unused cluster name",
        "Bootstrap the disposable cluster from the checked out configuration",
        "Provision a test volume, remount, delete and restore the stock controller",
        "Remove the owned cluster and verify the node is absent",
        "Bind measured bytes to the live result after verified cleanup",
        "Upload the qualified system image and receipt",
        "Post Run astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7",
        "Post Run actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
        "Complete job",
    )

    def expected_receipt(self):
        return {
            "schema_version": 2,
            "repository": REPOSITORY,
            "source_revision": self.EXPECTED_SOURCE,
            "run_id": self.RUN_ID,
            "run_attempt": 1,
            "archive_size": self.ARCHIVE_SIZE,
            "archive_sha256": self.ARCHIVE_SHA256,
            "recipe_sha256": self.RECIPE,
            "config_id": self.CONFIG,
            "stock_config_id": self.STOCK_CONFIG,
            "restored_stock_config_id": self.STOCK_CONFIG,
            "binary_sha256": self.ELF,
            "stock_binary_sha256": self.STOCK_ELF,
            "candidate_runtime_digest": "sha256:e9af4f1d407629a7a8ca114c1281360cd89eab2fabaf56c4fa52350d9489430a",
            "live_report_sha256": "d2bc3196a4e0ba910b4b6aef903589e00282c5cd3e3b2d81431423e65ccba049",
            "measurement_sha256": "ea44e1aaa6b59968065704d525839c1e187b484f2a50bfd90581102e0577b7a4",
            "static_report_sha256": "8ee309e705abc56f94c758bb0fa1f2dce8c0b988ab0eb2836d657bf17e690f64",
            "cleanup_verified": True,
            "cluster_cleanup_outcome": "success",
            "pvc_status": "pass",
        }

    def verify_pins(self, run_id):
        super().verify_pins(run_id)
        self.require(positive(run_id) and run_id == self.RUN_ID, "run_id_invalid")
        self.require(
            digest(canonical(self.expected_receipt()) + b"\n") == self.RECEIPT_SHA256,
            "receipt_pins_invalid",
        )

    def preflight(self, env):
        run_id = self.dispatch(env, env.get("QUALIFIED_RUN_ID", ""))
        artifact = self.evidence(run_id, None)
        for path, pin in (
            (self.WORKFLOW, self.WORKFLOW_SHA256),
            ("images/candidates/local-path/Dockerfile", self.RECIPE),
        ):
            data = self.body(
                f"{API}/contents/{path}?ref={self.EXPECTED_SOURCE}",
                None,
                "application/vnd.github.raw+json",
            )
            self.require(digest(data) == pin, "source_file_mismatch")
        return artifact

    def job_matches(self, job):
        return (
            super().job_matches(job)
            and positive(job["id"])
            and job["id"] == self.JOB_ID
            and tuple(step["name"] for step in job["steps"]) == self.STEPS
        )

    def select_artifact(self, document, run_id):
        self.require(document["total_count"] == 1, "artifact_count")
        artifact = super().select_artifact(document, run_id)
        self.require(
            (artifact["id"], artifact["size_in_bytes"], artifact["digest"])
            == (self.ARTIFACT_ID, self.ZIP_SIZE, self.ZIP_DIGEST),
            "artifact_pin_mismatch",
        )
        return artifact

    def validate_receipt(self, raw, run_id, size):
        self.require(digest(raw) == self.RECEIPT_SHA256, "receipt_digest_mismatch")
        receipt = decode(raw, 8192)
        self.require(
            run_id == self.RUN_ID
            and size == self.ARCHIVE_SIZE
            and canonical(receipt) == canonical(self.expected_receipt()),
            "receipt_invalid",
        )
        return receipt

    def verify_image(self, details):
        self.require(
            details["Id"] == self.CONFIG
            and details["Os"] == "linux"
            and details["Architecture"] == "amd64"
            and details["Config"]["Entrypoint"] == ["/bin/sh", "-c", "/" + self.BINARY]
            and details["Config"]["User"] == "0",
            "image_config_invalid",
        )

    def unpack(self, path, artifact, run_id, target):
        self.select_artifact({"total_count": 1, "artifacts": [artifact]}, run_id)
        receipt = super().unpack(path, artifact, run_id, target)
        # Whole-tar SHA already fixes layer order and the final notices layer.
        # Read the two files directly from their uncompressed donor and replacement layers.
        try:
            with tarfile.open(target, "r:") as archive:
                for layer, size, checksum in self.ELF_LAYERS:
                    with archive.extractfile("blobs/sha256/" + layer) as source:
                        with tarfile.open(fileobj=source, mode="r:") as contents:
                            obj = contents.getmember(self.BINARY)
                            self.require(obj.isfile() and obj.size == size, "elf_member")
                            with contents.extractfile(obj) as elf:
                                self.require(
                                    hashlib.file_digest(elf, "sha256").hexdigest() == checksum,
                                    "elf_digest_mismatch",
                                )
        except (tarfile.TarError, KeyError) as error:
            raise Rejected("local-path_publication_elf_layer_invalid") from error
        return receipt

    def anonymous_readback(self, tag, manifest, config):
        # Verify every blob of the pushed single-platform manifest with an anonymous pull grant.
        try:
            auth = self.registry_auth()
            self.readback(tag, manifest, config, auth)
            raw = self.body(f"{self.V2}/manifests/{manifest}", auth, MANIFEST_TYPES)
            self.require("sha256:" + digest(raw) == manifest, "manifest_digest_mismatch")
            layers = decode(raw)["layers"]
            self.require(
                type(layers) is list
                and 0 < len(layers) <= 128
                and all(is_digest(d["digest"]) and positive(d["size"]) for d in layers)
                and sum(d["size"] for d in layers) <= LIMIT,
                "layer_descriptors_invalid",
            )
            for layer in layers:
                with self.open_url(
                    f"{self.V2}/blobs/{layer['digest']}", auth, "application/octet-stream"
                ) as stream:
                    checksum = hashlib.sha256()
                    left = layer["size"]
                    while left:
                        block = stream.read(min(left, 1024**2))
                        self.require(block, "short_layer")
                        checksum.update(block)
                        left -= len(block)
                    self.require(
                        not stream.read(1) and "sha256:" + checksum.hexdigest() == layer["digest"],
                        "layer_digest_mismatch",
                    )
        except HTTPError as error:
            if error.code in (401, 403, 404):
                return "blocked"
            raise
        return "verified"


PUBLISHER = LocalPathPublisher()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Verify the public producer authority without credentials",
    )
    if parser.parse_args(argv).preflight:
        artifact = PUBLISHER.preflight(os.environ)
        print(
            f"local-path preflight verified run={PUBLISHER.RUN_ID} artifact={artifact['id']} digest={artifact['digest']}"
        )
        return 0
    return PUBLISHER.main()


if __name__ == "__main__":
    raise SystemExit(main())
