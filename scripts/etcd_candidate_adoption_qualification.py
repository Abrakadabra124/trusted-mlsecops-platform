"""Regression tests for the image identity reported by a running etcd container."""

import unittest
from unittest.mock import patch

from mlsecops.contracts import Rejected
from scripts import etcd_candidate_adoption as adoption

CONFIG = "sha256:" + "a" * 64
MANIFEST = "sha256:" + "b" * 64
INDEX = "sha256:" + "c" * 64
TAG = "localhost/etcd-candidate:" + CONFIG[7:]


class RunningImageIdentity(unittest.TestCase):
    def test_imported_index_resolves_to_scanned_manifest_and_config(self):
        ref = "docker.io/library/import-test@" + INDEX
        with patch.object(
            adoption, "image_manifest", return_value=(MANIFEST, {"config": {"digest": CONFIG}})
        ) as read:
            adoption.verify_candidate_ref({"imageRef": ref}, TAG, MANIFEST, CONFIG)
        read.assert_called_once_with(INDEX)

    def test_other_manifest_or_other_config_refuses(self):
        for resolved, config in ((INDEX, CONFIG), (MANIFEST, INDEX)):
            with (
                self.subTest(resolved=resolved, config=config),
                patch.object(
                    adoption,
                    "image_manifest",
                    return_value=(resolved, {"config": {"digest": config}}),
                ),
                self.assertRaises(Rejected),
            ):
                adoption.verify_candidate_ref({"imageRef": INDEX}, TAG, MANIFEST, CONFIG)

    def test_tag_needs_matching_image_id_from_live_container(self):
        adoption.verify_candidate_ref({"imageRef": TAG, "imageId": CONFIG}, TAG, MANIFEST, CONFIG)
        for image_id in (None, INDEX):
            with self.subTest(image_id=image_id), self.assertRaises(Rejected):
                adoption.verify_candidate_ref(
                    {"imageRef": TAG, "imageId": image_id}, TAG, MANIFEST, CONFIG
                )

    def test_config_only_ref_and_malformed_ref(self):
        for ref in (CONFIG, CONFIG[7:]):
            adoption.verify_candidate_ref({"imageRef": ref}, TAG, MANIFEST, CONFIG)
        with self.assertRaises(Rejected):
            adoption.verify_candidate_ref({"imageRef": "import-test:latest"}, TAG, MANIFEST, CONFIG)
