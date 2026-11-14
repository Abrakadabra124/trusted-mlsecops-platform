"""Controlled regression tests for pinned M12 scheduling and evidence ownership."""

import copy
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from mlsecops import inference_gate as gate
from mlsecops import signing
from mlsecops.contracts import Rejected, bounded_read, canonical, digest, write_json
from scripts import m12_pinned_native as staged


class PinnedWindowTests(unittest.TestCase):
    def test_verify_retained_bytes_signature_identity_and_original_expiry(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)

            def save(path, value):
                write_json(path, value)
                return digest(bounded_read(path))

            campaign = "0" * 32
            files = state / "candidate-inference" / campaign
            public = signing.create_key(state / "permit.pem")
            authority = signing.create_key(state / "trust.pem")
            source = dict(source_revision="a" * 40, source_fingerprint="b" * 64, image_id="image")
            permit = dict(
                campaign_id=campaign,
                proposal_sha256="c" * 64,
                subject_sha256="d" * 64,
                model_sha256="e" * 64,
                issued_at=1000,
                expires_at=1500,
                **source,
            )
            envelope = signing.sign(permit, staged.KIND, state / "permit.pem")
            payload_hash = digest(canonical(permit))
            peer = dict(
                identity=dict(root_sha256=digest(signing.decode64(authority))),
                policy_sha256=payload_hash,
            )
            config = dict(
                trust_target=staged.PEER.value,
                trust_root=authority,
                permit_public=public,
                expected_campaign=campaign,
                expected_permit=payload_hash,
                permit_envelope=envelope,
            )
            demo = dict(candidate=dict(candidate_reference="f" * 64), evaluation_reference="1" * 64)
            proposal = dict(
                proposal_reference=permit["proposal_sha256"],
                model_sha256=permit["model_sha256"],
                subject_sha256=permit["subject_sha256"],
            )
            refused = dict(
                candidate=demo["candidate"]["candidate_reference"],
                proposal=proposal["proposal_reference"],
                model=proposal["model_sha256"],
                parent_refusal="release_assurance_required",
                job_outcome="rejected",
            )
            native = dict(
                authority_target=staged.PEER.value,
                cases=[
                    dict(id="qualification-permit-payload", actual=payload_hash),
                    dict(id="qualification-permit-envelope", actual=digest(canonical(envelope))),
                ],
                ownership_return=dict(
                    transfer=dict(before="a", after="b", release_ready=False),
                    observation=None,
                    heartbeat_before=1,
                    heartbeat_after=2,
                    return_seconds=1,
                    identity_events_delivered=0,
                    outbox_retained=True,
                    release_ready=False,
                ),
            )
            artifacts = {
                name: save(files / name, value)
                for name, value in (
                    ("config.json", config),
                    ("probe.json", native),
                    ("request.json", {}),
                    ("reference.json", {}),
                )
            }
            actual = dict(
                source=source,
                actual_refusal=refused,
                native=native,
                status="pass",
                release_ready=False,
                qualification_campaign_id=campaign,
                qualification_permit_sha256=payload_hash,
                artifact_hashes=artifacts,
                candidate_reference=refused["candidate"],
                evaluation_reference=demo["evaluation_reference"],
                proposal_issued_at=850,
                finished_at="1970-01-01T00:20:00+00:00",
                proposal_expires_at=1600,
                **proposal,
            )
            packet = dict(
                prepared=dict(profile=source, actual=refused, **source),
                actual=actual,
                peer=peer,
                started_at="1970-01-01T00:15:00+00:00",
                owner=dict(
                    source=source,
                    proposal_sha256=save(state / "evidence/release-native.json", proposal),
                    inputs={"storage-demo.json": save(state / "storage-demo.json", demo)},
                ),
            )
            staged.verify(state, packet)
            for key, value in (
                ("proposal_expires_at", 1400),
                ("finished_at", "1970-01-01T00:30:00+00:00"),
                ("candidate_reference", "0" * 64),
                ("evaluation_reference", "0" * 64),
                ("qualification_permit_sha256", "0" * 64),
                ("qualification_campaign_id", "../foreign"),
            ):
                changed = copy.deepcopy(packet)
                changed["actual"][key] = value
                with self.subTest(key=key), self.assertRaises(Rejected):
                    staged.verify(state, changed)
            for name in staged.ARTIFACTS:
                path = files / name
                original = bounded_read(path)
                for replacement in (None, b"{} "):
                    if replacement is None:
                        path.unlink()
                    else:
                        path.write_bytes(replacement)
                    with (
                        self.subTest(name=name, replacement=replacement),
                        self.assertRaises(Rejected),
                    ):
                        staged.verify(state, packet)
                path.write_bytes(original)
            changed = copy.deepcopy(packet)
            foreign = {**config, "permit_public": authority}
            changed["actual"]["artifact_hashes"]["config.json"] = save(
                files / "config.json", foreign
            )
            with self.assertRaises(Rejected):
                staged.verify(state, changed)

    def test_case_inventory_requires_both_permit_digests(self):
        self.assertTrue(
            {"qualification-permit-payload", "qualification-permit-envelope"} <= gate.NATIVE_CASES
        )

    def test_early_pin_without_proposal_cannot_start_legacy_qualification(self):
        with (
            TemporaryDirectory() as directory,
            patch.dict(gate.os.environ, {"M12_EARLY_SHA256": "a" * 64}, clear=True),
            patch.object(gate, "hosted"),
            patch.object(gate.kube_serving_native, "prepare") as prepare,
            self.assertRaisesRegex(Rejected, "proposal_required"),
        ):
            gate.qualify(Path(directory), Path(directory))
        prepare.assert_not_called()

    def test_inline_and_staged_paths_use_the_same_long_campaign_once(self):
        packet = dict(
            owner="owned",
            prepared={"profile": "owned"},
            actual={"started_at": "early"},
            primary="controls",
            peer="candidate",
        )
        for staged_capture in (False, True):
            for fault in (
                "none",
                "bytes",
                "runner",
                "primary",
                "peer_before",
                "peer_after",
                "controlled",
            ):
                with self.subTest(staged=staged_capture, fault=fault), TemporaryDirectory() as tmp:
                    state = Path(tmp)
                    path = state / staged.PACKET
                    write_json(path, packet)
                    pin = digest(bounded_read(path)) if staged_capture else None
                    if fault == "bytes":
                        if not staged_capture:
                            continue
                        path.write_bytes(b"{}")
                    owners = ["other" if fault == "runner" else "owned", "owned"]
                    histories = [
                        "changed" if fault == "primary" else "controls",
                        "changed" if fault == "peer_before" else "candidate",
                        "changed" if fault == "peer_after" else "candidate",
                    ]
                    campaign = Mock(return_value={"status": "pass"})
                    if fault == "controlled":
                        campaign.side_effect = Rejected("controlled_outage")
                    with (
                        patch.object(staged, "hosted"),
                        patch.object(staged, "owner", side_effect=owners),
                        patch.object(staged, "verify"),
                        patch.object(staged, "capture", return_value=packet) as capture,
                        patch.object(staged.kube_authority_pair, "read", side_effect=histories),
                        patch.object(staged.kube_serving_native, "qualify", campaign),
                    ):
                        if fault == "none":
                            start, native = staged.finish(state, state, "image", "pin", pin)
                            self.assertEqual(
                                (start, native["actual_inference"]), ("early", packet["actual"])
                            )
                        else:
                            with self.assertRaises(Rejected):
                                staged.finish(state, state, "image", "pin", pin)
                        self.assertEqual(capture.call_count, int(not staged_capture))
                        if fault in ("none", "peer_after", "controlled"):
                            campaign.assert_called_once_with(
                                state, state, "image", prepared=packet["prepared"]
                            )
                        else:
                            campaign.assert_not_called()

    def test_no_long_campaign_when_early_candidate_refuses(self):
        with (
            patch.object(staged, "hosted"),
            patch.object(staged, "owner"),
            patch.object(staged.promotion_state, "install") as install,
            patch.object(
                staged.kube_serving_native, "prepare", return_value={"profile": {}, "actual": {}}
            ) as prepare,
            patch.object(staged.kube_authority_pair, "read"),
            patch.object(
                staged.kube_candidate_native,
                "qualify",
                side_effect=Rejected("candidate_inference_window"),
            ) as actual,
            patch.object(staged.kube_serving_native, "qualify") as controlled,
            self.assertRaisesRegex(Rejected, "candidate_inference_window"),
        ):
            staged.finish("root", "state", "image", "original", None)
        prepare.assert_called_once_with("root", "state", "image", proposal_pin="original")
        install.assert_called_once_with("state", backend=staged.kube_storage.binding)
        actual.assert_called_once_with("root", "state", "image", prepared=({}, {}), pinned_m12=True)
        controlled.assert_not_called()
