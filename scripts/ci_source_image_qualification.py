"""Source-only image transfer: real archives, no local Docker invocation."""

import io
import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import ci_source_image as channel

SHA = "a" * 40
FP = "b" * 64
OWNER = "9" * 64
ROOT = Path(__file__).resolve().parents[1]


def config():
    return {
        "os": "linux",
        "architecture": "amd64",
        "config": {
            "User": "65532:65532",
            "Labels": {
                "org.opencontainers.image.revision": SHA,
                "org.trusted-mlsecops.source-fingerprint": FP,
            },
        },
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "d" * 64]},
    }


def archive(path, *, document=None, extra=(), manifest=None):
    data = canonical(config() if document is None else document)
    name = digest(data) + ".json"
    row = {"Config": name, "RepoTags": None, "Layers": ["d" * 64 + "/layer.tar"]}
    rows = [
        (name, data),
        ("manifest.json", canonical([row] if manifest is None else manifest)),
        ("d" * 64 + "/layer.tar", b"synthetic layer, never loaded by Docker"),
    ]
    with tarfile.open(path, "w") as output:
        for key, body in rows:
            member = tarfile.TarInfo(key)
            member.size = len(body)
            output.addfile(member, io.BytesIO(body))
        for member, body in extra:
            output.addfile(member, io.BytesIO(body))
    return "sha256:" + digest(data)


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "transfer"
        channel.workspace_create(self.directory, OWNER)
        self.tar = self.directory / "image.tar"
        self.identifier = archive(self.tar)
        self.receipt = dict(
            schema_version=1,
            source_revision=SHA,
            source_fingerprint=FP,
            image_id=self.identifier,
            archive_sha256="c" * 64,
            archive_bytes=100,
            tar_sha256=channel.file_pin(self.tar, channel.TAR_LIMIT)[0],
            tar_bytes=self.tar.stat().st_size,
        )

    def expected(self):
        return dict(revision=SHA, fingerprint=FP)

    def inspected(self):
        return dict(Id=self.identifier, Os="linux", Architecture="amd64", Config=config()["config"])

    def packed(self):
        compressed = self.directory / "image.tar.gz"
        channel.compress(self.tar, compressed)
        pin, size = channel.file_pin(compressed, channel.ARCHIVE_LIMIT)
        self.receipt.update(archive_sha256=pin, archive_bytes=size)
        self.tar.unlink()
        return compressed

    def test_original_archive_and_closed_receipt(self):
        self.assertEqual(channel.archive_identity(self.tar, self.receipt), self.identifier)
        self.assertEqual(channel.validate_receipt(self.receipt, self.expected()), self.receipt)
        channel.image_identity(self.inspected(), self.expected(), self.identifier)

    def test_foreign_revision_image_fingerprint_and_bool_sizes_refused(self):
        for key, value in (
            ("source_revision", "0" * 40),
            ("source_fingerprint", "0" * 64),
            ("image_id", "wrong"),
            ("archive_bytes", True),
            ("tar_bytes", 0),
            ("schema_version", True),
            ("archive_sha256", "x" * 64),
            ("tar_sha256", "0" * 63),
            ("extra", "data"),
            ("archive_bytes", channel.ARCHIVE_LIMIT + 1),
            ("tar_bytes", channel.TAR_LIMIT + 1),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(Rejected):
                channel.validate_receipt(self.receipt | {key: value}, self.expected())
        with self.assertRaises(Rejected):
            channel.validate_receipt([], self.expected())

    def test_inspected_foreign_image_platform_owner_labels(self):
        mutations = [
            dict(Id="sha256:" + "f" * 64),
            dict(Os="windows"),
            dict(Architecture="arm64"),
            dict(Config={}),
            dict(Config=config()["config"] | {"User": "0"}),
            dict(Config=config()["config"] | {"Labels": {}}),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(Rejected):
                channel.image_identity(
                    self.inspected() | mutation, self.expected(), self.identifier
                )

    def test_extra_unsafe_nonregular_duplicate_archive_members_refused(self):
        for name, kind in (
            ("private.pem", tarfile.REGTYPE),
            ("../evil", tarfile.REGTYPE),
            ("/absolute", tarfile.REGTYPE),
            ("manifest.json", tarfile.REGTYPE),
            ("blobs/sha256/" + "f" * 64, tarfile.SYMTYPE),
            ("blobs/sha256/" + "e" * 64, tarfile.LNKTYPE),
            ("blobs\\unsafe", tarfile.REGTYPE),
        ):
            member = tarfile.TarInfo(name)
            member.type = kind
            member.linkname = "target"
            archive(self.tar, extra=[(member, b"")])
            with self.subTest(name=name, kind=kind), self.assertRaises(Rejected):
                channel.archive_identity(self.tar, self.receipt)

    def test_manifest_config_and_archive_corruption_refused(self):
        archive(self.tar, manifest=[])
        with self.assertRaises(Rejected):
            channel.archive_identity(self.tar, self.receipt)
        archive(self.tar, document=config() | {"architecture": "arm64"})
        with self.assertRaises(Rejected):
            channel.archive_identity(self.tar, self.receipt)
        self.tar.write_bytes(b"broken")
        with self.assertRaises(Rejected):
            channel.archive_identity(self.tar, self.receipt)

    def test_valid_oci_and_legacy_directories_are_not_extracted(self):
        entries = []
        for name in ("blobs", "blobs/sha256", "d" * 64):
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            entries.append((member, b""))
        archive(self.tar, extra=entries)
        self.assertEqual(channel.archive_identity(self.tar, self.receipt), self.identifier)
        self.assertFalse((self.directory / "blobs").exists())

    def test_archive_limits_and_missing_config(self):
        with patch.object(channel, "MEMBER_LIMIT", 2), self.assertRaises(Rejected):
            channel.archive_identity(self.tar, self.receipt)
        with patch.object(channel, "METADATA_LIMIT", 2), self.assertRaises(Rejected):
            channel.archive_identity(self.tar, self.receipt)
        archive(self.tar, manifest=[dict(Config="absent", RepoTags=None, Layers=[])])
        with self.assertRaises(Rejected):
            channel.archive_identity(self.tar, self.receipt)

    def test_file_size_empty_nonregular_hardlink_and_changed_identity(self):
        with self.assertRaises(Rejected):
            channel.file_pin(self.tar, 1)
        with self.assertRaises(Rejected):
            channel.file_pin(self.directory, channel.TAR_LIMIT)
        other = self.directory / "linked"
        other.hardlink_to(self.tar)
        with self.assertRaises(Rejected):
            channel.file_pin(self.tar, channel.TAR_LIMIT)
        other.unlink()
        empty = self.directory / "empty"
        empty.touch()
        with self.assertRaises(Rejected):
            channel.file_pin(empty, channel.TAR_LIMIT)

    def test_compression_and_decompression_are_bounded(self):
        compressed = self.directory / "image.tar.gz"
        with patch.object(channel, "ARCHIVE_LIMIT", 16), self.assertRaises(Rejected):
            channel.compress(self.tar, compressed)
        compressed.unlink()
        channel.compress(self.tar, compressed)
        restored = self.directory / "restored"
        with patch.object(channel, "TAR_LIMIT", 32), self.assertRaises(Rejected):
            channel.decompress(compressed, restored)
        restored.unlink()
        channel.decompress(compressed, restored)
        self.assertEqual(restored.read_bytes(), self.tar.read_bytes())

    def test_compression_never_overwrites_and_invalid_gzip_refuses(self):
        target = self.directory / "compressed"
        target.write_bytes(b"owned by another operation")
        with self.assertRaises(Rejected):
            channel.compress(self.tar, target)
        self.assertEqual(target.read_bytes(), b"owned by another operation")
        with self.assertRaises(Rejected):
            channel.decompress(target, self.directory / "restored")

    def test_receive_checks_pins_before_loading(self):
        compressed = self.packed()
        with (
            patch.object(channel, "source_contract", return_value=self.expected()),
            patch.object(channel, "command") as command,
        ):
            compressed.write_bytes(compressed.read_bytes() + b"x")
            with self.assertRaises(Rejected):
                channel.receive(self.root, self.directory, self.receipt, owner=OWNER)
            command.assert_not_called()

    def test_receive_checks_decompressed_hash_before_docker(self):
        self.packed()
        wrong = self.receipt | {"tar_sha256": "0" * 64}
        with (
            patch.object(channel, "source_contract", return_value=self.expected()),
            patch.object(channel, "command") as command,
        ):
            with self.assertRaises(Rejected):
                channel.receive(self.root, self.directory, wrong, owner=OWNER)
            command.assert_not_called()

    def test_receive_exact_identity_load_tag_and_real_worker_entrypoint(self):
        self.packed()
        calls = []

        def command(args, timeout=30):
            if args[1] == "info":
                return json.dumps(dict(OSType="linux", Driver="overlay2"))
            calls.append(args)
            return json.dumps([self.inspected()]) if args[1:3] == ["image", "inspect"] else ""

        with (
            patch.object(channel, "source_contract", return_value=self.expected()),
            patch.object(channel, "command", side_effect=command),
            patch.object(channel, "execute", side_effect=self.probe) as probe,
        ):
            self.assertEqual(
                channel.receive(self.root, self.directory, self.receipt, owner=OWNER), self.receipt
            )
        self.assertTrue(any(row[1:3] == ["image", "load"] for row in calls))
        self.assertIn(["docker", "image", "tag", self.identifier, channel.IMAGE], calls)
        arguments = probe.call_args.args[0]
        self.assertNotIn("--rm", arguments)
        self.assertTrue(any(row[1:3] == ["container", "ls"] for row in calls))
        for expected in ("none", "--read-only", "--cap-drop", "65532:65532", self.identifier):
            self.assertIn(expected, arguments)

    def probe(self, arguments, output, timeout, *, cidfile):
        cidfile.write_text("e" * 64, encoding="ascii")
        return 0

    def test_probe_cleanup_requires_final_container_absence(self):
        self.packed()

        def command(args, timeout=30):
            if args[1] == "info":
                return json.dumps(dict(OSType="linux", Driver="overlay2"))
            if args[1:3] == ["image", "inspect"]:
                return json.dumps([self.inspected()])
            if args[1:3] == ["container", "ls"]:
                return "e" * 64
            return ""

        with (
            patch.object(channel, "source_contract", return_value=self.expected()),
            patch.object(channel, "command", side_effect=command),
            patch.object(channel, "execute", side_effect=self.probe),
            self.assertRaises(Rejected),
        ):
            channel.receive(self.root, self.directory, self.receipt, owner=OWNER)

    def test_probe_failure_and_timeout_still_check_final_container_state(self):
        for fault in ("failed", "timeout", "empty-cid", "invalid-cid"):
            channel.cleanup(self.directory, owner=OWNER)
            channel.workspace_create(self.directory, OWNER)
            archive(self.tar)
            self.packed()
            calls = []

            def command(args, timeout=30):
                calls.append(args)
                if args[1] == "info":
                    return json.dumps(dict(OSType="linux", Driver="overlay2"))
                if args[1:3] == ["image", "inspect"]:
                    return json.dumps([self.inspected()])
                return ""

            def failed_probe(args, output, timeout, *, cidfile):
                if fault in ("empty-cid", "invalid-cid"):
                    cidfile.write_bytes(b"" if fault == "empty-cid" else b"not-an-id")
                    raise Rejected("controlled_create_interruption")
                if fault == "timeout":
                    cidfile.write_text("e" * 64)
                    raise Rejected("controlled_timeout")
                return 125

            with (
                self.subTest(fault=fault),
                patch.object(channel, "source_contract", return_value=self.expected()),
                patch.object(channel, "command", side_effect=command),
                patch.object(channel, "execute", side_effect=failed_probe),
            ):
                with self.assertRaises(Rejected):
                    channel.receive(self.root, self.directory, self.receipt, owner=OWNER)
            self.assertTrue(any(row[1:3] == ["container", "ls"] for row in calls))

    def test_existing_tag_failed_load_wrong_loaded_identity_and_probe_failure(self):
        for mode in ("existing", "load", "identity", "probe"):
            with self.subTest(mode=mode):
                channel.cleanup(self.directory, owner=OWNER)
                channel.workspace_create(self.directory, OWNER)
                self.identifier = archive(self.tar)
                self.packed()

                def command(args, timeout=30):
                    if args[1] == "info":
                        return json.dumps(dict(OSType="linux", Driver="overlay2"))
                    if args[1:3] == ["image", "ls"]:
                        return self.identifier if mode == "existing" else ""
                    if args[1:3] == ["image", "load"] and mode == "load":
                        raise Rejected("fixture_load_failed")
                    if args[1:3] == ["image", "inspect"]:
                        return json.dumps(
                            [self.inspected() | ({"Id": "wrong"} if mode == "identity" else {})]
                        )
                    return ""

                with (
                    patch.object(channel, "source_contract", return_value=self.expected()),
                    patch.object(channel, "command", side_effect=command),
                    patch.object(channel, "execute", return_value=1 if mode == "probe" else 0),
                ):
                    with self.assertRaises(Rejected):
                        channel.receive(self.root, self.directory, self.receipt, owner=OWNER)

    def test_cleanup_rejects_foreign_files_before_deleting_anything(self):
        extra = self.directory / "foreign"
        extra.write_bytes(b"keep")
        with self.assertRaises(Rejected):
            channel.cleanup(self.directory, owner=OWNER)
        self.assertTrue(self.tar.is_file())
        extra.unlink()
        self.assertEqual(channel.cleanup(self.directory, owner=OWNER), 2)
        self.assertFalse(self.directory.exists())
        self.assertEqual(channel.cleanup(self.directory, owner=OWNER), 0)

    def test_existing_allowed_filename_is_not_cleanup_authority(self):
        foreign = self.root / "foreign-transfer"
        foreign.mkdir()
        (foreign / "image.tar").write_bytes(b"belongs to another operation")
        with self.assertRaises(Rejected):
            channel.cleanup(foreign, owner=OWNER)
        self.assertEqual((foreign / "image.tar").read_bytes(), b"belongs to another operation")

    def test_preexisting_container_id_is_rejected_before_any_docker_call(self):
        self.packed()
        (self.directory / "probe.cid").write_text("e" * 64)
        with (
            patch.object(channel, "source_contract", return_value=self.expected()),
            patch.object(channel, "command") as command,
            self.assertRaises(Rejected),
        ):
            channel.receive(self.root, self.directory, self.receipt, owner=OWNER)
        command.assert_not_called()

    def test_foreign_owner_and_modified_marker_never_allow_cleanup(self):
        with self.assertRaises(Rejected):
            channel.cleanup(self.directory, owner="8" * 64)
        self.assertTrue(self.tar.exists())
        marker = self.directory / "owner.json"
        marker.write_bytes(canonical(dict(schema_version=1, owner="8" * 64)))
        with self.assertRaises(Rejected):
            channel.cleanup(self.directory, owner=OWNER)
        self.assertTrue(self.tar.exists())

    def test_cleanup_failure_keeps_authority_for_verified_retry(self):
        unlink = Path.unlink

        def failure(path, *args, **kwargs):
            if path == self.tar:
                raise PermissionError("controlled deletion denied")
            return unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", failure), self.assertRaises(PermissionError):
            channel.cleanup(self.directory, owner=OWNER)
        channel.workspace_check(self.directory, OWNER)
        self.assertEqual(channel.cleanup(self.directory, owner=OWNER), 2)

    def test_manifest_id_backend_refuses_before_image_mutations(self):
        for info in (
            {"OSType": "linux", "Driver": "overlayfs"},
            {"OSType": "windows", "Driver": "overlay2"},
            {},
            [],
        ):
            with (
                self.subTest(info=info),
                patch.object(channel, "command", return_value=json.dumps(info)) as command,
            ):
                with self.assertRaises(Rejected):
                    channel.classic_store()
                self.assertEqual(command.call_args.args[0][1], "info")

    def test_workspace_owner_is_required_before_creating_directory(self):
        target = self.root / "new"
        with self.assertRaises(Rejected):
            channel.workspace_create(target, "invalid")
        self.assertFalse(target.exists())
        with self.assertRaises(Rejected):
            channel.workspace_create(self.directory, OWNER)
        self.assertTrue(self.tar.exists())


class SourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "repository"
        self.root.mkdir()
        for name in channel.INPUTS:
            target = self.root / name
            target.parent.mkdir(exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes().replace(b"\r\n", b"\n"))
        (self.root / "mlsecops").mkdir()
        (self.root / "mlsecops/example.py").write_text('"""Public fixture code."""\n')
        (self.root / ".gitignore").write_text(".runtime/\nmlsecops/ignored.py\n")
        self.git("init", "--quiet")
        self.commit()

    def git(self, *args):
        return channel.command(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "core.autocrlf=false",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                *args,
            ]
        )

    def commit(self):
        self.git("add", ".")
        self.git("commit", "--quiet", "--no-gpg-sign", "-m", "Public fixture")

    def test_git_archive_materializes_committed_allowlist_only(self):
        source = channel.source_contract(self.root)
        private = self.root / ".runtime"
        private.mkdir()
        (private / "private.pem").write_bytes(b"synthetic private canary")
        target = self.directory / "build"
        target.mkdir()
        context = channel.build_context(self.root, target, source)
        observed = {p.relative_to(context).as_posix() for p in context.rglob("*") if p.is_file()}
        self.assertEqual(observed, set(channel.INPUTS) | {"mlsecops/example.py"})
        self.assertFalse((context / ".runtime").exists())
        self.assertFalse((context / ".gitignore").exists())
        self.assertEqual(channel.source_fingerprint(context), source["fingerprint"])

    def test_live_ignored_python_cannot_become_public_build_input(self):
        ignored = self.root / "mlsecops/ignored.py"
        ignored.write_bytes(b'PRIVATE_CANARY = "never publish"\n')
        source = channel.source_contract(self.root)
        target = self.directory / "build"
        target.mkdir()
        with self.assertRaises(Rejected):
            channel.build_context(self.root, target, source)
        self.assertFalse((target / "context/mlsecops/ignored.py").exists())

    def test_dirty_public_recipe_or_missing_material_never_reaches_build(self):
        (self.root / "new.txt").write_text("uncommitted")
        with self.assertRaises(Rejected):
            channel.source_contract(self.root)
        (self.root / "new.txt").unlink()
        recipe = self.root / "Dockerfile"
        recipe.write_text(recipe.read_text() + "\nCOPY .runtime /private\n")
        self.commit()
        with self.assertRaises(Rejected):
            channel.source_contract(self.root)
        (self.root / ".dockerignore").unlink()
        self.commit()
        with self.assertRaises(Rejected):
            channel.source_contract(self.root)

    def test_immutable_commit_is_used_after_local_file_changes(self):
        source = channel.source_contract(self.root)
        original = (self.root / "mlsecops/example.py").read_bytes()
        (self.root / "mlsecops/example.py").write_bytes(b"UNCOMMITTED_PRIVATE_CANARY")
        target = self.directory / "build"
        target.mkdir()
        context = channel.build_context(self.root, target, source)
        self.assertEqual((context / "mlsecops/example.py").read_bytes(), original)

    def test_unsafe_git_archive_entries_and_missing_closure_refuse(self):
        source = channel.source_contract(self.root)
        for name, kind in (
            ("../foreign", tarfile.REGTYPE),
            ("mlsecops", tarfile.SYMTYPE),
            ("unexpected", tarfile.DIRTYPE),
            ("mlsecops/example.py", tarfile.SYMTYPE),
            ("mlsecops", tarfile.DIRTYPE),
        ):
            target = self.directory / "build"
            target.mkdir()

            def write_fixture(args, timeout=30):
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = "foreign"
                with tarfile.open(target / "source.tar", "w") as packed:
                    packed.addfile(member)
                return ""

            with (
                self.subTest(name=name, kind=kind),
                patch.object(channel, "command", side_effect=write_fixture),
            ):
                with self.assertRaises(Rejected):
                    channel.build_context(self.root, target, source)
            shutil.rmtree(target)

    def test_prepare_actual_git_context_and_closed_image_receipt(self):
        source = channel.source_contract(self.root)
        document = config()
        document["config"]["Labels"] = {
            "org.opencontainers.image.revision": source["revision"],
            "org.trusted-mlsecops.source-fingerprint": source["fingerprint"],
        }
        identifier = "sha256:" + digest(canonical(document))
        original_command = channel.command
        builds = []

        def command(args, timeout=30):
            if args[1] == "info":
                return json.dumps(dict(OSType="linux", Driver="overlay2"))
            if args[0] == "git":
                return original_command(args, timeout)
            if args[1] == "build":
                context = Path(args[-1])
                builds.append(
                    {p.relative_to(context).as_posix() for p in context.rglob("*") if p.is_file()}
                )
                self.assertEqual(timeout, 900)
            if args[1:3] == ["image", "inspect"]:
                return json.dumps(
                    [
                        dict(
                            Id=identifier,
                            Os="linux",
                            Architecture="amd64",
                            Config=document["config"],
                        )
                    ]
                )
            return ""

        def save(args, output, timeout, **kwargs):
            self.assertEqual(args, ["docker", "image", "save", identifier])
            self.assertEqual(kwargs["output_limit"], channel.TAR_LIMIT)
            archive(output, document=document)
            return 0

        target = self.directory / "transfer"
        with (
            patch.object(channel, "command", side_effect=command),
            patch.object(channel, "execute", side_effect=save),
        ):
            receipt = channel.prepare(self.root, target, owner=OWNER)
        self.assertEqual(receipt["source_revision"], source["revision"])
        self.assertEqual(receipt["image_id"], identifier)
        self.assertEqual(
            channel.file_pin(target / "image.tar.gz", channel.ARCHIVE_LIMIT),
            (receipt["archive_sha256"], receipt["archive_bytes"]),
        )
        self.assertEqual(builds, [set(channel.INPUTS) | {"mlsecops/example.py"}])
        self.assertFalse(any(p.name.startswith("source-build-") for p in target.iterdir()))
        self.assertEqual(channel.cleanup(target, owner=OWNER), 3)

    def test_existing_transfer_directory_is_not_adopted(self):
        target = self.directory / "transfer"
        target.mkdir()
        foreign = target / "foreign"
        foreign.write_text("keep")
        with self.assertRaises(Rejected):
            channel.prepare(self.root, target, owner=OWNER)
        self.assertEqual(foreign.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
