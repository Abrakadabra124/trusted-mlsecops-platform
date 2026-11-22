import copy
import io
import tarfile
import unittest
from unittest.mock import patch

from mlsecops.contracts import Rejected, digest
from scripts import image_node_runc as runc


class NodeRuncTests(unittest.TestCase):
    def test_single_binary_layer(self):
        parents = ["usr", "usr/local", "usr/local/sbin"]
        dirs = []
        for name in parents:
            d = tarfile.TarInfo(name)
            d.type, d.mode = tarfile.DIRTYPE, 0o755
            dirs.append(d)
        base = {d.name: runc.node.directory_record(d) for d in dirs}
        base[runc.PATH] = ({"type": "0"}, {})
        binary = tarfile.TarInfo(runc.PATH)
        binary.mode, binary.size = 0o755, 3

        def check(entries, original=base):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as tar:
                for member, data in entries:
                    tar.addfile(member, io.BytesIO(data))
            stream.seek(0)
            with patch.object(runc, "BINARY", (3, digest(b"abc"))):
                runc.check_layer(stream, original)

        valid = [(binary, b"abc")]
        check(valid)
        check([(d, b"") for d in dirs] + valid)
        setuid = copy.deepcopy(binary)
        setuid.mode = 0o4755
        xattr = copy.deepcopy(binary)
        xattr.pax_headers = {"SCHILY.xattr.security.capability": "x"}
        link = tarfile.TarInfo(binary.name)
        link.type, link.linkname = tarfile.SYMTYPE, "other"
        foreign = tarfile.TarInfo("usr/local/bin/file")
        changed_dir = copy.deepcopy(dirs[-1])
        changed_dir.uid = 19
        for entries, original in (
            ([], base),
            (valid * 2, base),
            ([(binary, b"abd")], base),
            ([(setuid, b"abc")], base),
            ([(xattr, b"abc")], base),
            ([(link, b"")], base),
            (valid + [(foreign, b"")], base),
            ([(changed_dir, b""), *valid], base),
            (valid, {**base, parents[1]: ({"type": "2"}, {})}),
            (valid, {k: v for k, v in base.items() if k != runc.PATH}),
        ):
            with self.subTest(entries=len(entries)), self.assertRaises(Rejected):
                check(entries, original)

    def test_scoped_inventory_keeps_every_other_row(self):
        path = "/" + runc.PATH

        def row(name, version, location):
            return {"name": name, "type": "go-module", "version": version, "paths": [location]}

        def observation(version, go):
            return {
                "packages": [
                    row(runc.MODULE, version, path),
                    row("stdlib", go, path),
                    row("stdlib", "go1.26.7", "/usr/local/bin/containerd"),
                ]
            }

        old = observation("v1.4.3", "go1.26.7")
        new = observation("v1.4.4", "go1.26.11")
        self.assertEqual(runc.compare_inventory(old, new)["unchanged_other_rows"], 1)
        for change in (
            lambda a: a["packages"].pop(0),
            lambda a: a["packages"].append(a["packages"][1]),
            lambda a: a["packages"][-1].update(version="go1.26.11"),
            lambda a: a["packages"][0].update(paths=[path, "/another"]),
        ):
            changed = copy.deepcopy(new)
            change(changed)
            with self.assertRaises(Rejected):
                runc.compare_inventory(old, changed)
