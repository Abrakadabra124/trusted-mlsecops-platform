import copy
import io
import tarfile
import tempfile
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, digest
from scripts.image_archive import identity


def qualify():
    configuration = {
        "os": "linux",
        "architecture": "amd64",
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "b" * 64]},
        "config": {"Labels": {"org.trusted-mlsecops.source-fingerprint": "c" * 64}},
    }
    expected = {
        "Os": "linux",
        "Architecture": "amd64",
        "RootFS": {"Layers": configuration["rootfs"]["diff_ids"]},
        "Config": configuration["config"],
    }
    cases = []
    with tempfile.TemporaryDirectory(prefix="image-archive-contract-") as temporary:
        for name in (
            "valid",
            "multiple-images",
            "missing-config",
            "duplicate-config",
            "symlink-config",
            "big-config",
            "wrong-os",
            "wrong-arch",
            "wrong-layer",
            "wrong-label",
            "invalid-json",
            "unsafe-path",
            "duplicate-manifest",
            "manifest-object",
            "config-object",
        ):
            path = Path(temporary) / f"{name}.tar"
            config = copy.deepcopy(configuration)
            manifest = [{"Config": "config.json", "Layers": []}]
            if name == "multiple-images":
                manifest *= 2
            elif name == "wrong-os":
                config["os"] = "windows"
            elif name == "wrong-arch":
                config["architecture"] = "arm64"
            elif name == "wrong-layer":
                config["rootfs"]["diff_ids"] = []
            elif name == "wrong-label":
                config["config"]["Labels"] = {}
            elif name == "unsafe-path":
                manifest[0]["Config"] = "../config.json"
            elif name == "manifest-object":
                manifest = {}
            elif name == "config-object":
                config = []
            with tarfile.open(path, "w") as archive:

                def add(member_name, content, kind=tarfile.REGTYPE):
                    member = tarfile.TarInfo(member_name)
                    member.type = kind
                    member.size = len(content) if kind == tarfile.REGTYPE else 0
                    member.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
                    archive.addfile(member, io.BytesIO(content))

                add("manifest.json", canonical(manifest))
                if name == "duplicate-manifest":
                    add("manifest.json", canonical(manifest))
                content = canonical(config)
                if name == "big-config":
                    content = b"x" * (1024 * 1024 + 1)
                elif name == "invalid-json":
                    content = b"{"
                if name != "missing-config":
                    add(
                        "config.json",
                        content,
                        tarfile.SYMTYPE if name == "symlink-config" else tarfile.REGTYPE,
                    )
                if name == "duplicate-config":
                    add("config.json", content)
            try:
                result = identity(path, expected)
                passed = name == "valid" and result == "sha256:" + digest(canonical(configuration))
            except Rejected:
                passed = name != "valid"
            if not passed:
                raise Rejected(f"archive_contract_failed:{name}")
            cases.append({"id": name, "status": "pass"})
    return {
        "status": "pass",
        "scope": "archive-binding-contracts",
        "cases": cases,
        "checks": len(cases),
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
