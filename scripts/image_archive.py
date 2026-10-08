import tarfile
from pathlib import PurePosixPath

from mlsecops.contracts import Rejected, decode, digest


def identity(path, expected):
    try:
        with tarfile.open(path, "r:") as archive:
            members = {}
            for member in archive:
                if member.name in members or len(members) >= 10000:
                    raise Rejected("image_archive_ambiguous")
                members[member.name] = member

            def read(name):
                member = members[name]
                if (
                    PurePosixPath(name).is_absolute()
                    or ".." in PurePosixPath(name).parts
                    or "\\" in name
                    or not member.isfile()
                    or member.size > 1024 * 1024
                ):
                    raise Rejected("image_archive_metadata_invalid")
                return archive.extractfile(member).read(1024 * 1024 + 1)

            manifest = decode(read("manifest.json"))
            if not isinstance(manifest, list) or len(manifest) != 1:
                raise Rejected("image_archive_single_image_required")
            content = read(manifest[0]["Config"])
            config = decode(content)
            if (
                config["os"] != expected["Os"]
                or config["os"] != "linux"
                or config["architecture"] != expected["Architecture"]
                or config["architecture"] != "amd64"
                or config["rootfs"]["diff_ids"] != expected["RootFS"]["Layers"]
                or config["config"].get("Labels") != expected["Config"].get("Labels")
            ):
                raise Rejected("image_archive_inspect_mismatch")
            return "sha256:" + digest(content)
    except (OSError, tarfile.TarError, KeyError, TypeError, AttributeError) as error:
        raise Rejected("image_archive_invalid") from error
