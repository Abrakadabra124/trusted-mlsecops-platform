import re
from dataclasses import dataclass, fields

from mlsecops import signing
from mlsecops.contracts import Rejected, decode, require_fields

FIELDS = (
    "source_revision",
    "source_fingerprint",
    "source_sha256",
    "source_approval_sha256",
    "dataset_sha256",
    "lineage_sha256",
    "run_sha256",
    "evaluation_sha256",
)


@dataclass(frozen=True, slots=True, repr=False)
class Lineage:
    source_revision: str
    source_fingerprint: str
    source_sha256: str
    source_approval_sha256: str
    dataset_sha256: str
    lineage_sha256: str
    run_sha256: str
    evaluation_sha256: str

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            size = 40 if field.name == "source_revision" else 64
            if type(value) is not str or re.fullmatch(rf"[a-f0-9]{{{size}}}", value) is None:
                raise Rejected("audit_lineage_invalid")


def checked(value):
    require_fields(value, FIELDS)
    return Lineage(**value)


def from_verified_package(package, manifest, curator_public):
    projection = decode(package["documents"]["asset_projection"])
    bindings = projection["bindings"]
    provenance = signing.verify(
        decode(package["capsule"]["objects"][("lineage", bindings["lineage_object"])]),
        "data-lineage",
        curator_public,
    )
    materials = manifest["materials"]
    return Lineage(
        source_revision=manifest["source_commit"],
        source_fingerprint=bindings["source_fingerprint"],
        source_sha256=provenance["source_sha256"],
        source_approval_sha256=bindings["source_approval_digest"],
        dataset_sha256=materials["dataset_manifest"],
        lineage_sha256=bindings["lineage_object"],
        run_sha256=materials["provenance"],
        evaluation_sha256=materials["evaluation_report"],
    )
