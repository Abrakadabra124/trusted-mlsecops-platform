import re
from dataclasses import dataclass, field

from mlsecops.contracts import Rejected


def references(*values):
    if not all(type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) for value in values):
        raise Rejected("serving_context_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class ReleaseContext:
    selection_sha256: str
    bundle_sha256: str
    model_sha256: str
    schema_version: int = field(default=1, init=False)
    kind: str = field(default="release-selection", init=False)
    release_ready: bool = field(default=False, init=False)

    def __post_init__(self):
        references(self.selection_sha256, self.bundle_sha256, self.model_sha256)


@dataclass(frozen=True, slots=True, repr=False)
class QualificationContext:
    permit_sha256: str
    proposal_sha256: str
    bundle_sha256: str
    model_sha256: str
    schema_version: int = field(default=1, init=False)
    kind: str = field(default="candidate-qualification", init=False)
    release_ready: bool = field(default=False, init=False)

    def __post_init__(self):
        references(self.permit_sha256, self.proposal_sha256, self.bundle_sha256, self.model_sha256)


def bind(context, *, bundle_sha256, model_sha256):
    if type(context) not in (ReleaseContext, QualificationContext) or (
        context.bundle_sha256,
        context.model_sha256,
    ) != (bundle_sha256, model_sha256):
        raise Rejected("serving_context_binding")
    return context
