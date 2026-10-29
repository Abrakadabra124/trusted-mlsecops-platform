"""Controlled approvals for expiry tests; never used for an actual candidate."""

import time

from mlsecops.contracts import Rejected
from mlsecops.signing import sign
from scripts.serving_native import bind_release


def shorten(fixture):
    authorization = fixture.fixture
    expires = int(time.time()) + 90
    if not authorization.approval["issued_at"] < expires < authorization.assurance["expires_at"]:
        raise Rejected("controlled_approval_window")
    authorization.approval["expires_at"] = expires
    fixture.arguments["approval_envelope"] = sign(
        authorization.approval, "release-approval", authorization.authorities.keys["approver"]
    )
    return expires


def renew(fixture, image):
    authorization = fixture.fixture
    if authorization.bundle.attributes["sequence"] != 1 or authorization.approval["sequence"] != 1:
        raise Rejected("controlled_approval_sequence")
    authorization.bundle.attributes.update(sequence=2, release_id="2" * 32)
    authorization.approval.update(sequence=2, expires_at=authorization.assurance["expires_at"])
    # The changed descriptor changes its subject, every report binding, the
    # assurance and the approval. Re-sign all of these controlled materials.
    bind_release(fixture, image)
