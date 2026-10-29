"""Hosted source binding for candidate qualification; runtime reader is shared."""

import copy

from mlsecops import material_bundle, release_bundle, release_policy
from mlsecops.candidate_serving_reader import (
    KIND as KIND,
)
from mlsecops.candidate_serving_reader import (
    CandidateReader as CandidateReader,
)
from mlsecops.candidate_serving_reader import (
    QualifiedCandidate as QualifiedCandidate,
)
from mlsecops.contracts import Rejected, canonical, digest
from scripts.candidate_lineage_native import KNOWN_OWNERS, OWNERS


def bind_proposal(report, package, *, policy, source_trust, publisher_public, expected, clock):
    required = {
        "scope": "release-proposal-and-authorization-denial-not-full-M10",
        "status": "pass",
        "source_dirty": False,
        "release_ready": False,
        "source": expected,
        "proposal_reference": digest(canonical(package["envelope"])),
    }
    if not isinstance(report, dict) or canonical(
        {key: report.get(key) for key in required}
    ) != canonical(required):
        raise Rejected("qualification_source_report_binding")
    capsule = release_policy.checked(
        package["capsule"]["envelope"], material_bundle.KIND, publisher_public
    )
    context = {
        "candidate_reference": capsule["candidate_reference"],
        "evaluation_reference": capsule["evaluation_reference"],
        "policy": policy,
        "trust": source_trust,
        "expected": expected,
        "owners": copy.deepcopy(OWNERS),
        "known_owners": list(KNOWN_OWNERS),
    }
    verified = release_bundle.verify(
        package,
        context=context,
        publisher_public=publisher_public,
        expected_serving_image=expected["image_id"],
        clock=clock,
    )
    if (report.get("subject_sha256"), report.get("model_sha256")) != (
        verified["subject_sha256"],
        digest(verified["model"]),
    ):
        raise Rejected("qualification_source_subject_binding")
    return context, verified
