from mlsecops import artifact_intake
from mlsecops.contracts import digest


def receipt(content, image_id, scan):
    return artifact_intake.inspect_candidate(
        content,
        digest(content),
        image_id,
        image_id,
        lambda image, request: (artifact_intake.response(request, scan), {"image_id": image_id}),
    )
