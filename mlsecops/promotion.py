import psycopg

from mlsecops import promotion_state, release_authorization, release_bundle, storage
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.release_policy import checked


def publish(client, content):
    reference = storage.put(client, "releases", content)
    if reference != digest(content):
        raise Rejected("promotion_receipt_mismatch")
    return reference


def promote(client, **arguments):
    if "clock" in arguments:
        raise Rejected("promotion_clock_override_forbidden")
    if storage.connection_parameters(client)["user"] != "ml_promoter":
        raise Rejected("promotion_storage_identity")
    try:
        with storage.connect(client) as connection:
            clock = connection.execute(
                "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint"
            ).fetchone()[0]
    except psycopg.Error as error:
        raise Rejected(f"promotion_clock_unavailable:{error.sqlstate or 'unavailable'}") from None
    decision = release_authorization.verify(**arguments, clock=clock)
    policy = arguments["policy_envelope"]
    authority = checked(policy, "promotion-policy", arguments["trusted_root"])
    approval = checked(
        arguments["approval_envelope"],
        "release-approval",
        authority["identities"]["approver"]["public_key"],
    )
    proposal = release_bundle.publish(
        client,
        arguments["package"],
        context=arguments["context"],
        publisher_public=authority["identities"]["publisher"]["public_key"],
        expected_serving_image=arguments["expected_serving_image"],
        clock=clock,
    )
    report_references = {
        gate: publish(client, content) for gate, content in arguments["reports"].items()
    }
    authorization = {
        "schema_version": 1,
        "policy_envelope": policy,
        "assurance_envelope": arguments["assurance_envelope"],
        "approval_envelope": arguments["approval_envelope"],
        "reports": report_references,
        "decision": decision,
    }
    proof = publish(client, canonical(authorization))
    selection = {
        "schema_version": 1,
        "kind": "promotion-selection",
        "environment": decision["environment"],
        "policy_sha256": decision["policy_sha256"],
        "sequence": decision["sequence"],
        "subject_sha256": decision["subject_sha256"],
        "proposal_reference": proposal,
        "authorization_reference": proof,
        "issued_at": approval["issued_at"],
        "expires_at": decision["expires_at"],
    }
    content = canonical(selection)
    promotion_state.request(content)
    reference = publish(client, content)
    try:
        with storage.connect(client) as connection:
            receipt = connection.execute(
                "SELECT ml_promotion.record_selection(%s)", (reference,)
            ).fetchone()
            if receipt != (reference,):
                raise Rejected("promotion_state_receipt_mismatch")
        with storage.connect(client) as connection:
            observed = connection.execute(
                "SELECT request_sha256 FROM ml_promotion.events WHERE environment = %s AND sequence = %s",
                (selection["environment"], selection["sequence"]),
            ).fetchone()
    except psycopg.Error as error:
        raise Rejected(f"promotion_commit_unconfirmed:{error.sqlstate or 'unavailable'}") from None
    if observed != (reference,) or storage.get(client, "releases", reference) != content:
        raise Rejected("promotion_state_readback_mismatch")
    return {
        "state": "recorded-not-activated",
        "environment": selection["environment"],
        "sequence": selection["sequence"],
        "request_sha256": reference,
        "proposal_reference": proposal,
        "subject_sha256": decision["subject_sha256"],
        "release_ready": False,
    }
