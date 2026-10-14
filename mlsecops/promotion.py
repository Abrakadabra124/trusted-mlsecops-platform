import psycopg

from mlsecops import promotion_state, release_authorization, release_bundle, signing, storage
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.release_policy import checked


def publish(client, content):
    reference = storage.put(client, "releases", content)
    if reference != digest(content):
        raise Rejected("promotion_receipt_mismatch")
    return reference


def trust_scope(arguments, decision, authority):
    package = arguments["package"]
    manifest = release_bundle.index(
        package["envelope"], authority["identities"]["publisher"]["public_key"]
    )
    projection = decode(package["documents"]["asset_projection"])
    split = decode(package["documents"]["split_manifest"])
    artifacts = {
        digest(canonical(package["envelope"])),
        *(
            digest(canonical(arguments[name]))
            for name in ("policy_envelope", "assurance_envelope", "approval_envelope")
        ),
        decision["subject_sha256"],
        decision["policy_sha256"],
        decision["assurance_sha256"],
        decision["approval_sha256"],
        *manifest["materials"].values(),
        manifest["training_image"].removeprefix("sha256:"),
        manifest["serving_image"].removeprefix("sha256:"),
        *(reference for _, reference in package["capsule"]["objects"]),
        *(asset["sha256"] for asset in projection["graph"]["assets"]),
        arguments["context"]["trust"]["source_approval_digest"],
        projection["bindings"]["lineage_id"],
        projection["bindings"]["source_fingerprint"],
        *(item["sha256"] for item in split["objects"].values()),
        *(digest(content) for content in arguments["reports"].values()),
    }
    keys = {
        digest(signing.decode64(public))
        for public in (
            arguments["trusted_root"],
            *(identity["public_key"] for identity in authority["identities"].values()),
            *(arguments["context"]["trust"][role] for role in ("curator", "evaluator")),
        )
    }
    return {"policy_sha256": decision["policy_sha256"], "artifacts": artifacts, "keys": keys}


def promote(client, *, trust_lease=None, **arguments):
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
    if trust_lease is None:
        raise Rejected("promotion_online_trust_required")
    if trust_lease.environment != decision["environment"]:
        raise Rejected("promotion_trust_environment_mismatch")
    scope = trust_scope(arguments, decision, authority)
    trust_lease.refresh()
    trust_lease.check(**scope)
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
    trust_lease.refresh()
    trust_lease.check(**scope)
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
    trust_lease.refresh()
    trust_observation = trust_lease.check(**scope)
    return {
        "state": "recorded-not-activated",
        "environment": selection["environment"],
        "sequence": selection["sequence"],
        "request_sha256": reference,
        "proposal_reference": proposal,
        "subject_sha256": decision["subject_sha256"],
        "trust": trust_observation,
        "release_ready": False,
    }
