"""Submit immutable signed release references under operator-pinned authority."""

import sys
from pathlib import Path

import psycopg

from mlsecops import (
    promotion,
    release_bundle,
    release_policy,
    release_rollback,
    storage,
    trust,
    trust_authority,
)
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, require_fields
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce as enforce_privacy
from mlsecops.release_reader import document

CONFIG_FIELDS = (
    "schema_version",
    "storage_client",
    "trust_client",
    "context",
    "trusted_root",
    "expected_policy",
    "expected_serving_image",
    "trust_root",
    "minimum_trust_version",
)
REQUEST_FIELDS = (
    "schema_version",
    "proposal_reference",
    "policy_reference",
    "assurance_reference",
    "approval_reference",
)


def submit(config, request):
    try:
        return _submit(
            decode(canonical(config), release_policy.MAX_DOCUMENT),
            decode(canonical(request), 65536),
        )
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("promotion_controller_shape") from error


def _submit(config, request):
    require_fields(config, CONFIG_FIELDS)
    require_fields(request, REQUEST_FIELDS)
    if any(
        type(value["schema_version"]) is not int or value["schema_version"] != 1
        for value in (config, request)
    ):
        raise Rejected("promotion_controller_schema")
    for field in ("storage_client", "trust_client"):
        if type(config[field]) is not str or not Path(config[field]).is_absolute():
            raise Rejected("promotion_controller_client_path")
        if storage.connection_parameters(config[field])["user"] != "ml_promoter":
            raise Rejected("promotion_controller_identity")
    for field in REQUEST_FIELDS[1:]:
        if request[field] is not None or field not in ("assurance_reference", "approval_reference"):
            storage.object_id(request[field])
    environment = config["context"]["policy"]["environment"]
    lease = trust.Lease(
        lambda: trust_authority.read(config["trust_client"], environment, config["trust_root"]),
        trusted_root=config["trust_root"],
        environment=environment,
        minimum_version=config["minimum_trust_version"],
    )
    client = config["storage_client"]
    try:
        with storage.connect(client) as connection:
            clock = connection.execute(
                "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint"
            ).fetchone()[0]
    except psycopg.Error:
        raise Rejected("promotion_controller_clock_unavailable") from None
    policy_envelope = document(client, request["policy_reference"], release_policy.MAX_DOCUMENT)
    policy = release_policy.verify_policy(
        policy_envelope,
        trusted_root=config["trusted_root"],
        expected_policy=config["expected_policy"],
        environment=environment,
        clock=clock,
    )
    package = release_bundle.load(
        client,
        request["proposal_reference"],
        publisher_public=policy["identities"]["publisher"]["public_key"],
    )
    envelopes = {
        kind + "_envelope": None
        if request[kind + "_reference"] is None
        else document(client, request[kind + "_reference"], release_policy.MAX_DOCUMENT)
        for kind in ("assurance", "approval")
    }
    reports = {}
    if envelopes["assurance_envelope"] is not None:
        assurance = release_policy.checked(
            envelopes["assurance_envelope"],
            "release-assurance",
            policy["identities"]["assessor"]["public_key"],
        )
        references = assurance["reports"]
        require_fields(references, policy["required_gates"])
        for gate, reference in references.items():
            reference = storage.object_id(reference)
            content = storage.get(client, "releases", reference)
            if (
                not isinstance(content, bytes)
                or not 0 < len(content) <= release_policy.MAX_DOCUMENT
                or digest(content) != reference
            ):
                raise Rejected("promotion_controller_report_integrity")
            reports[gate] = content
            if sum(map(len, reports.values())) > 8 * release_policy.MAX_DOCUMENT:
                raise Rejected("promotion_controller_reports_size")
    return promotion.promote(
        client,
        trust_lease=lease,
        package=package,
        policy_envelope=policy_envelope,
        **envelopes,
        reports=reports,
        **{
            key: config[key]
            for key in ("context", "trusted_root", "expected_policy", "expected_serving_image")
        },
    )


def configured(config_path, request_path):
    return submit(
        decode(bounded_read(config_path, release_policy.MAX_DOCUMENT), release_policy.MAX_DOCUMENT),
        decode(bounded_read(request_path, 65536), 65536),
    )


def main(arguments=None):
    try:
        enforce_privacy()
        parser = Arguments(
            prog="promotion", description="Submit signed immutable release references"
        )
        parser.add_argument("--config", type=Path, required=True)
        parser.add_argument("--request", type=Path, required=True)
        options = parser.parse_args(arguments)
        result = configured(options.config, options.request)
        print(canonical(result).decode())
        return 0
    except (Exception, KeyboardInterrupt) as error:
        reason = (
            "promotion_sequence_conflict"
            if isinstance(error, Rejected) and str(error) == "promotion_commit_unconfirmed:P1004"
            else "promotion_rejected"
        )
        if isinstance(error, Rejected) and str(error) in release_rollback.PUBLIC_REJECTIONS:
            reason = str(error)
        print(reason, file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
