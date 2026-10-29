"""Explicit operator rotation; consumers adopt separately pinned keys, never requests."""

import sys

from mlsecops import trust_authority, trust_rotation
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json
from mlsecops.private_cli import Arguments


def migrate(state, *, backend=None):
    container, _ = trust_authority.current(state, backend=backend)
    _, execute = trust_authority.commands(state, backend)
    checksum = digest(trust_rotation.migration_sql().encode())
    if trust_authority.migration_version(container, execute) == 2:
        return {"migration_sha256": checksum, "reused": True, "release_ready": False}
    execute(
        container,
        f"""BEGIN;
SELECT pg_advisory_xact_lock(19293822);
SET LOCAL ROLE ml_owner;
DO $upgrade$ BEGIN
    IF NOT EXISTS (SELECT FROM ml_trust.migrations WHERE version = 2) THEN
        {trust_rotation.migration_sql()}
        INSERT INTO ml_trust.migrations VALUES (2, '{checksum}');
    END IF;
END $upgrade$;
COMMIT;""",
    )
    if trust_authority.migration_version(container, execute) != 2:
        raise Rejected("rotation_migration_unconfirmed")
    return {"migration_sha256": checksum, "reused": False, "release_ready": False}


def rotate(state, package, *, current_root, next_root, backend=None):
    intent = trust_rotation.authorization(package, current_root)
    container, before = trust_authority.current(state, backend=backend)
    _, execute = trust_authority.commands(state, backend)
    if trust_authority.migration_version(container, execute) != 2:
        raise Rejected("rotation_migration_required")
    reference, content = digest(canonical(package)), canonical(package)
    old = (current_root, intent["previous_version"], intent["previous_sha256"])
    new = (next_root, intent["next_version"], intent["next_sha256"])
    head = (before["root_public"], before["version"], before["sha256"])
    if head == old:
        previous, reused = before["envelope"], False
    elif head == new:
        raw = execute(
            container,
            "SELECT encode(envelope, 'hex') FROM ml_trust.documents "
            f"WHERE sha256 = '{intent['previous_sha256']}';",
        )
        prior_bytes = bytes.fromhex(raw)
        if digest(prior_bytes) != intent["previous_sha256"]:
            raise Rejected("rotation_previous_integrity")
        previous, reused = decode(prior_bytes), True
    else:
        raise Rejected("rotation_head_changed")
    verified = trust_rotation.verify(
        package,
        previous=previous,
        environment=before["environment"],
        current_root=current_root,
        next_root=next_root,
        clock=before["clock"],
    )
    if not reused:
        document = canonical(package["document"])
        execute(
            container,
            f"""BEGIN;
SELECT pg_advisory_xact_lock(19293822);
DO $guard$ DECLARE observed_root text; observed_environment text; observed_version bigint;
    observed_reference text; observed_clock bigint;
BEGIN
    SELECT root_public, environment INTO observed_root, observed_environment FROM ml_trust.settings;
    SELECT version, sha256 INTO observed_version, observed_reference
        FROM ml_trust.documents ORDER BY version DESC LIMIT 1;
    IF observed_root IS DISTINCT FROM '{current_root}'
      OR observed_environment IS DISTINCT FROM '{verified["environment"]}'
      OR observed_version IS DISTINCT FROM {verified["previous_version"]}
      OR observed_reference IS DISTINCT FROM '{verified["previous_sha256"]}' THEN
        RAISE EXCEPTION 'rotation_concurrent_update_conflict';
    END IF;
    observed_clock := floor(extract(epoch FROM clock_timestamp()))::bigint;
    IF observed_clock < {verified["issued_at"]} OR observed_clock >= {verified["expires_at"]} THEN
        RAISE EXCEPTION 'rotation_expired_or_future';
    END IF;
END $guard$;
SET LOCAL ROLE ml_owner;
INSERT INTO ml_trust.documents VALUES (
    {verified["next_version"]}, '{verified["next_sha256"]}', decode('{document.hex()}', 'hex'));
UPDATE ml_trust.settings SET root_public = '{next_root}';
INSERT INTO ml_trust.root_rotations VALUES (
    {verified["next_version"]}, '{reference}', decode('{content.hex()}', 'hex'));
COMMIT;""",
        )
        _, observed = trust_authority.current(state, backend=backend)
        if (observed["root_public"], observed["version"], observed["sha256"]) != new:
            raise Rejected("rotation_commit_unconfirmed")
    recorded = execute(
        container,
        "SELECT encode(package, 'hex') FROM ml_trust.root_rotations "
        f"WHERE version = {verified['next_version']};",
    )
    if recorded != content.hex():
        raise Rejected("rotation_receipt_unconfirmed")
    return {
        "state": "rotated-not-activated",
        "version": verified["next_version"],
        "document_sha256": verified["next_sha256"],
        "rotation_sha256": reference,
        "root_sha256": trust_rotation.key_id(next_root),
        "reused": reused,
        "release_ready": False,
    }


def main(arguments=None):
    try:
        parser = Arguments(prog="trust-root-store")
        parser.add_argument("action", choices=("migrate", "rotate"))
        parser.add_argument("--state", required=True)
        parser.add_argument("--backend", choices=("docker", "kubernetes"), default="docker")
        parser.add_argument("--confirm-authority", action="store_true")
        parser.add_argument("--document")
        parser.add_argument("--current-root")
        parser.add_argument("--next-root")
        options = parser.parse_args(arguments)
        if not options.confirm_authority:
            raise Rejected("rotation_explicit_authority_confirmation_required")
        backend = None
        if options.backend == "kubernetes":
            from mlsecops.kube_trust import binding

            backend = binding
        if options.action == "migrate":
            result = migrate(options.state, backend=backend)
        else:
            if None in (options.document, options.current_root, options.next_root):
                raise Rejected("rotation_document_and_operator_pins_required")
            result = rotate(
                options.state,
                read_json(options.document),
                current_root=options.current_root,
                next_root=options.next_root,
                backend=backend,
            )
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError, ValueError):
        print(
            canonical(
                {"status": "fail", "error": "trust_rotation_rejected", "release_ready": False}
            ).decode(),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
