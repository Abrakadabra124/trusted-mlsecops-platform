"""Re-sign controlled fixture evidence after a delegated role changes; never actual assurance."""

import copy
import uuid
from datetime import UTC, datetime

from mlsecops import release_key_rotation, release_policy, signing
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.storage import object_id
from scripts.serving_native import bind_release


def prepare(fixture, image, *, role, head, clock):
    if role not in release_policy.ROLES:
        raise Rejected("controlled_release_rotation_role")
    require_fields(head, ("sequence", "request_sha256"))
    release_policy.integer(head["sequence"])
    release_policy.integer(head["sequence"] + 1)
    object_id(head["request_sha256"])
    release_policy.integer(clock)
    authorization = fixture.fixture
    root = fixture.arguments["trusted_root"]
    previous_pin = fixture.arguments["expected_policy"]
    previous = release_policy.verify_policy(
        fixture.arguments["policy_envelope"],
        trusted_root=root,
        expected_policy=previous_pin,
        environment=authorization.policy["environment"],
        clock=clock,
    )
    release_policy.integer(previous["version"] + 1)
    successor = copy.deepcopy(previous)
    successor.update(version=previous["version"] + 1, issued_at=clock)
    key = authorization.authorities.directory / f"release-{role}-v{successor['version']}.pem"
    public = signing.create_key(key)
    successor["identities"][role]["public_key"] = public
    following_pin = digest(canonical(successor))
    owner = authorization.authorities.keys["root"]
    next_policy = signing.sign(successor, "promotion-policy", owner)
    intent = {
        "schema_version": 1,
        "environment": previous["environment"],
        "role": role,
        "previous_policy_sha256": previous_pin,
        "next_policy_sha256": following_pin,
        **head,
        "issued_at": clock,
        "expires_at": min(clock + 300, successor["expires_at"]),
    }
    package = {
        "schema_version": 1,
        "authorization": signing.sign(intent, "release-key-rotation", owner),
        "previous_policy": fixture.arguments["policy_envelope"],
        "next_policy": next_policy,
    }
    release_key_rotation.verify(
        package,
        trusted_root=root,
        expected_policy=previous_pin,
        head=head,
        environment=previous["environment"],
        clock=clock,
    )
    authorization.authorities.keys[role] = key
    authorization.authorities.public[role] = public
    authorization.authorities.policy = successor
    authorization.authorities.envelope = next_policy
    authorization.authorities.pin = following_pin
    authorization.policy, authorization.policy_envelope = successor, next_policy
    authorization.policy_hash = following_pin
    bundle = authorization.bundle
    if role == "publisher":
        bundle.materials.key, bundle.materials.public = key, public
        bundle.arguments["publisher_public"] = public
        bundle.capsule = bundle.materials.create()
    expires = min(clock + 1800, successor["expires_at"])
    bundle.attributes.update(
        sequence=head["sequence"] + 1,
        release_id=uuid.uuid4().hex,
        issued_at=clock,
        expires_at=expires,
    )
    bundle.arguments["clock"] = clock
    for value in (authorization.assurance, authorization.approval):
        value.update(policy_sha256=following_pin, issued_at=clock, expires_at=expires)
    authorization.approval["sequence"] = head["sequence"] + 1
    timestamp = datetime.fromtimestamp(clock, UTC).isoformat()
    authorization.reports = {
        gate: canonical({**decode(content), "started_at": timestamp, "finished_at": timestamp})
        for gate, content in authorization.reports.items()
    }
    fixture.arguments.update(policy_envelope=next_policy, expected_policy=following_pin)
    bind_release(fixture, image)
    return package
