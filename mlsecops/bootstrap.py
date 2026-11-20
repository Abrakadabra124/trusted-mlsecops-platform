import argparse
import re
import secrets
import sys
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mlsecops import key_files
from mlsecops.contracts import (
    Rejected,
    canonical,
    digest,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.inventory import collect
from mlsecops.signing import ROLES, create_key, encode64, load_key


def initialize(root, state, *, trust_key_path=None):
    """Initialize an owned workspace; a supplied original trust identity is never rotated."""
    root = Path(root).resolve()
    state = Path(state)
    if state.is_symlink():
        raise Rejected("symlink_state")
    state = state.resolve()
    private = None
    if trust_key_path is not None:
        # Validate one bounded snapshot before inventory or any workspace writes.
        # Never reopen the caller's file to import potentially different bytes.
        private = key_files.read(trust_key_path)
        try:
            original = serialization.load_pem_private_key(private, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            raise Rejected("invalid_signing_key") from None
        if not isinstance(original, Ed25519PrivateKey):
            raise Rejected("wrong_key_algorithm")
        original_public = encode64(original.public_key().public_bytes_raw())
    marker = safe_child(state, "workspace.json")
    if state.exists() and any(state.iterdir()) and not marker.is_file():
        raise Rejected("refusing_nonempty_unowned_workspace")
    existing = marker.exists()
    if existing:
        identity = read_json(marker)
        require_fields(identity, ("product", "schema_version", "workspace_id"))
        if (
            identity["product"] != "trusted-mlsecops"
            or type(identity["schema_version"]) is not int
            or identity["schema_version"] != 1
            or type(identity["workspace_id"]) is not str
            or re.fullmatch("[a-f0-9]{32}", identity["workspace_id"]) is None
        ):
            raise Rejected("incompatible_workspace")
        public = {
            role: encode64(
                load_key(safe_child(state, f"keys/{role}.pem")).public_key().public_bytes_raw()
            )
            for role in ROLES
        }
        if read_json(safe_child(state, "trusted-keys.json")) != public:
            raise Rejected("key_rotation_requires_explicit_migration")
        if private is not None and public["trust"] != original_public:
            raise Rejected("key_rotation_requires_explicit_migration")
    inventory = collect(root)
    state.mkdir(parents=True, exist_ok=True)
    if not existing:
        write_json(
            marker,
            {
                "product": "trusted-mlsecops",
                "schema_version": 1,
                "workspace_id": secrets.token_hex(16),
            },
        )
        public = {}
        for role in ROLES:
            path = safe_child(state, f"keys/{role}.pem")
            if role == "trust" and private is not None:
                # Exclusive creation and fsync use the same private-file contract as signing.
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with key_files.opened(path, create=True) as output:
                    output.write(private)
                public[role] = original_public
            else:
                public[role] = create_key(path)
        write_json(state / "trusted-keys.json", public)
    for name in ("quarantine", "approved", "candidates", "evaluations", "releases", "evidence"):
        (state / name).mkdir(exist_ok=True)
    write_json(state / "inventory.json", inventory)
    return {
        "workspace_digest": digest(canonical(read_json(marker))),
        "public_keys_digest": digest(canonical(public)),
        "policy_digest": digest(canonical(read_json(root / "policies/local-cpu.json"))),
        "schema_version": 1,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    arguments = parser.parse_args()
    try:
        result = initialize(Path(__file__).resolve().parents[1], arguments.state)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        print(f"Bootstrap rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
