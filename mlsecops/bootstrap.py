import argparse
import secrets
import sys
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from mlsecops.inventory import collect
from mlsecops.signing import ROLES, create_key


def initialize(root, state):
    root = Path(root).resolve()
    state = Path(state)
    if state.is_symlink():
        raise Rejected("symlink_state")
    state = state.resolve()
    inventory = collect(root)
    marker = state / "workspace.json"
    if state.exists() and any(state.iterdir()) and not marker.is_file():
        raise Rejected("refusing_nonempty_unowned_workspace")
    state.mkdir(parents=True, exist_ok=True)
    if marker.exists():
        identity = read_json(marker)
        if identity.get("product") != "trusted-mlsecops" or identity.get("schema_version") != 1:
            raise Rejected("incompatible_workspace")
    else:
        write_json(
            marker,
            {
                "product": "trusted-mlsecops",
                "schema_version": 1,
                "workspace_id": secrets.token_hex(16),
            },
        )
    public = {role: create_key(state / "keys" / f"{role}.pem") for role in ROLES}
    trusted = state / "trusted-keys.json"
    if trusted.exists():
        if read_json(trusted) != public:
            raise Rejected("key_rotation_requires_explicit_migration")
    else:
        write_json(trusted, public)
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
