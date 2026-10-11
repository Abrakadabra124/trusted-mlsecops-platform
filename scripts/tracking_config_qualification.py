import copy
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import tracking_config
from scripts.tracking_config import configuration, initialize, validate


def qualify():
    cases = []
    with tempfile.TemporaryDirectory(prefix="tracking-config-") as directory:
        state = Path(directory)
        initial = initialize(state, "sha256:" + "a" * 64, 15445)
        if initialize(state, initial["image"], 15445) != initial:
            raise Rejected("tracking_init_not_idempotent")
        cases.append("idempotent-state")
        files = configuration(state, initial)
        if set(files) != {"postgres", "server"}:
            raise Rejected("tracking_config_roles_invalid")
        hba = files["postgres"]["pg_hba.conf"].decode()
        for role in ("tracking_metadata", "tracking_auth"):
            if f"hostssl {role} {role} 0.0.0.0/0 cert" not in hba:
                raise Rejected("tracking_database_role_not_scoped")
        if "host all all 0.0.0.0/0 reject" not in hba or "trust" in hba:
            raise Rejected("tracking_hba_not_fail_closed")
        cases.append("database-specific-cert-auth")
        if "ca.key" in files["server"] or "ca.key" in files["postgres"]:
            raise Rejected("tracking_ca_key_leaked")
        cases.append("ca-private-key-host-only")
        for name, mutate in (
            ("image-change", lambda value: value.update(image="sha256:" + "b" * 64)),
            ("port-change", lambda value: value.update(port=15446)),
            ("owner-change", lambda value: value.update(identity="b" * 32)),
            ("material-change", lambda value: value["files"].update({"ca.crt": "b" * 64})),
        ):
            invalid = copy.deepcopy(initial)
            mutate(invalid)
            try:
                validate(state, invalid)
            except Rejected:
                cases.append(name)
            else:
                raise Rejected("tracking_config_mutation_accepted:" + name)
        for name, image, port in (
            ("mutable-image", "latest", 15445),
            ("root-port", initial["image"], 443),
            ("boolean-port", initial["image"], True),
        ):
            try:
                initialize(state, image, port)
            except Rejected:
                cases.append(name)
            else:
                raise Rejected("tracking_invalid_init_accepted:" + name)
        future = datetime.now(UTC) + timedelta(days=31)
        with patch.object(tracking_config, "datetime") as clock:
            clock.now.return_value = future
            try:
                validate(state, initial)
            except Rejected:
                cases.append("expired-certificate-denies-up")
            else:
                raise Rejected("tracking_expired_certificate_accepted")
            validate(state, initial, require_current_certificates=False)
            cases.append("unchanged-expired-certificate-allows-safe-stop")
        (state / "ca.crt").write_bytes(b"invalid")
        try:
            validate(state, initial)
        except Rejected:
            cases.append("changed-certificate-denied")
        else:
            raise Rejected("tracking_changed_certificate_accepted")
    return {"status": "pass", "scope": "tracking-configuration-contracts", "checks": len(cases)}


if __name__ == "__main__":
    print(canonical(qualify()).decode())
