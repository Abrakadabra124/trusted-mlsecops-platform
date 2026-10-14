import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import release_policy
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.signing import create_key, encode64, load_key, pae, sign


class ReleasePolicyContracts(unittest.TestCase):
    def test_bounded_canonical_payload_and_diagnostic_errors(self):
        with self.assertRaisesRegex(Rejected, "document_too_large"):
            self.check({"payload": "x" * (1024 * 1024 + 1)})
        nested = []
        for _ in range(1100):
            nested = [nested]
        with self.assertRaises(Rejected):
            self.check({"payload": nested})
        with (
            patch.object(release_policy, "canonical", side_effect=RecursionError),
            self.assertRaisesRegex(Rejected, "document_nesting"),
        ):
            self.check()
        content = b" " + canonical(self.policy)
        altered = copy.deepcopy(self.envelope)
        altered["payload"] = encode64(content)
        altered["signatures"][0]["sig"] = encode64(
            load_key(self.keys["root"]).sign(pae(altered["payloadType"], content))
        )
        with self.assertRaisesRegex(Rejected, "noncanonical_payload"):
            self.check(altered)
        for invalid in (None, "", "../root", "UPPER"):
            with self.assertRaisesRegex(Rejected, "invalid_identity"):
                release_policy.name(invalid)
        for invalid in (True, 0, -1, 2**53):
            with self.assertRaisesRegex(Rejected, "invalid_integer"):
                release_policy.integer(invalid)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.keys = {
            role: self.directory / f"{role}.pem"
            for role in ("root", "publisher", "assessor", "approver")
        }
        self.public = {role: create_key(path) for role, path in self.keys.items()}
        self.clock = 2000000000
        self.policy = {
            "schema_version": 1,
            "environment": "local-cpu",
            "version": 1,
            "issued_at": self.clock - 60,
            "expires_at": self.clock + 3600,
            "required_gates": list(release_policy.GATES),
            "identities": {
                role: {"issuer": f"lab-{role}", "public_key": self.public[role]}
                for role in ("publisher", "assessor", "approver")
            },
        }
        self.envelope = sign(self.policy, "promotion-policy", self.keys["root"])
        self.pin = digest(canonical(self.policy))

    def check(self, envelope=None, **changes):
        arguments = {
            "trusted_root": self.public["root"],
            "expected_policy": self.pin,
            "environment": "local-cpu",
            "clock": self.clock,
        }
        arguments.update(changes)
        return release_policy.verify_policy(
            self.envelope if envelope is None else envelope, **arguments
        )

    def test_signature_is_not_policy_authority_without_external_pin(self):
        self.assertEqual(self.check(), self.policy)
        for changes in (
            {"expected_policy": "0" * 64},
            {"environment": "production"},
            {"trusted_root": self.public["publisher"]},
        ):
            with self.assertRaises(Rejected):
                self.check(**changes)

    def test_weak_gate_set_self_approval_schema_and_time_are_rejected(self):
        variants = []
        for name, value in (
            ("schema_version", True),
            ("required_gates", ["M07"]),
            ("expires_at", self.clock),
            ("issued_at", self.clock + 1),
            ("version", 0),
        ):
            variants.append({**self.policy, name: value})
        repeated = copy.deepcopy(self.policy)
        repeated["identities"]["approver"]["public_key"] = self.public["publisher"]
        variants.append(repeated)
        for invalid in variants:
            with self.subTest(invalid=invalid.keys()), self.assertRaises(Rejected):
                self.check(
                    sign(invalid, "promotion-policy", self.keys["root"]),
                    expected_policy=digest(canonical(invalid)),
                )


if __name__ == "__main__":
    unittest.main()
