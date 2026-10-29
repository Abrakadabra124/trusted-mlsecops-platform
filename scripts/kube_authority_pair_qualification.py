"""Negative contracts for independent trust histories; no local infrastructure."""

import copy
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import kube_candidate_probe as probe
from mlsecops.contracts import Rejected, digest
from mlsecops.signing import encode64
from mlsecops.trust_targets import Target
from scripts import kube_authority_pair as pair
from scripts import kube_candidate_terminals as terminals

PUBLIC = encode64(b"r" * 32)
POLICY, MODEL, KEY, SUBJECT = (char * 64 for char in "pmkb")


def states():
    return {
        target.value: {
            "identity": {
                "target": target.value,
                "host": target.host,
                "ca_sha256": digest(target.value.encode()),
                "root_sha256": digest(b"r" * 32),
                "resources_sha256": digest((target.value + "resources").encode()),
                "volume_uid_sha256": digest((target.value + "volume").encode()),
                "spec_digest": digest((target.value + "spec").encode()),
            },
            "history_sha256": digest((target.value + "history").encode()),
            "version": 7,
            "policy_sha256": POLICY,
            "revoked_artifacts": ["a" * 64],
            "revoked_keys": ["c" * 64],
        }
        for target in Target
    }


def isolation(target, snapshot=None):
    snapshot = states() if snapshot is None else snapshot
    other = Target.MODEL_REVOCATION if target is Target.PRIMARY else Target.PRIMARY
    return {
        "authority_isolation": {
            "target": target.value,
            "host": target.host,
            "ca_sha256": snapshot[target.value]["identity"]["ca_sha256"],
            "other_target": other.value,
            "cross_ca_denied": True,
        }
    }


def revoked(before, target):
    result = copy.deepcopy(before)
    row = result[target.value]
    field, reference = (
        ("revoked_keys", KEY) if target is Target.PRIMARY else ("revoked_artifacts", MODEL)
    )
    row[field] = sorted([*row[field], reference])
    row["version"] += 1
    row["history_sha256"] = digest((row["history_sha256"] + "append").encode())
    return result


class AuthorityPairTests(unittest.TestCase):
    def test_read_binds_owned_resource_inventory_and_entire_ordered_history(self):
        for target in Target:
            marker = {"resources": {"pvc": "uid"}, "volume_uid": "volume", "spec_digest": "d" * 64}
            current = {"envelope": {}, "root_public": PUBLIC, "environment": "lab", "clock": 100}
            payload = {
                k: v
                for k, v in states()[target.value].items()
                if k not in ("identity", "history_sha256")
            }
            payload["promotion_policy_sha256"] = payload.pop("policy_sha256")

            def get_current(state, *, backend):
                selected, admin = backend(state)
                self.assertEqual(selected, state)
                self.assertEqual(admin.keywords, {"target": target})
                return {}, current

            with (
                patch.object(pair.kube_trust, "validate", return_value=marker) as validate,
                patch.object(pair.kube_trust, "admin", return_value="e" * 64) as admin,
                patch.object(pair.kube_trust, "directory", return_value=Path.cwd()) as directory,
                patch.object(pair.trust_authority, "current", side_effect=get_current),
                patch.object(pair.trust, "validate", return_value=payload) as trust_validate,
                patch.object(pair, "bounded_read", return_value=b"certificate"),
            ):
                result = pair.read("state", target.value)
            validate.assert_called_once_with("state", target=target)
            directory.assert_called_once_with("state", target=target)
            trust_validate.assert_called_once_with({}, PUBLIC, "lab", 100)
            self.assertEqual(admin.call_args.kwargs, {"target": target})
            for text in ("ml_trust.settings", "ml_trust.documents", "ORDER BY version", "sha256"):
                self.assertIn(text, admin.call_args.args[1])
            self.assertEqual(result["history_sha256"], "e" * 64)
            self.assertEqual(result["identity"]["ca_sha256"], digest(b"certificate"))

    def test_capture_rejects_shared_resources_or_different_root_policy(self):
        for field in (
            None,
            "host",
            "ca_sha256",
            "resources_sha256",
            "volume_uid_sha256",
            "spec_digest",
            "root_sha256",
            "policy_sha256",
        ):
            observed = states()
            primary, alternate = observed.values()
            if field == "policy_sha256":
                alternate[field] = "wrong"
            elif field == "root_sha256":
                alternate["identity"][field] = "wrong"
            elif field:
                alternate["identity"][field] = primary["identity"][field]
            with (
                self.subTest(field=field),
                patch.object(
                    pair, "read", side_effect=lambda state, target: observed[target.value]
                ),
            ):
                if field:
                    with self.assertRaisesRegex(Rejected, "candidate_authorities_"):
                        pair.capture("state", PUBLIC, POLICY)
                else:
                    self.assertEqual(pair.capture("state", PUBLIC, POLICY), observed)

    def test_transition_requires_exact_append_and_unchanged_peer_history(self):
        for target in Target:
            field, reference = (
                ("revoked_keys", KEY) if target is Target.PRIMARY else ("revoked_artifacts", MODEL)
            )
            other = Target.MODEL_REVOCATION if target is Target.PRIMARY else Target.PRIMARY
            remaining = "revoked_artifacts" if target is Target.PRIMARY else "revoked_keys"
            for fault in (
                None,
                "peer",
                "identity",
                "policy_sha256",
                "version",
                "history_sha256",
                "already",
                "drop",
                "extra",
                "other_revoke",
            ):
                before = states()
                after = revoked(before, target)
                old, new = before[target.value], after[target.value]
                if fault == "peer":
                    after[other.value]["history_sha256"] = "changed"
                elif fault == "identity":
                    new["identity"]["ca_sha256"] = "changed"
                elif fault == "policy_sha256":
                    new[fault] = "changed"
                elif fault == "version":
                    new[fault] += 1
                elif fault == "history_sha256":
                    new[fault] = old[fault]
                elif fault == "already":
                    old[field].append(reference)
                elif fault == "drop":
                    new[field] = [reference]
                elif fault == "extra":
                    new[field].append("x" * 64)
                elif fault == "other_revoke":
                    new[remaining].append("x" * 64)
                with self.subTest(target=target, fault=fault):
                    if fault:
                        with self.assertRaisesRegex(
                            Rejected, "candidate_authority_revoke_transition"
                        ):
                            pair.transition(before, after, target, field, reference)
                    else:
                        pair.transition(before, after, target, field, reference)
            with self.assertRaisesRegex(Rejected, "candidate_authority_revoke_target"):
                pair.transition(before, after, target, remaining, reference)

    def test_isolation_report_cannot_substitute_ca_target_or_bool(self):
        for target in Target:
            for field in (
                None,
                "host",
                "target",
                "ca_sha256",
                "other_target",
                "cross_ca_denied",
                "missing",
            ):
                report = isolation(target)
                if field == "missing":
                    report = {}
                elif field:
                    report["authority_isolation"][field] = (
                        1 if field == "cross_ca_denied" else "wrong"
                    )
                with self.subTest(target=target, field=field):
                    if field:
                        with self.assertRaisesRegex(
                            Rejected, "candidate_authority_isolation_binding"
                        ):
                            pair.isolation(report, states(), target)
                    else:
                        pair.isolation(report, states(), target)


class TerminalTests(unittest.TestCase):
    def execute(
        self,
        *,
        baseline=None,
        fault_mutation=None,
        cold_mutation=None,
        final_mutation=False,
        journal_changed=False,
        bad_base=False,
        pinned_roots=False,
    ):
        current = states() if baseline is None else baseline
        initial = copy.deepcopy(current)
        events = []
        config = {
            "permit_public": PUBLIC,
            "expected_permit": POLICY,
            "permit_envelope": {"signed": "unchanged"},
        }
        if pinned_roots:
            config.update(
                trust_root=PUBLIC, permit_public=encode64(b"p" * 32), minimum_trust_version=7
            )
        expected = {"model": MODEL, "bundle": SUBJECT}
        captures = 0

        def capture(*args):
            nonlocal captures
            self.assertEqual(args[1], PUBLIC)
            captures += 1
            result = copy.deepcopy(current)
            if captures == 4 and final_mutation:
                result["primary"]["history_sha256"] = "changed"
            return result

        def faults(state, profile, selected, request, **kwargs):
            nonlocal current
            target = kwargs.get("target", Target.PRIMARY)
            self.assertEqual(
                selected,
                {
                    **config,
                    **({"trust_target": target.value} if target is not Target.PRIMARY else {}),
                    **(
                        {"minimum_trust_version": initial[target.value]["version"]}
                        if pinned_roots and target is not Target.PRIMARY
                        else {}
                    ),
                },
            )
            self.assertEqual(request, expected)
            self.assertEqual(kwargs["expires_at"], 1600)
            self.assertEqual(kwargs["policy"], POLICY)
            self.assertEqual(kwargs["revoked_key"], KEY)
            fault = "key-revocation" if target is Target.PRIMARY else "revocation"
            self.assertEqual(kwargs["faults"], (fault,))
            events.append(target.value)
            current = revoked(current, target)
            result = {"probe": isolation(target, initial), "snapshot_sha256": "s" * 64}
            if fault_mutation:
                fault_mutation(target, current, result)
            return {fault: result}

        def invoke(state, profile, selected, request, **kwargs):
            target = kwargs["trust_target"]
            self.assertTrue(kwargs["candidate_probe"])
            self.assertEqual(request, {**expected, "cold_only": True})
            self.assertEqual(selected["permit_envelope"], config["permit_envelope"])
            self.assertEqual(selected.get("trust_target", "primary"), target.value)
            events.append("cold:" + target.value)
            client = Mock()
            client.request.return_value = {"items": []}
            reader = Mock()
            reader.load.side_effect = Rejected(
                "trust_key_revoked" if target is Target.PRIMARY else "trust_artifact_revoked"
            )
            with (
                patch.object(probe, "Client", return_value=client),
                patch.object(probe, "candidate", return_value=reader),
                patch.object(probe, "Worker") as worker,
            ):
                result = probe.qualify(selected, request)
                worker.assert_not_called()
            if cold_mutation:
                cold_mutation(target, result)
            return result

        with (
            patch.object(terminals, "capture", side_effect=capture),
            patch.object(
                terminals,
                "snapshot",
                side_effect=[{"journal": 1}, {"journal": 2 if journal_changed else 1}],
            ),
            patch.object(terminals, "faults", side_effect=faults),
            patch.object(terminals, "invoke", side_effect=invoke),
        ):
            result = terminals.exercise(
                "state",
                "profile",
                config,
                expected,
                base_probe={} if bad_base else isolation(Target.PRIMARY, initial),
                key="private",
                revoked_key=KEY,
                expires_at=1600,
            )
        self.assertEqual(
            events, ["model-revocation", "primary", "cold:primary", "cold:model-revocation"]
        )
        self.assertEqual(result["states"]["before"], initial)
        return result

    def test_same_permit_two_positive_faults_two_cold_denials(self):
        result = self.execute()
        self.assertIn(MODEL, result["states"]["after_key"]["model-revocation"]["revoked_artifacts"])
        self.assertIn(KEY, result["states"]["after_key"]["primary"]["revoked_keys"])

    def test_separate_signer_and_rotated_root_preserve_each_authority_floor(self):
        baseline = states()
        baseline[Target.MODEL_REVOCATION.value]["version"] = 2
        result = self.execute(baseline=baseline, pinned_roots=True)
        self.assertEqual(result["states"]["after_key"][Target.MODEL_REVOCATION.value]["version"], 3)

    def test_already_revoked_baseline_cannot_fake_second_positive(self):
        for target in Target:
            for field, reference in (("revoked_artifacts", MODEL), ("revoked_keys", KEY)):
                baseline = states()
                baseline[target.value][field].append(reference)
                with (
                    self.subTest(target=target, field=field),
                    self.assertRaisesRegex(Rejected, "candidate_terminal_baseline_revoked"),
                ):
                    self.execute(baseline=baseline)

    def test_isolation_missing_or_wrong_ca_rejects(self):
        with self.assertRaisesRegex(Rejected, "candidate_authority_isolation_binding"):
            self.execute(bad_base=True)

        def mutate(target, current, result):
            result["probe"]["authority_isolation"]["ca_sha256"] = "wrong"

        with self.assertRaisesRegex(Rejected, "candidate_authority_isolation_binding"):
            self.execute(fault_mutation=mutate)

    def test_cross_authority_mutation_rejects_before_next_phase(self):
        def mutate(target, current, result):
            other = "primary" if target is Target.MODEL_REVOCATION else "model-revocation"
            current[other]["history_sha256"] = "changed"

        with self.assertRaisesRegex(Rejected, "candidate_authority_revoke_transition"):
            self.execute(fault_mutation=mutate)

    def test_cold_binding_and_typed_cases_cannot_be_forged(self):
        for field, value in (
            ("status", "fail"),
            ("release_ready", 0),
            ("scope", "other"),
            ("authority_target", "other"),
            ("model_sha256", "other"),
            ("subject_sha256", "other"),
            ("cases", []),
            ("bool_case", False),
        ):

            def mutate(target, report):
                if field == "bool_case":
                    report["cases"][0]["actual"] = value
                else:
                    report[field] = value

            with (
                self.subTest(field=field),
                self.assertRaisesRegex(Rejected, "candidate_terminal_cold_binding"),
            ):
                self.execute(cold_mutation=mutate)

    def test_final_readback_and_model_journal_remain_unchanged(self):
        for kwargs in ({"final_mutation": True}, {"journal_changed": True}):
            with (
                self.subTest(kwargs=kwargs),
                self.assertRaisesRegex(Rejected, "candidate_terminal_readback_changed"),
            ):
                self.execute(**kwargs)

    def test_cold_probe_requires_exact_cause_without_worker(self):
        for target in Target:
            for outcome in (
                None,
                Rejected("expired"),
                Rejected(
                    "trust_key_revoked"
                    if target is Target.MODEL_REVOCATION
                    else "trust_artifact_revoked"
                ),
            ):
                client, reader = Mock(), Mock()
                client.request.return_value = {"items": []}
                reader.load.side_effect = outcome
                with (
                    self.subTest(target=target, outcome=outcome),
                    patch.object(probe, "Client", return_value=client),
                    patch.object(probe, "candidate", return_value=reader),
                    patch.object(probe, "Worker") as worker,
                ):
                    with self.assertRaisesRegex(Rejected, "candidate_probe_case:cold-"):
                        probe.qualify({"trust_target": target.value}, {"cold_only": True})
                    worker.assert_not_called()
        with (
            patch.object(probe, "Client", return_value=client),
            self.assertRaisesRegex(Rejected, "candidate_cold_fault_conflict"),
        ):
            probe.qualify({}, {"cold_only": True, "fault": "revocation"})


if __name__ == "__main__":
    unittest.main()
