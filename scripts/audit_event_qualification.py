import copy
import unittest
from dataclasses import asdict

from mlsecops import serving_audit, serving_context
from mlsecops.contracts import Rejected, canonical


def event(stage="response_intended", status=200, context=None):
    return {
        "schema_version": 2,
        "request_id": "a" * 32,
        "principal_id": "b" * 32,
        "route": "predict",
        "stage": stage,
        "status": status,
        "context": asdict(context or serving_context.QualificationContext(*["c" * 64] * 4))
        if status == 200
        else None,
    }


class EventContracts(unittest.TestCase):
    def test_versioned_context_preserves_distinct_authority_and_copies_input(self):
        for context in (
            serving_context.ReleaseContext(*["d" * 64] * 3),
            serving_context.QualificationContext(*["c" * 64] * 4),
        ):
            value = event(context=context)
            accepted = serving_audit.checked(value)
            self.assertEqual(accepted, value)
            value["context"]["model_sha256"] = "e" * 64
            self.assertEqual(accepted["context"], asdict(context))
            self.assertLess(len(canonical(accepted)) + 150, serving_audit.MAX_RECORD)

    def test_allowlist_rejects_payload_and_forged_or_ambiguous_context(self):
        mutations = (
            lambda value: value.update(schema_version=True),
            lambda value: value.update(schema_version=3),
            lambda value: value.update(raw_features="PRIVATE_CANARY"),
            lambda value: value.update(principal_id=None),
            lambda value: value.update(request_id="CLIENT_CANARY"),
            lambda value: value.update(route="/v1/predict?secret=CANARY"),
            lambda value: value.update(stage="delivered"),
            lambda value: value.update(status=True),
            lambda value: value.update(context=None),
            lambda value: value["context"].update(selection_sha256="f" * 64),
            lambda value: value["context"].update(kind="release-selection"),
            lambda value: value["context"].update(kind="unknown"),
            lambda value: value["context"].update(release_ready=True),
            lambda value: value["context"].update(release_ready=0),
            lambda value: value["context"].update(schema_version=True),
            lambda value: value["context"].update(permit_sha256="secret"),
            lambda value: value["context"].update(model_sha256=None),
            lambda value: value.update(context=[]),
        )
        for mutate in mutations:
            value = event()
            mutate(value)
            with self.subTest(value=value), self.assertRaisesRegex(Rejected, "audit_event_invalid"):
                serving_audit.checked(value)

    def test_stages_require_truthful_status_and_no_context_on_failure(self):
        for stage in (
            "request_started",
            "response_intended",
            "response_started",
            "response_completed",
            "aborted",
        ):
            for status in (None, 200, 503):
                value = event(stage, status)
                valid = (stage == "request_started" and status is None) or (
                    stage != "request_started" and (status is not None or stage == "aborted")
                )
                if valid:
                    self.assertEqual(serving_audit.checked(value), value)
                else:
                    with self.assertRaises(Rejected):
                        serving_audit.checked(value)
        value = event("response_started", 503)
        value["context"] = copy.deepcopy(event()["context"])
        with self.assertRaises(Rejected):
            serving_audit.checked(value)

    def test_mixed_versions_are_written_through_the_real_journal(self):
        from scripts.audit_admission_qualification import journal_fixture, wait_for
        from scripts.serving_audit_qualification import event as legacy_event

        with journal_fixture() as (journal, path):
            journal.emit(legacy_event())
            ticket = journal.reserve()
            sequence = journal.emit(event(), ticket=ticket)
            wait_for(lambda: journal.confirmed(ticket, sequence))
            journal.release(ticket)
            journal.close()
            from mlsecops.contracts import decode

            records = [decode(line) for line in path.read_bytes().splitlines()]
            self.assertEqual([value["schema_version"] for value in records], [1, 1])
            self.assertEqual(records[0]["event"], legacy_event())
            self.assertEqual(records[1]["event"], event())


if __name__ == "__main__":
    unittest.main()
