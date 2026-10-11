from mlsecops import holdout_budget, storage
from mlsecops.contracts import Rejected, canonical, digest

CLAIM_CASES = ("four-process-unique-atomic-claims", "concurrent-over-budget-denied")
RECEIPT_FIELDS = {"holdout_digest", "slot", "reservation", "policy_digest"}
REJECTION_CODES = {
    "holdout_budget_exhausted",
    "storage_connection_rejected",
    "storage_claim_verification_failed",
    "storage_claim_rejected:unavailable",
    *(
        f"storage_claim_rejected:{code}"
        for code in (
            "08000",
            "08001",
            "08003",
            "08004",
            "08006",
            "08007",
            "08P01",
            "23505",
            "40001",
            "40P01",
            "42501",
            "53300",
            "55P03",
            "57014",
            "57P01",
            "57P02",
            "57P03",
            "XX000",
        )
    ),
}


class ClaimFailure(Rejected):
    def __init__(self, case, diagnostics):
        super().__init__(f"holdout_qualification_failed:{case}")
        self.diagnostics = diagnostics


def check_claims(receipts, holdout_digest):
    storage.object_id(holdout_digest)
    attempts = min(len(receipts), holdout_budget.LIMIT + 1) if type(receipts) is list else 0
    observed = {
        "schema_version": 1,
        "diagnostic_only": True,
        "complete": attempts == holdout_budget.LIMIT,
        "attempts": attempts,
        "claimed_slots": [],
        "rejection_codes": {},
        "invalid_receipts": 0,
    }
    accepted, refused = [], []
    for item in receipts[: holdout_budget.LIMIT] if type(receipts) is list else []:
        if type(item) is dict and set(item) == {"rejected"}:
            raw = item["rejected"]
            code = (
                raw
                if type(raw) is str and len(raw) <= 64 and raw in REJECTION_CODES
                else "unclassified_rejection"
            )
            observed["rejection_codes"][code] = observed["rejection_codes"].get(code, 0) + 1
            refused.append(item)
        elif (
            type(item) is dict
            and set(item) == RECEIPT_FIELDS
            and type(item["slot"]) is int
            and 1 <= item["slot"] <= holdout_budget.LIMIT
        ):
            accepted.append(item)
            observed["claimed_slots"].append(item["slot"])
        else:
            observed["invalid_receipts"] += 1
    observed["claimed_slots"].sort()
    expected = [
        {
            "holdout_digest": holdout_digest,
            "slot": slot,
            "reservation": digest(holdout_budget.reservation(holdout_digest, slot)),
            "policy_digest": digest(canonical(holdout_budget.policy())),
        }
        for slot in range(2, holdout_budget.LIMIT + 1)
    ]
    if (
        not observed["complete"]
        or observed["invalid_receipts"]
        or sorted(accepted, key=lambda item: item["slot"]) != expected
    ):
        raise ClaimFailure(CLAIM_CASES[0], observed)
    if refused != [{"rejected": "holdout_budget_exhausted"}]:
        raise ClaimFailure(CLAIM_CASES[1], observed)
    return observed
