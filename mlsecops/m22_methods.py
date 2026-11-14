"""Data-only reviewer challenge on the full locked train and matched candidate seed."""

from copy import deepcopy

from mlsecops.contracts import Rejected, canonical, digest, require_fields
from mlsecops.datasets import FEATURES, validate_rows
from scripts import absolute_poisoning, poisoning


def prepare(method, family, train, probes, seed):
    require_fields(method, ("family", "train_entity_ids", "trigger"))
    ids, trigger = method["train_entity_ids"], method["trigger"]
    policy = absolute_poisoning.policy()
    if (
        family not in policy["families"]
        or method["family"] != family
        or type(ids) is not list
        or len(ids) not in policy["budgets"]
        or any(type(i) is not int or i < 0 for i in ids)
        or sorted(set(ids)) != ids
        or type(trigger) is not dict
        or bool(trigger) != (family == "backdoor")
        or not set(trigger).issubset(FEATURES)
        or any(type(v) not in (int, float) or not 0 <= v <= 1 for v in trigger.values())
    ):
        raise Rejected("M22_review_method")
    known = policy["trigger"]
    if trigger == {known["feature"]: known["value"]}:
        raise Rejected("M22_review_known_trigger")
    if seed not in policy["seeds"] or len(train) != max(policy["train_sizes"]):
        raise Rejected("M22_review_unmatched_train")
    validate_rows(train)
    altered = deepcopy(train)
    lookup = {row["entity_id"]: row for row in altered}
    if any(i not in lookup or lookup[i]["label"] != policy["source_label"] for i in ids):
        raise Rejected("M22_review_ineligible_train_id")
    if family == "label-flip":
        # An explicit ID list can still be a verbatim replay of a published random selection.
        for size in policy["train_sizes"]:
            for known_seed in policy["seeds"]:
                selected = poisoning.selected_indices(train[:size], len(ids), known_seed)
                if set(ids) == {train[i]["entity_id"] for i in selected}:
                    raise Rejected("M22_review_known_selection")
    triggered = deepcopy(probes)
    for row in [*(lookup[i] for i in ids), *triggered]:
        for feature, value in trigger.items():
            row["features"][FEATURES.index(feature)] = value
    for i in ids:
        lookup[i]["label"] = policy["target_label"]
    receipt = {
        "family": family,
        "changed_rows": len(ids),
        "train_rows": len(train),
        "fraction": len(ids) / len(train),
        "changed_entity_ids": ids,
        "before_digest": digest(canonical(train)),
        "after_digest": digest(canonical(altered)),
        "method_digest": digest(canonical(method)),
    }
    case = {
        "id": "review-" + family,
        "family": family,
        "count": len(ids),
        "train_rows": len(train),
        "seed": seed,
    }
    return case, (altered, receipt), triggered
