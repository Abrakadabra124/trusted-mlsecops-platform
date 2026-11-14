import copy
import unittest

from mlsecops.contracts import Rejected
from mlsecops.controller_delivery import check_pair


class PairBinding(unittest.TestCase):
    def setUp(self):
        self.metadata = {"model_digest": "model", "run_id": "run"}
        self.candidate = {"metadata": self.metadata, "candidate_reference": "candidate"}
        self.evaluation = {
            "candidate_reference": "candidate",
            "dataset_reference": "data",
            "report": self.metadata.copy(),
        }
        self.controller = {
            "publisher": {"result": self.candidate},
            "scorer": {"result": {"evaluation": self.evaluation, "evaluation_reference": "eval"}},
        }

    def check(self, controller):
        check_pair(controller, "candidate", "eval", "data", self.metadata, self.evaluation)

    def test_original_pair(self):
        self.check(self.controller)

    def test_same_model_different_subject_or_signature(self):
        for role, field, value in (
            ("publisher", "candidate_reference", "other"),
            ("publisher", "metadata", {**self.metadata, "run_id": "other"}),
            ("scorer", "evaluation_reference", "other"),
            ("scorer", "evaluation", {**self.evaluation, "dataset_reference": "other"}),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                changed = copy.deepcopy(self.controller)
                changed[role]["result"][field] = value
                self.check(changed)
