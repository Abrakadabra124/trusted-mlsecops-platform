import copy
import unittest
from unittest.mock import Mock, patch

import numpy as np
import onnx
from onnx import TensorProto, helper

from mlsecops import model, prediction_protocol
from mlsecops.contracts import Rejected
from mlsecops.datasets import generate
from mlsecops.signing import decode64
from mlsecops.worker import train


def attribute(node, name):
    return next(value for value in node.attribute if value.name == name)


class ModelContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.features = [row["features"] for row in generate(seed=73037, rows=1000)]
        cls.trained = train(
            {"action": "train", "train": generate(rows=1000), "seed": 17, "features": cls.features}
        )
        cls.content = decode64(cls.trained["model"])
        cls.valid = onnx.load_model_from_string(cls.content)

    def rejected_before_load(self, content):
        with patch.object(model.ort, "InferenceSession") as constructor:
            with self.assertRaises(Rejected):
                model.session(content)
            constructor.assert_not_called()

    def test_actual_export_and_thousand_golden_cases_match_python(self):
        runtime, scan = model.session(self.content)
        scores = np.asarray(model.predict(runtime, self.features))
        expected = np.asarray(self.trained["python_scores"])
        self.assertLessEqual(float(np.max(np.abs(scores - expected))), 1e-5)
        outside = np.abs(expected - 0.5) > 1e-5
        np.testing.assert_array_equal(scores[outside] >= 0.5, expected[outside] >= 0.5)
        self.assertEqual(scan["policy_version"], "linear-onnx-v2")
        self.assertEqual(scan["inspected_nodes"], 2)
        prediction_protocol.validate_scan(scan)

    def test_bytes_type_size_and_renamed_pickle_rejected_before_load(self):
        for content in (
            None,
            True,
            "onnx",
            bytearray(self.content),
            b"",
            b"\x80\x04N.",
            b"{not-onnx}",
            b"x" * (50 * 1024 * 1024 + 1),
        ):
            with self.subTest(kind=type(content)):
                self.rejected_before_load(content)

    def test_binary_label_meaning_and_logistic_transform_are_enforced(self):
        for name, values in (
            ("classlabels_ints", [1, 0]),
            ("classlabels_ints", [1, 2]),
            ("post_transform", b"NONE"),
            ("post_transform", b"SOFTMAX"),
            ("multi_class", 1),
        ):
            invalid = copy.deepcopy(self.valid)
            node = invalid.graph.node[1]
            previous = attribute(node, name)
            node.attribute.remove(previous)
            node.attribute.append(helper.make_attribute(name, values))
            with self.subTest(name=name, values=values):
                self.rejected_before_load(invalid.SerializeToString())

    def test_nonfinite_unbounded_and_noncomplementary_classifier_parameters(self):
        for name in ("coefficients", "intercepts"):
            for value in (float("nan"), float("inf"), 1e30, 0.125):
                invalid = copy.deepcopy(self.valid)
                attribute(invalid.graph.node[1], name).floats[0] = value
                with self.subTest(name=name, value=value):
                    self.rejected_before_load(invalid.SerializeToString())
            invalid = copy.deepcopy(self.valid)
            attribute(invalid.graph.node[1], name).floats.pop()
            self.rejected_before_load(invalid.SerializeToString())

    def test_scaler_has_six_finite_offsets_and_positive_bounded_scales(self):
        for name, value in (
            ("offset", float("nan")),
            ("offset", 1e30),
            ("scale", float("inf")),
            ("scale", 0.0),
            ("scale", -1.0),
            ("scale", 1e30),
        ):
            invalid = copy.deepcopy(self.valid)
            attribute(invalid.graph.node[0], name).floats[0] = value
            with self.subTest(name=name, value=value):
                self.rejected_before_load(invalid.SerializeToString())
        invalid = copy.deepcopy(self.valid)
        attribute(invalid.graph.node[0], "scale").floats.pop()
        self.rejected_before_load(invalid.SerializeToString())

    def test_disconnected_scaler_and_extra_cast_are_not_complete_inspection(self):
        invalid = copy.deepcopy(self.valid)
        invalid.graph.node[1].input[0] = invalid.graph.input[0].name
        self.rejected_before_load(invalid.SerializeToString())
        invalid = copy.deepcopy(self.valid)
        invalid.graph.node.append(
            helper.make_node("Cast", ["label"], ["unused"], to=TensorProto.INT64)
        )
        self.rejected_before_load(invalid.SerializeToString())

    def test_unknown_conflicting_opsets_and_ir_are_rejected(self):
        for domain, version in (("", 19), ("ai.onnx.ml", 2), ("custom", 1)):
            invalid = copy.deepcopy(self.valid)
            invalid.opset_import.append(helper.make_opsetid(domain, version))
            with self.subTest(domain=domain):
                self.rejected_before_load(invalid.SerializeToString())
        invalid = copy.deepcopy(self.valid)
        invalid.ir_version = 9
        self.rejected_before_load(invalid.SerializeToString())

    def test_inline_external_and_sparse_initializers_are_not_unscanned_payloads(self):
        for external in (False, True):
            invalid = copy.deepcopy(self.valid)
            tensor = helper.make_tensor("unused", TensorProto.FLOAT, [1], [0.0])
            if external:
                tensor.data_location = TensorProto.EXTERNAL
                tensor.external_data.add(key="location", value="../private")
            invalid.graph.initializer.append(tensor)
            with self.subTest(external=external):
                self.rejected_before_load(invalid.SerializeToString())
        invalid = copy.deepcopy(self.valid)
        invalid.graph.sparse_initializer.add()
        self.rejected_before_load(invalid.SerializeToString())

    def test_dynamic_six_feature_input_and_binary_output_shapes_are_checked(self):
        for change in (
            "batch",
            "features",
            "input-type",
            "label-type",
            "label-rank",
            "probability-shape",
            "output-name",
        ):
            invalid = copy.deepcopy(self.valid)
            if change == "batch":
                invalid.graph.input[0].type.tensor_type.shape.dim[0].dim_value = 1
            elif change == "features":
                invalid.graph.input[0].type.tensor_type.shape.dim[1].dim_value = 5
            elif change == "input-type":
                invalid.graph.input[0].type.tensor_type.elem_type = TensorProto.DOUBLE
            elif change == "label-type":
                invalid.graph.output[0].type.tensor_type.elem_type = TensorProto.FLOAT
            elif change == "label-rank":
                invalid.graph.output[0].type.tensor_type.shape.dim.add(dim_value=1)
            elif change == "probability-shape":
                invalid.graph.output[1].type.tensor_type.shape.dim[1].dim_value = 3
            else:
                invalid.graph.output[1].name = "unbound-output"
            with self.subTest(change=change):
                self.rejected_before_load(invalid.SerializeToString())

    def test_auxiliary_graphs_and_custom_operators_are_rejected(self):
        for change in ("function", "training", "custom", "nested", "empty", "oversized"):
            invalid = copy.deepcopy(self.valid)
            if change == "function":
                invalid.functions.add()
            elif change == "training":
                invalid.training_info.add()
            elif change == "custom":
                invalid.graph.node[1].domain = "untrusted"
            elif change == "nested":
                invalid.graph.node[0].attribute.append(
                    helper.make_attribute("nested", invalid.graph)
                )
            elif change == "empty":
                del invalid.graph.node[:]
            else:
                invalid.graph.node.extend([invalid.graph.node[0]] * 17)
            with self.subTest(change=change):
                self.rejected_before_load(invalid.SerializeToString())

    def test_missing_duplicate_unknown_and_wrong_type_attributes_are_rejected(self):
        for change in ("missing", "duplicate", "unknown", "wrong-type"):
            invalid = copy.deepcopy(self.valid)
            node = invalid.graph.node[0]
            if change == "missing":
                node.attribute.pop()
            elif change == "duplicate":
                node.attribute.append(copy.deepcopy(node.attribute[0]))
            elif change == "unknown":
                node.attribute.append(helper.make_attribute("unused", 1))
            else:
                node.attribute[0].type = onnx.AttributeProto.INTS
            with self.subTest(change=change):
                self.rejected_before_load(invalid.SerializeToString())

    def test_runtime_failure_is_controlled_not_raw_exception(self):
        with patch.object(model.ort, "InferenceSession", side_effect=RuntimeError("private-path")):
            with self.assertRaisesRegex(Rejected, "model_runtime_rejected"):
                model.session(self.content)

    def test_missing_interface_and_checker_failure_cannot_reach_runtime(self):
        invalid = copy.deepcopy(self.valid)
        del invalid.graph.output[:]
        self.rejected_before_load(invalid.SerializeToString())

        invalid = copy.deepcopy(self.valid)
        invalid.metadata_props.add(key="duplicate", value="one")
        invalid.metadata_props.add(key="duplicate", value="two")
        self.rejected_before_load(invalid.SerializeToString())

    def test_unknown_protobuf_fields_cannot_escape_inspection(self):
        self.rejected_before_load(self.content + b"\xa0\x1f\x01")

    def test_report_requires_current_policy_and_both_inspected_nodes(self):
        scan = model.inspect_model(self.content)
        for field, value in (
            ("policy_version", "linear-onnx-v1"),
            ("inspected_nodes", 0),
            ("inspected_nodes", 1),
            ("inspected_nodes", 3),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                prediction_protocol.validate_scan({**scan, field: value})

    def test_invalid_array_conversion_and_ambiguous_threshold_tie(self):
        runtime = Mock()
        runtime.get_inputs.return_value = [Mock()]
        runtime.get_inputs.return_value[0].name = "features"
        runtime.run.return_value = [[[0], [0, 1]], [[0.5, 0.5]]]
        with self.assertRaisesRegex(Rejected, "prediction_shape_rejected"):
            model.predict(runtime, self.features[:1])
        for label in (0, 1):
            runtime.run.return_value = [np.array([label]), np.array([[0.5, 0.5]])]
            self.assertEqual(model.predict(runtime, self.features[:1]), [0.5])

    def test_predictions_are_binary_normalized_and_consistent_outside_epsilon(self):
        invalid_outputs = [
            [],
            [np.array([1])],
            [np.array([1]), np.array([[0.8, 0.8]])],
            [np.array([1]), np.array([[-0.1, 0.9]])],
            [np.array([2]), np.array([[0.1, 0.9]])],
            [np.array([0]), np.array([[0.1, 0.9]])],
            [np.array([True]), np.array([[False, True]])],
            [np.array([1]), np.array([[float("nan"), 0.9]])],
        ]
        for outputs in invalid_outputs:
            runtime = Mock()
            runtime.get_inputs.return_value = [Mock(name="features")]
            runtime.get_inputs.return_value[0].name = "features"
            runtime.run.return_value = outputs
            with self.subTest(outputs=outputs), self.assertRaises(Rejected):
                model.predict(runtime, self.features[:1])

    def test_prediction_runtime_error_is_controlled(self):
        runtime = Mock()
        runtime.get_inputs.side_effect = RuntimeError("private-path")
        with self.assertRaisesRegex(Rejected, "prediction_runtime_rejected"):
            model.predict(runtime, self.features[:1])


if __name__ == "__main__":
    unittest.main()
