import numpy as np
import onnx
import onnxruntime as ort
from onnx import AttributeProto, TensorProto

from mlsecops.contracts import Rejected
from mlsecops.datasets import FEATURES, validate_features

OPERATORS = (("ai.onnx.ml", "Scaler"), ("ai.onnx.ml", "LinearClassifier"))


def tensor_interface(value, element_type, width=None):
    tensor = value.type.tensor_type
    dimensions = tensor.shape.dim
    if (
        value.type.WhichOneof("value") != "tensor_type"
        or tensor.elem_type != element_type
        or len(dimensions) != (1 if width is None else 2)
        or dimensions[0].HasField("dim_value")
        or (width is not None and dimensions[1].dim_value != width)
    ):
        raise Rejected("model_tensor_interface_rejected")


def attributes(node, expected):
    values = {value.name: value for value in node.attribute}
    if (
        values.keys() != expected.keys()
        or len(values) != len(node.attribute)
        or any(values[name].type != kind for name, kind in expected.items())
    ):
        raise Rejected("model_attribute_contract_rejected")
    return values


def vector(attribute, count, positive=False):
    values = np.asarray(attribute.floats, dtype=np.float64)
    if (
        len(values) != count
        or not np.isfinite(values).all()
        or (np.abs(values) > 1e6).any()
        or (positive and (values <= 0).any())
    ):
        raise Rejected("model_parameter_rejected")
    return values


def inspect_model(content):
    if not isinstance(content, bytes) or not content or len(content) > 50 * 1024 * 1024:
        raise Rejected("model_size_rejected")
    try:
        model = onnx.load_model_from_string(content)
    except Exception as error:
        raise Rejected("model_parse_rejected") from error
    if (
        model.ir_version != 8
        or not 2 <= len(model.opset_import) <= 3
        or {(value.domain, value.version) for value in model.opset_import}
        != {("", 18), ("ai.onnx.ml", 1)}
        or model.functions
        or model.training_info
        or model.configuration
        or len(model.graph.node) != 2
        or model.graph.initializer
        or model.graph.sparse_initializer
        or model.graph.quantization_annotation
    ):
        raise Rejected("model_structure_rejected")
    if len(model.graph.input) != 1 or len(model.graph.output) != 2:
        raise Rejected("model_interface_rejected")
    width = len(FEATURES)
    tensor_interface(model.graph.input[0], TensorProto.FLOAT, width)
    tensor_interface(model.graph.output[0], TensorProto.INT64)
    tensor_interface(model.graph.output[1], TensorProto.FLOAT, 2)
    scaler, classifier = model.graph.node
    if (
        tuple((node.domain, node.op_type) for node in model.graph.node) != OPERATORS
        or list(scaler.input) != [model.graph.input[0].name]
        or len(scaler.output) != 1
        or list(classifier.input) != list(scaler.output)
        or list(classifier.output) != [value.name for value in model.graph.output]
        or len({model.graph.input[0].name, *scaler.output, *classifier.output}) != 4
        or any(not name for name in (*scaler.input, *scaler.output, *classifier.output))
        or any(node.overload or node.device_configurations for node in model.graph.node)
    ):
        raise Rejected("model_topology_rejected")
    scaling = attributes(scaler, {"offset": AttributeProto.FLOATS, "scale": AttributeProto.FLOATS})
    vector(scaling["offset"], width)
    vector(scaling["scale"], width, positive=True)
    linear = attributes(
        classifier,
        {
            "classlabels_ints": AttributeProto.INTS,
            "coefficients": AttributeProto.FLOATS,
            "intercepts": AttributeProto.FLOATS,
            "multi_class": AttributeProto.INT,
            "post_transform": AttributeProto.STRING,
        },
    )
    coefficients = vector(linear["coefficients"], 2 * width)
    intercepts = vector(linear["intercepts"], 2)
    if (
        list(linear["classlabels_ints"].ints) != [0, 1]
        or linear["multi_class"].i != 0
        or linear["post_transform"].s != b"LOGISTIC"
        or not np.array_equal(coefficients[:width], -coefficients[width:])
        or intercepts[0] != -intercepts[1]
    ):
        raise Rejected("model_binary_classifier_rejected")
    inspected_bytes = model.SerializeToString(deterministic=True)
    model.DiscardUnknownFields()
    if model.SerializeToString(deterministic=True) != inspected_bytes:
        raise Rejected("model_unknown_fields_rejected")
    try:
        onnx.checker.check_model(model, full_check=True)
    except Exception as error:
        raise Rejected("model_check_rejected") from error
    return {
        "format": "onnx",
        "inspected_nodes": 2,
        "unsupported": 0,
        "skipped": 0,
        "errors": 0,
        "policy_version": "linear-onnx-v2",
        "onnx_version": onnx.__version__,
    }


def session(content):
    scan = inspect_model(content)
    try:
        # Provider discovery uses the global logger before session options apply.
        # Keep errors/fatal diagnostics; CPU discovery warnings are not model output.
        ort.set_default_logger_severity(3)
        options = ort.SessionOptions()
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        options.log_severity_level = 3
        runtime = ort.InferenceSession(
            content, sess_options=options, providers=["CPUExecutionProvider"]
        )
    except Exception:
        raise Rejected("model_runtime_rejected") from None
    return runtime, scan


def predict(runtime, features):
    inputs = validate_features(features)
    try:
        outputs = runtime.run(None, {runtime.get_inputs()[0].name: inputs})
    except Exception:
        raise Rejected("prediction_runtime_rejected") from None
    if not isinstance(outputs, list) or len(outputs) != 2:
        raise Rejected("prediction_shape_rejected")
    try:
        labels, probabilities = (np.asarray(value) for value in outputs)
    except (TypeError, ValueError):
        raise Rejected("prediction_shape_rejected") from None
    if (
        labels.shape != (len(features),)
        or labels.dtype.kind not in "iu"
        or probabilities.shape != (len(features), 2)
        or probabilities.dtype.kind != "f"
        or not np.isfinite(probabilities).all()
    ):
        raise Rejected("prediction_shape_rejected")
    if (
        not np.isin(labels, [0, 1]).all()
        or (probabilities < 0).any()
        or (probabilities > 1).any()
        or not np.allclose(probabilities.sum(axis=1), 1.0, rtol=0, atol=1e-6)
    ):
        raise Rejected("prediction_range_rejected")
    scores = probabilities[:, 1]
    outside = np.abs(scores - 0.5) > 1e-5
    if not np.array_equal(labels[outside], (scores[outside] >= 0.5).astype(np.int64)):
        raise Rejected("prediction_label_rejected")
    return scores.tolist()
