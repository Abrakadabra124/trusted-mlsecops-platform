import numpy as np
import onnx
import onnxruntime as ort
from onnx import AttributeProto, TensorProto

from mlsecops.contracts import Rejected
from mlsecops.datasets import FEATURES, validate_features

ALLOWED_OPERATORS = {
    ("ai.onnx.ml", "Scaler"),
    ("ai.onnx.ml", "LinearClassifier"),
    ("", "Cast"),
}


def inspect_model(content):
    if not content or len(content) > 50 * 1024 * 1024:
        raise Rejected("model_size_rejected")
    try:
        model = onnx.load_model_from_string(content)
    except Exception as error:
        raise Rejected("model_parse_rejected") from error
    if model.functions or model.training_info or len(model.graph.node) > 16:
        raise Rejected("model_structure_rejected")
    if not model.graph.node or len(model.graph.input) != 1 or len(model.graph.output) != 2:
        raise Rejected("model_interface_rejected")
    input_type = model.graph.input[0].type.tensor_type
    dimensions = input_type.shape.dim
    if (
        input_type.elem_type != TensorProto.FLOAT
        or len(dimensions) != 2
        or dimensions[1].dim_value != len(FEATURES)
    ):
        raise Rejected("model_input_rejected")
    inspected = 0
    for tensor in model.graph.initializer:
        if tensor.external_data or tensor.data_location == TensorProto.EXTERNAL:
            raise Rejected("external_tensor_rejected")
    if model.graph.sparse_initializer:
        raise Rejected("sparse_initializer_rejected")
    for node in model.graph.node:
        if (node.domain, node.op_type) not in ALLOWED_OPERATORS:
            raise Rejected("operator_not_allowed")
        for attribute in node.attribute:
            if attribute.type in (
                AttributeProto.GRAPH,
                AttributeProto.GRAPHS,
                AttributeProto.TENSOR,
                AttributeProto.TENSORS,
                AttributeProto.SPARSE_TENSOR,
                AttributeProto.SPARSE_TENSORS,
            ):
                raise Rejected("nested_model_data_rejected")
        inspected += 1
    try:
        onnx.checker.check_model(model, full_check=True)
    except Exception as error:
        raise Rejected("model_check_rejected") from error
    return {
        "format": "onnx",
        "inspected_nodes": inspected,
        "unsupported": 0,
        "skipped": 0,
        "errors": 0,
        "policy_version": "linear-onnx-v1",
        "onnx_version": onnx.__version__,
    }


def session(content):
    scan = inspect_model(content)
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    options.log_severity_level = 3
    runtime = ort.InferenceSession(
        content, sess_options=options, providers=["CPUExecutionProvider"]
    )
    return runtime, scan


def predict(runtime, features):
    inputs = validate_features(features)
    outputs = runtime.run(None, {runtime.get_inputs()[0].name: inputs})
    probabilities = np.asarray(outputs[1])
    if probabilities.shape != (len(features), 2) or not np.isfinite(probabilities).all():
        raise Rejected("prediction_shape_rejected")
    scores = probabilities[:, 1]
    if (scores < 0).any() or (scores > 1).any():
        raise Rejected("prediction_range_rejected")
    return scores.tolist()
