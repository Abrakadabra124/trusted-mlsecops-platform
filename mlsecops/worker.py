import argparse
import importlib.metadata
import sys

from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.datasets import arrays, validate_features
from mlsecops.model import predict, session
from mlsecops.signing import decode64, encode64

MAX_PROTOCOL = 16 * 1024 * 1024


def train(request):
    from skl2onnx import to_onnx
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    require_fields(request, ("action", "train", "seed", "features"))
    if type(request["seed"]) is not int or not 0 <= request["seed"] <= 2**32 - 1:
        raise Rejected("invalid_training_seed")
    train_features, train_labels = arrays(request["train"])
    golden = validate_features(request["features"])
    classifier = make_pipeline(
        StandardScaler(),
        LogisticRegression(random_state=request["seed"], solver="lbfgs", max_iter=300),
    )
    classifier.fit(train_features, train_labels)
    exported = to_onnx(
        classifier,
        golden[:1],
        target_opset=18,
        options={id(classifier.steps[-1][1]): {"zipmap": False}},
    ).SerializeToString()
    runtime, scan = session(exported)
    onnx_scores = predict(runtime, request["features"])
    python_scores = classifier.predict_proba(golden)[:, 1].tolist()
    return {
        "schema_version": 1,
        "action": "train",
        "model": encode64(exported),
        "model_digest": digest(exported),
        "input_digest": digest(canonical(request)),
        "python_scores": python_scores,
        "onnx_scores": onnx_scores,
        "scan": scan,
        "seed": request["seed"],
        "versions": {
            name: importlib.metadata.version(name)
            for name in ("numpy", "scikit-learn", "skl2onnx", "onnx", "onnxruntime")
        },
    }


def predict_request(request):
    require_fields(request, ("action", "model", "features", "batch_id"))
    if not isinstance(request["batch_id"], str) or len(request["batch_id"]) != 32:
        raise Rejected("invalid_batch_id")
    content = decode64(request["model"])
    runtime, scan = session(content)
    return {
        "schema_version": 1,
        "action": "predict",
        "batch_id": request["batch_id"],
        "model_digest": digest(content),
        "scores": predict(runtime, request["features"]),
        "scan": scan,
    }


def execute(request):
    if not isinstance(request, dict):
        raise Rejected("invalid_worker_request")
    if request.get("action") == "train":
        return train(request)
    if request.get("action") == "predict":
        return predict_request(request)
    raise Rejected("unknown_worker_action")


def main():
    argparse.ArgumentParser(description="Offline bounded training/prediction worker").parse_args()
    try:
        request = decode(sys.stdin.buffer.read(MAX_PROTOCOL + 1), MAX_PROTOCOL)
        output = canonical(execute(request))
        if len(output) > MAX_PROTOCOL:
            raise Rejected("worker_output_too_large")
        sys.stdout.buffer.write(output)
        return 0
    except Rejected as error:
        sys.stderr.write(f"Worker rejected: {error}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
