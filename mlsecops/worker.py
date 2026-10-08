import argparse
import gzip
import importlib.metadata
import sys
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.datasets import arrays, validate_features
from mlsecops.model import predict, session
from mlsecops.prediction_protocol import response, validate_request
from mlsecops.signing import encode64

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
    content = validate_request(request)
    runtime, scan = session(content)
    return response(request, predict(runtime, request["features"]), scan)


def execute(request):
    if not isinstance(request, dict):
        raise Rejected("invalid_worker_request")
    if request.get("action") == "train":
        return train(request)
    if request.get("action") == "predict":
        return predict_request(request)
    raise Rejected("unknown_worker_action")


def main():
    parser = argparse.ArgumentParser(description="Offline bounded training/prediction worker")
    parser.add_argument("--request-file", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.request_file:
            with gzip.open(arguments.request_file, "rb") as source:
                content = source.read(MAX_PROTOCOL + 1)
        else:
            content = sys.stdin.buffer.read(MAX_PROTOCOL + 1)
        request = decode(content, MAX_PROTOCOL)
        output = canonical(execute(request))
        if len(output) > MAX_PROTOCOL:
            raise Rejected("worker_output_too_large")
        sys.stdout.buffer.write(output)
        return 0
    except (Rejected, OSError, EOFError) as error:
        sys.stderr.write(f"Worker rejected: {error}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
