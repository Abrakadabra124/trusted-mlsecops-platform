import argparse
import gzip
import importlib.metadata
import sys
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.process_privacy import enforce as enforce_privacy

MAX_PROTOCOL = 16 * 1024 * 1024


def train(request):
    from skl2onnx import to_onnx
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    from mlsecops.datasets import arrays, validate_features
    from mlsecops.model import predict, session
    from mlsecops.signing import encode64

    require_fields(request, ("action", "train", "seed", "features"))
    if request["action"] not in ("train", "research-robust-train", "reference-logistic-train"):
        raise Rejected("invalid_training_action")
    if type(request["seed"]) is not int or not 0 <= request["seed"] <= 2**32 - 1:
        raise Rejected("invalid_training_seed")
    train_features, train_labels = arrays(request["train"])
    if request["action"] == "research-robust-train" and set(train_labels.tolist()) != {0, 1}:
        raise Rejected("robust_training_requires_two_classes")
    golden = validate_features(request["features"])
    classifier = make_pipeline(
        StandardScaler(),
        LogisticRegression(random_state=request["seed"], solver="lbfgs", max_iter=300),
    )
    classifier.fit(train_features, train_labels)
    optimization = None
    if request["action"] == "train":
        from mlsecops.noise_training import refit

        refit(classifier, train_features, train_labels, balanced=True)
    if request["action"] == "research-robust-train":
        from mlsecops.robust_training import refit

        optimization = refit(classifier, train_features, train_labels)
    exported = to_onnx(
        classifier,
        golden[:1],
        target_opset=18,
        options={id(classifier.steps[-1][1]): {"zipmap": False}},
    ).SerializeToString()
    runtime, scan = session(exported)
    onnx_scores = predict(runtime, request["features"])
    python_scores = classifier.predict_proba(golden)[:, 1].tolist()
    output = {
        "schema_version": 1,
        "action": request["action"],
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
    if optimization is not None:
        output["optimization"] = optimization
    return output


def predict_request(request):
    from mlsecops.model import predict, session
    from mlsecops.prediction_protocol import response, validate_request

    content = validate_request(request)
    runtime, scan = session(content)
    return response(request, predict(runtime, request["features"]), scan)


def execute(request):
    if not isinstance(request, dict):
        raise Rejected("invalid_worker_request")
    if request.get("action") in ("train", "research-robust-train", "reference-logistic-train"):
        return train(request)
    if request.get("action") == "predict":
        return predict_request(request)
    if request.get("action") == "inspect":
        from mlsecops import artifact_intake
        from mlsecops.model import inspect_model

        content = artifact_intake.validate_request(request)
        try:
            scan = inspect_model(content)
        except Rejected as error:
            reason = (
                str(error) if str(error) in artifact_intake.REASONS else "model_profile_rejected"
            )
            return artifact_intake.response(request, reason=reason)
        return artifact_intake.response(request, scan=scan)
    raise Rejected("unknown_worker_action")


class PrivateArguments(argparse.ArgumentParser):
    def error(self, message):
        raise Rejected("worker_arguments_invalid")


def main():
    try:
        enforce_privacy()
        parser = PrivateArguments(description="Offline bounded training/prediction worker")
        parser.add_argument("--request-file", type=Path)
        arguments = parser.parse_args()
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
    except Exception:
        sys.stderr.write("worker_rejected\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
