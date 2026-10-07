import argparse
import sys
from pathlib import Path

from mlsecops.bootstrap import initialize
from mlsecops.contracts import Rejected, canonical, read_json, write_json
from mlsecops.datasets import prepare
from mlsecops.inventory import build_image
from mlsecops.pipeline import evaluate_candidate, train_candidate
from mlsecops.sandbox import resolve_image


def main():
    parser = argparse.ArgumentParser(description="Trusted MLSecOps local developer reference")
    parser.add_argument(
        "action", choices=["bootstrap", "build", "prepare", "train", "evaluate", "demo"]
    )
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    parser.add_argument("--dataset")
    parser.add_argument("--run")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    policy = read_json(root / "policies/local-cpu.json")
    try:
        if arguments.action == "build":
            fingerprint = build_image(root, arguments.image)
            result = {"image_id": resolve_image(arguments.image), "source_fingerprint": fingerprint}
        elif arguments.action == "bootstrap":
            result = initialize(root, arguments.state)
        elif arguments.action == "prepare":
            result = {"dataset_id": prepare(arguments.state, policy)}
        elif arguments.action == "train":
            result = train_candidate(arguments.state, arguments.dataset, policy, arguments.image)
        elif arguments.action == "evaluate":
            result = evaluate_candidate(arguments.state, arguments.run, policy, arguments.image)
        else:
            bootstrap = initialize(root, arguments.state)
            dataset_id = prepare(arguments.state, policy)
            candidate = train_candidate(arguments.state, dataset_id, policy, arguments.image)
            evaluation = evaluate_candidate(
                arguments.state, candidate["run_id"], policy, arguments.image
            )
            result = {
                "bootstrap": bootstrap,
                "candidate": candidate,
                "evaluation": evaluation,
                "status": "developer-preview-not-R1-accepted",
            }
            write_json(arguments.state / "demo.json", result)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        print(f"Operation rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
