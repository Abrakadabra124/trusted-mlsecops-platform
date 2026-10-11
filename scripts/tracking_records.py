import math
import re

from mlsecops.contracts import Rejected, canonical, digest

DIGEST_FIELDS = (
    "dataset_id",
    "input_digest",
    "policy_digest",
    "source_fingerprint",
    "model_digest",
    "validation_probability_digest",
)
INPUT_FIELDS = (
    "dataset_id",
    "input_digest",
    "policy_digest",
    "source_fingerprint",
    "source_revision",
    "image_id",
    "materials_digest",
    "versions_digest",
)


def number(value, maximum):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum


def export_records(report, policy):
    try:
        runs, metrics = report["runs"], report["metrics"]
        if (
            report["status"] != "pass"
            or type(runs) is not list
            or len(runs) != 3
            or type(metrics["fresh_runs"]) is not int
            or metrics["fresh_runs"] != 3
            or not number(policy["repeat_tolerance"], 1e-6)
            or not number(metrics["max_probability_difference"], policy["repeat_tolerance"])
            or len(metrics["auprc"]) != 3
            or not all(number(value, 1) for value in metrics["auprc"])
            or max(metrics["auprc"]) - min(metrics["auprc"]) > 1e-4
            or report["policy_digest"] != digest(canonical(policy))
        ):
            raise Rejected("tracking_reproducibility_report_invalid")
        records = []
        for run, auprc in zip(runs, metrics["auprc"], strict=True):
            params = {key: run[key] for key in DIGEST_FIELDS}
            if any(
                not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                for value in params.values()
            ):
                raise Rejected("tracking_material_digest_invalid")
            for key, expression in (
                ("run_id", r"[0-9a-f]{32}"),
                ("source_revision", r"[0-9a-f]{40}"),
                ("image_id", r"sha256:[0-9a-f]{64}"),
            ):
                if not isinstance(run[key], str) or not re.fullmatch(expression, run[key]):
                    raise Rejected("tracking_identity_invalid")
                params[key] = run[key]
            if (
                run["status"] != "unapproved-candidate"
                or not number(run["validation_parity_max_error"], 1e-5)
                or any(
                    params[key] != report[key]
                    for key in ("policy_digest", "dataset_id", "source_fingerprint")
                )
                or not isinstance(run["materials"], dict)
                or not run["materials"]
                or not isinstance(run["versions"], dict)
                or not run["versions"]
            ):
                raise Rejected("tracking_source_binding_invalid")
            params.update(
                materials_digest=digest(canonical(run["materials"])),
                versions_digest=digest(canonical(run["versions"])),
                status="unapproved-candidate",
                training_seed=str(policy["training_seed"]),
                data_seed=str(policy["data_seed"]),
            )
            records.append(
                {
                    "source_run_id": run["run_id"],
                    "params": params,
                    "metrics": {
                        "auprc": auprc,
                        "validation_parity_max_error": run["validation_parity_max_error"],
                    },
                }
            )
        if len({record["source_run_id"] for record in records}) != 3 or any(
            len({record["params"][key] for record in records}) != 1 for key in INPUT_FIELDS
        ):
            raise Rejected("tracking_runs_reused_or_inputs_changed")
        return records
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("tracking_projection_schema_invalid") from None
