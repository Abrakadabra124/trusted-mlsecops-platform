import math
import re

from prometheus_client.parser import text_string_to_metric_families

from mlsecops.contracts import Rejected

ROUTES = ("predict", "ready", "live", "other")
OUTCOMES = ("2xx", "3xx", "4xx", "5xx", "aborted")
BOUNDARIES = ("0.01", "0.025", "0.05", "0.1", "0.2", "0.5", "1.0", "5.0", "10.0", "+Inf")
COMMENTS = {
    "# HELP mlsecops_http_responses_total Observed ASGI response outcomes",
    "# TYPE mlsecops_http_responses_total counter",
    "# HELP mlsecops_http_duration_seconds Time to final ASGI send or abort",
    "# TYPE mlsecops_http_duration_seconds histogram",
    "# HELP mlsecops_http_metrics_errors_total Discarded metric observations or failed scrapes",
    "# TYPE mlsecops_http_metrics_errors_total counter",
}
FAMILIES = {
    "mlsecops_http_responses": ("counter", "Observed ASGI response outcomes", 20),
    "mlsecops_http_duration_seconds": ("histogram", "Time to final ASGI send or abort", 48),
    "mlsecops_http_metrics_errors": (
        "counter",
        "Discarded metric observations or failed scrapes",
        1,
    ),
}


def checked(content, needles):
    if (
        type(content) is not bytes
        or not 1 <= len(content) <= 16384
        or any(needle in content for needle in needles)
    ):
        raise Rejected("metrics_privacy_output_invalid")
    try:
        text = content.decode("ascii")
        comments = [line for line in text.splitlines() if line.lstrip().startswith("#")]
        if len(comments) != 6 or set(comments) != COMMENTS:
            raise ValueError
        expected = {
            ("mlsecops_http_responses_total", (("outcome", outcome), ("route", route)))
            for route in ROUTES
            for outcome in OUTCOMES
        }
        for route in ROUTES:
            expected.update(
                ("mlsecops_http_duration_seconds_bucket", (("le", boundary), ("route", route)))
                for boundary in BOUNDARIES
            )
            expected.update(
                ("mlsecops_http_duration_seconds_" + suffix, (("route", route),))
                for suffix in ("sum", "count")
            )
        expected.add(("mlsecops_http_metrics_errors_total", ()))
        observed = {}
        families = set()
        for family in text_string_to_metric_families(text):
            if family.name in families or FAMILIES.get(family.name) != (
                family.type,
                family.documentation,
                len(family.samples),
            ):
                raise ValueError
            families.add(family.name)
            for sample in family.samples:
                identity = sample.name, tuple(sorted(sample.labels.items()))
                if (
                    identity not in expected
                    or not sample.name.startswith(family.name + "_")
                    or identity in observed
                    or sample.timestamp is not None
                    or sample.exemplar is not None
                    or not math.isfinite(sample.value)
                    or sample.value < 0
                ):
                    raise ValueError
                if not sample.name.endswith("_sum") and not sample.value.is_integer():
                    raise ValueError
                observed[identity] = sample.value
        if observed.keys() != expected or families != FAMILIES.keys():
            raise ValueError
        for route in ROUTES:
            total = sum(
                observed["mlsecops_http_responses_total", (("outcome", outcome), ("route", route))]
                for outcome in OUTCOMES
            )
            buckets = [
                observed[
                    "mlsecops_http_duration_seconds_bucket", (("le", boundary), ("route", route))
                ]
                for boundary in BOUNDARIES
            ]
            if (
                buckets != sorted(buckets)
                or buckets[-1] != total
                or observed["mlsecops_http_duration_seconds_count", (("route", route),)] != total
            ):
                raise ValueError
        if observed["mlsecops_http_metrics_errors_total", ()] != 0:
            raise ValueError
    except Exception:
        raise Rejected("metrics_privacy_schema_invalid") from None
    return {"series": len(observed), "bytes": len(content)}


def scan(request, needles):
    credential = getattr(request, "metrics_credential", None)
    if type(credential) is not str or re.fullmatch("[a-f0-9]{64}", credential) is None:
        raise Rejected("metrics_privacy_credential_missing")
    status, headers, content = request("/metrics", credential=credential, raw=True)
    private_needles = (*needles, credential.encode())
    try:
        if status != 200 or type(headers) is not list or not 2 <= len(headers) <= 4:
            raise ValueError
        observed = {}
        for name, value in headers:
            if type(name) is not str or type(value) is not str:
                raise ValueError
            key = name.lower()
            if (
                key not in ("cache-control", "content-type", "content-length", "date")
                or key in observed
                or len(name) + len(value) > 128
                or any(needle in (name + ":" + value).encode("ascii") for needle in private_needles)
            ):
                raise ValueError
            observed[key] = value
        if (
            observed.get("cache-control") != "no-store"
            or observed.get("content-type") != "text/plain; version=0.0.4; charset=utf-8"
            or "content-length" in observed
            and observed["content-length"] != str(len(content))
            or "date" in observed
            and re.fullmatch(
                r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} "
                r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
                r"[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT",
                observed["date"],
            )
            is None
        ):
            raise ValueError
    except Exception:
        raise Rejected("metrics_privacy_scrape_invalid") from None
    return checked(content, private_needles)
