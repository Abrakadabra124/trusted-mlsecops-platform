"""Bounded HTTP evidence for a real signer-policy transition."""

import time

from mlsecops.contracts import Rejected


def observe_refusal(request, body, mutate, *, clock=time.monotonic, pause=time.sleep):
    anchor = clock()
    if request("/v1/predict", body)[0] != 200:
        raise Rejected("signer_trace_initial_prediction")
    receipt = mutate()
    rows, first, denials, previous = [], None, 0, 0
    for _ in range(260):
        start = clock() - anchor
        status = request("/v1/predict", body)[0]
        end = clock() - anchor
        if (
            not 0 <= previous <= start <= end <= 65
            or type(status) is not int
            or status not in (200, 503)
        ):
            raise Rejected("signer_trace_invalid_observation")
        if status == 200 and (first is not None or end >= 60):
            raise Rejected("signer_trace_late_ml")
        if status == 503:
            first = end if first is None else first
            if first > 60:
                raise Rejected("signer_trace_refusal_late")
            denials += 1
        rows.append({"start_seconds": start, "end_seconds": end, "http_status": status})
        previous = end
        if denials >= 2:
            return {
                "anchor": "successful-request-start-lower-bound-on-last-trust-read",
                "first_503_seconds": first,
                "trace": rows,
                "observations": len(rows),
                "trust_receipt": receipt,
            }
        pause(0.25)
    raise Rejected("signer_trace_refusal_missing")
