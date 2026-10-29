"""Observe a real signed approval expiry; never mutate serving clocks or policy."""

import time

from mlsecops.kube_serving_lifecycle import valid

CHECKS = {
    "approval-expiry-window",
    "approval-expiry-clock-order",
    "approval-expiry-response-contract",
    "approval-expiry-no-late-ML",
    "approval-expiry-first-denial",
    "approval-expiry-complete-trace",
    "approval-expiry-no-reactivation",
}


def exercise(request, body, expected, check):
    wall, anchor = time.time(), time.monotonic()
    expires = expected["expires_at"]
    check("approval-expiry-window", type(expires) is int and 0 < expires - wall <= 120)
    deadline = anchor + expires - wall
    records, first, successes, denials = [], None, 0, 0
    previous, previous_wall = anchor, wall
    while time.monotonic() < deadline + 5 and len(records) < 512:
        start, start_wall = time.monotonic(), time.time()
        status, reply = request("/v1/predict", body)
        end, end_wall = time.monotonic(), time.time()
        check(
            "approval-expiry-clock-order",
            previous <= start <= end
            and previous_wall <= start_wall <= end_wall
            and abs((end_wall - wall) - (end - anchor)) <= 2,
        )
        previous, previous_wall = end, end_wall
        check("approval-expiry-response-contract", valid(status, reply, expected))
        records.append(
            {
                "start_epoch": start_wall,
                "end_epoch": end_wall,
                "end_seconds": end - anchor,
                "http_status": status,
            }
        )
        if status == 200:
            successes += 1
            check(
                "approval-expiry-no-late-ML",
                first is None and end < deadline and end_wall < expires,
            )
        else:
            denials += 1
            if first is None:
                first = end_wall - expires
                # Reader uses ceil(wall) and permits <=2 s SQL/host skew. An
                # unrelated early outage must not count as expiry evidence.
                check("approval-expiry-first-denial", -2 <= first <= 0 and end <= deadline)
        if denials >= 2 and start_wall >= expires + 1:
            break
        time.sleep(2 if deadline - time.monotonic() > 2.1 else 0.05)
    check(
        "approval-expiry-complete-trace",
        successes > 0
        and denials >= 2
        and bool(records)
        and records[-1]["start_epoch"] >= expires + 1,
    )
    check(
        "approval-expiry-no-reactivation",
        request("/readyz")[0] == 503
        and all(request("/v1/predict", body)[0] == 503 for _ in range(2)),
    )
    return {
        "expires_at": expires,
        "started_epoch": wall,
        "first_503_seconds_from_expiry": first,
        "trace": records,
    }
