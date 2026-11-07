"""Nine real HTTP reads of public constant assets, inside the M13 leak capture."""

import re

from mlsecops import monitoring_dashboard as dashboard
from mlsecops.contracts import Rejected


def checked(path, response, needles):
    status, headers, content = response
    route, separator, _ = path.partition("?")
    expected = b"" if separator else dashboard.ASSETS[route].encode()
    if status != (400 if separator else 200) or content != expected:
        raise Rejected("dashboard_response_content")
    if not 1 <= len(headers) <= 12:
        raise Rejected("dashboard_response_headers")
    values = {}
    for key, value in headers:
        key = key.lower()
        if key in values or len(key) + len(value) > 2048:
            raise Rejected("dashboard_response_headers")
        values[key] = value
    required = {key.lower(): value for key, value in dashboard.HEADERS.items()}
    required["content-length"] = str(len(content))
    if not separator:
        media = dashboard.MEDIA[route]
        required["content-type"] = media + ("; charset=utf-8" if media.startswith("text/") else "")
    if any(values.get(key) != value for key, value in required.items()):
        raise Rejected("dashboard_response_headers")
    if (
        set(values) - required.keys() - {"date", "connection"}
        or not re.fullmatch(
            r"[A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT",
            values.get("date", ""),
        )
        or values.get("connection", "close") != "close"
    ):
        raise Rejected("dashboard_response_headers")
    encoded = "\n".join(key + ":" + value for key, value in values.items()).encode()
    if any(needle in content or needle in encoded for needle in needles):
        raise Rejected("dashboard_response_canary")


def exercise(request, needles):
    marker = needles[0].decode()
    count = 0
    for path in dashboard.ASSETS:
        for suffix, headers in (("", {}), ("", {"X-Private": marker}), ("?private=" + marker, {})):
            target = path + suffix
            checked(target, request(target, authorized=False, headers=headers, raw=True), needles)
            count += 1
    return count
