"""Bounded operator-only signed-label body; authentication precedes this reader."""

import asyncio
import re

from mlsecops.contracts import Rejected, decode

MAX_BODY = 262144


async def read(request):
    lengths = request.headers.getlist("content-length")
    if (
        len(lengths) != 1
        or re.fullmatch(r"[0-9]{1,6}", lengths[0]) is None
        or not 0 < int(lengths[0]) <= MAX_BODY
        or request.headers.getlist("content-type") != ["application/json"]
        or request.headers.getlist("content-encoding")
        or request.headers.getlist("transfer-encoding")
        or request.scope.get("query_string")
    ):
        raise Rejected("monitor_label_body")
    expected, content = int(lengths[0]), bytearray()
    async with asyncio.timeout(2):
        async for chunk in request.stream():
            if len(content) + len(chunk) > expected:
                raise Rejected("monitor_label_body")
            content.extend(chunk)
    if len(content) != expected:
        raise Rejected("monitor_label_body")
    return decode(bytes(content), MAX_BODY)
