"""Read public campaign metadata in the controller, using its explicit read-only token."""

import re

from mlsecops.contracts import Rejected
from scripts import ci_asset_http as transport
from scripts.ci_source_image_native import REPOSITORY, number

# Both guards read the repo, commit and latest run. Terminal cleanup also reads the
# original attempt and its single jobs page. Match the complete, undecoded target.
_ROUTE = re.compile(
    re.escape("repos/" + REPOSITORY)
    + r"(?:/commits/[a-f0-9]{40}|/actions/runs/([0-9]{1,16})"
    + r"(?:/attempts/([0-9]{1,16})(?:/jobs\?per_page=100)?)?)?"
)


class Client:
    """Pass as source_api to the guards or cleanup. Keep the private store client separate."""

    __slots__ = ("_token",)

    def __init__(self, token):
        if type(token) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]{1,4096}", token):
            raise Rejected("campaign_source_token")
        self._token = token

    def __getstate__(self):
        raise TypeError("campaign_source_client_is_process_local")

    def __call__(self, method, path):
        if type(method) is not str or method != "GET" or type(path) is not str:
            raise Rejected("campaign_source_route")
        match = _ROUTE.fullmatch(path)
        if match is None:
            raise Rejected("campaign_source_route")
        for identifier in match.groups():
            if identifier is not None:
                number(identifier)

        headers = {
            "Authorization": "Bearer " + self._token,
            "Accept": transport._JSON,
            "User-Agent": "mlsecops-campaign-source",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        try:
            with transport._response(transport._API, "GET", "/" + path, headers) as response:
                if response.status == 200 and not ("?" in path and "Link" in response.headers):
                    return transport._json_value(response)
        except Exception:
            # Drop transport/parser exceptions and their context, which can contain wire data.
            pass
        raise Rejected("campaign_source_metadata_unavailable")
