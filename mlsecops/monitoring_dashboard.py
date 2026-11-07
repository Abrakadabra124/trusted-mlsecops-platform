"""Public immutable shell; all monitoring data still requires the operator bearer."""

from fastapi import Request
from fastapi.responses import Response

from mlsecops.monitoring_dashboard_assets import CSS, HTML
from mlsecops.monitoring_dashboard_script import SCRIPT

ASSETS = {"/monitoring/ui": HTML, "/monitoring/ui.css": CSS, "/monitoring/ui.js": SCRIPT}
MEDIA = {
    "/monitoring/ui": "text/html",
    "/monitoring/ui.css": "text/css",
    "/monitoring/ui.js": "application/javascript",
}
HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


async def asset(request: Request):
    path = request.scope["path"]
    if path not in ASSETS:
        return Response(status_code=404, headers=HEADERS)
    if (
        request.scope.get("query_string")
        or request.headers.getlist("transfer-encoding")
        or request.headers.getlist("content-length") not in ([], ["0"])
    ):
        return Response(status_code=400, headers=HEADERS)
    return Response(ASSETS[path], media_type=MEDIA[path], headers=HEADERS)


def install(app):
    for path in ASSETS:
        app.add_api_route(path, asset, methods=["GET"])
