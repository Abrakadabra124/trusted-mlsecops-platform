"""Bounded HTTPS transport for release assets in the designated private repository."""

import http.client
import re
from contextlib import closing, contextmanager

from mlsecops.ci_transfer import MAX_ENVELOPE_BYTES
from mlsecops.contracts import Rejected, canonical, decode

_REPO = "repos/Abrakadabra124/trusted-mlsecops-ci-private"
_API = "api.github.com"
_UPLOADS = "uploads.github.com"
_CDN = "release-assets.githubusercontent.com"
_JSON = "application/vnd.github+json"
_BINARY = "application/octet-stream"
_JSON_LIMIT = 1024 * 1024
_ID = r"[1-9][0-9]{0,15}"
_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
_BRANCH_PART = r"[A-Za-z0-9_-][A-Za-z0-9._-]*"
_TAG = rf"ci-candidate-{_ID}-{_ID}"
_RELEASE = rf"/releases/{_ID}"
_ASSET = rf"/releases/assets/{_ID}"
_UPLOAD = _RELEASE + "/assets"
_LISTS = rf"/releases\?per_page=(?:20|100)|{_UPLOAD}\?per_page=[67]"
_READ = (
    rf"(?:|{_RELEASE}|{_ASSET}|{_LISTS}|/releases/tags/{_TAG}|/git/ref/tags/{_TAG}"
    rf"|/git/ref/heads/{_BRANCH_PART}(?:/{_BRANCH_PART})*)"
)
_DELETE = rf"(?:{_RELEASE}|{_ASSET}|/git/refs/tags/{_TAG})"


def _need(condition):
    if not condition:
        raise Rejected("ci_asset_http_rejected")


def _route(path, pattern):
    _need(type(path) is str and len(path) <= 512 and path.startswith(_REPO))
    suffix = path[len(_REPO) :]
    _need(".." not in suffix and re.fullmatch(pattern, suffix) is not None)
    return "/" + path


@contextmanager
def _response(host, method, target, headers, body=None):
    # A new direct TLS connection for every request: no ambient proxy, cookies or redirects.
    try:
        with closing(http.client.HTTPSConnection(host, timeout=30)) as connection:
            connection.set_debuglevel(0)
            connection.request(method, target, body, headers)
            with connection.getresponse() as response:
                yield response
    except (OSError, http.client.HTTPException):
        raise Rejected("ci_asset_http_unavailable") from None


def _read(response, limit):
    lengths = response.headers.get_all("Content-Length", [])
    transfers = response.headers.get_all("Transfer-Encoding", [])
    _need(not transfers or (transfers == ["chunked"] and not lengths))
    _need(response.headers.get_all("Content-Encoding", []) in ([], ["identity"]))
    size = None
    if lengths:
        _need(len(lengths) == 1 and re.fullmatch(r"[0-9]{1,10}", lengths[0]))
        size = int(lengths[0])
        _need(size <= limit)
    raw = response.read(limit + 1)
    _need(len(raw) <= limit and (size is None or len(raw) == size))
    return raw


def _json_value(response, expected_type=dict):
    try:
        value = decode(_read(response, _JSON_LIMIT), _JSON_LIMIT)
    except Rejected:
        raise Rejected("ci_asset_http_invalid_response") from None
    _need(type(value) is expected_type)
    return value


def _post_data(path, body):
    _need(type(body) is dict)
    if path == _REPO + "/git/refs":
        _need(body.keys() == {"ref", "sha"})
        _need(type(body["ref"]) is str and re.fullmatch("refs/tags/" + _TAG, body["ref"]))
        _need(type(body["sha"]) is str and re.fullmatch(r"[a-f0-9]{40}", body["sha"]))
    else:
        fields = {
            "tag_name": str,
            "target_commitish": str,
            "name": str,
            "body": str,
            "draft": bool,
            "prerelease": bool,
            "make_latest": str,
        }
        _need(body.keys() <= fields.keys() and "tag_name" in body)
        _need(all(type(value) is fields[key] for key, value in body.items()))
        _need(re.fullmatch(_TAG, body["tag_name"]))
        _need(sum(len(value) for value in body.values() if type(value) is str) <= _JSON_LIMIT)
    data = canonical(body)
    _need(len(data) <= _JSON_LIMIT)
    return data


def _signed_target(response):
    locations = response.headers.get_all("Location", [])
    _need(len(locations) == 1 and len(locations[0]) <= 8192)
    origin = "https://" + _CDN
    location = locations[0]
    _need(location.startswith(origin + "/"))
    target = location[len(origin) :]
    path, _, query = target.partition("?")
    _need(re.fullmatch(r"/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+", path))
    _need(not {".", ".."}.intersection(path.split("/")))
    # Keep signed query bytes intact. Only this one opaque target goes to the CDN.
    _need(re.fullmatch(r"(?:[A-Za-z0-9_.~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})+", query))
    signatures = [field[4:] for field in query.split("&") if field.startswith("sig=")]
    _need(len(signatures) == 1 and signatures[0])
    return target


class Client:
    def __init__(self, token, *, write=False):
        _need(type(token) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,4096}", token))
        _need(type(write) is bool)
        self._token = token
        self._write = write

    def _headers(self, accept):
        return {
            "Authorization": "Bearer " + self._token,
            "Accept": accept,
            "User-Agent": "mlsecops-private-assets",
            "X-GitHub-Api-Version": "2026-03-10",
        }

    def json(self, method, path, *, body=None, absent=False):
        _need(type(absent) is bool and (not absent or method == "GET"))
        _need(method in ("GET", "POST", "DELETE") and (method == "GET" or self._write))
        headers = self._headers(_JSON)
        data = None
        if method == "POST":
            target = _route(path, r"/(?:releases|git/refs)")
            data = _post_data(path, body)
            headers["Content-Type"] = "application/json"
        else:
            _need(body is None)
            target = _route(path, _READ if method == "GET" else _DELETE)
        with _response(_API, method, target, headers, data) as response:
            if absent and response.status == 404:
                return None
            _need(response.status == {"GET": 200, "POST": 201, "DELETE": 204}[method])
            if method == "DELETE":
                _need(response.headers.get_all("Content-Length", []) in ([], ["0"]))
                _need(response.headers.get("Transfer-Encoding") is None)
                return {}
            if "?" in target:
                _need(response.headers.get("Link") is None)
                return _json_value(response, list)
            return _json_value(response)

    def upload(self, path, name, content) -> dict:
        _need(self._write and type(name) is str and re.fullmatch(_NAME, name))
        _need(type(content) is bytes and 0 < len(content) <= MAX_ENVELOPE_BYTES)
        target = _route(path, _UPLOAD) + "?name=" + name
        headers = self._headers(_JSON) | {"Content-Type": _BINARY}
        with _response(_UPLOADS, "POST", target, headers, content) as response:
            _need(response.status == 201)
            return _json_value(response)

    def download(self, path, limit) -> bytes:
        _need(type(limit) is int and 0 < limit <= MAX_ENVELOPE_BYTES)
        target = _route(path, _ASSET)
        with _response(_API, "GET", target, self._headers(_BINARY)) as response:
            if response.status == 302:
                signed_target = _signed_target(response)
            else:
                _need(response.status == 200)
                return _read(response, limit)
        with _response(_CDN, "GET", signed_target, {"Accept": _BINARY}) as response:
            _need(response.status == 200)
            return _read(response, limit)
