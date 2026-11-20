"""Check release-asset credentials against one operator-signed disposable private prerelease."""

import hashlib
import os
import re
import sys

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from scripts import ci_asset_http as http
from scripts import ci_private_assets as store
from scripts import ci_private_channel as channel
from scripts.ci_source_image_native import same

KIND = "store-access-probe"
STAGES = ("upload", "reader", "cleanup")
ROLES = ("publisher", "reader")


def _need(condition):
    if not condition:
        raise Rejected("access_probe_refused")


def payload(nonce, run, attempt, role) -> bytes:
    """Return the inert fixture for publisher.bin or reader.bin. IDs may be integers or decimal strings."""
    store._hex(nonce, 32)
    _need(role in ROLES)
    run = channel.number(run) if type(run) is str else store._number(run)
    attempt = channel.number(attempt) if type(attempt) is str else store._number(attempt)
    return (
        b"MLSecOps store-access-probe v1\n"
        + hashlib.sha256(canonical([nonce, run, attempt, role])).digest()
    )


def _quota(headers, name):
    values = headers.get_all("X-RateLimit-" + name, [])
    if not values:
        return None
    _need(len(values) == 1 and re.fullmatch(r"[0-9]{1,16}", values[0]))
    return int(values[0])


def _permission_denial(api, release_id, nonce, run, attempt):
    """Send one ordinary reader.bin upload. Only an explicit remote permission response qualifies."""
    path = store._endpoint({"release_id": store._number(release_id)}) + "/assets"
    target = http._route(path, http._UPLOAD) + "?name=reader.bin"
    headers = api._headers(http._JSON) | {"Content-Type": http._BINARY}
    raw = payload(nonce, run, attempt, "reader")
    with http._response(http._UPLOADS, "POST", target, headers, raw) as response:
        outcome = {201: "response_created", 403: "response_forbidden"}.get(
            response.status, "response_other"
        )
        print("reader_check=" + outcome)
        _need(response.status == 403)
        _need(
            response.headers.get("Retry-After") is None
            and response.headers.get("X-GitHub-SSO") is None
        )
        remaining = _quota(response.headers, "Remaining")
        limit = _quota(response.headers, "Limit")
        used = _quota(response.headers, "Used")
        _need(remaining != 0 and limit != 0 and (limit is None or used is None or used < limit))
        print("reader_check=denial_body")
        body = decode(http._read(response, 8192), 8192)
        _need(type(body) is dict and body.keys() <= {"message", "documentation_url", "status"})
        _need(
            body.get("status", "403") == "403"
            and body.get("message")
            in (
                "Resource not accessible by personal access token",
                "Resource not accessible by integration",
            )
        )
        url = body.get("documentation_url", "")
        _need(type(url) is str and not re.search(r"rate[\s_-]*limit|abuse", url, re.I))


class Probe:
    def __init__(self, api, nonce, public, run, attempt):
        self.api, self.nonce, self.run, self.attempt = api, nonce, run, attempt
        self.fixtures = {role + ".bin": payload(nonce, run, attempt, role) for role in ROLES}
        channel.key(public)
        store._repo(api)
        name = "ci-access-" + nonce
        rows = api.json("GET", store.ROOT + "/releases?per_page=100")
        _need(type(rows) is list and len(rows) < 100)
        matches = []
        seen_ids = set()
        for row in rows:
            _need(type(row) is dict and type(row.get("tag_name")) is str)
            identifier = store._number(row.get("id"))
            _need(identifier not in seen_ids)
            seen_ids.add(identifier)
            if name in (row.get("name"), row["tag_name"]):
                matches.append(row)
        _need(len(matches) == 1)
        row = matches[0]
        body = row.get("body")
        _need(type(body) is str and body.isascii() and len(body) <= 8192)
        envelope = decode(body.encode("ascii"), 8192)
        _need(canonical(envelope).decode("ascii") == body)
        record = signing.verify(envelope, KIND, public)
        expected = dict(
            nonce=nonce,
            repository_id=store.REPOSITORY_ID,
            release_id=row["id"],
            target_commitish=store._hex(row.get("target_commitish"), 40),
        )
        require_fields(record, expected)
        same(record, expected)
        _need(signing.encode64(canonical(record)) == envelope["payload"])
        self.release_id = record["release_id"]
        self.path = store._endpoint(record)
        self.fields = dict(
            id=self.release_id,
            name=name,
            tag_name=name,
            target_commitish=record["target_commitish"],
            draft=False,
            prerelease=True,
            immutable=False,
            body=body,
        )
        same(row, self.fields)
        self.initial = self._listing(row.get("assets"))
        _need(self.inventory() == self.initial)

    def _id(self, row, name):
        data = self.fixtures[name]
        same(
            row, dict(name=name, state="uploaded", size=len(data), digest="sha256:" + digest(data))
        )
        return store._number(row.get("id"))

    def _listing(self, rows):
        _need(type(rows) is list and len(rows) <= len(self.fixtures))
        ids = {}
        for row in rows:
            _need(type(row) is dict and type(row.get("name")) is str)
            name = row["name"]
            _need(name in self.fixtures and name not in ids)
            identifier = self._id(row, name)
            _need(identifier not in ids.values())
            ids[name] = identifier
        return ids

    def inventory(self):
        store._repo(self.api)
        row = self.api.json("GET", self.path)
        same(row, self.fields)
        embedded = self._listing(row.get("assets"))
        listed = self._listing(self.api.json("GET", self.path + "/assets?per_page=6"))
        _need(embedded == listed)
        return listed

    def read(self, name, identifier):
        path = store._asset({"id": identifier})
        _need(self._id(self.api.json("GET", path), name) == identifier)
        data = self.fixtures[name]
        _need(self.api.download(path, len(data)) == data)

    def upload(self):
        _need(not self.initial)
        store._repo(self.api)
        name = "publisher.bin"
        row = self.api.upload(self.path + "/assets", name, self.fixtures[name])
        identifier = self._id(row, name)
        _need(self.inventory() == {name: identifier})
        self.read(name, identifier)
        _need(self.inventory() == {name: identifier})

    def reader(self):
        name = "publisher.bin"
        print("reader_check=publisher_bytes")
        _need(self.initial.keys() == {name})
        self.read(name, self.initial[name])
        print("reader_check=inventory_before")
        _need(self.inventory() == self.initial)
        store._repo(self.api)
        print("reader_check=write_request")
        _permission_denial(self.api, self.release_id, self.nonce, self.run, self.attempt)
        print("reader_check=inventory_after")
        _need(self.inventory() == self.initial)

    def cleanup(self):
        remaining = self.initial.copy()
        # Verify every original before the first deletion, and its identity again at use.
        for name, identifier in remaining.items():
            self.read(name, identifier)
        for name, identifier in self.initial.items():
            _need(self.inventory() == remaining)
            self.read(name, identifier)
            _need(self.inventory() == remaining)
            store._repo(self.api)
            path = store._asset({"id": identifier})
            self.api.json("DELETE", path)
            _need(self.api.json("GET", path, absent=True) is None)
            del remaining[name]
        _need(self.inventory() == {})


def main(arguments=None):
    args = sys.argv[1:] if arguments is None else arguments
    stage = args[0] if len(args) == 1 and args[0] in STAGES else "invalid"
    try:
        _need(stage in STAGES)
        if stage == "reader":
            print("reader_check=fixture")
        token = os.environ["CANDIDATE_ACCESS_TOKEN"]
        _need(token.startswith("github_pat_"))
        api = http.Client(token, write=stage in ("upload", "cleanup"))
        probe = Probe(
            api,
            os.environ["CANDIDATE_PROBE_NONCE"],
            os.environ["CANDIDATE_PROBE_PUBLIC"],
            os.environ["GITHUB_RUN_ID"],
            os.environ["GITHUB_RUN_ATTEMPT"],
        )
        getattr(probe, stage)()
    except (Exception, KeyboardInterrupt):
        print(f"access_probe_{stage}=refused")
        return 1
    print(f"access_probe_{stage}=pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
