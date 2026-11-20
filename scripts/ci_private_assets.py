"""Private release lifecycle for one public CI run and attempt."""

import re
import time
from copy import deepcopy

from mlsecops import ci_transfer
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from scripts import ci_upstream_transfer as upstream
from scripts import ci_validation_transfer as validation
from scripts import frozen_candidate_transfer as frozen
from scripts.ci_private_channel import REPOSITORY, REPOSITORY_ID

ROOT = "repos/" + REPOSITORY
CONTROL = "producer-control"
CONTROL_MAGIC = b"MLSCONTROL\x01"
OVERHEAD = ci_transfer.NONCE_BYTES + ci_transfer.TAG_BYTES
CANDIDATE_LIMIT = frozen.MAX_ARCHIVE + len(ci_transfer.MAGIC) + OVERHEAD
LIMITS = {
    "candidate-shared": CANDIDATE_LIMIT,
    "candidate-serving": CANDIDATE_LIMIT,
    "upstream-serving": min(upstream.MAX_ENVELOPE_BYTES, ci_transfer.MAX_ENVELOPE_BYTES),
    "validation-serving": validation.MAX_ENVELOPE_BYTES,
    CONTROL: 65536,
}
PACKETS = tuple(k for k in LIMITS if k != CONTROL)
TTL = ci_transfer.TRANSPORT_TTL["candidate"]
OWNER_FIELDS = ("repository", "run_id", "run_attempt", "source_revision", "producer_job")
RECEIPT_FIELDS = (
    "schema_version",
    "expected",
    "repository_id",
    "tag",
    "private_head",
    "release_id",
    "issued_at",
    "expires_at",
    "assets",
)


def _need(ok):
    if not ok:
        raise Rejected("private_asset_refused")


def _number(value):
    _need(type(value) is int and 1 <= value <= ci_transfer.MAX_INTEGER)
    return value


def _hex(value, length):
    _need(type(value) is str and len(value) == length and re.fullmatch("[0-9a-f]+", value))
    return value


def _owner(expected):
    require_fields(expected, OWNER_FIELDS)
    owner = expected.copy()
    _need(owner["repository"] == ci_transfer.REPOSITORY and owner["producer_job"] == "producer")
    _number(owner["run_id"])
    _number(owner["run_attempt"])
    _hex(owner["source_revision"], 40)
    return owner


def _tag(owner):
    return f"ci-candidate-{owner['run_id']}-{owner['run_attempt']}"


def _repo(api):
    repo = api.json("GET", ROOT)
    _need(
        isinstance(repo, dict)
        and repo.get("full_name") == REPOSITORY
        and _number(repo.get("id")) == REPOSITORY_ID
        and repo.get("private") is True
        and repo.get("fork") is False
        and repo.get("visibility") == "private"
        and isinstance(repo.get("owner"), dict)
        and repo["owner"].get("login") == REPOSITORY.split("/")[0]
    )
    return repo


def _ref(row, ref, head=None):
    _need(isinstance(row, dict) and row.get("ref") == "refs/" + ref)
    obj = row.get("object")
    _need(isinstance(obj, dict) and obj.get("type") == "commit")
    actual = _hex(obj.get("sha"), 40)
    _need(head is None or actual == head)
    return actual


def _head(api):
    branch = _repo(api).get("default_branch")
    _need(
        type(branch) is str
        and len(branch) <= 200
        and re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*", branch)
        and ".." not in branch
    )
    ref = "heads/" + branch
    return _ref(api.json("GET", ROOT + "/git/ref/" + ref), ref)


def _check_tag(api, receipt):
    ref = "tags/" + receipt["tag"]
    _ref(api.json("GET", ROOT + "/git/ref/" + ref), ref, receipt["private_head"])


def _visible_releases(api, tag, *, maximum=19):
    # One bounded page; reject a full page instead of assuming there is no next page.
    rows = api.json("GET", ROOT + "/releases?per_page=20")
    _need(type(rows) is list and len(rows) <= maximum)
    result = []
    for row in rows:
        _need(isinstance(row, dict) and type(row.get("tag_name")) is str)
        if row["tag_name"] == tag:
            result.append(_number(row.get("id")))
    return result


def _new(owner, head, issued):
    _number(issued)
    return dict(
        schema_version=1,
        expected=owner,
        repository_id=REPOSITORY_ID,
        tag=_tag(owner),
        private_head=_hex(head, 40),
        release_id=None,
        issued_at=issued,
        expires_at=_number(issued + TTL),
        assets={},
    )


def _open(receipt):
    _need(receipt["issued_at"] <= int(time.time()) < receipt["expires_at"])


def _release_fields(r):
    # The by-tag reader can reconstruct this marker only with the independently expected run.
    body = canonical(
        dict(
            kind="t21-private-assets-v1",
            owner_sha256=digest(canonical(r["expected"])),
            issued_at=r["issued_at"],
        )
    ).decode("ascii")
    return dict(
        tag_name=r["tag"],
        target_commitish=r["private_head"],
        name=r["tag"],
        body=body,
        draft=False,
        prerelease=True,
    )


def _release(row, receipt):
    _need(isinstance(row, dict) and row.get("immutable") is False)
    for key, value in _release_fields(receipt).items():
        _need(type(row.get(key)) is type(value) and row[key] == value)
    i = _number(row.get("id"))
    _need(receipt["release_id"] in (None, i))
    return i


def _magic(stem):
    return CONTROL_MAGIC if stem == CONTROL else ci_transfer.MAGIC


def _size(stem, size):
    _need(type(size) is int and len(_magic(stem)) + OVERHEAD <= size <= LIMITS[stem])


def _wire(stem, raw):
    _need(type(raw) is bytes and raw.startswith(_magic(stem)))
    _size(stem, len(raw))


def _pin(stem, meta):
    _need(
        isinstance(meta, dict)
        and meta.get("name") == stem + ".bin"
        and meta.get("state") == "uploaded"
    )
    _size(stem, meta.get("size"))
    checksum = meta.get("digest")
    _need(type(checksum) is str and checksum.startswith("sha256:"))
    return dict(id=_number(meta.get("id")), size=meta["size"], sha256=_hex(checksum[7:], 64))


def _listing(rows):
    _need(type(rows) is list and len(rows) <= len(LIMITS))
    pins = {}
    ids = set()
    for row in rows:
        _need(isinstance(row, dict) and type(row.get("name")) is str)
        stem = row["name"].removesuffix(".bin")
        _need(stem in LIMITS and stem not in pins)
        pin = _pin(stem, row)
        _need(pin["id"] not in ids)
        ids.add(pin["id"])
        pins[stem] = pin
    return pins


def _asset(pin):
    return ROOT + "/releases/assets/" + str(pin["id"])


def _endpoint(receipt):
    return ROOT + "/releases/" + str(receipt["release_id"])


def _inventory(api, receipt):
    _repo(api)
    _check_tag(api, receipt)
    by_tag = api.json("GET", ROOT + "/releases/tags/" + receipt["tag"])
    _release(by_tag, receipt)
    path = _endpoint(receipt)
    by_id = api.json("GET", path)
    _release(by_id, receipt)
    listed = _listing(api.json("GET", path + "/assets?per_page=6"))
    _need(_listing(by_tag.get("assets")) == listed == _listing(by_id.get("assets")))
    return listed


def _read(api, stem, pin):
    _repo(api)
    path = _asset(pin)
    _need(_pin(stem, api.json("GET", path)) == pin)
    raw = api.download(path, pin["size"])
    _wire(stem, raw)
    _need(len(raw) == pin["size"] and digest(raw) == pin["sha256"])
    return raw


def _receipt(value, owner):
    require_fields(value, RECEIPT_FIELDS)
    expected = _owner(value["expected"])
    _need(owner == expected)
    r = _new(owner, value["private_head"], value["issued_at"])
    r["release_id"] = None if value["release_id"] is None else _number(value["release_id"])
    assets = value["assets"]
    _need(type(assets) is dict and assets.keys() <= LIMITS.keys())
    ids = set()
    for stem, row in assets.items():
        require_fields(row, ("id", "size", "sha256"))
        _size(stem, row["size"])
        _hex(row["sha256"], 64)
        i = _number(row["id"])
        _need(i not in ids)
        ids.add(i)
        r["assets"][stem] = row.copy()
    _need(not assets or r["release_id"] is not None)
    for key in ("schema_version", "expires_at", "tag", "repository_id"):
        _need(type(value[key]) is type(r[key]) and value[key] == r[key])
    return r


def producer_receipt(receipt, expected):
    """Return a detached four-packet receipt within its original live transport window."""
    r = _receipt(receipt, _owner(expected))
    _need(set(r["assets"]) == set(PACKETS))
    _open(r)
    return r


def publish(api, expected, packets, seal_control, *, checkpoint=None):
    """Return a private receipt only after exact-ID readback of all five assets."""
    owner = _owner(expected)
    require_fields(packets, PACKETS)
    packets = packets.copy()
    _need(callable(seal_control) and (checkpoint is None or callable(checkpoint)))
    for stem, packet in packets.items():
        _wire(stem, packet)
    r = _new(owner, _head(api), int(time.time()))
    tag = r["tag"]
    ref = "tags/" + tag
    _need(_visible_releases(api, tag, maximum=18) == [])
    _need(api.json("GET", ROOT + "/releases/tags/" + tag, absent=True) is None)
    _need(api.json("GET", ROOT + "/git/ref/" + ref, absent=True) is None)

    def remember():
        if checkpoint is not None:
            checkpoint(deepcopy(r))

    # Create-only tag reservation. A conflicting create must fail; never adopt an existing ref.
    _repo(api)
    created = api.json(
        "POST", ROOT + "/git/refs", body={"ref": "refs/" + ref, "sha": r["private_head"]}
    )
    _ref(created, ref, r["private_head"])
    remember()
    _check_tag(api, r)
    _repo(api)
    _need(_visible_releases(api, tag, maximum=18) == [])
    _need(api.json("GET", ROOT + "/releases/tags/" + tag, absent=True) is None)
    row = api.json("POST", ROOT + "/releases", body=_release_fields(r) | {"make_latest": "false"})
    r["release_id"] = _release(row, r)
    _need(_listing(row.get("assets")) == {})
    remember()

    for stem in LIMITS:
        content = seal_control(producer_receipt(r, owner)) if stem == CONTROL else packets[stem]
        _wire(stem, content)
        _need(_inventory(api, r) == r["assets"])
        _open(r)
        meta = api.upload(_endpoint(r) + "/assets", stem + ".bin", content)
        pin = _pin(stem, meta)
        _need(pin["size"] == len(content) and pin["sha256"] == digest(content))
        _need(pin["id"] not in {p["id"] for p in r["assets"].values()})
        r["assets"][stem] = pin
        remember()
        _read(api, stem, pin)
    _need(_inventory(api, r) == r["assets"])
    _open(r)
    return r


def fetch_control(api, expected):
    """Read the control ciphertext by exact ID; the caller must authenticate it."""
    owner = _owner(expected)
    _repo(api)
    row = api.json("GET", ROOT + "/releases/tags/" + _tag(owner))
    _need(isinstance(row, dict) and type(row.get("body")) is str and len(row["body"]) <= 512)
    marker = decode(row["body"].encode(), 512)
    _need(isinstance(marker, dict))
    r = _new(owner, row.get("target_commitish"), marker.get("issued_at"))
    r["release_id"] = _release(row, r)
    _open(r)
    pins = _inventory(api, r)
    _need(pins.keys() == LIMITS.keys())
    raw = _read(api, CONTROL, pins[CONTROL])
    _open(r)
    return raw


def fetch(api, expected, receipt, stem):
    """Read one ciphertext using the independently authenticated producer receipt."""
    r = _receipt(receipt, _owner(expected))
    _need(type(stem) is str and stem in PACKETS and set(PACKETS) <= r["assets"].keys())
    _open(r)
    pins = _inventory(api, r)
    _need(pins.keys() == LIMITS.keys() and all(pins[k] == v for k, v in r["assets"].items()))
    raw = _read(api, stem, r["assets"][stem])
    _open(r)
    return raw


def _authorize(r, authorize, retained_copy):
    _need(callable(authorize))
    decision = authorize(deepcopy(r))
    require_fields(decision, ("terminal", "primary", "receipt_sha256"))
    _need(
        decision["terminal"] is True
        and type(decision["primary"]) is bool
        and decision["receipt_sha256"] == digest(canonical(r))
    )
    if decision["primary"]:
        _need(callable(retained_copy))
        for stem, pin in r["assets"].items():
            raw = retained_copy(stem)
            _wire(stem, raw)
            _need(len(raw) == pin["size"] and digest(raw) == pin["sha256"])


def cleanup(api, expected, receipt, *, authorize, retained_copy=None):
    """Delete only verified owned objects after independent terminal authorization."""
    r = _receipt(receipt, _owner(expected))
    _authorize(r, authorize, retained_copy)
    _repo(api)
    tag = r["tag"]
    by_tag = ROOT + "/releases/tags/" + tag
    ref = "tags/" + tag
    by_ref = ROOT + "/git/ref/" + ref
    siblings = _visible_releases(api, tag)
    release_id = r["release_id"]
    if siblings:
        _need(siblings == [release_id])
        pins = _inventory(api, r)
        _need(all(k in r["assets"] and p == r["assets"][k] for k, p in pins.items()))
        # Check every member before deleting the first one. A prior interrupted cleanup
        # may have already removed an owned ID; require its individual absence too.
        for stem, pin in r["assets"].items():
            if stem in pins:
                _need(_pin(stem, api.json("GET", _asset(pin))) == pin)
            else:
                _need(api.json("GET", _asset(pin), absent=True) is None)
        for stem in list(pins):
            _need(_inventory(api, r) == pins)
            path = _asset(pins.pop(stem))
            api.json("DELETE", path)
            _need(api.json("GET", path, absent=True) is None)
        _need(_inventory(api, r) == {})
        api.json("DELETE", _endpoint(r))

    if release_id is not None:
        _need(api.json("GET", _endpoint(r), absent=True) is None)
        for pin in r["assets"].values():
            _need(api.json("GET", _asset(pin), absent=True) is None)
    _need(api.json("GET", by_tag, absent=True) is None and _visible_releases(api, tag) == [])
    _repo(api)
    row = api.json("GET", by_ref, absent=True)
    if row is not None:
        _ref(row, ref, r["private_head"])
        api.json("DELETE", ROOT + "/git/refs/" + ref)
    _need(api.json("GET", by_ref, absent=True) is None)
    _need(api.json("GET", by_tag, absent=True) is None and _visible_releases(api, tag) == [])
    _head(api)  # A positive repository/ref read distinguishes lost access from completed cleanup.
