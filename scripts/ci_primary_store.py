"""Private storage of receiver-signed ciphertext in an operator-pinned release.

Use ci_asset_http.Client with write=True for put and a read credential for both getters.
Receipts, asset IDs and digests travel only through the private operator channel.
"""

from mlsecops import ci_transfer
from mlsecops.contracts import Rejected, digest, require_fields
from scripts import ci_campaign_control as control
from scripts import ci_private_assets as store
from scripts.ci_source_image_native import same

MAGIC = b"MLSPRIMARY\x01"
FILES = {"shared": "shared.bin", "serving": "serving.bin"}


def _need(ok):
    if not ok:
        raise Rejected("ci_primary_store_refused")


def _call(operation, *args):
    # An ambiguous write must not be retried here or expose a transport diagnostic.
    try:
        return operation(*args)
    except Exception:
        raise Rejected("ci_primary_store_io_unconfirmed") from None


def _binding(role, owner, source, release):
    _need(type(role) is str and role in FILES)
    control.binding(owner, source)
    require_fields(release, ("repository_id", "release_id", "name", "target_commitish"))
    _need(store._number(release["repository_id"]) == store.REPOSITORY_ID)
    store._number(release["release_id"])
    store._hex(release["target_commitish"], 40)
    name = f"ci-primary-{owner['run_id']}-{owner['run_attempt']}"
    _need(type(release["name"]) is str and release["name"] == name)
    return dict(
        schema_version=1,
        role=role,
        run_owner=owner.copy(),
        source=source.copy(),
        release=release.copy(),
    )


def _size(value):
    _need(type(value) is int and len(MAGIC) < value <= ci_transfer.MAX_ENVELOPE_BYTES)
    return value


def _wire(raw):
    _need(type(raw) is bytes and raw.startswith(MAGIC))
    _size(len(raw))


def _pin(row, name):
    same(row, {"state": "uploaded", "name": name})
    sha = row.get("digest")
    _need(type(sha) is str and sha.startswith("sha256:"))
    return dict(
        id=store._number(row.get("id")),
        name=name,
        size=_size(row.get("size")),
        sha256=store._hex(sha[7:], 64),
    )


def _select(rows, name):
    _need(type(rows) is list and len(rows) <= len(FILES))
    ids, names = set(), set()
    selected = None
    for row in rows:
        _need(type(row) is dict)
        filename = row.get("name")
        identifier = store._number(row.get("id"))
        _need(type(filename) is str and filename in FILES.values())
        _need(identifier not in ids and filename not in names)
        ids.add(identifier)
        names.add(filename)
        # A concurrent sibling upload may still have no size or digest.
        if filename == name:
            selected = _pin(row, name)
    return selected


def _inventory(api, release, name):
    _call(store._repo, api)
    path = store._endpoint(release)
    row = _call(api.json, "GET", path)
    same(
        row,
        dict(
            id=release["release_id"],
            name=release["name"],
            tag_name=release["name"],
            target_commitish=release["target_commitish"],
            draft=False,
            prerelease=True,
        ),
    )
    embedded = _select(row.get("assets"), name)
    listed = _select(_call(api.json, "GET", path + "/assets?per_page=6"), name)
    _need(embedded == listed)
    # Existing evidence remains readable after sealing. Only a mutable release can accept a file.
    _need(type(row.get("immutable")) is bool and (listed is not None or not row["immutable"]))
    return listed


def _read(api, release, pin):
    path = store._asset(pin)
    _need(_pin(_call(api.json, "GET", path), pin["name"]) == pin)
    _call(store._repo, api)
    raw = _call(api.download, path, pin["size"])
    _wire(raw)
    _need(len(raw) == pin["size"] and digest(raw) == pin["sha256"])
    _need(_inventory(api, release, pin["name"]) == pin)
    return raw


def put(api, data, *, role, run_owner, source, release) -> dict:
    """Create the one role asset or re-read identical ciphertext. Return a detached private receipt."""
    binding = _binding(role, run_owner, source, release)
    _wire(data)
    release = binding["release"]
    name = FILES[role]
    checksum = digest(data)
    pin = _inventory(api, release, name)
    if pin is None:
        _call(store._repo, api)
        row = _call(api.upload, store._endpoint(release) + "/assets", name, data)
        pin = _pin(row, name)
        _need(_inventory(api, release, name) == pin)
    _need(pin["size"] == len(data) and pin["sha256"] == checksum)
    _need(_read(api, release, pin) == data)
    return binding | {"asset": pin}


def get(api, receipt, *, role, run_owner, source, release) -> bytes:
    """Read only the asset pinned by an independently supplied, trusted private receipt."""
    binding = _binding(role, run_owner, source, release)
    require_fields(receipt, (*binding, "asset"))
    same(receipt, {"role": role, "schema_version": 1})
    for key in ("run_owner", "source", "release"):
        require_fields(receipt[key], binding[key])
        same(receipt[key], binding[key])
    name = FILES[role]
    pin = receipt["asset"]
    require_fields(pin, ("id", "name", "size", "sha256"))
    same(pin, {"name": name})
    store._number(pin["id"])
    _size(pin["size"])
    store._hex(pin["sha256"], 64)
    pin = pin.copy()
    _need(_inventory(api, binding["release"], name) == pin)
    return _read(api, binding["release"], pin)


def get_unverified(api, *, role, run_owner, source, release) -> bytes:
    """Recover untrusted ciphertext from the pinned release and fixed receiver filename.

    Authenticate the receiver signature for this role, run and source using its
    out-of-band job public key before using the bytes as evidence. Remote metadata
    and readback establish transport integrity only.
    """
    binding = _binding(role, run_owner, source, release)
    pin = _inventory(api, binding["release"], FILES[role])
    _need(pin is not None)
    return _read(api, binding["release"], pin)
