"""Retain five original ciphertexts and a caller-authenticated journal tip in a pinned origin."""

from mlsecops.contracts import Rejected, canonical, digest, require_fields
from scripts import ci_campaign_control as control
from scripts import ci_campaign_journal as journal
from scripts import ci_private_assets as store
from scripts.ci_source_image_native import same

TIP_NAME = "journal-tip.bin"
TIP_MAGIC = b"MLSTIP\x01"
TIP_LIMIT = 16384


def _need(ok):
    if not ok:
        raise Rejected("origin_backup_unconfirmed")


def _origin(release, run_owner, source):
    control.binding(run_owner, source)
    require_fields(release, ("repository_id", "release_id", "name", "target_commitish"))
    name = f"ci-origin-{run_owner['run_id']}-{run_owner['run_attempt']}"
    same(release, dict(repository_id=store.REPOSITORY_ID, name=name))
    store._number(release["release_id"])
    store._hex(release["target_commitish"], 40)
    return release.copy()


def _binding(release, checkpoint, run_owner, source):
    release = _origin(release, run_owner, source)
    require_fields(checkpoint, ("storage", "issuer"))
    expected = run_owner | {"source_revision": source["source_revision"]}
    working = store._receipt(checkpoint["storage"], expected)
    pins = working["assets"]
    require_fields(pins, store.LIMITS)
    issuer = checkpoint["issuer"]
    require_fields(issuer, ("public", "storage_sha256", "control_sha256"))
    journal._public(issuer["public"])
    producer = working | {"assets": {stem: pins[stem] for stem in store.PACKETS}}
    same(
        issuer,
        dict(
            storage_sha256=digest(canonical(producer)), control_sha256=pins[store.CONTROL]["sha256"]
        ),
    )

    _need(release["release_id"] != working["release_id"])
    return release, dict(storage=working, issuer=issuer.copy())


def _tip_size(size):
    _need(type(size) is int and len(TIP_MAGIC) < size <= TIP_LIMIT)
    return size


def _tip_wire(raw):
    _need(type(raw) is bytes and raw.startswith(TIP_MAGIC))
    _tip_size(len(raw))


def _tip_pin(row):
    same(row, dict(name=TIP_NAME, state="uploaded"))
    checksum = row.get("digest")
    _need(type(checksum) is str and checksum.startswith("sha256:"))
    return dict(
        id=store._number(row.get("id")),
        size=_tip_size(row.get("size")),
        sha256=store._hex(checksum[7:], 64),
    )


def _listing(rows):
    _need(type(rows) is list and len(rows) <= len(store.LIMITS) + 1)
    originals = []
    tip = None
    for row in rows:
        if isinstance(row, dict) and row.get("name") == TIP_NAME:
            _need(tip is None)
            tip = _tip_pin(row)
        else:
            originals.append(row)
    pins = store._listing(originals)
    if tip is not None:
        require_fields(pins, store.LIMITS)
        _need(all(pin["id"] != tip["id"] for pin in pins.values()))
    return pins, tip


def _inventory(api, release, originals=None, *, putting_tip=False):
    store._repo(api)
    path = store._endpoint(release)
    pins, tip = _listing(api.json("GET", path + "/assets?per_page=7"))
    row = api.json("GET", path)
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
    _need(_listing(row.get("assets")) == (pins, tip))
    immutable = row.get("immutable")
    _need(type(immutable) is bool)
    if immutable:
        require_fields(pins, store.LIMITS)
        _need(not putting_tip or tip is not None)
    if originals is not None:
        working_ids = {pin["id"] for pin in originals.values()}
        _need(tip is None or tip["id"] not in working_ids)
        for stem, pin in pins.items():
            _need(pin["id"] not in working_ids)
            same(pin, {key: originals[stem][key] for key in ("size", "sha256")})
    return pins, tip


def copy_originals(api, *, release, checkpoint, run_owner, source, key) -> None:
    """Copy while the working receipt is live. An explicit retry resumes identical files only."""
    release, closed = _binding(release, checkpoint, run_owner, source)
    working = closed["storage"]
    originals = working["assets"]
    store._open(working)
    raw_control = store.fetch_control(api, working["expected"])
    control.retained_identity(raw_control, closed, key=key, run_owner=run_owner, source=source)
    snapshot = _inventory(api, release, originals)
    pins, _ = snapshot
    # Verify pre-existing files first. Fetch payloads individually to bound peak memory.
    order = (*pins, *(stem for stem in store.LIMITS if stem not in pins))
    for stem in order:
        raw = (
            raw_control
            if stem == store.CONTROL
            else store.fetch(api, working["expected"], working, stem)
        )
        _need(_inventory(api, release, originals) == snapshot)
        if stem not in pins:
            store._repo(api)
            store._open(working)
            row = api.upload(store._endpoint(release) + "/assets", stem + ".bin", raw)
            pins[stem] = store._pin(stem, row)
            _need(_inventory(api, release, originals) == snapshot)
        _need(store._read(api, stem, pins[stem]) == raw)
        del raw
    _need(pins.keys() == originals.keys() and _inventory(api, release, originals) == snapshot)
    store._open(working)


def reader(api, *, release, checkpoint, run_owner, source):
    """Return read_asset(stem, max_size) for historical replay, using only the pinned retained release."""
    release, closed = _binding(release, checkpoint, run_owner, source)
    originals = closed["storage"]["assets"]
    snapshot = _inventory(api, release, originals)
    pins, _ = snapshot
    require_fields(pins, store.LIMITS)

    def read_asset(stem, max_size):
        _need(type(stem) is str and stem in pins)
        pin = pins[stem]
        _need(type(max_size) is int and pin["size"] <= max_size)
        _need(_inventory(api, release, originals) == snapshot)
        raw = store._read(api, stem, pin)
        _need(_inventory(api, release, originals) == snapshot)
        return raw

    return read_asset


def _read_witness(api, release, snapshot):
    _, tip = snapshot
    _need(tip is not None)
    path = store._asset(tip)
    store._repo(api)
    _need(_tip_pin(api.json("GET", path)) == tip)
    raw = api.download(path, tip["size"])
    _tip_wire(raw)
    _need(len(raw) == tip["size"] and digest(raw) == tip["sha256"])
    _need(_inventory(api, release) == snapshot)
    return raw


def get_witness(api, *, release, run_owner, source) -> bytes:
    """Read untrusted tip bytes before journal recovery. The caller verifies their signature."""
    release = _origin(release, run_owner, source)
    return _read_witness(api, release, _inventory(api, release))


def put_witness(api, raw, *, release, checkpoint, run_owner, source) -> None:
    """Create the fixed tip once, or confirm identical bytes on an explicit retry."""
    _tip_wire(raw)
    release, closed = _binding(release, checkpoint, run_owner, source)
    originals = closed["storage"]["assets"]
    snapshot = _inventory(api, release, originals, putting_tip=True)
    pins, tip = snapshot
    require_fields(pins, store.LIMITS)
    for stem, pin in pins.items():
        store._read(api, stem, pin)
    _need(_inventory(api, release, originals, putting_tip=True) == snapshot)
    if tip is None:
        row = api.upload(store._endpoint(release) + "/assets", TIP_NAME, raw)
        tip = _tip_pin(row)
        snapshot = (pins, tip)
        _need(_inventory(api, release, originals) == snapshot)
    same(tip, dict(size=len(raw), sha256=digest(raw)))
    _need(_read_witness(api, release, snapshot) == raw)
