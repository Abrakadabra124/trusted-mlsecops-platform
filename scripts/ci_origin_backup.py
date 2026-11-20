"""Retain the original encrypted working assets in an independent private prerelease.

Both entry points require a closed checkpoint from the caller's authenticated journal.
The operator independently pins the origin release, separate from working, journal and primary.
"""

from mlsecops.contracts import Rejected, canonical, digest, require_fields
from scripts import ci_campaign_control as control
from scripts import ci_campaign_journal as journal
from scripts import ci_private_assets as store
from scripts.ci_source_image_native import same


def _need(ok):
    if not ok:
        raise Rejected("origin_backup_unconfirmed")


def _binding(release, checkpoint, run_owner, source):
    control.binding(run_owner, source)
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

    require_fields(release, ("repository_id", "release_id", "name", "target_commitish"))
    name = f"ci-origin-{run_owner['run_id']}-{run_owner['run_attempt']}"
    same(release, dict(repository_id=store.REPOSITORY_ID, name=name))
    _need(store._number(release["release_id"]) != working["release_id"])
    store._hex(release["target_commitish"], 40)
    return release.copy(), dict(storage=working, issuer=issuer.copy())


def _inventory(api, release, originals):
    store._repo(api)
    path = store._endpoint(release)
    pins = store._listing(api.json("GET", path + "/assets?per_page=6"))
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
    embedded = store._listing(row.get("assets"))
    _need(pins == embedded)
    _need(
        type(row.get("immutable")) is bool
        and (not row["immutable"] or pins.keys() == originals.keys())
    )
    original_ids = {pin["id"] for pin in originals.values()}
    for stem, pin in pins.items():
        _need(pin["id"] not in original_ids)
        same(pin, {key: originals[stem][key] for key in ("size", "sha256")})
    return pins


def copy_originals(api, *, release, checkpoint, run_owner, source, key) -> None:
    """Copy while the working receipt is live. An explicit retry resumes identical files only."""
    release, closed = _binding(release, checkpoint, run_owner, source)
    working = closed["storage"]
    originals = working["assets"]
    store._open(working)
    raw_control = store.fetch_control(api, working["expected"])
    control.retained_identity(raw_control, closed, key=key, run_owner=run_owner, source=source)
    pins = _inventory(api, release, originals)
    # Verify pre-existing files first. Fetch payloads individually to bound peak memory.
    order = (*pins, *(stem for stem in store.LIMITS if stem not in pins))
    for stem in order:
        raw = (
            raw_control
            if stem == store.CONTROL
            else store.fetch(api, working["expected"], working, stem)
        )
        _need(_inventory(api, release, originals) == pins)
        if stem not in pins:
            store._repo(api)
            store._open(working)
            row = api.upload(store._endpoint(release) + "/assets", stem + ".bin", raw)
            pins[stem] = store._pin(stem, row)
            _need(_inventory(api, release, originals) == pins)
        _need(store._read(api, stem, pins[stem]) == raw)
        del raw
    _need(pins.keys() == originals.keys() and _inventory(api, release, originals) == pins)
    store._open(working)


def reader(api, *, release, checkpoint, run_owner, source):
    """Return read_asset(stem, max_size) for historical replay, using only the pinned retained release."""
    release, closed = _binding(release, checkpoint, run_owner, source)
    originals = closed["storage"]["assets"]
    pins = _inventory(api, release, originals)
    require_fields(pins, store.LIMITS)

    def read_asset(stem, max_size):
        _need(type(stem) is str and stem in pins)
        pin = pins[stem]
        _need(type(max_size) is int and pin["size"] <= max_size)
        _need(_inventory(api, release, originals) == pins)
        raw = store._read(api, stem, pin)
        _need(_inventory(api, release, originals) == pins)
        return raw

    return read_asset
