"""Private operator journal for producer checkpoints."""

import re
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from scripts import ci_campaign_control as control
from scripts import ci_private_assets as store

MAGIC = b"MLSJOURNAL\x01"
KIND = "campaign-publisher-journal"
LIMIT = 16 * 1024
STAGES = (
    (),
    (),
    store.PACKETS[:1],
    store.PACKETS[:2],
    store.PACKETS[:3],
    store.PACKETS,
    store.PACKETS,
    (*store.PACKETS, store.CONTROL),
)


def _need(value):
    if not value:
        raise Rejected("campaign_journal_refused")


def _public(value):
    _need(type(value) is str and len(value) == 44)
    raw = signing.decode64(value)
    _need(len(raw) == 32 and signing.encode64(raw) == value)
    return value


def _binding(journal, owner, source, trusted_public):
    control.binding(owner, source)
    require_fields(journal, ("repository_id", "release_id", "name", "target_commitish"))
    _need(store._number(journal["repository_id"]) == store.REPOSITORY_ID)
    store._number(journal["release_id"])
    store._hex(journal["target_commitish"], 40)
    name = journal["name"]
    _need(type(name) is str and re.fullmatch(r"ci-journal-[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", name))
    return dict(
        journal=journal.copy(),
        run_owner=owner.copy(),
        source=source.copy(),
        trusted_public=_public(trusted_public),
    )


def _cipher(key):
    _need(type(key) is bytes and len(key) == 32)
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=MAGIC).derive(key)
    return AESGCM(derived)


def _path(binding):
    return store.ROOT + "/releases/" + str(binding["journal"]["release_id"])


def _name(binding, step):
    run = binding["run_owner"]
    return f"checkpoint-{run['run_id']}-{run['run_attempt']}-{step:02d}.bin"


def _pin(row, name):
    _need(type(row) is dict and row.get("name") == name and row.get("state") == "uploaded")
    size = row.get("size")
    _need(type(size) is int and len(MAGIC) + 28 < size <= LIMIT)
    sha = row.get("digest")
    _need(type(sha) is str and sha.startswith("sha256:"))
    return dict(id=store._number(row.get("id")), size=size, sha256=store._hex(sha[7:], 64))


def _inventory(api, binding):
    store._repo(api)
    journal = binding["journal"]
    releases = api.json("GET", store.ROOT + "/releases?per_page=100")
    _need(type(releases) is list and len(releases) < 100)
    matches = []
    for row in releases:
        _need(type(row) is dict and type(row.get("tag_name")) is str)
        identifier = store._number(row.get("id"))
        if identifier == journal["release_id"] or journal["name"] in (
            row["tag_name"],
            row.get("name"),
        ):
            _need(row.get("name") == row["tag_name"] == journal["name"])
            matches.append(identifier)
    _need(matches == [journal["release_id"]])
    release = api.json("GET", _path(binding))
    _need(
        type(release) is dict
        and store._number(release.get("id")) == journal["release_id"]
        and release.get("name") == release.get("tag_name") == journal["name"]
        and release.get("target_commitish") == journal["target_commitish"]
        and release.get("draft") is False
        and release.get("prerelease") is True
        and release.get("immutable") is False
    )
    rows = release.get("assets")
    _need(type(rows) is list and len(rows) <= len(STAGES))
    by_name = {}
    for row in rows:
        _need(type(row) is dict and type(row.get("name")) is str and row["name"] not in by_name)
        by_name[row["name"]] = row
    pins = []
    for step in range(1, len(rows) + 1):
        name = _name(binding, step)
        pins.append(_pin(by_name.get(name), name))
    _need(len({p["id"] for p in pins}) == len(pins))
    return pins


def _tip(step, pin):
    return dict(step=step, asset_id=pin["id"], sha256=pin["sha256"])


def _checkpoint(value, binding, step, previous):
    require_fields(value, ("storage", "issuer"))
    expected = binding["run_owner"] | {"source_revision": binding["source"]["source_revision"]}
    storage = store._receipt(value["storage"], expected)
    _need((storage["release_id"] is None) == (step == 1))
    _need(storage["release_id"] != binding["journal"]["release_id"])
    _need(set(storage["assets"]) == set(STAGES[step - 1]))
    if previous is not None:
        prior = previous["storage"]
        prefix = {name: storage["assets"][name] for name in prior["assets"]}
        # Only step 2 can introduce the working release ID. Prior pins and all other
        # scalar authority must survive every subsequent callback unchanged.
        previous_id = None if step == 2 else storage["release_id"]
        _need(storage | {"assets": prefix, "release_id": previous_id} == prior)

    issuer = value["issuer"]
    if step < 7:
        _need(issuer is None)
    else:
        require_fields(issuer, ("public", "control_sha256", "storage_sha256"))
        _need(_public(issuer["public"]) != binding["trusted_public"])
        store._hex(issuer["control_sha256"], 64)
        producer = storage | {"assets": {k: storage["assets"][k] for k in store.PACKETS}}
        _need(issuer["storage_sha256"] == digest(canonical(producer)))
        if step == 8:
            _need(
                issuer == previous["issuer"]
                and storage["assets"][store.CONTROL]["sha256"] == issuer["control_sha256"]
            )
        issuer = issuer.copy()
    return dict(storage=storage, issuer=issuer)


def _header(binding, step, previous_tip):
    return dict(binding=binding, step=step, previous=previous_tip)


def _seal(header, checkpoint, cipher, path):
    record = header | {"checkpoint": checkpoint}
    signed = signing.sign(record, KIND, path)
    # Re-opening the key in signing.sign can observe a rotated or replaced key.
    # Verify against the external anchor before sending any bytes.
    signing.verify(signed, KIND, header["binding"]["trusted_public"])
    nonce = secrets.token_bytes(12)
    raw = MAGIC + nonce + cipher.encrypt(nonce, canonical(signed), MAGIC + canonical(header))
    _need(len(raw) <= LIMIT)
    return raw


def _read(api, header, pin, cipher, previous):
    binding, step = header["binding"], header["step"]
    path = store._asset(pin)
    _need(_pin(api.json("GET", path), _name(binding, step)) == pin)
    store._repo(api)
    raw = api.download(path, pin["size"])
    _need(
        type(raw) is bytes
        and len(raw) == pin["size"]
        and raw.startswith(MAGIC)
        and digest(raw) == pin["sha256"]
    )
    offset = len(MAGIC) + 12
    try:
        plain = cipher.decrypt(raw[len(MAGIC) : offset], raw[offset:], MAGIC + canonical(header))
    except InvalidTag:
        raise Rejected("campaign_journal_authentication") from None
    record = signing.verify(decode(plain, LIMIT), KIND, binding["trusted_public"])
    require_fields(record, (*header, "checkpoint"))
    _need(canonical({k: record[k] for k in header}) == canonical(header))
    return _checkpoint(record["checkpoint"], binding, step, previous)


def publisher(api, *, journal, run_owner, source, key, trusted_public, key_path):
    """Open an empty operator-pinned release before starting handoff.publish."""
    binding = _binding(journal, run_owner, source, trusted_public)
    cipher = _cipher(key)
    _need(
        signing.encode64(signing.load_key(key_path).public_key().public_bytes_raw())
        == trusted_public
    )
    _need(_inventory(api, binding) == [])
    pins = []
    previous = None
    usable = True

    def append(value):
        nonlocal previous, usable
        _need(usable and len(pins) < len(STAGES))
        # A lost response is ambiguous. No retry or automatic adoption by this writer.
        usable = False
        step = len(pins) + 1
        checked = _checkpoint(value, binding, step, previous)
        header = _header(binding, step, _tip(step - 1, pins[-1]) if pins else None)
        raw = _seal(header, checked, cipher, key_path)
        name = _name(binding, step)
        _need(_inventory(api, binding) == pins)
        store._repo(api)
        pin = _pin(api.upload(_path(binding) + "/assets", name, raw), name)
        _need(pin["size"] == len(raw) and pin["sha256"] == digest(raw))
        pins.append(pin)
        _need(_inventory(api, binding) == pins)
        previous = _read(api, header, pin, cipher, previous)
        _need(previous == checked and _inventory(api, binding) == pins)
        usable = True
        return _tip(step, pin)

    return append


def recover(
    api, *, journal, run_owner, source, key, trusted_public, allow_partial=False, expected_tip=None
):
    """Audit signed checkpoints; incomplete prefixes carry no deletion/retention authority."""
    binding = _binding(journal, run_owner, source, trusted_public)
    cipher = _cipher(key)
    _need(type(allow_partial) is bool)
    if expected_tip is not None:
        require_fields(expected_tip, ("step", "asset_id", "sha256"))
        _need(store._number(expected_tip["step"]) <= len(STAGES))
        store._number(expected_tip["asset_id"])
        store._hex(expected_tip["sha256"], 64)
        expected_tip = expected_tip.copy()
    pins = _inventory(api, binding)
    complete = len(pins) == len(STAGES)
    _need(complete or allow_partial)
    checkpoint = tip = None
    for step, pin in enumerate(pins, start=1):
        checkpoint = _read(api, _header(binding, step, tip), pin, cipher, checkpoint)
        tip = _tip(step, pin)
    _need(expected_tip is None or expected_tip == tip)
    _need(_inventory(api, binding) == pins)
    return dict(checkpoint=checkpoint, tip=tip, complete=complete)
