"""Local, private transfer of the exact original frozen candidate, without authority minting."""

import argparse
import io
import re
import stat
import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZIP_STORED, BadZipFile, ZipFile, ZipInfo

from mlsecops import datasets, material_bundle, release_bundle, release_policy, signing
from mlsecops import final_evidence as final
from mlsecops import performance_delivery as delivery
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    require_fields,
    safe_child,
)
from mlsecops.storage import object_id
from scripts.m18_delivery_freeze import RECEIPT
from scripts.serving_retention import window

KIND = "original-frozen-candidate-transfer"
MANIFEST = "manifest.json"
CAS = "evidence/M18-objects/"
IDENTITY = (*delivery.SOURCE, *delivery.IDENTITY)
MAX_FILES = 64
MAX_ARCHIVE = material_bundle.MAX_TOTAL_BYTES + 16 * final.LIMIT
CLASSIFICATION = "private-local-only"
SECRET_FIELDS = {
    "password",
    "passwords",
    "token",
    "access_token",
    "private_key",
    "secret",
    "credentials",
    "dsn",
    "raw_logs",
    "review_packet",
}
SECRET_BYTES = re.compile(
    rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{50,}|(?:https?|postgres(?:ql)?)://[^/\s:@]+:[^@\s/]+@"
)


def need(value):
    final.need(value, "frozen-transfer-rejected")


def authority(freeze_pin, freeze, expected, run_owner, clock):
    object_id(freeze_pin)
    delivery.owner("M14", freeze)
    require_fields(expected, IDENTITY)
    need(
        isinstance(expected["source_revision"], str)
        and re.fullmatch("[a-f0-9]{40}", expected["source_revision"]) is not None
    )
    need(
        isinstance(expected["image_id"], str)
        and re.fullmatch("sha256:[a-f0-9]{64}", expected["image_id"]) is not None
    )
    for name in set(IDENTITY) - {"source_revision", "image_id"}:
        object_id(expected[name])
    require_fields(run_owner, ("repository", "run_id", "run_attempt", "producer_job"))
    for key, pattern in (
        ("repository", r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}"),
        ("producer_job", r"[A-Za-z0-9_-]{1,100}"),
    ):
        need(isinstance(run_owner[key], str) and re.fullmatch(pattern, run_owner[key]) is not None)
    for key in ("run_id", "run_attempt"):
        release_policy.integer(run_owner[key])
    release_policy.integer(clock)


def approved(name):
    return (
        name in (*delivery.FILES, RECEIPT) or re.fullmatch(CAS + "[a-f0-9]{64}", name) is not None
    )


def no_credentials(raw):
    """Defense in depth on selected bytes; not a public-data classifier or runtime scan."""
    need(SECRET_BYTES.search(raw) is None)
    if raw.lstrip()[:1] not in (b"{", b"["):
        return
    value = decode(raw, material_bundle.MAX_OBJECT_BYTES)
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            need(not SECRET_FIELDS & {k.lower() for k in item})
            pending.extend(item.values())
            # Envelopes contain base64 JSON; inspect the authenticated payload as well.
            if set(item) == {"payloadType", "payload", "signatures"}:
                no_credentials(signing.decode64(item["payload"]))
        elif isinstance(item, list):
            pending.extend(item)


def closure(read, *, freeze_pin, freeze, expected):
    """Read only producer-selected paths and the exact signed capsule dependency set."""
    index = decode(read(RECEIPT, freeze_pin, final.LIMIT))
    require_fields(index, ("schema_version", *delivery.SOURCE, "freeze", "policy_reference"))
    final.same(index["schema_version"], 1, "transfer-schema")
    final.same(index["freeze"], freeze, "transfer-freeze")
    final.subset(index, {k: expected[k] for k in delivery.SOURCE}, "transfer-source")
    fixed = {name: decode(read(name, pin, final.LIMIT)) for name, pin in freeze.items()}
    keys, trust = fixed["trusted-keys.json"], fixed["storage-trust.json"]
    require_fields(keys, signing.ROLES)
    need(all(len(signing.decode64(v)) == 32 for v in keys.values()))
    require_fields(trust, ("curator", "evaluator", "source_approval_digest"))
    read(CAS + object_id(index["policy_reference"]), index["policy_reference"], final.LIMIT)
    proposal = fixed[delivery.PROPOSAL]
    pin = object_id(proposal["proposal_reference"])
    final.same(pin, expected["proposal_reference"], "transfer-proposal")
    manifest = release_bundle.index(decode(read(CAS + pin, pin, final.LIMIT)), keys["approver"])
    refs = manifest["materials"]
    capsule = decode(
        read(CAS + refs["capsule"], refs["capsule"], material_bundle.MAX_ENVELOPE_BYTES)
    )
    descriptors = material_bundle._index(capsule, keys["approver"])["objects"]
    for name in release_bundle.DOCUMENTS:
        read(CAS + refs[name], refs[name], final.LIMIT)
    for row in descriptors:
        need(len(read(CAS + row["sha256"], row["sha256"], row["bytes"])) == row["bytes"])
    return index, manifest


def checked_files(reader, **pins):
    files = {}

    def read(name, pin, limit):
        need(approved(name))
        raw = reader(name, limit)
        need(0 < len(raw) <= limit and digest(raw) == object_id(pin))
        no_credentials(raw)
        if name in files:
            need(files[name] == raw)
        files[name] = raw
        need(len(files) <= MAX_FILES and sum(map(len, files.values())) <= MAX_ARCHIVE - final.LIMIT)
        return raw

    index, proposal = closure(read, **pins)
    return files, index, proposal


def checked_view(root, view, files, index, proposal, expected, clock):
    for name, raw in files.items():
        atomic_write(safe_child(view, name), raw)
    values, keys, _ = delivery.frozen(root, view, index)
    final.same({k: values[k] for k in IDENTITY}, expected, "transfer-identity")
    # Historical final.frozen alone does not grant a fresh job an unexpired window.
    window(values, clock)  # The existing 600-second minimum, never shortened or renewed.
    policy = release_policy.verify_policy(
        decode(files[CAS + index["policy_reference"]]),
        trusted_root=keys["trust"],
        expected_policy=values["promotion_policy"],
        environment="local-cpu",
        clock=clock,
    )
    need(policy["expires_at"] - clock >= 600)
    approval = release_policy.checked(
        decode(files[CAS + values["integrity_snapshot"]["approval"]]), "source", keys["curator"]
    )
    datasets.validate_approval(
        approval,
        decode(bounded_read(root / "policies/local-cpu.json")),
        moment=datetime.fromtimestamp(clock, UTC),
    )
    card = decode(files[CAS + proposal["materials"]["model-card"]])
    return dict(
        handling=CLASSIFICATION,
        public_synthetic_proven=False,
        model_card_classification=card["data_classification"],
        source_approval_purpose=approval["purpose"],
        source_lock_sha256=values["data_lock"],
        dataset_reference=values["dataset_reference"],
        source_approval_sha256=values["integrity_snapshot"]["approval"],
        reason="signed-synthetic-provenance-does-not-authorize-publication",
    )


def pack(manifest, files):
    stream = io.BytesIO()
    with ZipFile(stream, "w", compression=ZIP_STORED, allowZip64=False) as archive:
        for name, raw in sorted({MANIFEST: manifest, **files}.items()):
            entry = ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(entry, raw)
    raw = stream.getvalue()
    need(len(raw) <= MAX_ARCHIVE)
    return raw


def unpack(raw, manifest_pin):
    object_id(manifest_pin)
    need(len(raw) <= MAX_ARCHIVE)
    with ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        need(
            1 < len(names) <= MAX_FILES + 1 and len(set(names)) == len(names) and MANIFEST in names
        )
        need(all(name == MANIFEST or approved(name) for name in names))
        need(sum(entry.file_size for entry in entries) <= MAX_ARCHIVE)
        for entry in entries:
            need(entry.compress_type == ZIP_STORED and entry.flag_bits == 0 and not entry.is_dir())
            need(
                stat.S_ISREG(entry.external_attr >> 16)
                and 0 < entry.file_size <= material_bundle.MAX_OBJECT_BYTES
            )
        files = {name: archive.read(name) for name in names}
    manifest_raw = files.pop(MANIFEST)
    need(digest(manifest_raw) == manifest_pin and len(manifest_raw) <= final.LIMIT)
    manifest = decode(manifest_raw)
    need(canonical(manifest) + b"\n" == manifest_raw)
    # Reject comments, preambles, hidden trailers and alternate container metadata too.
    need(pack(manifest_raw, files) == raw)
    return manifest, files


def inventory(files):
    return {name: dict(sha256=digest(raw), bytes=len(raw)) for name, raw in sorted(files.items())}


def export(root, state, *, freeze_pin, freeze, expected, run_owner, clock):
    """Write one local private archive below root/.runtime; return pins, never package contents."""
    authority(freeze_pin, freeze, expected, run_owner, clock)
    final.clean(root, expected["source_revision"], expected["source_fingerprint"])
    files, index, proposal = checked_files(
        lambda name, limit: bounded_read(safe_child(state, name), limit),
        freeze_pin=freeze_pin,
        freeze=freeze,
        expected=expected,
    )
    parent = safe_child(root, ".runtime/frozen-transfers")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with TemporaryDirectory(prefix="verify-", dir=parent) as temporary:
        classification = checked_view(
            root, Path(temporary), files, index, proposal, expected, clock
        )
    manifest = dict(
        schema_version=1,
        kind=KIND,
        run_owner=run_owner,
        identity=expected,
        freeze_sha256=freeze_pin,
        freeze=freeze,
        proposal_window={k: proposal[k] for k in ("issued_at", "expires_at")},
        classification=classification,
        files=inventory(files),
    )
    manifest_raw = canonical(manifest) + b"\n"
    pin = digest(manifest_raw)
    raw = pack(manifest_raw, files)
    final.clean(root, expected["source_revision"], expected["source_fingerprint"])
    target = safe_child(parent, pin + ".zip")
    if target.exists():
        need(bounded_read(target, MAX_ARCHIVE) == raw)
    else:
        atomic_write(target, raw)
    return dict(
        path=str(target),
        manifest_sha256=pin,
        archive_sha256=digest(raw),
        classification=classification,
        release_ready=False,
    )


@contextmanager
def materialize(root, archive, *, manifest_pin, freeze_pin, freeze, expected, run_owner, clock):
    """Yield a new owned temporary state; never extract into a caller's existing state."""
    authority(freeze_pin, freeze, expected, run_owner, clock)
    final.clean(root, expected["source_revision"], expected["source_fingerprint"])
    manifest, stored = unpack(bounded_read(archive, MAX_ARCHIVE), manifest_pin)
    require_fields(
        manifest,
        (
            "schema_version",
            "kind",
            "run_owner",
            "identity",
            "freeze_sha256",
            "freeze",
            "proposal_window",
            "classification",
            "files",
        ),
    )
    final.subset(
        manifest,
        dict(
            schema_version=1,
            kind=KIND,
            run_owner=run_owner,
            identity=expected,
            freeze_sha256=freeze_pin,
            freeze=freeze,
        ),
        "transfer-owner",
    )
    final.same(manifest["files"], inventory(stored), "transfer-preimages")
    files, index, proposal = checked_files(
        lambda name, limit: stored[name], freeze_pin=freeze_pin, freeze=freeze, expected=expected
    )
    need(files.keys() == stored.keys())
    final.same(
        manifest["proposal_window"],
        {k: proposal[k] for k in ("issued_at", "expires_at")},
        "transfer-original-window",
    )
    parent = safe_child(root, ".runtime/frozen-transfers")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with TemporaryDirectory(prefix="reader-", dir=parent) as temporary:
        view = Path(temporary)
        classification = checked_view(root, view, files, index, proposal, expected, clock)
        final.same(manifest["classification"], classification, "transfer-classification")
        final.clean(root, expected["source_revision"], expected["source_fingerprint"])
        yield (
            view,
            dict(manifest_sha256=manifest_pin, classification=classification, release_ready=False),
        )


def verify(root, archive, **arguments):
    with materialize(root, archive, **arguments) as (_, summary):
        return summary


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("export", "verify"))
    parser.add_argument(
        "--authority",
        required=True,
        type=Path,
        help="Externally trusted local JSON: freeze_pin, freeze, expected, run_owner",
    )
    parser.add_argument("--clock", required=True, type=int, help="Caller current UTC epoch seconds")
    parser.add_argument("--state", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--manifest-pin")
    args = parser.parse_args(arguments)
    root = Path(__file__).resolve().parents[1]
    owner = decode(bounded_read(args.authority, final.LIMIT))
    require_fields(owner, ("freeze_pin", "freeze", "expected", "run_owner"))
    if args.mode == "export":
        need(args.state is not None and args.archive is None and args.manifest_pin is None)
        result = export(root, args.state, **owner, clock=args.clock)
    else:
        need(args.state is None and args.archive is not None and args.manifest_pin is not None)
        result = verify(
            root, args.archive, manifest_pin=args.manifest_pin, **owner, clock=args.clock
        )
    print(canonical(result).decode())


if __name__ == "__main__":
    try:
        main()
    except (
        Rejected,
        OSError,
        KeyError,
        TypeError,
        ValueError,
        BadZipFile,
        AttributeError,
        OverflowError,
        RecursionError,
    ):
        sys.exit("Frozen candidate transfer rejected; inspect original pins locally")
