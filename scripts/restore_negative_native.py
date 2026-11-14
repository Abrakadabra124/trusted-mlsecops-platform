"""Controlled signed approval history in the owner's v2 backup. See seeded() and replay()."""

import json
import re
from contextlib import ExitStack, contextmanager
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

from mlsecops import (
    load_clock,
    material_bundle,
    promotion_state,
    release_authorization,
    release_bundle,
    release_policy,
    release_reader,
    serving,
    serving_startup,
    signing,
    storage,
    storage_backup,
    storage_bootstrap,
    storage_restore,
    trust,
    trust_authority,
)
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.load_golden import Golden
from mlsecops.sandbox import resolve_image
from mlsecops.security_events import hexadecimal
from scripts import promotion_entrypoint_native as promoter
from scripts import serving_native
from scripts.kube_approval_fixture import renew
from scripts.promotion_qualification import PromotionAdmissionContracts
from scripts.release_reader_native import disposable

ENV = "local-cpu"
SCOPE = "controlled-approvals-in-shared-v2-snapshot"
IDENTITY = ("workspace_id", "container_id", "network_id", "volume")
CLIENT_FILES = {"ca.crt": "ca.crt", "client.crt": "ml_serving.crt", "client.key": "ml_serving.key"}


@contextmanager
def target_client(target, marker):
    """Keep libpq on the verified restored credentials across every serving reconnect."""
    exported = safe_child(target, "storage-clients/serving")
    require(not (exported / ".no-passwords").exists())
    with TemporaryDirectory() as tmp:
        client = Path(tmp).resolve()
        for name in ("connection.json", *CLIENT_FILES):
            atomic_write(client / name, bounded_read(safe_child(exported, name), 4096))
        params, files = storage.connection_materials(client)
        require(
            (params["host"], params["port"], params["user"])
            == ("127.0.0.1", marker["port"], "ml_serving")
        )
        require(
            all(
                files[k] == digest(bounded_read(safe_child(target, "storage-pki/" + v), 4096))
                for k, v in CLIENT_FILES.items()
            )
        )
        yield client


def require(condition):
    if not condition:
        raise Rejected("restore_negative_binding")


def sha(value):
    return digest(canonical(value))


def golden_release_id(campaign, features, score):
    # A signed release ID is 128 bits. Commit the independent Python reference before promotion.
    return sha(dict(campaign=campaign, features=features, expected_score=score))[:32]


def refusal(operation, expected):
    try:
        operation()
    except Rejected as error:
        if str(error) == expected:
            return expected
    raise Rejected("restore_negative_wrong_refusal")


def archive_fault(content, model, case):
    """Change only complete matching COPY rows in an uncompressed custom-format pg_dump."""
    lookup = storage.object_id(model).encode("ascii")
    require(case in ("missing", "corrupt") and content.startswith(b"PGDMP"))
    prefix = lookup + b"\t\\\\x"
    match = re.search(re.escape(prefix) + rb"([0-9a-f]+)\t", content)
    require(match is not None)
    original = bytes.fromhex(match[1].decode("ascii"))
    require(original and digest(original) == model)
    replacement = bytes([original[0] ^ 1]) + original[1:]
    after = digest(replacement)
    new_key = model if case == "corrupt" else after
    require(after.encode() not in content)
    new_row = new_key.encode() + b"\t\\\\x" + replacement.hex().encode() + b"\t"
    old_row = match[0]
    count = content.count(old_row)
    require(content.count(prefix) == count)
    return content.replace(old_row, new_row), dict(
        before=model,
        after=after,
        lookup_after=new_key,
        occurrences=count,
        payload_bytes=len(original),
    )


def backup_negatives(root, directory, public, backup_id, scratch, model):
    """Two fresh private archive copies. Both must refuse before creating a restore target."""
    directory, scratch = Path(directory), Path(scratch)
    policy = read_json(Path(root) / "policies/local-cpu.json")
    statement, content = storage_backup.read_backup(directory, public, policy)
    require(statement["schema_version"] == 2 and sha(statement) == storage.object_id(backup_id))
    envelope = read_json(directory / "manifest.json")
    cases = {}
    for case in ("corrupt", "missing"):
        damaged, row = archive_fault(content, model, case)
        with TemporaryDirectory(dir=scratch) as temporary:
            private = Path(temporary)
            archive, target = private / "archive", private / "target"
            write_json(archive / "manifest.json", envelope)
            atomic_write(archive / "data.dump", damaged)
            reason = refusal(
                lambda: storage_restore.restore(
                    root, archive, target, public, expected_backup_id=backup_id
                ),
                "backup_archive_integrity_failed",
            )
            require(not target.exists() and not target.is_symlink())
            cases[case] = dict(
                row=row,
                archive_sha256=digest(damaged),
                archive_bytes=len(damaged),
                reason=reason,
                target_created=target.exists(),
            )
    return dict(backup_id=backup_id, cases=cases)


def history(client):
    with storage.connect(client) as db:
        rows = db.execute(
            "SELECT environment, sequence, request_sha256, previous_sha256, "
            "extract(epoch FROM recorded_at)::text FROM ml_promotion.events "
            'ORDER BY environment COLLATE "C", sequence',
        ).fetchall()
    return [
        dict(environment=env, sequence=seq, request_sha256=ref, previous_sha256=prev, epoch=epoch)
        for env, seq, ref, prev, epoch in rows
    ]


def sql_identity(marker):
    return {key: marker[key] for key in IDENTITY}


def archive_objects(client, rows):
    """Read the restored serving-role CAS. Deduplicate bytes shared by the two approvals."""
    objects = {}

    def store(content):
        objects[digest(content)] = signing.encode64(content)

    for event in rows:
        if event["environment"] != ENV:
            continue
        selection = release_reader.document(client, event["request_sha256"], 65536)
        proof = release_reader.document(
            client, selection["authorization_reference"], 4 * release_policy.MAX_DOCUMENT
        )
        store(canonical(selection))
        store(canonical(proof))
        policy = decode(signing.decode64(proof["policy_envelope"]["payload"]))
        package = release_bundle.load(
            client,
            selection["proposal_reference"],
            publisher_public=policy["identities"]["publisher"]["public_key"],
        )
        store(canonical(package["envelope"]))
        store(canonical(package["capsule"]["envelope"]))
        for content in (*package["capsule"]["objects"].values(), *package["documents"].values()):
            store(content)
        for reference in proof["reports"].values():
            store(storage.get(client, "releases", reference))
    return objects


def read_trust(authority, public):
    return trust_authority.read(authority / "storage-clients/serving", ENV, public)


def server_probe(client, args, authority, public, minimum, golden):
    def reader():
        return release_reader.Reader(
            client,
            **{
                k: args[k]
                for k in ("context", "trusted_root", "expected_policy", "expected_serving_image")
            },
            minimum_sequence=2,
            trust_lease=trust.Lease(
                lambda: read_trust(authority, public),
                trusted_root=public,
                environment=ENV,
                minimum_version=minimum,
            ),
        )

    start = load_clock.sample()
    engine = serving.Engine(reader())
    with serving_native.site(engine) as request:
        status, reply = request("/readyz")
        result = dict(
            start_clock=start,
            route="/readyz",
            status=status,
            response=reply,
            startup=engine.startup_failure,
        )
        ready_clock = load_clock.sample()
        result["ready_clock"] = ready_clock
        status, reply = request("/v1/predict", golden.body)
        result["predict"] = dict(
            route="/v1/predict", payload_sha256=digest(golden.body), status=status, response=reply
        )
        check_http(result, golden, minimum, set())
        result["verified_clock"] = load_clock.sample()
        if minimum == 1:
            result["selection_sha256"] = engine.loaded.request_sha256
        if minimum == 2:
            result["cold_reader"] = refusal(reader().load, "trust_key_revoked")
    return result


class Seed:
    def __init__(self, root, state, image, campaign, authority, fixture, expected):
        self.root, self.state, self.image, self.campaign = root, state, image, campaign
        self.authority, self.fixture = authority, fixture
        self.args = fixture.arguments
        self.public = fixture.trust_fixture.public
        self.source = storage_bootstrap.validate(state)
        self.model = digest(fixture.fixture.bundle.materials.fixture.model)
        self.receipts = []
        self.features, self.score = expected[0][:1], expected[1][0]

    def publish(self, keys):
        stored = trust_authority.update(
            self.authority,
            self.args["expected_policy"],
            self.fixture.trust_fixture.key,
            revoked_keys=keys,
        )
        envelope, clock = read_trust(self.authority, self.public)
        require(stored["document_sha256"] == sha(envelope))
        return dict(envelope=envelope, sql_second=clock)

    def populate(self):
        policy = self.args["expected_policy"]
        promotion_state.install(self.state)
        promotion_state.configure(self.state, ENV, policy)
        client = self.state / "storage-clients/serving"
        require(not any(r["environment"] == ENV for r in history(client)))
        trust_authority.install(self.authority, ENV, self.public)
        self.initial = self.publish([])
        for seq in (1, 2):
            if seq == 2:
                renew(self.fixture, self.image)
            receipt = promoter.controlled(
                self.root, self.state, self.authority, self.args, self.public
            )
            require(receipt["sequence"] == seq)
            self.receipts.append(receipt)
        self.source_events = history(client)
        require(
            [r["request_sha256"] for r in self.receipts]
            == [r["request_sha256"] for r in self.source_events if r["environment"] == ENV]
        )

    def verify_restored(self, target, backup_id):
        """Call once, after the owner stops the source and restores its exact pinned backup."""
        target = Path(target).resolve()
        directory = safe_child(self.state, "backups/" + storage.object_id(backup_id))
        public = read_json(self.state / "trusted-keys.json")
        policy = read_json(self.root / "policies/local-cpu.json")
        manifest = read_json(directory / "manifest.json")
        statement = storage_backup.verify_manifest(manifest, public, policy)
        require(
            sha(statement) == backup_id
            and statement["source_workspace"] == self.source["workspace_id"]
        )
        receipt = read_json(target / "recovery.json")
        dest = storage_bootstrap.validate(target)
        require(
            receipt["backup_id"] == backup_id
            and receipt["target_workspace"] == dest["workspace_id"]
            and receipt["container_id"] == dest["container_id"]
        )
        require(all(dest[key] != self.source[key] for key in IDENTITY))
        require(storage_bootstrap.validate(self.state) == self.source)
        require(
            storage_bootstrap.inspect("container", self.source["container_id"])["State"]["Running"]
            is False
        )
        with target_client(target, dest) as client:
            observations = self.observe(client)
        require(storage_bootstrap.validate(target) == dest)
        require(
            storage_bootstrap.inspect("container", self.source["container_id"])["State"]["Running"]
            is False
        )
        record = dict(
            schema_version=1,
            scope=SCOPE,
            campaign=self.campaign,
            image=self.image,
            backup_id=backup_id,
            backup_manifest=manifest,
            backup_public=public,
            backup_policy=policy,
            restore=receipt,
            source=sql_identity(self.source),
            target=sql_identity(dest),
            context=self.args["context"],
            release_root=self.args["trusted_root"],
            trust_root=self.public,
            initial=self.initial,
            receipts=self.receipts,
            features=self.features,
            expected_score=self.score,
            archive=backup_negatives(
                self.root, directory, public, backup_id, self.authority / "evidence", self.model
            ),
            **observations,
        )
        replay(record, backup_id=backup_id, campaign=self.campaign, image=self.image)
        return record

    def observe(self, client):
        rows = history(client)
        require(canonical(rows) == canonical(self.source_events))
        head = promotion_state.state(client, ENV)
        require(head["request_sha256"] == self.receipts[-1]["request_sha256"])
        objects = archive_objects(client, rows)
        golden = Golden.from_expected(
            dict(
                features=self.features,
                scores=[self.score],
                model=self.model,
                bundle=self.receipts[1]["subject_sha256"],
            )
        )
        healthy = server_probe(client, self.args, self.authority, self.public, 1, golden)
        require(healthy["status"] == 200 and healthy["startup"] is None)
        signer = self.args["approval_envelope"]["signatures"][0]["keyid"]
        revoked = self.publish([signer])
        negative = server_probe(client, self.args, self.authority, self.public, 2, golden)
        after = promotion_state.state(client, ENV)
        require(canonical(head) == canonical(after))
        return dict(
            events=rows,
            head=head,
            final_head=after,
            objects=objects,
            healthy=healthy,
            revoked=revoked,
            negative=negative,
        )


@contextmanager
def seeded(root, state, image, campaign, *, bind_candidate):
    """Seed controlled approvals before backup. bind_candidate(fixture, image) binds the owner's
    evaluated model and returns its reference features and scores. The first row is used for HTTP.
    """
    promoter.hosted()
    hexadecimal(campaign, 32)
    root, state = Path(root).resolve(), Path(state).resolve()
    image = resolve_image(image)
    with disposable(root, state, campaign, "m17-trust", 15453) as authority, ExitStack() as cleanup:
        PromotionAdmissionContracts.setUpClass()
        cleanup.callback(PromotionAdmissionContracts.tearDownClass)
        fixture = PromotionAdmissionContracts()
        cleanup.callback(lambda: require(fixture.doCleanups()))
        fixture.setUp()
        expected = bind_candidate(fixture, image)
        fixture.fixture.bundle.attributes["release_id"] = golden_release_id(
            campaign, expected[0][:1], expected[1][0]
        )
        serving_native.bind_release(fixture, image)
        seed = Seed(root, state, image, campaign, authority, fixture, expected)
        seed.populate()
        yield seed


def check_http(obs, golden, version, ids):
    response = obs["response"]
    prediction = obs["predict"]
    require_fields(prediction, ("route", "payload_sha256", "status", "response"))
    require(
        obs["route"] == "/readyz"
        and prediction["route"] == "/v1/predict"
        and prediction["payload_sha256"] == digest(golden.body)
    )
    for reply in (response, prediction["response"]):
        identifier = hexadecimal(reply["request_id"], 32)
        require(identifier not in ids)
        ids.add(identifier)
    if version == 1:
        require(obs["startup"] is None and obs["status"] == prediction["status"] == 200)
        require(
            canonical(response)
            == canonical(
                dict(
                    ready=True,
                    request_id=response["request_id"],
                    bundle_sha256=golden.bundle,
                    model_sha256=golden.model,
                )
            )
        )
        require(golden.valid(prediction["response"]))
    else:
        require(
            obs["startup"] == serving_startup.record("reader", None, Rejected("trust_key_revoked"))
        )
        for sample, code in ((obs, "not_ready"), (prediction, "model_unavailable")):
            reply = sample["response"]
            require(
                sample["status"] == 503
                and canonical(reply)
                == canonical(
                    dict(schema_version=1, request_id=reply["request_id"], error={"code": code})
                )
            )


def check_ledger(rows, ledger):
    encoded = []
    for row in rows:
        require_fields(
            row, ("environment", "sequence", "request_sha256", "previous_sha256", "epoch")
        )
        release_policy.name(row["environment"])
        release_policy.integer(row["sequence"])
        storage.object_id(row["request_sha256"])
        if row["previous_sha256"] is not None:
            storage.object_id(row["previous_sha256"])
        require(re.fullmatch(r"[0-9]{1,12}\.[0-9]{6}", row["epoch"]) is not None)
        # Same UTF-8 serialization as jsonb_build_array(...)::text in promotion_recovery.ledger_sql.
        encoded.append(
            json.dumps(
                [
                    row[k]
                    for k in (
                        "environment",
                        "sequence",
                        "request_sha256",
                        "previous_sha256",
                        "epoch",
                    )
                ]
            ).encode()
        )
    require(
        canonical(ledger)
        == canonical(
            dict(
                rows=len(rows),
                bytes=sum(map(len, encoded)),
                invalid=0,
                sha256=digest(b"\n".join(encoded)),
            )
        )
    )


def verify_release(record, read, event, seq, previous, clock):
    ref = event["request_sha256"]
    selection = promotion_state.request(read(ref))
    require(event["sequence"] == seq and event["previous_sha256"] == previous)
    require(selection["sequence"] == seq and selection["environment"] == ENV)
    proof = decode(read(selection["authorization_reference"]))
    require_fields(
        proof,
        (
            "schema_version",
            "policy_envelope",
            "assurance_envelope",
            "approval_envelope",
            "reports",
            "decision",
        ),
    )
    require(type(proof["schema_version"]) is int and proof["schema_version"] == 1)
    policy = release_policy.verify_policy(
        proof["policy_envelope"],
        trusted_root=record["release_root"],
        expected_policy=selection["policy_sha256"],
        environment=ENV,
        clock=clock,
    )
    publisher = policy["identities"]["publisher"]["public_key"]
    env = decode(read(selection["proposal_reference"]))
    manifest = release_bundle.index(env, publisher)
    if seq == 1:
        require(
            manifest["release_id"]
            == golden_release_id(record["campaign"], record["features"], record["expected_score"])
        )
    refs = manifest["materials"]
    capsule = decode(read(refs["capsule"]))
    contents = material_bundle._index(capsule, publisher)
    package = dict(
        envelope=env,
        capsule=dict(
            envelope=capsule,
            objects={
                (row["namespace"], row["sha256"]): read(row["sha256"])
                for row in contents["objects"]
            },
        ),
        documents={k: read(refs[k]) for k in release_bundle.DOCUMENTS},
    )
    decision = release_authorization.verify(
        package=package,
        **{k: proof[k] for k in ("policy_envelope", "assurance_envelope", "approval_envelope")},
        reports={gate: read(key) for gate, key in proof["reports"].items()},
        context=record["context"],
        trusted_root=record["release_root"],
        expected_policy=selection["policy_sha256"],
        expected_serving_image=record["image"],
        clock=clock,
    )
    approver = policy["identities"]["approver"]["public_key"]
    approval = release_policy.checked(proof["approval_envelope"], "release-approval", approver)
    require(approval["action"] == "promote" and approval["schema_version"] == 1)
    require(
        canonical(decision) == canonical(proof["decision"])
        and selection["issued_at"] == approval["issued_at"]
    )
    require(
        all(
            selection[k] == decision[k]
            for k in ("subject_sha256", "environment", "sequence", "policy_sha256", "expires_at")
        )
    )
    receipt = dict(
        environment=ENV,
        sequence=seq,
        request_sha256=ref,
        state="recorded-not-activated",
        subject_sha256=decision["subject_sha256"],
        proposal_reference=selection["proposal_reference"],
        trust=dict(version=1, document_sha256=sha(record["initial"]["envelope"])),
        release_ready=False,
    )
    require(canonical(record["receipts"][seq - 1]) == canonical(receipt))
    return dict(
        model=refs["model"],
        bundle=decision["subject_sha256"],
        approval=decision["approval_sha256"],
        signer=digest(signing.decode64(approver)),
        policy=decision["policy_sha256"],
        expires_at=decision["expires_at"],
    )


def check_archive(record, model, archive, content=None):
    require_fields(record, ("backup_id", "cases"))
    require_fields(record["cases"], ("corrupt", "missing"))
    altered = set()
    for case, sample in record["cases"].items():
        require_fields(
            sample, ("row", "archive_sha256", "archive_bytes", "reason", "target_created")
        )
        row = sample["row"]
        if content is not None:
            damaged, expected_row = archive_fault(content, digest(model), case)
            require(
                canonical(row) == canonical(expected_row)
                and sample["archive_sha256"] == digest(damaged)
            )
        require_fields(row, ("before", "after", "lookup_after", "occurrences", "payload_bytes"))
        changed = bytes([model[0] ^ 1]) + model[1:]
        require(
            row["before"] == digest(model)
            and row["after"] == digest(changed)
            and row["lookup_after"] == (row["before"] if case == "corrupt" else row["after"])
            and row["payload_bytes"] == len(model)
            and type(row["occurrences"]) is int
            and row["occurrences"] >= 1
        )
        require(
            sample["reason"] == "backup_archive_integrity_failed"
            and sample["target_created"] is False
            and sample["archive_bytes"] == archive["bytes"]
        )
        altered.add(storage.object_id(sample["archive_sha256"]))
    require(len(altered) == 2 and archive["sha256"] not in altered)
    require(
        record["cases"]["missing"]["row"]["occurrences"]
        == record["cases"]["corrupt"]["row"]["occurrences"]
    )


def replay(record, *, backup_id, campaign, image, archive_bytes=None):
    """Offline. Owner pins the private record independently, then passes its external backup/run pins."""
    try:
        return _replay(
            record, storage.object_id(backup_id), hexadecimal(campaign, 32), image, archive_bytes
        )
    except (KeyError, TypeError, ValueError, IndexError, OverflowError, RecursionError):
        raise Rejected("restore_negative_evidence") from None


def _replay(r, backup_id, campaign, image, archive_bytes):
    require_fields(
        r,
        (
            "schema_version",
            "scope",
            "campaign",
            "image",
            "backup_id",
            "backup_manifest",
            "backup_public",
            "backup_policy",
            "restore",
            "source",
            "target",
            "context",
            "release_root",
            "trust_root",
            "initial",
            "revoked",
            "receipts",
            "events",
            "head",
            "final_head",
            "objects",
            "healthy",
            "negative",
            "features",
            "expected_score",
            "archive",
        ),
    )
    require(
        type(r["schema_version"]) is int
        and r["schema_version"] == 1
        and r["scope"] == SCOPE
        and r["image"] == image
        and re.fullmatch(r"sha256:[a-f0-9]{64}", image) is not None
        and r["campaign"] == campaign
        and r["backup_id"] == r["archive"]["backup_id"] == backup_id
        and len(canonical(r)) <= 8 * 1024 * 1024
    )
    receipt = r["restore"]
    require_fields(
        receipt,
        (
            "schema_version",
            "backup_id",
            "source_workspace",
            "target_workspace",
            "container_id",
            "port",
            "restored_at",
            "elapsed_seconds",
            "tables",
            "promotion",
            "status",
            "release_ready",
        ),
    )
    moment = datetime.fromisoformat(receipt["restored_at"])
    statement = storage_backup.verify_manifest(
        r["backup_manifest"], r["backup_public"], r["backup_policy"], moment=moment
    )
    require(
        sha(statement) == backup_id == receipt["backup_id"]
        and type(receipt["schema_version"]) is int
        and statement["schema_version"] == receipt["schema_version"] == 2
        and canonical(statement["tables"]) == canonical(receipt["tables"])
        and canonical(statement["promotion"]) == canonical(receipt["promotion"])
        and receipt["release_ready"] is False
        and receipt["status"] == "storage-restored-not-release-ready"
    )
    for identity in (r["source"], r["target"]):
        require_fields(identity, IDENTITY)
        workspace = hexadecimal(identity["workspace_id"], 32)
        hexadecimal(identity["network_id"])
        hexadecimal(identity["container_id"])
        require(identity["volume"] == "tml-" + workspace[:12] + "-storage-data")
    require(all(r["source"][k] != r["target"][k] for k in IDENTITY))
    require(
        statement["source_workspace"] == receipt["source_workspace"] == r["source"]["workspace_id"]
        and receipt["target_workspace"] == r["target"]["workspace_id"]
        and receipt["container_id"] == r["target"]["container_id"]
    )
    check_ledger(r["events"], statement["promotion"]["tables"]["events"])
    rows = [e for e in r["events"] if e["environment"] == ENV]
    require(len(rows) == len(r["receipts"]) == 2)
    pool = {storage.object_id(k): signing.decode64(v) for k, v in r["objects"].items()}
    require(all(digest(v) == k for k, v in pool.items()))
    used = set()

    def read(reference):
        used.add(reference)
        return pool[reference]

    releases = []
    previous = None
    for seq, event in enumerate(rows, 1):
        second = int(Decimal(event["epoch"]))
        require(second <= datetime.fromisoformat(statement["completed_at"]).timestamp())
        releases.append(verify_release(r, read, event, seq, previous, second))
        previous = event["request_sha256"]
    require(used == pool.keys())
    a, b = releases
    require(
        a["policy"] == b["policy"]
        and a["signer"] == b["signer"]
        and a["model"] == b["model"]
        and a["bundle"] != b["bundle"]
        and a["approval"] != b["approval"]
    )
    head = dict(environment=ENV, sequence=2, request_sha256=previous, release_ready=False)
    require(canonical(head) == canonical(r["head"]) == canonical(r["final_head"]))
    golden = Golden.from_expected(
        dict(
            model=b["model"],
            bundle=b["bundle"],
            features=r["features"],
            scores=[r["expected_score"]],
        )
    )
    clocks = []
    ids = set()
    previous_trust = None
    for version, phase, key in ((1, "healthy", "initial"), (2, "negative", "revoked")):
        sample = r[phase]
        require_fields(
            sample,
            (
                "start_clock",
                "ready_clock",
                "verified_clock",
                "route",
                "status",
                "response",
                "predict",
                "startup",
                "cold_reader" if version == 2 else "selection_sha256",
            ),
        )
        clock = sample["start_clock"]
        end = sample["verified_clock"]
        clocks.extend((clock, sample["ready_clock"], end))
        stored = r[key]
        require_fields(stored, ("envelope", "sql_second"))
        sql = release_policy.integer(stored["sql_second"])
        payload = trust.validate(stored["envelope"], r["trust_root"], ENV, sql)
        for anchor in (clock, end):
            trust.validate(
                stored["envelope"], r["trust_root"], ENV, anchor["after_ns"] // load_clock.NS
            )
        require(
            sql <= clock["before_ns"] // load_clock.NS
            and payload["version"] == version
            and payload["promotion_policy_sha256"] == b["policy"]
            and payload["revoked_artifacts"] == []
            and payload["revoked_keys"] == ([] if version == 1 else [b["signer"]])
            and end["after_ns"] // load_clock.NS < b["expires_at"]
        )
        if version == 2:
            trust.successor(previous_trust, payload)
            require(
                sample["cold_reader"] == "trust_key_revoked"
                and r["healthy"]["verified_clock"]["after_ns"] // load_clock.NS
                <= payload["issued_at"]
            )
        else:
            require(
                payload["issued_at"] <= int(Decimal(rows[0]["epoch"]))
                and sample["selection_sha256"] == previous
            )
        previous_trust = payload
        check_http(sample, golden, version, ids)
    for start, end in zip(clocks, clocks[1:]):
        require(start["after_ns"] <= end["before_ns"])
        load_clock.window(dict(start=start, end=end), end["monotonic_ns"] - start["monotonic_ns"])
    require(moment.timestamp() <= clocks[0]["before_ns"] / load_clock.NS)
    if archive_bytes is not None:
        require(
            type(archive_bytes) is bytes
            and len(archive_bytes) == statement["archive"]["bytes"]
            and digest(archive_bytes) == statement["archive"]["sha256"]
        )
    check_archive(r["archive"], pool[b["model"]], statement["archive"], archive_bytes)
    return dict(
        scope=SCOPE,
        status="pass",
        release_ready=False,
        backup_id=backup_id,
        campaign=campaign,
        target_workspace=r["target"]["workspace_id"],
        source_workspace=r["source"]["workspace_id"],
        image=image,
        approved_sequences=[1, 2],
        selected_request_sha256=previous,
        approval_sha256=b["approval"],
        release_subject=b["bundle"],
        model_sha256=b["model"],
        revoked_approver_sha256=b["signer"],
        healthy_status=r["healthy"]["predict"]["status"],
        verified_clock=dict(r["healthy"]["verified_clock"]),
        cold_ready_status=r["negative"]["status"],
        cold_predict_status=r["negative"]["predict"]["status"],
        archive_refusals={k: v["reason"] for k, v in r["archive"]["cases"].items()},
    )
