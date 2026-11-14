"""Observe four independently running HTTP/ONNX deployments under one qualification authority."""

import asyncio
import math
import os
import time
from contextlib import ExitStack
from functools import partial

from mlsecops import (
    release_bundle,
    sandbox,
    serving,
    serving_runtime,
    signing,
    storage_bootstrap,
    trust,
    trust_authority,
)
from mlsecops.canary_native_evidence import read_pinned
from mlsecops.candidate_serving_reader import FLEET_KIND, KIND, CandidateReader
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    decode,
    digest,
    read_json,
    safe_child,
)
from mlsecops.datasets import FEATURES
from mlsecops.inventory_fleet import ROLES, require, sha
from mlsecops.load_golden import Golden
from mlsecops.prediction_protocol import PredictionBatch
from mlsecops.security_events import hexadecimal
from scripts import canary_rollout_native as rollout
from scripts import inventory_fleet_materials as materials
from scripts.canary_candidate_native import _trust_update
from scripts.canary_rollback_native import stamp
from scripts.candidate_serving_reader import bind_proposal
from scripts.release_reader_native import disposable


def pinned(state):
    pin = os.environ.get("M19_FLEET_INPUTS_SHA256")
    if not pin:
        raise FileNotFoundError("M19 fleet owner pin unavailable")
    return decode(read_pinned(safe_child(state, materials.FILE), hexadecimal(pin)))


def prepare(state, client, report, policy, keys, campaign, expected, features):
    package = release_bundle.load(
        client, report["proposal_reference"], publisher_public=keys["approver"]
    )
    context, verified = bind_proposal(
        report,
        package,
        policy=policy,
        source_trust=read_json(state / "storage-trust.json"),
        publisher_public=keys["approver"],
        expected=expected,
        clock=math.ceil(time.time()),
    )
    batch = PredictionBatch(verified["model"], features)
    output, execution = sandbox.run_worker(expected["image_id"], batch.request, timeout=30)
    scores, _, receipt = batch.consume(output)
    require(
        execution["image_id"] == expected["image_id"]
        and receipt["model_digest"] == report["model_sha256"]
    )
    reference = dict(features=features, scores=scores.tolist())
    golden = Golden.from_expected(
        {**reference, "model": report["model_sha256"], "bundle": report["subject_sha256"]}
    )
    issued = int(time.time())
    permit = dict(
        schema_version=1,
        purpose=KIND,
        campaign_id=campaign,
        environment="local-cpu",
        **expected,
        proposal_sha256=report["proposal_reference"],
        subject_sha256=report["subject_sha256"],
        model_sha256=report["model_sha256"],
        issued_at=issued,
        expires_at=min(issued + 600, verified["manifest"]["expires_at"]),
    )
    projection = decode(package["documents"]["asset_projection"])
    lineage = package["capsule"]["objects"][("lineage", projection["bindings"]["lineage_object"])]
    item = dict(
        proposal=package["envelope"],
        projection=projection,
        lineage_envelope=decode(lineage),
        permit=signing.sign(permit, KIND, safe_child(state, materials.KEY)),
        golden=reference,
    )
    return context, golden, sha(permit), item


def observe(engine, port):
    with engine.lock:
        engine.worker.ping()
        session = engine.worker.binding["session_id"]
        identifier = engine.worker.container
        actual = storage_bootstrap.inspect("container", identifier)
        serving_runtime.verify_container(actual, engine.worker.image, session)
        require(actual["State"]["Running"] is True and actual["Id"] == identifier)
        return dict(
            container=identifier,
            session=session,
            port=port,
            loaded=dict(
                permit_sha256=engine.loaded.permit_sha256,
                subject_sha256=engine.loaded.subject_sha256,
                model_sha256=engine.worker.binding["model_sha256"],
                image_id=actual["Image"],
                evaluation_policy_sha256=sha(engine.reader.context["policy"]),
            ),
        )


def probe(target, golden):
    wall_start = time.time_ns()
    sample = asyncio.run(rollout.sample(target, golden))
    return {**sample, "wall_start_ns": wall_start, "wall_end_ns": time.time_ns()}


def capture(root, state, owner, files, campaign):
    rollout.hosted()
    inputs = pinned(state)
    hexadecimal(campaign, 32)
    features = [[0.1] * len(FEATURES)]
    expected = {
        **owner["source"],
        "image_id": files["evidence/release-native.json"]["source"]["image_id"],
    }
    policy = read_json(root / "policies/local-cpu.json")
    client = safe_child(state, "storage-clients/serving")
    keys = files["trusted-keys.json"]
    public = inputs["qualification_root"]
    directory = safe_child(state, "evidence/M19-fleet-" + campaign)
    directory.mkdir(mode=0o700, exist_ok=False)
    releases = {
        k: prepare(state, client, r, policy, keys, campaign, expected, features)
        for k, r in inputs["reports"].items()
    }
    key = safe_child(state, materials.KEY)
    roster = dict(
        schema_version=1,
        environment="local-cpu",
        campaign_id=campaign,
        permits={k: v[2] for k, v in releases.items()},
    )
    roster_envelope = signing.sign(roster, FLEET_KIND, key)
    observed, active = {}, {}
    env = "local-cpu"
    with (
        disposable(root, state, campaign, "inventory-fleet-trust", 15446) as authority,
        ExitStack() as stack,
    ):
        trust_authority.install(authority, env, public)
        read = partial(trust_authority.read, authority / "storage-clients/serving", env, public)
        update = partial(_trust_update, authority, key, sha(roster), public, env, read)
        before, _ = update(1, [])
        for role, label in ROLES.items():
            context, golden, pin, item = releases[label]
            reader = CandidateReader(
                client,
                context=context,
                publisher_public=keys["approver"],
                proposal_reference=inputs["reports"][label]["proposal_reference"],
                permit_envelope=item["permit"],
                permit_public=public,
                expected_permit=pin,
                expected_campaign=campaign,
                fleet_envelope=roster_envelope,
                trust_lease=trust.Lease(
                    read, trusted_root=public, environment=env, minimum_version=1
                ),
            )
            engine = serving.Engine(reader)
            activated = time.monotonic_ns()
            target, access = stack.enter_context(
                rollout.endpoint(engine, directory / (role + ".jsonl"))
            )
            history = probe(target, golden) if role == "previous" else None
            if history is not None:
                require(history["status"] == 200 and golden.valid(history["reply"]))
            observed[role] = dict(activation_ns=activated, history=history)
            active[role] = (engine, target, access, golden)
        for role, (engine, target, _, golden) in active.items():
            running = observe(engine, target[0])
            observed[role].update(
                running,
                attestation=signing.sign(
                    dict(campaign=campaign, role=role, owner=owner, **running),
                    "inventory-running-worker",
                    key,
                ),
                healthy=probe(target, golden),
            )
            require(
                observed[role]["healthy"]["status"] == 200
                and golden.valid(observed[role]["healthy"]["reply"])
            )
        ancestor = next(
            a["sha256"]
            for a in releases["current"][3]["projection"]["graph"]["assets"]
            if a["kind"] == "dataset"
        )
        start = stamp()
        after, _ = update(2, [ancestor])
        committed = stamp()
        for role, (_, target, access, golden) in active.items():
            count = sum(access.admissions().values())
            sample = probe(target, golden)
            observed[role].update(
                after=sample, admissions=[count, sum(access.admissions().values())]
            )
        for role, (engine, target, _, golden) in active.items():
            sample = observed[role]["after"]
            if role == "independent":
                require(sample["status"] == 200 and golden.valid(sample["reply"]))
                require(
                    all(
                        value == observed[role][field]
                        for field, value in observe(engine, target[0]).items()
                    )
                    and engine.reader.trust.floor == 2
                )
                observed[role]["reader_result"] = "trust-version-2"
            else:
                require(sample["status"] == 503)
                try:
                    engine.reader.load()
                except Rejected as error:
                    require(str(error) == "trust_artifact_revoked")
                    observed[role]["reader_result"] = str(error)
                else:
                    raise Rejected("M19_revoked_fleet_load")
            lease = engine.reader.trust
            require(lease.floor == 2 and lease.observed_digest == sha(after))
            observed[role]["trust_readback"] = dict(
                version=lease.floor, document_sha256=lease.observed_digest
            )
        finished = stamp()
    for role, ob in observed.items():
        ob["journal"] = digest(bounded_read(directory / (role + ".jsonl")))
    require(inputs == pinned(state))
    return dict(
        campaign=campaign,
        owner=owner,
        sources={k: v[3] for k, v in releases.items()},
        roster=roster_envelope,
        deployments=observed,
        before=before,
        after=after,
        start=start,
        committed=committed,
        finished=finished,
    )
