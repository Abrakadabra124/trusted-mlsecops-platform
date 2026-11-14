"""Owned hosted T19 traffic and recovery capture, followed by offline verification."""

import asyncio
import os
import secrets
import sys
import time
import uuid
from contextlib import ExitStack, contextmanager
from datetime import datetime
from pathlib import Path

from mlsecops import (
    canary_campaign,
    canary_native_evidence,
    load_measurement,
    serving_audit,
    serving_http,
)
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.datasets import FEATURES
from mlsecops.inventory import command, source_fingerprint
from mlsecops.load_probe import listen
from mlsecops.security_events import hexadecimal
from mlsecops.serving_access import Access
from mlsecops.storage_bootstrap import inspect, validate
from mlsecops.trust_acceptance import materials
from scripts.kube_load_native import failure_site
from scripts.kube_trust_native import hosted

IMAGE = "trusted-mlsecops:dev"
PACKET = "evidence/canary-native-private.json"
ROLLBACK_PACKET = "evidence/canary-rollback-private.json"


def require(condition):
    if not condition:
        raise Rejected("canary_rollout_native")


def capture_inputs(root, proposal_variable="T19_PROPOSAL_SHA256"):
    require(not command(["git", "-C", str(root), "status", "--porcelain"]))
    return dict(
        source=dict(
            source_revision=command(["git", "-C", str(root), "rev-parse", "HEAD"]),
            source_fingerprint=source_fingerprint(root),
        ),
        methods=digest(canonical(materials(root))),
        runner={k: os.environ[k] for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")},
        proposal_pin=hexadecimal(os.environ[proposal_variable]),
    )


@contextmanager
def endpoint(engine, path):
    token = secrets.token_hex(32)
    access = Access(
        dict(
            schema_version=1,
            clients=[
                dict(
                    token=token,
                    principal_id=secrets.token_hex(16),
                    requests_per_second=1000,
                    burst=1000,
                    max_in_flight=4,
                )
            ],
        )
    )
    journal = serving_audit.Journal(path)
    with ExitStack() as stack:
        stack.callback(journal.close, timeout=5)
        journal.start()
        port = stack.enter_context(
            listen(
                serving_http.create_app(
                    engine, clients=access, audit=journal, startup_diagnostics=True
                )
            )
        )
        require(engine.startup_failure is None)
        yield (port, token), access


async def sample(target, golden):
    start = time.monotonic_ns()
    status, reply = await load_measurement.request(*target, golden.body)
    return dict(start_ns=start, end_ns=time.monotonic_ns(), status=status, reply=reply)


async def recover(targets, goldens, revoke, candidate_access):
    start = time.monotonic_ns()
    proof = await asyncio.to_thread(revoke)
    committed = time.monotonic_ns()
    samples = []
    for _ in range(200):
        before = sum(candidate_access.admissions().values())
        seen = await sample(targets["candidate"], goldens["candidate"])
        after = sum(candidate_access.admissions().values())
        samples.append(seen)
        if seen["status"] == 503:
            break
        require(
            seen["status"] == 200
            and goldens["candidate"].valid(seen["reply"])
            and seen["end_ns"] - start < 120_000_000_000
        )
        await asyncio.sleep(0.5)
    else:
        raise Rejected("canary_candidate_revocation_unobserved")
    restored = await sample(targets["stable"], goldens["stable"])
    require(restored["status"] == 200 and goldens["stable"].valid(restored["reply"]))
    return dict(
        start_ns=start,
        committed_ns=committed,
        trust=proof,
        candidate=samples,
        restored=restored,
        observed_at_ns=time.time_ns(),
        denial_admissions=dict(before=before, after=after),
    )


def traffic(root, state, *, inventory=False):
    from scripts.canary_candidate_native import actual_candidate
    from scripts.canary_stable_native import stable_release

    proposal_variable = "M19_PROPOSAL_SHA256" if inventory else "T19_PROPOSAL_SHA256"
    inputs = capture_inputs(root, proposal_variable)
    campaign, started = uuid.uuid4().hex, now()
    directory = safe_child(state, "evidence/canary-native-" + campaign)
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    features = [[0.1] * len(FEATURES)]
    print(canonical(dict(stage="stable-and-candidate-activation")).decode(), flush=True)
    with ExitStack() as stack:
        a, stable, a_binding = stack.enter_context(
            stable_release(root, state, IMAGE, campaign, features)
        )
        b, candidate, b_binding, revoke = stack.enter_context(
            actual_candidate(
                root,
                state,
                IMAGE,
                campaign,
                inputs["proposal_pin"],
                features,
                **({"revoke_dataset": True} if inventory else {}),
            )
        )
        goldens = dict(stable=stable, candidate=candidate)
        endpoints = {
            role: stack.enter_context(endpoint(engine, directory / (role + ".jsonl")))
            for role, engine in (("stable", a), ("candidate", b))
        }
        targets = {role: endpoint[0] for role, endpoint in endpoints.items()}
        if inventory:
            with b.lock:
                observation = dict(
                    permit_sha256=b.loaded.permit_sha256,
                    subject_sha256=b.loaded.subject_sha256,
                    model_sha256=b.worker.binding["model_sha256"],
                    image_id=b.worker.image,
                    evaluation_policy_sha256=digest(canonical(b.reader.context["policy"])),
                )
        print(canonical(dict(stage="live-canary-traffic")).decode(), flush=True)
        measured = asyncio.run(
            canary_campaign.run(
                state, **targets, stable_golden=stable, candidate_golden=candidate, requests=200
            )
        )
        if measured["decision"] != "complete":
            print(
                canonical(dict(stage="canary-held", stages=measured["stages"])).decode(), flush=True
            )
            raise Rejected("canary_traffic_held")
        fault = asyncio.run(recover(targets, goldens, revoke, endpoints["candidate"][1]))
        if inventory:
            try:
                b.reader.load()
            except Rejected as error:
                require(str(error) == "trust_artifact_revoked")
                reader_refusal = str(error)
            else:
                raise Rejected("M19_revoked_dataset_admitted")
    require(inputs == capture_inputs(root, proposal_variable))
    record = dict(
        schema_version=1,
        campaign=campaign,
        started_at=started,
        finished_at=now(),
        source=inputs["source"],
        methods=inputs["methods"],
        runner=inputs["runner"],
        proposal_sha256=inputs["proposal_pin"],
        stable=a_binding,
        candidate=b_binding,
        goldens={k: dict(body=v.body.decode(), score=v.score) for k, v in goldens.items()},
        traffic=measured,
        recovery=fault,
        journals={k: digest(bounded_read(directory / (k + ".jsonl"))) for k in goldens},
    )
    if inventory:
        return dict(
            traffic=record,
            observation=observation,
            reader_refusal=reader_refusal,
            inventory_source_sha256=digest(bounded_read(directory / "inventory-source.json")),
        )
    return record


def owned_traffic(root, state):
    inputs = capture_inputs(root)
    pin = hexadecimal(os.environ["T19_PRIMARY_SHA256"])
    packet = decode(canary_native_evidence.read_pinned(safe_child(state, PACKET), pin))
    summary = canary_native_evidence.replay(state, packet, **inputs)
    return inputs, pin, packet, summary


def probe_features(packet):
    body = decode(packet["goldens"]["candidate"]["body"].encode(), 65536)
    return [[row[name] for name in FEATURES] for row in body["instances"]]


def controlled_rollback(root, state):
    from scripts.canary_rollback_native import drill

    inputs, pin, traffic_packet, _ = owned_traffic(root, state)
    started = now()
    drill_packet = drill(
        root, state, IMAGE, traffic_packet["campaign"], probe_features(traffic_packet)
    )
    require(inputs == capture_inputs(root))
    return dict(
        schema_version=1,
        owner=inputs,
        traffic_sha256=pin,
        started_at=started,
        finished_at=now(),
        drill=drill_packet,
    )


def measured(root, state):
    """Replay both independently pinned packets after all owned stores have stopped."""
    from scripts.canary_rollback_native import replay

    hosted()
    marker = validate(state)
    require(inspect("container", marker["container_id"])["State"]["Running"] is False)
    inputs, pin, packet, summary = owned_traffic(root, state)
    record = decode(
        canary_native_evidence.read_pinned(
            safe_child(state, ROLLBACK_PACKET), os.environ["T19_ROLLBACK_SHA256"]
        )
    )
    require_fields(
        record, ("schema_version", "owner", "traffic_sha256", "started_at", "finished_at", "drill")
    )
    require(type(record["schema_version"]) is int and record["schema_version"] == 1)
    require(record["owner"] == inputs and record["traffic_sha256"] == pin)
    drill = record["drill"]
    require(
        drill["campaign"] == packet["campaign"]
        and drill["image"] == packet["candidate"]["image_id"]
    )
    require(drill["features"] == probe_features(packet))
    stamps = [
        datetime.fromisoformat(s)
        for s in (packet["finished_at"], record["started_at"], record["finished_at"], now())
    ]
    require(all(s.utcoffset() is not None for s in stamps) and stamps == sorted(stamps))
    return packet, summary, replay(drill)


def publish_pin(state, name, record):
    path = safe_child(state, name)
    write_json(path, record)
    pin = digest(canonical(record) + b"\n")
    canary_native_evidence.read_pinned(path, pin)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        print("sha256=" + pin, file=output)
    return pin


def main():
    stage = "startup"
    try:
        hosted()
        root = Path(__file__).resolve().parents[1]
        state = root / ".runtime"
        if sys.argv[1:] == ["replay"]:
            stage = "post-cleanup-replay"
            _, result, durable = measured(root, state)
            print(
                canonical(
                    dict(
                        status="pass",
                        scope="native-canary-traffic-and-controlled-whole-bundle-recovery",
                        release_ready=False,
                        durable=durable,
                        **result,
                    )
                ).decode(),
                flush=True,
            )
        elif sys.argv[1:] in (["capture"], ["rollback"]):
            stage = sys.argv[1]
            capture, name = (
                (traffic, PACKET) if stage == "capture" else (controlled_rollback, ROLLBACK_PACKET)
            )
            pin = publish_pin(state, name, capture(root, state))
            print(canonical(dict(stage=stage, primary_sha256=pin)).decode(), flush=True)
        else:
            raise Rejected("canary_native_arguments")
        return 0
    except Exception as error:
        from scripts.kube_security_outage_native import failure_report

        print(
            canonical(
                dict(
                    stage=stage,
                    status="fail",
                    scope="native-canary",
                    site=failure_site(error),
                    callers=failure_report(error)["callers"],
                )
            ).decode(),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
