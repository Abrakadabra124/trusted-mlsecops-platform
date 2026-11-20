"""Terminal cleanup of one original campaign using independent public and private readers."""

from copy import deepcopy

from mlsecops.contracts import Rejected, canonical, digest, require_fields
from scripts import ci_campaign_control as control
from scripts import ci_campaign_guard as guard
from scripts import ci_private_assets as store
from scripts.ci_source_image_native import same

MAX_JOBS = 32
CONCLUSIONS = frozenset(
    {
        "success",
        "failure",
        "cancelled",
        "timed_out",
        "skipped",
        "neutral",
        "action_required",
        "stale",
        "startup_failure",
    }
)


def _need(ok):
    if not ok:
        raise Rejected("campaign_terminal_refused")


def _call(operation, *args, **kwargs):
    # External transports and private replay readers may put sensitive details in exceptions.
    try:
        return operation(*args, **kwargs)
    except Exception:
        raise Rejected("campaign_terminal_operation_unconfirmed") from None


def _job_names(values):
    _need(type(values) in (list, tuple) and 1 <= len(values) <= MAX_JOBS)
    for name in values:
        _need(
            type(name) is str
            and 1 <= len(name) <= 128
            and name.strip() == name
            and name.isascii()
            and name.isprintable()
        )
    names = frozenset(values)
    _need("producer" in names and len(names) == len(values))
    return names


def _completed(row):
    same(row, {"status": "completed"})
    conclusion = row.get("conclusion")
    _need(type(conclusion) is str and conclusion in CONCLUSIONS)
    return conclusion


def _public_observation(api, owner, sha, names):
    def get(suffix):
        return _call(api, "GET", "repos/" + guard.REPOSITORY + suffix)

    identity = dict(id=guard.REPOSITORY_ID, full_name=guard.REPOSITORY, private=False, fork=False)
    repo = get("")
    same(repo, identity | {"visibility": "public"})
    same(repo.get("owner"), {"login": "Abrakadabra124"})
    same(get("/commits/" + sha), {"sha": sha})
    path = "/actions/runs/" + str(owner["run_id"])
    attempt = owner["run_attempt"]
    exact_path = path + "/attempts/" + str(attempt)
    fields = dict(
        id=owner["run_id"],
        head_sha=sha,
        head_branch=guard.BRANCH,
        path=guard.WORKFLOW,
        event="workflow_dispatch",
    )
    latest = get(path)
    same(latest, fields)
    latest_attempt = store._number(latest.get("run_attempt"))
    _need(latest_attempt >= attempt)
    workflow = store._number(latest.get("workflow_id"))
    exact = get(exact_path)
    same(exact, fields | {"run_attempt": attempt, "workflow_id": workflow})
    for row in (latest, exact):
        for key in ("repository", "head_repository"):
            same(row.get(key), identity)
    outcome = _completed(exact)
    if latest_attempt == attempt:
        _need(_completed(latest) == outcome)

    page = get(exact_path + "/jobs?per_page=100")
    same(page, {"total_count": len(names)})
    jobs = page.get("jobs")
    _need(type(jobs) is list and len(jobs) == len(names))
    by_name = {}
    ids = set()
    for job in jobs:
        same(job, {"run_id": owner["run_id"], "run_attempt": attempt, "head_sha": sha})
        name = job.get("name")
        identifier = store._number(job.get("id"))
        _need(type(name) is str and name in names and name not in by_name and identifier not in ids)
        by_name[name] = {"id": identifier, "conclusion": _completed(job)}
        ids.add(identifier)
    return latest_attempt, dict(workflow_id=workflow, conclusion=outcome, jobs=by_name)


def _checkpoint(read_journal, owner, source, tip):
    result = _call(
        read_journal, run_owner=owner.copy(), source=source.copy(), expected_tip=tip.copy()
    )
    require_fields(result, ("complete", "checkpoint", "tip"))
    _need(result["complete"] is True)
    require_fields(result["tip"], tip)
    same(result["tip"], tip)
    checkpoint = result["checkpoint"]
    require_fields(checkpoint, ("issuer", "storage"))
    expected = owner | {"source_revision": source["source_revision"]}
    receipt = store._receipt(checkpoint["storage"], expected)
    assets = receipt["assets"]
    _need(assets.keys() == store.LIMITS.keys())
    issuer = checkpoint["issuer"]
    require_fields(issuer, ("public", "control_sha256", "storage_sha256"))
    _need(type(issuer["public"]) is str and len(issuer["public"]) == 44)
    four_packets = receipt | {"assets": {name: assets[name] for name in store.PACKETS}}
    _need(issuer["storage_sha256"] == digest(canonical(four_packets)))
    _need(issuer["control_sha256"] == assets[store.CONTROL]["sha256"])
    return {"issuer": issuer.copy(), "storage": receipt}


def cleanup(
    api,
    *,
    source_api,
    run_owner,
    source,
    expected_jobs,
    expected_tip,
    read_journal,
    replay_retained,
):
    """Remove the verified working release only after terminality and independent primary replay."""
    control.binding(run_owner, source)
    owner, source = run_owner.copy(), source.copy()
    names = _job_names(expected_jobs)
    require_fields(expected_tip, ("step", "asset_id", "sha256"))
    _need(store._number(expected_tip["step"]) == 8)
    store._number(expected_tip["asset_id"])
    store._hex(expected_tip["sha256"], 64)
    tip = expected_tip.copy()

    latest_attempt, terminal = _public_observation(
        source_api, owner, source["source_revision"], names
    )
    checkpoint = _checkpoint(read_journal, owner, source, tip)
    receipt = checkpoint["storage"]
    binding = dict(
        run_owner=owner, source=source, tip=tip, checkpoint=checkpoint, terminal=terminal
    )
    replay = _call(replay_retained, **deepcopy(binding))
    require_fields(replay, ("verified", "binding_sha256", "read_asset"))
    _need(replay["verified"] is True and replay["binding_sha256"] == digest(canonical(binding)))
    reader = replay["read_asset"]
    _need(callable(reader))
    receipt_sha256 = digest(canonical(receipt))

    def authorize(actual):
        _need(digest(canonical(actual)) == receipt_sha256)
        current_attempt, observed = _public_observation(
            source_api, owner, source["source_revision"], names
        )
        _need(current_attempt >= latest_attempt and observed == terminal)
        return dict(terminal=True, primary=True, receipt_sha256=receipt_sha256)

    def retained_copy(stem):
        return _call(reader, stem, receipt["assets"][stem]["size"])

    expected = owner | {"source_revision": source["source_revision"]}
    _call(store.cleanup, api, expected, receipt, authorize=authorize, retained_copy=retained_copy)
