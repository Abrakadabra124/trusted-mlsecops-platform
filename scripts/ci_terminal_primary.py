"""Independent historical primary replay for ci_campaign_terminal.cleanup."""

from mlsecops.contracts import Rejected, canonical, digest, require_fields
from scripts import ci_campaign_control as control
from scripts import ci_campaign_journal as journal
from scripts import ci_private_assets as assets
from scripts.ci_source_image_native import same

ROLES = ("shared", "serving")


def _need(ok):
    if not ok:
        raise Rejected("terminal_primary_unconfirmed")


def replayer(root, *, api, release, key, receiver_keys, read_asset):
    """Bind an operator-pinned primary release and independent retained asset reader.

    receiver_keys maps each role to {job_id, public} from that exact job's
    independent output. read_asset(stem, max_size) reads the retained originals.
    """
    from scripts import ci_primary_handoff as primary
    from scripts import ci_primary_store as store

    require_fields(release, ("repository_id", "release_id", "name", "target_commitish"))
    release = release.copy()
    require_fields(receiver_keys, ROLES)
    keys = {}
    for role in ROLES:
        row = receiver_keys[role]
        require_fields(row, ("job_id", "public"))
        keys[role] = (assets._number(row["job_id"]), journal._public(row["public"]))
    _need(callable(read_asset))

    def replay(*, run_owner, source, tip, checkpoint, terminal):
        binding = dict(
            run_owner=run_owner, source=source, tip=tip, checkpoint=checkpoint, terminal=terminal
        )
        binding_pin = digest(canonical(binding))
        jobs = terminal["jobs"]
        same(jobs.get("producer"), {"conclusion": "success"})
        job_ids = {assets._number(jobs["producer"]["id"])}
        public_keys = {journal._public(checkpoint["issuer"]["public"])}
        for role, (job_id, public) in keys.items():
            same(jobs.get(role), dict(id=job_id, conclusion="success"))
            _need(job_id not in job_ids and public not in public_keys)
            job_ids.add(job_id)
            public_keys.add(public)

        expected = run_owner | {"source_revision": source["source_revision"]}
        working = assets._receipt(checkpoint["storage"], expected)
        _need(release["release_id"] != working["release_id"])
        pins = working["assets"]
        require_fields(pins, assets.LIMITS)

        def retained(stem):
            pin = pins[stem]
            raw = read_asset(stem, pin["size"])
            assets._wire(stem, raw)
            _need(len(raw) == pin["size"] and digest(raw) == pin["sha256"])
            return raw

        context = dict(run_owner=run_owner, source=source)
        identity = control.retained_identity(
            retained(assets.CONTROL), checkpoint, key=key, **context
        )
        for stem in assets.PACKETS:
            retained(stem)
        for role, (_, public) in keys.items():
            packet = store.get_unverified(api, release=release, role=role, **context)
            result = primary.replay(
                root,
                packet,
                role=role,
                key=key,
                trusted_public=public,
                owner=identity["owner"],
                origin=identity["origin"],
                **context,
            )
            del packet
            same(result, {"release_ready": False})
            if role == "serving":
                same(result["receipt"]["reports"], identity["reports"])
        return dict(verified=True, binding_sha256=binding_pin, read_asset=read_asset)

    return replay
