"""Keep post-rotation trust Jobs separate within one explicit owner transfer."""

from mlsecops.contracts import canonical
from scripts import kube_owned_probe as ownership
from scripts import kube_serving_native as probes
from scripts.kube_serving_faults import Coordinator
from scripts.kube_trust_native import hosted


def qualify(state, profile, config, rollback_config, expected, rotation, policy, key, model):
    hosted()

    def observe():
        old = probes.invoke(
            state,
            profile,
            config,
            {**expected, "ready": False, "reader_refusal": "trust_authority_missing_or_foreign"},
        )
        for operator_config in (config, rollback_config):
            operator_config.update(
                trust_root=rotation["next_public"],
                minimum_trust_version=rotation["receipt"]["version"],
            )
        serving = probes.invoke(state, profile, config, expected)
        lifecycle = {}
        for fault in ("outage", "blackhole", "policy-change", "revocation"):
            print(canonical({"stage": "live-trust-" + fault}).decode(), flush=True)
            # The Job cleans itself before leaving this context. Reversible
            # faults restore here, before the outer owner transfer resumes.
            with Coordinator(state, fault, policy, key, model) as coordinator:
                lifecycle[fault] = probes.invoke(
                    state,
                    profile,
                    config,
                    {**expected, "fault": fault},
                    coordinator=coordinator,
                )
                print(
                    canonical({"completed_fault": fault, "result": lifecycle[fault]}).decode(),
                    flush=True,
                )
        print(canonical({"stage": "controlled-after-revocation"}).decode(), flush=True)
        revoked = probes.invoke(state, profile, config, {**expected, "ready": False})
        return dict(old_config_refusal=old, serving=serving, live_trust=lifecycle, revoked=revoked)

    return ownership.run(state, profile, observe)
