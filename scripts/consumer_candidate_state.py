"""Prepare private consumer files inside the ordinary frozen transfer's live context."""

import secrets
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mlsecops import key_files, signing
from mlsecops.contracts import Rejected, atomic_write, bounded_read, canonical, decode, safe_child
from mlsecops.security_events import hexadecimal
from scripts import ci_candidate_transfer as bridge
from scripts import frozen_candidate_transfer as transfer


def _need(condition):
    if not condition:
        raise Rejected("consumer_candidate_state_rejected")


@contextmanager
def materialize(
    root,
    envelope,
    *,
    trust_key_path,
    key,
    freeze_pin,
    freeze,
    expected,
    run_owner,
    phase,
    expected_context,
    ciphertext_pin,
    manifest_pin,
):
    """Yield fresh consumer files, never SQL/cluster readiness or a reusable destination.

    Caller authority and the original local private key are mandatory. The existing
    materializer owns all temporary paths and their rollback, including on errors.
    Finish caller-owned infrastructure cleanup before leaving this context.
    """
    owner = bridge._authority(key, freeze_pin, freeze, expected, run_owner, phase)
    with bridge.materialize(
        root,
        envelope,
        key=key,
        **owner,
        phase=phase,
        expected_context=expected_context,
        ciphertext_pin=ciphertext_pin,
        manifest_pin=manifest_pin,
    ) as (state, summary):
        try:
            files, index, proposal = transfer.checked_files(
                lambda name, limit: bounded_read(safe_child(state, name), limit),
                **{k: owner[k] for k in ("freeze_pin", "freeze", "expected")},
            )
            paths = {Path(name) for name in files}
            paths |= {p for path in paths.copy() for p in path.parents if p != Path(".")}
            _need({p.relative_to(state) for p in state.rglob("*")} == paths)
            report = files[transfer.delivery.PROPOSAL]
            campaign = hexadecimal(decode(report)["campaign_id"], 32)
            _need(campaign == proposal["release_id"])
            # Read once through the ordinary bounded private-file reader. Validate
            # and copy those same bytes; never regenerate a key or public registry.
            private = key_files.read(trust_key_path)
            original = serialization.load_pem_private_key(private, password=None)
            _need(isinstance(original, Ed25519PrivateKey))
            _need(
                signing.encode64(original.public_key().public_bytes_raw())
                == decode(files["trusted-keys.json"])["trust"]
            )
            workspace = secrets.token_hex(16)
            directory = "release-proposals/" + campaign + "/"
            additions = {
                "workspace.json": canonical(
                    dict(product="trusted-mlsecops", schema_version=1, workspace_id=workspace)
                )
                + b"\n",
                "keys/trust.pem": private,
                directory + "report.json": report,
                directory + "policy-envelope.json": canonical(
                    decode(files[transfer.CAS + index["policy_reference"]])
                ),
            }
            for name, raw in additions.items():
                path = safe_child(state, name)
                atomic_write(path, raw)
                _need(bounded_read(path) == raw)
            # Preparation I/O must not consume the original minimum window or
            # change any frozen identity/signature before the consumer starts.
            values, current = bridge._fresh(root, state, owner)
            bridge._window(expected_context, values, current)
        except (*bridge.FAILURES, UnsupportedAlgorithm):
            raise Rejected("consumer_candidate_state_rejected") from None
        yield (
            state,
            summary | dict(workspace_id=workspace, campaign_id=campaign, storage_imported=False),
        )
