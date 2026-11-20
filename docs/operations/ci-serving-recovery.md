# Private M13/M14/M15 consumer lifecycle

T21 resource lifecycle only. This API does not run gates, import a candidate,
renew a proposal/window, issue trust keys, configure GitHub or publish evidence.
The caller keeps the original candidate/phase freshness checks and exclusively
owns one hosted runner. It captures dependency stdout/stderr privately.

## Contract and implementation plan

- Reuse the unchanged `ci_consumer_recovery.Recovery` for all Docker identity,
  label, exclusive-volume and absence checks. No name-only deletion or adoption.
- Exclusively create `producer/ci-serving-recovery`, with one SQL-only witness
  and three cluster-only witnesses, named `SQL`, `M13`, `M14`, `M15`.
  SQL workspace bytes exactly copy producer; cluster workspace bytes exactly
  copy the new consumer. Run owner and exact source/image bind every witness.
- Arm each resource before bootstrap and observe in `finally`, including partial
  failure. SQL PKI must already exist and validate; the lifecycle creates no keys.
  Observe clusters through the witness directory: Docker observation is global,
  and this deliberately omits the optional private kubeconfig copy.
- Transition through fixed M13 -> M14 -> M15 only. Reuse the original campaign
  path/pin/before/after checks and marker archival with optional trusted delete
  and bootstrap callbacks. Archive markers within the disposable consumer state.
  Retire only the prior cluster, keep the same pinned SQL running, and arm the
  next cluster only after verified absence.
- Durable in-progress state blocks retries after ambiguous failure. Cleanup
  attempts M15, M14, M13, then SQL even if another owned resource failed.
  Missing/corrupt witnesses are failure, never evidence of absence. A separate
  loaded lifecycle can clean owned resources after consumer files are gone.
  Creating or transitioning resources requires every fixed witness to remain
  present and bound, even a witness for a future phase.
- Test negative ownership, replacement IDs, shared volumes, order, partial
  bootstrap, failed observation, cleanup and live-SQL transitions first, plus
  the unchanged legacy transition. Require >=95% statements and branches for
  each changed security module, using only boundary fixtures locally.

## Intended caller API

`Lifecycle.begin(producer, state, run_owner=..., source=...)` creates the durable
owner state before any consumer SQL or cluster exists. `Lifecycle.load(producer,
run_owner=..., source=...)` requires the same trusted external bindings.

The hosted caller must explicitly call `storage_pki.initialize(state)` from
`mlsecops.storage_pki` for the newly owned consumer before `begin/bootstrap_sql`.
`consumer_candidate_state.materialize` does not create `storage-pki`.
Initialization creates the consumer SQL TLS (Transport Layer Security) CA,
server certificate and role client certificates under `state/storage-pki`;
an existing directory is validated, not rotated. This consumer transport PKI
is separate from the original release signing trust root supplied by the caller.
Keep the original pinned trust keys and frozen package bytes unchanged; do not
call `bootstrap.initialize` to provision or regenerate frozen/signing trust.
Although existing `Recovery.arm_sql` also invokes `storage_pki.initialize`, this
lifecycle intentionally requires `storage_pki.validate(state)` to pass first.

`bootstrap_sql(state)` arms and observes existing SQL bootstrap and returns the
new source SQL marker pin. `start(state, source_pin)` starts M13. Call
`transition(state, "M13", source_pin)` then `transition(state, "M14", source_pin)`
only after each gate completed; returned packets retain the original campaign
transition schema. `cleanup()` returns fixed M15/M14/M13/SQL booleans. It never
claims gate success. Every cleanup attempt closes the lifecycle for further work;
cleanup itself may be retried against unchanged witnesses.

```python
from mlsecops import storage_pki
from scripts.ci_serving_recovery import Lifecycle

# Hosted caller, inside the existing private-output boundary:
storage_pki.initialize(state)  # New consumer SQL TLS only; no release trust changes.
life = Lifecycle.begin(producer, state, run_owner=run_owner, source=source)
source_pin = life.bootstrap_sql(state)
life.start(state, source_pin)
# Run/retain M13 with the original candidate and existing freshness checks.
step_13_14 = life.transition(state, "M13", source_pin)
# Run/retain M14 under its distinct permit and original expiry.
step_14_15 = life.transition(state, "M14", source_pin)
# Run/retain M15 before materialization exits; keep both transition packets.

# An outer finally, including when any earlier operation raises:
cleanup = Lifecycle.load(producer, run_owner=run_owner, source=source).cleanup()
# Require all(cleanup.values()) separately from gate/replay success.
```

This is an API sequence for the future hosted driver, not a local execution
command or a complete try/finally implementation. The driver must place cleanup
outside the consumer materialization context and cover initialization failures.
`run_owner` has exactly `repository`, `run_id`, `run_attempt`, `producer_job`;
`source` has exactly `source_revision`, `source_fingerprint`, `image_id`.
Both come from the trusted caller. The original source SQL pin returned by
`bootstrap_sql` must stay unchanged through both transitions.

All witnesses, pins and observations remain private. No copied trust key, SQL
credential or kubeconfig is needed in durable witnesses. The caller must retain
gate evidence privately before the consumer materialization context exits.
Never reset a witness or remove rows to retry; ambiguous attempts require cleanup
and refusal, not refreshed IDs. Existing original proposal/policy/transport
deadlines and distinct qualification permits remain mandatory outside this helper.

On partial bootstrap, observation runs in `finally`; a failed observation leaves
the resource unconfirmed and cleanup cannot adopt it. On archive or transition
failure, retain the durable witnesses and run cleanup, never replay the transition
or rewrite ownership. Missing/foreign child records yield `False` for that resource
while independently owned resources still get cleanup attempts. A missing or
invalid top-level owner manifest refuses all cleanup. Escalate such incomplete
cleanup to the runner owner; do not fall back to cluster-name deletion or prune.

Cluster cleanup deletes only recorded Docker IDs and exclusive recorded volumes,
without a Kubernetes API. SQL cleanup retains the existing Recovery contract:
verify the recorded container identity and that it has stopped, not removal of
the SQL container, volume or network. An exclusively owned disposable hosted
runner remains required. Concurrent users of global kind/trust/SQL state remain
unsupported. Rollback means removing this caller integration; it does not change
the legacy `serving_campaign.transition` behavior when callbacks are omitted.

## Qualification and limits

Use `../t20-recovery/.venv/Scripts/python.exe` (pinned Python 3.12.15), the new
qualification plus `scripts.serving_campaign_qualification` and existing
retention replay/primary fixture tests:

```powershell
& '../t20-recovery/.venv/Scripts/python.exe' -B -m unittest scripts.ci_serving_recovery_qualification scripts.serving_campaign_qualification scripts.serving_retention_qualification.RetentionTests.test_trio_replay_requires_ordered_windows_and_distinct_phase_permits scripts.m18_serving_retention_qualification.ServingPrimaryTests.test_capture_preserves_all_original_bytes_and_native_admissions
```

Verified with pinned Python 3.12.15: 31 tests passed (20 lifecycle, 9 campaign,
2 existing retention fixtures). Branch-enabled coverage, without exclusions,
measured each changed production module separately:

| Module | Statements | Branches |
| --- | --- | --- |
| `scripts/ci_serving_recovery.py` | 202/202 (100%) | 14/14 (100%) |
| `scripts/serving_campaign.py` | 93/93 (100%) | 12/12 (100%) |

The new tests use real Recovery records and identity/volume checks with a strict
in-memory Docker boundary. Existing signed retention fixtures cover campaign
replay/privacy. Negative tests were observed failing before implementation,
including missing-witness independence and refusal before new resource creation.
Ruff and docs checks are mandatory. No Docker/SQL/Kubernetes process, network,
native CI or external model ran locally. Boundary tests do not prove hosted
M13/M14/M15, M11/M12 or final M18 acceptance.
