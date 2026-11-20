# Original validation import into owned consumer SQL

This T21 component joins the existing private validation companion to the newly
owned consumer SQL. It does not provision infrastructure, issue a proposal,
extend expiry, sign reports, train, promote or authorize a release. The caller
keeps the original candidate materialization context open and owns cleanup.

## Contract and local implementation plan

1. Authenticate the externally pinned validation envelope/context with
   `ci_validation_transfer.materialize`, using the original freeze, candidate,
   source, image, run owner and phase. Reuse its signed split-manifest checks.
2. Reuse `consumer_candidate_storage._target` for workspace, storage marker,
   running SQL ownership and curator binding. Independently bind publisher
   user/host/hostaddr/port, CA, certificate and key to that same target PKI.
3. Query only a bounded SHA inventory of `ml.validation`. Reject foreign keys
   without fetching their payloads. An existing expected key must contain the
   exact original bytes. Write only through the new consumer curator client;
   verify the digest and exact publisher readback.
4. Keep bounded pre/post observations private. Check target and original
   source/transport windows after all receipt I/O and companion cleanup. Only
   the successful API return establishes import success. Neither observation
   file is a completion receipt, including after a failed final check.
5. Qualify negative material, owner, server/client, readback, expiry and partial
   failure cases first. Use real signed fixtures, AES and ordinary storage
   functions with simulated Docker/psycopg boundaries. Measure the new module's
   statements and branches separately, each at least 95%; no local infrastructure.

## Caller interface

The caller supplies `root`, its existing materialized `state`, and the original
validation `envelope`, plus keyword arguments `key`, `freeze_pin`, `freeze`,
`expected`, `run_owner`, `phase`, `expected_context`, `ciphertext_pin`,
`expected_workspace_id`, `storage_pin` to
`scripts.consumer_validation_storage.import_validation`.

The candidate must already have passed the existing candidate materializer and
package import. The consumer's original public-key registry and proposal remain
unchanged. `phase` is M13, M14 or M15; the companion context uses `validation-`
plus that phase. All pins/context arrive independently of the untrusted envelope.
Use the same externally pinned consumer workspace and `storage.json` as package
import, with newly provisioned curator and publisher clients. Never supply source
SQL credentials or recreate original approver/evaluator private keys.

Inside that existing caller context:

```python
from scripts.consumer_validation_storage import import_validation

result = import_validation(
    root,
    state,
    sealed_validation["envelope"],
    key=transfer_key,
    **owner,  # Independently trusted freeze_pin/freeze/expected/run_owner.
    phase=phase,
    expected_context=sealed_validation["context"],
    ciphertext_pin=sealed_validation["ciphertext_sha256"],
    expected_workspace_id=prepared["workspace_id"],
    storage_pin=consumer_storage_pin,
)
```

The envelope and its expected metadata must arrive through independently trusted
caller inputs. This example does not authorize extracting expected pins from an
untrusted artifact. No caller-selected destination or SQL namespace is accepted.

The return contains `status=pass`, `validation_sha256`, `workspace_id`,
`storage_pin`, `pre_receipt`/`post_receipt` and `pre_sha256`/`post_sha256`, plus
`handling=private` and `release_ready=false`. Receipt paths are relative to state:
`evidence/consumer-validation/<owned-random-id>/pre.json` and `post.json`.
Each file is bounded to 64 KiB and contains metadata, not validation rows or keys.
Both use `status=observation, accepted=false`, even on successful import. They
describe earlier observations and cannot replace a successful API return.

Original proposal/policy and transport deadlines remain mandatory. The existing
conservative actual-time checks require at least 600 seconds of original inner
window. Transport expiry remains the minimum of original proposal expiry and
issued time plus 1800 seconds. There is no production clock override.

## Failure and recovery

On rejection, do not infer success from a SQL command or a leftover receipt.
Only the original validation SHA can be inserted by this API; that object may
remain after a readback, receipt or postflight failure. An exact-byte retry within the original
window is permitted after correcting the cause. Foreign rows, clients, owners or
expired material require refusal; this API never deletes, updates or clears data.
The caller must perform its existing owned infrastructure cleanup before leaving
the candidate context. This importer removes only companion temporary files.

Envelopes, validation bytes, owner metadata, pins, return values and receipts are
private. Keep them inside owned runtime storage; never publish them, raw logs,
keys or credentials through artifacts, logs or workflow outputs. This component
does not configure GitHub or implement a hosted transfer.

## Qualification

Use the parent's pinned Python 3.12.15 environment from this isolated worktree:

```powershell
$python = '../t20-recovery/.venv/Scripts/python.exe'
& $python -B -W error -m unittest scripts.consumer_validation_storage_qualification
& $python -B -W error -m coverage run --branch --data-file=.runtime/consumer-validation.coverage --source=scripts.consumer_validation_storage -m unittest scripts.consumer_validation_storage_qualification
& $python -B -m coverage report --data-file=.runtime/consumer-validation.coverage -m
& $python -B -m ruff check scripts/consumer_validation_storage.py scripts/consumer_validation_storage_qualification.py
& $python -B -m ruff format --check scripts/consumer_validation_storage.py scripts/consumer_validation_storage_qualification.py
& $python -B scripts/check_docs.py
```

Final focused qualification on Python 3.12.15: **26 tests passed in 119.293s**,
with **0 failures, 0 errors and 0 skips**. Separate new-module coverage measured
in memory with branch tracking and no configuration/exclusions: **72/72
statements and 4/4 branches, 100% each**. Both independent fractions exceed 95%;
no aggregate percentage substitutes for either check. Ruff check and format
check passed. The two unchanged candidate-import/companion baseline tests passed
separately in 11.662s.

The first negative run was RED because the new importer was absent. A later
fixture correction made the foreign source revision actually differ from the
existing signed fixture; production validation was not relaxed. Final cases
cover all three phases, wrong material/owner/server/client, foreign bounded
inventory, exact-byte retry, bad publisher readback, partial failure, receipt
failure, final target/source changes and expiry after receipt or context cleanup.
The exact 600-second boundary passes; a 0.01-second shortfall is rejected.

Boundary fixtures cannot prove a live PostgreSQL TLS connection, Docker/Kubernetes behavior or
native M13/M14/M15 acceptance. The current M11/M12 job is a separate parent-owned
run; this component makes no claim about its result or full same-candidate gates.
