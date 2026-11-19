# Original candidate consumer file preparation

## Contract recorded before implementation

`scripts.consumer_candidate_state.materialize(root, envelope, *, trust_key_path,
key, freeze_pin, freeze, expected, run_owner, phase, expected_context,
ciphertext_pin, manifest_pin)` is a context manager yielding `(state, summary)`.
All transfer arguments retain the existing `ci_candidate_transfer.materialize`
meaning and must come from the caller's independent authority. The adapter enters
that existing context itself; it never accepts an existing workspace destination.
`trust_key_path` names the caller's original private Ed25519 trust key, supplied
locally outside the archive. Its public bytes must exactly match the pinned
`trusted-keys.json` trust entry. No keys or signatures are generated.

Ownership and rollback: only the fresh materializer-owned directory is writable.
The original closed file inventory is rechecked before adding anything. Existing
workspace markers, consumer directories, credentials and arbitrary extra entries
are rejected. Four new files are prepared and read back:

- `workspace.json`, with the ordinary product/schema and a fresh 32-hex identifier;
- `keys/trust.pem`, containing the exact caller-supplied original private bytes;
- `release-proposals/{campaign}/report.json`, byte-identical to the frozen report;
- `release-proposals/{campaign}/policy-envelope.json`, canonical original envelope.

The report campaign must equal the signed release bundle's `release_id`. The
frozen closure and current original validity windows are rechecked before yielding.
There is no expiry extension or new proposal. A context instance is single-use;
another invocation creates a different workspace. On preparation failure, normal
exit or consumer exception, the existing materializer removes its owned state and
staging. Consumer exceptions propagate unchanged when cleanup succeeds. Caller
key/source files are never modified. Cleanup errors remain visible through the
existing context manager, including its exception chain if the consumer also fails.
The caller must finish native resource cleanup **inside** the context, before its
local state disappears. This helper does not own or clean up infrastructure.

## Consumer inspection and SQL boundary

`m12_pinned_native.owner` reads the frozen proposal and campaign report with the
same external report pin, then requires a live cluster owner and source identity.
`shared_serving_native.owner` additionally binds the M11 demo pin.
`trust_delivery.freeze` / `serving_output_native.verified_materials` subsequently
load the signed bundle through a serving SQL client. File preparation alone cannot
complete these native paths.

No SQL import API is exposed in this bounded change. `storage.connection_materials`
validates role, endpoint and TLS certificate pins, but its closed `connection.json`
has no workspace/cluster identity proving that the endpoint belongs to a **new**
consumer. A fresh-looking client directory can still name an old server. Safe
import therefore needs caller-supplied, independently verified runtime ownership
metadata and newly provisioned clients, which this adapter neither has nor creates.

The existing schema permits promoter INSERT/SELECT on `releases`; the ordinary
`release_bundle.publish` stores the complete capsule/documents there and checks
digest/readback through `release_bundle.load`/`read`. Curator can write
`manifests`/`lineage`/data splits, but neither curator nor promoter can write the
original `candidates` or `evaluations` namespaces. No namespace impersonation or
admin bypass is permitted. A future importer must bind the new target first and
use these ordinary verifiers, not claim that a closure copy recreated runtime
metadata. `summary.storage_imported` remains false here.

The prepared directory is private and now contains a signing key. Do not archive,
publish or transport it. Transport stays unchanged; no SQL credentials, kubeconfig,
private review packets, registry regeneration, bootstrap or hosted dispatch occur.
Windows retains the existing contracts/key-files limitations: trusted local parent
directories are required; POSIX mode checks do not constitute Windows ACL proof.

## Qualification plan

Use real signed fixtures and the existing encrypted transfer round trip offline.
Exercise wrong/malformed root keys, corrupt closure, mismatched owner/freeze/source,
expired original windows, foreign/reused workspace entries, write/readback failures
and consumer exceptions. Assert original bytes, normal consumer owner bindings and
owned-directory removal, not only mock calls. Measure this module separately with
branch coverage; require at least 95% lines and branches. Native SQL/Kubernetes and
full M11/M12 readiness are not established by this qualification.

## Recorded offline verification

Run from the isolated worktree using the existing pinned Python 3.12.15 interpreter
at `../t20-recovery/.venv/Scripts/python.exe` (PowerShell):

```powershell
$python = '../t20-recovery/.venv/Scripts/python.exe'
& $python -B -Werror -m coverage run --branch --data-file=.runtime/consumer-state.coverage --source=scripts.consumer_candidate_state -m unittest scripts.consumer_candidate_state_qualification scripts.ci_candidate_transfer_qualification
& $python -B -m coverage report --data-file=.runtime/consumer-state.coverage -m
& $python -B -m ruff check scripts/consumer_candidate_state.py scripts/consumer_candidate_state_qualification.py
& $python -B scripts/check_docs.py
```

Observed on the isolated branch based on `25cf982`: 35 tests passed in 103.473s
(12 consumer preparation tests, 23 existing transfer tests). The adapter covered
42/42 statements and 4/4 branches, 100% each, with no exclusions. The initial
test-first run failed because the adapter did not yet exist. Tests forbid SQL,
subprocess execution, bootstrap and signing/key generation in the adapter path;
real signed fixtures and the ordinary encrypted transfer run offline. Consumer
owner tests replace only native cluster/source observations with controlled
fixtures; they do not prove a live cluster or SQL import. A cleanup exit failure
is injected after real temporary-directory cleanup so even a red test owns no
leaked child state.

For a refused preparation, check caller pins, original key identity and remaining
original validity privately. Do not repair a refusal by resealing the proposal,
extending its window or modifying registry bytes. Retry only a corrected caller
input in a new context while original validity still holds. If runtime readiness
is required, hand off to the parent workflow owner for the missing independently
bound target metadata and native validation; this adapter cannot supply it.
