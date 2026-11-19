# Original candidate import into new consumer SQL

## API contract recorded before implementation

`scripts.consumer_candidate_storage.import_candidate(root, state, *, freeze_pin,
freeze, expected, run_owner, expected_workspace_id, storage_pin)` returns a private
receipt. Call it inside the live `consumer_candidate_state.materialize` context,
after the caller completes a **new** `storage_bootstrap.bootstrap(state, port)`.
The caller independently pins that new `storage.json` and supplies the adapter's
workspace ID. Port 15440 is supported; no producer port or client directory is
accepted as authority. Keep that context alive through all native cleanup.

Preflight before SQL writes:

1. Snapshot and validate explicit frozen owner/pins, original signatures and
   current original windows (including the unchanged 600-second minimum).
2. Reconstruct only the exact signed release/capsule/documents from frozen CAS;
   check original campaign report, canonical policy and trust key identity.
3. Pin `storage.json`, check expected workspace and real PKI validation, call
   `storage_bootstrap.validate` at the actual Docker boundary. Require the owned
   container running, the actual loopback port and attached network ID.
4. Correlate fixed `storage-clients/{promoter,serving,curator}` configs, CA/client
   certificates and private-key bytes with this state PKI and pinned port. Store
   only material hashes, never credentials. Reject copied producer clients.
5. Read bounded `releases` inventory as promoter. Require it to be a byte-exact
   subset of the validated package closure. Save a private preflight receipt.

Import uses ordinary `release_bundle.publish` as promoter, then ordinary serving
`load`/`read` plus exact original reference/package checks. Only `releases` receives
INSERTs. Postflight repeats frozen/window, native ownership, PKI/client and bounded
inventory checks; owner/material snapshots must stay identical and a successful
inventory must exactly equal the package closure. Save a separate post receipt,
read it back and hash it, then recheck the stable native target and actual frozen
freshness **after all receipt I/O**, immediately before returning its pin.
No bootstrap, migrations, schema changes,
new signatures/proposals, arbitrary clients, table deletion or rollback occur.
Optional validation companion import is not part of this module.

## Idempotency, failure and ownership assumptions

`storage.put` uses `INSERT ... ON CONFLICT DO NOTHING`, then checks stored payload
equals supplied bytes. `storage.get` checks size and SHA-256. The schema grants
promoter INSERT/SELECT on releases; serving only reads it. A bounded extra SELECT
lists at most expected-count + 1 primary keys so foreign rows are rejected without
reading arbitrary payloads. Existing rows must match exact closure bytes. This
permits an empty store, same-byte repeat or interrupted subset. Identical bytes
alone do not prove which prior attempt wrote them. Nothing assumes a fresh marker
means an empty database. Other namespaces are neither inspected nor modified.

The caller must serialize this import against other writers/admin changes and
protect local parent directories. Observations and separate ordinary SQL
connections are not a global transaction or a defense against a malicious Docker
daemon/host administrator. Before/after checks detect observed changes; they do
not promise atomic exclusion of concurrent host mutations. The external storage
pin must come after the caller's new successful bootstrap, not from an archive.

Receipts live under a new owned `evidence/consumer-storage/<attempt>/` directory.
Preflight rejection does not write SQL. Publication can leave an exact partial
subset because the ordinary publisher uses multiple committed connections.
Handled publication failures record a postflight result when receipt I/O remains
available, then reject; unavailable or changed postflight ownership never becomes
success. A private post file can still record an earlier `status=pass` observation
if its own I/O consumes the remaining window or the target changes during that I/O.
The final checks then reject and **no accepted receipt is returned to the caller**.
Never recover acceptance by globbing a post file or hashing it after a failed call.
Only a successful API return supplies an accepted receipt. The late refusal does
not rewrite that earlier observation, avoiding another unchecked receipt-I/O window.
No foreign data is removed. A corrected retry is allowed only with the same trusted
owner/pins, unexpired original authority and exact existing bytes. Receipt-write
failure rejects even if SQL writes already committed. The caller retains cleanup
ownership and must stop SQL before leaving the file-adapter context.

## Offline qualification plan

Use the real AES materializer, signed candidate readers, real generated test PKI,
ordinary `storage_bootstrap.validate`, `storage.put/get` and release readers.
At infrastructure boundaries substitute Docker command results and psycopg
connection/cursor behavior, not the ordinary storage/publisher/reader functions.
The existing frozen fixtures also control source-clean observations and the clock.
No Docker/SQL/WSL/Kubernetes process or network connection may run locally.
First demonstrate RED, then cover copied clients, foreign server/labels/IDs/port,
marker and PKI changes, stopped container, partial writes, bad SQL/receipt
readback, corrupt hashes, stale windows and wrong candidate. Measure the new module
separately at >=95% statements and branches. Hosted native qualification remains
the parent's responsibility and is not established by these boundary fixtures.

## Verified result and caller receipt

The successful return contains `status=pass`, `proposal_reference`, `workspace_id`,
`storage_pin`, `pre_receipt`/`post_receipt` paths relative to state and their
`pre_sha256`/`post_sha256` pins, `handling=private`, and `release_ready=false`.
The driver must treat `Rejected` as import failure, keep any recorded observations
private, and run its owned cleanup inside the file-adapter context. There is no
receipt recovery or success inference from a leftover `post.json` after refusal.

From the isolated worktree based on `bf4ba7e`, using the existing pinned Python
3.12.15 interpreter:

```powershell
$python = '../t20-recovery/.venv/Scripts/python.exe'
& $python -B -Werror -m coverage run --branch --data-file=.runtime/consumer-storage.coverage --source=scripts.consumer_candidate_storage -m unittest scripts.consumer_candidate_storage_qualification scripts.consumer_candidate_state_qualification
& $python -B -m coverage report --data-file=.runtime/consumer-storage.coverage -m
& $python -B -m ruff check scripts/consumer_candidate_storage.py scripts/consumer_candidate_storage_qualification.py
& $python -B -m ruff format --check scripts/consumer_candidate_storage.py scripts/consumer_candidate_storage_qualification.py
& $python -B scripts/check_docs.py
```

Observed final result: **35 tests passed in 166.618s**, comprising 23 importer tests
and 12 unchanged file-adapter regressions. Importer coverage: **125/125 statements
and 6/6 branches, 100% each**, no exclusions. The test-first run initially failed
because the importer did not exist. Two later window-boundary tests reproduced
stale pre-publication writes and stale post-inventory success, then passed after
reordering/rechecking. Parent review supplied two more post-receipt boundary tests:
both first reproduced erroneous success, then passed after final target/freshness
checks were moved after receipt write/readback/hash. No original window was relaxed.

This verifies real signed/AES/PKI parsing and ordinary Python SQL publication logic
against strict boundary fixtures. It does not verify a live PostgreSQL server, TLS
handshake, Docker daemon, Kubernetes consumer or M11/M12 acceptance. Parent-owned
hosted qualification and review remain required; this module does not dispatch it.
