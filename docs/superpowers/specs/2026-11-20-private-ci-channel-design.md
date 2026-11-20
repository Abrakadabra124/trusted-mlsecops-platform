# Private CI channel prerequisite

Scope: week 13, T21. This is a necessary transport prerequisite for one-candidate
parallel acceptance, not M18 or R1 acceptance. Existing thresholds, proposal
windows, independent M22 challenges and image blockers remain unchanged.

## Decision and alternatives

Use `Abrakadabra124/trusted-mlsecops-ci-private` as a separate private execution
repository containing the exact publicly published Git commit DAG. Preserve the
actual execution repository/run/attempt; never substitute the source repository
name in GitHub environment variables. Source remains the public platform code.
The owner delegated implementation choices and requested autonomous execution.
This choice is the implementer's decision, not a separately claimed user design.

Public Actions artifacts are readable by repository readers, including encrypted
ones. They cannot carry the existing private packets. Public jobs with a private
external store would introduce another credential and authority boundary.
Private execution uses repository-scoped `GITHUB_TOKEN` and an ephemeral
repository secret for AES instead of forwarding the owner's personal token.

## Required boundary

- Only the exact same-owner private repository, fixed numeric repository ID,
  visibility/private checks, no fork and exact publicly available source commit.
- Standard hosted Ubuntu runners only. No local Docker/WSL/Kubernetes/SQL.
- The account Actions hard zero-spend guard was observed through authenticated
  UI before provisioning. Private billing details stay outside Git. No paid
  budget changes, larger runners, external models or optional research.
- Transport context binds actual execution repository/run/attempt, source/image,
  phase, payload and original time limits. Other repository names fail closed.
- Initial native qualification uses only a small generated canary. Fixture
  image/candidate/proposal identities are explicitly synthetic. No ML gate claim.
- Ciphertext is uploaded only to the private run. Expected context and envelope
  pin arrive through trusted producer job outputs, not the downloaded artifact.
  AES key is a temporary repository secret, never an output/artifact/Git file.
- Bounded exact artifact download, immutable ID, one-day retention fallback,
  explicit owned deletion with absent readback even if receiver fails. No cache.
- Delete the temporary secret after terminal run. Retain only closed outcomes
  publicly; private diagnostic packets stay in the authorized private contour.

## Validation and subsequent work

Require negative tests before implementation, separate >=95% statement/branch
coverage for new/changed security modules, scoped review, real producer/receiver
jobs and verified cleanup. Test altered ciphertext with updated pin, altered AAD,
wrong key, wrong run/attempt/repository and foreign cleanup ownership.

The canary does not prove frozen-candidate signatures, image transfer, independent
consumer provisioning, combined gates, output retention or final clean checkout.
Connect these only after the channel and real execution identity are validated.
Account/repository administrators and GitHub remain trusted; check visibility
before each operation but do not claim protection against a malicious owner
changing repository visibility during execution.

Sources inspected 2026-11-20: [artifact access](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts),
[Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions),
[hard budgets](https://docs.github.com/en/billing/concepts/budgets-and-alerts).
