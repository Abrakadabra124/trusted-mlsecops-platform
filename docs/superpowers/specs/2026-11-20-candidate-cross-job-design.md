# Original candidate cross-job delivery

Week 13, T21. Complete the original candidate path with the existing acceptance
contracts, not another release definition. The verified private canary remains
valid, but it cannot establish capacity for the full Kubernetes campaign.

## Required correction to placement

Current `cluster.bootstrap` requires >=4 CPU, >=15 GiB Docker memory and >=12 GiB
free disk, and configures the node as 4 CPU/12 GiB. Standard private Ubuntu
runners provide 2 CPU/8 GB; standard public Ubuntu provides 4 CPU/16 GB.
[GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
checked 2026-11-20. Do not weaken this profile or enable paid larger runners.

Run actual producer/consumers on the existing public hosted profile. Store private
candidate/validation/upstream/retained packets as encrypted release assets in the
existing same-owner private execution repository. Its role is storage here.
Public runner logs/outputs/artifacts must not contain private packet bytes or pins.

## Boundaries

1. **Exact image before private inputs.** Build the existing source-only worker
   once from a clean, publicly published checkout. Its Dockerfile/.dockerignore
   copy only already-public source, dependency locks and local policy, never
   runtime, keys, models or data. Transfer that exact image as a bounded archive
   and verify config ID, source labels and bytes on a fresh runner. This particular
   source-only image may be public; it does not classify candidate images or
   arbitrary caller-selected images as public. No real model is embedded.
   The existing platform requires Linux classic `overlay2`, where Docker ID is
   the configuration digest. Both endpoints check this before image mutation;
   containerd manifest/index identity is not silently treated as the config ID.
   Compressed/raw caps are fixed at 384 MiB/2 GiB before native measurement.
   Each job has an external owner witness; downloaded bytes cannot authorize
   local deletion. Refuse pre-existing probe state before calling Docker.
2. **Original trust identity.** Provision one temporary Ed25519 trust key through
   repository secrets before creating producer state. Producer derives its public
   registry from this original key. Consumers receive the same key by the secret
   channel and verify it against the frozen public key. Curator/evaluator/approver
   private keys stay in producer. No key enters artifacts, job outputs or Git.
3. **Private store credentials.** Use separate repository-only publisher and
   reader credentials, restricted to the private repository's Contents write/read.
   Do not forward the owner's broad local gh token to CI. Credentials are inputs,
   never generated or inferred by the artifact adapter. Provisioning must be
   explicit and verified before native private candidate dispatch.
4. **Independent authority.** Trusted producer writes a bounded, authenticated
   private control record separately from ciphertext assets. Consumer verifies
   actual public source/run/attempt/producer job and fixed phase before accepting
   control data as expected pins. The read-only consumer cannot rewrite that
   record. A manifest taken from an untrusted downloaded archive is not authority.
   Before enabling consumer primary-evidence uploads, resolve the separate write
   boundary: repository-wide Contents write also permits changes to producer
   records. Keep those records write-isolated, or verify a producer-only signature
   against an independently delivered public key. A read-only download step followed
   by a same-repository writer token is not read-only authority isolation. This
   access decision remains open; no such credential has been provisioned.
5. **Lifecycle.** Prepare image before opening original proposal; train/evaluate
   once, freeze once, seal phase-specific packets. Consumers use ordinary readers,
   fresh owned SQL/cluster and original gates. Preserve producer owner separately
   from consumer cleanup owner. No re-signing, retraining, expiry extension or
   skipped failures to make handoff succeed. M18 remains last, one candidate.
6. **Cleanup.** Bound sizes, lifetimes and one run/attempt namespace. On failure,
   delete only verified owned assets, confirm absence, then revoke temporary keys
   and credentials after terminal jobs. Private records and evidence never become
   public because they are encrypted. Retain necessary primary evidence in the
   authorized private contour for replay; cleanup must not destroy its sole copy.

## Alternatives and retained limits

Full execution in the private repository is rejected for current capacity.
Public encrypted artifacts remain disallowed for private candidate packets.
Another cloud service, paid runners, local infrastructure and sharing the owner's
wide credential are outside the authorized solution. Exact image transport and
fresh secret-bound bootstrap are independent prerequisites that can be completed
while the narrow private store credential flow is prepared.

Image vulnerabilities, full inventory coverage, independent human M22 challenges,
same-candidate gate aggregation and clean-checkout R1 reproduction remain required.
Repository administrators, GitHub and authorized trusted controller code remain
trusted. Public code image publication conveys no model release permission.
