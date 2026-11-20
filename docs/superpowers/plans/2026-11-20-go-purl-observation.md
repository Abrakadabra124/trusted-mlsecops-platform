# Go PURL interface observation implementation plan

> **For agentic workers:** use superpowers:subagent-driven-development or superpowers:executing-plans for the bounded tasks below. Existing owner authorization covers this R1 implementation; this plan does not introduce another approval requirement.

**Goal:** obtain native evidence for the pinned scanner's parsed package, matching trace and report binding before adding conservative Kubernetes module scans to R1-B02/M18.

**Architecture:** reuse the existing isolated scanner runner and fresh database checks. One Grype invocation per fixed PURL produces JSON, CycloneDX JSON and a private trace. Publish a closed observation only; this workflow grants no application coverage or release authority.

**Tech Stack:** GitHub-hosted Ubuntu 24.04, locked Python 3.12.15, uv 0.12.23, existing Grype 0.120.1 image digest and its embedded Syft 1.54.1.

**Spec:** [M18](../../acceptance.md#m18), [R1-B02](../../r1-delivery.md), [publisher evidence](../../evidence/image-kubernetes-provenance-2026-11-20.md). This is a prerequisite within the existing full R1 goal, not a replacement acceptance target.

## Global constraints

- Keep the current `scripts.image_audit.GRYPE_IMAGE` digest and database maximum age 120 hours. No scanner, policy, severity or acceptance threshold changes.
- Use only the public repository and a standard disposable GitHub-hosted runner; no costs or local Docker/WSL/Kubernetes/SQL.
- Keep raw SBOM, original findings and runtime coverage unchanged. Unknown severity, ignores and coverage alerts do not permit release.
- No models, keys, candidate pins, raw logs or arbitrary error text in public output. No workflow artifact uploads or new credentials.
- Do not run the full CI matrix for this diagnostic step. The dedicated branch is `qualify/go-purl-observation`.

## Review focus

1. Empty JSON matches with no parsed package must not be interpreted as successful package coverage.
2. Wrong source/PURL/version/type, missing CycloneDX and ambiguous trace must remain visible as failed or unconfirmed observations.
3. Nonfatal matcher errors may coexist with exit zero; observe the malformed-version case rather than infer success from exit status.
4. Database mutation or failed positive control invalidates the experiment.
5. Cleanup must address recorded container IDs and verify absence; no global deletion or adoption by name.

## Task 1: fixed-input native observation

**Files:** create [go-purl-observation.yml](../../../.github/workflows/go-purl-observation.yml). Existing scanner implementation remains unchanged.

**Consumes:** `image_audit.scanner(run, name, image, arguments, mounts=(), network=False)`, `image_audit.snapshot(cache)`, `image_audit_contract.database(report, timestamp)`, `go_detection_control(report, returncode, "module", timestamp)`.

**Produces:** bounded public observations for three fixed case labels, with typed binding flags, package/match/trace counts, exit code and verified cleanup. Raw JSON/CDX/log files stay in the disposable runner's private directory. No generic production verifier is introduced before observing the actual native format.

- [x] Inspect exact upstream JSON/CycloneDX presenters, writer, matching loop and logging dependency. Ordinary JSON `source.target` reflects the input; it is not a processed-package counter. Template output cannot expose a nonexistent `.Packages` field.
- [x] Implement locked provisioning and one DB update. Preserve the DB snapshot for every scan; cache read-only and network disabled during scans.
- [x] Configure fixed PURLs: `golang.org/x/net@v0.16.0` as existing positive control; `k8s.io/streaming@v0.36.4` to observe the expected zero-match shape; `golang.org/x/net@not-a-version` to observe malformed-version handling. Do not choose replacement versions after inspecting results. Native execution is tracked below.
- [x] Request `-vvv`, JSON stdout and `cyclonedx-json=/out/package.cdx.json` from the same invocation. Use a separate owned output directory per case and bounded reads; do not expose raw trace.
- [x] Implement recording of actual outcomes, including unexpected nonzero matches for streaming or unexpected handling of the malformed version. These observations must not be relabeled coverage pass.
- [x] Add always-cleanup using only recorded IDs and post-absence verification.

## Task 2: validation, review and native probe

- [x] Validate YAML, each extracted Bash block and each inline Python block. Run `python scripts/check_docs.py` and `git diff --check`.
- [x] Exercise the observation projection with controlled wrong-identity, missing-secondary-output and malformed-log inputs. Check that arbitrary private text cannot enter public output. These checks validate the diagnostic boundary, not production package coverage.
- [x] Perform one scoped workflow/privacy/cleanup review and fix its concrete findings. Review approved workflow blob `16ff3deb9ce2851ed588ca2677eab2e750e3d3ec`; no material findings.
- [x] Verify repository visibility is public, then push the reviewed source only to the dedicated branch. Record the exact run ID and SHA; do not restart after an observer timeout. Runs `44670568366` / `0feb2637` and `44672008908` / `9c7eca66` are terminal failures before package observations; see the [runbook](../../operations/go-purl-observation.md).
- [ ] Read terminal job state, closed observations and cleanup proof. Retain raw diagnostics privately. Document the actual supported report/trace contract and any unresolved behavior.

## Next required integration

Use the observed protocol, the full 27-module/96-instance source matrix and the separate main-module assessment to implement bound supplemental scans: 28 unique PURLs, comprising 27 published workspace modules and the existing known Kubernetes root coordinate. Every derived coordinate needs its own justified mapping; no tag arithmetic or raw version replacement. Preserve all original findings and all 14 runtime targets. A later Kubernetes coverage profile requires complete original inventory, complete mappings, actual additional scans and unchanged database/input bindings. Full same-candidate M18, independent M22 and the remaining R1 requirements still apply.

Parent verification before native execution: 17 controlled tests passed in 0.819 s on Python 3.12.15, all four Bash blocks passed syntax checks, inline Python passed compile/AST/Ruff, and documentation passed. Controlled tests substitute the Docker boundary; they are not native scanner evidence. The workflow contains no production coverage authorization.

The diagnostic follow-up preserves the original scanner exception if cleanup also fails. Parent reran 19 tests in 0.916 s, including the real scanner command builder with only its process boundary substituted. The second native run returned Docker exit 125 without a recorded CID. The underlying cause remains unresolved; closed failure classification is the next bounded step, not an assertion of a repaired scanner.
