# Bound Kubernetes supplemental scans implementation plan

> **For agentic workers:** use superpowers:subagent-driven-development for the disjoint tasks and parent integration below. Existing owner authorization covers implementation, scoped reviews and public disposable hosted validation. This is required R1-B02 work, not a new approval or acceptance target.

**Goal:** run actual additional module scans for the proven Kubernetes aliases and join them with unchanged original image findings before application coverage can be considered complete.

**Architecture:** a fixed reviewed registry binds source/publication evidence to exact image configs and full observed inventories. A bounded reader verifies one PURL's JSON, CycloneDX and trace from the same invocation. The existing image auditor runs all 28 fixed coordinates against its current read-only DB once, then joins the relevant results to each of the four original image scans. Full R1 and all 14 runtime/controller targets remain unchanged.

**Tech Stack:** existing Python 3.12.15, locked uv, Grype 0.120.1/Syft 1.54.1 and current pinned image digests. No new dependency.

**Spec:** [M18](../../acceptance.md#m18), [R1-B02](../../r1-delivery.md), [reviewed source mapping](../../evidence/kubernetes-module-mapping-2026-11-20.md), [observed scanner protocol](../../evidence/go-purl-observation-2026-11-20.md). The established private review and primary replay receipts are maintainer inputs, not caller-supplied runtime authority.

## Global constraints and design decisions

- No local Docker/WSL/Kubernetes/SQL, external models, costs, secret publication, private raw reports or changes to the foundation repository. Use only standard public GitHub-hosted CI for native execution.
- Keep all originals: source SBOM, raw `(devel)`/`UNKNOWN`/pseudo versions, original scan reports and Critical/High/Unknown findings. Additional scans cannot waive original findings or severity policy.
- Preserve Grype/Syft pins, existing detection controls, DB freshness <=120 hours, hash validation, offline scan networking, read-only cache and exact-ID owned cleanup.
- Production/security-critical new modules need >=95% statement and >=95% branch coverage individually, listed negative cases and a scoped primary review.
- Stop new work at <=30% remaining account quota to retain the owner's minimum 25%; no reset or purchase.
- Ruling: use exact reviewed mapping constants, not tag arithmetic or rewritten SBOM versions. Generic re-verification of the complete publisher trust chain on every audit is unnecessary for this fixed registry; its source, recipe and proof snapshot digests are pinned and changes require review.
- Ruling: conservative module-level matching does not use compiler reachability to suppress findings. Only the seven recorded publishing path deltas are accepted, bound to their exact module/revisions/path/direction/hash/mode.
- Ruling: `not-a-version` returning a normal zero-match report proves that caller coordinates must not reach scanner unchecked. The runner has no arbitrary-PURL entry point and scans the fixed complete set of 28.
- For a registry reference require its exact pinned manifest. For an already verified local config reference require the exact config digest; keep the registry-manifest provenance association explicit rather than claiming a manifest was observed locally.

## Review focus

1. Wrong image/config/manifest, changed full inventory, missing/extra/duplicate package or wrong runner-main alias must fail before supplemental execution.
2. A supplied digest or `equal=true` near a mapping is not trust. Only the code-pinned reviewed registry selects coordinates.
3. Source echo or empty matches alone do not prove processing. Missing/foreign CDX, wrong PURL trace, malformed report, ignored findings, matcher errors and stale/changed DB must not grant coverage.
4. Expected severity exit 2 and operational failure differ. Do not waive an arbitrary ERROR log simply because there is one; verify any allowed exact threshold message against pinned upstream source.
5. A correct supplemental subset cannot authorize a full image: all its mapped instances, complete relevant scan set and original image scan must be bound, with original findings retained.

## Task 1: fixed source-bound alias registry

**Files:** create `scripts/image_kubernetes_aliases.py`, its small fixed data file if useful, and `scripts/image_kubernetes_aliases_qualification.py`. No edits to other tasks' files.

**Produces:** `resolve(observation, reference) -> mapping | None`; unknown config returns `None`, a known but changed inventory/reference raises `Rejected`. Mapping contains image config, proven manifest association, source/proof digest, instance bindings and sorted unique coordinates. `coordinates() -> tuple[(module, version), ...]` returns all 28 exact reviewed coordinates; validation is complete before any scanner call. `validate_coordinate(module, version)` rejects any tuple outside this fixed set.

- [ ] Begin with negative tests for tampered proof data, wrong config/manifest/reference/inventory/package/path/version, foreign module, missing/duplicate instance and misuse of root vs runner identity.
- [ ] Populate constants only from the parent-replayed 27/96 matrix, separate four-main-module assessment, publisher evidence and seven reviewed fixed deltas. Two auxiliary modules remain proof dependencies, not additional scan coordinates.
- [ ] Bind actual 588 raw scanner rows across the four fixed images using existing independent inventory digests. Retain original versions and expose derived coordinates separately.
- [ ] Run tests and per-module statement/branch coverage; parent recheck the four actual private observations. Scoped review before integration acceptance.

## Task 2: bound single-coordinate report reader

**Files:** create `scripts/image_go_supplemental_contract.py` and `scripts/image_go_supplemental_qualification.py`. No image auditor or registry edits.

**Consumes:** expected `(module, version)` from the already validated registry, JSON report, CycloneDX document, bounded trace bytes, numeric exit, expected DB descriptor and timestamp. This reader verifies reports; it is not the external authorization boundary for arbitrary coordinates.

**Produces:** `assess(module, version, report, cdx, trace, returncode, expected_database, timestamp=None) -> result`, with complete findings, counts, status and binding facts. Exact canonical PURL and strict coordinate syntax are checked again; errors raise `Rejected`. Use the existing `database` and severity vocabulary.

- [ ] Begin with negative fixtures: malformed coordinate/report, wrong source/CDX/name/version/type/PURL, missing/duplicate component, wrong or ambiguous trace, ignored matches/coverage alerts, foreign match, stale/mismatched DB, invalid exit and nonfatal matcher errors.
- [ ] Verify parsed package independently from source echo; zero matches require observed exact-PURL search and zero-completion evidence. Nonzero findings require complete binding and consistent policy exit. Reject unknown operational errors, including the one-ERROR shortcut.
- [ ] Verify any exact allowed fail-on threshold log message against pinned primary source, document limits, and test a foreign error alongside it.
- [ ] Return all findings without filtering/dropping Unknown or unfixed items. Run tests, >=95% statements/branches and one scoped review.

## Task 3: actual runner, join and audit integration

**Owner:** parent. Create a focused runner/join module and qualification tests; modify `scripts/image_audit.py`, `scripts/image_scope.py` and their affected qualifications. Reuse existing `scanner`, `snapshot`, safe reads and output bounds.

- [ ] Write negative tests for incomplete/extra/duplicate scan sets, changed report/CDX/trace bytes, DB mutation, original-finding loss, changed original SBOM/config and a profile-name/boolean-only coverage bypass.
- [ ] Scan all 28 registry coordinates once when a proven Kubernetes inventory is present. Each invocation emits JSON/CDX/private trace into its own absolute owned path. Keep the cache read-only and network off; prove recorded containers absent after execution.
- [ ] Join exact relevant PURLs into each original image result, retaining original reports/findings and separate supplemental provenance. Recompute counts/status; original fail remains fail, Unknown remains inconclusive. Mapping alone never sets `sbom_validated` or grants application coverage.
- [ ] Permit the four Kubernetes coverage profiles only after complete joined evidence and exact target bindings. Preserve every existing target in the runtime denominator.
- [ ] Run changed modules' negative tests, existing image audit/scope regressions and per-module coverage. One integrated review, fix concrete findings and publish scoped commits.

## Task 4: native evidence and operations

- [ ] Add a dedicated public hosted validation using the four pinned public images, their original SBOM scans and all 28 additional coordinates against the same DB. No local cluster or model is required for this image-specific validation; it does not replace the later complete 14-target runtime acceptance.
- [ ] Verify exact source, terminal jobs, closed results and owned cleanup; retain raw evidence privately, publish only the reviewed safe projection. Do not restart on observer timeout.
- [ ] Add/update runbook and playbook with encountered failure, recovery and reproduction instructions. Record actual coverage/findings and remaining blockers, without declaring full B02/M18/R1 complete.
