# M21 on the controller candidate

The controller producer and the ordinary M21 verifier run in separate steps of the same hosted synthetic job. The workspace, source revision, SQL container, public keys, run and attempt are bound before training. The scorer produces a signed evaluation during M04. A separate promoter Job reads this exact evaluation and both matrix denials. The matrix also spends a fresh slot on a second evaluation of the same candidate. Its reference must differ from the delivery evaluation.

In the controller training function, immediately before `restore_history` and after M04 has produced its signed subject, use the opt-in hook below.

```python
if "M21_START_SHA256" in os.environ:
    from mlsecops.controller_intake import capture

    capture(root, state, subject, image)
```

After starting the owned SQL and before the existing M07 step, add the first step below. Give the existing M07 step the ID `training` and add `M21_START_SHA256: ${{ steps.intake_start.outputs.start }}` alongside its existing environment. The capture hook exports `capture` through that step's GITHUB_OUTPUT. The existing `source` step seals the original storage-demo file. Run M21 while the host SQL is still active. If proposal lifetime is tight, execute the M21 consumer after time-sensitive serving measurements and before stopping storage. Include the additional SQL rows in subsequent backup and ledger checks.

```yaml
- name: Begin controller intake campaign
  id: intake_start
  run: uv run --locked python -B -m scripts.controller_intake begin

# Existing training and source steps go here.

- name: Qualify the original controller candidate
  id: intake
  env:
    M21_START_SHA256: ${{ steps.intake_start.outputs.start }}
    M21_CAPTURE_SHA256: ${{ steps.training.outputs.capture }}
    M17_DEMO_SHA256: ${{ steps.source.outputs.demo }}
  run: |
    uv run --locked python -B -m mlsecops.acceptance --gate M21 --output .runtime/evidence/M21.json
    echo "gate=$(sha256sum .runtime/evidence/M21.json | cut -d' ' -f1)" >> "$GITHUB_OUTPUT"

- name: Verify M21 artifacts and reject a substituted digest
  env:
    M21_START_SHA256: ${{ steps.intake_start.outputs.start }}
    M21_CAPTURE_SHA256: ${{ steps.training.outputs.capture }}
    M17_DEMO_SHA256: ${{ steps.source.outputs.demo }}
    M21_GATE_SHA256: ${{ steps.intake.outputs.gate }}
  run: |
    uv run --locked python -B -m scripts.controller_intake verify
    uv run --locked python -B -m scripts.controller_intake check-substitution
```

After fencing, ordinary M21 reads the transferred original evaluation, additional evaluation and signed denials from the authoritative SQL with promoter credentials. Its Docker scan and three SQL controls use the same fetched model. These controls spend additional holdout slots. The separate process that verifies delivery reads the pinned gate, primary, four component reports, start and controller capture. Only the compact verification output is suitable for the job log. Retain packet files privately for replay.

A mismatched byte digest fails with `M21_pin_mismatch` and the input basename. A foreign subject or disagreement between the read-only controller and SQL destination fails the M21 step. Preserve all pins and identify the first failing producer. A new attempt starts with fresh owned storage. A completed verification establishes laboratory intake coverage for this subject. The output always has `release_ready=false`.
