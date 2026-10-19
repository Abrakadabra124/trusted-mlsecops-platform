# Native attempt 4c86fcb: metrics pass, source lock mismatch

Code commit `4c86fcbdced07618d9fbe587e43e0c5c8cec0536`. Все 10 workflows terminal на 2026-10-19 17:28:20 UTC, attempt 1: **2 success / 8 failure**. Никакие runs не отменялись/не перезапускались. [Основное evidence](serving-metrics-2026-10-19.md).

| Workflow | Run | Conclusion | Evidence |
| --- | --- | --- | --- |
| Developer | [39294067908](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294067908) | failure | source_lock_mismatch_explicit_update_required |
| Documentation | [39294067677](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294067677) | success | documentation integrity |
| Evasion | [39294067990](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294067990) | failure | source lock mismatch; no new evasion outcome |
| Poisoning | [39294067859](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294067859) | failure | source lock mismatch; 12 tests / 1 error; native research skipped |
| Intake | [39294067748](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294067748) | success | controlled intake |
| Kubernetes | [39294067959](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294067959) | failure | source lock mismatch; train/evaluate interrupted |
| Tracking | [39294067777](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294067777) | failure | qualification_failed:acceptance-dispatch-M02; inconclusive |
| Paired training | [39294067783](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294067783) | failure | source lock mismatch; execution incomplete |
| Storage | [39294067808](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294067808) | failure | metrics 35 pass; worker 13 pass; M03 source lock mismatch |
| Image audit | [39294067757](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/39294067757) | failure | candidate qualification M02; package scan skipped; publication inconclusive |

## Что действительно проверено

Storage job 118201901845: **35 metrics tests / 0 skips, 2.935 s**, collector 115 statements / 30 branches / 100%, probe 69 statements / 36 branches / 100%. Worker guard **13 tests / 0 skips, 0.290 s**, 19 statements / 6 branches / 100%; native kernel receipt pass. Private audit 77 tests pass. Developer intake component 36 tests pass до отказа source verification. Нового actual-candidate report нет: downstream steps skipped после M03. Предыдущий candidate pass не переносится на эту revision.

## M03 report

```json
{
  "artifact_hashes": {},
  "cases": [],
  "exit_code": 1,
  "finished_at": "2026-10-19T17:27:30.144907+00:00",
  "gate": "M03",
  "input_digests": {
    "source_fingerprint": "30fbd2ef30fb192ca941fedb35916f66413091d50a656cd525706aafbc9b192a"
  },
  "metrics": {},
  "policy_digest": "9a78ff344304e12e52c54652d8750aae69038e2a1ae2fb2c375a752e67fedb24",
  "profile": "local-cpu",
  "redaction_version": 1,
  "residual_risks": [
    "source_lock_mismatch_explicit_update_required"
  ],
  "schema_version": 1,
  "source_revision": "4c86fcbdced07618d9fbe587e43e0c5c8cec0536",
  "started_at": "2026-10-19T17:27:26.445366+00:00",
  "status": "fail"
}
```

## Причина и безопасное исправление

prometheus-client изменил uv.lock, но data.lock продолжал требовать прежний digest. Fail-closed source verification корректно отклонила запуск. Локальный read-only аудит подтвердил: изменён только input uv.lock, остальные generator/policy inputs прежние. Две свежие генерации совпадают побайтно с frozen output: **1 915 576 bytes**, SHA-256 **1a96301cdec7f66ab56265db150befb99147350f0ccef6fab8dd6f2887df6473**.

Явная correction меняет только data.lock.inputs[uv.lock]: bytes 113055 -> 113874; SHA-256 cb48185d54892acf8954b8725ade419cd62506e6892a0f9c29194ffdf6fd309f -> 649875fff6c02f34ded1b4f024e58419349d4d0a3f05574dc066f62308b8be27. Dataset output, seeds, model policy, thresholds, code generator и gate logic не меняются. Автоматического update-lock в CI нет. Tracking/Image M02 dispatch failures не объявляются новым package scan или ML measurement. Исторические image/ML blockers остаются открытыми.
