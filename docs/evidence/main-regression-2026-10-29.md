# Main regression, 2026-10-29 МСК

Проверен опубликованный commit `139d13de4f5701c824003ed69ed7ed161ab4dc4a`. Все десять запущенных workflow завершились `success`; состояние прочитано через GitHub CLI после завершения jobs. Новых локальных инфраструктурных запусков не было.

| Workflow | Run | Итог |
|---|---|---|
| Documentation integrity | [40785368950](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40785368950) | success |
| Developer runtime qualification | [40785369255](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40785369255) | success |
| Storage role and TLS qualification | [40785369033](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40785369033) | success |
| MLflow tracking compatibility and private service | [40785369016](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40785369016) | success |
| Kubernetes isolation qualification | [40785369151](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40785369151) | success |
| Worker, storage and tracking image audit | [40785368980](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40785368980) | success |
| Intake evidence contracts | [40785368964](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40785368964) | success |
| Candidate-bound M08 poisoning acceptance | [40785369297](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40785369297) | success |
| Candidate-bound M09 format parity and evasion | [40785369282](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40785369282) | success |
| Paired current candidate robustness and utility | [40785368955](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/40785368955) | success |

Это integration checkpoint опубликованной balanced training recipe. Десять workflow successes не означают passing M01-M23 на одном candidate: jobs создают собственные окружения и кандидатов. Прежняя общая привязка M08/M09 на `e7d166e` зафиксирована в [native evidence](../noise-training-validation.md#подтверждённый-native-результат-2026-10-29-мск), её нельзя автоматически переносить на другой source/image/revision.

Не закрыты независимые M22 challenges, полное observed system-image coverage, CP3-CP5 и M18. Прежние system-image High/Critical/Unknown findings не отменяются успешным audit только worker/storage/tracking images. Чистая validation не превращает score в калиброванную вероятность: [FPR/Brier trade-off](../noise-training-validation.md) сохраняется. Этот checkpoint не включает новый M22 controller, реализуемый после указанного commit.
