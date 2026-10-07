# Model card: Release Risk Advisor developer preview

Статус: **unapproved candidate**, не trusted release. Назначение - показать воспроизводимый CPU training/evaluation путь и проверки целостности на synthetic dataset. Модель не разрешает выпуск ПО.

## Реализация

scikit-learn StandardScaler обучается только на train, затем Logistic Regression с solver lbfgs, seed 17 и максимумом 300 итераций. Экспорт skl2onnx с opset 18, zipmap выключен. Runtime использует ONNX Runtime CPUExecutionProvider и один вычислительный поток.

Training/prediction идут в отдельных короткоживущих Linux containers. У workers нет сети, host mounts, service-account token или signing keys. JSON protocol ограничивает размеры; scorer хранит labels отдельно и проверяет shape/range/finite probabilities перед вычислением метрик.

## Проверенные числа

Локальная qualification 2026-10-07: три fresh-process обучения, один pinned image/source fingerprint. Holdout: 3 000 строк, 1 222 положительных labels.

| Измерение | Результат |
| --- | --- |
| AUPRC | 0.9323007296445032 во всех трёх повторах |
| Constant-score baseline AUPRC | 0.4073333333333333 |
| Прирост | 0.5249673963111698 |
| Максимальное различие validation probabilities между повторами | 0.0 |
| Максимальная Python/ONNX ошибка на 3 000 validation cases | 2.086162567138672e-7 |

AUPRC - площадь под precision-recall кривой. Constant-score baseline имеет AUPRC, равную доле положительного класса. Эти synthetic метрики не переносятся на реальные release decisions.

## Ограничения и неподходящие применения

Нет реального бизнес-dataset, калибровки вероятностей на настоящих релизах, доказанной fairness/privacy, adversarial campaign или независимого человеческого review. Пока нет holdout query budget и всей инфраструктуры M07. Повторы подтверждают численную повторяемость в фиксированном профиле, не bit-for-bit гарантию для произвольной платформы.

Запрещено использовать модель для финансовых, медицинских, кадровых решений и автоматического обхода security policy. Подписанный evaluation report не заменяет promotion approval. Полная приёмка M01-M23 остаётся inconclusive.
