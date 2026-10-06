# Реестр источников

Проверено 2026-10-06. Короткие выводы в документах - авторский синтез, не цитирование стандартов целиком. У веб-документации версия может меняться. Приведённая версия спецификации не означает внедрённое соответствие. Для больших NIST-документов изучались релевантные разделы, а не заявляется постраничный аудит всего стандарта.

## S01
[Светлана Газизова, Positive Technologies: «Что такое MLSecOps...»](https://habr.com/ru/companies/pt/articles/832190/), 2024-07-30. Предоставленная статья, авторский практический обзор. Использование: постановка задачи защиты ML-конвейера. Не нормативный документ и не измерение нашей платформы.

## S02
Предоставленный локально PDF **«MLOps для разработки и мониторинга моделей»**, 11 страниц, бренд «Практикум PRO». SHA-256: `87a2099c71731fc052f0a750474d5d91c26f36efc1a51c36b68cf7fb404c6cb1`. Текст всех страниц прочитан, ключевые развороты визуально проверены. Это программа обучения, не стандарт MLSecOps. Публичный URL и разрешение на републикацию не предоставлены; оригинал не включён в Git. Дата файла в метаданных не используется как дата публикации курса.

## S03
[Satish Chandra Gupta, MLOps: Machine Learning Life Cycle](https://www.ml4devs.com/articles/mlops-machine-learning-life-cycle/), опубликовано 2022-09-12, обновление страницы 2023-03-17. Авторский первоисточник циклов Data/ML/Dev/Ops. На предоставленной иллюстрации указана CC BY-NC-ND 4.0; иллюстрация не изменялась и не загружалась в репозиторий.

## S04
[NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework), [AI RMF 1.0, полный документ](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf), январь 2023. Изучены характеристики доверия и раздел 5 с GOVERN/MAP/MEASURE/MANAGE. Страница сообщает о пересмотре 1.0; не называем проект пересмотра опубликованной версией 2.0. Добровольный framework, не сертификат.

## S05
[NIST AI 100-2E2025, publication record](https://csrc.nist.gov/pubs/ai/100/2/e2025/final), [текст](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf), март 2025, final. Использованы таксономия, раздел 2.3 о poisoning и обсуждение ограничений устойчивости в конце раздела 2.2. Используется для классов угроз, не как обещание эффективности детектора.

## S06
[NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final), июль 2024, final. SSDF-профиль для generative AI и dual-use foundation models. Релевантен будущему GenAI-треку; нельзя выдавать табличный MVP за соответствие всему этому профилю.

## S07
[MITRE ATLAS, данные на фиксированном commit](https://github.com/mitre-atlas/atlas-data/blob/3259f388d19cbcca11bacf12a0ef97f4198f711b/dist/ATLAS.yaml). Проверены названия и идентификаторы: `AML.T0010` AI Supply Chain Compromise, `AML.T0020` Poison Training Data, `AML.T0015` Evade AI Model, `AML.T0024.000` Infer Training Data Membership. ATLAS - база поведения атакующих, не рейтинг надёжности продукта.

## S08
[OWASP AI Exchange](https://owaspai.org/). Проверены группы input/development/runtime threats и testing. Используется как дополнительная карта рисков. Страница отдельного ML Security Top 10 не была надёжно получена; ей не приписываются проверенные выводы. LLM Top 10 не заменяет модель угроз predictive ML.

## S09
[Google Cloud: MLOps continuous delivery and automation pipelines](https://docs.cloud.google.com/architecture/mlops-continuous-delivery-and-automation-pipelines-in-machine-learning), last reviewed 2024-08-28. Принципы CI/CD/CT и проверки данных/моделей; источник прямо ориентирован преимущественно на predictive AI. Не основание покупать облако.

## S10
[DVC user guide](https://doc.dvc.org/user-guide), [defining pipelines](https://origin-doc.dvc.org/user-guide/pipelines/defining-pipelines). Версионирование файлов, зависимостей и DAG. Не механизм авторизации и не подпись доверенного происхождения.

## S11
[MLflow authentication](https://mlflow.org/docs/latest/self-hosting/security/basic-http-auth/). Проверены явное включение authentication, разрешения, администраторы и ограничения basic auth. `latest` меняется; реальные RBAC API, миграции и defaults проверяются для зафиксированной версии до установки.

## S12
[MLflow Tracking Server](https://mlflow.org/docs/latest/self-hosting/architecture/tracking-server/). Разделены metadata backend, artifact storage и безопасность сетевого доступа. MLflow выбран для экспериментов, а не как самостоятельный корень доверия релиза.

## S13
[scikit-learn: Model persistence](https://scikit-learn.org/stable/model_persistence.html). Риски выполнения кода при pickle/joblib/cloudpickle, компромиссы ONNX/skops и ограничения совместимости. Номер на странице при проверке: 1.9.1; это не версия, уже установленная для нового проекта.

## S14
[ONNX Runtime documentation](https://onnxruntime.ai/docs/). Рекомендация исследовать и тестировать недоверенные модели в безопасной среде. Выбор ONNX не отменяет sandbox, лимиты и управление уязвимостями runtime.

## S15
[PyTorch: Reproducibility](https://docs.pytorch.org/docs/2.14/notes/randomness.html). Документирует ограничения воспроизводимости между версиями/платформами. Используется как предостережение для будущего GPU-трека, PyTorch в первый стенд не добавляется.

## S16
[Evidently: Data Drift](https://docs.evidentlyai.com/metrics/preset_data_drift). Сравнение current/reference, column/prediction drift, роль proxy-метрик без ground truth. Значения по умолчанию не принимаются за универсальные production-пороги.

## S17
[SLSA v1.2 specification](https://slsa.dev/spec/v1.2/), статус Approved на дату проверки. Build/source tracks и provenance. Подпись артефакта сама по себе не даёт уровень SLSA.

## S18
[Sigstore: Verifying signatures](https://docs.sigstore.dev/cosign/verifying/verify/). Проверка подписей blobs/образов и ограничение certificate identity/issuer. Допуск signer и отзыв доверия определяются политикой нашего проекта, а не одним успешным вызовом Cosign.

## S19
[CycloneDX AI/ML-BOM](https://cyclonedx.org/capabilities/mlbom/). Формат инвентаризации модели/данных и связанных сведений. Не замена model card, provenance и независимым испытаниям.

## S20
[Mitchell et al., Model Cards for Model Reporting](https://arxiv.org/abs/1810.03993), 2018/2019. Первичная исследовательская работа о контексте использования и отчёте об оценке модели. Использование: структура будущей model card.

## S21
[Gebru et al., Datasheets for Datasets](https://arxiv.org/abs/1803.09010), первоначально 2018. Первичная работа о документации происхождения, состава и использования datasets. Использование: паспорт набора данных и ограничения разрешённого применения.

## S22
[Исходная DevSecOps-платформа, проверенный commit](https://github.com/Abrakadabra124/enterprise-devsecops-platform/tree/fe73d86ef8cf4564478058e50a21ac6a1d3e2dc2). Read-only изучены README, constraints, threat model, CI workflow, схема Release Ledger и публичная приёмка. Это исходный код и заявленные границы, не новая проверка работающего кластера.

## S23
[Историческая приёмка 2026-10-04](https://github.com/Abrakadabra124/enterprise-devsecops-platform/blob/fe73d86ef8cf4564478058e50a21ac6a1d3e2dc2/docs/evidence/acceptance-2026-10-04.json). Результаты предыдущего стенда; новые ML-гарантии из них не следуют. Полный source fingerprint указан отдельно от commit документации в [gap analysis](baseline-gap.md).

## S24
[GitHub Actions baseline run 37211112894](https://github.com/Abrakadabra124/enterprise-devsecops-platform/actions/runs/37211112894). Через API 2026-10-06 проверены conclusion=success и head SHA `fe73d86ef8cf4564478058e50a21ac6a1d3e2dc2`. Hosted source CI не подтверждает текущую доступность локального Kubernetes.
