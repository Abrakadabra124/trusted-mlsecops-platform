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

## Дополнение R0.2

Ниже дополнительные материалы, проверенные **2026-10-06**. Дата публикации указана только если найдена в самом источнике; дата получения не заменяет её. Восемь компаний представляют выборку публичных инженерных материалов, а не весь мировой рынок. Полные сторонние тексты в Git не копируются.

## S25
Предоставленный текст «MLSecOps (Machine Learning Security Operations)...», SHA-256 `f715c867df1df60bb4c78ec9b5750188ea45d57459d527e6d39b45dc649556dc`. Дата автора неизвестна, получен 2026-10-06. Упоминания доменов без конкретных статей не считаются проверенными цитатами. Используется как набор гипотез для [fact-check](material-review.md), оригинальный файл не републикуется.

## S26
[CyberOrda: инструменты и курсы MLSecOps](https://cyberorda.com/MlSecOps/). Каталог сообщества, дата публикации страницы не установлена. Полезен для discovery, сам предупреждает о неподдерживаемых инструментах. Не comparative benchmark и не гарантия безопасности перечисленного ПО.

## S27
[Google: Introducing Secure AI Framework](https://blog.google/innovation-and-ai/technology/safety-security/introducing-googles-secure-ai-framework/), 2023-06-08. Первичное объявление SAIF. Используется для исторической точки отсчёта, не как новость 2026 года.

## S28
[Google: How we’re securing the AI frontier](https://blog.google/innovation-and-ai/technology/safety-security/ai-security-frontier-strategy-tools/), 2025-10-06; [SAIF risk map](https://www.saif.google/secure-ai-framework), [controls](https://saif.google/secure-ai-framework/controls), страницы актуальной документации. Подтверждено объявление SAIF 2.0 и расширение к агентам. Из карты переносим компонентный risk mapping; автоматического соответствия SAIF не заявляем.

## S29
[Microsoft Research: Lessons From Red Teaming 100 Generative AI Products](https://www.microsoft.com/en-us/research/publication/lessons-from-red-teaming-100-generative-ai-products/), январь 2025; [engineering summary](https://www.microsoft.com/en-us/security/blog/2025/01/13/3-takeaways-from-red-teaming-100-generative-ai-products/), 2025-01-13. Опыт команды Microsoft, не независимый межвендорный benchmark. Изучены выводы об области применения, роли человека и различии red teaming/benchmarking.

## S30
[AWS: Governing the ML lifecycle at scale, Part 4](https://aws.amazon.com/blogs/machine-learning/governing-the-ml-lifecycle-at-scale-part-4-scaling-mlops-with-security-and-governance-controls/), 2025-02-07. Reference multi-account ML platform, разделение development/test/production/data governance и ролей approval. Переносится принцип, не обязательная покупка SageMaker и не эквивалентность namespace облачному account.

## S31
[Anthropic, UK AISI, Alan Turing Institute: A small number of samples can poison LLMs](https://www.anthropic.com/research/small-samples-poison), 2025-10-09. Эксперимент с узким backdoor и моделями 600M-13B; 250 документов относятся к исследованной постановке. Используется для проверки предположения о процентном бюджете, не для универсального порога или утверждения о нашем классификаторе.

## S32
[NVIDIA AI Red Team: Four Ways to Deploy More Secure AI Agents](https://developer.nvidia.com/blog/four-ways-to-deploy-more-secure-ai-agents/), 2026-07-30. Изучен основной текст, не только AI-generated summary. Описывает access control, execution isolation, egress и secret handling. После timeout web-reader основной текст получен напрямую с того же официального URL; эксперименты NVIDIA не воспроизводились.

## S33
[OpenAI: Designing AI agents to resist prompt injection](https://openai.com/index/designing-agents-to-resist-prompt-injection/), 2026-03-11. Источник о защите agent systems и ограничении последствий манипуляции. Для predictive ML переносится принцип внешнего контроля действий, а не prompt-инструменты или обещание полной защиты.

## S34
[Databricks: Agentic AI Security, DASF v3.0](https://www.databricks.com/blog/agentic-ai-security-new-risks-and-controls-databricks-ai-security-framework-dasf-v30), 2026-03-20. Расширяет модель рисков на agents/MCP. Дата и версия относятся к проверенной публикации, не заявляется отсутствие более поздних версий. Capability boundaries рассматриваются отдельно от рекомендаций поставщика по конкретным продуктам.

## S35
[Hugging Face: Pickle Scanning](https://huggingface.co/docs/hub/security-pickle). Документация без надёжно установленной даты публикации, проверена 2026-10-06. Прямо оговаривает неполноту сканирования и best-effort списков imports. Нельзя интерпретировать чистый scan как доказательство безопасности модели.

## S36
[Hugging Face: Safetensors](https://huggingface.co/docs/safetensors/index). Документация формата хранения tensors, дата страницы не установлена. Используется для уточнения границ формата; не обеспечивает честность весов, качество модели или безопасность процесса конвертации из pickle.

## S37
[Trusted-AI: Adversarial Robustness Toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox). README описывает evasion, poisoning, extraction, inference и поддерживаемые estimators. GitHub API 2026-10-06: archived=false. Название библиотеки не доказывает поддержку конкретной атаки нашим estimator; требуется compatibility spike.

## S38
[OWASP SAMM: About](https://owaspsamm.org/about/). Technology/process-agnostic модель зрелости software assurance, не специализированный MLSecOps стандарт. Дата страницы не установлена. Используется для risk-based уровня зрелости, не требования достичь максимума во всех категориях.

## S39
[Sigma: Rules](https://sigmahq.io/docs/basics/rules.html), [официальная спецификация](https://sigmahq.io/sigma-specification/). Формат описания детектирующих правил с logsource и полями, а не готовый ML anomaly detector. Конкретный backend и field mappings пока не выбраны.

## S40
[NIST SP 800-226: Guidelines for Evaluating Differential Privacy Guarantees](https://csrc.nist.gov/pubs/sp/800/226/final), final 2025-03-06. Проверены publication record и scope документа. DP рассматривается как математическая гарантия с условиями и privacy hazards, не синоним маскирования и не функция, которую достаточно включить галочкой.

## S41
[CoSAI: Model Context Protocol Security](https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf). В документе approval date **2026-01-08**; путь загрузки `/2026/03/` не подменяет эту дату. Изучены scope, supply-chain и lifecycle guidance. Это условный GenAI/MCP-трек, не требование установить MCP в CPU reference.

## S42
[CoSAI: Agentic Identity and Access Management](https://www.coalitionforsecureai.org/wp-content/uploads/2026/04/agentic-identity-and-access-control.pdf). Approval Technical Steering Committee **2026-03-20**, не «апрель» по URL. Изучены capability-risk matrix, short-lived scoped identities и lifecycle. Применимость к будущим агентам отделена от контроля обычных ML Jobs.

## S43
[Protect AI: ModelScan](https://github.com/protectai/modelscan). Первичный репозиторий инструмента анализа serialization attacks. GitHub API 2026-10-06: archived=false, pushed_at=2026-09-28T23:10:13Z. Это признак активности репозитория, не гарантия качества, отсутствия CVE или поддержки нашего ONNX профиля.

## S44
[Bethge Lab: Foolbox](https://github.com/bethgelab/foolbox). Описывает adversarial examples для PyTorch/TensorFlow/JAX. GitHub API 2026-10-06: archived=false, pushed_at=2025-12-03T08:37:14Z. Не выбран как обязательная зависимость tabular scikit-learn reference; дата push не равна дате стабильного релиза.
