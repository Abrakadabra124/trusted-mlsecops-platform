# ADR 0017: tracking как отдельный недоверенный к выпуску сервис

Дата: 2026-10-11. Статус: offline API/auth spike реализован; PostgreSQL/TLS deployment не принят. Scope: T07/T08 и M06, без ослабления M01-M23. [Реализация и границы](../tracking-spike.md).

## Требование

Три fresh-process обучения должны иметь отдельные tracking runs с проверяемыми ссылками на данные, код, policy, image и outputs. Изменение seed/data/environment нельзя считать повторением прежнего эксперимента, даже если predictions совпали. Потеря tracking metadata не меняет одобренный runtime release.

## Границы реализации

- Проверить MLflow 3.17.0 с auth extra в отдельном dependency lock. Не добавлять MLflow SDK и credentials в offline training/prediction image и не менять рабочие volumes/SQL schema.
- Сначала разрешить и проверить pinned зависимости, затем проверять отдельный lab service. Сбой загрузки/audit означает inconclusive, известные блокирующие findings означают fail; переход к deployed runtime не происходит автоматически.
- Для целевого сервиса нужна отдельная PostgreSQL metadata DB и auth DB/role, недоступные trainer. Запись выполняет внешний publisher после проверки артефактов. MLflow aliases/tags/metrics не являются подписью или release approval.
- Basic auth требует TLS на доступном клиенту endpoint, с проверкой CA/hostname. Default permissions должны быть NO_PERMISSIONS, publisher получает только необходимые права на выделенный experiment. Реальными requests проверить anonymous/foreign denial и positive controls. Наличие настройки не доказательство запрета доступа.
- Не использовать pickle/autolog/model loader MLflow в доверенном процессе: модель остаётся проверенным ONNX artifact. Не вводить AI Gateway/LLM/agents, дополнительные orchestrators, платное облако или новые внешние credentials.
- Только синтетические runs и owned test resources. Никаких настроек глобального pip/uv, отключения TLS или подмены рабочего environment.

## Критерий следующего increment

Предварительный Linux probe использует два одноразовых SQLite files и loopback HTTP внутри `--network none`, без публикации host ports. Это намеренно не внедряемая topology: она проверяет API/auth/version compatibility перед изменениями постоянного storage. Локально 53 реальные HTTP проверки и три свежих training runs прошли. PostgreSQL/TLS требование остаётся обязательным, SQLite не становится финальным решением.

Digest-bound runs, отдельная identity publisher, три независимых обучения, mutation negative tests, проверенный auth/artifact access и повторение после restart. Пока dependency spike не завершён, T08/M06 остаются открытыми; это не причина задерживать независимые reproducibility contracts T07.

## Основания и ограничения

- [Версия MLflow 3.17.0](https://pypi.org/project/mlflow/3.17.0/): выбранный кандидат, а не плавающий latest; Apache-2.0, Python >=3.10.
- [MLflow authentication](https://mlflow.org/docs/latest/self-hosting/security/basic-http-auth/): auth extra, secret key, configurable default permission и RBAC. Современная документация описывает другой API grants, чем старые примеры; проверить API установленной версии до реализации клиента.
- [Tracking architecture](https://mlflow.org/docs/latest/self-hosting/architecture/overview/): metadata backend отделён от artifact storage.
- [Backend stores](https://mlflow.org/docs/latest/self-hosting/architecture/backend-store/): SQL backend и migrations требуют отдельной recovery процедуры.

Это проектный выбор, не доказательство отсутствия vulnerabilities. Известные image findings продолжают блокировать release. Успешный dependency audit не покрывает все HTTP routes, artifact authorization или operating-system packages.
