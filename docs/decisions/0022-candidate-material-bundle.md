# ADR-0022: Закрытый verification bundle до release approval

Дата: 2026-10-11. Статус: **Accepted для foundation T13**, полный [ADR 0002](0002-release-trust.md) не закрыт.

## Контекст

Проверка lineage требует manifest/lineage/candidate/evaluation. Serving имеет SELECT только на releases. Выдать ему publisher/promoter/scorer credentials означало бы расширить доверенную область. Копировать только model digest недостаточно: digest не доказывает происхождение или independent evaluation. При этом полные gates ещё не приняты, поэтому нельзя выдать signature комплекта за разрешение на запуск.

## Решение

Сохранить минимальное замыкание проверяемых материалов в существующем CAS releases. Отдельный DSSE payload type `candidate-materials` и постоянный unapproved state отделяют evidence transport от release approval. Общий `candidate_lineage.reconcile` принимает bounded source callback; существующие SQL readers получают необязательный explicit reader. Их проверки подписи/subject не дублируются и не заменяются глобальным monkeypatch в runtime.

Primary source сверена 2026-10-11: [DSSE protocol v1.0.2](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md). Подписываются точные serialized bytes вместе с payload type; тип описывает смысл/schema, keyid не является основанием доверия. В нашем приложении authorization определяется переданным trusted public key и проверкой signature, а не keyid из envelope. Parsed payload берётся из проверенных bytes. Формат application-specific, без заявления in-toto compatibility или SLSA certification.

Trust/configuration остаются вне bundle. Внешний signer должен отличаться от curator/evaluator. Каждая операция сохраняет `release_ready=false`; даже корректно подписанная capsule с quality failure не получает approval. Полный [контракт](../material-bundle.md) перечисляет material set, bounds и API.

## Альтернативы

- Serving с доступом ко всем metadata tables увеличил бы полномочия и требовал бы migration. Текущие grants не меняются.
- ZIP/tar artifact добавил бы path/extraction risk, ещё один формат и credentials transport. Сейчас достаточно существующего immutable SQL CAS; не нужен новый object-store service.
- Отдельный упрощённый verifier мог бы пропустить semantic checks или разойтись с SQL implementation. Explicit reader сохраняет единую проверку.
- Подписать сразу полный release невозможно без обязательных материалов и принятого gate set. Capsule не подменяет этот конечный результат.

## Последствия и пересмотр

Publication не атомарна между objects, но индекс идёт последним, каждый receipt/readback проверяется. При interrupted write допускаются orphaned immutable objects, не approved state. Автоматическое удаление или reset запрещены. [PB-11/RB-23](../operations/material-bundle-troubleshooting.md) описывает безопасный повтор.

Это trusted-host lab foundation. Следующий этап обязан добавить full release schema, authenticated requests, signed policy/approval, sequencing, revocation и scoped controllers. Полный source/build attestation, ML-BOM, model card и model intake gate не становятся реализованными только потому, что capsule содержит evaluator scan receipt.
