# ADR 0027: PostgreSQL journal вместо изменяемого alias

Дата: 2026-10-14. Статус: реализация локального increment; native qualification pending до evidence. Полный M10/M11/M17 не закрыт.

## Контекст

Verified approval без постоянного sequence допускает повтор и конкурентные изменения. CAS обеспечивает неизменяемость байтов, но не уникальность пары environment/sequence. Переписывать checksum исходной database schema нельзя: существующая лаборатория должна оставаться проверяемой и не мигрироваться скрыто.

## Решение

Добавить отдельную schema ml_promotion, immutable event history, head и pinned authority. Trusted promoter вызывает единственную ограниченную SECURITY DEFINER функцию; остальные DML grants не выдаются. Row lock сериализует один environment, independent environments не требуют общей глобальной блокировки. Expiry пересчитывается по server clock после ожидания, не только на входе SDK.

SDK проверяет signed chain до CAS/ledger writes. Selection request получает время исходного approval, поэтому retry с теми же документами детерминирован. Старый sequence не возвращает head назад, current exact duplicate не добавляет событие. Ошибка commit/readback не становится false success.

Старый backup отказывается работать с новым ledger; существенная scope-проверка выполняется в экспортируемом snapshot, не только отдельным preflight. Полная согласованная recovery chain требует следующего increment, до него работа с journal остаётся явной лабораторной квалификацией без разрешения deployment.

## Проверенные первоисточники

- [PostgreSQL 18: explicit locking](https://www.postgresql.org/docs/18/explicit-locking.html), проверено 2026-10-14. Row lock удерживается транзакцией; ожидающий writer получает актуальную строку после освобождения lock.
- [PostgreSQL 18: CREATE FUNCTION](https://www.postgresql.org/docs/18/sql-createfunction.html), проверено 2026-10-14. SECURITY DEFINER требует безопасного search_path и ограничения EXECUTE, а не общих привилегий пользователю.

Это применение механизмов PostgreSQL, не обещание защиты от администратора БД или скомпрометированного trusted controller. Loader обязан перепроверять proof; SQL row и registry alias не становятся достаточным разрешением.

## Альтернативы

File-based counter плохо согласуется с уже используемой SQL identity/backup и конкурентными процессами. Scan append-only CAS не даёт уникального sequence без отдельной транзакционной координации. Выдача promoter общих UPDATE/DELETE излишне расширяет полномочия. Новый оркестратор, очередь или отдельная БД пока не нужны для одной короткой транзакции.
