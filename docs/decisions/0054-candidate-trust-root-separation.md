# ADR 0054: отдельные permit signer и online trust root

Дата: 2026-10-30. Статус: implemented, local contracts passed; native verification pending. T14/CP3/R1-B04. Продолжает [плановую ротацию](0053-authority-root-rotation.md); полного M11/R1 не объявляет.

## Причина

Qualification Reader использовал один public key для подписи permit и online trust-policy. Плановая ротация добавляет старый root в revoked keys. При совмещении ролей это также отзывает неизменный permit, поэтому простая замена root не может восстановить тот же разрешённый кандидат. Удаление старого ключа из revocations или повторная подпись permit скрыли бы этот эффект и не проверили бы требуемый переход.

## Решение

`CandidateReader` получает отдельный явно закреплённый `trust_root_public`. Он обязан совпадать с root переданного Lease и с environment. Отсутствие параметра сохраняет прежний контракт root=permit signer. Новый native профиль всегда создаёт разные ключи authority и qualification permit. Ключи curator/evaluator/publisher и содержимое source proposal не меняются.

В operator config поля `trust_root` и `minimum_trust_version` задают online policy authority, а `permit_public` проверяет только подпись qualification permit. Подписанный permit остаётся в revocation scope: замена root не разрешает использование отозванного permit signer. Новый ключ нельзя получить из ответа trust service или входного HTTP-запроса. Это изменение qualification path, не выдача production approval и не смена release signer.

## Live проверка

1. После фиксации одного source-bound candidate и одного permit подготовить обе authority и additive migrations. Снять полные snapshots; сформировать dual-signed package до начала измеряемого перехода.
2. Запустить реальный HTTP app/Engine с отдельным Kubernetes worker и прежним root. Успешное начальное предсказание задаёт консервативную нижнюю границу времени последней trust read.
3. По handshake `ready` trusted host coordinator применяет package к primary authority. Ключи и SQL admin credentials не передаются serving Pod. Callback не выполняет весь предварительный negative suite.
4. Зафиксировать timestamped 200/503 trace: первый завершённый 503 <=60 s от нижней границы, отсутствие ML после первого отказа, ready=503 и точный cold refusal `trust_authority_missing_or_foreign`. Старый Engine остаётся fenced.
5. Закрыть прежний Engine и проверить отсутствие worker. Создать новый Engine с заранее явно заданными root/version и прежними permit bytes, proposal и model. Проверить HTTP contract, digest и golden predictions.
6. Проверить primary history/revocations, exact retry и неизменность peer. Затем отдельной операторской транзакцией ротировать peer с сохранением его собственной истории; primary и model/promotion storage должны остаться прежними. Это две последовательные операции, не распределённая атомарная транзакция.
7. Продолжить прежние actual-candidate faults и независимые terminal revocations новым authority key. Для каждого authority operator закрепляет его собственный version floor: версии разных histories не обязаны совпадать.

Максимальное время жизни permit 600 s и предел остановки ML 60 s не изменены. При недостатке окна эксперимент отказывает. Не создаётся второй permit для скрытого продления работы. Сбой после primary commit оставляет наблюдаемое промежуточное состояние; old root автоматически не возвращается.

## Проверка и границы

Новые RED tests подтвердили отсутствие явного root binding, root fault и recovery path. Локальная группа из 77 methods прошла без infrastructure startup. Проверены подписи с отдельным root, сохранённый отказ revoked permit signer, неверный root/floor, точная причина cold refusal, новый Engine, ошибочный/неполный trace, late ML, нечисловые timestamps, изменённые snapshots, неизвестный commit и ошибочный retry. Native runner ещё должен подтвердить реальные timings, источник образа и cleanup.

Изменяемые части: [Reader](../../mlsecops/candidate_serving_reader.py), [HTTP probe](../../mlsecops/kube_candidate_probe.py), [host coordinator](../../scripts/kube_candidate_root.py), [native pipeline](../../scripts/kube_candidate_native.py). [Ранбук](../operations/authority-root-rotation.md). Для полной приёмки сохраняются release-signing key rotation, M22 independent challenges, image findings и остальные обязательные gates.
