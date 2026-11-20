# Bootstrap с исходным trust key

Неделя 13, T21, Task 1. Компонент позволяет producer создать исходную trust
identity из заранее подготовленного приватного файла. Это API prerequisite для
cross-job delivery, не завершение hosted provisioning или M18/R1.

Код: [bootstrap](../../mlsecops/bootstrap.py).
Проверки: [original trust qualification](../../scripts/bootstrap_trust_qualification.py).
Прежний [bootstrap contract](../../scripts/bootstrap_qualification.py) сохраняется.

## Контракт вызова

```python
from mlsecops.bootstrap import initialize

result = initialize(root, state, trust_key_path=private_trust_file)
```

`trust_key_path` - необязательный keyword-only аргумент. Без него fresh bootstrap
по-прежнему генерирует четыре роли, а повторный вызов проверяет прежние ключи.
CLI не расширен: приватные bytes не передаются в аргументах командной строки.
Вызывающий orchestration передаёт путь к подготовленному приватному файлу.
Результат сохраняет прежнюю схему с digest workspace, public keys и policy.

Ответственный - доверенный оператор producer. До вызова он обеспечивает
закреплённое окружение, обычные inventory prerequisites, доверенные родительские
каталоги и одного владельца инициализации. Разрешён только новый или пустой
каталог либо ранее созданный полностью согласованный workspace. Сам bootstrap
по-прежнему вызывает inventory с Docker inspection; приведённый API не является
разрешением запускать локальную инфраструктуру. Компонентные тесты заменяют
inventory контролируемым результатом и не запускают Docker, Kubernetes или SQL.

## Проверка и запись

1. Обычный [private-file reader](../../mlsecops/key_files.py) читает не более
   4096 bytes. Он отвергает symlink файла/непосредственного родителя, hardlink,
   нерегулярный или недоступный файл, превышение размера и обнаруженное изменение
   во время чтения. На POSIX он также проверяет владельца и отсутствие group/other
   permissions по открытому descriptor.
2. Bootstrap разбирает один полученный snapshot как незашифрованный Ed25519
   private key. Пустой, повреждённый, public-only, зашифрованный ключ или другой
   алгоритм дают отказ до inventory и любых записей state. Повторного чтения
   внешнего файла для импорта нет: последующая подмена пути не меняет snapshot.
3. Для существующего workspace проверяются ownership marker, все четыре private
   keys и их соответствие `trusted-keys.json`. Переданный original key должен
   иметь ту же публичную identity, что сохранённый `trust`. Другая корректная PEM
   сериализация той же identity допустима, но сохранённые bytes не заменяются.
   Несогласованный workspace отвергается до inventory и изменения файлов.
4. После успешного inventory fresh bootstrap сначала записывает ownership marker,
   затем создаёт обычные `curator`, `evaluator`, `approver` и импортирует исходные
   bytes в `keys/trust.pem`. Импорт использует exclusive create, приватный режим
   и fsync через тот же private-file helper. Существующий destination не заменяется.
5. После записи всех ключей публикуется public registry. Затем создаются обычные
   каталоги и inventory. Повторный запуск сохраняет ownership, все роли и данные;
   inventory обновляется по прежнему контракту.

Public registry содержит только verification keys. Исходные private keys
`curator`, `evaluator`, `approver` остаются в producer. Consumer получает тот же
`trust` через отдельный разрешённый secret channel и проверяет frozen registry.
Этот компонент не доставляет secrets, не меняет [frozen transfer allowlist](frozen-candidate-transfer.md)
и не помещает private key в frozen evidence, Actions artifacts, outputs или Git.
Подготовленный state и исходный файл нельзя архивировать целиком.

## Отказ и восстановление

| Симптом | Проверка без раскрытия ключа | Действие |
| --- | --- | --- |
| `invalid_signing_key`, `wrong_key_algorithm` | Тип, размер, способ подготовки файла; не печатать PEM или parser traceback | Исправить внешний provisioning до создания state |
| `signing_key_file_*`, `symlink_key` | Владелец, mode, тип файла и link count; доверенность родителя | Исправить внешний путь/доступ, не обходить reader |
| `refusing_nonempty_unowned_workspace` | Наличие чужих файлов и ownership marker | Выбрать другой неиспользованный каталог, не присваивать существующий |
| `key_rotation_requires_explicit_migration` | Сопоставить только public identities и исходную authority | Остановить запуск; замена registry не является rotation procedure |
| Прерывание после marker, до registry | Наличие marker, полный набор private files, наличие registry | Сохранить state для приватного разбора; retry обязан отказать, не генерируя недостающие ключи |
| Ошибка после полной публикации ключей/registry | Проверить их согласованность штатным повторным вызовом | Retry может завершить каталоги/inventory без замены identity |

Не удалять marker и не достраивать отсутствующие ключи вручную ради зелёного
bootstrap. Если state неполон, требуется отдельное решение владельца о recovery
или новой попытке в другом каталоге; исходный partial state автоматически не
удаляется. Ошибка inventory до создания state оставляет отсутствующий/пустой
каталог нетронутым. Это fail-closed повторный вход, не транзакция над всеми файлами.

## Проверка компонента

В изолированном checkout с Python 3.12 и закреплёнными зависимостями:

```powershell
$python = './.venv/Scripts/python.exe'
$coverageFile = Join-Path ([IO.Path]::GetTempPath()) 'bootstrap-trust.coverage'
& $python -B -W error -m coverage run --branch --data-file=$coverageFile --source=mlsecops.bootstrap -m unittest scripts.bootstrap_trust_qualification scripts.bootstrap_qualification scripts.foundation_qualification scripts.key_files_qualification scripts.consumer_candidate_state_qualification
& $python -B -m coverage report --data-file=$coverageFile -m
& $python -B -m ruff check --no-cache mlsecops/bootstrap.py scripts/bootstrap_trust_qualification.py
& $python -B -m ruff format --check --no-cache mlsecops/bootstrap.py scripts/bootstrap_trust_qualification.py
& $python -B scripts/check_docs.py
```

Порог применяется отдельно к statements и branches всего `mlsecops.bootstrap`,
без coverage exclusions. Тесты используют настоящие Ed25519 files, подписи и
public registry. Fault injection охватывает остановку создания ролей, частичную
запись trust key, столкновение destination, остановку перед registry и ошибку
записи inventory. Проверяются сохранённые bytes/ownership и поведение retry.

Проверено 2026-11-20 на Windows с Python 3.12.15: перечисленный прогон выполнил
78 tests, 0 failures/errors, 4 POSIX-only skips. Новый модуль содержит 21 test,
из них один POSIX-only. Для всего `mlsecops.bootstrap` покрыты 73/73 statements
и 26/26 branches, excluded lines отсутствуют; оба порога проверены отдельно.
Ruff lint/format и документационный validator прошли. Проверка ключей и подписей
реальная, только inventory заменён fixture; дополнительные faults вводятся на
границах чтения/записи. Windows symlink/hardlink cases выполнены, read-denial
проверен инъекцией `PermissionError`. Выполнен self-review по Task 1 и исходному
контракту; независимый reviewer не запускался.

## Границы доказательства

Native POSIX validation остаётся pending. Windows-прогон не доказывает POSIX
ownership/mode enforcement, descriptor-relative no-follow или устойчивость к
Linux filesystem races. POSIX-only tests должны пройти отдельно в разрешённом
Linux окружении. Windows ACL/reparse и враждебная замена доверенных родительских
каталогов сохраняют ограничения существующего private-file helper.

Вызовы для одного state должны выполняться последовательно: это не конкурентный
transaction manager и не защита от администратора runner. Совместное хранение
trust identity в producer/consumer не доказывает независимость администраторов.
Реальные secrets, cross-job provisioning, native campaign и интеграция exact
source-only image этим изменением не проверяются. M01-M23 и сроки исходной
кампании не изменены.
