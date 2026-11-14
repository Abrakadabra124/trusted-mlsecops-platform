# M17. Восстановление SQL и оценённого кандидата

Владелец интеграции запускает `scripts.m17_restore_native.capture` на одноразовом
hosted runner с исходной SQL lab, завершённым `storage_pipeline.demo` и доступным
worker image этой модели. Подготовьте отдельный свободный порт и новый путь target.
Оператор должен иметь право остановить source. Закрепите SHA-256 точных байтов
`storage-demo.json` и SHA-256 канонического JSON доверенного набора публичных
ключей из независимого входа владельца. Эти значения нужны до начала операции.

```python
from scripts.m17_restore_native import capture, replay

packet = capture(root, state, target, image, demo_pin=demo_pin, keys_pin=keys_pin,
                 port=15440, backup_pin=daily_receipt["backup_id"])
```

Передайте `backup_id` из проверенной инвентарной записи
`daily_backup.execute("verify", state, owner_path, inventory)`. Подписанная копия
v2 с временем snapshot должна лежать в `state/backups/<backup_id>`. Этот путь
использует существующие байты. До остановки source адаптер проверяет подпись,
правильный workspace, внешний pin и архив. Для подготовки такой копии timer
вызывает `python -m mlsecops.storage_backup --state STATE --include-promotion --recovery-point`.
В объединённом hosted-сценарии `daily_backup_systemd_native.capture(root, state,
owner_path, inventory)` агента расписания возвращает `(receipt, scheduler)`.
Возьмите `backup_pin` из `receipt["backup_id"]`, а `keys_pin` вычислите как
`digest(canonical(owner["trusted_keys"]))` по отдельному файлу владельца.
Для самостоятельного упражнения параметр `backup_pin` можно опустить.
При наличии promotion journal передайте `include_promotion=True`. В backup
сохраняются публичные привязки и данные SQL.
Ключи новых подписей и актуальные решения независимой trust authority требуют
отдельного восстановления.

Сохраните `packet` приватно через `contracts.write_json`. На выходе capture закрепите
SHA-256 **записанных байтов** пакета (включая перевод строки) и ID backup из
`packet["receipt"]["backup_id"]` в выходах владельца. Для повторной проверки
сначала сравните байты файла с этим SHA-256, затем передайте декодированный пакет
в `replay(packet, backup_pin=backup_id, demo_pin=demo_pin, public=public, policy=policy)`.
Используйте исходные закреплённые публичные ключи и policy. Пакет содержит
внутренний отчёт демонстрации, идентификаторы ресурсов и два ряда golden scores.
Для публичного отчёта используйте результат replay.

RPO для данного отказа измеряется от времени SQL-команды, получившей
repeatable-read snapshot, до начала остановки source. Время SQL записано в
подписанный manifest. Предварительная проверка закреплённой копии завершается
при работающем source. Таймер RTO стартует непосредственно перед вызовом остановки.
Он включает повторную проверку backup при restore, создание target, импорт, проверку подписей
dataset/evaluation, повторное чтение validation из target, сравнение 1 000
предсказаний и итоговую проверку ledger и состояния source. Допуски составляют
900 секунд на восстановление, 24 часа на возраст точки и `policy["repeat_tolerance"]`
на максимальную абсолютную ошибку. Вместе с результатом сохраняется интервал
по настенным часам. Значения одного прогона относятся к этой копии и этому отказу.

После остановки source адаптер оставляет его остановленным. Target остаётся у
владельца для проверки approvals, отзыва ключей и serving readiness. При ошибке
сохраните backup и partial target, сверьте ownership и receipt по
[процедуре восстановления](promotion-recovery-troubleshooting.md).
Затем выполните cleanup принадлежащих прогону ресурсов. Для полного M17 нужны
проверки допуска и отзыва до ready, измерение времени до этой границы и evidence
ежедневных резервных копий.
