# Ограниченный перенос публичного source-only image

Процедура переносит только образ `trusted-mlsecops:dev`, собранный из разрешённых
публичных source files и проверенного Dockerfile. Это проверка переноса exact image
между отдельными GitHub-hosted jobs. `python -m mlsecops.worker --help` проверяет
обычный CLI (command-line interface), но не обучение, inference, frozen candidate,
принятие ML release или общий M18/R1.

## Контракт и состояние проверки

Репозиторий: `Abrakadabra124/trusted-mlsecops-platform`, numeric ID `1407811916`,
public, не fork. Эти свойства проверены публичным GET 20 ноября 2026 и повторно
проверяются реальным GitHub API (application programming interface) в каждом job.
Исполнение ограничено веткой `qualify/source-image-transfer` и файлом
[source-image-transfer.yml](../../.github/workflows/source-image-transfer.yml).

Локально выполнены controlled tests без Docker и без изменения GitHub:
30 tests [core](../../scripts/ci_source_image_qualification.py), 22 tests
[driver](../../scripts/ci_source_image_native_qualification.py), 18 соседних tests
API transport. Все 70 прошли без skips. На этом снимке core: 244/244 statements,
30/30 branches; driver: 174/174 statements, 30/30 branches. Это результат fixtures,
а не native transfer. Совместный preflight семи modules с обновлённым bootstrap
из родительского checkout: 130 tests, 126 pass и 4 POSIX-only skips на Windows;
bootstrap: 73/73 statements, 26/26 branches. Каждый из трёх modules отдельно
прошёл оба порога 95%. Hosted Linux должен пройти без skips.

Hosted producer/receiver, фактический размер image, время исполнения, удаление
GitHub artifact и внешний readback после настоящего run пока **pending**.
Успех этих локальных тестов не снимает этот статус. Результаты будущего run нужно
записать с его URL, SHA, attempt, artifact ID и итогом каждого job.

## Предпосылки и ответственность

Владелец qualification проверяет интегрированный commit: core, driver, bootstrap,
tests и workflow. Review обязателен до разрешённого push qualification-ветки.
Ни приватные модели, ни dataset, ни keys, ни runtime state в этот канал не входят.
Тесты bootstrap создают только временные fixture keys и не используют реальные.

Нужны три свежих `ubuntu-24.04` GitHub-hosted runners, доступ к public repository
и закреплённым dependency sources. Переиспользования self-hosted runner, cache
образов, privileged service, cluster, SQL, registry publication или local Docker
эта процедура не предусматривает. Core требует Linux Docker с classic `overlay2`:
платформа закрепляет config image ID; containerd manifest/index ID не принимается.
Несовместимый image store даёт отказ, а не автоматическую смену формата identity.

Используются уже закреплённые SHA actions и версии `uv 0.12.23`, Python `3.12.15`,
`uv.lock`; процедура не обновляет packages. У producer/receiver `contents: read`
и `actions: read`. Только cleanup получает `actions: write`. Checkout выключает
сохранение credentials. API transport запрещает redirects, ограничивает ответ
1 MiB и timeout одного запроса 30 секунд; токен не печатается.

## Подготовка и запуск

Проверить clean integrated checkout и выполнить локальный preflight:

```bash
git status --porcelain --untracked-files=all
git rev-parse HEAD
uv sync --locked --no-build --python 3.12.15
uv run --locked ruff check scripts/ci_source_image.py scripts/ci_source_image_qualification.py scripts/ci_source_image_native.py scripts/ci_source_image_native_qualification.py mlsecops/bootstrap.py scripts/bootstrap_trust_qualification.py
uv run --locked ruff format --check scripts/ci_source_image.py scripts/ci_source_image_qualification.py scripts/ci_source_image_native.py scripts/ci_source_image_native_qualification.py mlsecops/bootstrap.py scripts/bootstrap_trust_qualification.py
uv run --locked python scripts/check_docs.py
uv run --locked python -B -W error -m coverage run --branch --source=scripts.ci_source_image,scripts.ci_source_image_native,mlsecops.bootstrap -m unittest scripts.ci_source_image_qualification scripts.ci_source_image_native_qualification scripts.bootstrap_trust_qualification scripts.bootstrap_qualification scripts.foundation_qualification scripts.key_files_qualification scripts.consumer_candidate_state_qualification
uv run --locked python -m coverage json -o .coverage-source-image.json
uv run --locked python - <<'PY'
import json
from pathlib import Path
files = json.loads(Path('.coverage-source-image.json').read_bytes())['files']
files = {name.replace('\\', '/'): entry for name, entry in files.items()}
expected = {'scripts/ci_source_image.py', 'scripts/ci_source_image_native.py', 'mlsecops/bootstrap.py'}
if set(files) != expected:
    raise SystemExit('Coverage inventory differs')
for name, entry in files.items():
    stats = entry['summary']
    for covered, total in (('covered_lines', 'num_statements'), ('covered_branches', 'num_branches')):
        if stats[total] <= 0 or stats[covered] * 100 < stats[total] * 95:
            raise SystemExit('Coverage below 95%: ' + name)
print('All three modules meet both individual thresholds')
PY
```

Первый `git status` должен быть пустым. На Windows POSIX-only bootstrap checks
могут быть skipped; такой прогон не заменяет hosted Linux preflight. Workflow
сам запускает все семь test modules, запрещает любые skips и проверяет отдельно
statements и branches каждого из трёх production modules. Среднее coverage всех
модулей не заменяет individual thresholds.

Начальный запуск выполняется **одним push** reviewed commit в точную
qualification-ветку после разрешения владельца. Новый workflow ещё не находится
на default branch `main`, поэтому начальный `workflow_dispatch` не используется.
Main не меняется ради регистрации workflow. `workflow_dispatch` оставлен как
возможность после будущей регистрации; guard принимает его только для той же
ветки и сверяет фактический event с run API. После push не отправлять отдельный
dispatch. Существующие push workflows на проверенном base используют другие
точные branches; эта ветка не входит в их фильтры. Открытие PR - отдельное событие
и может запустить PR workflows, поэтому не входит в данную процедуру.

До нового запуска проверить, что предыдущий run завершён и его artifacts очищены.
Concurrency group `source-image-transfer` общая для ветки, `cancel-in-progress:
false`. Это сериализует runs, но не ограничивает число вручную поставленных
запусков; владелец не должен ставить повторные runs без необходимости.

## Что делает workflow

1. Producer сверяет настоящий `GITHUB_JOB` до команд, Linux/hosted/ubuntu24/X64,
   event, workflow ref/SHA, branch, numeric repo ID и clean Git HEAD. Реальный API
   подтверждает public/nonfork identity, опубликованный commit и run/attempt/SHA,
   workflow path и оба repository identities.
2. Driver создаёт новый 64-hex owner в `RUNNER_TEMP/source-image-owner.json` вместе
   с run/attempt/job/SHA/repository ID. Это закрытая локальная запись с exclusive
   create, mode 0600 и проверкой type/link/size/fields. RUNNER_TEMP находится вне
   checkout. Ожидаемый owner никогда не читается из download directory.
3. Core `prepare(..., owner=...)` создаёт свежий owned directory и marker,
   строит ограниченный контекст из committed allowlist, проверяет pinned recipes,
   собирает image, проверяет его labels/ID, сохраняет tar и gzip. Archive metadata
   и layer/config identity сверяются до допуска к публикации. Owner не входит
   в build context.
4. Producer повторно сверяет source и API authority. В `GITHUB_OUTPUT` пишет
   только закрытую receipt: schema version, source revision/fingerprint, image ID,
   SHA-256 и byte count gzip/tar. В receipt нет owner или иных секретов.
5. Upload содержит ровно `.runtime/source-image/image.tar.gz`, имя
   `source-image-{run_id}-{run_attempt}`, compression level 0, retention 1 день,
   `overwrite: false`. Marker, логи, keys и произвольные файлы не публикуются.
6. Receiver на отдельном свежем runner проверяет producer receipt и API artifact
   по ID до download: имя, размер, expired flag, owner run, head SHA/branch и оба
   repo IDs. Создаёт свой независимый owner и `workspace_create` до download.
   Download выбирает только producer artifact ID текущего run.
7. Core `receive(..., expected, owner=...)` принимает только owned directory с
   `owner.json` и `image.tar.gz`, проверяет точные producer pins и загружает image.
   Receiver не переиздаёт pins. CLI smoke использует ordinary worker `--help`;
   временный контейнер явно удаляется с проверкой отсутствия. Owner передаётся
   также локальной очистке; повторная очистка отсутствующего directory даёт 0.
8. Cleanup job с `always()` проверяет полный доступный список artifacts этого
   run, допускает максимум один и проверяет каждую запись до любого DELETE.
   Перед удалением ещё раз проверяет authority и отдельную artifact record.
   После DELETE требует именно GET 404 для этого ID и доступный пустой run list.
   Access denied, иная попытка, foreign artifact и изменение identity дают отказ.

Producer ограничен 20 минутами, receiver 8, cleanup 5. Gzip максимум 384 MiB;
GitHub ZIP максимум 385 MiB с 1 MiB запасом на упаковку; распакованный tar максимум
2 GiB. Это границы одного artifact/run, а не резервирование GitHub quota. На
runner временно сосуществуют gzip, tar и Docker layers, поэтому 385 MiB не является
лимитом всего диска runner. Actions logs/metadata также не входят в этот лимит.

## Read-only диагностика и критерий успеха

В shell оператора задать `RUN_ID`, `RUN_ATTEMPT`, `SOURCE_SHA` по проверенному run.
Значения не брать из скачанного artifact. GitHub CLI должен быть авторизован;
не выводить token, raw job logs, owner records или private files.

```bash
REPO=Abrakadabra124/trusted-mlsecops-platform
gh api "repos/$REPO" --jq '{id,full_name,private,fork,visibility}'
gh api "repos/$REPO/actions/runs/$RUN_ID" --jq '{id,run_attempt,head_sha,head_branch,event,path,status,conclusion}'
gh run view "$RUN_ID" --repo "$REPO" --json status,conclusion,url,jobs
gh api "repos/$REPO/actions/runs/$RUN_ID/artifacts?per_page=100" --jq '{total_count,artifacts:[.artifacts[]|{id,name,size_in_bytes,expired,workflow_run}]}'
```

Успех требует producer/receiver/cleanup `success`, локальных status `pass`,
receipt с исходными pins, ожидаемого ID и независимого API readback с
`total_count=0`, `artifacts=[]`. Для известного удалённого `ARTIFACT_ID` отдельно
проверить GET 404 через `request('GET', path, absent=True)`; любой иной отказ не
считать отсутствием. Успешный DELETE без этих наблюдений недостаточен.

## Отказы, отмена и ограниченная очистка

При guard failure не менять guard, API identities или receipt ради зелёного run.
Сначала сверить SHA, job, branch, event, repo visibility и image store. При
превышении лимитов остановиться и пересмотреть source image отдельно; не
увеличивать лимит после наблюдения результата без review. При несовпадении
producer pins receiver должен отказаться до Docker load.

Если отсутствует external owner record, локальная очистка возвращает 0 только
при отсутствии directory. Если directory существует, отсутствующий/чужой marker,
hardlink, symlink или неизвестный entry означает отказ без удаления. Не копировать
owner из каталога и не делать `rm -rf`, `docker system prune` или global artifact
delete. Потерянный disposable runner не требует локального восстановления;
повтор выполняется на новом runner и новом run после контроля остаточного artifact.

Отмена всего workflow или инфраструктурный сбой может не дать `always()` cleanup
завершиться. Retention 1 день - fallback, а не доказательство немедленного удаления.
Дождаться terminal status старого run и проверить его exact artifacts. Не делать
rerun для очистки старой попытки: новый `run_attempt` намеренно не владеет её именем.
Не запускать ещё один перенос, пока судьба остатка не установлена.

После отдельного разрешения владельца на удаление остатка выполнить следующий
узкий recovery из reviewed integrated checkout. Это API-only операция, не native
driver execution: она не подделывает hosted environment и не запускает Docker.
`GH_TOKEN` уже должен быть безопасно передан в environment без вывода. Значения
`RUN_ID`, `RUN_ATTEMPT`, `SOURCE_SHA` относятся к исходной попытке.

```bash
uv run --locked python - <<'PY'
import os, re
from scripts.ci_source_image_native import (
    BRANCH, REPOSITORY, REPOSITORY_ID, WORKFLOW, artifact_path,
    cleanup, need, number, request, same,
)
run = number(os.environ['RUN_ID'])
attempt = number(os.environ['RUN_ATTEMPT'])
sha = os.environ['SOURCE_SHA']
need(re.fullmatch(r'[a-f0-9]{40}', sha) is not None)
environment = {'GITHUB_RUN_ID': str(run), 'GITHUB_RUN_ATTEMPT': str(attempt), 'GITHUB_SHA': sha}
identity = dict(id=REPOSITORY_ID, full_name=REPOSITORY, private=False, fork=False)
def reauthorize():
    repo = request('GET', 'repos/' + REPOSITORY)
    same(repo, identity | {'visibility': 'public'})
    same(repo.get('owner'), {'login': 'Abrakadabra124'})
    same(request('GET', f'repos/{REPOSITORY}/commits/{sha}'), {'sha': sha})
    record = request('GET', f'repos/{REPOSITORY}/actions/runs/{run}')
    same(record, dict(id=run, run_attempt=attempt, head_sha=sha, head_branch=BRANCH,
                     path=WORKFLOW, status='completed'))
    need(record.get('event') in ('push', 'workflow_dispatch'))
    for field in ('repository', 'head_repository'):
        same(record.get(field), identity)
reauthorize()
print({'artifacts_deleted': cleanup(request, environment, reauthorize)})
# If read-only diagnosis recorded an ID, repeat its absence check independently.
if os.environ.get('ARTIFACT_ID'):
    identifier = number(os.environ['ARTIFACT_ID'])
    need(request('GET', artifact_path(identifier), absent=True) is None)
PY
```

Recovery использует тот же полный-list/individual-record/404/empty-list contract,
ничего не удаляет по одному имени. Если run уже перезапущен, identity изменилась,
list неполон/недоступен или artifact чужой, остановиться и передать владельцу
только публичные run/SHA/ID и тип отказа. Не обходить проверку ownership.
После успешного recovery повторить независимую read-only диагностику выше.
Эта remote recovery процедура ещё не проверена на реальном отменённом run;
API failure paths проверены controlled fixtures.

## Разобранные controlled проблемы

В Windows fixture Git archive учитывал глобальный `core.autocrlf` и менял LF на
CRLF, поэтому проверка content digest правильно отказывала. Core закрепляет для
архива `-c core.autocrlf=false -c core.eol=lf`; ожидаемый digest не ослаблялся.
Это обнаружение в controlled test, не native/production incident.

Review также выявил опасность preexisting `probe.cid` и удаления чужого
`image.tar` очисткой только по имени. Исправление требует fresh owned namespace,
external owner authority и точного начального набора receiver entries до Docker.
Core и driver тестируют отказ без чужого удаления. Hosted подтверждение остаётся
pending, как и actual build/upload/download/readback. Bootstrap qualification
проверяет временные trust fixtures; она не разрешает публикацию настоящих ключей.
