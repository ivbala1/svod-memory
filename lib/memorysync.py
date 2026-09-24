#!/usr/bin/env python3
"""Синхронизация и статус (Свод-0, шаг 3).

Таймер обходит репозитории карты, что есть на диске, каждый под его
замком: сервер впереди, fast-forward; локально впереди, проверка и push;
расхождение, rebase на отсоединённой вершине; конфликт человеку словами;
повтор ожидающих кандидатов. Итог по репозиторию пишется в кэш
`sync/<область>.json`: показ, решений по нему никто не принимает.

Статус выводится из git и двух каталогов (ожидание, отказы) плюс кэш.
Статус называет и то, что разъедает доставку (Свод-0, шаг 5, взамен
компактора): индекс выше порога, дрейф записей тем в индекс, раздел сводки
выше потолка; тем же измерением, каким писатель отказывает.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
import traceback

from memoryctl import utc_now
import memoryremember
import svodgit


HOOKS_DIR = (Path(__file__).resolve().parents[1] / "githooks")
HOOK_NAMES = ("pre-commit", "pre-push")


# ---------------------------------------------------------------------------
# Хуки

def hooks_state(root: Path) -> tuple[bool, str]:
    """(стоят, слова): core.hooksPath указывает на каталог хуков движка."""
    result = svodgit.git(root, "config", "--get", "core.hooksPath", check=False)
    value = result.stdout.decode().strip() if result.returncode == 0 else ""
    if not value:
        return False, f"core.hooksPath не задан; укажи каталог хуков движка: git config core.hooksPath {HOOKS_DIR}"
    configured = Path(value).expanduser()
    if not configured.is_absolute():
        configured = root / configured
    try:
        same = configured.resolve() == HOOKS_DIR.resolve()
    except OSError:
        same = False
    if not same:
        return False, f"core.hooksPath = {value}, а хуки движка в {HOOKS_DIR}"
    missing = [name for name in HOOK_NAMES
               if not (HOOKS_DIR / name).is_file() or not os.access(HOOKS_DIR / name, os.X_OK)]
    if missing:
        return False, "хуки не исполняемы: " + ", ".join(missing)
    return True, ""


def install_hooks(root: Path) -> None:
    svodgit.git(root, "config", "core.hooksPath", str(HOOKS_DIR))


# ---------------------------------------------------------------------------
# Синхронизация одного репозитория

def sync_repo(scope: str, root: Path, config, *, scanner: str | None = None,
              today: dt.date | None = None, state: Path | None = None) -> dict:
    """Один репозиторий под замком. Итог словами и фактами."""
    outcome: dict = {"scope": scope, "root": str(root), "at": utc_now(), "done": [],
                     "problems": [], "candidates": [], "caught_up": False}
    try:
        svodgit.require_marker(root, scope)
    except ValueError as exc:
        outcome["problems"].append(str(exc))
        return outcome
    installed, words = hooks_state(root)
    if not installed:
        outcome["problems"].append(f"хуки: {words}")
    try:
        with svodgit.lock(root, exclusive=True):
            _sync_locked(scope, root, config, outcome, scanner=scanner, today=today, state=state)
    except svodgit.Busy as exc:
        outcome["problems"].append(str(exc))
    except svodgit.GitError as exc:
        outcome["problems"].append(f"git: {exc}")
    return outcome


def _sync_locked(scope: str, root: Path, config, outcome: dict, *, scanner, today, state) -> None:
    healed = svodgit.heal(root)
    outcome["done"] += [f"вылечено: {h}" for h in healed]
    if svodgit.rebase_in_progress(root):
        outcome["problems"].append("идёт ручной rebase ветки main, пропуск: закончи его "
                                   "(git rebase --continue) или отмени (git rebase --abort)")
        outcome["candidates"] = memoryremember.retry_pending(
            root, scope, config, fetched=False, scanner=scanner, today=today, state=state)
        return
    if svodgit.branch(root) != "main":
        outcome["problems"].append("репозиторий не на ветке main; верни main руками")
        return
    dirty = svodgit.dirty_paths(root)
    fetched, why = svodgit.fetch(root)
    if not fetched:
        outcome["problems"].append(f"сети нет: {why}")
    if dirty:
        outcome["problems"].append("в репозитории правят руками, пропуск: " + ", ".join(sorted(dirty)))
        outcome["candidates"] = memoryremember.retry_pending(
            root, scope, config, fetched=False, scanner=scanner, today=today, state=state)
        return
    head = svodgit.head(root)
    remote = svodgit.remote_head(root) if fetched else None
    if fetched and remote and head != remote:
        if svodgit.fast_forward(root, head, remote):
            outcome["done"].append(f"fast-forward до {remote[:12]}")
            head = remote
        else:
            state_word, words, final = memoryremember.publish(
                root, scope, head, config, scanner=scanner, today=today, verify_ahead=True)
            if state_word == "saved":
                outcome["done"].append(f"опубликовано {final[:12]}")
            else:
                outcome["problems"].append(words)
    elif fetched and remote is None and head is not None:
        state_word, words, final = memoryremember.publish(
            root, scope, head, config, scanner=scanner, today=today, verify_ahead=True)
        if state_word == "saved":
            outcome["done"].append(f"опубликовано {final[:12]} (первая публикация)")
        else:
            outcome["problems"].append(words)
    outcome["candidates"] = memoryremember.retry_pending(
        root, scope, config, fetched=fetched, scanner=scanner, today=today, state=state)
    # Вершина сервера учтена в HEAD: только тогда автомат судит по свежему.
    outcome["caught_up"] = fetched and (remote is None or svodgit.is_ancestor(root, remote, "HEAD"))
    if fetched:
        for name in memoryremember.drop_settled_failures(root, scope, config, state=state):
            outcome["done"].append(f"снят исполненный отказ {name}")


def write_cache(scope: str, outcome: dict, state: Path | None = None) -> None:
    svodgit.replace_file(svodgit.sync_cache_path(scope, state),
                         json.dumps(outcome, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8"))


ROUTER_CACHE_DAYS = 30
USAGE_DAYS_KEEP = 120


def prune_router_cache(state: Path | None = None, days: int = ROUTER_CACHE_DAYS) -> int:
    """Отметки доставки старше 30 суток убираются: они производные, и потеря
    отметки стоит одной лишней доставки материала. Каталог рос без края
    (замер 09.09.2026: 13 МБ, 3038 файлов, 770 старше срока). Метки дней
    использования старше 120 суток тоже: наблюдению нужно окно в 60 суток,
    остальное запас. Метки записей не убираются: их по одной на запись.

    ⚠️ Закрепления (`pins/`) не трогаем ни при каком возрасте. Закрепление
    пишется один раз и при продолжении разговора не переписывается, поэтому
    его возраст не доказывает, что сессия кончилась; снятое закрепление
    старой сессии дало бы заказчику соседа. Уборка молчит: удалять нечего,
    разговора нет."""
    import memorycontext as mc
    claude = (state or svodgit.state_dir()) / "claude"
    base = claude / "sessions"
    edge = time.time() - days * 86400
    removed = 0
    for path in base.rglob("*") if base.is_dir() else ():
        try:
            if path.is_file() and path.stat().st_mtime < edge:
                path.unlink()
                removed += 1
        except OSError:
            continue
    # Возраст метки дня это её имя, а не время файла: копия каталога
    # состояния не должна омолодить метки.
    дни = claude / mc.USAGE_DIR / "days"
    граница = mc.today_utc() - dt.timedelta(days=USAGE_DAYS_KEEP)
    for path in sorted(дни.iterdir()) if дни.is_dir() else ():
        try:
            if dt.date.fromisoformat(path.name) < граница:
                path.unlink()
                removed += 1
        except (ValueError, OSError):
            continue
    return removed


# ---------------------------------------------------------------------------
# Самообслуживание (решение владельца 24.09.2026): явно закрытое сворачивает
# автомат, неиспользуемое только наблюдается заметкой статуса.

AUTO_CLOSE_LIMIT = 10
AUTO_CLOSE_ID = "auto-close-"
AUTO_REOPEN_ID = "auto-reopen-"
# Коммиты автомата: их правка не считается правкой человека.
AUTO_SUBJECTS = tuple(memoryremember.COMMIT_PREFIX + вид for вид in (AUTO_CLOSE_ID, AUTO_REOPEN_ID))
MAINTENANCE_MODES = ("on", "observe", "off")


def maintenance_from_config(topics_raw: bytes) -> dict:
    """Раздел maintenance {executor, closed}; без него выключено. Разбор
    отдельно от тем: опечатка выключает автомат, а не писателей."""
    raw = json.loads(topics_raw.decode("utf-8")).get("maintenance")
    if raw is None:
        return {"executor": "", "closed": "off"}
    if (not isinstance(raw, dict) or not isinstance(raw.get("executor", ""), str)
            or raw.get("closed", "off") not in MAINTENANCE_MODES):
        raise ValueError('topics.json: maintenance это {"executor": имя машины строкой, '
                         f'"closed": on, observe или off}}, получено {raw!r}')
    return {"executor": raw.get("executor", ""), "closed": raw.get("closed", "off")}


def same_machine(executor: str) -> bool:
    """Эта ли машина исполнитель. Имя сравнивается без регистра и без
    суффикса .local: macOS отдаёт его то с суффиксом, то без."""
    def норма(имя: str) -> str:
        return имя.strip().casefold().removesuffix(".local")
    return bool(норма(executor)) and норма(executor) == норма(socket.gethostname())


def protected_records(config) -> set[str]:
    """Ожидаемые записи стенда и hotKeep тем: их автомат не трогает."""
    import memoryverify as mv
    держать = {name.removesuffix(".md")
               for _topic, _tokens, keep in mv.load_topics(config.topics).drift for name in keep}
    if config.questions:
        вопросы = json.loads(config.questions.decode("utf-8")).get("questions") or []
        держать |= {q["expect"] for q in вопросы
                    if isinstance(q, dict) and isinstance(q.get("expect"), str)}
    return держать


def _commits(root: Path, paths, *options: str) -> list[tuple[str, float, str, list[str]]]:
    """Коммиты к путям, новые первыми: (хеш, время, тема, файлы). Один вызов."""
    текст = svodgit.out(root, "log", *options, "--format=%x00%H %ct %s", "--name-only",
                        "--", *paths, check=False)
    коммиты = []
    for кусок in текст.split("\0"):
        строки = кусок.strip().splitlines()
        if not строки or строки[0].count(" ") < 2:
            continue
        хеш, время, тема = строки[0].split(" ", 2)
        коммиты.append((хеш, float(время), тема, [s for s in строки[1:] if s]))
    return коммиты


def _listed_at(root: Path, rev: str, path: str) -> str | None:
    """Значение поля listed шапки файла в ревизии; None, если файла нет."""
    import memoryverify as mv
    файл = svodgit.git(root, "show", f"{rev}:{path}", check=False)
    return (mv.parse_frontmatter(файл.stdout.decode("utf-8", "replace"))[0].get("listed")
            if файл.returncode == 0 else None)


def _unfold(text: str) -> tuple[str, int]:
    """Текст без строк listed в шапке и их число."""
    конец = text.find("\n---\n", 4)
    строки = text[4:конец].split("\n")
    шапка = [s for s in строки if s.split(":", 1)[0].strip() != "listed"]
    return "---\n" + "\n".join(шапка) + text[конец:], len(строки) - len(шапка)


def _fold_origin(root: Path, path: str) -> str:
    """Тема коммита, последним менявшего поле listed шапки, по истории файла
    с переименованиями (--follow; путь в каждом коммите свой). Слияние в
    истории файла это решение человека: пусто. Без слияний история линейна,
    и состояние до коммита это следующий, более старый коммит списка."""
    история = _commits(root, [path], "--follow")
    пути = sorted({файлы[-1] for *_, файлы in история if файлы} | {path})
    if svodgit.out(root, "log", "--full-history", "--merges", "--format=%H", "--", *пути,
                   check=False):
        return ""
    значения = [_listed_at(root, хеш, файлы[-1] if файлы else path)
                for хеш, _, _, файлы in история] + [None]
    return next((тема for (_, _, тема, _), было, стало in zip(история, значения[1:], значения)
                 if было != стало), "")


def reopen_candidates(root: Path, tree: dict[str, bytes], today: dt.date) -> dict[str, str]:
    """Свёрнутое автоматом, чей срок продлили или сняли на другой машине
    (rebase сливает правки без конфликта в любом порядке): одна строка listed
    первой в шапке, как её ставит автомат, срок в будущем или снят, и поле
    последним менял коммит свёртки (_fold_origin). slug -> текст без listed."""
    import memoryverify as mv
    итог = {}
    for slug, text in sorted(mv._records(tree).items()):
        fields, _ = mv.parse_frontmatter(text)
        срок = fields.get("valid_until")
        try:
            if fields.get("listed") != "false" or (срок and dt.date.fromisoformat(срок) < today):
                continue
        except ValueError:
            continue  # битую дату называет проверка формы
        без, строк = _unfold(text)
        # Подпись автомата дёшево отсекает ручные свёртки: историю читаем мало.
        if строк == 1 and text.startswith("---\nlisted: false\n") and _fold_origin(
                root, f"memory/{slug}.md").startswith(memoryremember.COMMIT_PREFIX + AUTO_CLOSE_ID):
            итог[slug] = без
    return итог


def _auto_submit(итог: dict, prefix: str, слова: tuple[str, str], тексты: dict[str, str],
                 *, head: str, today: dt.date, state: Path | None, **писатель) -> None:
    """Подача автомата манифестом; тот же набор даёт тот же id и тело."""
    готово, действие = слова
    слаги = sorted(тексты)
    cid = (f"{prefix}{today:%Y%m%d}-"
           + hashlib.sha1(",".join(слаги).encode("utf-8")).hexdigest()[:8])
    if memoryremember.candidate_path("personal", cid, state).exists():
        # Тот же набор уже ждёт повтора синхронизации: новая подача с другой
        # основой была бы отказом без смысла.
        итог["done"].append(f"{действие} {cid} ждёт повтора")
        return
    изменения = [{"operation": "put", "path": f"memory/{s}.md", "content": тексты[s]}
                 for s in слаги]
    _код, ответ = memoryremember.run_remember(
        scope="personal", candidate_id=cid, source="memory-sync",
        session=socket.gethostname(), content_type="manifest",
        body=json.dumps({"changes": изменения}, ensure_ascii=False,
                        sort_keys=True).encode("utf-8"),
        projection=None, state=state, today=today, base=head, **писатель)
    состояние, причина = ответ.get("state"), ответ.get("reason")
    if состояние == "saved":
        итог["done"].append(f"{готово}: {', '.join(слаги)}")
    elif состояние == "pending" and ответ.get("commit"):
        итог["done"].append(f"{готово} локально, ждёт отправки: {', '.join(слаги)} ({причина})")
    elif состояние == "pending":
        итог["done"].append(f"{действие} {cid} ждёт: {причина}")
    else:
        итог["problems"].append(f"{действие} {cid}: {состояние}: {причина}")


def close_expired(root: Path, config, *, current: bool = True, data_root: Path | None = None,
                  scanner: str | None = None, today: dt.date | None = None,
                  state: Path | None = None) -> dict:
    """Автомат закрытого на машине-исполнителе, только при `current` (fetch
    удался, вершина сервера в HEAD, проблем нет). В режиме on снимает свои
    отказы, возвращает (reopen_candidates), затем сворачивает; observe лишь
    называет. Не под замками обхода: писатель берёт замок сам."""
    import memorycontext as mc
    итог: dict = {"done": [], "problems": []}
    try:
        настройка = maintenance_from_config(config.topics)
    except ValueError as exc:
        итог["problems"].append(f"автомат закрытого выключен: {exc}")
        return итог
    режим = настройка["closed"]
    if режим == "off" or not same_machine(настройка["executor"]) or not current:
        return итог
    try:
        today = today or mc.today_utc()
        писатель = {"data_root": data_root, "scanner": scanner, "today": today, "state": state}
        head = svodgit.head(root)
        tree = svodgit.read_tree(root, head) if head else {}
        if режим == "on":
            for файл in svodgit.failed_dir("personal", state).glob("auto-*.json"):
                if файл.name.startswith((AUTO_CLOSE_ID, AUTO_REOPEN_ID)):
                    файл.unlink()
            вернуть = dict(sorted(reopen_candidates(root, tree, today).items())[:AUTO_CLOSE_LIMIT])
            if вернуть:
                _auto_submit(итог, AUTO_REOPEN_ID, ("возвращено после продления срока",
                                                    "возврат после продления срока"),
                             вернуть, head=head, **писатель)
                head = svodgit.head(root)
                tree = svodgit.read_tree(root, head)
        # Свёрнутые dated_records уже пропускает; остальное в следующий прогон.
        слаги = sorted(set(dated_records(tree, today)[0]) - protected_records(config))
        слаги = слаги[:AUTO_CLOSE_LIMIT]
        if слаги and режим == "observe":
            итог["done"].append("свернул бы по сроку: " + ", ".join(слаги))
        elif слаги:
            # Строка первая, а не у срока: встречная правка срока дала бы
            # конфликт rebase и расходящуюся main; слияние чинит возврат.
            _auto_submit(итог, AUTO_CLOSE_ID, ("свёрнуто по сроку", "свёртка по сроку"),
                         {s: "---\nlisted: false\n" + tree[f"memory/{s}.md"].decode("utf-8")[4:]
                          for s in слаги}, head=head, **писатель)
    except Exception as exc:  # noqa: BLE001 - шаг не роняет таймер, слова в итог
        итог["problems"].append(f"автомат закрытого: {type(exc).__name__}: {exc}")
    return итог


def sync_all(*, data_root: Path | None = None, scanner: str | None = None,
             today: dt.date | None = None, state: Path | None = None) -> list[dict]:
    """Все репозитории карты, что есть на диске. Один упавший не
    останавливает остальные."""
    config = memoryremember.load_config()
    prune_router_cache(state)
    outcomes = []
    личный = None
    for scope, root in svodgit.repo_map(data_root).items():
        try:
            outcome = sync_repo(scope, root, config, scanner=scanner, today=today, state=state)
        except Exception as exc:  # noqa: BLE001 - итог одного репозитория словами
            outcome = {"scope": scope, "root": str(root), "at": utc_now(), "done": [],
                       "problems": [f"{type(exc).__name__}: {exc}"], "candidates": [],
                       "traceback": traceback.format_exc()}
        outcomes.append(outcome)
        if scope == "personal":
            личный = outcome
        else:
            write_cache(scope, outcome, state)
    # Самообслуживание после обхода, а не внутри: sync_repo держит замок,
    # а писатель берёт его снова. Кэш личной области пишется один раз, уже
    # с итогом шага: иначе подсказка между двумя записями видела бы
    # устаревшую поломку.
    if личный is not None:
        допуск = bool(личный.get("caught_up")) and not личный["problems"]
        шаг = close_expired(Path(личный["root"]), config, current=допуск,
                            data_root=data_root, scanner=scanner, today=today, state=state)
        личный["done"] += шаг["done"]
        личный["problems"] += шаг["problems"]
        write_cache("personal", личный, state)
    return outcomes


# ---------------------------------------------------------------------------
# Статус

def _ahead_behind(root: Path, head: str | None, remote: str | None) -> tuple[int | None, int | None]:
    if not head or not remote:
        return None, None
    text = svodgit.out(root, "rev-list", "--left-right", "--count", f"{head}...{remote}", check=False)
    parts = text.split()
    if len(parts) != 2:
        return None, None
    return int(parts[0]), int(parts[1])


def _candidates(scope: str, base: Path | None, kind: str) -> list[dict]:
    directory = svodgit.pending_dir(scope, base) if kind == "pending" else svodgit.failed_dir(scope, base)
    items = []
    if not directory.is_dir():
        return items
    for path in sorted(directory.glob("*.json")):
        data = svodgit.read_json(path) or {}
        items.append({"id": path.stem, "reason": data.get("reason"),
                      "commit": data.get("commit"), "submitted_at": data.get("submitted_at")})
    return items


SECTION_HEADROOM = 200


def dated_records(tree: dict[str, bytes], today: dt.date) -> tuple[list[str], list[str]]:
    """Записи с истёкшим сроком: слаги с просроченным valid_until и слаги, у
    которых review_after уже прошёл, оба по дереву HEAD. Граница у обоих та
    же, что у отбора (memorycontext._entry_expired): дата действует ПО
    указанный день включительно, «после» начинается со следующего. Битая
    дата не считается: её называет проверка формы писателя. Свёрнутые
    записи (`listed: false`) не считаются: они и так вне выдачи."""
    import memoryverify as mv
    expired: list[str] = []
    review: list[str] = []
    for slug, text in sorted(mv._records(tree).items()):
        fields, _ = mv.parse_frontmatter(text)
        # Свёрнутая запись из выдачи уже убрана владельцем: срок у неё
        # ничего не решает, а заметка напоминала бы о ней бесконечно.
        if fields.get("listed") == "false":
            continue
        for key, bucket in (("valid_until", expired), ("review_after", review)):
            value = fields.get(key)
            if not value:
                continue
            try:
                boundary = dt.date.fromisoformat(value)
            except ValueError:
                continue
            if today > boundary:
                bucket.append(slug)
    return expired, review


OBSERVE_DAYS = 60
COVERAGE_DAYS = 30
AUTO_REPORT_DAYS = 30
AUTO_LAG_DAYS = 2
# Итог автомата: единственная заметка, по которой разбирать нечего.
AUTO_NOTE = f"автомат за {AUTO_REPORT_DAYS} дней свернул по сроку: "


def usage_notes(root: Path, tree: dict[str, bytes], config, today: dt.date,
                state: Path | None = None) -> list[str]:
    """Наблюдение неиспользуемого (решение владельца 24.09.2026): только
    заметка. При покрытии (учёт не короче 60 суток, 30 меток дней за
    последние 60) называет записи проекта в индексе без срока, не из стенда
    и hotKeep, не выданные хуком и не правленные человеком 60 суток. Плюс
    счёт свёрнутого автоматом за 30 суток."""
    import memorycontext as mc
    import memoryverify as mv
    метки = (state or svodgit.state_dir()) / "claude" / mc.USAGE_DIR
    полночь = dt.datetime.combine(today, dt.time(), dt.timezone.utc).timestamp()
    граница = полночь - OBSERVE_DAYS * 86400
    возрасты = []
    for путь in (метки / "days").iterdir() if (метки / "days").is_dir() else ():
        try:
            возрасты.append((today - dt.date.fromisoformat(путь.name)).days)
        except ValueError:
            continue
    покрытие = (sum(0 <= д < OBSERVE_DAYS for д in возрасты) >= COVERAGE_DAYS
                and max(возрасты) >= OBSERVE_DAYS)
    кандидаты = []
    защищённые = protected_records(config) if покрытие else set()
    for slug, text in sorted(mv._records(tree).items()) if покрытие else ():
        fields, _ = mv.parse_frontmatter(text)
        if (fields.get("type") != "project" or fields.get("valid_until")
                or slug in защищённые or mc.record_index_line(f"{slug}.md", fields) is None):
            continue
        try:
            if (метки / "records" / slug).stat().st_mtime >= граница:
                continue
        except OSError:
            pass  # метки нет: на этой машине не выдавалась ни разу
        кандидаты.append(slug)
    # Git только после покрытия и кандидатов: окно 60 суток нужно правкам,
    # 30 суток хватает счёту автомата.
    окно = OBSERVE_DAYS if кандидаты else AUTO_REPORT_DAYS
    коммиты = _commits(root, ["memory/"], f"--since=@{int(полночь - окно * 86400)}")
    правленые = {f for _, _, тема, файлы in коммиты if not тема.startswith(AUTO_SUBJECTS)
                 for f in файлы}
    кандидаты = [s for s in кандидаты if f"memory/{s}.md" not in правленые]
    notes = []
    if кандидаты:
        notes.append(f"свернул бы (не выдавалась хуком {OBSERVE_DAYS} дней на машине "
                     f"{socket.gethostname()}): " + ", ".join(кандидаты))
    свёрнуто = {f for _, время, тема, файлы in коммиты if тема.startswith(AUTO_SUBJECTS[0])
                and время >= полночь - AUTO_REPORT_DAYS * 86400 for f in файлы}
    if свёрнуто:
        notes.append(f"{AUTO_NOTE}{len(свёрнуто)}")
    return notes


def lagging_closed(tree: dict[str, bytes], expired: list[str], config,
                   today: dt.date) -> tuple[list[str], str | None]:
    """При closed: on незащищённое истёкшее это работа автомата:
    «просрочено» оставляет стенд и hotKeep, а истёкшее больше 2 суток назад
    значит автомат отстал. Это заметка: исполнитель бывает выключен."""
    import memoryverify as mv
    try:
        настройка = maintenance_from_config(config.topics)
    except ValueError:
        return expired, None  # слова об опечатке даёт проблема таймера
    if настройка["closed"] != "on":
        return expired, None
    защищённые = protected_records(config)
    край = today - dt.timedelta(days=AUTO_LAG_DAYS)
    отстало = [s for s in expired if s not in защищённые and dt.date.fromisoformat(
        mv.parse_frontmatter(tree[f"memory/{s}.md"].decode("utf-8"))[0]["valid_until"]) < край]
    note = (f"автомат закрытого отстал (исполнитель {настройка['executor']}, эта машина "
            f"{socket.gethostname()}): {', '.join(отстало)}") if отстало else None
    return [s for s in expired if s in защищённые], note


def repo_health(scope: str, root: Path, config,
                state: Path | None = None) -> tuple[list[str], list[str]]:
    """Что разъедает доставку, словами и только при действии (цель 4:
    записанный факт находится). Измерение то же, что у проверок писателя,
    по дереву HEAD.

    Два списка, и разница между ними в том, красит ли находка итог статуса.
    Сломанная доставка (раздел сводки выше потолка) это проблема: хвост
    раздела до сессии не доезжает. Размер индекса, дрейф и малый запас
    раздела это заметки: доставка цела, работа для владельца видна, но
    держать из-за неё статус красным неделями значит приучить не смотреть на
    статус вовсе. Личный индекс целиком в сессию не отдаётся, и писатель по
    его размеру не отказывает: размер показатель обслуживания. Уезжает
    только каталог раздела User, поэтому его запас виден заметкой."""
    import memorycontext as mc
    import memoryverify as mv
    head = svodgit.head(root)
    if head is None:
        return [], []
    tree = svodgit.read_tree(root, head)
    topics = mv.load_topics(config.topics)
    findings: list[str] = []
    notes: list[str] = []
    # Просроченная запись из выдачи уходит молча (valid_until), а review_after
    # доставку не меняет вовсе: без этих строк оба срока узнавались бы только
    # поимённо через explain. Это работа владельца, итог не красят.
    # Дата та же, что у отбора (UTC), иначе около полуночи статус и доставка
    # расходились бы. Список полный: усечённый скрывал бы хвост навсегда.
    просрочено, обзор = dated_records(tree, mc.today_utc())
    отстал = None
    if scope == "personal":
        просрочено, отстал = lagging_closed(tree, просрочено, config, mc.today_utc())
    if отстал:
        notes.append(отстал)
    if просрочено:
        notes.append(f"просрочено: valid_until истёк у {', '.join(просрочено)}")
    if обзор:
        notes.append(f"обзор: review_after прошёл у {', '.join(обзор)}")
    if mv.client_name(scope) is None:
        text = mv.router_index_text(tree)
        chars, lines = len(text), len(text.splitlines())
        budget = topics.budget
        hard = (budget.get("hardBytes"), budget.get("hardLines"))
        soft = (budget.get("softBytes"), budget.get("softLines"))
        if all(hard) and (chars > hard[0] or lines > hard[1]):
            notes.append(f"индекс {chars} симв / {lines} строк выше потолка {hard[0]} / {hard[1]}")
        elif all(soft) and (chars > soft[0] or lines > soft[1]):
            notes.append(f"индекс {chars} симв / {lines} строк выше порога {soft[0]} / {soft[1]}"
                         + (f", потолок {hard[0]} / {hard[1]}" if all(hard) else ""))
        if scope == "personal":
            каталог = len(mc._user_catalog_block(mc.parse_index(text), maximum=10**9))
            предел = mc.USER_CATALOG_LIMIT
            if каталог > предел:
                notes.append(f"каталог сведений о владельце {каталог} симв выше потолка "
                             f"{предел} по верхней оценке (просроченные тоже в счёте): "
                             "на вопрос «что ты обо мне помнишь» строки уйдут без пояснений")
        for topic, slugs in sorted(mv.drifted_records(tree, topics.drift).items()):
            names = ", ".join(s[:-3] if s.endswith(".md") else s for s in slugs[:3])
            notes.append(f"дрейф: {topic} {len(slugs)} записей в индексе ({names}"
                         + (" …" if len(slugs) > 3 else "") + ")")
        if scope == "personal":
            notes += usage_notes(root, tree, config, mc.today_utc(), state)
        return findings, notes
    spec = next((s for s in topics.specs.values() if s.owner == scope), None)
    data = tree.get(f"memory/topics/{spec.filename}") if spec is not None else None
    if data is None:
        return findings, notes
    for section in mc.parse_sections(data.decode("utf-8", "replace")):
        cap = mc.section_cap(section)
        if len(section.text) > cap:
            findings.append(f"сводка: раздел «{section.title}» {len(section.text)} симв "
                            f"при потолке {cap}")
        elif cap - len(section.text) < SECTION_HEADROOM:
            # Запас виден заранее: узнавать его из отказа подачи дорого.
            notes.append(f"запас: раздел «{section.title}» {cap - len(section.text)} симв "
                         f"до потолка {cap}")
    return findings, notes


def repo_status(scope: str, root: Path, *, fetch: bool = False, state: Path | None = None,
                config=None) -> dict:
    info: dict = {"scope": scope, "root": str(root)}
    try:
        marker = svodgit.read_marker(root)
        info["marker"] = marker
        if marker != scope:
            info["problem"] = (f"{svodgit.MARKER_NAME} говорит {marker}" if marker
                               else f"нет {svodgit.MARKER_NAME}")
        if fetch:
            fetched, why = svodgit.fetch(root)
            info["fetched"] = fetched
            if not fetched:
                info["fetch_error"] = why
        head = svodgit.head(root)
        remote = svodgit.remote_head(root)
        ahead, behind = _ahead_behind(root, head, remote)
        info.update({
            "branch": svodgit.branch(root), "head": head, "remote": remote,
            "ahead": ahead, "behind": behind,
            "dirty": sorted(svodgit.dirty_paths(root)),
            "rebase_in_progress": svodgit.rebase_in_progress(root),
        })
        hooks_ok, hooks_words = hooks_state(root)
        info["hooks"] = hooks_ok
        if not hooks_ok:
            info["hooks_problem"] = hooks_words
        info["health"], info["notes"] = (repo_health(scope, root, config, state)
                                         if config is not None else ([], []))
    except (svodgit.GitError, ValueError) as exc:
        info["problem"] = str(exc)
    info["pending"] = _candidates(scope, state, "pending")
    info["failed"] = _candidates(scope, state, "failed")
    info["last_sync"] = svodgit.read_json(svodgit.sync_cache_path(scope, state))
    return info


def status(*, data_root: Path | None = None, fetch: bool = False,
           state: Path | None = None) -> dict:
    config = memoryremember.load_config()
    repos = [repo_status(scope, root, fetch=fetch, state=state, config=config)
             for scope, root in svodgit.repo_map(data_root).items()]
    # Каталог области с memory/, но без .git: читатель его отдаёт, а
    # синхронизация и писатель не видят. Молчать об этом нельзя.
    for scope, root in svodgit.repo_map(data_root, on_disk_only=False).items():
        if (root / "memory").is_dir() and not (root / ".git").exists():
            repos.append({"scope": scope, "root": str(root),
                          "problem": "каталог области без git-репозитория: читатель его "
                                     "отдаёт, синхронизация и писатель не видят"})
    return {"at": utc_now(), "repos": repos, "ok": all(_repo_ok(r) for r in repos)}


def _repo_ok(info: dict) -> bool:
    if info.get("problem") or info.get("hooks_problem"):
        return False
    if info.get("branch") != "main" or info.get("rebase_in_progress"):
        return False
    if info.get("dirty") or info.get("pending") or info.get("failed"):
        return False
    if info.get("health"):
        return False
    if info.get("ahead") or info.get("behind"):
        return False
    last = info.get("last_sync") or {}
    return not last.get("problems")


def format_human(result: dict) -> str:
    lines = []
    for info in result["repos"]:
        head = (info.get("head") or "")[:12] or "нет коммитов"
        parts = [f"{info['scope']}: {info.get('branch') or 'отсоединена'} {head}"]
        if info.get("ahead") is not None:
            parts.append(f"впереди {info['ahead']}, позади {info['behind']}")
        elif info.get("remote") is None:
            parts.append("сервера не видно")
        if info.get("dirty"):
            parts.append("грязные: " + ", ".join(info["dirty"][:5])
                         + (" …" if len(info["dirty"]) > 5 else ""))
        if info.get("rebase_in_progress"):
            parts.append("идёт rebase")
        if info.get("problem"):
            parts.append("⚠️ " + info["problem"])
        if info.get("hooks_problem"):
            parts.append("⚠️ хуки: " + info["hooks_problem"])
        if info.get("fetch_error"):
            parts.append("сеть: " + info["fetch_error"])
        lines.append("; ".join(parts))
        for item in info.get("pending", []):
            стоянка = "коммит локальный" if item.get("commit") else "проверка ещё не выполнялась"
            lines.append(f"  ждёт {item['id']}: {item.get('reason') or стоянка}")
        for item in info.get("failed", []):
            lines.append(f"  отказ {item['id']}: {item.get('reason')}")
        for finding in info.get("health", []):
            lines.append(f"  {finding}")
        for note in info.get("notes", []):
            lines.append(f"  {note}")
        last = info.get("last_sync")
        if last:
            summary = "; ".join(last.get("problems") or last.get("done") or ["без изменений"])
            lines.append(f"  таймер {last.get('at')}: {summary}")
    lines.append("итог: " + ("ok" if result["ok"] else "есть что разобрать"))
    return "\n".join(lines)


def format_nudge(result: dict, monthly: bool = False) -> str:
    """Подсказка для хука старта сессии: пусто, если разбирать нечего.
    Заменяет подсказку компактора (Свод-0, шаг 5).

    Каждый день одна короткая строка только о поломках: синхронизация,
    отказы, сломанная доставка. Раз в месяц (`monthly`, решение владельца
    24.09.2026) вторая строка со ВСЕМИ заметками целиком: сокращённая до
    первой она прятала бы остальные навсегда. Запас раздела и мягкий порог
    индекса не приходят и тогда: раздел у потолка остановит писатель в
    момент записи, порог это ранний сигнал `status`."""
    bits: list[str] = []
    подсказки: list[bool] = []
    заметки: list[str] = []
    for info in result["repos"]:
        scope = info["scope"]
        if info.get("problem"):
            bits.append(f"{scope}: {info['problem']}")
        if info.get("hooks_problem"):
            bits.append(f"{scope}: хуки: {info['hooks_problem']}")
        if info.get("rebase_in_progress") or ("branch" in info and info["branch"] != "main"):
            bits.append(f"{scope}: ветка {info.get('branch') or 'отсоединена'}")
        if info.get("dirty"):
            bits.append(f"{scope}: грязных путей {len(info['dirty'])}")
        if info.get("ahead") or info.get("behind"):
            bits.append(f"{scope}: впереди {info['ahead']}, позади {info['behind']}")
        if info.get("pending"):
            bits.append(f"{scope}: ждёт {len(info['pending'])}")
        отказы = info.get("failed", [])
        if отказы:
            bits.append(f"{scope}: отказ {отказы[0]['id']}"
                        + (f" и ещё {len(отказы) - 1}" if len(отказы) > 1 else ""))
        измерение = list(info.get("health", []))
        if измерение:
            # Ежедневная строка ОДНА и короткая: перечислять два десятка
            # разделов у потолка значит приучить её пролистывать.
            хвост = f" и ещё {len(измерение) - 1}" if len(измерение) > 1 else ""
            bits.append(f"{scope}: {измерение[0]}{хвост}")
        подсказки.append(bool(измерение))
        problems = (info.get("last_sync") or {}).get("problems")
        if problems:
            bits.append(f"{scope}: таймер: {'; '.join(problems)[:100]}")
        if monthly:
            заметки += [f"{scope}: {f}" for f in info.get("notes", [])
                        if not f.startswith("запас:") and "выше порога" not in f]
    строки = []
    if bits:
        # Хвост выбирается по находкам измерения, а не по подстроке во всей
        # строке: имя отказа со словом «индекс» уводило подсказку не туда.
        строки.append("Память: " + "; ".join(bits)
                      + (" → /memory-compact" if any(подсказки) else " → memory status"))
    if заметки:
        только_итог = all(f.split(": ", 1)[1].startswith(AUTO_NOTE) for f in заметки)
        строки.append("Память, раз в месяц: " + "; ".join(заметки)
                      + (" → memory status" if только_итог else " → /memory-compact"))
    return "\n".join(строки)


# ---------------------------------------------------------------------------
# CLI

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="memory-sync", description="синхронизация памяти")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--root", type=Path, default=None, help="каталог данных (MEMORY_REPO)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    import memorycontext as mc
    if mc.TOPICS_ERROR:
        # Единственный вход таймера обязан отвечать словами, а не
        # трассировкой: чаще всего это забытый MEMORY_CONFIG_DIR.
        print(f"memory-sync: {mc.TOPICS_ERROR}", file=sys.stderr)
        return 1
    state = svodgit.state_dir()
    try:
        outcomes = sync_all(data_root=args.root, state=state)
    except Exception as exc:  # noqa: BLE001 - трассировка в файл, слова наружу
        state.mkdir(parents=True, exist_ok=True)
        (state / "sync-error.log").write_text(traceback.format_exc(), encoding="utf-8")
        print(f"memory-sync: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if args.as_json:
        print(json.dumps(outcomes, ensure_ascii=False, sort_keys=True))
    else:
        for outcome in outcomes:
            summary = "; ".join(outcome["problems"] or outcome["done"] or ["без изменений"])
            print(f"{outcome['scope']}: {summary}")
            for item in outcome.get("candidates", []):
                print(f"  {item['id']}: {item['state']}" + (f" ({item['reason']})" if item.get("reason") else ""))
    return 0 if all(not o["problems"] for o in outcomes) else 1
