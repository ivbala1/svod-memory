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
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

import memoryremember
import svodgit


HOOKS_DIR = (Path(__file__).resolve().parents[1] / "githooks")
HOOK_NAMES = ("pre-commit", "pre-push")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Хуки

def hooks_path_expected() -> str:
    return str(HOOKS_DIR)


def hooks_state(root: Path) -> tuple[bool, str]:
    """(стоят, слова): core.hooksPath указывает на каталог хуков движка."""
    result = svodgit.git(root, "config", "--get", "core.hooksPath", check=False)
    value = result.stdout.decode().strip() if result.returncode == 0 else ""
    if not value:
        return False, "core.hooksPath не задан; поставь установщиком (install.sh)"
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
                     "problems": [], "candidates": []}
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
        if head is None or svodgit.is_ancestor(root, head, remote):
            if head is None:
                svodgit.git(root, "reset", "--quiet", "--hard", remote)
            else:
                svodgit.git(root, "merge", "--quiet", "--ff-only", remote)
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


def write_cache(scope: str, outcome: dict, state: Path | None = None) -> None:
    svodgit.replace_file(svodgit.sync_cache_path(scope, state),
                         json.dumps(outcome, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8"))


def sync_all(*, data_root: Path | None = None, scanner: str | None = None,
             today: dt.date | None = None, state: Path | None = None) -> list[dict]:
    """Все репозитории карты, что есть на диске. Один упавший не
    останавливает остальные."""
    config = memoryremember.load_config()
    outcomes = []
    for scope, root in svodgit.repo_map(data_root).items():
        try:
            outcome = sync_repo(scope, root, config, scanner=scanner, today=today, state=state)
        except Exception as exc:  # noqa: BLE001 - итог одного репозитория словами
            outcome = {"scope": scope, "root": str(root), "at": utc_now(), "done": [],
                       "problems": [f"{type(exc).__name__}: {exc}"], "candidates": [],
                       "traceback": traceback.format_exc()}
        write_cache(scope, outcome, state)
        outcomes.append(outcome)
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


def repo_health(scope: str, root: Path, config) -> list[str]:
    """Что разъедает доставку, словами и только при действии (цель 4:
    записанный факт находится). Индексный корень: индекс выше порога или
    потолка бюджета, дрейф записей тем в индекс сверх hotKeep. Клиентский:
    раздел сводки выше потолка доставки, включая не тронутые разделы, то
    есть долг, который писатель при правке раздела не пропустит. Измерение
    то же, что у проверок писателя, по дереву HEAD."""
    import memorycontext as mc
    import memoryverify as mv
    head = svodgit.head(root)
    if head is None:
        return []
    tree = svodgit.read_tree(root, head)
    topics = mv.load_topics(config.topics)
    findings: list[str] = []
    if mv.client_name(scope) is None:
        text = mv.router_index_text(tree)
        chars, lines = len(text), len(text.splitlines())
        budget = json.loads(config.topics.decode("utf-8")).get("budget") or {}
        hard = (budget.get("hardBytes"), budget.get("hardLines"))
        soft = (budget.get("softBytes"), budget.get("softLines"))
        if all(hard) and (chars > hard[0] or lines > hard[1]):
            findings.append(f"индекс {chars} симв / {lines} строк выше потолка {hard[0]} / {hard[1]}")
        elif all(soft) and (chars > soft[0] or lines > soft[1]):
            findings.append(f"индекс {chars} симв / {lines} строк выше порога {soft[0]} / {soft[1]}"
                            + (f", потолок {hard[0]} / {hard[1]}" if all(hard) else ""))
        for topic, slugs in sorted(mv.drifted_records(tree, topics.drift).items()):
            names = ", ".join(s[:-3] if s.endswith(".md") else s for s in slugs[:3])
            findings.append(f"дрейф: {topic} {len(slugs)} записей в индексе ({names}"
                            + (" …" if len(slugs) > 3 else "") + ")")
        return findings
    spec = next((s for s in topics.specs.values() if s.owner == scope), None)
    data = tree.get(f"memory/topics/{spec.filename}") if spec is not None else None
    if data is None:
        return findings
    for section in mc.parse_sections(data.decode("utf-8", "replace")):
        cap = mc.section_cap(section)
        if len(section.text) > cap:
            findings.append(f"сводка: раздел «{section.title}» {len(section.text)} симв "
                            f"при потолке {cap}")
    return findings


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
        info["health"] = repo_health(scope, root, config) if config is not None else []
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
            lines.append(f"  ждёт {item['id']}: {item.get('reason') or 'коммит локальный'}")
        for item in info.get("failed", []):
            lines.append(f"  отказ {item['id']}: {item.get('reason')}")
        for finding in info.get("health", []):
            lines.append(f"  {finding}")
        last = info.get("last_sync")
        if last:
            summary = "; ".join(last.get("problems") or last.get("done") or ["без изменений"])
            lines.append(f"  таймер {last.get('at')}: {summary}")
    lines.append("итог: " + ("ok" if result["ok"] else "есть что разобрать"))
    return "\n".join(lines)


def format_nudge(result: dict) -> str:
    """Одна строка для хука старта сессии: только если есть что разобрать,
    иначе пустая строка. Заменяет подсказку компактора (Свод-0, шаг 5)."""
    bits: list[str] = []
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
        for item in info.get("failed", []):
            bits.append(f"{scope}: отказ {item['id']}")
        for finding in info.get("health", []):
            bits.append(f"{scope}: {finding}")
        problems = (info.get("last_sync") or {}).get("problems")
        if problems:
            bits.append(f"{scope}: таймер: {'; '.join(problems)[:100]}")
    if not bits:
        return ""
    tail = (" → /memory-compact" if any("дрейф" in b or "индекс" in b for b in bits)
            else " → memory status")
    return "Память: " + "; ".join(bits) + tail


# ---------------------------------------------------------------------------
# CLI

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="memory-sync", description="синхронизация памяти")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--root", type=Path, default=None, help="каталог данных (MEMORY_REPO)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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
