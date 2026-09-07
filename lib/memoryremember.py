#!/usr/bin/env python3
"""Писатель памяти (Свод-0, шаг 3): один репозиторий, один кандидат,
один проход `apply`, общий с таймером цикл публикации.

Кандидат это файл в каталоге ожидания: намерение записи с ожиданиями
основы. Он пишется до замка и живёт, пока git не докажет доставку.
Успех только после приёма сервером; сети нет, коммит остаётся
локальным, кандидат ждёт таймера (решение владельца 1а).
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path, PurePosixPath
import re

import configpaths
import memoryverify
import svodgit


EXIT_SAVED = 0
EXIT_FAILED = 2
EXIT_BUSY = 3
EXIT_PENDING = 4
EXIT_ERROR = 7

ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
COMMIT_PREFIX = "memory: "
PUBLISH_ROUNDS = 3


class Refusal(Exception):
    """Отказ проверок словами: кандидат уходит в failed/ с этой причиной."""


class Wait(Exception):
    """Кандидат ждёт: репозиторий или сеть не готовы, ничего не тронуто."""


# ---------------------------------------------------------------------------
# Конфигурация

def load_config() -> memoryverify.Config:
    topics = configpaths.config_path("topics.json").read_bytes()
    questions_path = configpaths.config_path("eval_questions.json")
    questions = questions_path.read_bytes() if questions_path.is_file() else None
    return memoryverify.Config(topics=topics, questions=questions)


# ---------------------------------------------------------------------------
# Пути и проекция

def safe_path(path: str) -> str:
    """Целевой путь только внутри memory/, нормализованный, без .., без
    .git; иначе отказ до любой записи."""
    if not isinstance(path, str) or not path or "\x00" in path or path.startswith("/"):
        raise Refusal(f"путь {path!r} недопустим")
    pure = PurePosixPath(path)
    parts = pure.parts
    if any(part in ("..", ".", "") for part in parts) or any(part == ".git" for part in parts):
        raise Refusal(f"путь {path}: только внутри memory/, без .. и .git")
    normalized = "/".join(parts)
    if normalized != path or not normalized.startswith("memory/") or normalized == "memory/":
        raise Refusal(f"путь {path}: только внутри memory/, без .. и .git")
    name = parts[-1]
    if not (name.endswith(".md") or name == ".gitkeep"):
        raise Refusal(f"путь {path}: в области памяти допустимы только Markdown-файлы")
    return normalized


def require_no_symlinks(root: Path, path: str) -> None:
    current = root
    for part in PurePosixPath(path).parts:
        current = current / part
        if current.is_symlink():
            raise Refusal(f"путь {path}: компонент {current.name} это символическая ссылка")


def parse_projection(projection: dict | None, scope: str, content_type: str) -> dict:
    if content_type == "manifest":
        if projection not in (None, {}, {"kind": "manifest"}):
            raise Refusal("манифесту проекция не нужна")
        return {}
    if content_type != "markdown":
        raise Refusal("content-type только markdown либо manifest")
    if not isinstance(projection, dict) or not projection:
        raise Refusal("записи нужна проекция с record_slug")
    slug = projection.get("record_slug")
    if not isinstance(slug, str) or not memoryverify.SLUG_RE.fullmatch(slug):
        raise Refusal("projection.record_slug обязан быть slug вида [a-z0-9_]{1,64}")
    keys = set(projection) - {"base_revision"}
    if keys == {"record_slug"}:
        if memoryverify.client_name(scope) is not None:
            raise Refusal("клиентской записи нужен указатель: index_line и index_section "
                          "(строка уезжает в раздел сводки темы)")
        return {"record_slug": slug}
    if keys != {"record_slug", "index_line", "index_section"}:
        raise Refusal("проекция несёт record_slug, либо record_slug, index_line и index_section")
    line = projection["index_line"]
    section = projection["index_section"]
    if not isinstance(line, str) or not line.strip() or "\n" in line or len(line.encode()) > 1024:
        raise Refusal("projection.index_line: одна непустая строка")
    if not isinstance(section, str) or not section.strip():
        raise Refusal("projection.index_section: непустое имя раздела")
    return {"record_slug": slug, "index_line": line, "index_section": section}


def parse_manifest(body: bytes) -> tuple[list[dict], str | None]:
    """Манифест формата apply: changes с put/remove, необязательный
    base_revision (хеш коммита основы)."""
    try:
        manifest = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise Refusal(f"манифест не JSON: {exc}")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("changes"), list) \
            or not manifest["changes"]:
        raise Refusal("манифест обязан быть объектом с непустым списком changes")
    base = manifest.get("base_revision")
    if base is not None and not (isinstance(base, str) and re.fullmatch(r"[0-9a-f]{40,64}", base)):
        raise Refusal("base_revision манифеста это хеш коммита основы")
    changes = []
    seen = set()
    for i, raw in enumerate(manifest["changes"]):
        if not isinstance(raw, dict) or raw.get("operation") not in ("put", "remove"):
            raise Refusal(f"изменение {i}: operation только put либо remove")
        path = raw.get("path")
        if isinstance(raw.get("area"), str) and isinstance(path, str) and not path.startswith("memory/"):
            path = f"{raw['area']}/{path}"
        path = safe_path(path)
        if path in seen:
            raise Refusal(f"изменение {i}: путь {path} повторяется")
        seen.add(path)
        if raw["operation"] == "put":
            content = raw.get("content")
            if not isinstance(content, str):
                raise Refusal(f"изменение {i}: put требует строку content")
            changes.append({"operation": "put", "path": path, "content": content})
        else:
            if "content" in raw:
                raise Refusal(f"изменение {i}: remove не несёт content")
            changes.append({"operation": "remove", "path": path})
    return changes, base


# ---------------------------------------------------------------------------
# Указатели: шапка записи и раздел сводки

def _yaml_scalar(value: str) -> str:
    if '"' not in value:
        return f'"{value}"'
    if "'" not in value:
        return f"'{value}'"
    raise Refusal("значение шапки содержит оба вида кавычек")


def apply_index_projection(body: bytes, slug: str, projection: dict) -> tuple[bytes, str]:
    """Указатель общего корня переезжает в шапку записи: поля type, title,
    index, если шапка их ещё не несёт. Шапка главнее проекции."""
    import memorycontext as mc
    text = body.decode("utf-8")
    fields, error = memoryverify.parse_frontmatter(text)
    if error:
        raise Refusal(f"memory/{slug}.md: {error}")
    if "index_line" not in projection:
        return body, ""
    if mc.record_index_line(f"{slug}.md", fields) is not None:
        return body, (f"index_line проекции не использована: шапка записи {slug} "
                      "уже несёт type, title и index")
    if any(fields.get(key, "").strip() for key in ("title", "index")):
        raise Refusal(f"шапка записи {slug} несёт часть полей индекса; нужны все три "
                      "(type, title, index) либо ни одного")
    match = mc.INDEX_ITEM_RE.match(projection["index_line"])
    if match is None or Path(match.group(2)).name != f"{slug}.md":
        raise Refusal(f"index_line не ссылается на {slug}.md")
    kinds = {section: kind for kind, section in mc.INDEX_SECTIONS.items()}
    kind = kinds.get(projection.get("index_section"))
    if kind not in mc.INDEX_TYPES:
        raise Refusal(f"раздел {projection.get('index_section')!r} не раздел индекса "
                      f"({', '.join(mc.INDEX_SECTIONS[k] for k in mc.INDEX_TYPES)})")
    title, hook = match.group(1).strip(), match.group(3).strip()
    if not title or not hook:
        raise Refusal("index_line: пустой заголовок или крючок")
    insert = f"type: {kind}\ntitle: {_yaml_scalar(title)}\nindex: {_yaml_scalar(hook)}\n"
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        new = text[:end + 1] + insert + text[end + 1:]
    else:
        new = "---\n" + insert + "---\n" + text
    return new.encode("utf-8"), ""


def index_line_slug(line: str) -> str | None:
    clean = memoryverify.strip_code(line)
    for target in memoryverify.MARKDOWN_LINK_RE.findall(clean):
        name = Path(target).name
        if name.endswith(".md"):
            return name[:-3]
    for target in memoryverify.DELIVERED_WIKI_LINK_RE.findall(clean):
        name = Path(target.strip()).name
        if name:
            return name[:-3] if name.endswith(".md") else name
    return None


def insert_rollup_pointer(rollup_text: str, section: str, line: str) -> str:
    """Строка-указатель в названный раздел сводки темы (по заголовку, регистр
    и краевые пробелы не значимы). Прежняя строка этой записи внутри раздела
    заменяется на месте; строка в другом разделе убирается оттуда, и новая
    дописывается в конец названного раздела."""
    slug = index_line_slug(line)
    if slug is None:
        raise Refusal("index_line без ссылки на запись указателем не является")
    import memorycontext as mc
    lines = rollup_text.splitlines()
    fenced, _open = mc.scan_code_fences(lines)
    wanted = section.strip().casefold()
    start, end = None, len(lines)
    for i, current in enumerate(lines):
        heading = None if fenced[i] else re.match(r"^##\s+(.+?)\s*$", current)
        if not heading:
            continue
        if start is not None:
            end = i
            break
        if heading.group(1).strip().casefold() == wanted:
            start = i
    if start is None:
        raise Refusal(f"раздела {section!r} нет в сводке темы")
    existing = [i for i, current in enumerate(lines)
                if not fenced[i] and index_line_slug(current) == slug]
    inside = [i for i in existing if start < i < end]
    if inside:
        lines[inside[0]] = line
        for i in sorted(set(existing) - {inside[0]}, reverse=True):
            del lines[i]
    else:
        for i in sorted(existing, reverse=True):
            del lines[i]
            if i < start:
                start -= 1
            if i < end:
                end -= 1
        position = start
        for i in range(start + 1, end):
            if lines[i].strip():
                position = i
        if mc.scan_code_fences(lines[start:end])[1]:
            raise Refusal(f"раздел {section!r} заканчивается незакрытым блоком кода; "
                          "указатель класть некуда")
        lines.insert(position + 1, line)
    return "\n".join(lines) + ("\n" if rollup_text.endswith("\n") else "")


def rollup_path(scope: str, config: memoryverify.Config) -> str:
    topics = memoryverify.load_topics(config.topics)
    mine = [name for name, (_topic, owner) in topics.placement.items() if owner == scope]
    if not mine:
        raise Refusal(f"у области {scope} нет темы-владельца: указатель класть некуда")
    if len(mine) > 1:
        raise Refusal(f"у области {scope} несколько сводок ({', '.join(sorted(mine))}): "
                      "указатель неоднозначен")
    return f"memory/topics/{mine[0]}"


# ---------------------------------------------------------------------------
# Кандидат

def direct_paths(candidate: dict) -> list[str]:
    if candidate["content_type"] == "manifest":
        changes, _ = parse_manifest(candidate["body"].encode("utf-8"))
        return [change["path"] for change in changes]
    return [f"memory/{candidate['projection']['record_slug']}.md"]


def compute_files(candidate: dict, head_tree: dict[str, bytes], scope: str,
                  config: memoryverify.Config) -> tuple[dict[str, bytes | None], list[str]]:
    """Файлы кандидата: путь -> байты либо None (удаление). Производный
    путь один, указатель в разделе сводки, он считается заново на текущей
    сводке."""
    notes: list[str] = []
    body = candidate["body"].encode("utf-8")
    if candidate["content_type"] == "manifest":
        changes, _ = parse_manifest(body)
        return {c["path"]: (c["content"].encode("utf-8") if c["operation"] == "put" else None)
                for c in changes}, notes
    projection = candidate["projection"]
    slug = projection["record_slug"]
    if not body.strip():
        raise Refusal("тело записи пустое")
    files: dict[str, bytes | None] = {}
    if memoryverify.client_name(scope) is None:
        data, note = apply_index_projection(body, slug, projection)
        if note:
            notes.append(note)
        files[f"memory/{slug}.md"] = data
        return files, notes
    files[f"memory/{slug}.md"] = body
    pointer = rollup_path(scope, config)
    rollup = head_tree.get(pointer)
    if rollup is None:
        raise Refusal(f"{pointer}: сводки темы нет в репозитории, указатель класть некуда")
    files[pointer] = insert_rollup_pointer(
        rollup.decode("utf-8"), projection["index_section"], projection["index_line"]).encode("utf-8")
    return files, notes


def candidate_path(scope: str, candidate_id: str, base: Path | None = None) -> Path:
    return svodgit.pending_dir(scope, base) / f"{candidate_id}.json"


def failed_path(scope: str, candidate_id: str, base: Path | None = None) -> Path:
    return svodgit.failed_dir(scope, base) / f"{candidate_id}.json"


def _same_intent(a: dict, b: dict) -> bool:
    keys = ("scope", "id", "content_type", "projection", "body")
    return all(a.get(k) == b.get(k) for k in keys)


def submit(*, scope: str, candidate_id: str, source: str, session: str,
           content_type: str, body: bytes, projection: dict | None,
           root: Path, state: Path | None = None) -> tuple[Path, dict]:
    """Кандидат в ожидание до замка: проверка id и путей, ожидания основы
    из дерева base_revision либо HEAD. Тот же id с другим телом отказ, с
    тем же телом повтор."""
    if not ID_RE.fullmatch(candidate_id):
        raise Refusal("id только из букв, цифр, точки, дефиса и подчёркивания, не длиннее 80")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise Refusal("тело не в UTF-8")
    projection = parse_projection(projection, scope, content_type)
    base_revision = None
    if content_type == "manifest":
        _changes, base_revision = parse_manifest(body)
    candidate = {
        "scope": scope, "id": candidate_id, "source": source, "session": session,
        "content_type": content_type, "projection": projection, "body": text,
        "submitted_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        .replace("+00:00", "Z"),
        "base": None, "expectations": {}, "commit": None, "result": {}, "reason": None,
    }
    paths = direct_paths(candidate)
    for path in paths:
        require_no_symlinks(root, path)
    # Без base_revision основа это ветка main, а не HEAD: посреди rebase
    # движка вершина отсоединена и мгновенна, и ожидания от неё позже
    # отказали бы кандидату как «запись менялась».
    base = base_revision or svodgit.rev(root, "refs/heads/main") or svodgit.head(root)
    if base_revision and svodgit.rev(root, base_revision) is None:
        raise Refusal(f"base_revision {base_revision} нет в истории репозитория")
    candidate["base"] = base
    candidate["expectations"] = {p: (svodgit.blob(root, base, p) if base else None) for p in paths}
    path = candidate_path(scope, candidate_id, state)
    data = json.dumps(candidate, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8")
    if not svodgit.create_file(path, data):
        existing = svodgit.read_json(path) or {}
        if not _same_intent(existing, candidate):
            raise Refusal(f"кандидат {candidate_id} уже ждёт с другим телом; выбери другой id "
                          f"или удали {path}")
        return path, existing
    old_failure = failed_path(scope, candidate_id, state)
    if old_failure.exists():
        old_failure.unlink()
    return path, candidate


def refuse_before_submit(*, scope: str, candidate_id: str, source: str, session: str,
                         content_type: str, reason: str, state: Path | None = None) -> Path | None:
    """Отказ до кандидата (плохая проекция, тело, id занят другим телом)
    сохраняется в failed/ той же формой, что и отказ проверок: статус его
    покажет, повторная подача с тем же id заменит. Небезопасный id или
    область файла не получают: имя файла строится из них."""
    if not ID_RE.fullmatch(candidate_id) or not svodgit.SCOPE_RE.fullmatch(scope):
        return None
    if candidate_path(scope, candidate_id, state).exists():
        # Под этим id уже ждёт другое намерение: его не стирать и не
        # заслонять отказом, слова отказа уходят вызывающему.
        return None
    candidate = {
        "scope": scope, "id": candidate_id, "source": source, "session": session,
        "content_type": content_type, "projection": None, "body": None,
        "submitted_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        .replace("+00:00", "Z"),
        "base": None, "expectations": {}, "commit": None, "result": {}, "reason": reason,
    }
    target = failed_path(scope, candidate_id, state)
    svodgit.replace_file(target, json.dumps(candidate, ensure_ascii=False, indent=1,
                                            sort_keys=True).encode("utf-8"))
    return target


def save_candidate(path: Path, candidate: dict) -> None:
    svodgit.replace_file(path, json.dumps(candidate, ensure_ascii=False, indent=1,
                                          sort_keys=True).encode("utf-8"))


def fail_candidate(path: Path, candidate: dict, reason: str, state: Path | None = None) -> Path:
    candidate = dict(candidate, reason=reason)
    target = failed_path(candidate["scope"], candidate["id"], state)
    svodgit.replace_file(target, json.dumps(candidate, ensure_ascii=False, indent=1,
                                            sort_keys=True).encode("utf-8"))
    if path.exists():
        path.unlink()
    return target


# ---------------------------------------------------------------------------
# Проход apply (шаги 1-9 дизайна), вызывается под замком

def _restore(root: Path, paths, head_tree: dict[str, bytes]) -> None:
    """Пути кандидата возвращаются к HEAD."""
    for path in sorted(paths):
        if path in head_tree:
            svodgit.git(root, "checkout", "--quiet", "HEAD", "--", path)
        else:
            svodgit.git(root, "rm", "--quiet", "--cached", "--ignore-unmatch", "--", path)
            target = root / path
            if target.exists() or target.is_symlink():
                target.unlink()


def _index_bytes(root: Path, path: str) -> bytes | None:
    result = svodgit.git(root, "cat-file", "blob", f":{path}", check=False)
    return result.stdout if result.returncode == 0 else None


def _worktree_bytes(root: Path, path: str) -> bytes | None:
    target = root / path
    try:
        return target.read_bytes()
    except (OSError, IsADirectoryError):
        return None


def _clean_leftovers(root: Path, files: dict[str, bytes | None], head_tree: dict[str, bytes]) -> None:
    """Шаг 2: грязное дерево допустимо только как след упавшего прохода
    на путях кандидата; иначе кандидат ждёт, репозиторий не трогается."""
    dirty = svodgit.dirty_paths(root)
    if not dirty:
        return
    foreign = sorted(dirty - set(files))
    if foreign:
        raise Wait("в репозитории правят руками, кандидат ждёт: " + ", ".join(foreign))
    for path in sorted(dirty):
        allowed = {files[path], head_tree.get(path)}
        for content in (_index_bytes(root, path), _worktree_bytes(root, path)):
            if content not in allowed:
                raise Wait(f"{path}: незакоммиченное содержимое не похоже ни на кандидата, "
                           "ни на основу; разбери руками, кандидат ждёт")
    _restore(root, dirty, head_tree)


def _check_base(candidate: dict, root: Path, head: str | None, head_tree: dict[str, bytes],
                files: dict[str, bytes | None]) -> None:
    """Шаг 4: сверка основы по прямым путям."""
    stale = []
    for path in direct_paths(candidate):
        expected = candidate["expectations"].get(path)
        current = svodgit.blob(root, head, path) if head else None
        if current == expected:
            continue
        wanted = files[path]
        if wanted is None and current is None:
            continue
        if wanted is not None and head_tree.get(path) == wanted:
            continue
        stale.append(path)
    if stale:
        raise Refusal("запись менялась после того, как её читал агент: " + ", ".join(stale)
                      + "; перечитай и подай заново")


def _write(root: Path, files: dict[str, bytes | None]) -> None:
    for path, data in sorted(files.items()):
        target = root / path
        if data is None:
            if target.exists():
                target.unlink()
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    svodgit.git(root, "add", "-A", "--", *sorted(files))


def verify_trees(root: Path, scope: str, new: str, old: str | None,
                 config: memoryverify.Config, scanner: str | None,
                 today: dt.date | None) -> memoryverify.Report:
    return memoryverify.check(svodgit.read_tree(root, new), svodgit.read_tree(root, old),
                              root=scope, config=config, today=today, scanner=scanner)


def apply(path: Path, candidate: dict, *, root: Path, scope: str,
          config: memoryverify.Config, scanner: str | None = None,
          today: dt.date | None = None, state: Path | None = None) -> dict:
    """Один проход по кандидату под замком. Результат: state saved,
    pending либо failed, слова, коммит."""
    notes: list[str] = []
    written = False
    files: dict[str, bytes | None] = {}
    head_tree: dict[str, bytes] = {}
    try:
        healed = svodgit.heal(root)
        notes += [f"вылечено: {h}" for h in healed]
        if svodgit.rebase_in_progress(root):
            raise Wait("идёт ручной rebase ветки main; закончи его (git rebase --continue) "
                       "или отмени (git rebase --abort), кандидат ждёт")
        if svodgit.branch(root) != "main":
            where = svodgit.branch(root) or "отсоединённая вершина"
            raise Wait(f"репозиторий не на ветке main ({where}); верни main руками")
        head = svodgit.head(root)
        head_tree = svodgit.read_tree(root, head)
        files, file_notes = compute_files(candidate, head_tree, scope, config)
        notes += file_notes
        _clean_leftovers(root, files, head_tree)
        fetched, why = svodgit.fetch(root)
        remote = None
        if fetched:
            remote = svodgit.remote_head(root)
            if svodgit.fast_forward(root, head, remote):
                head = remote
                head_tree = svodgit.read_tree(root, head)
                files, _ = compute_files(candidate, head_tree, scope, config)
        else:
            notes.append(f"сети нет ({why}); работаем от локальной вершины, таймер отправит")
        _check_base(candidate, root, head, head_tree, files)
        # Вершина впереди сервера (чужие ручные коммиты, первая публикация):
        # публикация сверяет дерево против сервера, как это делает таймер,
        # иначе коммит без происхождения уехал бы на сервер вместе с кандидатом.
        verify_ahead = fetched and remote != head
        written = True
        _write(root, files)
        tree = svodgit.write_tree(root)
        report = memoryverify.Report(ok=True, errors=[], warnings=[])
        if head and tree == svodgit.tree_of(root, head):
            # Всё уже в HEAD: след упавшего прохода после update-ref либо
            # повтор. Пустой коммит не делается, публикуется вершина.
            commit = head
            notes.append("дерево уже равно HEAD, нового коммита нет")
        else:
            if head and candidate.get("commit") is None and svodgit.subject_exists(
                    root, COMMIT_PREFIX + candidate["id"], "HEAD"):
                _restore(root, files, head_tree)
                raise Refusal(f"коммит «{COMMIT_PREFIX}{candidate['id']}» уже есть в истории; "
                              "выбери другой id")
            report = verify_trees(root, scope, tree, head, config, scanner, today)
            # Предупреждения только по файлам кандидата: сироты вики-ссылок в
            # нетронутых записях каждой подаче перечислять незачем.
            report.warnings = [w for w in report.warnings if w.split(":", 1)[0] in files]
            notes += report.warnings
            if not report.ok:
                _restore(root, files, head_tree)
                raise Refusal("; ".join(report.errors))
            commit = svodgit.commit_tree(root, tree, head, COMMIT_PREFIX + candidate["id"])
            if svodgit.tree_of(root, commit) != tree:
                _restore(root, files, head_tree)
                raise Wait("дерево коммита не равно проверенному; повтор в следующем проходе")
            svodgit.update_ref(root, "refs/heads/main", commit, head)
            candidate["commit"] = commit
        candidate["commit"] = commit
        candidate["result"] = {p: svodgit.blob(root, commit, p) for p in direct_paths(candidate)}
        candidate["reason"] = None
        save_candidate(path, candidate)
        if not fetched:
            candidate["reason"] = "сети нет; коммит локальный, таймер отправит"
            save_candidate(path, candidate)
            return {"state": "pending", "commit": commit, "reason": candidate["reason"],
                    "notes": notes, "warnings": report.warnings}
        outcome, words, final = publish(root, scope, commit, config, scanner=scanner, today=today,
                                        verify_ahead=verify_ahead)
        if final != commit:
            candidate["commit"] = final
            candidate["result"] = {p: svodgit.blob(root, final, p) for p in direct_paths(candidate)}
        if outcome == "saved":
            path.unlink()
            return {"state": "saved", "commit": final, "notes": notes, "warnings": report.warnings}
        candidate["reason"] = words
        save_candidate(path, candidate)
        return {"state": "pending", "commit": final, "reason": words, "notes": notes,
                "warnings": report.warnings}
    except Refusal as exc:
        target = fail_candidate(path, candidate, str(exc), state)
        return {"state": "failed", "reason": str(exc), "file": str(target), "notes": notes}
    except Wait as exc:
        candidate["reason"] = str(exc)
        save_candidate(path, candidate)
        return {"state": "pending", "commit": candidate.get("commit"), "reason": str(exc),
                "notes": notes}
    except svodgit.GitError:
        raise
    except Exception as exc:  # noqa: BLE001 - закрытый ответ словами, не трассировка
        words = f"{type(exc).__name__}: {exc}"
        if candidate.get("commit"):
            # Коммит уже в main: ошибка публикации или учёта. Кандидат ждёт,
            # таймер докажет доставку git-ом либо повторит.
            candidate["reason"] = f"после коммита: {words}; таймер повторит"
            save_candidate(path, candidate)
            return {"state": "pending", "commit": candidate["commit"],
                    "reason": candidate["reason"], "notes": notes}
        # Проверка не смогла выполниться (битая кодировка сводки, тема без
        # tokens, отказ стенда): это не «ждём таймера», а отказ с причиной.
        # Иначе кандидат зависал в ожидании без слов и каждый прогон таймера
        # падал на нём, не доходя до остальных. Начатая запись откатывается.
        if written:
            try:
                _restore(root, files, head_tree)
            except svodgit.GitError:
                pass
        reason = f"проверка не выполнилась: {words}"
        target = fail_candidate(path, candidate, reason, state)
        return {"state": "failed", "reason": reason, "file": str(target), "notes": notes}


# ---------------------------------------------------------------------------
# Публикация закреплённой вершины: одна функция у писателя и таймера

def rebase_onto(root: Path, scope: str, commit: str, remote: str,
                config: memoryverify.Config, scanner: str | None,
                today: dt.date | None) -> tuple[str, str, str]:
    """Rebase на отсоединённой вершине; main переводится на результат
    только после зелёной проверки против дерева сервера."""
    old_main = svodgit.rev(root, "refs/heads/main")
    marker = svodgit.engine_rebase_marker(root)
    svodgit.git(root, "checkout", "--quiet", "--detach", commit)
    marker.write_text(commit, encoding="utf-8")
    try:
        result = svodgit.git(root, "rebase", "--quiet", remote, check=False)
        if result.returncode != 0:
            conflicts = svodgit.out(root, "diff", "--name-only", "--diff-filter=U", check=False).split()
            svodgit.git(root, "rebase", "--abort", check=False)
    finally:
        # Метка снимается только когда rebase действительно кончился: после
        # таймаута git он может продолжаться, и лечение обязано знать, чей он.
        if marker.exists() and not svodgit.rebase_in_progress(root):
            marker.unlink()
    if result.returncode != 0:
        svodgit.git(root, "checkout", "--quiet", "main")
        where = ", ".join(conflicts) if conflicts else result.stderr.decode("utf-8", "replace").strip()
        return "pending", f"конфликт с сервером: {where}; две версии нужно свести руками", commit
    rebased = svodgit.head(root)
    report = verify_trees(root, scope, rebased, remote, config, scanner, today)
    if not report.ok:
        svodgit.git(root, "checkout", "--quiet", "main")
        return "pending", "после rebase дерево красное против сервера: " + "; ".join(report.errors), commit
    svodgit.update_ref(root, "refs/heads/main", rebased, old_main)
    svodgit.git(root, "checkout", "--quiet", "main")
    return "ok", "", rebased


def publish(root: Path, scope: str, commit: str, config: memoryverify.Config, *,
            scanner: str | None = None, today: dt.date | None = None,
            verify_ahead: bool = False) -> tuple[str, str, str]:
    """Опубликовать ровно этот коммит в main сервера. Вершина сервера
    берётся из fetch этого прохода. (saved|pending, слова, итоговый коммит)."""
    if not svodgit.has_remote(root):
        return "pending", "у репозитория нет origin; публиковать некуда", commit
    for _round in range(PUBLISH_ROUNDS):
        remote = svodgit.remote_head(root)
        if remote and svodgit.is_ancestor(root, commit, remote):
            return "saved", "", commit
        if remote and not svodgit.is_ancestor(root, remote, commit):
            state, words, commit = rebase_onto(root, scope, commit, remote, config, scanner, today)
            if state != "ok":
                return state, words, commit
            if svodgit.is_ancestor(root, commit, remote):
                return "saved", "", commit
        elif verify_ahead:
            report = verify_trees(root, scope, commit, remote, config, scanner, today)
            if not report.ok:
                return "pending", "дерево вершины красное против сервера: " + "; ".join(report.errors), commit
        problem = svodgit.scan_range(root, remote, commit, scanner)
        if problem:
            return "pending", problem, commit
        accepted, words = svodgit.push(root, commit, remote)
        if accepted:
            return "saved", "", commit
        fetched, why = svodgit.fetch(root)
        if not fetched:
            return "pending", why, commit
        if svodgit.remote_head(root) == remote:
            return "pending", words, commit
    return "pending", "сервер уходил вперёд три круга подряд; таймер повторит", commit


# ---------------------------------------------------------------------------
# Доставка и повтор ожидающих (таймер)

def blobs_match(root: Path, commit: str, result: dict[str, str | None]) -> bool:
    return bool(result) and all(svodgit.blob(root, commit, p) == oid for p, oid in result.items())


def delivered(root: Path, candidate: dict) -> bool:
    """Доставка доказана git-ом: хеш достижим из origin/main либо blob
    каждого прямого пути на сервере равен результату коммита."""
    commit = candidate.get("commit")
    remote = svodgit.remote_head(root)
    if not commit or not remote:
        return False
    if svodgit.rev(root, commit) and svodgit.is_ancestor(root, commit, remote):
        return True
    return blobs_match(root, remote, candidate.get("result") or {})


def committed_locally(root: Path, candidate: dict) -> bool:
    commit = candidate.get("commit")
    head = svodgit.head(root)
    if not commit or not head:
        return False
    if svodgit.rev(root, commit) and svodgit.is_ancestor(root, commit, head):
        return True
    return blobs_match(root, head, candidate.get("result") or {})


def retry_pending(root: Path, scope: str, config: memoryverify.Config, *,
                  fetched: bool, scanner: str | None = None,
                  today: dt.date | None = None, state: Path | None = None) -> list[dict]:
    """Повтор кандидатов области под уже взятым замком: доставлен, удалить;
    закоммичен локально, ничего; иначе apply заново. Без сети ничего не
    удаляется."""
    outcomes = []
    directory = svodgit.pending_dir(scope, state)
    if not directory.is_dir():
        return outcomes
    for path in sorted(directory.glob("*.json")):
        candidate = svodgit.read_json(path)
        if candidate is None or candidate.get("id") != path.stem:
            outcomes.append({"id": path.stem, "state": "unreadable", "file": str(path)})
            continue
        try:
            if candidate.get("commit"):
                if fetched and delivered(root, candidate):
                    path.unlink()
                    outcomes.append({"id": candidate["id"], "state": "delivered"})
                    continue
                if committed_locally(root, candidate):
                    outcomes.append({"id": candidate["id"], "state": "committed",
                                     "reason": candidate.get("reason")})
                    continue
            result = apply(path, candidate, root=root, scope=scope, config=config,
                           scanner=scanner, today=today, state=state)
        except svodgit.GitError as exc:
            # Один кандидат с отказом git не останавливает остальных; причина
            # остаётся в его файле, чтобы статус сказал словами.
            candidate["reason"] = f"git отказал: {exc}"
            save_candidate(path, candidate)
            result = {"state": "error", "reason": candidate["reason"]}
        outcomes.append({"id": candidate["id"], **{k: v for k, v in result.items()
                                                   if k in ("state", "reason", "commit")}})
    return outcomes


# ---------------------------------------------------------------------------
# Команда remember

def run_remember(*, scope: str, candidate_id: str, source: str, session: str,
                 content_type: str, body: bytes, projection: dict | None,
                 data_root: Path | None = None, state: Path | None = None,
                 scanner: str | None = None, today: dt.date | None = None) -> tuple[int, dict]:
    try:
        root = svodgit.scope_root(scope, data_root)
        svodgit.require_marker(root, scope)
    except ValueError as exc:
        return EXIT_ERROR, {"state": "error", "reason": str(exc)}
    try:
        config = load_config()
    except OSError as exc:
        return EXIT_ERROR, {"state": "error", "reason": f"конфигурация не читается ({exc}); "
                            f"задай {configpaths.CONFIG_ENV}"}
    try:
        path, candidate = submit(scope=scope, candidate_id=candidate_id, source=source,
                                 session=session, content_type=content_type, body=body,
                                 projection=projection, root=root, state=state)
    except Refusal as exc:
        target = refuse_before_submit(scope=scope, candidate_id=candidate_id, source=source,
                                      session=session, content_type=content_type,
                                      reason=str(exc), state=state)
        result = {"state": "failed", "reason": str(exc)}
        if target is not None:
            result["file"] = str(target)
        return EXIT_FAILED, result
    try:
        with svodgit.lock(root, exclusive=True):
            result = apply(path, candidate, root=root, scope=scope, config=config,
                           scanner=scanner, today=today, state=state)
    except svodgit.Busy as exc:
        return EXIT_BUSY, {"state": "busy", "reason": str(exc), "file": str(path)}
    except svodgit.GitError as exc:
        candidate["reason"] = f"git отказал: {exc}"
        save_candidate(path, candidate)
        return EXIT_ERROR, {"state": "error", "reason": str(exc), "file": str(path)}
    result.setdefault("id", candidate_id)
    result.setdefault("scope", scope)
    if result["state"] == "saved":
        return EXIT_SAVED, result
    if result["state"] == "pending":
        result.setdefault("file", str(path))
        return EXIT_PENDING, result
    return EXIT_FAILED, result
