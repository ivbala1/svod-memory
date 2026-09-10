#!/usr/bin/env python3
"""Писатель памяти (Свод-0, шаг 3): один репозиторий, один кандидат,
один проход `apply`, общий с таймером цикл публикации.

Кандидат это файл в каталоге ожидания: намерение записи с ожиданиями
основы. Он пишется до замка и живёт, пока git не докажет доставку.
Успех только после приёма сервером; сети нет, коммит остаётся
локальным, кандидат ждёт таймера (решение владельца 1а).
"""

from __future__ import annotations

from dataclasses import dataclass
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

def refuse_all(errors: list[str], tail: str = "") -> None:
    """Один отказ со всеми нарушениями стадии. Пустой список это молчание.
    `tail` называет словами, что дальше не проверялось, если после этих
    нарушений вычислять было нечего."""
    if not errors:
        return
    raise Refusal("; ".join(errors + ([tail] if tail else [])))


def path_errors(path) -> list[str]:
    """Все нарушения целевого пути разом: внутри memory/, нормализован,
    без .. и .git, и это Markdown."""
    if not isinstance(path, str) or not path or "\x00" in path or path.startswith("/"):
        return [f"путь {path!r} недопустим"]
    parts = PurePosixPath(path).parts
    if not parts:
        return [f"путь {path}: только внутри memory/, без .. и .git"]
    errors = []
    if (any(part in ("..", ".", "") for part in parts) or any(part == ".git" for part in parts)
            or "/".join(parts) != path or not path.startswith("memory/")):
        errors.append(f"путь {path}: только внутри memory/, без .. и .git")
    if not (parts[-1].endswith(".md") or parts[-1] == ".gitkeep"):
        errors.append(f"путь {path}: в области памяти допустимы только Markdown-файлы")
    return errors


def symlink_errors(root: Path, path: str) -> list[str]:
    current = root
    for part in PurePosixPath(path).parts:
        current = current / part
        if current.is_symlink():
            return [f"путь {path}: компонент {current.name} это символическая ссылка"]
    return []


def parse_projection(projection: dict | None, scope: str, content_type: str) -> dict:
    if content_type == "manifest":
        if projection not in (None, {}, {"kind": "manifest"}):
            raise Refusal("манифесту имя записи и указатель не нужны: пути лежат в нём самом")
        return {}
    if content_type != "markdown":
        raise Refusal("content-type только markdown либо manifest")
    if not isinstance(projection, dict) or not projection:
        raise Refusal("записи нужно имя: --record")
    errors: list[str] = []
    slug = projection.get("record_slug")
    if not isinstance(slug, str) or not memoryverify.SLUG_RE.fullmatch(slug):
        errors.append("имя записи (--record) это slug вида [a-z0-9_]{1,64}")
    keys = set(projection) - {"base_revision"}
    pointer = keys == {"record_slug", "index_line", "index_section"}
    if keys == {"record_slug"}:
        if memoryverify.client_name(scope) is not None:
            errors.append("клиентской записи нужен указатель: --section и --line "
                          "(строка уезжает в раздел сводки темы)")
    elif not pointer:
        errors.append("подача несёт --record, либо --record вместе с --section и --line")
    if pointer:
        line = projection["index_line"]
        section = projection["index_section"]
        if not isinstance(line, str) or not line.strip() or "\n" in line or len(line.encode()) > 1024:
            errors.append("--line: одна непустая строка со ссылкой на запись")
        if not isinstance(section, str) or not section.strip():
            errors.append("--section: непустое имя раздела сводки")
        # Ссылка в строке обязана вести на подаваемую запись: иначе указатель
        # уезжает в сводку за чужую запись, а поданная остаётся без него.
        if isinstance(line, str) and isinstance(slug, str) and index_line_slug(line) != slug:
            errors.append(f"--line: строка со ссылкой на запись {slug}, например "
                          "«- [[имя]] чем полезна»")
    refuse_all(errors)
    if pointer:
        return {"record_slug": slug, "index_line": projection["index_line"],
                "index_section": projection["index_section"]}
    return {"record_slug": slug}


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
    errors: list[str] = []
    base = manifest.get("base_revision")
    if base is not None and not (isinstance(base, str) and re.fullmatch(r"[0-9a-f]{7,64}", base)):
        errors.append("base_revision манифеста это хеш коммита основы, от семи знаков")
    changes = []
    seen = set()
    # Каждое изменение проверяется до конца списка: агент видит все негодные
    # пути и операции разом, а не первый из них.
    for i, raw in enumerate(manifest["changes"]):
        if not isinstance(raw, dict) or raw.get("operation") not in ("put", "remove"):
            errors.append(f"изменение {i}: operation только put либо remove")
            continue
        path = raw.get("path")
        if isinstance(raw.get("area"), str) and isinstance(path, str) and not path.startswith("memory/"):
            path = f"{raw['area']}/{path}"
        bad = path_errors(path)
        if bad:
            errors += [f"изменение {i}: {problem}" for problem in bad]
            continue
        if path in seen:
            errors.append(f"изменение {i}: путь {path} повторяется")
        seen.add(path)
        if raw["operation"] == "put":
            content = raw.get("content")
            if not isinstance(content, str):
                errors.append(f"изменение {i}: put требует строку content")
                continue
            changes.append({"operation": "put", "path": path, "content": content})
        else:
            if "content" in raw:
                errors.append(f"изменение {i}: remove не несёт content")
                continue
            changes.append({"operation": "remove", "path": path})
    refuse_all(errors)
    return changes, base


def expand_manifest_files(body: bytes) -> bytes:
    """Изменение манифеста может назвать локальный файл вместо целого
    документа внутри строки JSON. Подстановка делается один раз, до
    кандидата: в ожидании лежит самодостаточное намерение, а не ссылка на
    файл, который к утру изменится."""
    try:
        manifest = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return body  # словами об этом скажет parse_manifest
    if not isinstance(manifest, dict) or not isinstance(manifest.get("changes"), list):
        return body
    errors: list[str] = []
    touched = False
    for i, raw in enumerate(manifest["changes"]):
        if not isinstance(raw, dict) or "file" not in raw:
            continue
        source = raw.pop("file")
        if raw.get("operation") != "put":
            # Удалению текст не нужен, и читать названный файл незачем.
            errors.append(f"изменение {i}: file несёт только операция put")
            continue
        if "content" in raw:
            errors.append(f"изменение {i}: content и file вместе не подаются")
            continue
        if not isinstance(source, str) or not source:
            errors.append(f"изменение {i}: file это путь к локальному файлу")
            continue
        try:
            with open(source, "rb") as поток:
                # Читаем на байт больше предела: ошибочно названный огромный
                # файл или бесконечный поток не должны съесть память до того,
                # как проверка скажет о пределе словами.
                data = поток.read(memoryverify.MAX_RECORD_BYTES + 1)
        except OSError as exc:
            errors.append(f"изменение {i}: file {source} не читается ({exc})")
            continue
        if len(data) > memoryverify.MAX_RECORD_BYTES:
            errors.append(f"изменение {i}: file {source} больше предела записи")
            continue
        try:
            raw["content"] = data.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"изменение {i}: file {source} не в UTF-8")
            continue
        touched = True
    refuse_all(errors)
    return json.dumps(manifest, ensure_ascii=False).encode("utf-8") if touched else body


# ---------------------------------------------------------------------------
# Указатели: шапка записи и раздел сводки

def _yaml_scalar(value: str, откуда: str = "шапки") -> str:
    if '"' not in value:
        return f'"{value}"'
    if "'" not in value:
        return f"'{value}'"
    raise Refusal(f"значение {откуда} содержит оба вида кавычек, шапку из него не собрать")


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
    # Полнота шапки считается прямо по её полям. Раньше её выводили из
    # record_index_line, а та отдаёт None по трём разным причинам сразу
    # (снята из индекса, чужой type, пустое поле), и запись с полной шапкой
    # и `listed: false` получала отказ «несёт часть полей».
    ключи = {key for key in ("type", "title", "index") if key in fields}
    полные = {key for key in ключи if fields.get(key, "").strip()}
    if полные == {"type", "title", "index"}:
        return body, (f"--line не использована: шапка записи {slug} "
                      "уже несёт type, title и index")
    errors: list[str] = []
    if ключи:
        errors.append(f"шапка записи {slug} несёт часть полей индекса; нужны все три "
                      "(type, title, index) непустыми либо ни одного")
    match = mc.INDEX_ITEM_RE.match(projection["index_line"])
    if match is None or Path(match.group(2)).name != f"{slug}.md":
        errors.append(f"--line не ссылается на {slug}.md")
    kinds = {section: kind for kind, section in mc.INDEX_SECTIONS.items()}
    kind = kinds.get(projection.get("index_section"))
    if kind not in mc.INDEX_TYPES:
        errors.append(f"раздел {projection.get('index_section')!r} не раздел индекса "
                      f"({', '.join(mc.INDEX_SECTIONS[k] for k in mc.INDEX_TYPES)})")
    title, hook = ("", "") if match is None else (match.group(1).strip(), match.group(3).strip())
    if match is not None and (not title or not hook):
        errors.append("--line: пустой заголовок или крючок")
    refuse_all(errors)
    insert = (f"type: {kind}\ntitle: {_yaml_scalar(title, 'заголовка в --line')}\n"
              f"index: {_yaml_scalar(hook, 'крючка в --line')}\n")
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        new = text[:end + 1] + insert + text[end + 1:]
    else:
        new = "---\n" + insert + "---\n" + text
    return new.encode("utf-8"), ""


def index_line_slug(line: str) -> str | None:
    """Запись, которой принадлежит строка: САМАЯ ЛЕВАЯ ссылка любого вида.
    Раньше markdown-ссылки перебирались раньше вики-ссылок независимо от
    места, и строка «[отчёт](other.md) про [[нашу_запись]]» приписывалась
    чужой записи."""
    clean = memoryverify.strip_code(line)
    кандидаты: list[tuple[int, str]] = []
    for match in memoryverify.MARKDOWN_LINK_RE.finditer(clean):
        name = Path(match.group(1)).name
        if name.endswith(".md"):
            кандидаты.append((match.start(), name[:-3]))
    for match in memoryverify.DELIVERED_WIKI_LINK_RE.finditer(clean):
        name = Path(match.group(1).strip()).name
        if name:
            кандидаты.append((match.start(), name[:-3] if name.endswith(".md") else name))
    return min(кандидаты)[1] if кандидаты else None


def pointer_slug(line: str) -> str | None:
    """Слаг строки, которая является УКАЗАТЕЛЕМ: пункт списка, начинающийся со
    ссылки на запись. Ровно такую строку писатель и порождает, поэтому только
    такую он вправе заменить. Проза со ссылкой в середине предложения это
    факт заказчика, а не указатель: её не трогают."""
    match = re.match(r"^\s*[-*]\s+(.*)$", line)
    if not match:
        return None
    # Слаг берётся ТОЛЬКО из ссылки, которая открывает пункт. Иначе указателем
    # считались бы «- [ ] задача, схема в [[запись]]» (пункт-дело) и
    # «- [Инцидент](https://…) ещё открыт, схема в [[запись]]» (пункт с
    # внешней ссылкой), где слаг пришёл бы из середины строки.
    начало = match.group(1)
    if начало.startswith("[["):
        конец = начало.find("]]")
        ссылка = начало[:конец + 2] if конец > 0 else ""
    else:
        первая = re.match(r"^\[[^\]]*\]\([^)\s]+\)", начало)
        ссылка = первая.group(0) if первая else ""
    return index_line_slug(ссылка) if ссылка else None


def insert_rollup_pointer(rollup_text: str, section: str, line: str) -> tuple[str, list[str]]:
    """Строка-указатель в названный раздел сводки темы (по заголовку, регистр
    и краевые пробелы не значимы). Прежняя строка этой записи внутри раздела
    заменяется на месте, лишние повторы внутри раздела убираются.

    ⚠️ За пределами названного раздела не трогается ничего. Упоминание записи
    там это чаще всего проза заказчика с фактами, а не указатель, и молчаливое
    удаление такой строки теряло принятый факт. Найденные упоминания
    возвращаются словами: переносить их или нет, решает автор отдельной
    подачей, где обе правки видны и сторожатся объявленной основой."""
    slug = index_line_slug(line)
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
    # Обе беды независимы: строка без ссылки и раздел, которого нет.
    refuse_all(([] if slug is not None else
                ["--line без ссылки на запись указателем не является"])
               + ([] if start is not None else [f"раздела {section!r} нет в сводке темы"]))
    # Внутри названного раздела заменяем прежнюю строку записи: сперва
    # строгий указатель (пункт списка со ссылки), а если такого нет, любое
    # упоминание. В живых сводках указатель это чаще абзац с фактами и
    # ссылкой, и запрещать эту форму значит запрещать привычный стиль.
    строгие = [i for i in range(start + 1, end)
               if not fenced[i] and pointer_slug(lines[i]) == slug]
    любые = [i for i in range(start + 1, end)
             if not fenced[i] and index_line_slug(lines[i]) == slug]
    # Повторы убираются только среди СТРОГИХ указателей: их писатель и делал.
    # Из нестрогих упоминаний заменяется ровно одно, первое; остальные строки
    # раздела это чужая проза, их не удаляют, о них говорят словами.
    inside = строгие or любые[:1]
    прочие = [i for i, current in enumerate(lines)
              if not fenced[i] and i not in inside and index_line_slug(current) == slug]
    # Всё, что уедет из сводки, запоминается ДО правки списка: после вставки и
    # удаления строк прежние номера указывают не туда, а автор обязан увидеть
    # каждую тронутую строку.
    заменено = lines[inside[0]].strip() if inside else ""
    убранные = [lines[i].strip() for i in sorted(set(inside) - set(inside[:1]))]
    свои = [i for i in прочие if start < i < end]
    чужие_разделы = sorted({_section_of(lines, fenced, i) for i in прочие if i not in свои})
    if inside:
        lines[inside[0]] = line
        for i in sorted(set(inside) - {inside[0]}, reverse=True):
            del lines[i]
            if i < end:
                end -= 1
    else:
        position = start
        for i in range(start + 1, end):
            if lines[i].strip():
                position = i
        if mc.scan_code_fences(lines[start:end])[1]:
            raise Refusal(f"раздел {section!r} заканчивается незакрытым блоком кода; "
                          "указатель класть некуда")
        lines.insert(position + 1, line)
    notes = []
    if заменено and заменено != line.strip():
        notes.append(f"в разделе {section!r} заменена прежняя строка записи: {_кратко(заменено)}")
    for убранная in убранные:
        notes.append(f"в разделе {section!r} убран лишний указатель этой записи: {_кратко(убранная)}")
    if свои:
        notes.append(f"в разделе {section!r} запись упомянута ещё {len(свои)} раз "
                     "(строки не тронуты): указатель у записи один, остальное это проза")
    if чужие_разделы:
        notes.append(f"запись упомянута ещё в разделах {', '.join(чужие_разделы)}; "
                     "строки оставлены как есть, перенос решает автор отдельной подачей")
    return "\n".join(lines) + ("\n" if rollup_text.endswith("\n") else ""), notes


def _кратко(текст: str, предел: int = 160) -> str:
    """Длинная строка в словах обрезается ЗАМЕТНО: без пометки автор решил
    бы, что уехало ровно столько, сколько показано."""
    return текст if len(текст) <= предел else f"{текст[:предел]}… (всего {len(текст)} знаков)"


def _section_of(lines: list[str], fenced: list[bool], index: int) -> str:
    """Заголовок раздела, в котором лежит строка; «до первого раздела», если
    строка стоит выше любого заголовка."""
    for i in range(index, -1, -1):
        if fenced[i]:
            continue
        heading = re.match(r"^##\s+(.+?)\s*$", lines[i])
        if heading:
            return f"«{heading.group(1).strip()}»"
    return "до первого раздела"


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
    текст, слова = insert_rollup_pointer(
        rollup.decode("utf-8"), projection["index_section"], projection["index_line"])
    files[pointer] = текст.encode("utf-8")
    notes += [f"{pointer}: {w}" for w in слова]
    return files, notes


def candidate_tree(base_tree: dict[str, bytes],
                   files: dict[str, bytes | None]) -> dict[str, bytes]:
    """Дерево кандидата: копия дерева основы с наложенными файлами и
    вычеркнутыми удаляемыми. Только целиком: на одних файлах кандидата
    замещение записи с уводом предшественника в архив прошло бы зелёным,
    потому что находимость, достижимость и индекс смотрят на весь корпус."""
    tree = dict(base_tree)
    for path, data in files.items():
        if data is None:
            tree.pop(path, None)
        else:
            tree[path] = data
    return tree


def candidate_path(scope: str, candidate_id: str, base: Path | None = None) -> Path:
    return svodgit.pending_dir(scope, base) / f"{candidate_id}.json"


def failed_path(scope: str, candidate_id: str, base: Path | None = None) -> Path:
    return svodgit.failed_dir(scope, base) / f"{candidate_id}.json"


def _same_intent(a: dict, b: dict) -> bool:
    keys = ("scope", "id", "content_type", "projection", "body")
    if not all(a.get(k) == b.get(k) for k in keys):
        return False
    # Основа входит в намерение, только когда её НАЗВАЛ автор: та же запись
    # от другой прочитанной версии это другая защита от затирания. Основа,
    # выведенная из ветки main, меняется сама (свой же локальный коммит), и
    # повтором той же команды управлять не должна.
    if not (a.get("declared") or b.get("declared")):
        return True
    return a.get("declared") == b.get("declared") and a.get("base") == b.get("base")


def make_candidate(*, scope: str, candidate_id: str, source: str, session: str,
                   content_type: str, body: bytes, projection: dict | None,
                   root: Path, base: str | None = None) -> dict:
    """Намерение записи как данные: проверка id и путей, ожидания основы
    из объявленной версии либо из ветки main. Ничего не пишет, поэтому
    годится и сухому прогону.

    Объявленная основа это версия корпуса, на которой автор читал запись.
    Она делает две вещи: сверка не даёт затереть более позднюю правку, и
    запись разрешено переписать под тем же именем."""
    # Три проверки конверта независимы друг от друга, поэтому выполняются все
    # три, а не до первого нарушения.
    errors: list[str] = []
    if not ID_RE.fullmatch(candidate_id):
        errors.append("id только из букв, цифр, точки, дефиса и подчёркивания, не длиннее 80")
    text = None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        errors.append("тело не в UTF-8")
    parsed: dict = {}
    try:
        parsed = parse_projection(projection, scope, content_type)
    except Refusal as exc:
        errors.append(str(exc))
    base_revision = None
    if base is not None and not re.fullmatch(r"[0-9a-f]{7,64}", base.strip()):
        errors.append("объявленная основа это хеш коммита, от семи знаков")
    elif base is not None:
        base_revision = base.strip()
    if content_type == "manifest" and text is not None:
        try:
            body = expand_manifest_files(body)
            text = body.decode("utf-8")
            _changes, from_manifest = parse_manifest(body)
            # Сверка после приведения к полному хешу: тот же коммит короткой и
            # полной записью это одна основа, а не две разные.
            if from_manifest and base_revision \
                    and (svodgit.rev(root, from_manifest) or from_manifest) \
                    != (svodgit.rev(root, base_revision) or base_revision):
                errors.append("основа объявлена дважды и по-разному: в манифесте "
                              f"{from_manifest}, флагом {base_revision}")
            base_revision = base_revision or from_manifest
        except Refusal as exc:
            errors.append(str(exc))
    refuse_all(errors, "дальше не проверялось: пути кандидата и его дерево "
                       "считаются только по исправному конверту")
    projection = parsed
    candidate = {
        "scope": scope, "id": candidate_id, "source": source, "session": session,
        "content_type": content_type, "projection": projection, "body": text,
        "submitted_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        .replace("+00:00", "Z"),
        "base": None, "declared": base_revision is not None, "expectations": {},
        "commit": None, "result": {}, "reason": None,
    }
    paths = direct_paths(candidate)
    for path in paths:
        errors += symlink_errors(root, path)
    if base_revision:
        полная = svodgit.rev(root, base_revision)
        if полная is None:
            errors.append(f"объявленной основы {base_revision} нет в истории репозитория")
        else:
            base_revision = полная
    refuse_all(errors)
    # Без base_revision основа это ветка main, а не HEAD: посреди rebase
    # движка вершина отсоединена и мгновенна, и ожидания от неё позже
    # отказали бы кандидату как «запись менялась».
    base = base_revision or svodgit.rev(root, "refs/heads/main") or svodgit.head(root)
    candidate["base"] = base
    candidate["expectations"] = {p: (svodgit.blob(root, base, p) if base else None) for p in paths}
    return candidate


def submit(*, scope: str, candidate_id: str, source: str, session: str,
           content_type: str, body: bytes, projection: dict | None,
           root: Path, state: Path | None = None, base: str | None = None) -> tuple[Path, dict]:
    """Кандидат в ожидание до замка. Тот же id с другим телом отказ, с
    тем же телом повтор."""
    candidate = make_candidate(scope=scope, candidate_id=candidate_id, source=source,
                               session=session, content_type=content_type, body=body,
                               projection=projection, root=root, base=base)
    path = candidate_path(scope, candidate_id, state)
    data = json.dumps(candidate, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8")
    if not svodgit.create_file(path, data):
        existing = svodgit.read_json(path) or {}
        if not _same_intent(existing, candidate):
            raise Refusal(f"кандидат {candidate_id} уже ждёт с другим телом или другой основой; "
                          f"выбери другой id или удали {path}")
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
# Проверка до замка и сухой прогон


@dataclass
class Checked:
    """Вердикт, посчитанный до замка, вместе с обеими сторонами сравнения.
    Проход под замком берёт его, только когда его собственные входы вышли
    ровно такими же; иначе проверяет заново. Вердикт не окончателен: основу
    обновляет fetch уже под замком."""
    report: memoryverify.Report
    base: dict[str, bytes]
    tree: dict[str, bytes]
    notes: list[str]
    revision: str | None = None


def precheck(candidate: dict, *, root: Path, scope: str, config: memoryverify.Config,
             scanner: str | None = None, today: dt.date | None = None) -> Checked:
    """Вердикт по кандидату без замка: оба дерева считаются в памяти от
    вершины main, репозиторий не меняется ни одним вызовом. Пять секунд
    проверки уходят из-под замка, а отказ оформления перестаёт стоить
    записи в рабочее дерево и отката."""
    base = svodgit.rev(root, "refs/heads/main") or svodgit.head(root)
    base_tree = svodgit.read_tree(root, base)
    files, notes = compute_files(candidate, base_tree, scope, config)
    tree = candidate_tree(base_tree, files)
    if tree == base_tree:
        # Менять нечего (повтор принятого тела): проверять заново тот же
        # корпус незачем, проход под замком тоже не станет.
        notes.append("дерево уже равно основе, менять нечего")
        report = memoryverify.Report(ok=True, errors=[], warnings=[])
    else:
        report = memoryverify.check(tree, base_tree, root=scope, config=config,
                                    today=today, scanner=scanner)
        # Предупреждения только по файлам кандидата, как и под замком.
        report.warnings = [w for w in report.warnings if w.split(":", 1)[0] in files]
    return Checked(report=report, base=base_tree, tree=tree, notes=notes, revision=base)


def run_dry(*, scope: str, candidate_id: str, source: str, session: str,
            content_type: str, body: bytes, projection: dict | None, root: Path,
            config: memoryverify.Config, scanner: str | None = None,
            today: dt.date | None = None, base: str | None = None) -> tuple[int, dict]:
    """Сухой прогон: тот же вердикт, что у подачи, без замка, коммита и
    следа в каталоге состояния. Вердикт относится к локальному снимку:
    занятость id, устаревание основы, изменения на сервере и сканирование
    отправляемой истории видны только проходу под замком."""
    result = {"state": "checked", "dry_run": True, "id": candidate_id, "scope": scope}
    try:
        candidate = make_candidate(scope=scope, candidate_id=candidate_id, source=source,
                                   session=session, content_type=content_type, body=body,
                                   projection=projection, root=root, base=base)
        checked = precheck(candidate, root=root, scope=scope, config=config,
                           scanner=scanner, today=today)
    except Refusal as exc:
        return EXIT_FAILED, {**result, "state": "failed", "reason": str(exc)}
    except svodgit.GitError as exc:
        return EXIT_ERROR, {**result, "state": "error", "reason": f"git отказал: {exc}"}
    except Exception as exc:  # noqa: BLE001 - закрытый ответ словами, не трассировка
        return EXIT_FAILED, {**result, "state": "failed",
                             "reason": f"проверка не выполнилась: {type(exc).__name__}: {exc}"}
    result["notes"] = checked.notes
    result["warnings"] = checked.report.warnings
    result["base"] = checked.revision
    if not checked.report.ok:
        return EXIT_FAILED, {**result, "state": "failed",
                             "reason": "; ".join(checked.report.errors)}
    # Нулевой код у сухого прогона значит «проверки зелёные», а не «сохранено».
    return EXIT_SAVED, result


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
          today: dt.date | None = None, state: Path | None = None,
          checked: Checked | None = None) -> dict:
    """Один проход по кандидату под замком. Результат: state saved,
    pending либо failed, слова, коммит. `checked` это вердикт, полученный
    до замка; он берётся только когда входы проверки вышли теми же."""
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
                # Слова о файлах пересчитываются вместе с самими файлами:
                # сводка после перемотки другая, и прежние слова про неё
                # уже неверны.
                files, свежие = compute_files(candidate, head_tree, scope, config)
                notes = [note for note in notes if note not in file_notes] + свежие
                file_notes = свежие
        else:
            notes.append(f"сети нет ({why}); работаем от локальной вершины, таймер отправит")
        _check_base(candidate, root, head, head_tree, files)
        # Вершина впереди сервера (чужие ручные коммиты, первая публикация):
        # публикация сверяет дерево против сервера, как это делает таймер,
        # иначе коммит без происхождения уехал бы на сервер вместе с кандидатом.
        verify_ahead = fetched and remote != head
        # Вердикт до записи: если входы проверки вышли теми же, что до замка
        # (та же основа после fetch, то же дерево кандидата), красный отчёт
        # отказывает, не тронув рабочее дерево и не требуя отката.
        reused = (checked is not None and checked.base == head_tree
                  and checked.tree == candidate_tree(head_tree, files))
        if reused and not checked.report.ok:
            notes += checked.report.warnings
            raise Refusal("; ".join(checked.report.errors))
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
            if head and candidate.get("commit") is None and not candidate.get("declared") \
                    and svodgit.subject_exists(root, COMMIT_PREFIX + candidate["id"], "HEAD"):
                # Имя уже занято в истории, и подача не назвала версию, на
                # которой читала запись: без этого не отличить осознанную
                # правку от случайного повтора чужого id. С объявленной
                # основой правку сторожит сверка ожиданий.
                _restore(root, files, head_tree)
                raise Refusal(f"коммит «{COMMIT_PREFIX}{candidate['id']}» уже есть в истории; "
                              "назови основу (--base), если правишь эту запись, "
                              "либо выбери другой id")
            if reused and checked.tree == svodgit.read_tree(root, tree):
                # Проверка получила бы ровно те же входы: те же пять секунд
                # второй раз не тратим. Любое расхождение (сдвиг вершины,
                # чужой коммит, правка байтов при add) возвращает полную
                # проверку уходящего дерева.
                report = checked.report
                notes.append("проверено до замка, уходит то же дерево")
            else:
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
        # Все файлы кандидата, а не только прямые пути: указатель клиентской
        # записи живёт в сводке, и доставка без него это не доставка.
        candidate["result"] = {p: svodgit.blob(root, commit, p) for p in files}
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
            candidate["result"] = {p: svodgit.blob(root, final, p) for p in files}
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


def drop_settled_failures(root: Path, scope: str, config: memoryverify.Config, *,
                          state: Path | None = None) -> list[str]:
    """Отказ, чьё намерение уже исполнено, снимается сам. Доказывает это
    git, а не часы: файлы кандидата, наложенные на дерево вершины, ничего в
    нём не меняют, значит факт в корпусе уже есть (обычно сохранён под
    другим именем), а файл отказа только держит статус красным.

    Отказ, оформленный до кандидата, тела не несёт: по нему нельзя посчитать
    ни файлов, ни дерева, и он остаётся ждать человека."""
    dropped: list[str] = []
    directory = svodgit.failed_dir(scope, state)
    if not directory.is_dir():
        return dropped
    head = svodgit.head(root)
    if head is None:
        return dropped
    head_tree = svodgit.read_tree(root, head)
    for path in sorted(directory.glob("*.json")):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        candidate = svodgit.read_json(path)
        if not candidate or candidate.get("body") is None:
            continue
        try:
            files, _notes = compute_files(candidate, head_tree, scope, config)
        except Exception:  # noqa: BLE001 - неисполнимый отказ просто остаётся
            continue
        if candidate_tree(head_tree, files) != head_tree:
            continue
        # Отказ пишется без общего замка, поэтому между чтением и снятием под
        # тем же именем могла лечь НОВАЯ беда. Снимаем ровно проверенный файл.
        # Окно между этой сверкой и unlink остаётся: закрыть его можно только
        # замком на каталоге состояния, то есть вторым учётом поверх git.
        # Цена окна это слова одного отказа, никогда не факт, поэтому платим
        # словами, а не механизмом.
        try:
            if path.read_bytes() != raw:
                continue
            path.unlink()
        except OSError:
            continue
        dropped.append(candidate.get("id") or path.stem)
    return dropped


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
                 scanner: str | None = None, today: dt.date | None = None,
                 dry_run: bool = False, base: str | None = None) -> tuple[int, dict]:
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
    # Дата берётся один раз на запуск: сама проверка иначе взяла бы текущую
    # на каждый вызов, и на границе суток вердикт до замка перестал бы
    # годиться проходу под замком.
    today = today or dt.datetime.now(dt.timezone.utc).date()
    if dry_run:
        return run_dry(scope=scope, candidate_id=candidate_id, source=source, session=session,
                       content_type=content_type, body=body, projection=projection,
                       root=root, config=config, scanner=scanner, today=today, base=base)
    try:
        path, candidate = submit(scope=scope, candidate_id=candidate_id, source=source,
                                 session=session, content_type=content_type, body=body,
                                 projection=projection, root=root, state=state, base=base)
    except Refusal as exc:
        target = refuse_before_submit(scope=scope, candidate_id=candidate_id, source=source,
                                      session=session, content_type=content_type,
                                      reason=str(exc), state=state)
        result = {"state": "failed", "reason": str(exc)}
        if target is not None:
            result["file"] = str(target)
        return EXIT_FAILED, result
    try:
        checked = precheck(candidate, root=root, scope=scope, config=config,
                           scanner=scanner, today=today)
    except Exception:  # noqa: BLE001 - вердикт до замка не обязателен
        # Отказ или сбой проверки до замка окончательным не является: основу
        # обновляет fetch уже под замком, и слова скажет проход apply.
        checked = None
    try:
        with svodgit.lock(root, exclusive=True):
            result = apply(path, candidate, root=root, scope=scope, config=config,
                           scanner=scanner, today=today, state=state, checked=checked)
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
