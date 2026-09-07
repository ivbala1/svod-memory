#!/usr/bin/env python3
"""Проверки кандидата как чистые функции (Свод-0, шаг 2).

Вход: дерево кандидата и дерево-основа как отображения «путь -> байты»
области памяти ОДНОГО репозитория, вид корня («common» либо
«clients/<имя>»), байты конфигурации (topics.json и вопросы стенда),
дата. Живые репозитории, соседние корни, состояние машины не читаются.
Выход: отчёт словами, каждая строка называет файл и что сделать.

Каждая проверка отвечает на цель модели угроз:
секреты (5), форма и ссылки (1, 4), шапка (7, 4),
достижимость и крючок (4), чужой заказчик (2, 3), разделы сводки
(2, 4), стенд (4, 2). Нет цели, нет проверки.

Модуль лист зависимостей: роутер и стенд импортируются внутри функций,
потому что роутер сам импортирует memoryctl, а memoryctl переэкспортирует
переехавшие сюда имена.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import datetime as dt
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import unicodedata

import topiclayout


# ---------------------------------------------------------------------------
# Вход и выход

@dataclass(frozen=True)
class Config:
    """Байты конфигурации ровно той версии, которой проверяем."""
    topics: bytes
    questions: bytes | None = None


@dataclass
class Report:
    ok: bool
    errors: list[str]
    warnings: list[str]
    facts: dict = field(default_factory=dict)


MEMORY_PREFIX = "memory/"
MAX_RECORD_BYTES = 256 * 1024
SCANNER_TIMEOUT_SEC = 180.0
CONFLICT_RE = re.compile(r"^(?:<<<<<<<|=======|>>>>>>>)(?: .*)?$", re.MULTILINE)
MARKDOWN_LINK_RE = re.compile(
    r"\]\((?!https?://|mailto:|#)([^)\s]+\.md)(?:#[^)]*)?\)")
WIKI_LINK_RE = re.compile(r"\[\[([^\]|#]+)")
# Целая вики-ссылка доставленной выдачи: закрывающие скобки обязательны,
# иначе ссылка, оборванная бюджетом доставки, засчиталась бы как доехавшая.
DELIVERED_WIKI_LINK_RE = re.compile(
    r"\[\[([^\[\]\n|#]+)(?:[#|][^\[\]\n]*)?\]\]")
# Грамматика slug: вопросы регистра и Unicode исключены.
SLUG_RE = re.compile(r"[a-z0-9_]{1,64}")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
DATE_FIELDS = ("valid_until", "review_after", "observed_at")
LINK_FIELDS = ("requires", "contradicts")
# Поля шапки, у которых есть читатель. Опечатка в имени поля молча
# теряла бы факт, поэтому неизвестное поле у новой и переписанной записи
# это отказ.
SCHEMA_FIELDS = ("valid_until", "review_after", "supersedes", "requires",
                 "contradicts", "type", "title", "index", "listed",
                 "probe", "source", "observed_at")
DESCRIPTIVE_TOP_FIELDS = frozenset({"name", "description", "metadata"})
KNOWN_TOP_FIELDS = DESCRIPTIVE_TOP_FIELDS | frozenset(SCHEMA_FIELDS)
# Поля, обязательные у новой и переписанной записи (решение владельца
# 04.09.2026): происхождение и крючок поиска. Задним числом не выдумываются.
PROVENANCE_FIELDS = ("source", "observed_at", "probe")

SECRET_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b")),
    ("telegram-bot-token", re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b")),
)

SUPERSEDED_RE = re.compile(r"(?:Свёрнуто в сводку|Замещено записью)\s*\[([^\]]+)\]")
FENCE_RE = re.compile(r"^(?P<indent>[ \t]{0,3})(?P<fence>`{3,}|~{3,})(?P<info>.*)$")


# ---------------------------------------------------------------------------
# Разбор текста

def strip_code(text: str) -> str:
    """Заменяет код пробелами, сохраняя разбиение на строки."""
    out: list[str] = []
    fence: str | None = None
    for line in text.splitlines():
        if fence is None:
            opener = FENCE_RE.match(line)
            if opener and not (opener.group("fence")[0] == "`" and "`" in opener.group("info")):
                fence = opener.group("fence")
                out.append("")
                continue
            out.append(_strip_inline_code(line))
            continue
        closer = FENCE_RE.match(line)
        closes = (
            closer is not None
            and closer.group("fence")[0] == fence[0]
            and len(closer.group("fence")) >= len(fence)
            and not closer.group("info").strip()
        )
        out.append("")
        if closes:
            fence = None
    return "\n".join(out)


def _strip_inline_code(line: str) -> str:
    out: list[str] = []
    index = 0
    length = len(line)
    while index < length:
        if line[index] == "\\" and index + 1 < length:
            out.append(line[index:index + 2])
            index += 2
            continue
        if line[index] != "`":
            out.append(line[index])
            index += 1
            continue
        start = index
        while index < length and line[index] == "`":
            index += 1
        run = index - start
        cursor = index
        while cursor < length:
            if line[cursor] != "`":
                cursor += 1
                continue
            edge = cursor
            while cursor < length and line[cursor] == "`":
                cursor += 1
            if cursor - edge == run:
                break
        else:
            # Пары нет: серия остаётся обычным текстом, и ссылки рядом видны.
            out.append("`" * run)
            continue
        out.append(" ")
        index = cursor
    return "".join(out)


def parse_frontmatter(text: str) -> tuple[dict[str, str], str | None]:
    if not text.startswith("---\n"):
        return {}, None
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}, "unclosed frontmatter"
    result: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if not line.strip() or line.startswith((" ", "\t", "#")):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip().strip('"\'')
    return result, None


def body_without_frontmatter(text: str) -> str:
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end >= 0:
            return text[end + 5:]
    return text


# Служебные файлы области: индекс и датированный инбокс. Записями не
# являются: у них нет ни происхождения, ни крючка, а достижимость инбокса
# держит строка преамбулы индекса.
SERVICE_FILES = frozenset({"MEMORY.md", "personal_inbox.md"})


def _is_record_path(path: str) -> bool:
    """Действующая запись: memory/<slug>.md, кроме служебных файлов."""
    name = path[len(MEMORY_PREFIX):] if path.startswith(MEMORY_PREFIX) else ""
    return bool(name) and name.endswith(".md") and "/" not in name and name not in SERVICE_FILES


def _records(tree: dict[str, bytes]) -> dict[str, str]:
    """slug -> текст действующих записей (нечитаемые пропускаются: их
    называет проверка формы)."""
    out = {}
    for path, data in tree.items():
        if not _is_record_path(path):
            continue
        try:
            out[path[len(MEMORY_PREFIX):-3]] = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
    return out


def _decode(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _snapshot_supersedes(tree: dict[str, bytes]) -> tuple[dict[str, str], set[str], set[str]]:
    """Карта slug -> цель supersedes плюс множества действующих и архивных."""
    edges: dict[str, str] = {}
    active: set[str] = set()
    archived: set[str] = set()
    for path, data in tree.items():
        name = path[len(MEMORY_PREFIX):] if path.startswith(MEMORY_PREFIX) else None
        if not name or not name.endswith(".md") or name == "MEMORY.md":
            continue
        if name.startswith("topics/"):
            continue
        if name.startswith("archive/"):
            slug = name[len("archive/"):-3]
            if "/" in slug:
                continue
            archived.add(slug)
        elif "/" in name:
            continue
        else:
            slug = name[:-3]
            active.add(slug)
        text = _decode(data)
        if text is None:
            continue
        fields, error = parse_frontmatter(text)
        if error:
            continue
        target = fields.get("supersedes")
        if target:
            edges[slug] = target
    return edges, active, archived


# ---------------------------------------------------------------------------
# Конфигурация: темы, раскладка, дрейф

@dataclass(frozen=True)
class Topics:
    specs: dict                                   # тема -> TopicSpec роутера
    placement: dict[str, tuple[str, str | None]]  # файл сводки -> (тема, владелец)
    drift: tuple[tuple[str, tuple[str, ...], frozenset[str]], ...]


def load_topics(raw: bytes) -> Topics:
    import memorycontext as mc
    label = Path("topics.json")
    parsed = json.loads(raw.decode("utf-8"))
    specs = mc.parse_topics(raw, label)
    placement = topiclayout.placement_from_config(parsed, label)
    drift = []
    for name, entry in parsed["topics"].items():
        tokens = entry.get("tokens")
        if not isinstance(tokens, list) or not tokens:
            raise ValueError(f"topics.json: у темы {name} нет tokens, дрейф не посчитать")
        drift.append((name, tuple(tokens), frozenset(entry.get("hotKeep") or ())))
    return Topics(specs=specs, placement=placement, drift=tuple(drift))


def client_name(root: str) -> str | None:
    return root[len("clients/"):] if root.startswith("clients/") else None


# ---------------------------------------------------------------------------
# 1. Секреты по патчу (цель 5)

def find_gitleaks() -> str | None:
    """Путь к gitleaks: PATH, затем ~/.local/bin (standalone-установка
    мимо пакетного менеджера в PATH неинтерактивных оболочек не попадает)."""
    executable = shutil.which("gitleaks")
    if executable:
        return executable
    local = Path.home() / ".local" / "bin" / "gitleaks"
    return str(local) if local.is_file() and os.access(local, os.X_OK) else None


def added_lines(base: dict[str, bytes], candidate: dict[str, bytes]) -> dict[str, list[str]]:
    """Строки, которых в основе не было: только они уезжают в историю
    впервые. Удалённые и неизменные строки сканировать незачем."""
    out: dict[str, list[str]] = {}
    for path, data in sorted(candidate.items()):
        old = base.get(path)
        if old == data:
            continue
        new_lines = data.decode("utf-8", "replace").splitlines()
        old_set = set(old.decode("utf-8", "replace").splitlines()) if old is not None else set()
        added = [line for line in new_lines if line not in old_set]
        if added:
            out[path] = added
    return out


def secret_errors(base: dict[str, bytes], candidate: dict[str, bytes],
                  scanner: str | None) -> list[str]:
    """Встроенные шаблоны и gitleaks по добавленным строкам. Нет сканера,
    нет записи: секреты ловим случайные, но ловим всегда."""
    errors: list[str] = []
    patch = added_lines(base, candidate)
    for path, lines in patch.items():
        text = "\n".join(lines)
        for name, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"{path}: похоже на секрет ({name}); убери его из записи")
    if not patch:
        return errors
    if not scanner:
        errors.append("сканер секретов gitleaks не найден; без него запись не принимается")
        return errors
    with tempfile.TemporaryDirectory(prefix="svod-secrets-") as tmp:
        for path, lines in patch.items():
            target = Path(tmp) / path.replace("/", "__")
            target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            result = subprocess.run(
                [scanner, "detect", "--no-git", "--source", tmp, "--no-banner",
                 "--redact", "--exit-code", "9"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=SCANNER_TIMEOUT_SEC)
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"сканер секретов не отработал ({exc}); запись не принимается")
            return errors
    if result.returncode == 9:
        errors.append("сканер секретов gitleaks нашёл похожее на секрет в добавленных "
                      "строках; убери его и подай заново")
    elif result.returncode != 0:
        errors.append(f"сканер секретов завершился с кодом {result.returncode}; "
                      "запись не принимается")
    return errors


# ---------------------------------------------------------------------------
# 2. Форма файла (цели 1, 4)

def file_errors(relative: str, text: str) -> list[str]:
    """Форма одного файла области памяти: размер, NUL, перевод строки,
    маркеры конфликта, встроенные шаблоны секретов, грамматика имени
    записи, шапка и её поля. relative без префикса memory/."""
    errors: list[str] = []
    label = f"memory/{relative}"
    if len(text.encode("utf-8")) > MAX_RECORD_BYTES:
        errors.append(f"{label}: файл больше {MAX_RECORD_BYTES} байт")
    if "\x00" in text:
        errors.append(f"{label}: NUL byte is forbidden")
    if text and not text.endswith("\n"):
        errors.append(f"{label}: final newline is required")
    if CONFLICT_RE.search(text):
        errors.append(f"{label}: conflict marker found")
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            errors.append(f"{label}: possible secret ({name})")
    if relative.endswith(".md") and relative != "MEMORY.md":
        pure = PurePosixPath(relative)
        if len(pure.parts) == 1 or (len(pure.parts) == 2 and pure.parts[0] == "archive"):
            if not SLUG_RE.fullmatch(pure.stem):
                errors.append(
                    f"{label}: имя записи обязано быть slug вида [a-z0-9_]{{1,64}}")
    fields, error = parse_frontmatter(text)
    if error:
        errors.append(f"{label}: {error}")
    for name in DATE_FIELDS:
        value = fields.get(name)
        if value is None:
            continue
        if not _valid_date(value):
            errors.append(
                f"{label}: {name} обязан быть корректной датой ISO ГГГГ-ММ-ДД (UTC), "
                f"получено: {value!r}")
    if "/" not in relative and relative.endswith(".md") and relative != "MEMORY.md":
        errors.extend(index_field_errors(fields, label))
    return errors


def _valid_date(value: str) -> bool:
    if not DATE_RE.fullmatch(value):
        return False
    try:
        dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def index_field_errors(frontmatter: dict[str, str], label: str) -> list[str]:
    """Поля генерируемого индекса: type из словаря разделов, listed только
    false, title и index непустые и только вместе, и только при type."""
    import memorycontext as mc
    errors: list[str] = []
    kind = frontmatter.get("type")
    if kind is not None and kind not in mc.INDEX_TYPES:
        errors.append(f"{label}: type обязан быть одним из "
                      f"{', '.join(mc.INDEX_TYPES)}, получено {kind!r}")
    listed = frontmatter.get("listed")
    if listed is not None and listed != "false":
        errors.append(f"{label}: listed допускает только false (строку в "
                      f"индекс не выводить), получено {listed!r}")
    present = {key for key in ("title", "index") if key in frontmatter}
    if present and present != {"title", "index"}:
        errors.append(f"{label}: title и index задаются только вместе")
    for key in sorted(present):
        if not frontmatter[key].strip():
            errors.append(f"{label}: {key} не может быть пустым")
    if present and kind is None:
        errors.append(f"{label}: строка индекса без type не знает своего раздела")
    return errors


def shape_errors(candidate: dict[str, bytes]) -> list[str]:
    errors: list[str] = []
    for path, data in sorted(candidate.items()):
        if not path.startswith(MEMORY_PREFIX):
            errors.append(f"{path}: файл вне области memory")
            continue
        relative = path[len(MEMORY_PREFIX):]
        if relative.endswith("/.gitkeep") or relative == ".gitkeep":
            continue
        if not relative.endswith(".md"):
            errors.append(f"{path}: в области памяти допустимы только Markdown-файлы")
            continue
        text = _decode(data)
        if text is None:
            errors.append(f"{path}: файл не в UTF-8")
            continue
        errors.extend(file_errors(relative, text))
    return errors


# ---------------------------------------------------------------------------
# 3. Шапка (цели 7, 4)

def touched_records(base: dict[str, bytes], candidate: dict[str, bytes]) -> dict[str, str]:
    """slug -> «new» либо «rewritten»: тело без шапки отличается от
    основы. Правка одной шапки записи не переписывает."""
    old = _records(base)
    out: dict[str, str] = {}
    for slug, text in _records(candidate).items():
        if slug not in old:
            out[slug] = "new"
        elif body_without_frontmatter(old[slug]) != body_without_frontmatter(text):
            out[slug] = "rewritten"
    return out


def header_errors(base: dict[str, bytes], candidate: dict[str, bytes]) -> list[str]:
    errors: list[str] = []
    touched = touched_records(base, candidate)
    for slug, text in sorted(_records(candidate).items()):
        label = f"memory/{slug}.md"
        fields, error = parse_frontmatter(text)
        if error or slug not in touched:
            continue
        what = "новая запись" if touched[slug] == "new" else "переписанная запись"
        unknown = sorted(set(fields) - KNOWN_TOP_FIELDS)
        if unknown:
            errors.append(
                f"{label}: поля шапки без читателя: {', '.join(unknown)}; "
                f"{what} несёт только name, description, metadata и поля схемы")
        for name in PROVENANCE_FIELDS:
            if not fields.get(name, "").strip():
                errors.append(
                    f"{label}: {what} обязана нести {name} "
                    f"({_provenance_hint(name)})")
    errors.extend(supersedes_errors(candidate))
    errors.extend(link_field_errors(candidate, base))
    return sorted(set(errors))


def probe_required_errors(candidate: dict[str, bytes], root: str) -> list[str]:
    """Доставляемая запись без крючка (цель 4), по всему дереву кандидата.
    Доставляемая: в индексном корне запись со строкой индекса, в
    клиентском любая запись (её отдаёт указатель сводки, listed ей не
    указ). Свёрнутая запись индексного корня и архив крючка не требуют:
    свёрнутую держит проза сводки в другом репозитории, архив находят
    только по имени."""
    import memorycontext as mc
    client = client_name(root) is not None
    errors: list[str] = []
    for slug, text in sorted(_records(candidate).items()):
        fields, error = parse_frontmatter(text)
        if error or fields.get("probe", "").strip():
            continue
        if not client and mc.record_index_line(f"{slug}.md", fields) is None:
            continue
        errors.append(
            f"memory/{slug}.md: доставляемая запись без крючка probe (как об этом "
            "спросят своими словами); без крючка находимость записи ничем не доказана")
    return errors


def _provenance_hint(name: str) -> str:
    return {"source": "откуда факт: разговор, документ, наблюдение",
            "observed_at": "дата, когда факт был верен, ГГГГ-ММ-ДД",
            "probe": "как об этом спросят своими словами"}[name]


def supersedes_errors(tree: dict[str, bytes]) -> list[str]:
    """Граф supersedes без циклов, самоссылок, потерянных целей и развилок;
    замещённая запись не остаётся действующей."""
    edges, active, archived = _snapshot_supersedes(tree)
    everything = active | archived
    errors: list[str] = []
    active_successors: dict[str, list[str]] = {}
    for slug, target in sorted(edges.items()):
        if target == slug:
            errors.append(f"memory/{slug}.md: supersedes ссылается сам на себя")
            continue
        if target not in everything:
            errors.append(
                f"memory/{slug}.md: цель supersedes «{target}» не существует "
                "ни среди действующих записей, ни в архиве")
            continue
        if slug in active:
            active_successors.setdefault(target, []).append(slug)
            if target in active:
                errors.append(
                    f"memory/{slug}.md: замещённая запись «{target}» осталась действующей; "
                    "уведи её в архив той же транзакцией, устаревший факт не может "
                    "выдаваться как действующий (R6)")
    for target, successors in sorted(active_successors.items()):
        if len(successors) > 1:
            errors.append(
                f"развилка supersedes: «{target}» замещена сразу {', '.join(sorted(successors))}; "
                "у старого слага один действующий преемник (A7)")
    for start in sorted(edges):
        current, seen = start, {start}
        while current in edges:
            current = edges[current]
            if current in seen:
                errors.append(f"цикл supersedes через «{current}» (A7)")
                break
            seen.add(current)
    return sorted(set(errors))


def _snapshot_link_fields(tree: dict[str, bytes]) -> dict[str, dict[str, tuple[str, ...]]]:
    result: dict[str, dict[str, tuple[str, ...]]] = {}
    for slug, text in _records(tree).items():
        fields, error = parse_frontmatter(text)
        if error:
            continue
        links = {}
        for name in LINK_FIELDS:
            raw = fields.get(name)
            if raw:
                links[name] = tuple(x.strip() for x in raw.split(",") if x.strip())
        if links:
            result[slug] = links
    return result


def link_field_errors(tree: dict[str, bytes],
                      before: dict[str, bytes] | None = None) -> list[str]:
    """requires и contradicts: цель существует и разрешается в действующую
    запись; новая связь на уже архивную цель не принимается."""
    edges, active, archived = _snapshot_supersedes(tree)
    links = _snapshot_link_fields(tree)
    was = _snapshot_link_fields(before) if before is not None else None
    backward: dict[str, list[str]] = {}
    for slug, target in edges.items():
        backward.setdefault(target, []).append(slug)

    def resolves(slug: str) -> bool:
        current, seen = slug, {slug}
        while current not in active:
            candidates = sorted(backward.get(current, ()),
                                key=lambda name: (name not in active, name))
            following = next((name for name in candidates if name not in seen), None)
            if following is None:
                return False
            seen.add(following)
            current = following
        return True

    errors: list[str] = []
    for slug, fields in sorted(links.items()):
        for name, targets in sorted(fields.items()):
            for target in targets:
                label = f"memory/{slug}.md: {name} -> «{target}»"
                if not SLUG_RE.fullmatch(target):
                    errors.append(f"{label}: цель не является slug (A4)")
                    continue
                if target == slug:
                    errors.append(f"{label}: связь сама на себя")
                    continue
                if target in active:
                    continue
                if target not in archived:
                    errors.append(f"{label}: цель не существует ни среди действующих, "
                                  "ни в архиве (A6)")
                    continue
                fresh = was is not None and target not in was.get(slug, {}).get(name, ())
                if fresh:
                    errors.append(
                        f"{label}: новая связь на уже архивную запись не принимается; "
                        "укажи действующего преемника (A6)")
                    continue
                if not resolves(target):
                    errors.append(
                        f"{label}: цепочка supersedes не ведёт к действующему "
                        "преемнику (A6)")
    return sorted(set(errors))


# ---------------------------------------------------------------------------
# 4. Ссылки внутри дерева (цель 4)

def link_errors(candidate: dict[str, bytes], topics: Topics | None = None,
                root: str = "personal") -> tuple[list[str], list[str]]:
    """Markdown-ссылки разрешаются внутри дерева. Ссылка на сводку темы,
    живущую у другого корня, законна: у неё логический путь. Ссылка за
    пределы корпуса не проверяется: её существование зависит от машины.
    Неразрешимая вики-ссылка это предупреждение."""
    errors: list[str] = []
    warnings: list[str] = []
    memory_root = Path("/memory")
    stems = {PurePosixPath(path).stem for path in candidate if path.endswith(".md")}
    placement = topics.placement if topics is not None else {}
    for path, data in sorted(candidate.items()):
        if not path.endswith(".md"):
            continue
        text = _decode(data)
        if text is None:
            continue
        archived = path.startswith("memory/archive/")
        text = strip_code(text)
        for target in MARKDOWN_LINK_RE.findall(text):
            clean = target.split("#", 1)[0]
            resolved = os.path.normpath(str(Path("/") / path).rsplit("/", 1)[0] + "/" + clean)
            if not resolved.startswith(str(memory_root) + "/"):
                # Ссылка за пределы корпуса: проверить её можно только на
                # диске конкретной машины, это дело doctor, не проверки дерева.
                continue
            inside = resolved[len("/memory/"):]
            if f"memory/{inside}" in candidate:
                continue
            if inside.startswith("topics/") and "/" not in inside[len("topics/"):]:
                place = placement.get(inside[len("topics/"):])
                if place is not None and place[1] and place[1] != root:
                    continue
            name = PurePosixPath(clean).name
            relocated = [p for p in candidate if PurePosixPath(p).name == name]
            if archived:
                warnings.append(f"{path}: archived note has stale link: {clean}")
            elif len(relocated) == 1:
                errors.append(f"{path}: link target moved: {clean} -> {relocated[0]}")
            else:
                errors.append(f"{path}: broken Markdown link: {clean}")
        for target in WIKI_LINK_RE.findall(text):
            stem = PurePosixPath(target.strip()).stem
            if stem and stem not in stems:
                # Вики-ссылка разрешается только внутри своей области. Глобальный
                # репозиторий живёт на машинах, где ничего другого нет: обрыв там
                # это отказ, в остальных областях предупреждение, как прежде.
                (errors if root == "global" else warnings).append(
                    f"{path}: unresolved wiki link: {stem}")
    return errors, warnings


# ---------------------------------------------------------------------------
# 5. Достижимость: сироты и архив не растут (цель 4)

_WORDISH = "_-./"


def _boundary_ok(ch: str) -> bool:
    """Сосед не продолжает имя. Точка словный знак намеренно: foo.md.bak
    не упоминание foo.md; комбинирующие знаки тоже не разделители."""
    if not ch:
        return True
    if ch.isalnum() or ch in _WORDISH:
        return False
    return unicodedata.category(ch)[0] != "M"


def _slug_mentioned(name: str, text: str) -> bool:
    base = name[:-3] if name.endswith(".md") else name
    for variant in (name, base):
        for m in re.finditer(re.escape(variant), text):
            before = text[m.start() - 1] if m.start() else ""
            after = text[m.end()] if m.end() < len(text) else ""
            if _boundary_ok(before) and _boundary_ok(after):
                return True
    return False


def router_index_text(tree: dict[str, bytes]) -> str:
    """Текст индекса тем же кодом, что у роутера: преамбула плюс строки из
    шапок. Роутер недоступен, пустой текст: ослаблять проверку нельзя."""
    try:
        import memorycontext as mc
    except Exception:
        return ""
    return mc.build_index_from_snapshot(tree, MEMORY_PREFIX) or ""


def router_index_slugs(index_text: str) -> set[str]:
    try:
        import memorycontext as mc
    except Exception:
        return set()
    return {entry.slug for entry in mc.parse_index(index_text)}


def unreachable_records(tree: dict[str, bytes], known_topics: set[str],
                        extra_rollups: str = "") -> set[str]:
    """Записи, недостижимые ни из индекса, ни из сводки темы. known_topics
    это пути сводок вида topics/<файл>."""
    from_index = router_index_slugs(router_index_text(tree))
    rollups = "\n".join(
        [text.decode("utf-8", "strict")
         for path, text in tree.items() if path[len(MEMORY_PREFIX):] in known_topics]
        + ([extra_rollups] if extra_rollups else []))
    orphans = set()
    for path in tree:
        if not path.startswith(MEMORY_PREFIX):
            continue
        name = path[len(MEMORY_PREFIX):]
        if name == "MEMORY.md" or name in known_topics or name.startswith("archive/"):
            continue
        if name in from_index or _slug_mentioned(name, rollups):
            continue
        orphans.add(name)
    return orphans


def invalid_archive(tree: dict[str, bytes], placement: dict | None = None,
                    root: str = "personal") -> set[str]:
    """Архивные записи без права называться архивными: пометка о замещении
    с существующим преемником вне архива и не индексом. Множество, а не
    ошибки: сравнивается до и после, расти не может."""
    bad = set()
    for path, content in tree.items():
        if not path.startswith("memory/archive/"):
            continue
        name = path[len(MEMORY_PREFIX):]
        text = _decode(content)
        if text is None:
            bad.add(name)
            continue
        m = SUPERSEDED_RE.search(text)
        if not m:
            bad.add(name)
            continue
        target = m.group(1).split("](")[0].strip().lstrip("./")
        if not target or target == name or target == "MEMORY.md" or target.startswith("archive/"):
            bad.add(name)
            continue
        exists = f"memory/{target}" in tree
        if (not exists and placement and target.startswith("topics/")
                and "/" not in target[len("topics/"):]):
            place = placement.get(target[len("topics/"):])
            exists = place is not None and place[1] is not None and place[1] != root
        if not exists:
            bad.add(name)
    return bad


def reach_errors(base: dict[str, bytes], candidate: dict[str, bytes],
                 topics: Topics, root: str) -> list[str]:
    known = {f"topics/{name}" for name in topics.placement}
    errors: list[str] = []
    for name in sorted(unreachable_records(candidate, known) - unreachable_records(base, known)):
        errors.append(
            f"memory/{name}: запись становится недостижимой (нет ни строки в индексе, "
            "ни упоминания в сводке темы); дай ей строку индекса в шапке (type, title, "
            "index) или упомяни в сводке той же подачей")
    before = invalid_archive(base, topics.placement, root)
    after = invalid_archive(candidate, topics.placement, root)
    replaced = {name for name in before & after
                if base.get(f"memory/{name}") != candidate.get(f"memory/{name}")}
    for name in sorted((after - before) | replaced):
        errors.append(
            f"memory/{name}: архивная запись обязана называть существующего преемника "
            "вне архива (пометка «Замещено записью» или «Свёрнуто в сводку»); старую "
            "запись без пометки можно оставить или удалить, но не переписать")
    return errors


# ---------------------------------------------------------------------------
# 6. Крючок находит запись (цель 4)

def _is_edge_punct(ch: str) -> bool:
    return unicodedata.category(ch).startswith("P")


def normalize_v13(text: str) -> str:
    norm = unicodedata.normalize("NFC", text).casefold()
    norm = " ".join(norm.split())
    start, end = 0, len(norm)
    while start < end and _is_edge_punct(norm[start]):
        start += 1
    while end > start and _is_edge_punct(norm[end - 1]):
        end -= 1
    return " ".join(norm[start:end].split())


def is_tautology(paraphrase: str, candidates) -> bool:
    """Крючок недопустимо совпадает с одной из строк записи."""
    norm = normalize_v13(paraphrase)
    if not norm:
        return True
    return any(normalize_v13(c) == norm for c in candidates if isinstance(c, str))


def tautology_candidates(slug: str, text: str) -> list[str]:
    """Строки записи, с которыми крючок не может совпадать: имя, поля
    индекса, name, description, первый заголовок."""
    fields, _ = parse_frontmatter(text)
    out = [slug, slug.replace("_", " "), fields.get("title", ""),
           fields.get("index", ""), fields.get("name", ""), fields.get("description", "")]
    for line in body_without_frontmatter(text).splitlines():
        if line.startswith("#"):
            out.append(line.lstrip("#").strip())
            break
    return [c for c in out if c]


def index_delivery(root: Path, question: str, today: dt.date) -> list[str]:
    """Прогон вопроса рабочим отбором роутера по выложенному дереву; слаги
    без расширения."""
    import memorycontext as mc
    entries = mc.parse_index(mc.build_index(root)) if (root / "memory" / "MEMORY.md").is_file() else ()
    chosen = mc.select_index_entries(root, question, entries, today=today)
    return [Path(entry.slug).stem for entry, _ in chosen]


def topic_delivery(root: Path, spec, question: str) -> str:
    """Полная выдача темы по вопросу тем же сборщиком, что у роутера,
    над выложенным деревом: сводка читается из него самого, без владельца."""
    import dataclasses
    import memorycontext as mc
    local = dataclasses.replace(spec, owner=None)
    decision = mc.RouteDecision(scope=spec.scope, source="check")
    text, _ = mc._topic_context(root, local, decision, question, "", "",
                                full_context=True, include_hot=False)
    return text


def delivered_link_present(delivered_text: str, slug: str) -> bool:
    """Однозначная ссылка на запись в доставленных байтах: Markdown-ссылка
    на файл либо целая вики-ссылка. Голое вхождение имени в прозе не
    считается."""
    name = f"{slug}.md"
    clean = strip_code(delivered_text)
    for target in MARKDOWN_LINK_RE.findall(clean):
        if Path(target).name == name:
            return True
    for target in DELIVERED_WIKI_LINK_RE.findall(clean):
        target = target.strip()
        if target and Path(target).name in (slug, name):
            return True
    return False


def probe_errors(base: dict[str, bytes], candidate: dict[str, bytes], *,
                 root: str, topics: Topics, laid_out: Path, today: dt.date,
                 facts: dict) -> list[str]:
    errors: list[str] = []
    client = client_name(root)
    spec = None
    if client is not None:
        spec = next((s for s in topics.specs.values() if s.owner == root), None)
    results: dict[str, bool] = {}
    for slug, text in sorted(_records(candidate).items()):
        fields, error = parse_frontmatter(text)
        if error:
            continue
        probe = fields.get("probe", "").strip()
        if not probe:
            continue
        if client is None and fields.get("listed") == "false":
            # Свёрнутую запись общего корня индекс не выдаёт по построению:
            # её держит упоминание в сводке (проверка достижимости), крючок
            # молчит. Клиентскую запись ищут через сводку, listed ей не указ.
            continue
        label = f"memory/{slug}.md"
        if is_tautology(probe, tautology_candidates(slug, text)):
            errors.append(f"{label}: крючок probe повторяет имя или заголовок записи; "
                          "напиши, как об этом спросят своими словами")
            continue
        if client is None:
            found = slug in index_delivery(laid_out, probe, today)
            hint = "отбор роутера по индексу его не выбирает; перепиши крючок или строку index"
        elif spec is None:
            results[slug] = True
            continue
        else:
            found = delivered_link_present(topic_delivery(laid_out, spec, probe), slug)
            hint = (f"выдача сводки {spec.filename} по этому вопросу не содержит ссылки "
                    "на запись; добавь указатель в выбираемый раздел или перепиши крючок")
        results[slug] = found
        if not found:
            errors.append(f"{label}: крючок «{probe}» не находит запись: {hint}")
    facts["probes"] = results
    return errors


# ---------------------------------------------------------------------------
# 7. Чужой заказчик (цели 2, 3)

def rollup_placement_errors(tree: dict[str, bytes] | set[str], placement: dict,
                            root: str) -> list[str]:
    """Сводка лежит в корне-владельце и только в нём."""
    client = client_name(root)
    errors = []
    for path in sorted(tree):
        if not path.startswith("memory/topics/"):
            continue
        name = path[len("memory/topics/"):]
        if "/" in name:
            errors.append(
                f"{path}: вложенный путь в memory/topics обходит правила размещения сводок")
            continue
        if not name or not name.endswith(".md"):
            continue
        place = placement.get(name)
        if client is not None:
            if place is not None and place[0] != client:
                errors.append(
                    f"{path}: сводка темы {place[0]} в клиентском корне "
                    f"clients/{client} это межклиентская утечка")
        elif place is not None and place[1]:
            errors.append(
                f"{path}: сводка темы {place[0]} живёт у владельца {place[1]}; "
                "копия в общем репозитории это второй канон, удали её той же транзакцией")
    if client is not None:
        for name, (topic, owner) in sorted(placement.items()):
            if owner == root and f"memory/topics/{name}" not in tree:
                errors.append(
                    f"memory/topics/{name}: каноническая сводка темы {topic} отсутствует "
                    f"в корне-владельце {root}")
    return errors


_ITEM_PTR_RE = re.compile(r"^\s*[-*]\s*\[[^\]]*\]\(([^)\s]+)\)")


def drifted_records(tree: dict[str, bytes], drift, own_client: str | None = None
                    ) -> dict[str, list[str]]:
    """Клиентские записи в общем индексе: тема -> слаги в порядке строк.
    Запись дрейфует по теме, если её имя содержит токен темы целым словом,
    она указана строкой индекса и не входит в hotKeep этой темы."""
    if "memory/MEMORY.md" not in tree:
        return {}
    slugs = []
    for line in router_index_text(tree).splitlines():
        m = _ITEM_PTR_RE.match(line)
        if m and "/" not in m.group(1) and m.group(1).endswith(".md"):
            slugs.append(m.group(1))
    out: dict[str, list[str]] = {}
    for topic, tokens, hot in drift:
        if own_client is not None and topic == own_client:
            continue
        mine = [s for s in slugs if s not in hot
                and any(re.search(r"(^|_)" + re.escape(t) + r"(_|\.)", s) for t in tokens)]
        if mine:
            out[topic] = mine
    return out


def drifted_slugs(tree: dict[str, bytes], drift, own_client: str | None = None) -> set[str]:
    return {s for files in drifted_records(tree, drift, own_client).values() for s in files}


def foreign_errors(base: dict[str, bytes], candidate: dict[str, bytes],
                   root: str, topics: Topics) -> list[str]:
    errors = rollup_placement_errors(candidate, topics.placement, root)
    client = client_name(root)
    fresh = drifted_slugs(candidate, topics.drift, client) - drifted_slugs(base, topics.drift, client)
    for slug in sorted(fresh):
        errors.append(
            f"memory/{slug}: клиентская запись не может появиться в общем индексе; "
            "место её содержимого в сводке темы, а строка индекса ведёт на сводку")
    return errors


# ---------------------------------------------------------------------------
# 8. Разделы сводки: потолок и выбираемость (цели 2, 4)

def rollup_section_delivery_size(rollup_text: str, section: str) -> tuple[int, int]:
    """Размер раздела сводки и его потолок доставки, в символах. Роутер
    режет раздел своим потолком, а указатель дописывается в конец, то есть
    в срезаемую часть: переросший раздел глотает указатель молча."""
    import memorycontext as mc
    wanted = section.strip().casefold()
    for part in mc.parse_sections(rollup_text):
        if part.title.strip().casefold() == wanted:
            return len(part.text), mc.section_cap(part)
    raise ValueError(f"раздела {section!r} нет в сводке темы")


def section_errors(base: dict[str, bytes], candidate: dict[str, bytes],
                   topics: Topics, facts: dict) -> tuple[list[str], list[str]]:
    import memorycontext as mc
    errors: list[str] = []
    warnings: list[str] = []
    sizes: dict[str, dict[str, list[int]]] = {}
    for path, data in sorted(candidate.items()):
        if not path.startswith("memory/topics/"):
            continue
        name = path[len("memory/topics/"):]
        place = topics.placement.get(name)
        text = _decode(data)
        if place is None or text is None:
            continue
        spec = topics.specs.get(place[0])
        old_text = _decode(base.get(path, b"")) or ""
        old_sections = {s.title: s.text for s in mc.parse_sections(old_text)}
        sections = mc.parse_sections(text)
        selectable = {s.title for s in mc.selectable_sections(spec, sections)} if spec else set()
        sizes[path] = {}
        for section in sections:
            cap = mc.section_cap(section)
            sizes[path][section.title] = [len(section.text), cap]
            if old_sections.get(section.title) == section.text:
                continue
            if len(section.text) > cap:
                errors.append(
                    f"{path}: раздел «{section.title}» весит {len(section.text)} символов "
                    f"при потолке доставки {cap}; освободи {len(section.text) - cap} "
                    "символов переносом абзаца в другой раздел, иначе хвост раздела "
                    "с указателями не доедет")
            if (spec is not None and section.title not in selectable
                    and not mc._is_mandatory(section) and not mc._is_raw(section)):
                warnings.append(
                    f"{path}: раздел «{section.title}» роутер не выберет ни по терминам, "
                    "ни по умолчанию; его содержимое придёт только при чтении файла")
    facts["sections"] = sizes
    return errors, warnings


# ---------------------------------------------------------------------------
# 9. Стенд: кандидат против основы (цели 4, 2)

def stand_errors(old_root: Path | None, new_root: Path, questions: bytes,
                 today: dt.date, facts: dict, warnings: list[str]) -> list[str]:
    import memoryeval
    data = json.loads(questions.decode("utf-8"))
    after = memoryeval.stand(new_root, data, today=today)
    facts["stand"] = memoryeval.summarize(after)
    before = memoryeval.stand(old_root, data, today=today) if old_root else after
    verdict = memoryeval.pairwise(before, after)
    errors = [f"стенд: вопрос {item['id']} {item['why']}"
              for item in verdict["absolute"]]
    for item in verdict["worse_rank"]:
        warnings.append(f"стенд: вопрос {item['id']} ранг ухудшился "
                        f"с {item['was']} до {item['now']}; запись всё ещё приходит")
    for item in verdict["regressions"]:
        errors.append(f"стенд: вопрос {item['id']} {item['why']}; верни находимость "
                      "записи или обнови вопросы стенда осознанным решением")
    for nid in verdict["new_false_positives"]:
        errors.append(f"стенд: отрицательный вопрос {nid} начал отдавать записи; "
                      "перепиши крючок, который его цепляет")
    return errors


# ---------------------------------------------------------------------------
# 9. Глобальный репозиторий это контракт целиком (цели 2, 3)

def contract_errors(candidate: dict[str, bytes]) -> list[str]:
    """Контракт из глобального дерева строится, непуст, помещается в потолок
    доставки и включает каждый файл дерева: свёрнутых записей, архива и
    сводок в глобальном нет. Иначе правило уехало бы на машину заказчика
    и не дошло бы до сессии."""
    import memorycontext as mc
    text = mc.build_index_from_snapshot(candidate)
    if text is None:
        return ["memory/MEMORY.md: у глобального репозитория нет преамбулы индекса"]
    entries = [e for e in mc.parse_index(text) if e.section in mc.INDEX_SECTIONS.values()]
    errors: list[str] = []
    if not entries:
        errors.append("контракт пуст: в глобальном репозитории ни одной видимой записи, "
                      "а он и есть контракт")
    block = mc.contract_block(entries)
    if len(block) > mc.CONTRACT_LIMIT:
        errors.append(f"контракт длиннее потолка доставки ({len(block)} > {mc.CONTRACT_LIMIT} "
                      "символов): роутер обрезал бы правила молча")
    listed = {e.slug for e in entries}
    for path in sorted(candidate):
        name = path[len(MEMORY_PREFIX):] if path.startswith(MEMORY_PREFIX) else None
        if not name or not name.endswith(".md") or name == "MEMORY.md":
            continue
        if name.startswith("archive/") or name.startswith("topics/"):
            errors.append(f"{path}: в глобальном репозитории нет архива и сводок, он весь контракт")
        elif "/" in name:
            continue
        elif name not in listed:
            errors.append(f"{path}: не входит в контракт (свёрнута или без type, title, index); "
                          "глобальный репозиторий это контракт целиком")
    return errors


def client_name_warnings(candidate: dict[str, bytes], topics: Topics,
                         members: tuple[str, ...]) -> list[str]:
    """Имя или псевдоним заказчика в глобальном дереве. Предупреждение, не
    отказ: список слов ловит случайный пример с именем, но изоляции не
    доказывает, а короткие псевдонимы дают ложные срабатывания."""
    words: set[str] = set(members)
    for key, spec in topics.specs.items():
        words.add(key)
        words.add(getattr(spec, "label", "") or "")
        words.update(alias.rstrip("*") for alias in getattr(spec, "aliases", ()))
    words = {w.casefold() for w in words if len(w) >= 4}
    if not words:
        return []
    pattern = re.compile(r"(?<!\w)(" + "|".join(re.escape(w) for w in sorted(words)) + r")(?!\w)",
                         re.IGNORECASE)
    warnings: list[str] = []
    for path, data in sorted(candidate.items()):
        if not path.endswith(".md"):
            continue
        text = _decode(data)
        if text is None:
            continue
        found = sorted({m.group(1).casefold() for m in pattern.finditer(text)})
        if found:
            warnings.append(f"{path}: упоминает заказчика ({', '.join(found)}); "
                            "глобальный репозиторий уходит на машины всех заказчиков")
    return warnings


# ---------------------------------------------------------------------------
# Сквозная проверка

def lay_out(tree: dict[str, bytes], where: Path) -> Path:
    """Выкладка дерева в каталог для функций роутера, которым нужен путь."""
    for path, data in tree.items():
        target = where / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (where / "memory").mkdir(exist_ok=True)
    return where


def check(candidate: dict[str, bytes], base: dict[str, bytes] | None, *,
          root: str, config: Config, today: dt.date | None = None,
          scanner: str | None = None) -> Report:
    """Все проверки над деревом кандидата. scanner - путь к gitleaks,
    None значит найти в системе; отсутствие сканера это отказ."""
    base = dict(base or {})
    today = today or dt.datetime.now(dt.timezone.utc).date()
    topics = load_topics(config.topics)
    facts: dict = {}
    errors: list[str] = []
    warnings: list[str] = []
    errors += secret_errors(base, candidate, scanner if scanner is not None else find_gitleaks())
    errors += shape_errors(candidate)
    errors += header_errors(base, candidate)
    errors += probe_required_errors(candidate, root)
    link_bad, link_warn = link_errors(candidate, topics, root)
    errors += link_bad
    warnings += link_warn
    errors += reach_errors(base, candidate, topics, root)
    errors += foreign_errors(base, candidate, root, topics)
    section_bad, section_warn = section_errors(base, candidate, topics, facts)
    errors += section_bad
    warnings += section_warn
    with tempfile.TemporaryDirectory(prefix="svod-check-") as tmp:
        new_root = lay_out(candidate, Path(tmp) / "new")
        old_root = lay_out(base, Path(tmp) / "old") if base else None
        errors += probe_errors(base, candidate, root=root, topics=topics,
                               laid_out=new_root, today=today, facts=facts)
        if (config.questions is not None and root == "personal"
                and "memory/MEMORY.md" in candidate):
            # Стенд меряет отбор по индексу личного корня, в нём роутер и
            # ищет; глобальный отдаётся контрактом целиком, клиентский
            # доставляется сводкой, его проверяют крючки.
            errors += stand_errors(old_root, new_root, config.questions, today, facts, warnings)
    if root == "global":
        import svodgit
        errors += contract_errors(candidate)
        warnings += client_name_warnings(candidate, topics, svodgit.federation_members(config.topics))
    touched = touched_records(base, candidate)
    facts["touched"] = touched
    return Report(ok=not errors, errors=sorted(set(errors)),
                  warnings=sorted(set(warnings)), facts=facts)
