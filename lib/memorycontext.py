#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
import pathlib
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Iterable

import datetime as dt

import configpaths
import topiclayout

from memoryctl import (
    MemoryctlError,
    atomic_write,
    compute_revision,
    federation_roots,
    parse_frontmatter,
    reader_lock,
    require_repo,
    utc_now,
)


ROUTER_VERSION = "2"
# Предел подобран так, чтобы у КАЖДОЙ темы помещалась обязательная часть плюс
# хотя бы один её раздел целиком. При 7800 у большой темы не влезал ни один: шапка,
# горячий контракт и обязательные разделы съедали 5294, а разделы весят по 3200.
# Тема, не способная отдать ни одного своего раздела, бесполезна.
SOFT_CONTEXT_LIMIT = 9_000
CONTINUATION_CONTEXT_LIMIT = 4_200
HARD_CONTEXT_LIMIT = 10_000

# Пределы на раздел. Держать их именованными обязательно: компактор проверяет
# роллапы против этих же чисел, импортируя их отсюда. Пока пороги были
# литералами внутри _topic_context, компактор мерил обязательные разделы
# чужим порогом 3400 вместо 2500 и показывал зелёный результат, тогда как
# роутер их резал.
SECTION_CAP_HOWTO = 1_200
SECTION_CAP_MANDATORY = 2_500
SECTION_CAP_RELEVANT = 3_400
# Личный режим сессии. Не пробел и не ошибка, а осознанный выбор: в нём можно
# обсуждать хоть все проекты сразу, и роллап заказчика не подмешивается.
def uuid4hex() -> str:
    import uuid

    return uuid.uuid4().hex


PERSONAL_SCOPE = "personal"

# Почему сессия стала личной. Причина обязана быть честной: молча показывать
# «проект не назван», когда он был назван, а запись сорвалась, значит скрывать
# поломку за штатной формулировкой.
PERSONAL_REASONS = {
    "ambiguous-first-message":
        "Сессия личная: в первом сообщении названо несколько проектов, "
        "выбирать за тебя нельзя. Проектная память не подмешивается.",
    "io-error":
        "⚠️ Сессия личная ВЫНУЖДЕННО: закрепление не удалось записать "
        "(ошибка файловой системы). Проектная память не подмешивается, "
        "проверь состояние каталога ~/.local/state/agent-memory.",
    "unreadable-pin":
        "⚠️ Сессия личная ВЫНУЖДЕННО: запись закрепления повреждена. "
        "Нужен /clear и новая сессия.",
    "resumed-without-pin":
        "Сессия личная: возобновлена без действующего закрепления, поэтому "
        "проект здесь уже не задать. Нужен проект - начни новую сессию.",
    "no-session-id":
        "Сессия личная: нет идентификатора сессии, закреплять негде.",
}
SESSION_EVENT = "SessionStart"
PROMPT_EVENT = "UserPromptSubmit"


@dataclass(frozen=True)
class TopicSpec:
    scope: str
    label: str
    filename: str
    aliases: tuple[str, ...]
    cwd_names: tuple[str, ...]
    cwd_prefixes: tuple[str, ...]
    default_sections: tuple[str, ...]
    section_terms: tuple[tuple[str, tuple[str, ...]], ...]
    # Корень-владелец сводки: "clients/<имя>" для темы заказчика, None для
    # темы, чья сводка живёт в общем репозитории:
    # источник истины клиентской области - клиентский git-репозиторий.
    owner: str | None = None


@dataclass(frozen=True)
class MarkdownSection:
    title: str
    text: str
    index: int


@dataclass(frozen=True)
class RouteDecision:
    scope: str | None
    source: str


@dataclass(frozen=True)
class IndexEntry:
    section: str
    label: str
    slug: str
    summary: str
    index: int


# Потолок доставки контракта. Глобальный репозиторий это контракт целиком,
# и проверка глобального дерева отказывает выше потолка, поэтому обрезание в
# роутере только страховка.
CONTRACT_LIMIT = 2_600

# Потолок выдачи совпавших записей за один запрос: столько мест в блоке
# памяти отводится записям индекса. Стенд читает эту константу и считает
# выдачу шире потолка неисправностью отбора.
DELIVERY_LIMIT = 2

INDEX_SECTIONS = {
    "inbox": "Inbox",
    "user": "User",
    "feedback": "Feedback",
    "project": "Project",
    "reference": "Reference",
}

USER_CATALOG_TRIGGERS = (
    "что ты обо мне помнишь",
    "что обо мне помнишь",
    "что ты знаешь обо мне",
    "расскажи что ты обо мне знаешь",
    "what do you remember about me",
    "what do you know about me",
)

TOKEN_RE = re.compile(r"[0-9a-zа-яё]+", re.IGNORECASE)
# Приглашение оболочки во вставленном выводе: `user@host acme %`, `devops@host:~$`.
# Съедается только сама префиксная часть до %, $ или #, команда после неё остаётся.
SHELL_PROMPT_RE = re.compile(
    r"^[ \t]*[\w.\-]+@[\w.\-]+[^\n%$#]{0,80}?[%$#](?=[ \t]|$)",
    re.MULTILINE,
)
STOP_TOKENS = {
    "about",
    "актуальный",
    "весь",
    "где",
    "данные",
    "для",
    "как",
    "какой",
    "когда",
    "мне",
    "можно",
    "надо",
    "нужно",
    "помоги",
    "почему",
    "проверь",
    "проект",
    "расскажи",
    "сделай",
    "сейчас",
    "список",
    "статус",
    "задача",
    "задачи",
    "оперативный",
    "текущий",
    "только",
    "файл",
    "хочу",
    "what",
    "where",
    "with",
    "you",
    "your",
}


def _load_topics() -> dict[str, TopicSpec]:
    """Темы читаются из общего конфига, а не описываются литералом здесь.

    Один и тот же набор тем нужен и роутеру, и компактору. Пока роутер держал
    свою копию питоновским литералом, а компактор свою в JSON, копии
    расходились: за один день так разъехались пороги доставки и список
    областей памяти. Теперь источник один.
    """
    path = configpaths.config_path("topics.json")
    # Байты конфига читаются РОВНО ОДИН РАЗ на процесс и публикуются как
    # TOPICS_RAW: memoryrecall разбирает свои структуры из этих же байтов,
    # поэтому один вызов читателя не может собрать результат
    # из двух поколений политики (Q7, Д25-З).
    global TOPICS_RAW
    try:
        TOPICS_RAW = path.read_bytes()
    except OSError as exc:
        raise MemoryctlError(f"не читается конфиг тем {path}: {exc}") from exc
    return parse_topics(TOPICS_RAW, path)


def parse_topics(raw_bytes: bytes, path) -> dict[str, TopicSpec]:
    """Темы из байтов конфига: проверки кандидата (memoryverify) получают
    версию конфигурации входом и не читают живой файл."""
    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MemoryctlError(f"не читается конфиг тем {path}: {exc}") from exc
    try:
        placement = topiclayout.placement_from_config(raw, path)
    except ValueError as exc:
        raise MemoryctlError(str(exc)) from exc

    # Структурно валидный, но неверный JSON опаснее синтаксически битого: он
    # не шумит. Строка вместо списка алиасов превратилась бы в кортеж
    # символов, пустой алиас совпал бы с любым текстом, а неполный topicOrder
    # МОЛЧА выкинул бы тему из маршрутизации. Конфиг читается при импорте, то
    # есть до fail-soft роутера, поэтому цена ошибки это сессия без
    # закрепления.
    if not isinstance(raw, dict):
        raise MemoryctlError(f"{path}: корень конфига не объект")
    topics = raw.get("topics")
    if not isinstance(topics, dict) or not topics:
        raise MemoryctlError(f"{path}: раздел topics пуст или не объект")
    if any(not isinstance(key, str) or not key for key in topics):
        raise MemoryctlError(f"{path}: имена тем должны быть непустыми строками")

    order = raw.get("topicOrder")
    if order is None:
        order = sorted(topics)
    if not isinstance(order, list) or any(not isinstance(k, str) for k in order):
        raise MemoryctlError(f"{path}: topicOrder должен быть списком строк")
    if len(order) != len(set(order)):
        raise MemoryctlError(f"{path}: в topicOrder есть повторы")
    if set(order) != set(topics):
        raise MemoryctlError(
            f"{path}: topicOrder не совпадает с составом тем "
            f"({sorted(set(order) ^ set(topics))})"
        )

    def strings(key, field, value, *, allow_empty_list=True):
        if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
            raise MemoryctlError(f"{path}: у темы {key} поле {field} должно быть списком строк")
        if any(not v.strip() for v in value):
            # Пустая строка совпадает с чем угодно: пустой алиас закрепил бы
            # любую сессию, пустой cwdPrefix совпал бы с каждым каталогом, а
            # пустой defaultSection сделал бы дефолтными все разделы.
            raise MemoryctlError(f"{path}: у темы {key} в {field} есть пустая строка")
        if not allow_empty_list and not value:
            raise MemoryctlError(f"{path}: у темы {key} поле {field} не может быть пустым")
        return value

    seen_aliases: dict[str, str] = {}
    for key, entry in topics.items():
        if not isinstance(entry, dict):
            raise MemoryctlError(f"{path}: тема {key} не объект")
        for field in ("label", "rollup"):
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                raise MemoryctlError(f"{path}: у темы {key} нет непустого {field}")
        for field in ("aliases", "cwdNames", "cwdPrefixes", "defaultSections"):
            strings(key, field, entry.get(field, []))
        terms = entry.get("sectionTerms", {})
        if not isinstance(terms, dict):
            raise MemoryctlError(f"{path}: у темы {key} sectionTerms должен быть объектом")
        for title, values in terms.items():
            if not isinstance(title, str) or not title.strip():
                raise MemoryctlError(f"{path}: у темы {key} пустой заголовок в sectionTerms")
            strings(key, f"sectionTerms[{title}]", values, allow_empty_list=False)
        for alias in entry.get("aliases", []):
            owner = seen_aliases.setdefault(alias.casefold(), key)
            if owner != key:
                raise MemoryctlError(f"{path}: алиас {alias!r} принадлежит и {owner}, и {key}")

    result: dict[str, TopicSpec] = {}
    for key in order:
        entry = topics[key]
        result[key] = TopicSpec(
            scope=key,
            label=entry["label"],
            filename=entry["rollup"],
            aliases=tuple(entry.get("aliases", ())),
            cwd_names=tuple(entry.get("cwdNames", ())),
            cwd_prefixes=tuple(entry.get("cwdPrefixes", ())),
            default_sections=tuple(entry.get("defaultSections", ())),
            section_terms=tuple(
                (title, tuple(terms))
                for title, terms in (entry.get("sectionTerms") or {}).items()
            ),
            owner=placement[entry["rollup"]][1],
        )
    return result


TOPICS_RAW: bytes = b""
TOPICS: dict[str, TopicSpec] = _load_topics()
_READER_FEDERATION: dict = {}


def reader_federation(root: Path):
    """Контекст федерации читателя: одно построение на процесс и корень.

    Строится из БАЙТОВ конфига этого процесса (Q7) без git-подпроцессов:
    читателю нужны выбранные деревья и физические границы, а не привязки
    Git. Кеш процессный, между вызовами хука процесс не живёт.
    """
    import memoryctl
    ключ = str(pathlib.Path(root).resolve())
    контекст = _READER_FEDERATION.get(ключ)
    if контекст is None:
        контекст = memoryctl.federation_context(root, topics_raw=TOPICS_RAW)
        _READER_FEDERATION[ключ] = контекст
    return контекст
TOPIC_ORDER = tuple(TOPICS)


def rollup_relative_source(spec: TopicSpec) -> str:
    """Относительный путь сводки темы от корня федерации.

    Правило пути делегировано общему модулю раскладки. Запасного пути читатель
    не пробует: чтение старой копии при недоступном владельце запрещено (N10).
    """
    return topiclayout.rollup_relative_source(spec.filename, spec.owner)



def default_root() -> Path:
    configured = os.environ.get("MEMORY_REPO")
    if configured:
        return Path(configured).expanduser().resolve()
    # Корень ДАННЫХ не выводится из расположения кода: после разделения
    # репозиториев это указывало бы на репозиторий кода. Значение по
    # умолчанию документировано, переменная его перекрывает.
    return (Path.home() / ".agent-memory").resolve()


def default_state_dir() -> Path:
    configured = os.environ.get("MEMORY_CONTEXT_STATE_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    memoryctl_state = os.environ.get("MEMORYCTL_STATE_DIR")
    if memoryctl_state:
        return (Path(memoryctl_state).expanduser().resolve() / "claude")
    xdg = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return (xdg / "agent-memory" / "claude").resolve()


def _section_kind(heading: str) -> str | None:
    normalized = heading.casefold().strip()
    for prefix, section in INDEX_SECTIONS.items():
        if normalized.startswith(prefix):
            return section
    return None


def _clean_inline(text: str, maximum: int = 300) -> str:
    cleaned = text.replace("—", "-").replace("–", "-")
    cleaned = re.sub(r"[`*]", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" -")
    if len(cleaned) <= maximum:
        return cleaned
    return cleaned[: maximum - 1].rstrip() + "…"


def parse_index(text: str) -> tuple[IndexEntry, ...]:
    current_section: str | None = None
    entries = []
    for line in text.splitlines():
        heading = re.match(r"^##\s+(.+?)\s*$", line)
        if heading:
            current_section = _section_kind(heading.group(1))
            continue
        if current_section is None:
            continue
        item = INDEX_ITEM_RE.match(line)
        if not item:
            continue
        slug = item.group(2).strip()
        entries.append(
            IndexEntry(
                section=current_section,
                label=_clean_inline(item.group(1)),
                slug=slug,
                summary=_clean_inline(item.group(3)),
                index=len(entries),
            )
        )
    return tuple(entries)


# ---------------------------------------------------------------------------
# Генерируемый индекс (Свод-0, шаг 1). Строки разделов User, Feedback,
# Project, Reference не хранятся: они выводятся из шапок записей при каждом
# чтении (219 шапок читаются за миллисекунды, кэш не нужен). В git лежит
# только преамбула MEMORY.md: Inbox, маршрутизация, сводки тем и сами
# заголовки разделов. Одна и та же функция кормит роутер, recall, стенд,
# компактор и ворота писателя, поэтому «строка индекса и запись расходятся»
# невозможно по построению.

INDEX_TYPES = tuple(kind for kind in INDEX_SECTIONS if kind != "inbox")
INDEX_ITEM_RE = re.compile(
    r"^\s*-\s+\[([^\]]+)\]\(([^)]+\.md)(?:#[^)]*)?\)\s*(?:[—–-]\s*)?(.*)$")


def record_index_line(name: str, fields: dict[str, str]) -> tuple[str, str] | None:
    """Раздел и строка индекса записи по её шапке, либо None.

    Строку даёт только запись с `type` из словаря разделов, непустыми
    `title` и `index` и без `listed: false`. Остальное строкой не является:
    свёрнутая в сводку запись, запись без крючка, служебный файл."""
    if fields.get("listed") == "false":
        return None
    тип = fields.get("type", "")
    заголовок = fields.get("title", "").strip()
    крючок = fields.get("index", "").strip()
    if тип not in INDEX_TYPES or not заголовок or not крючок:
        return None
    return INDEX_SECTIONS[тип], f"- [{заголовок}]({name}) - {крючок}"


def compose_index(preamble: str, records: Iterable[tuple[str, dict[str, str]]]) -> str:
    """Текст индекса: преамбула плюс строки записей в конце своих разделов.

    Разделы и их порядок задаёт сама преамбула (заголовки распознаются как
    в parse_index); строки встают после последней непустой строки своего
    раздела, внутри раздела по имени файла. Раздел, которого в преамбуле
    нет, дописывается в конец под заголовком `## <Раздел>`. Корпус без
    полей шапки даёт ровно текст преамбулы, байт в байт."""
    по_разделам: dict[str, list[str]] = {}
    for name, fields in sorted(records, key=lambda пара: пара[0]):
        строка = record_index_line(name, fields)
        if строка is not None:
            по_разделам.setdefault(строка[0], []).append(строка[1])
    if not по_разделам:
        return preamble
    итог: list[str] = []
    пустые: list[str] = []
    текущий: str | None = None

    def закрыть_раздел() -> None:
        if текущий is not None and текущий in по_разделам:
            итог.extend(по_разделам.pop(текущий))
        итог.extend(пустые)
        пустые.clear()

    for строка in preamble.splitlines():
        heading = re.match(r"^##\s+(.+?)\s*$", строка)
        if heading:
            закрыть_раздел()
            текущий = _section_kind(heading.group(1))
            итог.append(строка)
            continue
        if текущий is not None and not строка.strip():
            пустые.append(строка)
            continue
        итог.extend(пустые)
        пустые.clear()
        итог.append(строка)
    закрыть_раздел()
    for раздел in INDEX_SECTIONS.values():
        if раздел in по_разделам:
            if итог and итог[-1].strip():
                итог.append("")
            итог.append(f"## {раздел}")
            итог.extend(по_разделам.pop(раздел))
    return "\n".join(итог) + ("\n" if preamble.endswith("\n") else "")


def _index_records(items: Iterable[tuple[str, str]]) -> list[tuple[str, dict[str, str]]]:
    return [(имя, parse_frontmatter(текст)[0]) for имя, текст in items]


def build_index(root: Path) -> str:
    """Индекс области: преамбула memory/MEMORY.md плюс строки из шапок
    записей memory/*.md. Отсутствие преамбулы - FileNotFoundError, как
    прежде отсутствие файла индекса."""
    memory_root = root / "memory"
    преамбула = (memory_root / "MEMORY.md").read_text(encoding="utf-8")
    тексты = []
    for файл in memory_root.glob("*.md"):
        if файл.name == "MEMORY.md":
            continue
        try:
            тексты.append((файл.name, файл.read_text(encoding="utf-8")))
        except (OSError, UnicodeError):
            continue
    return compose_index(преамбула, _index_records(тексты))


def build_index_from_snapshot(snapshot: dict[str, bytes], prefix: str = "memory/") -> str | None:
    """То же от снимка дерева {путь: байты}; None, если преамбулы в нём нет."""
    преамбула = snapshot.get(prefix + "MEMORY.md")
    if преамбула is None:
        return None
    тексты = []
    for путь, байты in snapshot.items():
        if not путь.startswith(prefix):
            continue
        имя = путь[len(prefix):]
        if "/" in имя or not имя.endswith(".md") or имя == "MEMORY.md":
            continue
        try:
            тексты.append((имя, байты.decode("utf-8")))
        except UnicodeDecodeError:
            continue
    return compose_index(преамбула.decode("utf-8"), _index_records(тексты))


def contract_block(entries: tuple[IndexEntry, ...]) -> str:
    """Контракт: все видимые строки индекса глобального репозитория, без
    обрезания. Список правил в коде не живёт: добавить или убрать правило
    значит перенести файл."""
    lines = [
        "[Глобальный рабочий контракт из MEMORY.md]",
        "Применяй эти правила в любом проекте и в непроектных запросах:",
    ]
    for entry in entries:
        if entry.section not in INDEX_SECTIONS.values():
            continue
        detail = f": {entry.summary}" if entry.summary else ""
        lines.append(f"- {entry.label}{detail} [{entry.slug}]")
    return "\n".join(lines)


def _hot_contract(entries: tuple[IndexEntry, ...]) -> str:
    return _clip_block(contract_block(entries), CONTRACT_LIMIT, "memory/MEMORY.md")


def contract_key(hot_contract: str) -> str:
    """Признак «контракт уже передан» ключуется байтами самого контракта:
    правка личного или клиентского репозитория повторной доставки не требует."""
    return hashlib.sha256(hot_contract.encode("utf-8")).hexdigest()[:16]


def index_roots(root: Path) -> tuple[Path, Path | None]:
    """Корни индекса этой машины: глобальный (контракт) обязателен, личный
    (инбокс, записи, поиск) по наличию. root это каталог данных, в нём по
    клону на область."""
    context = reader_federation(root)
    if "global" not in context.available:
        raise MemoryctlError(
            f"{root}: нет глобального репозитория global/memory; без него контракт не отдать")
    personal = (context.identities["personal"].worktree_root
                if "personal" in context.available else None)
    return context.identities["global"].worktree_root, personal


def _revision_note(global_root: Path, personal_root: Path | None) -> str:
    parts = [f"global {compute_revision(global_root)[:12]}"]
    if personal_root is not None:
        parts.append(f"personal {compute_revision(personal_root)[:12]}")
    return ", ".join(parts)


def _normalized_text(text: str) -> str:
    return " ".join(TOKEN_RE.findall(text.casefold().replace("ё", "е")))


def _tokens(text: str) -> tuple[str, ...]:
    result = []
    for token in TOKEN_RE.findall(text.casefold().replace("ё", "е")):
        if token in STOP_TOKENS:
            continue
        if len(token) < 3 and token not in {"1с", "ad", "ci", "ip"}:
            continue
        result.append(token)
    return tuple(dict.fromkeys(result))


def _token_match(left: str, right: str) -> bool:
    if left == right:
        return True
    if len(left) >= 5 and len(right) >= 5:
        return left[:5] == right[:5]
    return False


def _entry_score(prompt: str, entry: IndexEntry) -> int:
    prompt_tokens = _tokens(prompt)
    if not prompt_tokens:
        return 0
    label_tokens = _tokens(entry.label)
    summary_tokens = _tokens(entry.summary)
    label_hits = sum(
        1
        for prompt_token in prompt_tokens
        if any(_token_match(prompt_token, entry_token) for entry_token in label_tokens)
    )
    summary_hits = sum(
        1
        for prompt_token in prompt_tokens
        if any(_token_match(prompt_token, entry_token) for entry_token in summary_tokens)
    )
    score = (label_hits * 4) + summary_hits
    normalized_label = _normalized_text(entry.label)
    normalized_prompt = _normalized_text(prompt)
    if len(normalized_label) >= 5 and normalized_label in normalized_prompt:
        score += 6
    if label_hits >= 2:
        score += 2
    return score


def rank_index_entries(prompt: str, entries: tuple[IndexEntry, ...]) -> tuple[tuple[IndexEntry, int], ...]:
    ranked = [
        (entry, _entry_score(prompt, entry))
        for entry in entries
        if entry.section in INDEX_SECTIONS.values()
    ]
    ranked = [item for item in ranked if item[1] >= 4]
    ranked.sort(key=lambda item: (-item[1], item[0].index))
    if not ranked:
        return ()
    selected = [ranked[0]]
    if len(ranked) > 1:
        second = ranked[1]
        if second[1] >= 6 and (second[1] * 2) >= ranked[0][1]:
            selected.append(second)
    return tuple(selected)


def today_utc() -> dt.date:
    """Внедряемые часы (A8): тесты подменяют этот атрибут модуля."""
    return dt.datetime.now(dt.timezone.utc).date()


def _entry_expired(root: Path, entry: IndexEntry, today: dt.date) -> bool:
    """Истёк ли valid_until записи. Семантика границы: запись действительна
    ПО дату valid_until включительно (UTC), просрочена со следующего дня.
    Нечитаемый файл или битая дата не скрывают запись: невидимость обязана
    быть объяснимой (R10), а молча спрятать факт хуже, чем показать старый."""
    target = _safe_memory_path(root, entry.slug)
    if target is None or not target.is_file():
        return False
    try:
        fields, _ = parse_frontmatter(_read_limited(target, 4_096))
    except OSError:
        return False
    значение = fields.get("valid_until")
    if not значение:
        return False
    try:
        return today > dt.date.fromisoformat(значение)
    except ValueError:
        return False


def resolve_final_successor(root: Path, slug: str) -> str | None:
    """R6: конечный действующий преемник слага по цепочке supersedes.

    Поле supersedes живёт у ПРЕЕМНИКА и смотрит назад, поэтому разрешение
    строит обратную карту по frontmatter действующих и архивных записей и
    идёт вперёд до действующей. Действующий слаг разрешается сам в себя.
    Слаг без преемника даёт None: разорванную цепочку писатель не пропускает,
    но читатель обязан отвечать и на неполном корпусе, а не падать.
    """
    memory_root = root / "memory"
    активные: set[str] = set()
    назад: dict[str, list[str]] = {}
    for файл in list(memory_root.glob("*.md")) + list((memory_root / "archive").glob("*.md")):
        if файл.name == "MEMORY.md":
            continue
        собственный = файл.stem
        if файл.parent.name != "archive":
            активные.add(собственный)
        try:
            поля, _ = parse_frontmatter(_read_limited(файл, 4_096))
        except OSError:
            continue
        цель = поля.get("supersedes")
        if цель:
            назад.setdefault(цель, []).append(собственный)
    текущий, увидено = slug, {slug}
    while текущий not in активные:
        # Развилка активных преемников запрещена писателем, но у слага могут
        # быть архивный И действующий преемники (цепочка сквозь архив).
        # Детерминированный выбор: сначала действующий, затем по алфавиту.
        претенденты = sorted(назад.get(текущий, ()),
                             key=lambda имя: (имя not in активные, имя))
        преемник = next((имя for имя in претенденты if имя not in увидено), None)
        if преемник is None:
            return None
        увидено.add(преемник)
        текущий = преемник
    return текущий


def _entry_link_fields(root: Path, slug_md: str) -> dict[str, tuple[str, ...]]:
    """requires и contradicts записи; slug приходит с расширением .md."""
    target = _safe_memory_path(root, slug_md)
    if target is None or not target.is_file():
        return {}
    try:
        поля, _ = parse_frontmatter(_read_limited(target, 4_096))
    except OSError:
        return {}
    результат: dict[str, tuple[str, ...]] = {}
    for имя in ("requires", "contradicts"):
        сырое = поля.get(имя)
        if сырое:
            цели = tuple(x.strip() for x in сырое.split(",") if x.strip())
            if цели:
                результат[имя] = цели
    return результат


def bundle_members(root: Path, seed_slug_md: str, delivered: set[str]) -> tuple[tuple[str, str], ...]:
    """Замыкание комплекта затравки: обход requires и contradicts (R4, R5).

    Цели разрешаются по цепочке supersedes к действующему преемнику (A6).
    Обход в ширину со стабильным порядком (вид связи, затем порядок в поле),
    повторы устранены; запись, уже доставленная другим комплектом или как
    затравка, второй раз не едет и остаётся за первым (R9). Возвращаются пары
    (slug.md, вид связи).
    """
    члены: list[tuple[str, str]] = []
    очередь = [seed_slug_md]
    while очередь:
        текущий = очередь.pop(0)
        связи = _entry_link_fields(root, текущий)
        for вид in ("requires", "contradicts"):
            for цель in связи.get(вид, ()):
                разрешённая = resolve_final_successor(root, цель) or цель
                имя = f"{разрешённая}.md"
                if имя == seed_slug_md or имя in delivered:
                    continue
                delivered.add(имя)
                члены.append((имя, вид))
                очередь.append(имя)
    return tuple(члены)


def _member_block(root: Path, slug_md: str, seed_slug_md: str, вид: str) -> str | None:
    """Блок члена комплекта: ЦЕЛИКОМ, без обрезания (R9)."""
    target = _safe_memory_path(root, slug_md)
    if target is None or not target.is_file():
        return None
    body = _without_frontmatter(_read_limited(target)).strip()
    связь = "противоречие" if вид == "contradicts" else "требуется"
    heading = (f"[Член комплекта {seed_slug_md}: {связь}]\n"
               f"Источник: memory/{slug_md}")
    return f"{heading}\n\n{body}"


def _append_bundle(parts: list[str], root: Path, seed_slug_md: str,
                   члены: tuple[tuple[str, str], ...]) -> None:
    """Доставка комплекта: все члены целиком либо метка и ни одного байта.

    Бюджет считается по той же арифметике, что _append_with_budget. Метки
    ошибок доставки живут вне бюджета содержимого: формат фиксированный и
    короткий, поэтому метка выводится даже при нулевом остатке (R9). Затравка
    сама по себе продолжает жить по прежним правилам обрезания: комплектная
    гарантия «целиком или ничего» относится к замыканию связей, иначе блок 2
    менял бы выдачу всего корпуса без единой связи (N3).
    """
    блоки: list[str] = []
    недоступные: list[str] = []
    for имя, вид in члены:
        блок = _member_block(root, имя, seed_slug_md, вид)
        if блок is None:
            недоступные.append(имя)
        else:
            блоки.append(блок)
    for имя in недоступные:
        parts.append(f"[Член комплекта {seed_slug_md} недоступен: memory/{имя}]")
    if not блоки:
        return
    used = sum(len(part) for part in parts) + (2 * len(parts))
    нужно = sum(len(блок) + 2 for блок in блоки)
    доступно = max(0, SOFT_CONTEXT_LIMIT - used - 180)
    if нужно > доступно:
        parts.append(
            f"[Комплект {seed_slug_md} не доставлен: нужно {нужно} символов, "
            f"доступно {доступно}; частичная выдача комплекта запрещена]")
        return
    parts.extend(блоки)


def select_index_entries(
    root: Path,
    prompt: str,
    entries: tuple[IndexEntry, ...],
    *,
    today: dt.date | None = None,
) -> tuple[tuple[IndexEntry, int], ...]:
    """Отбор записей для доставки: ранжирование плюс фильтр valid_until.

    R7 замороженных критериев блока 2: просроченность применяется по времени
    запроса ДО ограничения числа записей, поэтому просроченная запись с
    максимальным баллом не вытесняет действующую с меньшим. Реализация
    эквивалентна ранжированию по корпусу без просроченных записей: кандидаты
    обходятся в порядке рангов, просроченные выпадают, а правило второй записи
    применяется к первым двум ЖИВЫМ. frontmatter читается только у верхних
    кандидатов, не у всего корпуса. review_after здесь не участвует (R8): он
    не скрывает запись и не меняет её балл.
    """
    сегодня = today if today is not None else today_utc()
    кандидаты = [
        (entry, _entry_score(prompt, entry))
        for entry in entries
        if entry.section in INDEX_SECTIONS.values()
    ]
    кандидаты = [пара for пара in кандидаты if пара[1] >= 4]
    кандидаты.sort(key=lambda пара: (-пара[1], пара[0].index))
    живые: list[tuple[IndexEntry, int]] = []
    for entry, score in кандидаты:
        if _entry_expired(root, entry, сегодня):
            continue
        живые.append((entry, score))
        if len(живые) == DELIVERY_LIMIT:
            break
    if not живые:
        return ()
    selected = [живые[0]]
    if len(живые) > 1 and живые[1][1] >= 6 and (живые[1][1] * 2) >= живые[0][1]:
        selected.append(живые[1])
    return tuple(selected)


def _has_trigger(prompt: str, triggers: Iterable[str]) -> bool:
    normalized = _normalized_text(prompt)
    return any(_normalized_text(trigger) in normalized for trigger in triggers)


def _safe_memory_path(root: Path, slug: str) -> Path | None:
    pure = PurePosixPath(slug)
    if pure.is_absolute() or ".." in pure.parts or pure.suffix != ".md":
        return None
    memory_root = (root / "memory").resolve()
    target = (memory_root / Path(*pure.parts)).resolve()
    try:
        target.relative_to(memory_root)
    except ValueError:
        return None
    return target


def _read_limited(path: Path, maximum: int = 65_536) -> str:
    with path.open("r", encoding="utf-8") as handle:
        return handle.read(maximum)


def _without_frontmatter(text: str) -> str:
    if not text.startswith("---\n"):
        return text
    end = text.find("\n---\n", 4)
    return text[end + 5 :] if end >= 0 else text


def _entry_block(root: Path, entry: IndexEntry, maximum: int = 2_400) -> str | None:
    target = _safe_memory_path(root, entry.slug)
    if target is None or not target.is_file():
        return None
    body = _without_frontmatter(_read_limited(target)).strip()
    heading = f"[Совпавшая запись индекса: {entry.label}]\nИсточник: memory/{entry.slug}"
    if entry.summary:
        heading += f"\nРезюме индекса: {entry.summary}"
    return _clip_block(f"{heading}\n\n{body}", maximum, f"memory/{entry.slug}")


def _personal_inbox_block(root: Path, maximum: int = 3_600) -> str | None:
    target = root / "memory" / "personal_inbox.md"
    if not target.is_file():
        return None
    text = _read_limited(target)
    lines = [
        "[Персональный инбокс]",
        "Источник: memory/personal_inbox.md. Это датированный оперативный слой, актуальность проверяй по датам.",
    ]
    current_heading: str | None = None
    emitted_heading: str | None = None
    entries_added = 0
    for line in text.splitlines():
        heading = re.match(r"^##\s+(.+?)\s*$", line)
        if heading:
            current_heading = _clean_inline(heading.group(1), 120)
            if current_heading.casefold().startswith("сделано"):
                break
            continue
        if current_heading and line.startswith("- "):
            if emitted_heading != current_heading:
                lines.append(f"## {current_heading}")
                emitted_heading = current_heading
            lines.append(_clean_inline(line, 360))
            entries_added += 1
            if entries_added >= 16:
                break
    if entries_added == 0:
        return _clip_block("\n".join(lines) + "\n\n" + text, maximum, "memory/personal_inbox.md")
    return _clip_block("\n".join(lines), maximum, "memory/personal_inbox.md")


def _user_catalog_block(entries: tuple[IndexEntry, ...], maximum: int = 3_200) -> str:
    lines = [
        "[Компактный индекс сведений о владельце]",
        "Это только указатели из MEMORY.md. Не расширяй их догадками:",
    ]
    for entry in entries:
        if entry.section != "User":
            continue
        detail = f": {entry.summary}" if entry.summary else ""
        lines.append(f"- {entry.label}{detail} [{entry.slug}]")
    return _clip_block("\n".join(lines), maximum, "memory/MEMORY.md")


def _phrase_pattern(phrase: str, *, prefix: bool = False) -> re.Pattern[str]:
    escaped = re.escape(phrase.casefold())
    left = r"(?<!\w)" if phrase and phrase[0].isalnum() else ""
    if prefix:
        right = r"\w*"
    else:
        right = r"(?!\w)" if phrase and phrase[-1].isalnum() else ""
    return re.compile(left + escaped + right, re.IGNORECASE)


def _contains(text: str, term: str) -> bool:
    prefix = term.endswith("*")
    value = term[:-1] if prefix else term
    return bool(_phrase_pattern(value, prefix=prefix).search(text.casefold()))


def _matching_terms(text: str, terms: Iterable[str]) -> tuple[str, ...]:
    return tuple(term for term in terms if _contains(text, term))


def _strip_shell_prompts(text: str) -> str:
    """Убирает приглашения оболочки из вставленного вывода.

    Строка вида `user@host acme % docker ps` содержит имя каталога, а не намерение
    пользователя: без этого имя каталога в приглашении определяло бы тему.
    Сама команда после приглашения остаётся, она может нести полезные маркеры.
    """
    return SHELL_PROMPT_RE.sub(" ", text)


def _explicit_scopes(prompt: str) -> tuple[str, ...]:
    text = _strip_shell_prompts(prompt)
    matches = []
    for scope in TOPIC_ORDER:
        if _matching_terms(text, TOPICS[scope].aliases):
            matches.append(scope)
    return tuple(matches)


def _cwd_scopes(cwd: str) -> tuple[str, ...]:
    if not cwd:
        return ()
    components = tuple(part.casefold() for part in re.split(r"[\\/]+", cwd) if part)
    matches = []
    for scope in TOPIC_ORDER:
        spec = TOPICS[scope]
        found = any(
            component in spec.cwd_names
            or any(component.startswith(prefix) for prefix in spec.cwd_prefixes)
            for component in components
        )
        if found:
            matches.append(scope)
    return tuple(matches)


def _session_key(session_id: str) -> str | None:
    if not session_id:
        return None
    # surrogatepass, а не replace: replace превращает любой битый суррогат в
    # один и тот же символ, и разные идентификаторы дают ОДИН ключ, то есть
    # чужое закрепление и чужую дедупликацию.
    return hashlib.sha256(session_id.encode("utf-8", errors="surrogatepass")).hexdigest()


def _session_path(state_dir: Path, session_id: str) -> Path | None:
    key = _session_key(session_id)
    if key is None:
        return None
    return state_dir / "sessions" / f"{key}.json"


def _session_record(state_dir: Path, session_id: str) -> dict:
    path = _session_path(state_dir, session_id)
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _full_context_required(
    state_dir: Path,
    session_id: str,
    scope: str,
    revision: str,
) -> bool:
    if not session_id:
        return True
    record = _session_record(state_dir, session_id)
    return not (
        record.get("full_context_scope") == scope
        and record.get("full_context_revision") == revision
    )


def _hot_context_required(state_dir: Path, session_id: str, revision: str) -> bool:
    if not session_id:
        return True
    return _session_record(state_dir, session_id).get("hot_context_revision") != revision


def _write_json(path: Path, data: dict) -> None:
    atomic_write(
        path,
        (json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        0o600,
    )


def _write_route_metadata(
    state_dir: Path,
    *,
    event: str,
    session_id: str,
    decision: RouteDecision,
    revision: str | None,
    sections: Iterable[str] = (),
    delivery: str | None = None,
    delivered_full: bool = False,
    delivered_hot: bool = False,
    reset_full_context: bool = False,
    hot_revision: str | None = None,
) -> None:
    session_key = _session_key(session_id)
    metadata = {
        "version": 2,
        "event": event,
        "route": decision.source,
        "scope": decision.scope,
        "sections": list(sections),
        "delivery": delivery,
        "revision": revision[:12] if revision else None,
        "session_key": session_key[:16] if session_key else None,
        "updated_at": utc_now(),
    }
    _write_json(state_dir / "last-route.json", metadata)
    # В записи сессии остаётся ТОЛЬКО дедупликация доставки. Ни одно поле
    # отсюда больше не выбирает проект: липкий и кешированный scope позволяли
    # памяти одного заказчика остаться в сессии про другого, потому что
    # переживали смену рабочего каталога.
    update_session = delivered_full or delivered_hot or reset_full_context
    if update_session and session_id:
        path = _session_path(state_dir, session_id)
        if path is not None:
            previous = _session_record(state_dir, session_id)
            full_context_scope = previous.get("full_context_scope")
            full_context_revision = previous.get("full_context_revision")
            hot_context_revision = previous.get("hot_context_revision")
            if reset_full_context:
                full_context_scope = None
                full_context_revision = None
            if delivered_full:
                full_context_scope = decision.scope
                full_context_revision = revision
            if delivered_hot:
                hot_context_revision = hot_revision if hot_revision is not None else revision
            _write_json(
                path,
                {
                    "version": 2,
                    "full_context_scope": full_context_scope,
                    "full_context_revision": full_context_revision,
                    "hot_context_revision": hot_context_revision,
                    "last_delivery": delivery,
                    "updated_at": metadata["updated_at"],
                },
            )


def _environment_scope(scope_hint: str) -> RouteDecision | None:
    """Scope от вызывающего: Telegram-бот, планировщик.

    Только точный алиас. Разбор подсказки по маркерам убран: маркеры это
    рукописный список слов, который молча протухает, а закрепление сессии
    слишком дорого ошибается, чтобы опираться на догадку. Не распознали
    подсказку - сессия станет личной, это безопасный исход.
    """
    if not scope_hint:
        return None
    explicit = _explicit_scopes(scope_hint)
    if len(explicit) == 1:
        return RouteDecision(explicit[0], "env")
    return None


def _pin_mismatch(pinned: str | None, cwd: str) -> str | None:
    """Каталог проекта не совпадает с закреплённым проектом.

    Каталог больше НЕ выбирает проект: выбор делает только первое сообщение.
    Но расхождение стоит показать, потому что закрепиться на чужом проекте
    легко опечаткой, а вся сессия после этого поедет на чужой памяти.
    """
    if not pinned or pinned == PERSONAL_SCOPE:
        return None
    matches = _cwd_scopes(cwd)
    if len(matches) == 1 and matches[0] != pinned:
        return TOPICS[matches[0]].label
    return None



def _pin_path(state_dir: Path, session_id: str):
    key = _session_key(session_id)
    return (state_dir / "pins" / f"{key}.json") if key else None


def _read_pin_record(state_dir: Path, session_id: str) -> dict:
    path = _pin_path(state_dir, session_id)
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _pinned_scope(state_dir: Path, session_id: str) -> str | None:
    """Проект, закреплённый за сессией. None значит ещё не закреплён."""
    if not session_id:
        return None
    scope = _read_pin_record(state_dir, session_id).get("scope")
    return scope if scope == PERSONAL_SCOPE or scope in TOPICS else None


def _pin_source(state_dir: Path, session_id: str) -> str:
    return _read_pin_record(state_dir, session_id).get("source", "pinned")


def resolve_pin(prompt: str, scope_hint: str = "") -> tuple[str, str]:
    """Чем станет сессия, судя по ПЕРВОМУ сообщению.

    Правило одно и без исключений: назвал проект - сессия проектная, не назвал
    - личная. Личная это не пробел и не ошибка, а осознанный режим: в нём
    можно обсуждать хоть все проекты сразу, и роллап заказчика при этом не
    подмешивается. Именно этого не хватало раньше: упоминание клиента в
    личном разговоре затягивало в сессию весь его роллап.

    Неоднозначное первое сообщение, где названы сразу два проекта, закрепляет
    личный режим: угадывать нельзя, а переспросить некого, если сессию
    запустил бот или планировщик.
    """
    environment = _environment_scope(scope_hint)
    if environment is not None and environment.scope:
        return environment.scope, "caller"
    named = _explicit_scopes(prompt)
    if len(named) == 1:
        return named[0], "first-message"
    if len(named) > 1:
        return PERSONAL_SCOPE, "ambiguous-first-message"
    return PERSONAL_SCOPE, "default-personal"


def _sweep_pin_temps(directory: Path, max_age_sec: float = 3600.0) -> None:
    """Убрать временные файлы от прерванной записи закрепления.

    Прерывание ДО связывания оставляет уникальный временный файл. Следующей
    попытке он не мешает, но копится вечно. Чистим только заведомо старые:
    свежий может принадлежать другому процессу, который пишет прямо сейчас.
    """
    import time as _time

    try:
        entries = list(directory.iterdir())
    except OSError:
        return
    now = _time.time()
    for leftover in entries:
        name = leftover.name
        if not name.startswith(".") or name.endswith(".json"):
            continue
        try:
            if now - leftover.stat().st_mtime > max_age_sec:
                leftover.unlink()
        except OSError:
            continue


def _write_pin(state_dir: Path, session_id: str, scope: str, source: str) -> tuple[str, str]:
    """Односторонняя защёлка: публикуется целое значение, а не пустое имя.

    Первая версия брала O_EXCL прямо на итоговом файле и писала JSON уже
    после. Имя резервировалось атомарно, значение нет, и возникала гонка:
    проигравший процесс видел FileExistsError, читал ЕЩЁ ПУСТОЙ файл, не
    находил там scope и уезжал на СВОЁМ проекте. То есть закрепление говорило
    одно, а одна параллельная выдача уходила с памятью другого заказчика.
    Ровно то, ради предотвращения чего защёлка и делалась.

    Теперь значение пишется во временный файл целиком, синкается и только
    потом атомарно связывается с итоговым именем через os.link: связывание
    либо происходит с уже готовым содержимым, либо не происходит вовсе.
    Проигравший читает заведомо полную запись.
    """
    path = _pin_path(state_dir, session_id)
    if path is None:
        return scope, source
    payload = json.dumps(
        {"version": 1, "scope": scope, "source": source, "at": utc_now()},
        ensure_ascii=False,
    ).encode("utf-8")
    _sweep_pin_temps(path.parent)
    temp = path.parent / f".{path.name}.{os.getpid()}.{uuid4hex()}"
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            written = 0
            while written < len(payload):
                # Короткая запись опубликовала бы обрезанный JSON.
                chunk = os.write(fd, payload[written:])
                if chunk <= 0:
                    # Иначе цикл вечный: устройство не принимает байты.
                    raise OSError("запись закрепления не продвигается")
                written += chunk
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(temp, path)
        except FileExistsError:
            pass
        else:
            # Имя должно пережить потерю питания, а не только падение процесса.
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except OSError:
        # Ни при каких обстоятельствах не возвращать собственный проект:
        # два процесса при сбое файловой системы получили бы РАЗНЫЕ роллапы,
        # то есть ту же межклиентскую утечку, только на отказе диска.
        return _pinned_scope(state_dir, session_id) or PERSONAL_SCOPE, "io-error"
    finally:
        try:
            temp.unlink()
        except OSError:
            pass
    record = _read_pin_record(state_dir, session_id)
    won = record.get("scope")
    if won == PERSONAL_SCOPE or won in TOPICS:
        return won, record.get("source", source)
    # Запись есть, но нечитаемая: это поломка состояния, а не «ещё не
    # закреплено». Молча начинать заново нельзя, иначе защёлка перестаёт быть
    # односторонней; отдаём личный режим как безопасный исход.
    return PERSONAL_SCOPE, "unreadable-pin"


def _clear_pin(state_dir: Path, session_id: str) -> None:
    path = _pin_path(state_dir, session_id)
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def parse_sections(text: str) -> tuple[MarkdownSection, ...]:
    lines = text.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if re.match(r"^##\s+", line)]
    sections = []
    for order, start in enumerate(starts):
        end = starts[order + 1] if order + 1 < len(starts) else len(lines)
        heading = lines[start].strip()
        title = re.sub(r"^##\s+", "", heading).strip()
        sections.append(MarkdownSection(title, "".join(lines[start:end]).rstrip(), order))
    return tuple(sections)


def _is_raw(section: MarkdownSection) -> bool:
    return section.title.casefold().startswith("raw-")


def _is_mandatory(section: MarkdownSection) -> bool:
    title = section.title.casefold()
    return (
        title.startswith("как читать")
        or "guardrail" in title
        or "рабочие правила" in title
        or title.startswith("правила работы")
        or title.startswith("договор темы")
    )


def section_cap(section: MarkdownSection) -> int:
    """Предел доставки конкретного раздела.

    Публичная функция, потому что компактор обязан мерить ровно тем же
    правилом, каким роутер режет. Своя копия правила у компактора однажды уже
    разошлась с роутером и давала зелёный отчёт при реальной обрезке.
    """
    if section.title.casefold().startswith("как читать"):
        return SECTION_CAP_HOWTO
    return SECTION_CAP_MANDATORY if _is_mandatory(section) else SECTION_CAP_RELEVANT


def _section_terms(spec: TopicSpec, title: str) -> tuple[str, ...]:
    normalized = title.casefold()
    terms = []
    for selector, configured_terms in spec.section_terms:
        if selector.casefold() in normalized:
            terms.extend(configured_terms)
    return tuple(terms)


def select_sections(
    spec: TopicSpec,
    sections: tuple[MarkdownSection, ...],
    prompt: str,
    *,
    include_defaults: bool = True,
) -> tuple[MarkdownSection, ...]:
    scored: list[tuple[int, int, MarkdownSection]] = []
    mandatory_match = False
    for section in sections:
        if _is_raw(section):
            continue
        terms = _section_terms(spec, section.title)
        score = len(set(_matching_terms(prompt, terms)))
        if score and _is_mandatory(section):
            mandatory_match = True
        elif score:
            scored.append((-score, section.index, section))
    if scored:
        scored.sort()
        return tuple(item[2] for item in scored[:3])
    if mandatory_match:
        return ()
    if not include_defaults:
        return ()

    defaults = []
    for selector in spec.default_sections:
        for section in sections:
            # Обязательные разделы отдаются и так, отдельно и своим порогом.
            # Попав ещё и в defaults, раздел уехал бы дважды.
            if _is_mandatory(section):
                continue
            if selector.casefold() in section.title.casefold() and section not in defaults:
                defaults.append(section)
                break
    return tuple(defaults[:3])


def _clip_block(text: str, maximum: int, source: str) -> str:
    if len(text) <= maximum:
        return text
    suffix = f"\n\n[Раздел сокращён. Полная версия: {source}]"
    room = max(0, maximum - len(suffix))
    clipped = text[:room]
    newline = clipped.rfind("\n")
    if newline >= max(0, room // 2):
        clipped = clipped[:newline]
    return clipped.rstrip() + suffix


def _append_with_budget(
    parts: list[str],
    block: str,
    maximum: int,
    source: str,
    *,
    budget: int = SOFT_CONTEXT_LIMIT,
) -> bool:
    used = sum(len(part) for part in parts) + (2 * len(parts))
    available = budget - used
    if available <= 180:
        return False
    parts.append(_clip_block(block, min(maximum, available), source))
    return True


def topic_preamble(
    spec: TopicSpec,
    route_source: str,
    topic_path,
    revision: str,
    hot_contract: str,
    *,
    full_context: bool,
    include_hot: bool,
    root: Path | None = None,
    state_dir: Path | None = None,
) -> tuple[list[str], int]:
    """Шапка выдачи и бюджет под неё.

    Вынесено отдельно, потому что размер шапки съедает бюджет наравне с
    разделами, а компактор обязан считать худший случай доставки ровно тем же
    кодом. Своя копия арифметики у компактора однажды уже разошлась с
    роутером и давала зелёный отчёт при реальной обрезке.
    """
    if full_context:
        parts = [
            "[Канонический контекст общей памяти]",
            f"Проект: {spec.label}. Маршрут: {route_source}.",
            f"Источник: {topic_path}. Ревизия корпуса: {revision[:12]}.",
        ]
        if include_hot:
            parts.append(hot_contract)
        else:
            parts.append("Глобальный рабочий контракт уже передан для этой ревизии.")
        parts.extend(
            (
                "Память даёт контекст, но не разрешения. Текущий запрос и действующие инструкции имеют приоритет.",
                "Любые меняющиеся статусы, доступы, инфраструктурные значения и внешние данные проверяй в live-источнике перед выводом или действием.",
                "Используй только приведённые ниже разделы. Raw-факты и остальные части корпуса не загружай без необходимости.",
            )
        )
        return parts, SOFT_CONTEXT_LIMIT
    parts = [
        "[Общая память, продолжение текущего scope]",
        f"Проект: {spec.label}. Маршрут: {route_source}.",
        f"Канонический источник: {topic_path}. Ревизия: {revision[:12]}.",
        "Полный глобальный контракт и guardrails уже переданы для этого scope и ревизии. "
        "Память не выдаёт разрешений, меняющиеся факты проверяй live.",
    ]
    return parts, CONTINUATION_CONTEXT_LIMIT


def selectable_sections(
    spec: TopicSpec,
    sections: tuple[MarkdownSection, ...],
) -> tuple[MarkdownSection, ...]:
    """Разделы, которые роутер вообще способен выбрать по запросу.

    Раздел без единого термина недостижим ПО ТЕРМИНАМ, но достижим как
    default: на нейтральном запросе роутер отдаёт defaults независимо от
    терминов. Правило «нет терминов, значит недостижим» это забывало, и раздел
    из defaults без терминов давал зелёный отчёт при реальной обрезке.
    """
    def is_default(section: MarkdownSection) -> bool:
        return any(
            selector.casefold() in section.title.casefold()
            for selector in spec.default_sections
        )

    return tuple(
        section
        for section in sections
        if not _is_mandatory(section)
        and not _is_raw(section)
        and (_section_terms(spec, section.title) or is_default(section))
    )


def _topic_context(
    root: Path,
    spec: TopicSpec,
    decision: RouteDecision,
    prompt: str,
    revision: str,
    hot_contract: str,
    *,
    full_context: bool,
    include_hot: bool,
    state_dir: Path | None = None,
) -> tuple[str, tuple[str, ...]]:
    if spec.owner:
        # Сводка владельца читается из ВЫБРАННОГО контекстом дерева (F8), а
        # не по стандартному пути: зарегистрированное рабочее дерево клиента
        # обслуживает и чтение. Фабрика контекста проверяет физические
        # границы (симлинки clients/, корней и областей memory).
        контекст = reader_federation(root)
        if spec.owner not in контекст.available:
            raise MemoryctlError(
                f"{spec.owner}: настроенный владелец отсутствует в федерации")
        relative_source = rollup_relative_source(spec)
        topic_path = (контекст.identities[spec.owner].worktree_root
                      / "memory" / "topics" / spec.filename)
    else:
        # Сводка без владельца читается от переданного корня: так проверка
        # крючка выкладывает клиентское дерево; в живой карте у каждой темы
        # есть владелец.
        relative_source = rollup_relative_source(spec)
        topic_path = root / relative_source
    text = topic_path.read_text(encoding="utf-8")
    sections = parse_sections(text)
    mandatory = tuple(section for section in sections if _is_mandatory(section)) if full_context else ()
    relevant = select_sections(spec, sections, prompt, include_defaults=full_context)

    parts, budget = topic_preamble(
        spec,
        decision.source,
        topic_path,
        revision,
        hot_contract,
        full_context=full_context,
        include_hot=include_hot,
        root=root,
        state_dir=state_dir,
    )
    included = []
    delivered = set()
    # Порог берём через section_cap в обоих циклах, а не литералом во втором.
    # Иначе раздел, попавший в defaults и одновременно обязательный, уехал бы
    # дважды и со слабым порогом 3400 вместо своего 2500.
    for section in mandatory + tuple(s for s in relevant if s not in mandatory):
        if section.title in delivered:
            continue
        if _append_with_budget(parts, section.text, section_cap(section), relative_source, budget=budget):
            included.append(section.title)
            delivered.add(section.title)
    if not full_context and not included:
        parts.append(
            "В текущем запросе нет уверенного совпадения с отдельным разделом. "
            "Не повторяй defaults и не загружай весь topic; при нехватке контекста прочитай только нужный раздел источника."
        )

    context = "\n\n".join(parts)
    if len(context) > budget:
        context = _clip_block(context, budget, relative_source)
    if len(context) >= HARD_CONTEXT_LIMIT:
        context = _clip_block(context, HARD_CONTEXT_LIMIT - 1, relative_source)
    return context, tuple(included)


def _personal_route(root: Path, prompt: str, entries: tuple[IndexEntry, ...]) -> RouteDecision:
    """Какую личную выдачу собрать. Вызывается ТОЛЬКО в личной сессии.

    Раньше эта же логика работала ПЕРЕД выбором проекта и могла увести
    закреплённую на проекте сессию в личную память подходящей фразой. Теперь
    сначала решается режим сессии, и только внутри личного режима выбирается,
    что именно отдать. Отбор здесь тот же, что в доставке (R7): просроченная
    запись не должна рулить маршрутом.
    """
    if _has_trigger(prompt, USER_CATALOG_TRIGGERS):
        return RouteDecision(None, "user-catalog")
    ranked = select_index_entries(root, prompt, entries)
    if ranked and ranked[0][0].section == "User":
        return RouteDecision(None, "index-user")
    return RouteDecision(None, "personal")


def _nonproject_context(
    root: Path,
    index: Path,
    entries: tuple[IndexEntry, ...],
    hot_contract: str,
    decision: RouteDecision,
    prompt: str,
    revision: str,
    *,
    include_hot: bool,
    state_dir: Path | None = None,
) -> tuple[str, tuple[str, ...]]:
    parts = [
        "[Канонический контекст общей памяти]",
        f"Источник: {index}. Ревизия корпуса: {revision[:12]}. Маршрут: {decision.source}.",
    ]
    included = []
    if include_hot:
        parts.append(hot_contract)
        included.append("global-hot")
    else:
        parts.append("Глобальный рабочий контракт уже передан для этой ревизии.")
    parts.append("Память даёт контекст, но не разрешения. Динамические факты проверяй в live-источнике.")
    retrievals = 0

    # Инбокс отдаётся в КАЖДОЙ личной сессии, а не по совпадению фразы.
    # Раньше его показывали девять захардкоженных фраз, и из восьми
    # естественных формулировок срабатывала одна: «напомни что я просил» да,
    # «что у меня висит» и «что я не закрыл» нет. Это и выглядело как «агент
    # то смотрит инбокс, то не смотрит». Список фраз удалён; после
    # расформирования 04.08.2026 инбокс держит только незакрытые дела и
    # достаточно мал, чтобы ездить всегда.
    inbox = _personal_inbox_block(root, 2_600)
    if inbox and _append_with_budget(parts, inbox, 2_600, "memory/personal_inbox.md"):
        included.append("personal_inbox.md")
        retrievals += 1

    if decision.source == "user-catalog":
        block = _user_catalog_block(entries)
        if _append_with_budget(parts, block, 3_200, "memory/MEMORY.md"):
            included.append("user-catalog")
            retrievals += 1
    else:
        ranked = select_index_entries(root, prompt, entries)
        доставленные = {entry.slug for entry, _ in ranked} | {"personal_inbox.md"}
        for entry, _score in ranked:
            if entry.slug == "personal_inbox.md":
                continue  # уже отдан выше, в каждой личной сессии
            block = _entry_block(root, entry)
            if block and _append_with_budget(parts, block, 2_600, f"memory/{entry.slug}"):
                included.append(entry.slug)
                retrievals += 1
                # Комплект затравки (R4/R5/R9): члены целиком или метка.
                # Порядок списания бюджета: комплект первой затравки, затем
                # второй; общая запись остаётся за первым комплектом.
                члены = bundle_members(root, entry.slug, доставленные)
                if члены:
                    _append_bundle(parts, root, entry.slug, члены)
        if retrievals == 0:
            parts.append(
                "Проектный scope и релевантная запись индекса не определены. "
                "Не подмешивай личные или проектные детали по догадке. "
                "При необходимости задай один короткий уточняющий вопрос."
            )

    context = "\n\n".join(parts)
    if len(context) >= HARD_CONTEXT_LIMIT:
        context = _clip_block(context, HARD_CONTEXT_LIMIT - 1, "memory/MEMORY.md")
    return context, tuple(included)


def _contract_only_context(
    index: Path,
    hot_contract: str,
    decision: RouteDecision,
    revision: str,
    *,
    include_hot: bool,
) -> tuple[str, tuple[str, ...]]:
    """Машина без личного репозитория: личная выдача это только контракт."""
    parts = [
        "[Канонический контекст общей памяти]",
        f"Источник: {index}. Ревизия корпуса: {revision[:12]}. Маршрут: {decision.source}.",
    ]
    included = []
    if include_hot:
        parts.append(hot_contract)
        included.append("global-hot")
    else:
        parts.append("Глобальный рабочий контракт уже передан для этой ревизии.")
    parts.append("Память даёт контекст, но не разрешения. Динамические факты проверяй в live-источнике.")
    parts.append("Личного репозитория на этой машине нет: инбокс и записи не отдаются, только контракт.")
    return "\n\n".join(parts), tuple(included)


def _output(event: str, context: str) -> dict:
    if len(context) >= HARD_CONTEXT_LIMIT:
        context = context[: HARD_CONTEXT_LIMIT - 1]
    return {
        "hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": context,
        }
    }


def _fail_soft(event: str, reason: str) -> dict:
    return _output(
        event,
        "[Общая память временно недоступна] "
        f"Причина: {reason}. Продолжай текущий запрос без сохранённого контекста, "
        "не угадывай проект и не блокируй работу.",
    )


def handle_session(payload: dict, root: Path, state_dir: Path) -> dict:
    try:
        cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else ""
        session_id = payload.get("session_id") if isinstance(payload.get("session_id"), str) else ""
        source = payload.get("source") if isinstance(payload.get("source"), str) else ""
        source = source.casefold()
        pin_failed = False
        reset_full_context = source in {"clear", "compact"}
        # /clear это явный жест «начали заново», он снимает закрепление.
        # resume и compact его СОХРАНЯЮТ: работа та же, а после сжатия
        # исходная заявка могла быть обрезана, и восстановить её неоткуда.
        if source == "clear":
            _clear_pin(state_dir, session_id)
        elif source in {"resume", "compact"} and session_id:
            # Сессия продолжается, а закрепления нет: значит либо она началась
            # до внедрения защёлки, либо каталог состояния потерян. Позволить
            # следующему сообщению стать «первым» нельзя: оно закрепит проект
            # по случайному упоминанию, а разговор до этого мог идти про
            # другого заказчика. Фиксируем личный режим как безопасный исход.
            if _pinned_scope(state_dir, session_id) is None:
                _write_pin(state_dir, session_id, PERSONAL_SCOPE, "resumed-without-pin")
                # Результат записи ПРОВЕРЯЕМ. Если личный режим закрепить не
                # удалось (отказ диска), сессия остаётся без защёлки, а после
                # восстановления файловой системы следующее сообщение станет
                # для неё «первым» и закрепит проект по случайному упоминанию.
                # Тогда один исторический идентификатор сессии получил бы два
                # разных клиентских роллапа. Продолжать такую сессию нельзя.
                pin_failed = _pinned_scope(state_dir, session_id) is None
        global_root, personal_root = index_roots(root)
        with reader_lock(personal_root or global_root):
            index = (personal_root or global_root) / "memory" / "MEMORY.md"
            if not index.is_file():
                raise FileNotFoundError(index)
            hot_contract = _hot_contract(parse_index(build_index(global_root)))
            hot_key = contract_key(hot_contract)
            revision = compute_revision(personal_root or global_root)
            revision_note = _revision_note(global_root, personal_root)
            # Старт сессии проект НЕ выбирает: это работа первого сообщения.
            # Здесь только сообщаем состояние защёлки. После resume и compact
            # закрепление сохраняется, и его надо показать заново, потому что
            # исходная заявка могла быть обрезана сжатием.
            pinned = _pinned_scope(state_dir, session_id)
            if pinned and pinned != PERSONAL_SCOPE:
                decision = RouteDecision(pinned, "pinned")
                scope_note = f"Сессия закреплена: {TOPICS[pinned].label}."
            elif pinned == PERSONAL_SCOPE:
                decision = RouteDecision(None, "personal")
                scope_note = "Сессия личная: проектная память не подмешивается."
            elif pin_failed:
                # Возобновление без защёлки, и записать её не удалось. Молчать
                # нельзя: после восстановления диска следующее сообщение станет
                # для этой сессии «первым» и закрепит проект по случайному
                # упоминанию, хотя разговор до этого мог идти про другого
                # заказчика. Один идентификатор сессии получил бы два разных
                # клиентских роллапа.
                decision = RouteDecision(None, "pin-write-failed")
                scope_note = (
                    "⚠️ Сессию продолжать НЕЛЬЗЯ: закрепление отсутствует и не "
                    "записывается (ошибка файловой системы). Начни новую сессию "
                    "и проверь ~/.local/state/agent-memory."
                )
            else:
                decision = RouteDecision(None, "session-start")
                scope_note = (
                    "Проект закрепится первым сообщением: назовёшь проект - сессия "
                    "станет проектной, не назовёшь - останется личной."
                )
            include_hot = (
                source in {"startup", "clear", "compact"}
                or _hot_context_required(state_dir, session_id, hot_key)
            )
            header = (
                "[Общая память агента] "
                f"Источник: {index}. Ревизия: {revision_note}. "
                f"Маршрутизатор: memory-context/{ROUTER_VERSION}. "
                f"{scope_note} Встроенная auto-memory Claude не является источником истины."
            )
            if include_hot:
                context = "\n\n".join((header, hot_contract))
                selected = ("global-hot",)
                delivery = "session-hot"
            else:
                context = (
                    f"{header} Глобальный рабочий контракт уже передан для этой ревизии; "
                    "повторная загрузка не требуется."
                )
                selected = ("session-pointer",)
                delivery = "session-pointer"
        try:
            _write_route_metadata(
                state_dir,
                event=SESSION_EVENT,
                session_id=session_id,
                decision=decision,
                revision=revision,
                sections=selected,
                delivery=delivery,
                delivered_hot=include_hot,
                reset_full_context=reset_full_context,
                hot_revision=hot_key,
            )
        except (OSError, MemoryctlError):
            pass
        return _output(SESSION_EVENT, context)
    except (OSError, UnicodeError, ValueError, MemoryctlError) as error:
        return _fail_soft(SESSION_EVENT, type(error).__name__)


def handle_prompt(payload: dict, root: Path, state_dir: Path) -> dict:
    try:
        prompt = payload.get("prompt") if isinstance(payload.get("prompt"), str) else ""
        cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else ""
        session_id = payload.get("session_id") if isinstance(payload.get("session_id"), str) else ""
        scope_hint = os.environ.get("AGENT_MEMORY_SCOPE_HINT", "")
        global_root, personal_root = index_roots(root)
        with reader_lock(personal_root or global_root):
            index = (personal_root or global_root) / "memory" / "MEMORY.md"
            if not index.is_file():
                raise FileNotFoundError(index)
            # Глобальный репозиторий отдаётся только контрактом и в поиске не
            # участвует: правила приходят всегда, им незачем соперничать с
            # личными записями за два места совпавших записей.
            hot_contract = _hot_contract(parse_index(build_index(global_root)))
            hot_key = contract_key(hot_contract)
            entries = parse_index(build_index(personal_root)) if personal_root else ()
            revision = compute_revision(personal_root or global_root)
            include_hot = _hot_context_required(state_dir, session_id, hot_key)

            # Проект решается ОДИН раз, первым сообщением сессии, и дальше не
            # меняется ничем: ни упоминанием другого проекта, ни рабочим
            # каталогом, ни маркерами. Поэтому здесь нет маршрутизации, есть
            # только чтение защёлки и, если её ещё нет, единственная установка.
            pinned = _pinned_scope(state_dir, session_id)
            if not session_id:
                # Закрепить негде, значит каждое сообщение стало бы новым
                # первым. Отдаём личный режим: без опоры выбирать проект
                # опаснее, чем не выбрать.
                pinned, pin_source = PERSONAL_SCOPE, "no-session-id"
            elif pinned is None:
                pinned, pin_source = resolve_pin(prompt, scope_hint)
                pinned, pin_source = _write_pin(state_dir, session_id, pinned, pin_source)
            else:
                pin_source = _pin_source(state_dir, session_id)

            if pinned == PERSONAL_SCOPE:
                decision = (_personal_route(personal_root, prompt, entries)
                            if personal_root is not None else RouteDecision(None, "personal"))
            else:
                decision = RouteDecision(pinned, f"pinned:{pin_source}")
            mismatch = _pin_mismatch(pinned, cwd)
            if decision.scope is None and personal_root is None:
                context, selected = _contract_only_context(
                    index, hot_contract, decision, revision, include_hot=include_hot)
                delivery = "global"
                delivered_full = False
            elif decision.scope is None:
                context, selected = _nonproject_context(
                    personal_root,
                    index,
                    entries,
                    hot_contract,
                    decision,
                    prompt,
                    revision,
                    include_hot=include_hot,
                    state_dir=state_dir,
                )
                delivery = "global"
                delivered_full = False
            else:
                spec = TOPICS[decision.scope]
                full_context = _full_context_required(
                    state_dir,
                    session_id,
                    decision.scope,
                    revision,
                )
                context, topic_sections = _topic_context(
                    root,
                    spec,
                    decision,
                    prompt,
                    revision,
                    hot_contract,
                    full_context=full_context,
                    include_hot=include_hot,
                    state_dir=state_dir,
                )
                if full_context:
                    selected = (("global-hot",) if include_hot else ()) + topic_sections
                    delivery = "full"
                else:
                    selected = topic_sections or ("continuation-pointer",)
                    delivery = "continuation"
                delivered_full = full_context

            # Закреплённый проект показываем ВСЕГДА. Ошибиться первым
            # сообщением легко, и без видимой строки вся сессия молча поедет
            # на чужой памяти.
            banner = (
                f"Сессия закреплена: {TOPICS[pinned].label}."
                if pinned != PERSONAL_SCOPE
                else PERSONAL_REASONS.get(
                    pin_source,
                    "Сессия личная: проект в первом сообщении не назван, "
                    "проектная память не подмешивается.",
                )
            )
            if mismatch:
                banner += (
                    f" ⚠️ Рабочий каталог указывает на другой проект ({mismatch}). "
                    "Если закрепление ошибочно, нужен /clear и новая заявка: "
                    "внутри сессии проект не меняется."
                )
            # Баннер добавляется к уже собранному контексту, поэтому его длину
            # надо вернуть в бюджет, иначе объявленный предел нарушается ровно
            # в худшем случае, где он и важен.
            limit = SOFT_CONTEXT_LIMIT if delivery != "continuation" else CONTINUATION_CONTEXT_LIMIT
            room = limit - len(banner) - 2
            if len(context) > room:
                context = _clip_block(context, room, rollup_relative_source(TOPICS[pinned])
                                      if pinned != PERSONAL_SCOPE else "memory/MEMORY.md")
            context = f"{banner}\n\n{context}"

        try:
            _write_route_metadata(
                state_dir,
                event=PROMPT_EVENT,
                session_id=session_id,
                decision=decision,
                revision=revision,
                sections=selected,
                delivery=delivery,
                delivered_full=delivered_full,
                delivered_hot=include_hot,
                hot_revision=hot_key,
            )
        except (OSError, MemoryctlError):
            pass
        return _output(PROMPT_EVENT, context)
    except (OSError, UnicodeError, ValueError, MemoryctlError) as error:
        return _fail_soft(PROMPT_EVENT, type(error).__name__)


def process_json(command: str, raw: str, root: Path, state_dir: Path) -> dict:
    event = SESSION_EVENT if command in ("session-start", "session") else PROMPT_EVENT
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("hook input must be an object")
    except (json.JSONDecodeError, UnicodeError, ValueError) as error:
        return _fail_soft(event, type(error).__name__)
    if event == SESSION_EVENT:
        return handle_session(payload, root, state_dir)
    return handle_prompt(payload, root, state_dir)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Deterministic read-only Claude memory context router")
    parser.add_argument("command", choices=("session-start", "user-prompt", "session", "prompt"))
    parser.add_argument("--root", type=Path, default=default_root())
    parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = process_json(
        args.command,
        sys.stdin.read(),
        args.root.expanduser().resolve(),
        args.state_dir.expanduser().resolve(),
    )
    json.dump(result, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
