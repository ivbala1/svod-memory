#!/usr/bin/env python3
"""Доставка памяти любому агенту через оболочку, только чтение.

Зачем. Доставка и защита записи живут в хуках ОДНОГО инструмента. Замер
10.08.2026 показал, что вся разница между 1 и 10 верными ответами из 15 это
подложенный блок памяти. Значит агент без хуков (Codex, редактор, планировщик,
телефонный мост) отвечает почти вслепую. Оболочка есть у всех, поэтому фасад
делается командой, а не протоколом.

Чего здесь СОЗНАТЕЛЬНО нет.

1. Обработчик события хука не вызывается. `handle_prompt` не чистая функция:
   он пишет защёлку сессии, `last-route.json` и отметку о доставке. Команда,
   позвавшая его с тем же идентификатором, закрепила бы область за чужой
   сессией или «съела» полную выдачу до хука. Поэтому берутся сборщики блока,
   а состояние не трогается вовсе.

2. Рабочий каталог НЕ выбирает проект. Он не удостоверение: любой процесс того
   же пользователя может перейти в нужный каталог. Каталог задаёт только
   ПОТОЛОК, то есть верхнюю границу того, сколько памяти позволено запросить.
   Это защита от промаха, а не от умысла, и выдавать её за разграничение
   доступа нельзя.

3. Каталог сопоставляется по точному каноническому пути после realpath, а не
   по именам компонентов, как `cwdNames` в маршрутизаторе. Совпадение имён
   годится для предупреждения, но для разграничения данных слишком слабо:
   личный каталог, случайно названный как клиентский, менял бы область.

4. Каталог вне всех настроенных корней НЕ считается личным. Личная выдача
   включает инбокс и может выбрать клиентскую запись из общего индекса, так
   что «не знаю, где я» обязано означать минимум, а не максимум.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import configpaths
import memorycontext as mc
import memoryctl
import topiclayout
from memoryctl import MemoryctlError, compute_revision

PERSONAL = mc.PERSONAL_SCOPE

# Область, выданная командой, а не защёлкой сессии. Отдельный ярлык нужен,
# чтобы в стенограмме было видно, что проект выбран вызовом, и его нельзя
# спутать с закреплением, которое переживает всю сессию.
SHELL_SOURCE = "shell"


class RecallError(Exception):
    """Отказ, который надо показать вызывающему, а не проглотить."""


def _config_path() -> Path:
    return configpaths.config_path("topics.json")


def _load_scope_roots() -> dict[str, tuple[Path, ...]]:
    """Корни областей из общего конфига, с проверкой каждой предпосылки.

    Конфиг разграничения без проверки это ровно тот дефект, который в этом
    репозитории уже ловили четырежды: удобный признак вместо настоящего
    свойства. Молча пустой или дублирующийся корень тихо снял бы потолок.
    """
    path = _config_path()
    # Разбор из байтов, прочитанных memorycontext при импорте: scopeRoots и
    # TOPICS одного вызова принадлежат одному поколению конфига (Q7).
    try:
        raw = json.loads(mc.TOPICS_RAW.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MemoryctlError(f"не читается конфиг тем {path}: {exc}") from exc
    section = raw.get("scopeRoots")
    if not isinstance(section, dict) or not section:
        raise MemoryctlError(f"{path}: раздел scopeRoots пуст или не объект")

    known = set(mc.TOPICS) | {PERSONAL}
    roots: dict[str, tuple[Path, ...]] = {}
    занято: dict[Path, str] = {}
    for scope, values in section.items():
        if scope.startswith("_"):
            continue  # поле-комментарий
        if scope not in known:
            raise MemoryctlError(f"{path}: scopeRoots упоминает неизвестную область {scope!r}")
        if not isinstance(values, list) or not values:
            raise MemoryctlError(f"{path}: у области {scope} список корней пуст или не список")
        собранные: list[Path] = []
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise MemoryctlError(f"{path}: у области {scope} пустой корень")
            candidate = Path(value).expanduser()
            if not candidate.is_absolute():
                raise MemoryctlError(f"{path}: корень {value!r} области {scope} не абсолютный")
            # Несуществующий корень не ошибка: репозиторий заказчика может быть
            # не склонирован на этой машине. Ошибка это ОДИН путь у двух
            # областей, потому что тогда потолок неоднозначен.
            resolved = _resolve(candidate)
            owner = занято.setdefault(resolved, scope)
            if owner != scope:
                raise MemoryctlError(
                    f"{path}: корень {value!r} принадлежит и {owner}, и {scope}"
                )
            собранные.append(resolved)
        roots[scope] = tuple(собранные)

    if PERSONAL not in roots:
        raise MemoryctlError(f"{path}: в scopeRoots нет личного корня")
    без_корня = sorted(set(mc.TOPICS) - set(roots))
    if без_корня:
        # Тема без корня недостижима по каталогу вообще. Это допустимо, но
        # обязано быть решением, а не опечаткой, поэтому конфиг обязан
        # перечислить все темы.
        raise MemoryctlError(f"{path}: в scopeRoots нет корней для тем {без_корня}")
    return roots


def _resolve(path: Path, *, строго: bool = False) -> Path:
    """Физический путь. Символические ссылки и `..` снимаются здесь.

    Для КАТАЛОГА ВЫЗЫВАЮЩЕГО откат к лексическому пути недопустим: граница
    объявлена канонической, а лексический откат авторизует по строке. Петля
    ссылок, отказ доступа или несуществующий путь тогда снова дают потолок по
    внешнему виду пути. Поэтому там строгий режим и отказ.

    Для КОРНЕЙ ИЗ КОНФИГА откат допустим и нужен: репозиторий заказчика может
    быть не склонирован на этой машине, и несуществующий корень не должен
    ронять команду. Несуществующий корень никого не авторизует, потому что
    каталог вызывающего в него всё равно не попадёт.
    """
    try:
        return path.resolve(strict=строго)
    except (OSError, RuntimeError) as ошибка:
        if строго:
            raise RecallError(
                f"не удалось привести каталог {path} к каноническому виду: {ошибка}"
            ) from ошибка
        return path.absolute()


def ceiling_for(cwd: str | os.PathLike[str], roots: dict[str, tuple[Path, ...]]) -> str | None:
    """Самая узкая область, разрешённая рабочим каталогом. None значит никакой.

    Побеждает САМЫЙ ДЛИННЫЙ совпавший корень: клиентские каталоги лежат внутри
    личного, и без этого правила `~/src/acme` давал бы личный потолок,
    то есть доступ ко всей памяти сразу.
    """
    if not cwd:
        return None
    here = _resolve(Path(cwd), строго=True)
    лучший: tuple[int, str] | None = None
    for scope, paths in roots.items():
        for root in paths:
            if here == root or here.is_relative_to(root):
                глубина = len(root.parts)
                if лучший is None or глубина > лучший[0]:
                    лучший = (глубина, scope)
    return лучший[1] if лучший else None


def allowed_scopes(потолок: str | None) -> frozenset[str]:
    """Что вызывающему позволено запросить при таком потолке."""
    if потолок is None:
        return frozenset()
    if потолок == PERSONAL:
        return frozenset({PERSONAL}) | frozenset(mc.TOPICS)
    return frozenset({потолок})


def resolve_scope(requested: str | None, потолок: str | None) -> str | None:
    """Итоговая область. None значит только глобальный контракт.

    Слишком широкая выдача хуже слишком узкой: узкая портит ответ и легко
    повторяется, а широкая оставляет чужие данные в стенограмме и может
    повлиять на внешнее действие. Поэтому при сомнении сужаем.
    """
    разрешено = allowed_scopes(потолок)
    if requested is None:
        return потолок
    if requested not in (set(mc.TOPICS) | {PERSONAL}):
        raise RecallError(f"неизвестная область {requested!r}")
    if requested not in разрешено:
        где = "вне настроенных корней" if потолок is None else f"с потолком {потолок}"
        raise RecallError(
            f"область {requested!r} шире, чем разрешает рабочий каталог ({где}). "
            "Перейди в каталог этой области или запусти команду оттуда."
        )
    return requested


def _global_only_block(index: Path, hot_contract: str, revision: str) -> str:
    """Минимум для каталога без потолка: только глобальный контракт.

    Ни инбокса, ни записей, ни сводок. Этот блок уже едет в КАЖДУЮ сессию
    любой области, поэтому клиентских и личных данных в нём нет по построению.
    """
    return "\n\n".join(
        [
            "[Канонический контекст общей памяти]",
            f"Источник: {index}. Ревизия корпуса: {revision[:12]}. Маршрут: {SHELL_SOURCE}-global.",
            hot_contract,
            "Память даёт контекст, но не разрешения. Динамические факты проверяй в live-источнике.",
            "Рабочий каталог не лежит ни в одном настроенном корне памяти, поэтому "
            "записи и сводки не отдаются. Нужна конкретная область, запусти команду "
            "из её каталога или назови её через --scope.",
        ]
    )


def _read_consistently(root: Path, state_dir: Path, построить):
    """Прочитать дерево так, чтобы не поймать его в середине транзакции.

    Под замком одного чтения достаточно. Без замка сверяем ревизии до и после:
    совпали, значит транзакция в это окно не завершалась. Разошлись, значит
    читали во время записи, и единственная повторная попытка это исправляет.
    Сверяется ПОЛНЫЙ ревизионный вектор федерации, а не одна ревизия общего
    корня: сводка темы с владельцем читается из клиентского корня, и его
    транзакция меняет выдачу, не трогая общий репозиторий. Замок общего
    корня клиентского писателя тоже не держит, поэтому вектор сверяется и
    в ветке под замком.
    """
    global_root, personal_root = mc.index_roots(root)
    with memoryctl.reader_lock(personal_root or global_root):
        # Цикл до стабильной пары векторов: одиночный повтор принимал второй
        # результат вслепую, и длинная клиентская транзакция снова попадала
        # бы в промежуточное состояние. Предел попыток с явным отказом.
        for _попытка in range(3):
            до = memoryctl.revision_vector(
                root, federation=mc.reader_federation(root))
            итог = построить()
            if memoryctl.revision_vector(
                    root, federation=mc.reader_federation(root)) == до:
                return итог
        raise RecallError("корпус меняется во время чтения, повтори запрос")


def build_body(root: Path, scope: str | None, prompt: str) -> tuple[str, tuple[str, ...]]:
    """Тело блока: то же, что собрал бы хук, без единой записи состояния.

    Вызываются именно СБОРЩИКИ маршрутизатора, а не обработчик события,
    поэтому расхождение возможно только в шапке, и это проверяется тестом на
    побайтовое равенство.
    """
    global_root, personal_root = mc.index_roots(root)
    index = (personal_root or global_root) / "memory" / "MEMORY.md"
    if not index.is_file():
        raise RecallError(f"нет индекса памяти {index}")
    hot_contract = mc._hot_contract(mc.parse_index(mc.build_index(global_root)))
    entries = mc.parse_index(mc.build_index(personal_root)) if personal_root else ()
    revision = compute_revision(personal_root or global_root)

    if scope is None:
        return _global_only_block(index, hot_contract, revision), ("global-hot",)
    if scope == PERSONAL:
        if personal_root is None:
            decision = mc.RouteDecision(None, "personal")
            return mc._contract_only_context(
                index, hot_contract, decision, revision, include_hot=True)
        decision = mc._personal_route(personal_root, prompt, entries)
        return mc._nonproject_context(
            personal_root, index, entries, hot_contract, decision, prompt, revision, include_hot=True
        )
    spec = mc.TOPICS[scope]
    # Не `pinned:`, потому что ничего не закрепляется. Слово «pinned» в
    # стенограмме означало бы защёлку сессии, которой у команды нет.
    decision = mc.RouteDecision(scope, SHELL_SOURCE)
    return mc._topic_context(
        root,
        spec,
        decision,
        prompt,
        revision,
        hot_contract,
        full_context=True,
        include_hot=True,
    )


def banner_for(scope: str | None) -> str:
    """Шапка обязана говорить правду про ЭТОТ вызов.

    Прежняя редакция писала «Сессия закреплена», хотя команда не создаёт
    никакой защёлки и следующий вызов волен выбрать другую область. Это была
    настоящая дивергенция с хуком, спрятанная за формулировкой.
    """
    if scope is None:
        return ("Область этого вызова не определена: каталог вне настроенных корней, "
                "отдан только глобальный контракт. Сессию не закрепляет.")
    if scope == PERSONAL:
        return ("Область этого вызова: личная, отдаются глобальные правила, инбокс "
                "и подходящие записи. Сессию не закрепляет.")
    return f"Область этого вызова: {mc.TOPICS[scope].label}. Сессию не закрепляет."


def recall(
    prompt: str,
    *,
    scope: str | None,
    cwd: str,
    root: Path | None = None,
    state_dir: Path | None = None,
) -> str:
    """Блок, который отдал бы маршрутизатор. Ничего не пишет."""
    root = (root or mc.default_root()).expanduser()
    roots = _load_scope_roots()
    потолок = ceiling_for(cwd, roots)
    итог = resolve_scope(scope, потолок)

    state_dir = state_dir or mc.default_state_dir()
    body, _ = _read_consistently(root, state_dir, lambda: build_body(root, итог, prompt))

    banner = banner_for(итог)
    room = mc.SOFT_CONTEXT_LIMIT - len(banner) - 2
    if len(body) > room:
        source = (
            mc.rollup_relative_source(mc.TOPICS[итог])
            if итог and итог != PERSONAL
            else "memory/MEMORY.md"
        )
        body = mc._clip_block(body, room, source)
    return f"{banner}\n\n{body}"


def explain(
    slug: str,
    *,
    root: Path | None = None,
    today: dt.date | None = None,
) -> dict:
    """Объяснить видимость записи по данным её собственного корня (R10).

    Команда не обращается к каталогу состояния: для ответа достаточно файла,
    индекса его корня и цепочки supersedes. Это сохраняет обещание read-only
    даже на машине, где писатель ещё не создавал служебные файлы.
    """
    root = (root or mc.default_root()).expanduser().resolve()
    global_root, personal_root = mc.index_roots(root)
    имя = slug[:-3] if slug.endswith(".md") else slug
    if not memoryctl.SLUG_RE.fullmatch(имя):
        raise RecallError(f"недопустимый slug {slug!r}")
    файл_имя = f"{имя}.md"
    найденный_корень: Path | None = None
    найденный_файл: Path | None = None
    в_архиве = False
    for корень in memoryctl.federation_roots(mc.reader_federation(root)):
        действующая = корень / "memory" / файл_имя
        архивная = корень / "memory" / "archive" / файл_имя
        if действующая.is_file():
            найденный_корень, найденный_файл = корень, действующая
            break
        if архивная.is_file():
            найденный_корень, найденный_файл, в_архиве = корень, архивная, True
            break

    if найденный_файл is None or найденный_корень is None:
        return {
            "exists": None,
            "indexed": False,
            "superseded_by": None,
            "expired": None,
            "review_due": None,
            "delivery": False,
            "reason": "не существует",
        }

    if в_архиве:
        расположение = "архив"
    elif найденный_корень == personal_root:
        расположение = "личный"
    elif найденный_корень == global_root:
        расположение = "глобальный"
    else:
        try:
            расположение = найденный_корень.relative_to(root).as_posix()
        except ValueError:
            расположение = str(найденный_корень)

    индекс = найденный_корень / "memory" / "MEMORY.md"
    записи = mc.parse_index(mc.build_index(найденный_корень)) if индекс.is_file() else ()
    проиндексирована = any(entry.slug == файл_имя for entry in записи)
    текст = найденный_файл.read_text(encoding="utf-8")
    поля, _ = memoryctl.parse_frontmatter(текст)
    сегодня = today if today is not None else memoryctl.utc_today()

    def прошедшая_дата(поле: str) -> str | None:
        значение = поля.get(поле)
        if not значение:
            return None
        try:
            дата = dt.date.fromisoformat(значение)
        except ValueError:
            return None
        return значение if сегодня > дата else None

    просрочена = прошедшая_дата("valid_until")
    обзор_просрочен = прошедшая_дата("review_after")
    преемник = mc.resolve_final_successor(найденный_корень, имя) if в_архиве else None
    if преемник == имя:
        преемник = None
    доставка = not в_архиве and проиндексирована and просрочена is None

    # Запись без строки индекса может быть свёрнута в сводку темы, и после
    # переезда сводок каноническая формулировка живёт у владельца. Называть
    # такую запись «сиротой» значит путать штатное замещение с потерей (R10:
    # причины невидимости различимы). Чтение мягкое: explain обязан отвечать
    # и на неполном корпусе, поэтому битый конфиг или отсутствующая сводка
    # здесь не отказ, а «упоминания не нашлось».
    свёрнута_в = None
    if not проиндексирована and not в_архиве:
        try:
            # Раскладка из поколения процесса (Q7), деревья владельцев из
            # контекста читателя (F8): зарегистрированное рабочее дерево
            # обслуживает и explain.
            раскладка = topiclayout.placement_from_config(
                json.loads(mc.TOPICS_RAW.decode("utf-8")), _config_path())
        except (ValueError, UnicodeError, json.JSONDecodeError):
            раскладка = {}
        try:
            контекст = mc.reader_federation(root)
        except Exception:
            контекст = None
        for имя_сводки, (_ключ, владелец) in sorted(раскладка.items()):
            if найденный_корень == personal_root and владелец:
                if контекст is not None and владелец in контекст.available:
                    путь_сводки = (контекст.identities[владелец].worktree_root
                                   / "memory" / "topics" / имя_сводки)
                else:
                    путь_сводки = root / topiclayout.rollup_relative_source(
                        имя_сводки, владелец)
            else:
                путь_сводки = найденный_корень / "memory" / "topics" / имя_сводки
            try:
                текст_сводки = путь_сводки.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            if memoryctl._slug_mentioned(файл_имя, текст_сводки)                     or memoryctl._slug_mentioned(имя, текст_сводки):
                свёрнута_в = имя_сводки
                break

    if в_архиве and преемник:
        причина = f"замещена: {преемник}"
    elif в_архиве:
        причина = "в архиве без преемника"
    elif просрочена:
        причина = f"просрочена: {просрочена}"
    elif not проиндексирована and свёрнута_в:
        причина = f"свёрнута в сводку {свёрнута_в}: канон формулировки в сводке темы"
    elif not проиндексирована:
        причина = "не проиндексирована (сирота)"
    else:
        причина = "активна"
    return {
        "exists": расположение,
        "indexed": проиндексирована,
        "superseded_by": преемник,
        "expired": просрочена,
        "review_due": обзор_просрочен,
        "rolled_into": свёрнута_в,
        "delivery": доставка,
        "reason": причина,
    }


def _read_prompt(значение: str | None) -> str:
    """Вопрос из аргумента или со стандартного ввода.

    Через ввод он приходит без боя с кавычками оболочки, без предела длины
    аргументов и без утечки текста в список процессов.
    """
    if значение is None or значение == "-":
        return sys.stdin.read()
    return значение


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memory",
        description="Память агента из оболочки. Пока только чтение.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("recall", help="напечатать блок памяти по вопросу")
    r.add_argument("question", nargs="?", help="вопрос; '-' или пропуск читает stdin")
    r.add_argument("--scope", default=None, help="запрошенная область, не шире потолка каталога")
    r.add_argument("--root", type=Path, default=None, help="корень репозитория памяти")
    e = sub.add_parser("explain", help="объяснить видимость записи по slug")
    e.add_argument("slug", help="slug записи, с .md или без")
    e.add_argument("--root", type=Path, default=None, help="корень репозитория памяти")
    # Срез 1 блока 3 (B11). Команда remember промежуточная: в штатные
    # инструкции агентов не вносится до среза 3 (T5).
    m = sub.add_parser("remember", help="принять предложение в журнал памяти")
    m.add_argument("--scope", required=True, help="логическая область предложения")
    m.add_argument("--id", required=True, dest="proposal_id",
                   help="идентификатор идемпотентности [a-z0-9][a-z0-9_-]{7,63}")
    m.add_argument("--file", default=None, help="файл тела; без него читается stdin")
    m.add_argument("--content-type", default="markdown",
                   choices=["markdown", "manifest"])
    m.add_argument("--source", default="shell", help="агент-источник")
    m.add_argument("--session", default="shell", help="идентификатор сессии")
    m.add_argument("--birth-pair", default=None,
                   help="устарело (Свод-0, шаг 2): крючок поиска задаётся "
                        "полем probe в шапке записи; приложенная пара не "
                        "пишется и называется предупреждением")
    m.add_argument("--projection", default=None,
                   help="JSON-файл проекции кандидата (конверт v2, срез 2): "
                        "record_slug [+ index_line + index_section]")
    m.add_argument("--json", action="store_true", dest="as_json")
    st = sub.add_parser("status", help="состояние репозиториев памяти из git и каталога ожидания")
    st.add_argument("--fetch", action="store_true", help="сначала fetch с сервера")
    st.add_argument("--nudge", action="store_true",
                    help="одна строка только если есть что разобрать; для хука старта сессии")
    st.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command in ("recall", "explain"):
            if args.command == "recall":
                prompt = _read_prompt(args.question)
                # Физический каталог процесса, а не логический $PWD: под
                # символической ссылкой они расходятся, и потолок считался
                # бы по видимости.
                text = recall(prompt, scope=args.scope, cwd=os.getcwd(), root=args.root)
            else:
                text = json.dumps(explain(args.slug, root=args.root),
                                  ensure_ascii=False, sort_keys=True)
        elif args.command == "remember":
            import memoryremember
            проекция = None
            if args.projection:
                try:
                    raw = Path(args.projection).read_bytes()
                    if len(raw) > 8 * 1024:
                        raise ValueError("projection файл больше предела")
                    проекция = json.loads(raw.decode("utf-8"))
                except (OSError, ValueError) as exc:
                    print(json.dumps({"state": "failed", "reason": f"projection: {exc}"},
                                     ensure_ascii=False, sort_keys=True))
                    return memoryremember.EXIT_FAILED
            if args.birth_pair:
                print("memory remember: --birth-pair больше не читается, крючок это поле "
                      "probe в шапке записи", file=sys.stderr)
            try:
                тело = (Path(args.file).read_bytes() if args.file
                        else sys.stdin.buffer.read())
            except OSError as exc:
                print(json.dumps({"state": "failed", "reason": f"тело: {exc}"},
                                 ensure_ascii=False, sort_keys=True))
                return memoryremember.EXIT_FAILED
            код, результат = memoryremember.run_remember(
                scope=args.scope, candidate_id=args.proposal_id, source=args.source,
                session=args.session, content_type=args.content_type, body=тело,
                projection=проекция)
            if args.as_json:
                print(json.dumps(результат, ensure_ascii=False, sort_keys=True))
            else:
                print(" ".join(f"{k}={v}" for k, v in sorted(результат.items())))
            return код
        elif args.command == "status":
            import memorysync
            if args.nudge:
                # Подсказка не имеет права ломать старт сессии: любая ошибка
                # это молчание, слова скажет полный статус.
                try:
                    строка = memorysync.format_nudge(memorysync.status(fetch=False))
                except Exception:  # noqa: BLE001
                    return 0
                if строка:
                    print(строка)
                return 0
            итог = memorysync.status(fetch=args.fetch)
            if args.as_json:
                print(json.dumps(итог, ensure_ascii=False, sort_keys=True))
            else:
                print(memorysync.format_human(итог))
            return 0 if итог["ok"] else 1
        else:
            return 2
    except RecallError as error:
        # Диагностика в stderr: stdout это блок и ничего кроме блока, иначе
        # вызывающий подмешает наш текст в контекст модели.
        print(f"memory {args.command}: {error}", file=sys.stderr)
        return 3
    except (MemoryctlError, OSError, UnicodeError, ValueError) as error:
        print(f"memory {args.command}: {type(error).__name__}: {error}", file=sys.stderr)
        return 4
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
