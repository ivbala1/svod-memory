#!/usr/bin/env python3
"""Доставка памяти любому агенту через оболочку: чтение и подача записи.

Читающая часть (recall, explain) не пишет ничего: это проверено тестом на
корне без права записи. Подача (remember) пишет в память и публикует.

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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import configpaths
import memorycontext as mc
import memoryctl
import memoryverify
import svodgit
from memoryctl import MemoryctlError, compute_revision

PERSONAL = mc.PERSONAL_SCOPE

# Область, выданная командой, а не защёлкой сессии. Отдельный ярлык нужен,
# чтобы в стенограмме было видно, что проект выбран вызовом, и его нельзя
# спутать с закреплением, которое переживает всю сессию.
SHELL_SOURCE = "shell"


class RecallError(Exception):
    """Отказ, который надо показать вызывающему, а не проглотить."""


def _load_scope_roots() -> dict[str, tuple[Path, ...]]:
    """Корни областей из общего конфига, с проверкой каждой предпосылки.

    Конфиг разграничения без проверки это ровно тот дефект, который в этом
    репозитории уже ловили четырежды: удобный признак вместо настоящего
    свойства. Молча пустой или дублирующийся корень тихо снял бы потолок.
    """
    path = configpaths.config_path("topics.json")
    # Разбор, сделанный memorycontext при импорте: scopeRoots и TOPICS одного
    # вызова принадлежат одному поколению конфига (Q7).
    section = mc.TOPICS_CONFIG.get("scopeRoots")
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


def resolve_scope(requested: str | None, потолок: str | None) -> str | None:
    """Итоговая область. None значит только глобальный контракт.

    Слишком широкая выдача хуже слишком узкой: узкая портит ответ и легко
    повторяется, а широкая оставляет чужие данные в стенограмме и может
    повлиять на внешнее действие. Поэтому при сомнении сужаем.
    """
    if requested is None:
        return потолок
    # Писатель называет область как `clients/<имя>`, и агент повторяет ту же
    # запись у чтения. Принимаем обе формы, а отказ перечисляет допустимые.
    if requested.startswith("clients/"):
        requested = requested.split("/", 1)[1]
    if requested not in (set(mc.TOPICS) | {PERSONAL}):
        raise RecallError(f"неизвестная область {requested!r}; допустимы "
                          + ", ".join(sorted({PERSONAL} | set(mc.TOPICS)))
                          + " (клиентскую можно писать и как clients/<имя>)")
    # Личный потолок разрешает любую известную область, клиентский только
    # себя, каталог вне корней (потолок None) ничего: граница цели 2.
    if потолок != PERSONAL and requested != потолок:
        где = "вне настроенных корней" if потолок is None else f"с потолком {потолок}"
        raise RecallError(
            f"область {requested!r} шире, чем разрешает рабочий каталог ({где}). "
            "Перейди в каталог этой области или запусти команду оттуда."
        )
    return requested


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
        # Каталог без потолка получает минимум (пункт 4 докстроки модуля):
        # только глобальный контракт, ни инбокса, ни записей, ни сводок. Он и
        # так едет в каждую сессию любой области, чужих данных в нём нет.
        return mc._contract_only_context(
            index, hot_contract, mc.RouteDecision(None, f"{SHELL_SOURCE}-global"),
            revision, include_hot=True,
            note="Рабочий каталог не лежит ни в одном настроенном корне памяти, поэтому "
                 "записи и сводки не отдаются. Нужна конкретная область, запусти команду "
                 "из её каталога.")
    if scope == PERSONAL:
        if personal_root is None:
            decision = mc.RouteDecision(None, "personal")
            return mc._contract_only_context(
                index, hot_contract, decision, revision, include_hot=True)
        decision, ranked = mc._personal_route(personal_root, prompt, entries)
        return mc._nonproject_context(
            personal_root, entries, hot_contract, decision, prompt, revision,
            include_hot=True, ranked=ranked,
        )
    spec = mc.TOPICS[scope]
    # Не `pinned:`, потому что ничего не закрепляется. Слово «pinned» в
    # стенограмме означало бы защёлку сессии, которой у команды нет.
    decision = mc.RouteDecision(scope, SHELL_SOURCE)
    # Ревизия темы это вершина репозитория её владельца, ровно как у хука:
    # иначе команда и хук печатали бы разные хеши одного материала.
    return mc._topic_context(
        root,
        spec,
        decision,
        prompt,
        mc.topic_key(root, spec, revision),
        hot_contract,
        full_context=True,
        include_hot=True,
    )


def banner_for(scope: str | None, index: Path | None = None) -> str:
    """Шапка обязана говорить правду про ЭТОТ вызов.

    Прежняя редакция писала «Сессия закреплена», хотя команда не создаёт
    никакой защёлки и следующий вызов волен выбрать другую область. Это была
    настоящая дивергенция с хуком, спрятанная за формулировкой.

    Личная шапка называет индекс (`index`): путь к нему у хука даёт
    SessionStart, а команду зовут как раз без хука (Codex без одобрения,
    редактор), и пути memory/<имя> в теле иначе не от чего считать. В шапке,
    а не в теле: тело побайтово равно хуку.
    """
    if scope is None:
        return ("Область этого вызова не определена: каталог вне настроенных корней, "
                "отдан только глобальный контракт. Сессию не закрепляет.")
    if scope == PERSONAL:
        return ("Область этого вызова: личная, отдаются глобальные правила, инбокс "
                "и подходящие записи. Сессию не закрепляет."
                + (f" Источник: {index}." if index is not None else ""))
    return f"Область этого вызова: {mc.TOPICS[scope].label}. Сессию не закрепляет."


def recall(
    prompt: str,
    *,
    scope: str | None,
    cwd: str,
    root: Path | None = None,
) -> str:
    """Блок, который отдал бы маршрутизатор. Ничего не пишет."""
    root = (root or mc.default_root()).expanduser()
    roots = _load_scope_roots()
    потолок = ceiling_for(cwd, roots)
    итог = resolve_scope(scope, потолок)

    # Разделяемые замки на все корни федерации сразу: сводка темы с владельцем
    # читается из клиентского корня. Писатель и синхронизация меняют корень
    # только под исключительным замком, поэтому под взятыми замками дерево не
    # поймать в середине транзакции и одного чтения достаточно.
    with memoryctl.reader_locks(mc.reader_federation(root).values()) as все_взяты:
        if not все_взяты:
            # Писатель держит корень дольше срока ожидания: ревизии по HEAD
            # не видят его незакоммиченную запись, так что читать сейчас
            # значит рисковать половиной сводки. Хук читает всегда (его
            # контракт), команде честнее отказать словами.
            raise RecallError("корпус занят писателем дольше срока ожидания, повтори запрос")
        body, _ = build_body(root, итог, prompt)

    _, personal_root = mc.index_roots(root)
    banner = banner_for(итог, personal_root / "memory" / "MEMORY.md" if personal_root else None)
    return mc.with_banner(banner, body, итог)


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
    if not memoryverify.SLUG_RE.fullmatch(имя):
        raise RecallError(f"недопустимый slug {slug!r}")
    файл_имя = f"{имя}.md"
    найденный_корень: Path | None = None
    найденный_файл: Path | None = None
    в_архиве = False
    for корень in mc.reader_federation(root).values():
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
    поля, _ = memoryverify.parse_frontmatter(текст)
    сегодня = today if today is not None else mc.today_utc()
    просрочена = memoryverify.date_passed(поля, "valid_until", сегодня)
    обзор_просрочен = memoryverify.date_passed(поля, "review_after", сегодня)
    преемник = mc.resolve_final_successor(найденный_корень, имя) if в_архиве else None
    if преемник == имя:
        преемник = None
    в_списке = (not в_архиве and найденный_корень == personal_root and файл_имя in {
        e.slug for e in mc.folded_entries(найденный_корень, mc.second_place_whitelist())})
    доставка = not в_архиве and (проиндексирована or в_списке) and просрочена is None

    # Запись без строки индекса может быть свёрнута в сводку темы, и после
    # переезда сводок каноническая формулировка живёт у владельца. Называть
    # такую запись «сиротой» значит путать штатное замещение с потерей (R10:
    # причины невидимости различимы). Чтение мягкое: explain обязан отвечать
    # и на неполном корпусе, поэтому отсутствующая сводка или владелец вне
    # доступных здесь не отказ, а «упоминания не нашлось»; битый конфиг
    # отсекает main раньше.
    свёрнута_в = None
    if not проиндексирована and not в_архиве:
        # Темы из разбора процесса (Q7), деревья владельцев из контекста
        # читателя (F8): зарегистрированное рабочее дерево обслуживает и
        # explain. Старую копию при недоступном владельце не читаем (N10).
        контекст = mc.reader_federation(root)
        for spec in sorted(mc.TOPICS.values(), key=lambda spec: spec.filename):
            if найденный_корень == personal_root and spec.owner:
                if spec.owner not in контекст:
                    continue
                путь_сводки = контекст[spec.owner] / "memory" / "topics" / spec.filename
            else:
                путь_сводки = найденный_корень / "memory" / "topics" / spec.filename
            try:
                текст_сводки = путь_сводки.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            # _slug_mentioned сам перебирает имя с .md и без.
            if memoryverify._slug_mentioned(файл_имя, текст_сводки):
                свёрнута_в = spec.filename
                break

    if в_архиве and преемник:
        причина = f"замещена: {преемник}"
    elif в_архиве:
        причина = "в архиве без преемника"
    elif просрочена:
        причина = f"просрочена: {просрочена}"
    elif в_списке:
        причина = ("свёрнута, в белом списке второго места: приходит только вторым "
                   f"местом с пометкой «{mc.FOLDED_MARK}»")
    elif not проиндексирована and свёрнута_в:
        причина = f"свёрнута в сводку {свёрнута_в}: канон формулировки в сводке темы"
    elif (not проиндексирована and найденный_корень == personal_root
          and поля.get("listed") == "false"):
        причина = "свёрнута: вне индекса, находится поиском по корпусу"
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


def search_text(prompt: str, *, root: Path | None = None, limit: int = 10,
                cwd: str | os.PathLike[str], scope: str | None = None) -> str:
    """Второй проход: полнотекстовый поиск по всем записям области, включая
    свёрнутые записи и архив.

    Ранжирует тот же BM25, что даёт второе место в выдаче. Замер 10.09.2026 на
    независимых вопросах: нужный файл попадает в первую пятёрку в 65 случаях из
    75, а греп по основам кладёт его туда в 38. Граница та же, что у `recall`:
    область каталога или `--scope` не шире его потолка. У заказчика это
    единственный путь к записям помимо сводки: её разделы выбираются по
    терминам и режутся бюджетом (случай 24.09.2026).
    """
    root = (root or mc.default_root()).expanduser().resolve()
    итог = resolve_scope(scope, ceiling_for(cwd, _load_scope_roots()))
    if итог is None:
        raise RecallError("поиск по корпусу отдаётся только из каталога личной или клиентской области")
    владелец = "personal" if итог == PERSONAL else mc.TOPICS[итог].owner
    корень = mc.reader_federation(root).get(владелец)
    if корень is None or not (корень / "memory" / "MEMORY.md").is_file():
        raise RecallError(f"{root}: нет репозитория области {итог} с memory/MEMORY.md")
    шапка = f"[Поиск по памяти: {итог}]"
    документы, состояние = mc.corpus_documents(корень)
    заголовки = {имя: title for имя, title, _ in документы}
    ranked = mc.bm25_over(корень, prompt, документы)[:max(1, limit)]
    if not ranked:
        return f"{шапка}\nСовпадений нет: попробуй другие слова или формы."
    части = [шапка,
             "Это указатели, а не выдача: файл надо прочитать. Находка вне индекса "
             "бывает устаревшей, проверь дату и пометку о замещении."]
    for имя, счёт in ranked:
        части.append(f"- {состояние.get(имя, 'запись')}: {корень / 'memory' / имя}: "
                     f"{заголовки.get(имя) or 'без заголовка'}")
    return "\n".join(части)


def _personal_root(root: Path | None, cwd: str | os.PathLike[str], отказ: str) -> Path:
    """Личный репозиторий для команд, которые отдаются только из личного
    каталога; из любого другого отказ словами `отказ`."""
    root = (root or mc.default_root()).expanduser().resolve()
    if ceiling_for(cwd, _load_scope_roots()) != PERSONAL:
        raise RecallError(отказ)
    _, personal = mc.index_roots(root)
    if personal is None:
        raise RecallError(f"{root}: нет личного репозитория personal/memory")
    return personal


def score_breakdown(prompt: str, entry, *, root: Path, today=None) -> dict:
    """Разбивка счёта первого места по словам: совпавшие слова даёт тот же
    `memorycontext.entry_hits`, что считает `_entry_score`, бонусы названы
    словами, а счёт берётся у настоящего отбора."""
    prompt_tokens = mc.score_words(prompt)
    по_заголовку, по_индексу = mc.entry_hits(prompt_tokens, entry)
    бонусы: list[str] = []
    if prompt_tokens and mc.title_in_prompt(entry.label, prompt):
        бонусы.append("заголовок целиком в вопросе +6")
    if len(по_заголовку) >= 2:
        бонусы.append("два и более слова заголовка +2")
    счёт = mc._entry_score(prompt, entry)
    сегодня = today if today is not None else mc.today_utc()
    return {
        "slug": entry.slug,
        "title": entry.label,
        "score": счёт,
        "threshold": mc.SELECT_THRESHOLD,
        "title_hits": по_заголовку,
        "index_hits": по_индексу,
        "bonuses": бонусы,
        "expired": mc._entry_expired(root, entry, сегодня),
    }


def why_text(prompt: str, *, root: Path | None = None, limit: int = 5,
             cwd: str | os.PathLike[str]) -> str:
    """Почему по вопросу выдано то, что выдано: слова вопроса после
    стоп-списка, разбивка счёта верхних кандидатов первого места, счёт BM25
    второго места и сама выдача. Ответ на самый частый отказ писателя
    («крючок не находит запись»), которого раньше приходилось добиваться
    перебором. Граница та же, что у `search`: только личная область и
    только из личного каталога."""
    personal = _personal_root(
        root, cwd, "разбор отбора отдаётся только из личного каталога; память заказчика "
                   "спрашивают командой memory recall --scope <имя>")
    записи = mc.parse_index(mc.build_index(personal))
    сегодня = mc.today_utc()
    все_слова = [t for t in mc.TOKEN_RE.findall(prompt.casefold().replace("ё", "е"))]
    слова = mc._tokens(prompt, mc.SCORE_STOP_TOKENS)
    выброшены = [t for t in dict.fromkeys(все_слова) if t not in слова]
    # Формы с общим ключом совпадения считаются по первой; без этой строки
    # они не попадали ни в слова вопроса, ни в отброшенные.
    считаются = mc.score_words(prompt)
    первая = {mc._match_key(t): t for t in считаются}
    склеены = [f"{t} → {первая[mc._match_key(t)]}" for t in dict.fromkeys(слова)
               if t not in считаются]
    части = ["[Почему так выбрано]",
             f"слова вопроса для первого места: {', '.join(считаются) or 'нет'}"
             + (f"; склеены с первой формой: {', '.join(склеены)}" if склеены else "")
             + (f"; отброшены (стоп-слова и короткие): {', '.join(выброшены)}" if выброшены else ""),
             f"порог первого места {mc.SELECT_THRESHOLD}: слово заголовка 4, слово index 1, "
             "совпадение по первым пяти буквам, формы одного слова считаются раз"]
    разбор = sorted((score_breakdown(prompt, e, root=personal, today=сегодня) for e in записи),
                    key=lambda d: (-d["score"], d["slug"]))
    части.append("первое место, верхние кандидаты:")
    for d in [d for d in разбор if d["score"] > 0][:max(1, limit)]:
        куски = []
        if d["title_hits"]:
            куски.append("заголовок: " + ", ".join(d["title_hits"]) + f" (+{4 * len(d['title_hits'])})")
        if d["index_hits"]:
            куски.append("index: " + ", ".join(d["index_hits"]) + f" (+{len(d['index_hits'])})")
        куски.extend(d["bonuses"])
        метка = " просрочена" if d["expired"] else ""
        части.append(f"- {d['score']:>3} memory/{d['slug']}{метка}: " + "; ".join(куски))
    if not any(d["score"] > 0 for d in разбор):
        части.append("- ни одна запись не набрала ни балла")
    кандидаты = mc.second_place_candidates(personal, записи)
    свёрнутые = {e.slug for e in кандидаты if e.section == mc.FOLDED_SECTION}
    пометка = lambda slug: f" ({mc.FOLDED_MARK})" if slug in свёрнутые else ""
    bm25 = mc.bm25_ranking(personal, prompt, кандидаты)[:3]
    части.append(f"второе место, BM25 по телам (порог {mc.bm25_threshold(prompt):g}, разных "
                 f"ключей вопроса {mc.bm25_key_count(prompt)}: базовый {mc.BM25_THRESHOLD:g} "
                 f"до {mc.BM25_LENGTH_NORM} ключей, дальше растёт пропорционально"
                 + (f"; в кандидатах и свёрнутые из белого списка: {len(свёрнутые)}"
                    if свёрнутые else "") + "):")
    for slug, счёт in bm25:
        части.append(f"- {счёт:5.1f} memory/{slug}{пометка(slug)}")
    if not bm25:
        части.append("- совпадений нет")
    выдача = mc.select_index_entries(personal, prompt, записи, today=сегодня)
    части.append("выдача: " + (", ".join(f"memory/{e.slug}{пометка(e.slug)}" for e, _ in выдача)
                               or "пусто"))
    return "\n".join(части)


def index_text(*, root: Path | None = None, cwd: str | os.PathLike[str]) -> str:
    """Индекс личной памяти целиком, той же сборкой, что у роутера.

    Поверхность отбора курирует владелец, а посмотреть на неё было нечем:
    `explain` отвечает про одну запись, реплика роутера показывает только
    выбранные. Потолок тот же, что у `recall`: из каталога заказчика личный
    индекс не отдаём, иначе команда стала бы обходом границы областей.
    """
    return mc.build_index(_personal_root(
        root, cwd, "личный индекс отдаётся только из личного каталога; у сводки "
                   "заказчика индекса нет, её разделы и запас показывает memory status"))


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
        description="Память агента из оболочки: чтение, объяснение видимости, "
                    "подача записи и состояние репозиториев.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("recall", help="напечатать блок памяти по вопросу")
    r.add_argument("question", nargs="?", help="вопрос; '-' или пропуск читает stdin")
    r.add_argument("--scope", default=None, help="запрошенная область, не шире потолка каталога")
    r.add_argument("--root", type=Path, default=None, help="корень репозитория памяти")
    e = sub.add_parser("explain", help="объяснить видимость записи по slug")
    e.add_argument("slug", help="slug записи, с .md или без")
    e.add_argument("--root", type=Path, default=None, help="корень репозитория памяти")
    s_ = sub.add_parser("search", help="полнотекстовый поиск по записям области: личной или --scope <клиент>")
    s_.add_argument("question", nargs="?", help="вопрос; '-' или пропуск читает stdin")
    s_.add_argument("--scope", default=None, help="область поиска, не шире потолка каталога")
    s_.add_argument("--limit", type=int, default=10, help="сколько записей показать")
    s_.add_argument("--root", type=Path, default=None, help="корень репозитория памяти")
    w = sub.add_parser("why", help="почему по вопросу выбраны эти записи: разбивка счёта по словам")
    w.add_argument("question", nargs="?", help="вопрос; '-' или пропуск читает stdin")
    w.add_argument("--limit", type=int, default=5, help="сколько кандидатов первого места показать")
    w.add_argument("--root", type=Path, default=None, help="корень репозитория памяти")
    i = sub.add_parser("index", help="напечатать индекс личной памяти целиком")
    i.add_argument("--root", type=Path, default=None, help="корень репозитория памяти")
    m = sub.add_parser("remember", help="подать запись в память и опубликовать")
    m.add_argument("--scope", required=True,
                   help="ровно один репозиторий: global (контракт сессии), "
                        "personal (инбокс и личные записи) либо clients/<имя>")
    m.add_argument("--id", required=True, dest="proposal_id",
                   help="идентификатор идемпотентности: буквы, цифры, точка, дефис, "
                        "подчёркивание, до 80 символов; тот же id с тем же телом "
                        "безвреден, с другим телом отказ")
    m.add_argument("--file", default=None,
                   help="файл тела; без него читается stdin. Временный файл не "
                        "обязателен: подходит подстановка процесса, например "
                        "--file <(cat <<'EOF' ... EOF)")
    m.add_argument("--content-type", default="markdown",
                   choices=["markdown", "manifest"])
    m.add_argument("--source", default="shell", help="агент-источник")
    m.add_argument("--session", default="shell", help="идентификатор сессии")
    m.add_argument("--record", default=None,
                   help="имя записи: файл memory/<имя>.md. Личной и глобальной "
                        "записи этого достаточно")
    m.add_argument("--section", default=None,
                   help="раздел сводки темы, куда уезжает указатель клиентской записи")
    m.add_argument("--line", default=None,
                   help="строка-указатель со ссылкой на запись, только у клиентской "
                        "записи и вместе с --section")
    m.add_argument("--base", default=None,
                   help="хеш версии корпуса, на которой читалась запись; короткий "
                        "от семи знаков годится. Сверка не даст затереть более "
                        "позднюю правку, а запись разрешено переписать под тем же именем")
    m.add_argument("--dry-run", action="store_true", dest="dry_run",
                   help="только проверить и напечатать вердикт: без замка, без "
                        "коммита и без следа в каталоге состояния. Вердикт о "
                        "локальном снимке: занятость id, устаревание основы и "
                        "состояние сервера видны только настоящей подаче")
    m.add_argument("--json", action="store_true", dest="as_json")
    st = sub.add_parser("status", help="состояние репозиториев памяти из git и каталога ожидания")
    st.add_argument("--fetch", action="store_true", help="сначала fetch с сервера")
    st.add_argument("--nudge", action="store_true",
                    help="одна строка только если есть что разобрать; для хука старта "
                         "сессии: ежедневно поломки, заметки обслуживания раз в месяц")
    st.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _cwd_ceiling() -> tuple[str | None, str | None]:
    """Потолок каталога; при сбое None и имя ошибки, без имён областей."""
    try:
        return ceiling_for(os.getcwd(), _load_scope_roots()), None
    except Exception as exc:  # noqa: BLE001
        return None, type(exc).__name__


def _visible(итог: dict, потолок: str | None) -> dict:
    """Статус в пределах потолка, как у recall: личный каталог видит все
    области, клиентский свою и global, прочие только global; итог по видимым."""
    import memorysync
    if потолок != PERSONAL:
        spec = mc.TOPICS.get(потолок or "")
        видно = {"global"} | ({spec.owner} if spec and spec.owner else set())
        итог["repos"] = [r for r in итог["repos"] if r["scope"] in видно]
        итог["ok"] = all(memorysync._repo_ok(r) for r in итог["repos"])
    return итог


def _refused_early(args, reason: str, *, keep: bool = True) -> int:
    """Отказ до подачи (тело не прочитано): в failed/, как у проверок. Сухой
    прогон и подача в чужую область (keep=False) следа не оставляют."""
    import memoryremember
    target = None
    if keep and not args.dry_run:
        target = memoryremember.refuse_before_submit(
            scope=args.scope, candidate_id=args.proposal_id, source=args.source,
            session=args.session, content_type=args.content_type, reason=reason)
    result = {"state": "failed", "reason": reason}
    if args.dry_run:
        result["dry_run"] = True
    if target is not None:
        result["file"] = str(target)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return memoryremember.EXIT_FAILED


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if mc.TOPICS_ERROR:
        print(f"memory {args.command}: {mc.TOPICS_ERROR}", file=sys.stderr)
        return 7 if args.command == "remember" else 4
    try:
        if args.command in ("recall", "explain", "index", "search", "why"):
            if args.command == "index":
                text = index_text(root=args.root, cwd=os.getcwd())
            elif args.command == "why":
                text = why_text(_read_prompt(args.question), root=args.root,
                                limit=args.limit, cwd=os.getcwd())
            elif args.command == "search":
                text = search_text(_read_prompt(args.question), root=args.root,
                                   limit=args.limit, cwd=os.getcwd(), scope=args.scope)
            elif args.command == "recall":
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
            # Указатель записи это три флага, а не файл JSON: у подачи
            # остаётся одна команда и на одно понятие меньше.
            проекция = None
            if args.record is not None or args.section is not None or args.line is not None:
                проекция = {"record_slug": args.record}
                if args.section is not None:
                    проекция["index_section"] = args.section
                if args.line is not None:
                    проекция["index_line"] = args.line
            # Из каталога заказчика нельзя в чужую клиентскую область; global и
            # personal можно отовсюду, сбой потолка не отказ.
            свой = mc.TOPICS.get(_cwd_ceiling()[0] or "")
            if свой and свой.owner and args.scope.startswith("clients/") and args.scope != свой.owner:
                return _refused_early(args, f"область {args.scope} чужая для рабочего каталога ({свой.owner})", keep=False)
            try:
                тело = (Path(args.file).read_bytes() if args.file
                        else sys.stdin.buffer.read())
            except OSError as exc:
                return _refused_early(args, f"тело: {exc}")
            код, результат = memoryremember.run_remember(
                scope=args.scope, candidate_id=args.proposal_id, source=args.source,
                session=args.session, content_type=args.content_type, body=тело,
                projection=проекция, dry_run=args.dry_run, base=args.base)
            if args.as_json:
                print(json.dumps(результат, ensure_ascii=False, sort_keys=True))
            else:
                print(" ".join(f"{k}={v}" for k, v in sorted(результат.items())))
            return код
        elif args.command == "status":
            import memorysync
            if args.nudge:
                # Хук старта зовёт подсказку до закрепления, поэтому она видит
                # только области потолка каталога, как recall. Заметки месяца
                # (UTC) только при личном потолке и человеку; месяц это
                # локальный файл, удобство показа, а не состояние памяти.
                метка = svodgit.state_dir() / "nudge-month"
                месяц = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m")
                безлюдный = (mc.scheduled_run() or os.environ.get(
                    "CLAUDE_CODE_ENTRYPOINT", "").startswith("sdk"))
                потолок, беда = _cwd_ceiling()
                try:
                    месячная = (потолок == PERSONAL and not безлюдный
                                and метка.read_text(encoding="utf-8").strip() != месяц)
                except OSError:
                    месячная = True
                try:
                    итог = _visible(memorysync.status(fetch=False), потолок)
                    строка = memorysync.format_nudge(итог, monthly=месячная)
                except Exception:  # noqa: BLE001 - подсказка не ломает старт сессии
                    return 0
                if беда:
                    строка = "\n".join(filter(None, [
                        f"Память: область каталога не определена ({беда}), подсказка "
                        "ограничена global → memory status", строка]))
                # Заметки личной области не посчитаны: месяц не расходуется.
                if месячная and not any(r["scope"] == PERSONAL and r.get("problem")
                                        for r in итог["repos"]):
                    try:
                        svodgit.replace_file(метка, месяц.encode("utf-8"))
                    except OSError:
                        pass
                if строка:
                    print(строка)
                return 0
            потолок, беда = _cwd_ceiling()
            итог = _visible(memorysync.status(fetch=args.fetch), потолок)
            if args.as_json:
                print(json.dumps(итог, ensure_ascii=False, sort_keys=True))
            else:
                if потолок != PERSONAL:
                    print(f"Только области каталога ({беда or потолок or 'вне корней'}).")
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
        # У remember код 4 значит pending; посторонняя ошибка это 7 (error).
        return 7 if args.command == "remember" else 4
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
