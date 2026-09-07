#!/usr/bin/env python3
"""Стенд находимости: регрессия отбора записей, живущая в репозитории.

Зачем. Главный страх владельца: факты забываются каждый день и незаметно.
Незаметно, потому что потерю находимости видно только случайно. Этот стенд
делает её видимой числом: по каждому контрольному вопросу известно, пришла
ли ОЖИДАЕМАЯ запись, и сравнение с зафиксированной исходной точкой идёт
ПОПАРНО, вопрос к вопросу. Совокупный балл не может скрыть, что один вопрос
сломался, а другой улучшился.

Устройство честности (разбор Codex 11.08.2026, усилено 07.09.2026, Свод-0
шаг 5):

- У вопроса ОДНА ожидаемая запись (`expect`); вопрос с двумя обязательными
  записями это два вопроса. «Нашлось» значит, что пришла именно она, а не
  любой файл с похожим словом.
- Признак ответа (`markers`) ищется в теле ожидаемой записи: доказательство,
  что запись после правок всё ещё несёт ответ. Шапка исключена, иначе
  крючок индекса засчитывал бы сам себя. Это не диагноз устаревания, а
  пропавшее доказательство.
- Запреты (`forbid`): записи, которые не приходят и начать приходить не
  должны (устаревшая, похожая, чужая).
- Состояния делятся на абсолютные и относительные. Абсолютные красные сами
  по себе, точка их не благословляет: ожидаемой записи нет в дереве, в ней
  нет признака, выдана запрещённая, выдача шире потолка роутера.
  Относительные сравниваются с точкой или с основой: потеря находимости,
  новое срабатывание отрицательного вопроса. Ухудшение ранга при
  сохранённой находимости это предупреждение.
- Вместе с точкой фиксируются версии всего, что участвует в измерении:
  ревизия личного корня, хеш вопросов, хеш исходного кода функций отбора.
  Разошлись версии, сравнение недействительно, а не «примерно то же».
- Самопроверка с двумя заведомыми поломками: пустой отбор обязан уронить
  каждый находимый вопрос, отбор «всё подряд» обязан зажечь каждый
  отрицательный вопрос, каждый запрет и потолок выдачи. Не поймано,
  неисправен сам стенд, и его зелёный цвет ничего не значит.
- Группы вопросов не смешиваются: tuned настраивались 10.08.2026 и являются
  регрессионными, heldout отложенные. Итог всегда сообщается раздельно.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import configpaths
import memorycontext as mc
import svodgit
from memoryctl import compute_revision, federation_context

QUESTIONS_PATH = configpaths.config_path("eval_questions.json")
# Исходная точка живёт рядом с вопросами, в каталоге конфигурации
# (решение владельца В-11 от 31.08.2026): код обязан переноситься и
# публиковаться отдельно от планки качества личного корпуса. История точки
# это git того же репозитория: команда baseline коммитит её сама.
BASELINE_PATH = configpaths.baseline_path()

# Файлы, определяющие измерение целиком: маршрутизатор, сам стенд, модуль
# раскладки и конфигурация тем. Конфигурация входит наравне с кодом: поле
# owner переключает физический источник сводки, и без него в отпечатке смена
# раскладки не делала сравнение недействительным, хотя меняла доставку.
MEASUREMENT_FILES = (
    Path(mc.__file__),
    Path(__file__),
    HERE / "topiclayout.py",
    HERE / "configpaths.py",
    configpaths.config_path("topics.json"),
)

SLUG_RE = re.compile(r"[a-z0-9_]{1,64}")


class EvalError(Exception):
    """Отказ стенда, который нельзя молча проглотить."""


def load_questions(path: Path = QUESTIONS_PATH) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not data.get("questions") or not data.get("negatives"):
        raise EvalError(f"{path}: пустые questions или negatives")
    ids = [q["id"] for q in data["questions"]] + [n["id"] for n in data["negatives"]]
    if len(ids) != len(set(ids)):
        raise EvalError(f"{path}: повторяющиеся идентификаторы вопросов")
    for q in data["questions"]:
        if q.get("group") not in ("tuned", "heldout"):
            raise EvalError(f"{path}: у вопроса {q['id']} нет группы tuned/heldout")
        expect = q.get("expect")
        if not isinstance(expect, str) or not SLUG_RE.fullmatch(expect):
            raise EvalError(f"{path}: у вопроса {q['id']} нет ожидаемой записи expect "
                            "(имя одной записи без .md)")
        if not q.get("markers"):
            raise EvalError(f"{path}: у вопроса {q['id']} нет признаков ответа markers")
        forbid = q.get("forbid", [])
        if (not isinstance(forbid, list)
                or any(not isinstance(f, str) or not SLUG_RE.fullmatch(f) for f in forbid)):
            raise EvalError(f"{path}: у вопроса {q['id']} forbid не список имён записей")
    return data


def measurement_fingerprint(files: tuple[Path, ...] | None = None,
                            substitute: dict | None = None) -> str:
    """Отпечаток измерителя: байты обоих модулей ЦЕЛИКОМ.

    Ручной список зависимостей дважды оказался неполным, и оба раза это нашло
    ревью, а не тесты: сперва STOP_TOKENS (слово в стоп-списке меняло результат
    при прежнем отпечатке), затем _section_kind (его подмена роняла 10/15 и
    9/15 в ноль, отпечаток не менялся). Каждая забытая зависимость это ложная
    совместимость: недействительное сравнение выглядит действительным. Байты
    файлов не забывают ничего.

    Цена: любая правка маршрутизатора пересдаёт исходную точку, даже не
    влияющая на измерение. Это безопасная сторона: пересдача стоит одну
    команду, вера недействительному сравнению стоит незамеченную потерю
    памяти. Параметр files нужен тестам, чтобы доказывать чувствительность на
    настоящем механизме, а не на подменённых объектах в памяти.
    """
    куски = []
    for путь in (files or MEASUREMENT_FILES):
        if substitute is not None and путь in substitute:
            куски.append(substitute[путь])
        else:
            куски.append(путь.read_bytes())
    return hashlib.sha256(b"".join(куски)).hexdigest()


def versions(root: Path) -> dict:
    """Версии измерения: ревизия личного корня (хеш коммита), вопросы,
    отпечаток измерителя."""
    return {
        "corpus_revision": compute_revision(root),
        "questions_sha256": hashlib.sha256(QUESTIONS_PATH.read_bytes()).hexdigest(),
        "measurement_files": [p.name for p in MEASUREMENT_FILES],
        "measurement_sha256": measurement_fingerprint(),
    }


def _evidence(path: Path, markers: list[str]) -> bool:
    """Признак ответа в ТЕЛЕ ожидаемой записи; шапка исключена."""
    текст = mc._without_frontmatter(path.read_text(encoding="utf-8", errors="replace"))
    return any(re.search(м, текст, re.IGNORECASE) for м in markers)


def stand(root: Path, questions: dict, *, today=None, ранжировать=None) -> dict:
    """Чистый прогон стенда по одному выложенному дереву: результат ПО
    КАЖДОМУ вопросу. Ничего живого не читает; проверки кандидата
    (memoryverify) зовут его по обеим сторонам."""
    if ранжировать is None:
        # Стенд меряет РЕАЛЬНЫЙ отбор доставки, включая фильтр valid_until
        # (R7), а не голое ранжирование: иначе зелёный стенд мог бы скрыть
        # запись, отфильтрованную настоящим читателем.
        ранжировать = lambda prompt, записи: mc.select_index_entries(
            root, prompt, записи, today=today)
    записи = mc.parse_index(mc.build_index(root))
    достижимые = tuple(e for e in записи if e.section in mc.INDEX_SECTIONS.values())

    по_вопросам = {}
    for q in questions["questions"]:
        ожидаемая = q["expect"]
        файл = root / "memory" / f"{ожидаемая}.md"
        нет = not файл.is_file()
        признак = False if нет else _evidence(файл, q["markers"])
        выдано = [Path(e.slug).stem for e, _ in ранжировать(q["text"], записи)]
        полный = sorted(((mc._entry_score(q["text"], e), e) for e in достижимые),
                        key=lambda p: (-p[0], p[1].index))
        ранг = next((i + 1 for i, (_, e) in enumerate(полный)
                     if Path(e.slug).stem == ожидаемая), None)
        по_вопросам[q["id"]] = {
            "group": q["group"],
            "found": ожидаемая in выдано,
            "rank": ранг,
            "delivered": len(выдано),
            "missing": нет,
            "evidence": признак,
            "forbidden": sorted(set(выдано) & set(q.get("forbid", []))),
        }

    негативы = {}
    for n in questions["negatives"]:
        негативы[n["id"]] = {"fired": bool(ранжировать(n["text"], записи))}
    return {"questions": по_вопросам, "negatives": негативы}


def absolute_failures(result: dict) -> list[dict]:
    """Абсолютные состояния прогона: красные сами по себе, безотносительно
    точки или основы."""
    out = []
    for qid, r in result["questions"].items():
        if r.get("missing"):
            out.append({"id": qid, "why": "эталон исчез: ожидаемой записи нет в дереве"})
        elif not r.get("evidence"):
            out.append({"id": qid, "why": "ожидаемая запись больше не содержит признака ответа"})
        if r.get("forbidden"):
            out.append({"id": qid, "why": "выдана запрещённая запись " + ", ".join(r["forbidden"])})
        if r.get("delivered", 0) > mc.DELIVERY_LIMIT:
            out.append({"id": qid, "why": f"выдача шире потолка роутера "
                                          f"({r['delivered']} при потолке {mc.DELIVERY_LIMIT})"})
    return out


def personal_root(root: Path) -> Path:
    контекст = federation_context(root)
    if "personal" not in контекст.available:
        raise EvalError(f"{root}: нет личного репозитория personal/memory, стенд меряет его индекс")
    return контекст.identities["personal"].worktree_root


def run(root: Path, *, ранжировать=None, questions: dict | None = None) -> dict:
    """Прогон стенда по личному корню живой федерации с версиями измерения."""
    личный = personal_root(root)
    итог = stand(личный, questions or load_questions(), ранжировать=ранжировать)
    return {"versions": versions(личный), **итог}


def summarize(result: dict) -> dict:
    """Итог по группам. Смешивать tuned и heldout в одну цифру нельзя."""
    итог = {}
    for группа in ("tuned", "heldout"):
        свои = [r for r in result["questions"].values() if r["group"] == группа]
        итог[группа] = {"found": sum(1 for r in свои if r["found"]), "of": len(свои)}
    итог["negatives_fired"] = sum(1 for r in result["negatives"].values() if r["fired"])
    итог["absolute"] = [f"{item['id']}: {item['why']}" for item in absolute_failures(result)]
    return итог


def replace_baseline(result: dict, path: Path | None = None) -> list[str]:
    """Пересдать исходную точку: атомарная запись на место, коммит одного
    этого файла и отправка в репозитории конфигурации. История точки это
    git этого репозитория; чужие правки в нём не трогаются. Возвращает
    слова о том, что сделано."""
    точка = Path(path) if path is not None else BASELINE_PATH
    байты = (json.dumps(result, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
    врем = точка.with_name(f".{точка.name}.new{os.getpid()}")
    врем.write_bytes(байты)
    os.replace(врем, точка)
    заметки = [f"исходная точка записана: {точка}"]
    корень = точка.parent
    if not svodgit.is_repo(корень):
        заметки.append("каталог конфигурации не репозиторий git: история точки не сохранена")
        return заметки
    svodgit.git(корень, "add", "--", точка.name)
    if svodgit.git(корень, "diff", "--cached", "--quiet", "--", точка.name, check=False).returncode == 0:
        заметки.append("точка не изменилась, коммита нет")
        return заметки
    svodgit.git(корень, "commit", "--quiet", "--only", "-m", "стенд: точка пересдана", "--", точка.name)
    заметки.append("закоммичено локально")
    if not svodgit.has_remote(корень):
        заметки.append("сервера нет, не отправлено")
        return заметки
    отправка = svodgit.git(корень, "push", "--quiet", check=False)
    if отправка.returncode == 0:
        заметки.append("опубликовано")
    else:
        слова = отправка.stderr.decode("utf-8", "replace").strip().splitlines()
        заметки.append("не отправлено: " + (слова[-1] if слова else f"код {отправка.returncode}"))
    return заметки


def compare(baseline: dict, current: dict) -> dict:
    """Попарное сравнение с исходной точкой, действительное только при тех же
    вопросах и том же измерителе."""
    if baseline["versions"]["questions_sha256"] != current["versions"]["questions_sha256"]:
        return {"ok": False, "invalid": "наборы вопросов различаются, сравнение недействительно"}
    if baseline["versions"]["measurement_sha256"] != current["versions"]["measurement_sha256"]:
        return {"ok": False,
                "invalid": "код измерения изменился, исходная точка снята другим прибором: "
                           "пересдай baseline осознанным решением"}
    return pairwise(baseline, current)


def pairwise(baseline: dict, current: dict) -> dict:
    """Попарное сравнение двух прогонов без сверки версий: ни один вопрос не
    может перейти из «нашёлся» в «не нашёлся», ни один отрицательный не
    может начать срабатывать; абсолютные состояния текущего прогона красные
    сами по себе; ухудшение ранга при сохранённой находимости
    предупреждение; улучшения сообщаются, зачёта не требуют."""
    регрессии, улучшения, ранг_хуже = [], [], []
    for qid, было in baseline["questions"].items():
        стало = current["questions"].get(qid)
        if стало is None:
            регрессии.append({"id": qid, "why": "вопрос исчез из прогона"})
            continue
        if было["found"] and not стало["found"]:
            регрессии.append({"id": qid, "why": "перестал находиться"})
        elif not было["found"] and стало["found"]:
            улучшения.append(qid)
        if (было["found"] and стало["found"] and было.get("rank") and стало.get("rank")
                and стало["rank"] > было["rank"]):
            ранг_хуже.append({"id": qid, "was": было["rank"], "now": стало["rank"]})
    новые_ложные = [nid for nid, было in baseline["negatives"].items()
                    if not было["fired"] and current["negatives"].get(nid, {}).get("fired")]
    абсолютные = absolute_failures(current)
    return {
        "ok": not регрессии and not новые_ложные and not абсолютные,
        "regressions": регрессии,
        "absolute": абсолютные,
        "new_false_positives": новые_ложные,
        "worse_rank": ранг_хуже,
        "improvements": улучшения,
    }


def _everything(prompt, записи):
    """Саботаж «всё подряд»: каждая достижимая запись в выдаче."""
    return tuple((e, 0) for e in записи if e.section in mc.INDEX_SECTIONS.values())


def selfcheck(root: Path) -> dict:
    """Две заведомые поломки, которые стенд ОБЯЗАН поймать.

    Урок недели: четырежды проверка была зелёной, меряя соседнее свойство.
    Поэтому у стенда встроенный саботаж. Пустой отбор: сравнение обязано
    увидеть регрессию каждого вопроса, находимого в исходном прогоне. Отбор
    «всё подряд»: обязаны сработать каждый отрицательный вопрос, каждый
    непустой запрет и потолок выдачи у каждого вопроса. Не увидело, стенд
    неисправен, его зелёному верить нельзя. Заодно проверяется, что чистое
    самосравнение чисто.
    """
    вопросы = load_questions()
    базис = run(root, questions=вопросы)
    чистое = compare(базис, базис)
    if not чистое["ok"]:
        return {"ok": False, "why": "самосравнение без изменений даёт регрессии", "detail": чистое}

    пусто = run(root, questions=вопросы, ранжировать=lambda prompt, записи: ())
    сравнение = compare(базис, пусто)
    находимых = sum(1 for r in базис["questions"].values() if r["found"])
    поймано = sum(1 for r in сравнение["regressions"] if r["why"] == "перестал находиться")
    if сравнение["ok"] or поймано != находимых:
        return {"ok": False,
                "why": f"пустой отбор пойман не целиком: {поймано} из {находимых} регрессий",
                "detail": сравнение}

    всё = run(root, questions=вопросы, ранжировать=_everything)
    сравнение_всё = compare(базис, всё)
    отрицательных = len(всё["negatives"])
    сработало = sum(1 for r in всё["negatives"].values() if r["fired"])
    запретов = sum(1 for q in вопросы["questions"] if q.get("forbid"))
    попаданий = sum(1 for r in сравнение_всё.get("absolute", [])
                    if r["why"].startswith("выдана запрещённая запись"))
    записей = len([e for e in mc.parse_index(mc.build_index(personal_root(root)))
                   if e.section in mc.INDEX_SECTIONS.values()])
    шире = sum(1 for r in сравнение_всё.get("absolute", [])
               if r["why"].startswith("выдача шире потолка"))
    ожидается_шире = len(всё["questions"]) if записей > mc.DELIVERY_LIMIT else 0
    if (сравнение_всё["ok"] or сработало != отрицательных
            or len(сравнение_всё["new_false_positives"]) != отрицательных
            or попаданий != запретов
            or шире != ожидается_шире):
        return {"ok": False,
                "why": (f"отбор «всё подряд» пойман не целиком: отрицательных {сработало} из "
                        f"{отрицательных}, запретов {попаданий} из {запретов}, выдача шире "
                        f"потолка у {шире} из {ожидается_шире}"),
                "detail": сравнение_всё}
    return {"ok": True, "caught": поймано, "of": находимых,
            "everything": {"negatives": сработало, "forbid_hits": попаданий, "over_limit": шире}}
