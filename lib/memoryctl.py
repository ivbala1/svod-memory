#!/usr/bin/env python3
"""Утилиты читателей (Свод-0, шаг 3): шапка, файлы области, ссылки,
ревизия, карта репозиториев, каталог состояния.

Транзакционного слоя здесь больше нет: git и есть транзакционный слой
(писатель в memoryremember, синхронизация и статус в memorysync).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import os
from pathlib import Path

import configpaths
import svodgit
from memoryverify import MARKDOWN_LINK_RE, strip_code


class MemoryctlError(Exception):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise MemoryctlError(f"state directory is a symlink: {path}")
    os.chmod(path, 0o700)


def atomic_write(path: Path, data: bytes) -> None:
    """Права 0o600 даёт временный файл svodgit, os.replace переносит его."""
    ensure_private_dir(path.parent)
    svodgit.replace_file(path, data)


# ---------------------------------------------------------------------------
# Файлы области памяти

def collect_memory_files(root: Path) -> list[Path]:
    """Файлы .md области memory по алфавиту, без ссылок: os.walk без
    followlinks в каталоги-ссылки не заходит. Сама область ссылкой быть
    не может."""
    base = root / "memory"
    if base.is_symlink():
        raise MemoryctlError(f"data area memory is a symlink: {base}")
    if not base.is_dir():
        problem = "not a directory" if base.exists() else "missing"
        raise MemoryctlError(f"data area memory is {problem}: {base}")
    files = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames.sort()
        files.extend(path for path in (Path(dirpath) / name for name in sorted(filenames))
                     if path.suffix == ".md" and not path.is_symlink())
    return files


def compute_revision(root: Path) -> str:
    """Ревизия корпуса это хеш коммита HEAD; без git-репозитория (выложенное
    дерево, фикстура) отпечаток содержимого. Один запуск git на корень:
    вершина несуществующего репозитория это просто None."""
    try:
        head = svodgit.head(root)
    except svodgit.GitError:
        head = None
    if head:
        return head
    import hashlib
    digest = hashlib.sha256()
    snapshot = {path.relative_to(root).as_posix(): path.read_bytes() for path in collect_memory_files(root)}
    for relative, data in sorted(snapshot.items()):
        digest.update(relative.encode("utf-8") + b"\0" + str(len(data)).encode() + b"\0" + data + b"\0")
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Ссылки для doctor

WIKI_UNRESOLVED = ": unresolved wiki link: "
# Общая часть, а не собственный источник: провенансом для клиентской сводки
# служат личная и глобальная области, соседний заказчик им не служит.
SHARED_AREAS = ("personal", "global")


def _across_areas(root: Path, scope: str, warning: str) -> str:
    """Указатель в другую область федерации это провенанс, а не обрыв.

    Корпус разделён на области, и вики-ссылка разрешается только внутри
    своей (Свод-0, шаг 4). Но клиентская сводка законно называет личную
    запись-первоисточник, из которой её формулировка выросла: цель на месте,
    доставке ссылка ничего не стоит, читателю она говорит, откуда факт. Такие
    указатели надо называть, а не считать поломкой, иначе три десятка вечно
    красных предупреждений приучают не смотреть на проверку вовсе.

    ⚠️ Граница здесь настоящая: ссылка в область ДРУГОГО заказчика остаётся
    предупреждением. Это межклиентская утечка, ради запрета которой области и
    разделяли.
    """
    if WIKI_UNRESOLVED not in warning:
        return warning
    stem = warning.split(WIKI_UNRESOLVED, 1)[1].strip()
    federation = root.parent.parent if scope.startswith("clients/") else root.parent
    for area in SHARED_AREAS:
        if area == scope:
            continue
        if (federation / area / "memory" / f"{stem}.md").is_file():
            return warning.replace(WIKI_UNRESOLVED,
                                   f": wiki link to the {area} area: ")
    return warning


def validate_links(root: Path, files: list[Path], scope: str = "personal",
                   topics_raw: bytes | None = None) -> tuple[list[str], list[str]]:
    """Ссылки файлов области memory по правилу memoryverify.link_errors плюс
    предупреждение о ссылке за пределы корпуса, которой нет на этой машине."""
    import memoryverify
    snapshot = {}
    for path in files:
        try:
            snapshot[path.relative_to(root).as_posix()] = path.read_bytes()
        except OSError:
            continue
    raw = topics_raw if topics_raw is not None else configpaths.config_path("topics.json").read_bytes()
    errors, warnings = memoryverify.link_errors(snapshot, memoryverify.load_topics(raw), scope)
    warnings = [_across_areas(root, scope, w) for w in warnings]
    memory_root = (root / "memory").resolve()
    for path in files:
        relative = path.relative_to(root).as_posix()
        if relative.startswith("memory/archive/"):
            continue
        try:
            text = strip_code(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            continue
        for target in MARKDOWN_LINK_RE.findall(text):
            clean = target.split("#", 1)[0]
            resolved = (path.parent / clean).resolve(strict=False)
            try:
                resolved.relative_to(memory_root)
            except ValueError:
                if not resolved.exists():
                    warnings.append(
                        f"{relative}: external link target missing on this machine: {clean}")
    return errors, warnings


def countable_link_warnings(warnings: list[str]) -> set[str]:
    """Что считается долгом. Архив, цель вне корпуса и указатель в общую
    область федерации долгом не являются: первое история, второе про эту
    машину, третье провенанс."""
    return {w for w in warnings
            if not w.startswith("memory/archive/")
            and "external link target missing" not in w
            and "wiki link to the " not in w}


# ---------------------------------------------------------------------------
# Карта репозиториев для читателей

def federation_context(data_root: Path, *, topics_raw: bytes | None = None) -> dict[str, Path]:
    """Область -> корень, только области, доступные читателю на этой машине."""
    mapping = svodgit.repo_map(data_root, topics_raw, on_disk_only=False)
    # Читателю хватает области memory на диске: git нужен писателю и таймеру,
    # а выложенное дерево или фикстура репозиторием не являются. Каталог
    # области или memory ссылкой не отдаётся: так чужой клон выглядел бы своим.
    return {lid: path for lid, path in mapping.items() if (path / "memory").is_dir()
            and not path.is_symlink() and not (path / "memory").is_symlink()}


@contextlib.contextmanager
def reader_locks(roots):
    """Разделяемые замки на все корни чтения сразу: сводка темы читается из
    клиентского корня, и его писатель держит только свой замок. Отдаёт
    True, когда взяты все имеющиеся замки; False, если хоть один корень с
    замком читается без него (истёк срок ожидания, файл не открывается).
    Корень без git (выложенное дерево) замка не имеет и итог не портит."""
    with contextlib.ExitStack() as stack:
        taken = True
        for root in roots:
            taken = stack.enter_context(svodgit.lock(root, exclusive=False)) is not False and taken
        yield taken
