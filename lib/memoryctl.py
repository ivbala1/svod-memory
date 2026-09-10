#!/usr/bin/env python3
"""Утилиты читателей (Свод-0, шаг 3): шапка, файлы области, ссылки,
ревизия, карта репозиториев, каталог состояния.

Транзакционного слоя здесь больше нет: git и есть транзакционный слой
(писатель в memoryremember, синхронизация и статус в memorysync).
"""

from __future__ import annotations

import contextlib

from dataclasses import dataclass
import datetime as dt
import os
from pathlib import Path
import stat

import configpaths
import svodgit
from memoryverify import (  # noqa: F401 - имена, которые читатели берут через memoryctl
    MARKDOWN_LINK_RE, SLUG_RE, body_without_frontmatter, parse_frontmatter,
    strip_code, _slug_mentioned,
)

AREAS = ("memory",)


class MemoryctlError(Exception):
    pass


class ValidationError(MemoryctlError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_today() -> dt.date:
    return dt.datetime.now(dt.timezone.utc).date()


def default_root() -> Path:
    return svodgit.default_root()


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise MemoryctlError(f"state directory is a symlink: {path}")
    os.chmod(path, 0o700)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    ensure_private_dir(path.parent)
    svodgit.replace_file(path, data)
    os.chmod(path, mode)


# ---------------------------------------------------------------------------
# Файлы области памяти

def require_real_directory(path: Path, label: str, *, required: bool = True) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        if required:
            raise ValidationError([f"{label} is missing: {path}"])
        return False
    if stat.S_ISLNK(mode):
        raise ValidationError([f"{label} is a symlink: {path}"])
    if not stat.S_ISDIR(mode):
        raise ValidationError([f"{label} is not a directory: {path}"])
    return True


def iter_data_files(root: Path):
    for area in AREAS:
        base = root / area
        require_real_directory(base, f"data area {area}")
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            current = Path(dirpath)
            safe_dirs = []
            for dirname in sorted(dirnames):
                candidate = current / dirname
                if candidate.is_symlink():
                    yield area, candidate, "symlink"
                else:
                    safe_dirs.append(dirname)
            dirnames[:] = safe_dirs
            for filename in sorted(filenames):
                candidate = current / filename
                if candidate.is_symlink():
                    yield area, candidate, "symlink"
                elif filename == ".gitkeep" or candidate.suffix == ".md":
                    yield area, candidate, "file"
                else:
                    yield area, candidate, "unexpected"


def data_snapshot(root: Path) -> dict[str, bytes]:
    snapshot: dict[str, bytes] = {}
    for _area, path, kind in iter_data_files(root):
        if kind == "file" and path.name != ".gitkeep":
            snapshot[path.relative_to(root).as_posix()] = path.read_bytes()
    return snapshot


def collect_memory_files(root: Path) -> list[Path]:
    return [path for area, path, kind in iter_data_files(root)
            if area == "memory" and kind != "symlink" and path.suffix == ".md"]


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
    for relative, data in sorted(data_snapshot(root).items()):
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


def drifted_records(snapshot: dict, own_client: str | None = None,
                    topics_raw: bytes | None = None) -> dict[str, list[str]]:
    import memoryverify
    raw = topics_raw if topics_raw is not None else configpaths.config_path("topics.json").read_bytes()
    return memoryverify.drifted_records(snapshot, memoryverify.load_topics(raw).drift, own_client)


# ---------------------------------------------------------------------------
# Карта репозиториев для читателей

@dataclass(frozen=True)
class RootInfo:
    logical_id: str
    worktree_root: Path

    @property
    def client_name(self) -> str | None:
        return self.logical_id[len("clients/"):] if self.logical_id.startswith("clients/") else None


@dataclass(frozen=True)
class RepoMap:
    """Область -> путь. available: что есть на диске."""
    identities: dict[str, RootInfo]
    available: frozenset[str]

    @property
    def available_roots(self) -> tuple[Path, ...]:
        return tuple(self.identities[lid].worktree_root for lid in self.identities
                     if lid in self.available)


def federation_context(data_root: Path, state_dir: Path | None = None, *,
                       topics_raw: bytes | None = None, **_ignored) -> RepoMap:
    mapping = svodgit.repo_map(data_root, topics_raw, on_disk_only=False)
    identities = {lid: RootInfo(lid, path) for lid, path in mapping.items()}
    # Читателю хватает области memory на диске: git нужен писателю и таймеру,
    # а выложенное дерево или фикстура репозиторием не являются.
    available = frozenset(lid for lid, path in mapping.items() if (path / "memory").is_dir())
    return RepoMap(identities=identities, available=available)


def federation_roots(source, *, state_dir: Path | None = None) -> list[Path]:
    context = source if isinstance(source, RepoMap) else federation_context(source, state_dir)
    return list(context.available_roots)


def revision_vector(root: Path, *, federation: RepoMap | None = None) -> dict[str, str]:
    context = federation if federation is not None else federation_context(root)
    return {lid: compute_revision(context.identities[lid].worktree_root) for lid in context.available}


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
