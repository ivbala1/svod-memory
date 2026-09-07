#!/usr/bin/env python3
"""Утилиты читателей (Свод-0, шаг 3): шапка, файлы области, ссылки,
ревизия, карта репозиториев, каталог состояния.

Транзакционного слоя здесь больше нет: git и есть транзакционный слой
(писатель в memoryremember, синхронизация и статус в memorysync).
"""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import os
from pathlib import Path
import stat

import configpaths
import svodgit
from memoryverify import (  # noqa: F401 - переэкспорт для прежних вызывающих
    CONFLICT_RE, DATE_FIELDS, DATE_RE, FENCE_RE, LINK_FIELDS, MARKDOWN_LINK_RE,
    SECRET_PATTERNS, SLUG_RE, WIKI_LINK_RE, DESCRIPTIVE_TOP_FIELDS,
    KNOWN_TOP_FIELDS, SCHEMA_FIELDS, find_gitleaks, index_field_errors, link_field_errors,
    parse_frontmatter, strip_code, supersedes_errors, _snapshot_supersedes,
    _slug_mentioned, _boundary_ok,
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


def default_state_dir() -> Path:
    return svodgit.state_dir()


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


def require_repo(root: Path) -> None:
    errors = []
    for area in AREAS:
        try:
            require_real_directory(root / area, f"data area {area}")
        except ValidationError as exc:
            errors.extend(exc.errors)
    if errors:
        raise ValidationError(errors)


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
    дерево, фикстура) отпечаток содержимого."""
    if svodgit.is_repo(root):
        head = svodgit.head(root)
        if head:
            return head
    import hashlib
    digest = hashlib.sha256()
    for relative, data in sorted(data_snapshot(root).items()):
        digest.update(relative.encode("utf-8") + b"\0" + str(len(data)).encode() + b"\0" + data + b"\0")
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Ссылки для doctor

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
    return {w for w in warnings
            if not w.startswith("memory/archive/") and "external link target missing" not in w}


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
    """Область -> путь. available: что есть на диске; missing_clients: чего нет."""
    identities: dict[str, RootInfo]
    available: frozenset[str]

    @property
    def available_roots(self) -> tuple[Path, ...]:
        return tuple(self.identities[lid].worktree_root for lid in self.identities
                     if lid in self.available)

    @property
    def missing_clients(self) -> tuple[str, ...]:
        return tuple(sorted(lid[len("clients/"):] for lid in self.identities
                            if lid not in self.available and lid.startswith("clients/")))


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


def federation_client_names(source, *, state_dir: Path | None = None) -> tuple[str, ...]:
    context = source if isinstance(source, RepoMap) else federation_context(source, state_dir)
    return tuple(context.identities[lid].client_name for lid in context.identities
                 if lid in context.available and context.identities[lid].client_name)


def revision_vector(root: Path, *, federation: RepoMap | None = None) -> dict[str, str]:
    context = federation if federation is not None else federation_context(root)
    return {lid: compute_revision(context.identities[lid].worktree_root) for lid in context.available}


def reader_lock(root: Path):
    """Разделяемый замок читателя: не дольше 10 секунд, читает и без него."""
    return svodgit.lock(root, exclusive=False)
