#!/usr/bin/env python3
"""Git, замок, карта репозиториев и каталог ожидания (Свод-0, шаг 3).

Git и есть транзакционный слой: здесь только тонкие обёртки над ним и три
вещи, которых в git нет: замок репозитория (flock на `.git/svod.lock`),
карта «область -> путь» из `topics.json` и `MEMORY_REPO`, каталог
кандидатов в ожидании. Ни расписок, ни поколений, ни журналов.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

import configpaths


GIT_TIMEOUT_SEC = 60.0
NETWORK_TIMEOUT_SEC = 120.0
SCANNER_TIMEOUT_SEC = 180.0
# Push запускает pre-push, а тот сканирует тот же диапазон ещё раз своим
# бюджетом: предел push обязан вмещать и сеть, и сканер.
PUSH_TIMEOUT_SEC = NETWORK_TIMEOUT_SEC + SCANNER_TIMEOUT_SEC
EXCLUSIVE_WAIT_SEC = 60.0
SHARED_WAIT_SEC = 10.0
MARKER_NAME = ".svod.json"
LOCK_NAME = "svod.lock"
SCOPE_RE = re.compile(r"^(global|personal|clients/[a-z0-9_]{1,64})$")
# Корни индекса: глобальный (контракт, обязателен на каждой машине) и
# личный (инбокс и записи, по наличию). Клиентские корни доставляются сводкой.
INDEX_SCOPES = ("global", "personal")


class GitError(Exception):
    """Отказ git словами: что запускали и что он ответил."""


class Busy(Exception):
    """Замок не взят за отведённое время."""


# ---------------------------------------------------------------------------
# Подпроцессы

def git(root: Path, *args: str, timeout: float = GIT_TIMEOUT_SEC,
        check: bool = True, env: dict | None = None,
        data: bytes | None = None) -> subprocess.CompletedProcess:
    """Один вызов git в репозитории. check: ненулевой код это GitError."""
    окружение = dict(os.environ)
    # Ответы git разбираются по словам («couldn't find remote ref»), поэтому
    # локаль сообщений фиксирована; пути кандидата это буквальные имена, а
    # не шаблоны: `*`, `?`, `[` в имени записи не должны раскрываться.
    окружение["LC_ALL"] = "C"
    окружение["GIT_LITERAL_PATHSPECS"] = "1"
    if env:
        окружение.update(env)
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, env=окружение)
    except FileNotFoundError as exc:
        raise GitError("git не найден в PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {' '.join(args[:2])}: не ответил за {timeout:.0f} с") from exc
    if check and result.returncode != 0:
        raise GitError(
            f"git {' '.join(args)}: код {result.returncode}: "
            f"{result.stderr.decode('utf-8', 'replace').strip()}")
    return result


def out(root: Path, *args: str, **kw) -> str:
    return git(root, *args, **kw).stdout.decode("utf-8", "replace").strip()


def git_dir(root: Path) -> Path:
    path = Path(out(root, "rev-parse", "--git-dir"))
    return path if path.is_absolute() else (root / path).resolve()


def is_repo(root: Path) -> bool:
    try:
        return git(root, "rev-parse", "--git-dir", check=False).returncode == 0
    except GitError:
        return False


# ---------------------------------------------------------------------------
# Ссылки, деревья, объекты

def rev(root: Path, name: str) -> str | None:
    result = git(root, "rev-parse", "--verify", "--quiet", f"{name}^{{commit}}", check=False)
    if result.returncode != 0:
        return None
    return result.stdout.decode().strip()


def head(root: Path) -> str | None:
    return rev(root, "HEAD")


def branch(root: Path) -> str | None:
    """Имя ветки или None на отсоединённой вершине."""
    result = git(root, "symbolic-ref", "--quiet", "--short", "HEAD", check=False)
    if result.returncode != 0:
        return None
    return result.stdout.decode().strip()


def rebase_in_progress(root: Path) -> bool:
    directory = git_dir(root)
    return (directory / "rebase-merge").exists() or (directory / "rebase-apply").exists()


ENGINE_REBASE_MARKER = "svod-rebase"


def engine_rebase_marker(root: Path) -> Path:
    """Файл-метка собственного rebase движка: ставится перед `git rebase`,
    снимается после. Только помеченный rebase движок вправе отменить; любой
    другой (ручной, на ветке или на отсоединённой вершине, `git am`) это
    работа человека."""
    return git_dir(root) / ENGINE_REBASE_MARKER


def heal(root: Path) -> list[str]:
    """Лечение после падения: rebase --abort, если движок упал посреди
    своего помеченного rebase, и checkout main с отсоединённой вершины.
    Ветка main при этом не двигается. Чужой rebase не трогается: его
    доводит человек, вызывающие говорят об этом словами."""
    done = []
    marker = engine_rebase_marker(root)
    if rebase_in_progress(root):
        if not marker.exists():
            return done
        git(root, "rebase", "--abort", check=False)
        if rebase_in_progress(root):
            # Отмена не удалась: метка остаётся, чтобы следующий проход
            # не принял rebase движка за ручной.
            return done
        done.append("rebase --abort")
    if marker.exists():
        marker.unlink()
    if branch(root) is None and rev(root, "refs/heads/main") is not None:
        git(root, "checkout", "--quiet", "main")
        done.append("checkout main")
    return done


def dirty_paths(root: Path) -> set[str]:
    """Пути, отличающиеся от HEAD в индексе или рабочем каталоге, включая
    неотслеживаемые (кроме игнорируемых)."""
    raw = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
    paths = set()
    parts = raw.split(b"\0")
    i = 0
    while i < len(parts):
        item = parts[i]
        if not item:
            i += 1
            continue
        status, path = item[:2], item[3:].decode("utf-8", "replace")
        paths.add(path)
        if status[0:1] in (b"R", b"C"):
            i += 1  # исходный путь переименования следует отдельной записью
        i += 1
    return paths


def blob(root: Path, commit: str, path: str) -> str | None:
    """Хеш blob пути в дереве коммита; None, если пути нет."""
    result = git(root, "rev-parse", "--verify", "--quiet", f"{commit}:{path}", check=False)
    if result.returncode != 0:
        return None
    return result.stdout.decode().strip()


def read_blob(root: Path, commit: str, path: str) -> bytes | None:
    result = git(root, "cat-file", "blob", f"{commit}:{path}", check=False)
    if result.returncode != 0:
        return None
    return result.stdout


def read_tree(root: Path, commit: str | None, prefix: str = "memory/") -> dict[str, bytes]:
    """Дерево области памяти коммита как отображение «путь -> байты».
    Пустое, если коммита нет (репозиторий без истории)."""
    if commit is None:
        return {}
    listing = git(root, "ls-tree", "-r", "-z", commit, "--", prefix.rstrip("/"), check=False)
    if listing.returncode != 0:
        return {}
    entries: list[tuple[str, str]] = []
    for item in listing.stdout.split(b"\0"):
        if not item:
            continue
        meta, path = item.split(b"\t", 1)
        mode, kind, oid = meta.decode().split(" ")
        if kind != "blob":
            continue
        entries.append((oid, path.decode("utf-8", "replace")))
    if not entries:
        return {}
    batch = "\n".join(oid for oid, _ in entries).encode() + b"\n"
    raw = git(root, "cat-file", "--batch", data=batch).stdout
    tree: dict[str, bytes] = {}
    cursor = 0
    for oid, path in entries:
        newline = raw.index(b"\n", cursor)
        header = raw[cursor:newline].decode()
        size = int(header.split(" ")[2])
        start = newline + 1
        tree[path] = raw[start:start + size]
        cursor = start + size + 1
    return tree


def tree_of(root: Path, commit: str) -> str:
    return out(root, "rev-parse", f"{commit}^{{tree}}")


def write_tree(root: Path) -> str:
    return out(root, "write-tree")


def commit_tree(root: Path, tree: str, parent: str | None, message: str) -> str:
    args = ["commit-tree", tree]
    if parent:
        args += ["-p", parent]
    args += ["-m", message]
    return out(root, *args)


def update_ref(root: Path, ref: str, new: str, old: str | None) -> None:
    """Перевод ссылки со сверкой старого значения; пустое старое значение
    значит «ссылки ещё нет»."""
    git(root, "update-ref", ref, new, old or "")


def is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    return git(root, "merge-base", "--is-ancestor", ancestor, descendant, check=False).returncode == 0


def rev_list(root: Path, spec: str) -> list[str]:
    text = out(root, "rev-list", spec)
    return text.split() if text else []


def commit_subjects(root: Path, spec: str) -> list[str]:
    text = out(root, "log", "--format=%s", spec)
    return text.splitlines() if text else []


def subject_exists(root: Path, subject: str, ref: str = "HEAD") -> bool:
    if rev(root, ref) is None:
        return False
    result = git(root, "log", "--fixed-strings", "--grep", subject, "--format=%s", ref, check=False)
    return any(line.strip() == subject for line in result.stdout.decode("utf-8", "replace").splitlines())


# ---------------------------------------------------------------------------
# Сеть

def has_remote(root: Path) -> bool:
    return git(root, "remote", "get-url", "origin", check=False).returncode == 0


def fetch(root: Path) -> tuple[bool, str]:
    """(удалось, слова). Сети нет: (False, причина)."""
    if not has_remote(root):
        return False, "у репозитория нет origin"
    result = git(root, "fetch", "--quiet", "origin", "+refs/heads/main:refs/remotes/origin/main",
                 timeout=NETWORK_TIMEOUT_SEC, check=False)
    if result.returncode != 0:
        text = result.stderr.decode("utf-8", "replace").strip()
        if "couldn't find remote ref" in text:
            # Сервер есть, ветки на нём ещё нет: репозиторий новый.
            git(root, "update-ref", "-d", "refs/remotes/origin/main", check=False)
            return True, ""
        return False, f"fetch не удался: {text.splitlines()[-1] if text else 'без текста'}"
    return True, ""


def remote_head(root: Path) -> str | None:
    return rev(root, "refs/remotes/origin/main")


def push(root: Path, commit: str, expect: str | None) -> tuple[bool, str]:
    """Push ровно этого коммита в main с условием, что вершина сервера всё
    ещё та, что принёс fetch (lease). (принят, слова)."""
    lease = f"--force-with-lease=refs/heads/main:{expect or ''}"
    result = git(root, "push", "--quiet", lease, "origin", f"{commit}:refs/heads/main",
                 timeout=PUSH_TIMEOUT_SEC, check=False)
    if result.returncode == 0:
        return True, ""
    text = result.stderr.decode("utf-8", "replace").strip()
    last = text.splitlines()[-1] if text else "без текста"
    return False, f"сервер не принял push: {last}"


# ---------------------------------------------------------------------------
# Сканер секретов по диапазону коммитов

def find_gitleaks() -> str | None:
    executable = shutil.which("gitleaks")
    if executable:
        return executable
    local = Path.home() / ".local" / "bin" / "gitleaks"
    return str(local) if local.is_file() and os.access(local, os.X_OK) else None


def scan_range(root: Path, old: str | None, new: str, scanner: str | None = None) -> str | None:
    """Секреты покоммитно в диапазоне old..new; без old вся история new за
    вычетом того, что сервер уже несёт на любой своей ветке (тег или новая
    ветка на уже отправленных коммитах ничего нового не отправляют).
    None это чисто, иначе причина словами. Без сканера отправки нет."""
    executable = scanner or find_gitleaks()
    if not executable:
        return "сканер секретов gitleaks не найден; без него отправки нет"
    if old:
        log_opts = f"{old}..{new}"
    else:
        fresh = git(root, "rev-list", new, "--not", "--remotes=origin", check=False).stdout.strip()
        if not fresh:
            return None
        log_opts = f"{new} --not --remotes=origin"
    command = [executable, "git", "--no-banner", "--redact", "--exit-code", "42",
               "--log-opts", log_opts, str(root)]
    ignore = root / ".gitleaksignore"
    if ignore.is_file():
        command += ["--gitleaks-ignore-path", str(ignore)]
    try:
        result = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=SCANNER_TIMEOUT_SEC)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"сканер секретов не отработал ({exc}); отправки нет"
    if result.returncode == 42:
        return f"сканер секретов нашёл похожее на секрет в коммитах {log_opts}; отправки нет"
    if result.returncode != 0:
        return f"сканер секретов завершился с кодом {result.returncode} на {log_opts}; отправки нет"
    return None


# ---------------------------------------------------------------------------
# Замок

@contextlib.contextmanager
def lock(root: Path, *, exclusive: bool, wait: float | None = None):
    """flock на .git/svod.lock. Эксклюзивный ждёт до 60 секунд, дальше Busy;
    разделяемый ждёт до 10 секунд и отдаёт управление даже без замка
    (читатель читает всегда). Отдаёт True, если замок взят; False, если
    замок есть, но не взят (срок вышел, файл не открывается); None, если
    замка у корня нет (выложенное дерево, фикстура без git)."""
    limit = wait if wait is not None else (EXCLUSIVE_WAIT_SEC if exclusive else SHARED_WAIT_SEC)
    path = None
    try:
        # Обычный клон: каталог .git известен без подпроцесса; читатель берёт
        # замок на каждый корень федерации на каждом запросе.
        path = ((root / ".git") if (root / ".git").is_dir() else git_dir(root)) / LOCK_NAME
    except GitError:
        if exclusive:
            raise
    if path is None:
        # Читатель без git-репозитория (выложенное дерево, фикстура) читает без замка.
        yield None
        return
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        # Неписаный клон: замка у читателя здесь нет (None, как без git),
        # писателю отказ словами. False остаётся за занятым замком.
        if exclusive:
            raise GitError(f"{root}: замок {path.name} не открывается: {exc}") from exc
        yield None
        return
    taken = False
    try:
        deadline = time.monotonic() + limit
        flag = (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB
        while True:
            try:
                fcntl.flock(fd, flag)
                taken = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    if exclusive:
                        raise Busy(f"{root}: репозиторий занят другим писателем дольше "
                                   f"{limit:.0f} с")
                    break
                time.sleep(0.2)
        yield taken
    finally:
        if taken:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# ---------------------------------------------------------------------------
# Карта репозиториев и метка области

def default_root() -> Path:
    configured = os.environ.get("MEMORY_REPO")
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.home() / ".agent-memory").resolve()


def federation_members(topics_raw: bytes | None = None) -> tuple[str, ...]:
    raw = topics_raw if topics_raw is not None else configpaths.config_path("topics.json").read_bytes()
    parsed = json.loads(raw.decode("utf-8"))
    members = parsed.get("federationMembers")
    if not isinstance(members, list) or not all(
            isinstance(m, str) and re.fullmatch(r"[a-z0-9_]{1,64}", m) for m in members):
        raise ValueError("topics.json: federationMembers обязан быть списком имён заказчиков")
    return tuple(members)


def repo_map(data_root: Path | None = None, topics_raw: bytes | None = None,
             *, on_disk_only: bool = True) -> dict[str, Path]:
    """Область -> путь репозитория. Каталог данных сам не репозиторий, в нём
    по клону на область: global/, personal/, clients/<имя>/. Репозиторий,
    которого нет на диске, для этой машины не существует."""
    data = (data_root or default_root()).resolve()
    result = {scope: data / scope for scope in INDEX_SCOPES}
    for name in federation_members(topics_raw):
        result[f"clients/{name}"] = data / "clients" / name
    if on_disk_only:
        result = {scope: path for scope, path in result.items() if (path / ".git").exists()}
    return result


def scope_root(scope: str, data_root: Path | None = None) -> Path:
    """Путь репозитория области; чужая или отсутствующая область это отказ словами."""
    if not SCOPE_RE.fullmatch(scope):
        raise ValueError(f"область {scope!r} не global, не personal и не clients/<имя>")
    mapping = repo_map(data_root, on_disk_only=False)
    if scope not in mapping:
        raise ValueError(f"область {scope} не входит в federationMembers topics.json")
    path = mapping[scope]
    if not (path / ".git").exists():
        raise ValueError(f"область {scope}: репозитория {path} нет на этой машине")
    return path


def read_marker(root: Path) -> str | None:
    """Область из .svod.json репозитория; None, если файла нет."""
    path = root / MARKER_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"{path}: не читается ({exc})") from exc
    scope = data.get("scope") if isinstance(data, dict) else None
    if not isinstance(scope, str) or not SCOPE_RE.fullmatch(scope):
        raise ValueError(f"{path}: поле scope обязано быть global, personal либо clients/<имя>")
    return scope


def require_marker(root: Path, scope: str) -> None:
    """Сверка .svod.json с ожидаемой областью: чужой репозиторий по пути
    отказывает словами."""
    found = read_marker(root)
    if found is None:
        raise ValueError(f"{root}: нет {MARKER_NAME}; репозиторий памяти области {scope} "
                         "помечается установщиком или коммитом перехода")
    if found != scope:
        raise ValueError(f"{root}: {MARKER_NAME} говорит {found}, ожидалась область {scope}; "
                         "по этому пути лежит чужой репозиторий")


def write_marker(root: Path, scope: str) -> None:
    (root / MARKER_NAME).write_text(json.dumps({"scope": scope}) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Каталог состояния: ожидание, отказы, кэш синхронизации

def state_dir() -> Path:
    configured = os.environ.get("MEMORYCTL_STATE_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    xdg = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return (xdg / "agent-memory").resolve()


def pending_dir(scope: str, base: Path | None = None) -> Path:
    return (base or state_dir()) / "pending" / scope


def failed_dir(scope: str, base: Path | None = None) -> Path:
    return (base or state_dir()) / "failed" / scope


def sync_cache_path(scope: str, base: Path | None = None) -> Path:
    return (base or state_dir()) / "sync" / f"{scope.replace('/', '-')}.json"


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_file(path: Path, data: bytes) -> bool:
    """Создание без замены: временный файл, fsync, link, fsync каталога.
    False, если файл уже есть (его содержимое не трогается)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(temp, path)
    except FileExistsError:
        os.unlink(temp)
        return False
    finally:
        if temp.exists():
            os.unlink(temp)
    fsync_dir(path.parent)
    return True


def replace_file(path: Path, data: bytes) -> None:
    """Атомарная замена: временный файл, fsync, rename."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, path)
    fsync_dir(path.parent)


def read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None
