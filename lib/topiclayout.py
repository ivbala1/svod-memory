#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re


OWNER_RE = re.compile(r"^clients/[a-z0-9_]{1,64}$")


def _error(path: Path, topic: object, detail: str) -> ValueError:
    return ValueError(f"{path}: тема {topic!r}: {detail}")


def placement_from_config(raw, config_path: Path) -> dict[str, tuple[str, str | None]]:
    """Раскладка из уже разобранного конфига: PolicySnapshot читает байты
    topics.json ровно один раз, и второе чтение ради раскладки запрещено."""
    topics = raw.get("topics") if isinstance(raw, dict) else None
    if not isinstance(topics, dict) or not topics:
        raise _error(config_path, "<topics>", "раздел topics должен быть непустым объектом")

    placement: dict[str, tuple[str, str | None]] = {}
    for key, entry in topics.items():
        if not isinstance(key, str) or not key:
            raise _error(config_path, key, "ключ темы должен быть непустой строкой")
        if not isinstance(entry, dict):
            raise _error(config_path, key, "описание темы должно быть объектом")

        filename = entry.get("rollup")
        # Имя остаётся одним компонентом пути, иначе сводка обходит правила
        # корня-владельца через абсолютный путь или переход между каталогами.
        if (not isinstance(filename, str) or filename.startswith(".")
                or not filename.endswith(".md") or "/" in filename or "\\" in filename):
            raise _error(config_path, key, f"недопустимое имя роллапа {filename!r}")

        owner = None
        if "owner" in entry:
            owner = entry["owner"]
            # Владелец совпадает с ключом темы, чтобы конфиг не мог направить
            # клиентскую сводку в канон другого клиента.
            if (not isinstance(owner, str) or OWNER_RE.fullmatch(owner) is None
                    or owner != f"clients/{key}"):
                raise _error(config_path, key, f"недопустимый owner {owner!r}")

        previous = placement.get(filename)
        if previous is not None:
            raise _error(
                config_path, key,
                f"роллап {filename!r} уже назначен теме {previous[0]!r}",
            )
        placement[filename] = (key, owner)
    return placement


def rollup_relative_source(filename: str, owner: str | None) -> str:
    """Возвращает путь сводки от корня личной федерации."""
    if owner is not None:
        return f"{owner}/memory/topics/{filename}"
    return f"memory/topics/{filename}"
