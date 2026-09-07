"""Чистота lib/: функция без вызывающего, импорт без использования и
одинаковый помощник в двух модулях не заводятся заново.

Ревью 07.09.2026 нашло тринадцать функций без вызовов, лишние импорты и
дубли (find_gitleaks, SLUG_RE, разбор шапки, запись временного файла,
fast-forward). Проверка ходит по исходникам движка: lib/, bin/, githooks/
и tools/, если он есть. Тесты не считаются вызывающими: иначе мёртвая
функция жила бы ради собственного теста.
"""

from __future__ import annotations

import ast
from pathlib import Path
import re
import unittest

REPO_SOURCE = Path(__file__).resolve().parents[1]
LIB = REPO_SOURCE / "lib"

# Функции, которых движок сам не зовёт: их берут установщик машины
# (doctor читает указатели памяти), тесты и учения.
EXTERNAL_ENTRY_POINTS = {
    "configpaths._reset_for_tests",
    "memoryctl.collect_memory_files",
    "memoryctl.countable_link_warnings",
    "memoryctl.validate_links",
    "memorysync.install_hooks",
    "svodgit.write_marker",
}
# Одноимённые функции с заведомо разным смыслом: точки входа команд.
SAME_NAME_ALLOWED = {"main", "build_parser"}


def _engine_sources() -> dict[str, str]:
    sources = {}
    for directory in ("lib", "bin", "githooks", "tools"):
        base = REPO_SOURCE / directory
        if not base.is_dir():
            continue
        for path in sorted(base.iterdir()):
            if path.is_file() and path.suffix in ("", ".py"):
                sources[str(path.relative_to(REPO_SOURCE))] = path.read_text(encoding="utf-8")
    return sources


def _mentions(name: str, text: str) -> int:
    return len(re.findall(r"(?<![\w.])" + re.escape(name) + r"\b", text)) \
        + len(re.findall(r"\." + re.escape(name) + r"\b", text))


class LibHygieneTests(unittest.TestCase):
    def setUp(self):
        self.sources = _engine_sources()
        self.modules = {path.stem: ast.parse(path.read_text(encoding="utf-8"))
                        for path in sorted(LIB.glob("*.py"))}

    def _referenced_elsewhere(self, module: str, name: str) -> bool:
        own = self.sources[f"lib/{module}.py"]
        own_defs = len(re.findall(r"\bdef\s+" + re.escape(name) + r"\b", own))
        if _mentions(name, own) > own_defs:
            return True
        for path, text in self.sources.items():
            if path == f"lib/{module}.py":
                continue
            # Модуль импортируют и под своим именем, и под псевдонимом,
            # в том числе внутри функций: `import memorycontext as mc`.
            aliases = {module} | {alias for full, alias in re.findall(
                r"^\s*import\s+(\w+)\s+as\s+(\w+)", text, re.M) if full == module}
            for alias in aliases:
                if re.search(r"\b" + re.escape(alias) + r"\." + re.escape(name) + r"\b", text):
                    return True
            for block in re.findall(r"from\s+" + re.escape(module) + r"\s+import\s*(\([^)]*\)|[^\n]*)", text):
                if re.search(r"\b" + re.escape(name) + r"\b", block):
                    return True
        return False

    def test_every_function_has_a_caller(self):
        orphans = []
        for module, tree in self.modules.items():
            for node in tree.body:
                if not isinstance(node, ast.FunctionDef) or node.name.startswith("__"):
                    continue
                qualified = f"{module}.{node.name}"
                if qualified in EXTERNAL_ENTRY_POINTS:
                    continue
                if not self._referenced_elsewhere(module, node.name):
                    orphans.append(qualified)
        self.assertEqual(orphans, [], f"функции без вызывающего: {orphans}")

    def test_every_import_is_used_or_reexported(self):
        unused = []
        for module, tree in self.modules.items():
            imported = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported += [(a.asname or a.name).split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    imported += [a.asname or a.name for a in node.names]
            used = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    used.add(node.id)
                elif isinstance(node, ast.Attribute):
                    root = node
                    while isinstance(root, ast.Attribute):
                        root = root.value
                    if isinstance(root, ast.Name):
                        used.add(root.id)
            for name in imported:
                if name == "annotations" or name in used:
                    continue
                if not self._referenced_elsewhere(module, name):
                    unused.append(f"{module}: {name}")
        self.assertEqual(unused, [], f"импорты без использования: {unused}")

    def test_no_helper_is_defined_twice(self):
        bodies: dict[str, list[tuple[str, str]]] = {}
        for module, tree in self.modules.items():
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    body = ast.dump(ast.Module(body=node.body, type_ignores=[]))
                    bodies.setdefault(node.name, []).append((module, body))
                elif isinstance(node, ast.Assign) and len(node.targets) == 1 \
                        and isinstance(node.targets[0], ast.Name):
                    bodies.setdefault(node.targets[0].id, []).append(
                        (module, ast.dump(node.value)))
        doubles = []
        for name, items in bodies.items():
            if name in SAME_NAME_ALLOWED or len(items) < 2:
                continue
            seen: dict[str, str] = {}
            for module, body in items:
                if body in seen:
                    doubles.append(f"{name}: {seen[body]} и {module}")
                seen.setdefault(body, module)
        self.assertEqual(doubles, [], f"одинаковые определения в двух модулях: {doubles}")


if __name__ == "__main__":
    unittest.main()
