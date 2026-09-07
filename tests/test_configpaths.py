"""Адресация конфигурации слоя (срез 4).

Каталог конфигурации задаётся снаружи, а не выводится из расположения
кода. Проверяется: перечень закрыт, исходная точка через него НЕ
адресуется, логические имена манифеста разворачиваются одним резолвером,
отпечаток измерителя чувствителен к байтам конфигурации в чужом каталоге,
история исходной точки сохраняется в git.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

LIB = Path(__file__).resolve().parent.parent / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

import configpaths  # noqa: E402
import memoryeval  # noqa: E402

REPO = LIB.parent


class ПодменаКаталога:
    """Временный каталог конфигурации с копией живой.

    Копия нужна потому, что импорт роутера разбирает topics.json: пустышка
    сломала бы загрузку, а речь про адресацию, а не про разбор.
    """

    def __init__(self):
        self.tmp = None
        self.прежний = None

    def __enter__(self) -> Path:
        self.tmp = tempfile.TemporaryDirectory()
        каталог = Path(self.tmp.name) / "config"
        каталог.mkdir()
        for имя in configpaths.CONFIG_NAMES:
            shutil.copy2(configpaths.config_dir() / имя, каталог / имя)
        self.прежний = os.environ.get(configpaths.CONFIG_ENV)
        os.environ[configpaths.CONFIG_ENV] = str(каталог)
        configpaths._reset_for_tests()
        return каталог

    def __exit__(self, *_):
        if self.прежний is None:
            os.environ.pop(configpaths.CONFIG_ENV, None)
        else:
            os.environ[configpaths.CONFIG_ENV] = self.прежний
        configpaths._reset_for_tests()
        self.tmp.cleanup()
        return False


class РазрешениеПутей(unittest.TestCase):
    def test_без_переменной_каталог_модуля(self):
        прежний = os.environ.pop(configpaths.CONFIG_ENV, None)
        try:
            configpaths._reset_for_tests()
            self.assertEqual(configpaths.config_dir(),
                             Path(configpaths.__file__).resolve().parent)
        finally:
            if прежний is not None:
                os.environ[configpaths.CONFIG_ENV] = прежний
            configpaths._reset_for_tests()

    def test_переменная_перекрывает(self):
        with ПодменаКаталога() as каталог:
            self.assertEqual(configpaths.config_dir(), каталог)
            self.assertEqual(configpaths.config_path("topics.json"),
                             каталог / "topics.json")

    def test_имя_вне_перечня_отказ(self):
        with self.assertRaises(configpaths.ConfigPathError):
            configpaths.config_path("passwd")

    def test_исходная_точка_живёт_в_конфигурации_но_вне_перечня(self):
        """В-11: точка переехала к вопросам стенда, но своим адресом.

        Перечень определяет снимок кода и логические имена манифестов;
        точке не нужно ни то, ни другое. Поэтому config_path её по-
        прежнему отвергает, а baseline_path следует каталогу."""
        self.assertNotIn("eval_baseline.json", configpaths.CONFIG_NAMES)
        with self.assertRaises(configpaths.ConfigPathError):
            configpaths.config_path("eval_baseline.json")
        with ПодменаКаталога() as каталог:
            self.assertEqual(configpaths.baseline_path(),
                             каталог / "eval_baseline.json")

    def test_логические_имена(self):
        self.assertEqual(configpaths.logical_name("/где-то/topics.json"),
                         "config/topics.json")
        self.assertEqual(configpaths.logical_name("/где-то/memoryeval.py"),
                         "lib/memoryeval.py")

    def test_резолвер_разводит_разделы(self):
        корень = Path("/код")
        self.assertEqual(
            configpaths.resolve_manifest_path(корень, "lib/memoryctl.py"),
            корень / "lib/memoryctl.py")
        with ПодменаКаталога() as каталог:
            self.assertEqual(
                configpaths.resolve_manifest_path(корень, "config/topics.json"),
                каталог / "topics.json")

    def test_пары_манифеста_покрывают_перечень(self):
        with ПодменаКаталога() as каталог:
            пары = configpaths.manifest_entries()
            self.assertEqual([и for и, _ in пары],
                             [f"config/{н}" for н in configpaths.CONFIG_NAMES])
            for _, путь in пары:
                self.assertEqual(путь.parent, каталог)


class КореньДанных(unittest.TestCase):
    def test_default_root_не_выводится_из_кода(self):
        import memorycontext
        import memoryctl
        прежний = os.environ.pop("MEMORY_REPO", None)
        try:
            ожидание = (Path.home() / ".agent-memory").resolve()
            self.assertEqual(memorycontext.default_root(), ожидание)
            self.assertEqual(memoryctl.default_root(), ожидание)
        finally:
            if прежний is not None:
                os.environ["MEMORY_REPO"] = прежний


class СтрокаИндекса(unittest.TestCase):
    """Слаг строки-указателя: строка без ссылки на запись слага не имеет."""

    def test_слаг_строки(self):
        import memoryremember
        self.assertEqual(memoryremember.index_line_slug("- [Х](foo_bar.md) - о чём"),
                         "foo_bar")
        self.assertIsNone(memoryremember.index_line_slug("голый текст"))


class ПересдачаТочки(unittest.TestCase):
    def test_history_is_git_and_unrelated_index_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            def git(*args):
                return subprocess.check_output(["git", "-C", d, *args], text=True).strip()
            git("init", "--quiet", "-b", "main")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            git("config", "commit.gpgsign", "false")
            path = root / "eval_baseline.json"
            path.write_text('{"old": 1}\n')
            git("add", ".")
            git("commit", "--quiet", "-m", "seed")
            (root / "unrelated").write_text("staged")
            git("add", "unrelated")
            (root / "unrelated").write_text("unstaged")
            notes = memoryeval.replace_baseline({"new": 2}, path)
            self.assertEqual(json.loads(git("show", "HEAD:eval_baseline.json")), {"new": 2})
            self.assertEqual(json.loads(git("show", "HEAD^:eval_baseline.json")), {"old": 1})
            self.assertEqual(git("show", ":unrelated"), "staged")
            self.assertEqual((root / "unrelated").read_text(), "unstaged")
            self.assertIn("закоммичено локально", notes)
            self.assertTrue(any("не отправлено" in n for n in notes))
            self.assertEqual(list(root.glob("eval_baseline.*.json")), [])

    def test_push_failure_is_named_and_commit_survives(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            def git(*args):
                return subprocess.check_output(["git", "-C", d, *args], text=True).strip()
            git("init", "--quiet", "-b", "main")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            git("config", "commit.gpgsign", "false")
            git("remote", "add", "origin", str(root / "missing.git"))
            notes = memoryeval.replace_baseline({"new": 2}, root / "eval_baseline.json")
            self.assertTrue(any(n.startswith("не отправлено:") for n in notes))
            self.assertNotIn("опубликовано", notes)
            self.assertEqual(json.loads(git("show", "HEAD:eval_baseline.json")), {"new": 2})


if __name__ == "__main__":
    unittest.main()
