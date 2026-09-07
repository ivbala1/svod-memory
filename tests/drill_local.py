"""Учения шага 6: локальные серверы, настоящий CLI и gitleaks.

Запуск: python3 -u tests/drill_local.py. Данные нейтральные и временные;
сценарий подготовки репозиториев общий с тестами писателя.
"""

import json
import os
from pathlib import Path
import shutil
import random
import subprocess
import sys
import unittest

from test_svod0_writer import Federation, REPO_SOURCE, fresh_record, sh


class LocalFederation(Federation):
    def set_scanner(self, code, git_code=None):
        scanner = shutil.which("gitleaks")
        if not scanner:
            raise RuntimeError("Для учений нужен настоящий gitleaks в PATH")
        (self.scanner_dir / "gitleaks").symlink_to(Path(scanner).resolve())


class LocalDrill(unittest.TestCase):
    def setUp(self):
        self.fed = LocalFederation()
        self.addCleanup(self.fed.close)
        topics_path = self.fed.config / "topics.json"
        topics = json.loads(topics_path.read_text())
        topics["scopeRoots"] = {
            "personal": [str(self.fed.base)],
            "acme": [str(self.fed.base / "work" / "acme")],
            "home": [str(self.fed.base / "work" / "home")],
        }
        topics_path.write_text(json.dumps(topics))
        self.engine = REPO_SOURCE
        print("gitleaks:", self.run_command(["gitleaks", "version"]).stdout.strip())

    def run_command(self, args, *, env=None, cwd=None, code=0):
        result = subprocess.run([str(a) for a in args], cwd=cwd or self.fed.base,
                                env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def env(self, machine, config=None):
        return dict(os.environ, MEMORY_REPO=str(self.fed.machines[machine]),
                    MEMORY_CONFIG_DIR=str(config or self.fed.config),
                    MEMORYCTL_STATE_DIR=str(self.fed.states[machine]))

    def cli(self, machine, program, *args, code=0, config=None):
        return self.run_command([sys.executable, self.engine / "bin" / program, *args],
                                env=self.env(machine, config), code=code)

    def remember(self, machine, slug, hook, probe, body, *, code=0):
        candidate = self.fed.base / f"{slug}.md"
        candidate.write_bytes(fresh_record(slug, hook, probe, body))
        projection = self.fed.base / "projection.json"
        projection.write_text(json.dumps({"record_slug": slug}))
        result = self.cli(machine, "memory", "remember", "--scope", "personal",
                          "--id", f"{machine}-{slug}", "--source", "local-drill",
                          "--session", "step6", "--file", candidate,
                          "--projection", projection, "--json", code=code)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["state"], "saved" if code == 0 else "pending", parsed)
        return candidate.read_bytes()

    def sync(self, machine, *, code=0, config=None):
        return json.loads(self.cli(machine, "memory-sync", "--json", code=code,
                                   config=config).stdout)

    def manual(self, machine, slug, hook, probe, body):
        root = self.fed.root(machine)
        (root / "memory" / f"{slug}.md").write_bytes(fresh_record(slug, hook, probe, body))
        sh(root, "add", "--", f"memory/{slug}.md")
        sh(root, "commit", "-q", "-m", f"manual: {slug}", env=self.env(machine))
        return sh(root, "rev-parse", "HEAD")

    def test_local_drill(self):
        fed = self.fed
        kettle = self.remember("a", "reference_kettle", "как кипятить воду в чайнике",
                               "кипятить воду чайник", "Чайник кипятит воду.\n")
        toaster = self.remember("b", "reference_toaster", "как поджарить хлеб в тостере",
                                "поджарить хлеб тостер", "Тостер жарит хлеб.\n")
        self.sync("a")
        for machine in ("a", "b"):
            for slug, expected in (("kettle", kettle), ("toaster", toaster)):
                path = f"memory/reference_{slug}.md"
                self.assertEqual((fed.root(machine) / path).read_bytes(), expected)
                self.assertEqual(fed.origin_tree()[path], expected)
        print("OK: запись с обеих машин, сервер и клоны совпадают")

        local = self.manual("b", "reference_lamp", "как включить настольную лампу",
                            "включить настольную лампу", "Лампа включается кнопкой.\n")
        self.remember("a", "reference_iron", "как гладить бельё утюгом",
                      "гладить бельё утюг", "Утюг гладит бельё.\n")
        sh(fed.root("b"), "fetch", "-q", "origin")
        self.assertEqual(sh(fed.root("b"), "rev-list", "--left-right", "--count",
                            "HEAD...origin/main").split(), ["1", "1"])
        result = self.sync("b")
        personal = next(r for r in result if r["scope"] == "personal")
        self.assertEqual(personal["problems"], [], personal)
        self.assertNotEqual(sh(fed.root("b"), "rev-parse", "HEAD"), local)
        self.assertIn("memory/reference_lamp.md", fed.origin_tree())
        self.assertIn("memory/reference_iron.md", fed.origin_tree())
        self.sync("a")
        print("OK: расхождение разных файлов, rebase и публикация")

        origin = str(fed.origins / "personal.git")
        sh(fed.root("a"), "remote", "set-url", "origin", str(fed.base / "offline.git"))
        self.remember("a", "reference_clock", "как завести настенные часы",
                      "завести настенные часы", "Часы заводятся ключом.\n", code=4)
        waiting = fed.states["a"] / "pending" / "personal"
        self.assertEqual(len(list(waiting.glob("*.json"))), 1)
        self.assertNotIn("memory/reference_clock.md", fed.origin_tree())
        sh(fed.root("a"), "remote", "set-url", "origin", origin)
        self.sync("a")
        self.assertEqual(list(waiting.glob("*.json")), [])
        self.assertIn("memory/reference_clock.md", fed.origin_tree())
        self.sync("b")
        print("OK: недоступный сервер, pending, повтор после восстановления связи")

        local = self.manual("b", "reference_printer", "как чинить зелёный принтер",
                            "чем чинить принтер", "Версия Б: зелёный принтер.\n")
        self.remember("a", "reference_printer", "как чинить зелёный принтер",
                      "чем чинить принтер", "Версия А: зелёный принтер.\n")
        server = sh(fed.origins / "personal.git", "rev-parse", "main")
        result = self.sync("b", code=1)
        personal = next(r for r in result if r["scope"] == "personal")
        self.assertTrue(any("конфликт" in p and "memory/reference_printer.md" in p
                            for p in personal["problems"]), personal)
        self.assertEqual(sh(fed.root("b"), "rev-parse", "HEAD"), local)
        self.assertEqual(sh(fed.origins / "personal.git", "rev-parse", "main"), server)
        self.assertEqual(sh(fed.root("b"), "status", "--porcelain"), "")
        status = self.cli("b", "memory", "status", "--json", code=1)
        self.assertIn("конфликт", status.stdout)
        print("OK: конфликт назван в статусе; обе версии сохранены, main не сдвинут")

        # Импорт истории, созданной до установки хуков: секрет добавлен и удалён.
        legacy = fed.base / "legacy"
        self.run_command(["git", "clone", "-q", origin, legacy])
        secret = legacy / "memory" / "reference_import.md"
        token = "".join(random.Random(6).choices(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=36))
        secret.write_text("github_token = ghp_" + token + "\n")
        sh(legacy, "add", "--", "memory/reference_import.md")
        sh(legacy, "commit", "-q", "-m", "synthetic secret before hooks")
        secret.unlink()
        sh(legacy, "add", "-u")
        sh(legacy, "commit", "-q", "-m", "remove synthetic secret")
        sh(legacy, "config", "core.hooksPath", str(self.engine / "githooks"))
        push = self.run_command(["git", "-C", legacy, "push", "origin", "main"], code=1)
        self.assertIn("pre-push: сканер секретов нашёл", push.stderr)
        self.assertEqual(sh(fed.origins / "personal.git", "rev-parse", "main"), server)
        print("OK: настоящий pre-push остановил синтетический секрет в истории")

        # Восстановление по OPERATIONS: движок и конфигурация тоже из Git.
        engine_origin = fed.origins / "engine.git"
        config_origin = fed.origins / "config.git"
        self.run_command(["git", "clone", "-q", "--bare", REPO_SOURCE, engine_origin])
        sh(fed.config, "init", "-q", "-b", "main")
        sh(fed.config, "add", ".")
        sh(fed.config, "commit", "-q", "-m", "neutral configuration")
        self.run_command(["git", "clone", "-q", "--bare", fed.config, config_origin])
        recovered = fed.base / "recovered"
        self.run_command(["git", "clone", "-q", engine_origin, recovered / "svod"])
        self.run_command(["git", "clone", "-q", config_origin, recovered / "config"])
        self.engine = recovered / "svod"
        fed.clone("c")
        self.assertFalse(fed.states["c"].exists())
        for scope in ("global", "personal", "clients/acme"):
            sh(fed.root("c", scope), "config", "core.hooksPath", str(self.engine / "githooks"))
        config = recovered / "config"
        self.sync("c", config=config)
        result = json.loads(self.cli("c", "memory", "status", "--fetch", "--json",
                                     config=config).stdout)
        self.assertTrue(result["ok"], result)
        for repo in result["repos"]:
            self.assertEqual((repo["ahead"], repo["behind"], repo["dirty"]), (0, 0, []))
            self.assertTrue(repo["hooks"])
            self.assertEqual(sh(fed.root("c", repo["scope"]), "rev-parse", "HEAD^{tree}"),
                             sh(fed.origins / f"{repo['scope'].split('/')[-1]}.git",
                                "rev-parse", "main^{tree}"))
        recall = self.cli("c", "memory", "recall", "как чинить зелёный принтер", config=config)
        self.assertIn("Версия А: зелёный принтер", recall.stdout)
        print("OK: третья машина из Git с пустым состоянием; хуки, sync, status, recall")


if __name__ == "__main__":
    os.environ.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                      GIT_TERMINAL_PROMPT="0")
    unittest.main(verbosity=2)
