"""Свод-0, шаг 3: писатель, публикация, синхронизация, статус, хуки.

Фикстура нейтральная: два bare-сервера, две «машины» (клоны общего и
клиентского репозиториев), своя конфигурация тем и вопросов, подменный
gitleaks. Каждый тест доказывает инвариант из целей 4, 5, 6, 9.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO_SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_SOURCE / "lib"))

import configpaths  # noqa: E402
import memoryremember as mr  # noqa: E402
import memorysync as ms  # noqa: E402
import memoryverify as mv  # noqa: E402
import svodgit  # noqa: E402

TODAY = dt.date(2026, 9, 4)

TOPICS = {
    "federationMembers": ["acme"],
    "topics": {
        "acme": {
            "rollup": "acme.md", "owner": "clients/acme", "label": "Acme",
            "tokens": ["acme"], "hotKeep": [], "aliases": ["acme"],
            "cwdNames": ["acme"], "cwdPrefixes": [],
            "defaultSections": ["обзор"],
            "sectionTerms": {"обзор": ["обзор", "устройств*"],
                             "доступы": ["доступ*", "ssh"]},
        },
        "home": {
            "rollup": "home.md", "label": "Home", "tokens": ["home"],
            "hotKeep": [], "aliases": ["home"], "cwdNames": ["home"],
            "cwdPrefixes": [], "defaultSections": ["обзор"],
            "sectionTerms": {"обзор": ["обзор"]},
        },
    },
    "topicOrder": ["acme", "home"],
}
QUESTIONS = {
    "questions": [
        {"id": "q1", "group": "tuned", "text": "как чинить зелёный принтер",
         "expect": "reference_printer", "markers": ["зелёный принтер"]},
    ],
    "negatives": [{"id": "n1", "text": "погода на марсе завтра"}],
}
PREAMBLE = ("# Индекс\n\n## Inbox\n\n## User\n\n## Feedback\n\n"
            "## Project\n\n## Reference\n\n")


def record(slug: str, *, body: str = "Факт.\n", **fields) -> bytes:
    head = "".join(f"{k}: {v}\n" for k, v in fields.items())
    return f"---\n{head}---\n\n# {slug}\n\n{body}".encode("utf-8")


def fresh_record(slug: str, hook: str, probe: str, body: str = "Факт.\n") -> bytes:
    return record(slug, type="reference", title=hook.capitalize(), index=hook,
                  source="разговор", observed_at="2026-09-04", probe=probe, body=body)


def sh(root: Path, *args: str, env=None) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env).stdout.strip()


class Federation:
    """Два сервера, две машины, конфигурация и подменный сканер."""

    def __init__(self):
        self.dir = tempfile.TemporaryDirectory(prefix="svod-fed-")
        self.base = Path(self.dir.name)
        self.config = self.base / "config"
        self.config.mkdir()
        (self.config / "topics.json").write_text(json.dumps(TOPICS, ensure_ascii=False))
        (self.config / "eval_questions.json").write_text(json.dumps(QUESTIONS, ensure_ascii=False))
        self.scanner_dir = self.base / "scanner"
        self.scanner_dir.mkdir()
        self.set_scanner(0)
        self.saved_env = dict(os.environ)
        os.environ.update({
            "MEMORY_CONFIG_DIR": str(self.config),
            "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
            "PATH": f"{self.scanner_dir}:{os.environ.get('PATH', '')}",
        })
        os.environ.pop("MEMORY_REPO", None)
        configpaths._reset_for_tests()
        self.verify_config = mv.Config(topics=(self.config / "topics.json").read_bytes(),
                                       questions=(self.config / "eval_questions.json").read_bytes())
        self.origins = self.base / "origin"
        self.origins.mkdir()
        for name in ("global", "personal", "acme"):
            subprocess.run(["git", "init", "--quiet", "--bare", "-b", "main",
                            str(self.origins / f"{name}.git")], check=True)
        seed = self.base / "seed"
        self._seed_global(seed / "global")
        self._seed_personal(seed / "personal")
        self._seed_client(seed / "acme")
        self.machines: dict[str, Path] = {}
        self.states: dict[str, Path] = {}
        for machine in ("a", "b"):
            self.clone(machine)

    def set_scanner(self, code: int, git_code: int | None = None) -> None:
        """Подменный gitleaks: код выхода по патчу (detect) и по диапазону (git)."""
        path = self.scanner_dir / "gitleaks"
        git_code = code if git_code is None else git_code
        path.write_text(f"#!/bin/sh\ncase \"$1\" in git) exit {git_code};; *) exit {code};; esac\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def _seed_global(self, root: Path) -> None:
        """Глобальный репозиторий это контракт целиком: одно правило."""
        root.mkdir(parents=True)
        sh(root, "init", "--quiet", "-b", "main")
        (root / "memory").mkdir(parents=True)
        (root / "memory" / "MEMORY.md").write_text("# Индекс\n\n## Feedback\n\n")
        (root / "memory" / "feedback_words.md").write_bytes(record(
            "feedback_words", type="feedback", title="Отвечать словами",
            index="отказы и статус словами, без кодов", probe="как объяснять отказы словами", body="Отвечать словами.\n"))
        svodgit.write_marker(root, "global")
        sh(root, "add", "-A")
        sh(root, "commit", "--quiet", "-m", "seed")
        sh(root, "remote", "add", "origin", str(self.origins / "global.git"))
        sh(root, "push", "--quiet", "origin", "main")

    def _seed_personal(self, root: Path) -> None:
        root.mkdir(parents=True)
        sh(root, "init", "--quiet", "-b", "main")
        (root / "memory" / "topics").mkdir(parents=True)
        (root / "memory" / "MEMORY.md").write_text(PREAMBLE)
        (root / "memory" / "reference_printer.md").write_bytes(record(
            "reference_printer", type="reference", title="Зелёный принтер",
            index="как чинить зелёный принтер", probe="чем чинить принтер", body="Зелёный принтер чинится молотком.\n"))
        (root / "memory" / "topics" / "home.md").write_text("# Home\n\n## Обзор\n\nДом.\n")
        svodgit.write_marker(root, "personal")
        sh(root, "add", "-A")
        sh(root, "commit", "--quiet", "-m", "seed")
        sh(root, "remote", "add", "origin", str(self.origins / "personal.git"))
        sh(root, "push", "--quiet", "origin", "main")

    def _seed_client(self, root: Path) -> None:
        root.mkdir(parents=True)
        sh(root, "init", "--quiet", "-b", "main")
        (root / "memory" / "topics").mkdir(parents=True)
        (root / "memory" / "MEMORY.md").write_text("# Acme\n")
        (root / "memory" / "topics" / "acme.md").write_text(
            "# Acme\n\n## Обзор\n\nЗаказчик Acme.\n\n## Доступы\n\nПо ssh.\n")
        svodgit.write_marker(root, "clients/acme")
        sh(root, "add", "-A")
        sh(root, "commit", "--quiet", "-m", "seed")
        sh(root, "remote", "add", "origin", str(self.origins / "acme.git"))
        sh(root, "push", "--quiet", "origin", "main")

    def clone(self, machine: str, *, personal: bool = True) -> Path:
        """Машина это каталог данных с клоном на область; машина заказчика
        обходится без personal/."""
        data = self.base / machine
        data.mkdir(parents=True, exist_ok=True)
        scopes = ["global"] + (["personal"] if personal else [])
        for scope in scopes:
            subprocess.run(["git", "clone", "--quiet", str(self.origins / f"{scope}.git"),
                            str(data / scope)], check=True)
        subprocess.run(["git", "clone", "--quiet", str(self.origins / "acme.git"),
                        str(data / "clients" / "acme")], check=True)
        for scope in scopes + ["clients/acme"]:
            ms.install_hooks(data / scope)
        self.machines[machine] = data
        self.states[machine] = self.base / f"state-{machine}"
        return data

    def root(self, machine: str, scope: str = "personal") -> Path:
        return self.machines[machine] / scope

    def remember(self, machine: str, scope: str, cid: str, body: bytes, projection=None,
                 content_type="markdown", **kw):
        return mr.run_remember(scope=scope, candidate_id=cid, source="test", session="s",
                               content_type=content_type, body=body, projection=projection,
                               data_root=self.machines[machine], state=self.states[machine],
                               today=TODAY, **kw)

    def sync(self, machine: str, scope: str = "personal") -> dict:
        outcome = ms.sync_repo(scope, self.root(machine, scope), self.verify_config,
                               today=TODAY, state=self.states[machine])
        ms.write_cache(scope, outcome, self.states[machine])
        return outcome

    def origin_tree(self, scope: str = "personal") -> dict[str, bytes]:
        return svodgit.read_tree(self.origins / f"{scope.split('/')[-1]}.git", "main")

    def close(self) -> None:
        os.environ.clear()
        os.environ.update(self.saved_env)
        configpaths._reset_for_tests()
        self.dir.cleanup()


class Base(unittest.TestCase):
    def setUp(self):
        self.fed = Federation()
        self.addCleanup(self.fed.close)

    def pending(self, machine: str, scope: str = "personal") -> list[Path]:
        return sorted(svodgit.pending_dir(scope, self.fed.states[machine]).glob("*.json"))

    def failed(self, machine: str, scope: str = "personal") -> list[Path]:
        return sorted(svodgit.failed_dir(scope, self.fed.states[machine]).glob("*.json"))

    def manual_commit(self, root: Path, path: str, data: bytes, message: str,
                      no_verify: bool = False) -> str:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        sh(root, "add", "-A", "--", path)
        sh(root, "commit", "--quiet", *(["--no-verify"] if no_verify else []), "-m", message)
        return svodgit.head(root)


NEW_BODY = fresh_record("reference_kettle", "как кипятить воду в чайнике",
                        "кипятить воду чайник", "Чайник кипятит воду.\n")


class WriterTests(Base):
    def test_record_saved_only_after_server_accepts(self):
        code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual((code, result["state"]), (mr.EXIT_SAVED, result["state"]), result)
        self.assertEqual(result["state"], "saved")
        self.assertIn("memory/reference_kettle.md", self.fed.origin_tree())
        self.assertEqual(self.pending("a"), [])
        root = self.fed.root("a")
        self.assertEqual(svodgit.head(root), result["commit"])
        self.assertEqual(svodgit.remote_head(root), result["commit"])
        self.assertEqual(sh(root, "log", "-1", "--format=%s"), "memory: kettle-1")
        self.assertEqual(svodgit.dirty_paths(root), set())

    def test_second_machine_writes_on_top_of_first(self):
        self.fed.remember("a", "personal", "kettle-1", NEW_BODY, {"record_slug": "reference_kettle"})
        body = fresh_record("reference_toaster", "как поджарить хлеб в тостере",
                            "поджарить хлеб тостер", "Тостер жарит хлеб.\n")
        code, result = self.fed.remember("b", "personal", "toaster-1", body,
                                         {"record_slug": "reference_toaster"})
        self.assertEqual(result["state"], "saved", result)
        tree = self.fed.origin_tree()
        self.assertIn("memory/reference_kettle.md", tree)
        self.assertIn("memory/reference_toaster.md", tree)

    def test_red_check_moves_candidate_to_failed_and_restores_tree(self):
        body = record("reference_kettle", type="reference", title="Чайник",
                      index="как кипятить воду", body="Без происхождения.\n")
        code, result = self.fed.remember("a", "personal", "kettle-red", body,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("source", result["reason"])
        root = self.fed.root("a")
        self.assertEqual(svodgit.dirty_paths(root), set())
        self.assertFalse((root / "memory" / "reference_kettle.md").exists())
        self.assertEqual(len(self.failed("a")), 1)
        self.assertEqual(self.pending("a"), [])
        stored = json.loads(self.failed("a")[0].read_text())
        self.assertIn("source", stored["reason"])

    def test_changed_base_refuses_instead_of_overwriting(self):
        root_b = self.fed.root("b")
        path = "memory/reference_printer.md"
        projection = {"record_slug": "reference_printer"}
        body_b = fresh_record("reference_printer", "как чинить зелёный принтер",
                              "чем чинить принтер", "Версия машины Б: зелёный принтер.\n")
        # Кандидат Б подан с ожиданием старого blob, затем А меняет запись.
        path_b, cand = mr.submit(scope="personal", candidate_id="printer-b", source="t", session="s",
                                 content_type="markdown", body=body_b, projection=projection,
                                 root=root_b, state=self.fed.states["b"])
        body_a = fresh_record("reference_printer", "как чинить зелёный принтер",
                              "чем чинить принтер", "Версия машины А: зелёный принтер.\n")
        _, res_a = self.fed.remember("a", "personal", "printer-a", body_a, projection)
        self.assertEqual(res_a["state"], "saved", res_a)
        with svodgit.lock(root_b, exclusive=True):
            result = mr.apply(path_b, cand, root=root_b, scope="personal",
                              config=self.fed.verify_config, today=TODAY, state=self.fed.states["b"])
        self.assertEqual(result["state"], "failed", result)
        self.assertIn("менялась", result["reason"])
        self.assertIn(path, result["reason"])
        self.assertEqual(self.fed.origin_tree()[path], body_a)
        self.assertEqual(svodgit.dirty_paths(root_b), set())

    def test_same_id_same_body_repeats_other_body_refuses(self):
        self.fed.remember("a", "personal", "kettle-1", NEW_BODY, {"record_slug": "reference_kettle"})
        head = svodgit.head(self.fed.root("a"))
        code, again = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                        {"record_slug": "reference_kettle"})
        self.assertEqual(again["state"], "saved", again)
        self.assertEqual(svodgit.head(self.fed.root("a")), head, "повтор ничего не меняет")
        other = fresh_record("reference_kettle", "как кипятить воду в чайнике",
                             "кипятить воду чайник", "Иное про чайник.\n")
        code, again = self.fed.remember("a", "personal", "kettle-1", other,
                                        {"record_slug": "reference_kettle"})
        self.assertEqual(again["state"], "failed", again)
        self.assertIn("уже есть в истории", again["reason"])
        root = self.fed.root("b")
        other = fresh_record("reference_kettle", "как кипятить воду в чайнике", "кипятить воду чайник", "Иное.\n")
        path, _ = mr.submit(scope="personal", candidate_id="dup", source="t", session="s",
                            content_type="markdown", body=NEW_BODY,
                            projection={"record_slug": "reference_kettle"}, root=root,
                            state=self.fed.states["b"])
        with self.assertRaises(mr.Refusal) as ctx:
            mr.submit(scope="personal", candidate_id="dup", source="t", session="s",
                      content_type="markdown", body=other,
                      projection={"record_slug": "reference_kettle"}, root=root,
                      state=self.fed.states["b"])
        self.assertIn("другим телом", str(ctx.exception))
        same_path, same = mr.submit(scope="personal", candidate_id="dup", source="t", session="s",
                                    content_type="markdown", body=NEW_BODY,
                                    projection={"record_slug": "reference_kettle"}, root=root,
                                    state=self.fed.states["b"])
        self.assertEqual(same_path, path)

    def test_bad_id_and_bad_paths_refused_before_any_write(self):
        root = self.fed.root("a")
        with self.assertRaises(mr.Refusal):
            mr.submit(scope="personal", candidate_id="a/b", source="t", session="s",
                      content_type="markdown", body=NEW_BODY,
                      projection={"record_slug": "reference_kettle"}, root=root,
                      state=self.fed.states["a"])
        for bad in ("memory/../x.md", "other/x.md", "memory/.git/x.md", "memory/x.txt"):
            manifest = json.dumps({"changes": [{"operation": "put", "path": bad, "content": "x\n"}]})
            with self.assertRaises(mr.Refusal, msg=bad):
                mr.submit(scope="personal", candidate_id="bad", source="t", session="s",
                          content_type="manifest", body=manifest.encode(), projection=None,
                          root=root, state=self.fed.states["a"])
        self.assertEqual(self.pending("a"), [])
        self.assertEqual(svodgit.dirty_paths(root), set())

    def test_foreign_dirty_path_makes_candidate_wait_untouched(self):
        root = self.fed.root("a")
        (root / "memory" / "topics" / "home.md").write_text("# Home\n\n## Обзор\n\nПравят руками.\n")
        code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_PENDING)
        self.assertIn("правят руками", result["reason"])
        self.assertIn("memory/topics/home.md", result["reason"])
        self.assertEqual(len(self.pending("a")), 1)
        self.assertEqual(svodgit.dirty_paths(root), {"memory/topics/home.md"})
        self.assertNotIn("memory/reference_kettle.md", self.fed.origin_tree())

    def test_leftover_of_crashed_pass_is_restored_and_pass_completes(self):
        root = self.fed.root("a")
        # След упавшего прохода: файл кандидата лежит в рабочем каталоге и индексе.
        target = root / "memory" / "reference_kettle.md"
        target.write_bytes(NEW_BODY)
        sh(root, "add", "--", "memory/reference_kettle.md")
        code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(result["state"], "saved", result)
        self.assertIn("memory/reference_kettle.md", self.fed.origin_tree())

    def test_no_network_commits_locally_and_timer_delivers(self):
        root = self.fed.root("a")
        sh(root, "remote", "set-url", "origin", str(self.fed.base / "nowhere.git"))
        code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_PENDING, result)
        self.assertIn("сети нет", result["reason"])
        self.assertEqual(svodgit.head(root), result["commit"])
        self.assertEqual(len(self.pending("a")), 1)
        self.assertNotIn("memory/reference_kettle.md", self.fed.origin_tree())
        sh(root, "remote", "set-url", "origin", str(self.fed.origins / "personal.git"))
        outcome = self.fed.sync("a")
        self.assertEqual(outcome["problems"], [], outcome)
        self.assertIn("memory/reference_kettle.md", self.fed.origin_tree())
        self.assertEqual([c["state"] for c in outcome["candidates"]], ["delivered"])
        self.assertEqual(self.pending("a"), [])

    def test_crash_after_update_ref_before_candidate_saved_is_repaired(self):
        root = self.fed.root("a")
        path, cand = mr.submit(scope="personal", candidate_id="kettle-1", source="t", session="s",
                               content_type="markdown", body=NEW_BODY,
                               projection={"record_slug": "reference_kettle"}, root=root,
                               state=self.fed.states["a"])
        # Проход дошёл до update-ref и умер: коммит есть, кандидат без хеша.
        target = root / "memory" / "reference_kettle.md"
        target.write_bytes(NEW_BODY)
        sh(root, "add", "-A")
        sh(root, "commit", "--quiet", "--no-verify", "-m", "memory: kettle-1")
        head = svodgit.head(root)
        outcome = self.fed.sync("a")
        self.assertEqual(outcome["problems"], [], outcome)
        self.assertEqual(svodgit.head(root), head, "пустой коммит не создаётся")
        self.assertEqual(self.fed.origin_tree()["memory/reference_kettle.md"], NEW_BODY)
        self.assertEqual(self.pending("a"), [])

    def test_crash_after_push_before_candidate_removed_is_delivered(self):
        root = self.fed.root("a")
        code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(result["state"], "saved")
        # Кандидат «остался» после падения между push и удалением файла.
        cand = {"scope": "personal", "id": "kettle-1", "source": "t", "session": "s",
                "content_type": "markdown", "projection": {"record_slug": "reference_kettle"},
                "body": NEW_BODY.decode(), "submitted_at": "2026-09-04T00:00:00Z",
                "base": None, "expectations": {"memory/reference_kettle.md": None},
                "commit": result["commit"],
                "result": {"memory/reference_kettle.md": svodgit.blob(root, result["commit"],
                                                                     "memory/reference_kettle.md")},
                "reason": None}
        path = mr.candidate_path("personal", "kettle-1", self.fed.states["a"])
        svodgit.create_file(path, json.dumps(cand).encode())
        outcome = self.fed.sync("a")
        self.assertEqual([c["state"] for c in outcome["candidates"]], ["delivered"])
        self.assertEqual(self.pending("a"), [])

    def test_delivery_proved_by_blobs_when_rebase_rewrote_hash(self):
        root = self.fed.root("a")
        code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                         {"record_slug": "reference_kettle"})
        cand = {"commit": "0" * 40,
                "result": {"memory/reference_kettle.md": svodgit.blob(root, "HEAD",
                                                                     "memory/reference_kettle.md")}}
        self.assertTrue(mr.delivered(root, cand))
        self.assertFalse(mr.delivered(root, {"commit": "0" * 40, "result": {}}),
                         "пустой diff доставкой не считается")

    def test_client_record_gets_pointer_in_rollup_section(self):
        body = record("acme_vpn", type="project", title="VPN Acme", index="vpn acme",
                      source="разговор", observed_at="2026-09-04",
                      probe="как попасть в сеть заказчика по ssh", listed="false",
                      body="Доступ по ssh через бастион.\n")
        projection = {"record_slug": "acme_vpn", "index_section": "Доступы",
                      "index_line": "- [[acme_vpn]] ssh через бастион"}
        code, result = self.fed.remember("a", "clients/acme", "acme-vpn-1", body, projection)
        self.assertEqual(result["state"], "saved", result)
        tree = self.fed.origin_tree("clients/acme")
        self.assertIn("memory/acme_vpn.md", tree)
        rollup = tree["memory/topics/acme.md"].decode()
        self.assertIn("## Доступы\n\nПо ssh.\n- [[acme_vpn]] ssh через бастион\n", rollup)
        self.assertNotIn("memory/acme_vpn.md", self.fed.origin_tree("personal"))

    def test_client_record_without_pointer_or_section_refused(self):
        body = record("acme_vpn", type="project", title="VPN", index="vpn",
                      source="разговор", observed_at="2026-09-04", probe="как в сеть",
                      body="Факт.\n")
        code, result = self.fed.remember("a", "clients/acme", "acme-1", body,
                                         {"record_slug": "acme_vpn"})
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("указатель", result["reason"])
        code, result = self.fed.remember("a", "clients/acme", "acme-2", body,
                                         {"record_slug": "acme_vpn", "index_section": "Нет такого",
                                          "index_line": "- [[acme_vpn]] x"})
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("раздела", result["reason"])

    def test_manifest_put_and_remove_with_base_revision(self):
        root = self.fed.root("a")
        base = svodgit.head(root)
        manifest = {
            "base_revision": base,
            "changes": [
                {"operation": "put", "path": "memory/topics/home.md",
                 "content": "# Home\n\n## Обзор\n\nДом и сад, [[reference_printer]].\n"},
                {"operation": "put", "area": "memory", "path": "reference_kettle.md",
                 "content": NEW_BODY.decode()},
            ],
        }
        code, result = self.fed.remember("a", "personal", "man-1", json.dumps(manifest).encode(),
                                         None, content_type="manifest")
        self.assertEqual(result["state"], "saved", result)
        tree = self.fed.origin_tree()
        self.assertIn("Дом и сад", tree["memory/topics/home.md"].decode())
        self.assertEqual(tree["memory/reference_kettle.md"], NEW_BODY)
        stale = dict(manifest, base_revision=base)
        stale["changes"] = [{"operation": "remove", "path": "memory/topics/home.md"}]
        code, result = self.fed.remember("a", "personal", "man-2", json.dumps(stale).encode(),
                                         None, content_type="manifest")
        self.assertEqual(result["state"], "failed", result)
        self.assertIn("менялась", result["reason"])

    def test_wrong_marker_refuses_in_words(self):
        root = self.fed.root("a")
        svodgit.write_marker(root, "clients/acme")
        code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_ERROR)
        self.assertIn("чужой репозиторий", result["reason"])
        self.assertEqual(self.pending("a"), [])

    def test_busy_repository_refuses_after_wait(self):
        root = self.fed.root("a")
        old = svodgit.EXCLUSIVE_WAIT_SEC
        svodgit.EXCLUSIVE_WAIT_SEC = 0.3
        self.addCleanup(setattr, svodgit, "EXCLUSIVE_WAIT_SEC", old)
        with svodgit.lock(root, exclusive=True):
            code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                             {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_BUSY)
        self.assertEqual(len(self.pending("a")), 1, "кандидат записан до замка")
        outcome = self.fed.sync("a")
        self.assertEqual([c["state"] for c in outcome["candidates"]], ["saved"], outcome)


class SyncTests(Base):
    def test_server_ahead_is_fast_forwarded(self):
        self.fed.remember("a", "personal", "kettle-1", NEW_BODY, {"record_slug": "reference_kettle"})
        root_b = self.fed.root("b")
        outcome = self.fed.sync("b")
        self.assertEqual(outcome["problems"], [], outcome)
        self.assertTrue(any("fast-forward" in d for d in outcome["done"]), outcome)
        self.assertTrue((root_b / "memory" / "reference_kettle.md").exists())

    def test_divergence_is_rebased_and_published(self):
        root_b = self.fed.root("b")
        toaster = fresh_record("reference_toaster", "как поджарить хлеб в тостере",
                               "поджарить хлеб тостер", "Тостер.\n")
        local = self.manual_commit(root_b, "memory/reference_toaster.md", toaster, "memory: toaster")
        self.fed.remember("a", "personal", "kettle-1", NEW_BODY, {"record_slug": "reference_kettle"})
        outcome = self.fed.sync("b")
        self.assertEqual(outcome["problems"], [], outcome)
        tree = self.fed.origin_tree()
        self.assertIn("memory/reference_toaster.md", tree)
        self.assertIn("memory/reference_kettle.md", tree)
        self.assertEqual(svodgit.branch(root_b), "main")
        self.assertNotEqual(svodgit.head(root_b), local)
        self.assertEqual(svodgit.head(root_b), svodgit.remote_head(root_b))

    def test_conflict_leaves_main_in_place_and_names_file(self):
        root_b = self.fed.root("b")
        path = "memory/reference_printer.md"
        local = self.manual_commit(root_b, path, fresh_record(
            "reference_printer", "как чинить зелёный принтер", "чем чинить принтер", "Версия Б: зелёный принтер.\n"),
            "memory: printer-b")
        self.fed.remember("a", "personal", "printer-a", fresh_record(
            "reference_printer", "как чинить зелёный принтер", "чем чинить принтер", "Версия А: зелёный принтер.\n"),
            {"record_slug": "reference_printer"})
        outcome = self.fed.sync("b")
        self.assertEqual(len(outcome["problems"]), 1, outcome)
        self.assertIn("конфликт", outcome["problems"][0])
        self.assertIn(path, outcome["problems"][0])
        self.assertEqual(svodgit.head(root_b), local, "ветка main не двигалась")
        self.assertEqual(svodgit.branch(root_b), "main")
        self.assertFalse(svodgit.rebase_in_progress(root_b))
        self.assertEqual(svodgit.dirty_paths(root_b), set())
        cache = svodgit.read_json(svodgit.sync_cache_path("personal", self.fed.states["b"]))
        self.assertIn("конфликт", cache["problems"][0])

    def test_red_local_commit_is_not_published(self):
        root_b = self.fed.root("b")
        self.manual_commit(root_b, "memory/reference_bad.md",
                           record("reference_bad", type="reference", title="Плохая",
                                  index="плохая запись", body="Без происхождения.\n"),
                           "memory: bad", no_verify=True)
        outcome = self.fed.sync("b")
        self.assertEqual(len(outcome["problems"]), 1, outcome)
        self.assertIn("красное", outcome["problems"][0])
        self.assertNotIn("memory/reference_bad.md", self.fed.origin_tree())

    def test_dirty_tree_is_skipped_in_words(self):
        root_a = self.fed.root("a")
        (root_a / "memory" / "topics" / "home.md").write_text("# Home\n\n## Обзор\n\nРуками.\n")
        outcome = self.fed.sync("a")
        self.assertTrue(any("правят руками" in p for p in outcome["problems"]), outcome)

    def test_detached_head_and_stale_rebase_are_healed(self):
        root_a = self.fed.root("a")
        sh(root_a, "checkout", "--quiet", "--detach")
        outcome = self.fed.sync("a")
        self.assertEqual(outcome["problems"], [], outcome)
        self.assertEqual(svodgit.branch(root_a), "main")

    def test_sync_all_writes_cache_per_scope_and_survives_one_failure(self):
        svodgit.write_marker(self.fed.root("a", "clients/acme"), "personal")
        outcomes = ms.sync_all(data_root=self.fed.machines["a"], today=TODAY,
                               state=self.fed.states["a"])
        by_scope = {o["scope"]: o for o in outcomes}
        self.assertEqual(by_scope["personal"]["problems"], [])
        self.assertTrue(any("чужой" in p for p in by_scope["clients/acme"]["problems"]))
        for scope in ("personal", "clients/acme"):
            self.assertTrue(svodgit.sync_cache_path(scope, self.fed.states["a"]).is_file())


class StatusTests(Base):
    def test_status_reflects_git_and_candidates(self):
        root_a = self.fed.root("a")
        sh(root_a, "remote", "set-url", "origin", str(self.fed.base / "nowhere.git"))
        self.fed.remember("a", "personal", "kettle-1", NEW_BODY, {"record_slug": "reference_kettle"})
        self.fed.remember("a", "personal", "bad-1", record("reference_bad", body="x\n"),
                          {"record_slug": "reference_bad"})
        (root_a / "memory" / "topics" / "home.md").write_text("# Home\n\n## Обзор\n\nРуками.\n")
        result = ms.status(data_root=self.fed.machines["a"], state=self.fed.states["a"])
        common = next(r for r in result["repos"] if r["scope"] == "personal")
        self.assertEqual(common["branch"], "main")
        self.assertEqual(common["ahead"], 1)
        self.assertEqual(common["dirty"], ["memory/topics/home.md"])
        self.assertEqual([c["id"] for c in common["pending"]], ["kettle-1"])
        self.assertEqual([c["id"] for c in common["failed"]], ["bad-1"])
        self.assertTrue(common["hooks"])
        self.assertFalse(result["ok"])
        text = ms.format_human(result)
        self.assertIn("ждёт kettle-1", text)
        self.assertIn("отказ bad-1", text)
        self.assertIn("впереди 1", text)

    def test_clean_federation_is_ok(self):
        result = ms.status(data_root=self.fed.machines["a"], state=self.fed.states["a"])
        self.assertTrue(result["ok"], ms.format_human(result))
        self.assertEqual(ms.format_nudge(result), "")
        self.assertEqual({r["scope"] for r in result["repos"]}, {"global", "personal", "clients/acme"})

    def test_missing_hooks_are_named(self):
        root = self.fed.root("a")
        sh(root, "config", "--unset", "core.hooksPath")
        result = ms.status(data_root=self.fed.machines["a"], state=self.fed.states["a"])
        common = next(r for r in result["repos"] if r["scope"] == "personal")
        self.assertFalse(common["hooks"])
        self.assertIn("hooksPath", common["hooks_problem"])

    def test_health_uses_index_drift_and_section_measurements(self):
        topics = json.loads(json.dumps(TOPICS))
        topics["budget"] = {"softBytes": 1, "softLines": 1,
                            "hardBytes": 100000, "hardLines": 1000}
        config = mv.Config(topics=json.dumps(topics).encode())
        root = self.fed.root("a")
        tree = svodgit.read_tree(root, "HEAD")
        tree["memory/reference_acme_note.md"] = record(
            "reference_acme_note", type="reference", title="Сеть", index="сеть", body="Сеть.")
        with mock.patch.object(svodgit, "read_tree", return_value=tree):
            health = ms.repo_health("personal", root, config)
        self.assertTrue(any("выше порога" in h for h in health), health)
        self.assertTrue(any("дрейф: acme 1" in h for h in health), health)
        client = self.fed.root("a", "clients/acme")
        tree = {"memory/topics/acme.md": ("# Acme\n\n## Обзор\n\n" + "д" * 4000).encode()}
        with mock.patch.object(svodgit, "read_tree", return_value=tree):
            health = ms.repo_health("clients/acme", client, config)
        self.assertTrue(any("при потолке 3400" in h for h in health), health)
        nudge = ms.format_nudge({"repos": [{"scope": "clients/acme", "health": health}]})
        self.assertIn("сводка", nudge)
        self.assertNotIn("\n", nudge)


class HookTests(Base):
    def test_pre_commit_stops_secret_and_red_record(self):
        root = self.fed.root("a")
        target = root / "memory" / "reference_leak.md"
        target.write_bytes(fresh_record("reference_leak", "ключ от сервиса", "где ключ",
                                        "Ключ ghp_" + "a" * 30 + "\n"))
        sh(root, "add", "-A")
        result = subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "manual"],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("секрет", result.stderr.lower())
        self.assertIn("reference_leak.md", result.stderr)

    def test_pre_commit_passes_green_manual_commit(self):
        root = self.fed.root("a")
        (root / "memory" / "reference_kettle.md").write_bytes(NEW_BODY)
        sh(root, "add", "-A")
        sh(root, "commit", "-q", "-m", "manual green")

    def test_pre_push_blocks_range_when_scanner_flags_and_without_scanner(self):
        root = self.fed.root("a")
        (root / "memory" / "reference_kettle.md").write_bytes(NEW_BODY)
        sh(root, "add", "-A")
        sh(root, "commit", "-q", "--no-verify", "-m", "manual")
        self.fed.set_scanner(0, git_code=42)
        result = subprocess.run(["git", "-C", str(root), "push", "-q", "origin", "main"],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("сканер секретов нашёл", result.stderr)
        self.assertNotIn("memory/reference_kettle.md", self.fed.origin_tree())
        # Без сканера вовсе: каталог подмены убран из PATH, а домашний каталог
        # пуст, чтобы запасной ~/.local/bin/gitleaks не нашёлся.
        clean_path = ":".join(p for p in os.environ["PATH"].split(":")[1:]
                              if not (Path(p) / "gitleaks").exists())
        env = dict(os.environ, PATH=clean_path, HOME=str(self.fed.base / "emptyhome"))
        (self.fed.base / "emptyhome").mkdir(exist_ok=True)
        result = subprocess.run(["git", "-C", str(root), "push", "-q", "origin", "main"],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("не найден", result.stderr)
        self.assertNotIn("memory/reference_kettle.md", self.fed.origin_tree())
        self.fed.set_scanner(0)
        sh(root, "push", "-q", "origin", "main")
        self.assertIn("memory/reference_kettle.md", self.fed.origin_tree())

    def test_engine_push_is_stopped_by_range_scanner(self):
        self.fed.set_scanner(0, git_code=42)
        code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_PENDING, result)
        self.assertIn("сканер секретов", result["reason"])
        self.assertNotIn("memory/reference_kettle.md", self.fed.origin_tree())


class GitToolsTests(Base):
    def test_read_tree_round_trips_bytes(self):
        root = self.fed.root("a")
        tree = svodgit.read_tree(root, "HEAD")
        self.assertEqual(tree["memory/MEMORY.md"], PREAMBLE.encode())
        self.assertEqual(set(tree), {"memory/MEMORY.md", "memory/reference_printer.md",
                                     "memory/topics/home.md"})
        self.assertEqual(svodgit.read_tree(root, None), {})

    def test_repo_map_and_marker(self):
        mapping = svodgit.repo_map(self.fed.machines["a"])
        self.assertEqual(set(mapping), {"global", "personal", "clients/acme"})
        shutil.rmtree(self.fed.root("a", "clients/acme"))
        self.assertEqual(set(svodgit.repo_map(self.fed.machines["a"])), {"global", "personal"})
        with self.assertRaises(ValueError):
            svodgit.scope_root("clients/acme", self.fed.machines["a"])
        with self.assertRaises(ValueError):
            svodgit.scope_root("clients/nobody", self.fed.machines["a"])
        with self.assertRaises(ValueError):
            svodgit.require_marker(self.fed.root("a"), "clients/acme")

    def test_shared_lock_reads_even_when_writer_holds(self):
        root = self.fed.root("a")
        old = svodgit.SHARED_WAIT_SEC
        svodgit.SHARED_WAIT_SEC = 0.2
        self.addCleanup(setattr, svodgit, "SHARED_WAIT_SEC", old)
        with svodgit.lock(root, exclusive=True):
            with svodgit.lock(root, exclusive=False) as taken:
                self.assertFalse(taken)
        with svodgit.lock(root, exclusive=False) as taken:
            self.assertTrue(taken)

    def test_fast_forward_moves_only_without_divergence(self):
        """Один fast-forward у писателя и таймера: равенство и расхождение
        ничего не трогают, отставание подтягивается, пустой репозиторий
        сбрасывается на вершину сервера."""
        root_a, root_b = self.fed.root("a"), self.fed.root("b")
        head = svodgit.head(root_a)
        self.assertFalse(svodgit.fast_forward(root_a, head, head))
        self.assertFalse(svodgit.fast_forward(root_a, head, None))
        self.fed.remember("b", "personal", "lamp", fresh_record(
            "reference_lamp", "как включить лампу", "включить лампу"),
            {"record_slug": "reference_lamp"})
        sh(root_a, "fetch", "--quiet", "origin")
        remote = svodgit.remote_head(root_a)
        self.assertTrue(svodgit.fast_forward(root_a, head, remote))
        self.assertEqual(svodgit.head(root_a), remote)
        local = self.manual_commit(root_a, "memory/reference_iron.md", fresh_record(
            "reference_iron", "как гладить утюгом", "гладить утюг"), "memory: iron")
        self.fed.remember("b", "personal", "clock", fresh_record(
            "reference_clock", "как завести часы", "завести часы"),
            {"record_slug": "reference_clock"})
        sh(root_a, "fetch", "--quiet", "origin")
        self.assertFalse(svodgit.fast_forward(root_a, local, svodgit.remote_head(root_a)))
        self.assertEqual(svodgit.head(root_a), local)
        empty = self.fed.base / "empty"
        subprocess.run(["git", "init", "--quiet", "-b", "main", str(empty)], check=True)
        sh(empty, "remote", "add", "origin", str(self.fed.origins / "personal.git"))
        sh(empty, "fetch", "--quiet", "origin")
        remote = svodgit.remote_head(empty)
        self.assertTrue(svodgit.fast_forward(empty, None, remote))
        self.assertEqual(svodgit.head(empty), remote)


if __name__ == "__main__":
    unittest.main()


class SplitTests(Base):
    """Свод-0, шаг 4: глобальный репозиторий это контракт целиком, личный
    ищется, машина заказчика живёт без личного."""

    def test_global_rule_is_saved_and_enters_the_contract(self):
        body = fresh_record("feedback_short", "отвечать владельцу коротко",
                            "как коротко отвечать владельцу", "Коротко.\n")
        code, result = self.fed.remember("a", "global", "short-1", body,
                                         {"record_slug": "feedback_short"})
        self.assertEqual(result["state"], "saved", result)
        self.assertIn("memory/feedback_short.md", self.fed.origin_tree("global"))
        self.assertEqual(result["warnings"], [])

    def test_global_refuses_a_hidden_record(self):
        body = record("feedback_hidden", type="feedback", title="Скрытое", index="скрытое правило",
                      listed="false", source="разговор", observed_at="2026-09-04",
                      probe="что скрыто", body="Скрыто.\n")
        code, result = self.fed.remember("a", "global", "hidden-1", body,
                                         {"record_slug": "feedback_hidden"})
        self.assertEqual(code, mr.EXIT_FAILED, result)
        self.assertIn("контракт", result["reason"])

    def test_global_refuses_a_contract_over_the_delivery_limit(self):
        # Строка индекса режется роутером до 300 символов, поэтому потолок
        # 2 600 набирается числом правил: двенадцать по 280 символов.
        words = ("один", "два", "три", "четыре", "пять", "шесть",
                 "семь", "восемь", "девять", "десять", "одиннадцать", "двенадцать")
        changes = [{"operation": "put", "path": f"memory/feedback_{i}.md",
                    "content": record(f"feedback_{i}", type="feedback", title=f"Правило {w}",
                                      index="х" * 280, source="разговор",
                                      observed_at="2026-09-04", probe=f"как правило {w}",
                                      body="Текст.\n").decode("utf-8")}
                   for i, w in enumerate(words)]
        code, result = self.fed.remember("a", "global", "long-1",
                                         json.dumps({"changes": changes}).encode(),
                                         content_type="manifest")
        self.assertEqual(code, mr.EXIT_FAILED, result)
        self.assertIn("потолка", result["reason"])

    def test_global_refuses_an_unresolved_wiki_link(self):
        body = fresh_record("feedback_link", "правило со ссылкой наружу",
                            "как правило со ссылкой наружу", "См. [[nowhere]].\n")
        code, result = self.fed.remember("a", "global", "link-1", body,
                                         {"record_slug": "feedback_link"})
        self.assertEqual(code, mr.EXIT_FAILED, result)
        self.assertIn("unresolved wiki link", result["reason"])

    def test_global_client_name_is_a_warning_not_a_refusal(self):
        body = fresh_record("feedback_named", "правило про пример заказчика",
                            "как правило про пример заказчика", "Пример: у Acme так.\n")
        code, result = self.fed.remember("a", "global", "named-1", body,
                                         {"record_slug": "feedback_named"})
        self.assertEqual(result["state"], "saved", result)
        self.assertTrue(any("acme" in w for w in result["warnings"]), result["warnings"])

    def test_personal_link_to_a_global_rule_is_only_a_warning(self):
        body = fresh_record("reference_kettle", "как кипятить воду в чайнике",
                            "кипятить воду чайник", "Чайник. См. [[feedback_words]].\n")
        code, result = self.fed.remember("a", "personal", "kettle-1", body,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(result["state"], "saved", result)
        self.assertTrue(any("unresolved wiki link" in w for w in result["warnings"]), result)

    def test_machine_without_personal_repository(self):
        data = self.fed.clone("c", personal=False)
        result = ms.status(data_root=data, state=self.fed.states["c"])
        self.assertEqual({r["scope"] for r in result["repos"]}, {"global", "clients/acme"})
        code, res = self.fed.remember("c", "personal", "kettle-1", NEW_BODY,
                                      {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_ERROR, res)
        self.assertIn("нет на этой машине", res["reason"])
        body = record("acme_vpn", type="project", title="VPN Acme", index="vpn acme",
                      source="разговор", observed_at="2026-09-04",
                      probe="как попасть в сеть заказчика по ssh", listed="false",
                      body="Доступ по ssh через бастион.\n")
        projection = {"record_slug": "acme_vpn", "index_section": "Доступы",
                      "index_line": "- [[acme_vpn]] ssh через бастион"}
        code, res = self.fed.remember("c", "clients/acme", "acme-vpn-1", body, projection)
        self.assertEqual(res["state"], "saved", res)
        outcomes = ms.sync_all(data_root=data, today=TODAY, state=self.fed.states["c"])
        self.assertEqual({o["scope"] for o in outcomes}, {"global", "clients/acme"})
        self.assertTrue(all(not o["problems"] for o in outcomes), outcomes)


class ReviewRegressionTests(Base):
    """Ревью публикации 07.09.2026: каждый тест это воспроизведённый дефект."""

    def _older_pythons(self) -> list[str]:
        found = []
        for name in ("python3.10", "python3.11"):
            path = shutil.which(name)
            if path:
                found.append(path)
        for path in sorted(Path.home().glob(".local/share/uv/python/cpython-3.1[01]*/bin/python3.1?")):
            found.append(str(path))
        return found

    def test_sources_compile_on_python_310_and_311(self):
        interpreters = self._older_pythons()
        if not interpreters:
            self.skipTest("нет интерпретатора 3.10/3.11 для проверки синтаксиса")
        files = [f for f in (*(REPO_SOURCE / "lib").glob("*.py"), *(REPO_SOURCE / "bin").iterdir(),
                             *(REPO_SOURCE / "githooks").iterdir(), *(REPO_SOURCE / "tests").glob("*.py"))
                 if f.is_file()]
        for python in interpreters:
            for file in files:
                result = subprocess.run([python, "-m", "py_compile", str(file)],
                                        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(result.returncode, 0, f"{python}: {file.name}: {result.stderr}")

    def test_manual_rebase_is_left_to_the_operator(self):
        root_b = self.fed.root("b")
        path = "memory/reference_printer.md"
        self.manual_commit(root_b, path, fresh_record(
            "reference_printer", "как чинить зелёный принтер", "чем чинить принтер",
            "Версия Б: зелёный принтер.\n"), "memory: printer-b")
        self.fed.remember("a", "personal", "printer-a", fresh_record(
            "reference_printer", "как чинить зелёный принтер", "чем чинить принтер",
            "Версия А: зелёный принтер.\n"), {"record_slug": "reference_printer"})
        sh(root_b, "fetch", "--quiet", "origin")
        rebase = subprocess.run(["git", "-C", str(root_b), "rebase", "origin/main"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(rebase.returncode, 0, "конфликт ожидался")
        self.assertTrue(svodgit.rebase_in_progress(root_b))
        resolved = fresh_record("reference_printer", "как чинить зелёный принтер",
                                "чем чинить принтер", "Версии А и Б сведены: зелёный принтер.\n")
        (root_b / path).write_bytes(resolved)
        sh(root_b, "add", "--", path)
        outcome = self.fed.sync("b")
        self.assertTrue(svodgit.rebase_in_progress(root_b), "таймер не отменил ручной rebase")
        self.assertTrue(any("ручной rebase" in p for p in outcome["problems"]), outcome)
        self.assertEqual((root_b / path).read_bytes(), resolved, "разрешение конфликта цело")
        code, result = self.fed.remember("b", "personal", "kettle-1", NEW_BODY,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_PENDING, result)
        self.assertIn("ручной rebase", result["reason"])
        self.assertTrue(svodgit.rebase_in_progress(root_b))
        env = dict(os.environ, GIT_EDITOR="true")
        subprocess.run(["git", "-C", str(root_b), "rebase", "--continue"], check=True, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        outcome = self.fed.sync("b")
        self.assertEqual(outcome["problems"], [], outcome)
        self.assertEqual(svodgit.branch(root_b), "main")
        self.assertIn("сведены".encode("utf-8"), self.fed.origin_tree()[path])

    def test_writer_does_not_publish_unverified_commit_ahead_of_server(self):
        root_b = self.fed.root("b")
        self.manual_commit(root_b, "memory/reference_bad.md",
                           record("reference_bad", type="reference", title="Плохая",
                                  index="плохая запись без источника",
                                  probe="что за плохая запись без источника",
                                  body="Без происхождения.\n"),
                           "memory: bad", no_verify=True)
        code, result = self.fed.remember("b", "personal", "kettle-1", NEW_BODY,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_PENDING, result)
        self.assertIn("красное", result["reason"])
        self.assertNotIn("memory/reference_bad.md", self.fed.origin_tree())
        self.assertNotIn("memory/reference_kettle.md", self.fed.origin_tree())

    def test_check_that_cannot_run_is_a_refusal_with_words(self):
        root = self.fed.root("a", "clients/acme")
        self.manual_commit(root, "memory/topics/acme.md",
                           b"# Acme\n\n## \xd0\x9e\xd0\xb1\xd0\xb7\xd0\xbe\xd1\x80\n\n\xff\xfe\n",
                           "rollup broken", no_verify=True)
        code, result = self.fed.remember(
            "a", "clients/acme", "acme-1",
            fresh_record("reference_gate", "как открыть ворота", "открыть ворота", "Кодом.\n"),
            {"record_slug": "reference_gate", "index_line": "- [Ворота](reference_gate.md) - как открыть",
             "index_section": "Обзор"})
        self.assertEqual(code, mr.EXIT_FAILED, result)
        self.assertIn("проверка не выполнилась", result["reason"])
        self.assertEqual(len(self.failed("a", "clients/acme")), 1)
        self.assertEqual(self.pending("a", "clients/acme"), [])
        self.assertEqual(svodgit.dirty_paths(root), set())
        outcome = self.fed.sync("a", "clients/acme")
        self.assertNotIn("traceback", outcome)

    def test_refusal_before_candidate_is_recorded_in_failed(self):
        body = fresh_record("reference_gate", "как открыть ворота", "открыть ворота", "Кодом.\n")
        code, result = self.fed.remember("a", "clients/acme", "acme-1", body,
                                         {"record_slug": "reference_gate", "index_line": "- [Ворота](reference_gate.md) - x"})
        self.assertEqual(code, mr.EXIT_FAILED, result)
        self.assertEqual(len(self.failed("a", "clients/acme")), 1)
        self.assertIn("index_section", svodgit.read_json(self.failed("a", "clients/acme")[0])["reason"])
        code, result = self.fed.remember("a", "personal", "../x", NEW_BODY, {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_FAILED, result)
        self.assertNotIn("file", result, "небезопасный id файла не получает")
        self.assertEqual(self.failed("a"), [])

    def test_pointer_moves_to_the_named_section(self):
        rollup = "# Acme\n\n## Обзор\n\nЗаказчик.\n\n## Доступы\n\n- [Ворота](reference_gate.md) - старый\n"
        new = mr.insert_rollup_pointer(rollup, "Обзор", "- [Ворота](reference_gate.md) - новый")
        self.assertEqual(new, "# Acme\n\n## Обзор\n\nЗаказчик.\n- [Ворота](reference_gate.md) - новый\n\n## Доступы\n\n")
        same = mr.insert_rollup_pointer(rollup, "Доступы", "- [Ворота](reference_gate.md) - новый")
        self.assertIn("- новый\n", same)
        self.assertNotIn("- старый", same)
        with self.assertRaises(mr.Refusal):
            mr.insert_rollup_pointer(rollup, "Нет такого", "- [Ворота](reference_gate.md) - новый")

    def test_base_is_taken_from_main_not_from_a_detached_head(self):
        root_a = self.fed.root("a")
        self.fed.remember("a", "personal", "kettle-1", NEW_BODY, {"record_slug": "reference_kettle"})
        sh(root_a, "checkout", "--quiet", "--detach", "HEAD~1")
        updated = fresh_record("reference_kettle", "как кипятить воду в чайнике",
                               "кипятить воду чайник", "Чайник: версия два.\n")
        code, result = self.fed.remember("a", "personal", "kettle-2", updated,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_SAVED, result)
        self.assertIn("версия два".encode("utf-8"), self.fed.origin_tree()["memory/reference_kettle.md"])

    def test_git_pathspecs_are_literal(self):
        root_a = self.fed.root("a")
        (root_a / "memory" / "reference_star.md").write_bytes(NEW_BODY)
        result = svodgit.git(root_a, "add", "-A", "--", "memory/*.md", check=False)
        self.assertNotEqual(result.returncode, 0, "шаблон не раскрылся в имена записей")
        self.assertEqual(sh(root_a, "diff", "--cached", "--name-only"), "")

    def test_missing_config_is_words_not_a_traceback(self):
        env = dict(os.environ)
        env.pop("MEMORY_CONFIG_DIR", None)
        env["MEMORY_REPO"] = str(self.fed.machines["a"])
        env["MEMORYCTL_STATE_DIR"] = str(self.fed.states["a"])
        hook = subprocess.run([sys.executable, str(REPO_SOURCE / "bin" / "memory-context"), "session-start"],
                              input='{"session_id": "s1", "cwd": "/"}', text=True, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(hook.returncode, 0, hook.stderr)
        self.assertIn("временно недоступна", hook.stdout)
        self.assertIn("MEMORY_CONFIG_DIR", hook.stdout)
        self.assertNotIn("Traceback", hook.stderr)
        status = subprocess.run([sys.executable, str(REPO_SOURCE / "bin" / "memory"), "status"],
                                text=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(status.returncode, 0)
        self.assertIn("MEMORY_CONFIG_DIR", status.stderr)
        self.assertNotIn("Traceback", status.stderr)

    def test_status_names_a_data_directory_without_git(self):
        shutil.rmtree(self.fed.root("a", "clients/acme") / ".git")
        result = ms.status(data_root=self.fed.machines["a"], state=self.fed.states["a"])
        self.assertFalse(result["ok"])
        acme = next(r for r in result["repos"] if r["scope"] == "clients/acme")
        self.assertIn("без git-репозитория", acme["problem"])

    def test_long_header_keeps_expiry_and_fenced_headings_are_not_sections(self):
        import memorycontext as mc
        root_a = self.fed.root("a")
        probe = "как открыть ворота " * 300
        (root_a / "memory" / "reference_gate.md").write_bytes(record(
            "reference_gate", type="reference", title="Ворота", index="как открыть ворота",
            source="разговор", observed_at="2026-09-04", probe=f'"{probe.strip()}"',
            valid_until="2020-01-01", body="Кодом.\n"))
        entry = next(e for e in mc.parse_index(mc.build_index(root_a))
                     if e.slug.removesuffix(".md") == "reference_gate")
        self.assertTrue(mc._entry_expired(root_a, entry, TODAY), "длинная шапка не прячет срок")
        sections = mc.parse_sections("## Обзор\n\n```sh\n## не заголовок\n```\nхвост\n\n## Доступы\n\nssh\n")
        self.assertEqual([s.title for s in sections], ["Обзор", "Доступы"])
        self.assertIn("хвост", sections[0].text)

    def test_measurement_fingerprint_covers_the_header_parser(self):
        import memoryeval
        covered = {p.resolve() for p in memoryeval.MEASUREMENT_FILES}
        self.assertIn(Path(mv.__file__).resolve(), covered)

    def test_unreachable_records_tolerate_a_non_utf8_rollup(self):
        orphans = mv.unreachable_records({"memory/topics/acme.md": b"\xff\xfe## x\n",
                                          "memory/reference_gate.md": b"---\n---\n"},
                                         {"topics/acme.md"})
        self.assertIn("reference_gate.md", orphans)

    def test_reader_locks_wait_for_a_client_writer(self):
        import threading
        import time
        import memoryctl
        root = self.fed.root("a", "clients/acme")
        released = threading.Event()

        def hold():
            with svodgit.lock(root, exclusive=True):
                time.sleep(1.0)
            released.set()

        worker = threading.Thread(target=hold)
        worker.start()
        time.sleep(0.2)
        started = time.monotonic()
        with memoryctl.reader_locks([self.fed.root("a"), root]):
            self.assertTrue(released.is_set(), "чтение началось только после писателя")
        self.assertGreaterEqual(time.monotonic() - started, 0.5)
        worker.join()

    def test_push_timeout_covers_the_hook_scanner(self):
        self.assertGreaterEqual(svodgit.PUSH_TIMEOUT_SEC,
                                svodgit.NETWORK_TIMEOUT_SEC + svodgit.SCANNER_TIMEOUT_SEC)


class CodexRoundTests(Base):
    """Замечания независимой проверки 07.09.2026 к правкам по ревью."""

    def test_early_refusal_keeps_a_waiting_candidate(self):
        root_a = self.fed.root("a")
        sh(root_a, "remote", "set-url", "origin", str(self.fed.base / "nowhere.git"))
        code, _ = self.fed.remember("a", "personal", "kettle-1", NEW_BODY, {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_PENDING)
        other = fresh_record("reference_toaster", "как поджарить хлеб", "поджарить хлеб", "Тостер.\n")
        code, result = self.fed.remember("a", "personal", "kettle-1", other, {"record_slug": "reference_toaster"})
        self.assertEqual(code, mr.EXIT_FAILED, result)
        self.assertIn("другим телом", result["reason"])
        self.assertEqual(len(self.pending("a")), 1, "ожидающий кандидат не стёрт ранним отказом")
        self.assertEqual(self.failed("a"), [])

    def test_partial_write_is_rolled_back(self):
        root_a = self.fed.root("a")
        manifest = {"changes": [
            {"operation": "put", "path": "memory/reference_kettle.md", "content": NEW_BODY.decode()},
            {"operation": "put", "path": "memory/reference_toaster.md",
             "content": fresh_record("reference_toaster", "как поджарить хлеб", "поджарить хлеб", "Тостер.\n").decode()},
        ]}
        original = mr._write

        def broken_write(root, files):
            first = sorted(files)[0]
            (root / first).write_bytes(files[first])
            raise OSError("диск переполнен")

        with mock.patch.object(mr, "_write", broken_write):
            code, result = self.fed.remember("a", "personal", "pair-1", json.dumps(manifest).encode(),
                                             content_type="manifest")
        self.assertIs(mr._write, original)
        self.assertEqual(code, mr.EXIT_FAILED, result)
        self.assertIn("OSError", result["reason"])
        self.assertEqual(svodgit.dirty_paths(root_a), set(), "начатая запись откачена")
        self.assertEqual(len(self.failed("a")), 1)

    def test_error_after_commit_keeps_the_candidate_pending(self):
        root_a = self.fed.root("a")
        with mock.patch.object(mr, "publish", side_effect=RuntimeError("учёт упал")):
            code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY, {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_PENDING, result)
        self.assertIn("после коммита", result["reason"])
        self.assertIn("memory/reference_kettle.md", svodgit.read_tree(root_a, svodgit.head(root_a)))
        self.assertEqual(self.failed("a"), [])
        outcome = self.fed.sync("a")
        self.assertEqual([c["state"] for c in outcome["candidates"]], ["delivered"], outcome)
        self.assertIn("memory/reference_kettle.md", self.fed.origin_tree())

    def test_pointer_lands_after_the_last_line_of_the_section(self):
        rollup = "## A\nfirst\nlast\n## B\n- [x](reference_x.md) - старый\n"
        moved = mr.insert_rollup_pointer(rollup, "A", "- [x](reference_x.md) - новый")
        self.assertEqual(moved, "## A\nfirst\nlast\n- [x](reference_x.md) - новый\n## B\n")

    def test_fenced_examples_are_neither_sections_nor_pointers(self):
        import memorycontext as mc
        text = ("## Обзор\n\n````md\n```\n## пример\n- [x](reference_x.md) - пример\n```\n````\n"
                "хвост\n\n## Доступы\n\nssh\n")
        sections = mc.parse_sections(text)
        self.assertEqual([s.title for s in sections], ["Обзор", "Доступы"])
        self.assertIn("хвост", sections[0].text)
        moved = mr.insert_rollup_pointer(text, "Доступы", "- [x](reference_x.md) - новый")
        self.assertIn("- [x](reference_x.md) - пример\n", moved, "пример в коде не тронут")
        self.assertTrue(moved.endswith("ssh\n- [x](reference_x.md) - новый\n"), moved)

    def test_unwritable_lock_file_does_not_stop_a_reader(self):
        import memoryctl
        root = self.fed.root("a", "clients/acme")
        lock_file = root / ".git" / svodgit.LOCK_NAME
        lock_file.touch()
        lock_file.chmod(0)
        try:
            with svodgit.lock(root, exclusive=False) as taken:
                self.assertIsNone(taken, "замка нет, это не занятость")
            with memoryctl.reader_locks([self.fed.root("a"), root]) as all_taken:
                self.assertTrue(all_taken, "чтение без замка там, где замка нет, согласовано")
            with self.assertRaises(svodgit.GitError):
                with svodgit.lock(root, exclusive=True):
                    pass
        finally:
            lock_file.chmod(0o600)

    def test_heal_aborts_only_the_engine_marked_rebase(self):
        root_b = self.fed.root("b")
        path = "memory/reference_printer.md"
        self.manual_commit(root_b, path, fresh_record(
            "reference_printer", "как чинить зелёный принтер", "чем чинить принтер",
            "Версия Б: зелёный принтер.\n"), "memory: printer-b")
        self.fed.remember("a", "personal", "printer-a", fresh_record(
            "reference_printer", "как чинить зелёный принтер", "чем чинить принтер",
            "Версия А: зелёный принтер.\n"), {"record_slug": "reference_printer"})
        sh(root_b, "fetch", "--quiet", "origin")
        subprocess.run(["git", "-C", str(root_b), "rebase", "origin/main"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertTrue(svodgit.rebase_in_progress(root_b))
        self.assertEqual(svodgit.heal(root_b), [], "чужой rebase без метки не трогается")
        self.assertTrue(svodgit.rebase_in_progress(root_b))
        svodgit.engine_rebase_marker(root_b).write_text("x")
        self.assertEqual(svodgit.heal(root_b), ["rebase --abort"])
        self.assertFalse(svodgit.rebase_in_progress(root_b))
        self.assertFalse(svodgit.engine_rebase_marker(root_b).exists())
        self.assertEqual(svodgit.branch(root_b), "main")

    def test_fence_opener_with_backtick_in_info_is_text_and_unclosed_fence_refuses(self):
        import memorycontext as mc
        sections = mc.parse_sections("## A\n```foo`bar\n## B\ntext\n")
        self.assertEqual([s.title for s in sections], ["A", "B"])
        with self.assertRaises(mr.Refusal):
            mr.insert_rollup_pointer("## A\n```\nкод без конца\n", "A", "- [x](reference_x.md) - новый")


class CleanupTests(Base):
    """Долги чистоты 07.09.2026: горячий путь хука без лишних запусков git."""

    def test_hook_hot_path_runs_git_once_per_index_root(self):
        import memorycontext as mc
        data, state = self.fed.machines["a"], self.fed.states["a"] / "claude"
        seen: list[str] = []
        original = svodgit.git

        def counting(root, *args, **kw):
            seen.append(" ".join(args[:2]))
            return original(root, *args, **kw)

        with mock.patch.object(svodgit, "git", counting):
            session = mc.handle_session(
                {"session_id": "hot-1", "cwd": str(data), "source": "startup"}, data, state)
            session_calls = list(seen)
            seen.clear()
            prompt = mc.handle_prompt(
                {"session_id": "hot-1", "cwd": str(data), "prompt": "как чинить зелёный принтер"},
                data, state)
        self.assertIn("[Общая память агента]", session["hookSpecificOutput"]["additionalContext"])
        self.assertIn("Зелёный принтер чинится молотком",
                      prompt["hookSpecificOutput"]["additionalContext"])
        # Ревизия корня индекса это один rev-parse: глобальный и личный на
        # старте сессии, личный на запросе; замки и карта обходятся без git.
        self.assertEqual(len(session_calls), 2, session_calls)
        self.assertEqual(len(seen), 1, seen)
