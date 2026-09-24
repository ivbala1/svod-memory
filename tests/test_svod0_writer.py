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
import time
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

    def dry(self, machine: str, scope: str, cid: str, body: bytes, projection=None,
            content_type="markdown"):
        return mr.run_remember(scope=scope, candidate_id=cid, source="test", session="s",
                               content_type=content_type, body=body, projection=projection,
                               data_root=self.fed.machines[machine],
                               state=self.fed.states[machine], today=TODAY, dry_run=True)

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

    def test_fact_shadowing_other_record_is_saved_with_stand_warning(self):
        """Новая запись перебила чужую по её вопросу стенда: факт принят, а
        предупреждение с вопросом и перебитой записью доходит до автора."""
        questions = {"questions": [{"id": "q2", "group": "tuned", "text": "принтер в офисе",
                                    "expect": "reference_printer", "markers": ["принтер"]}],
                     "negatives": []}
        (self.fed.config / "eval_questions.json").write_text(
            json.dumps(questions, ensure_ascii=False))
        configpaths._reset_for_tests()
        body = record("reference_office", type="reference", title="Принтер в офисе",
                      index="принтер в офисе сломан", source="разговор",
                      observed_at="2026-09-04", probe="сломался принтер в офисе",
                      body="Офисный принтер сдан в ремонт.\n")
        code, result = self.dry("a", "personal", "office-dry", body,
                                {"record_slug": "reference_office"})
        self.assertEqual((code, result["state"]), (mr.EXIT_SAVED, "checked"), result)
        self.assertTrue(any("q2" in w and "reference_printer" in w
                            for w in result["warnings"]), result)
        code, result = self.fed.remember("a", "personal", "office-1", body,
                                         {"record_slug": "reference_office"})
        self.assertEqual((code, result["state"]), (mr.EXIT_SAVED, "saved"), result)
        self.assertTrue(any("q2" in w and "reference_printer" in w
                            for w in result["warnings"]), result)

    def test_fact_firing_stand_negative_is_saved_with_warning(self):
        body = fresh_record("reference_mars", "погода на марсе и прогноз",
                            "какая погода на марсе", "На Марсе холодно.\n")
        code, result = self.fed.remember("a", "personal", "mars-1", body,
                                         {"record_slug": "reference_mars"})
        self.assertEqual((code, result["state"]), (mr.EXIT_SAVED, "saved"), result)
        self.assertTrue(any("n1" in w for w in result["warnings"]), result)

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
            health, notes = ms.repo_health("personal", root, config)
        # Порог и дрейф это работа для владельца, а не сломанная доставка:
        # они видны заметками и итог статуса не красят.
        self.assertEqual(health, [])
        self.assertTrue(any("выше порога" in n for n in notes), notes)
        self.assertTrue(any("дрейф: acme 1" in n for n in notes), notes)
        self.assertTrue(ms._repo_ok({"branch": "main", "health": [], "notes": notes}))
        client = self.fed.root("a", "clients/acme")
        tree = {"memory/topics/acme.md": ("# Acme\n\n## Обзор\n\n" + "д" * 4000).encode()}
        with mock.patch.object(svodgit, "read_tree", return_value=tree):
            health, notes = ms.repo_health("clients/acme", client, config)
        self.assertTrue(any("при потолке 3400" in h for h in health), health)
        nudge = ms.format_nudge({"repos": [{"scope": "clients/acme", "health": health}]})
        self.assertIn("сводка", nudge)
        self.assertNotIn("\n", nudge)
        # Раздел под потолком, но впритык: запас виден заранее, а не из отказа.
        tree = {"memory/topics/acme.md": ("# Acme\n\n## Обзор\n\n" + "д" * 3300).encode()}
        with mock.patch.object(svodgit, "read_tree", return_value=tree):
            health, notes = ms.repo_health("clients/acme", client, config)
        self.assertEqual(health, [])
        self.assertTrue(any(n.startswith("запас: раздел") for n in notes), notes)


    def test_index_over_hard_ceiling_is_a_note_not_broken_delivery(self):
        """Личный индекс в сессию не отдаётся и писатель по его размеру не
        отказывает: превышение потолка это заметка, итог статуса не красный."""
        topics = json.loads(json.dumps(TOPICS))
        topics["budget"] = {"softBytes": 1, "softLines": 1, "hardBytes": 2, "hardLines": 1}
        config = mv.Config(topics=json.dumps(topics).encode())
        health, notes = ms.repo_health("personal", self.fed.root("a"), config)
        self.assertEqual(health, [])
        self.assertTrue(any("выше потолка" in n for n in notes), notes)

    def test_user_catalog_headroom_is_a_note(self):
        """Единственная часть индекса, которая уезжает в сессию, это каталог
        раздела User: его переполнение видно заметкой, итог не красный."""
        import memorycontext
        config = mv.Config(topics=json.dumps(TOPICS).encode())
        with mock.patch.object(memorycontext, "USER_CATALOG_LIMIT", 60):
            health, notes = ms.repo_health("personal", self.fed.root("a"), config)
        self.assertEqual(health, [])
        self.assertTrue(any("каталог сведений о владельце" in n for n in notes), notes)

    def test_expired_dates_are_notes(self):
        """Просроченный valid_until молча уводит запись из выдачи, review_after
        доставку не меняет: оба срока видны заметками статуса и месячной
        строкой подсказки старта, итог не красят."""
        config = mv.Config(topics=json.dumps(TOPICS).encode())
        root = self.fed.root("a")
        tree = svodgit.read_tree(root, "HEAD")
        tree["memory/reference_old.md"] = record(
            "reference_old", type="reference", title="Старое", index="старое",
            valid_until="2026-01-31", body="Старое.")
        tree["memory/reference_review.md"] = record(
            "reference_review", type="reference", title="Обзор", index="обзор",
            review_after="2026-01-15", body="Пересмотреть.")
        tree["memory/reference_fresh.md"] = record(
            "reference_fresh", type="reference", title="Свежее", index="свежее",
            valid_until="2999-12-31", review_after="2999-12-31", body="Свежее.")
        tree["memory/reference_both.md"] = record(
            "reference_both", type="reference", title="Оба", index="оба",
            valid_until="2026-01-01", review_after="2026-01-02", body="Оба срока.")
        tree["memory/reference_folded.md"] = record(
            "reference_folded", type="reference", title="Свёрнутое", index="свёрнутое",
            valid_until="2026-01-01", review_after="2026-01-01", listed="false",
            body="Свёрнуто владельцем.")
        tree["memory/reference_broken.md"] = record(
            "reference_broken", type="reference", title="Битая", index="битая",
            valid_until="вчера", review_after="2026-13-40", body="Битая дата.")
        import memorycontext
        with mock.patch.object(svodgit, "read_tree", return_value=tree), \
                mock.patch.object(memorycontext, "today_utc",
                                  return_value=dt.date(2026, 2, 1)):
            health, notes = ms.repo_health("personal", root, config)
        self.assertEqual(health, [])
        self.assertIn("просрочено: valid_until истёк у reference_both, reference_old", notes)
        self.assertIn("обзор: review_after прошёл у reference_both, reference_review", notes)
        self.assertFalse(any("reference_fresh" in n or "reference_broken" in n
                             or "reference_folded" in n for n in notes), notes)
        # Граница включительная у обоих полей: в день valid_until запись ещё
        # действует, в день review_after «после» ещё не наступило.
        expired, review = ms.dated_records(tree, dt.date(2026, 1, 15))
        self.assertEqual(expired, ["reference_both"])
        self.assertEqual(review, ["reference_both"])
        expired, review = ms.dated_records(tree, dt.date(2026, 1, 31))
        self.assertEqual(expired, ["reference_both"])
        self.assertEqual(review, ["reference_both", "reference_review"])
        self.assertEqual(ms.format_nudge({"repos": [{"scope": "personal", "notes": notes}]}), "")
        nudge = ms.format_nudge({"repos": [{"scope": "personal", "notes": notes}]}, monthly=True)
        self.assertIn("просрочено", nudge)
        self.assertTrue(nudge.endswith("/memory-compact"), nudge)


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

    def silent_ssh(self, root: Path) -> Path:
        """origin по ssh, а ssh молчит, как при неподтверждённом окне
        ssh-агента. Отдаёт файл, куда ssh запишет свой pid."""
        pid_file = self.fed.base / "ssh.pid"
        fake = self.fed.base / "silent-ssh"
        fake.write_text(f"#!/bin/sh\necho $$ > '{pid_file}'\nexec sleep 600\n")
        fake.chmod(0o755)
        sh(root, "remote", "set-url", "origin", "ssh://git@example.invalid/personal.git")
        patches = [mock.patch.dict(os.environ, {"GIT_SSH_COMMAND": str(fake)}),
                   mock.patch.object(svodgit, "NETWORK_TIMEOUT_SEC", 1.0)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return pid_file

    def assert_gone(self, pid_file: Path) -> None:
        pid = int(pid_file.read_text())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
                state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
            except (ProcessLookupError, FileNotFoundError):
                return
            if state == "Z":
                return
            time.sleep(0.1)
        self.fail(f"ssh {pid} пережил git")

    def test_silent_ssh_is_no_network_and_dies_with_git(self):
        root = self.fed.root("a")
        pid_file = self.silent_ssh(root)
        started = time.monotonic()
        fetched, why = svodgit.fetch(root)
        self.assertFalse(fetched)
        self.assertIn("не ответил", why)
        self.assertLess(time.monotonic() - started, 10)
        self.assert_gone(pid_file)

    def test_writer_behind_silent_ssh_commits_locally_and_frees_the_lock(self):
        root = self.fed.root("a")
        pid_file = self.silent_ssh(root)
        head = svodgit.head(root)
        code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_PENDING, result)
        self.assertIn("сети нет", result["reason"])
        self.assertNotEqual(svodgit.head(root), head)
        self.assert_gone(pid_file)
        with svodgit.lock(root, exclusive=True, wait=0.5) as taken:
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
        self.assertIn("--section", svodgit.read_json(self.failed("a", "clients/acme")[0])["reason"])
        code, result = self.fed.remember("a", "personal", "../x", NEW_BODY, {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_FAILED, result)
        self.assertNotIn("file", result, "небезопасный id файла не получает")
        self.assertEqual(self.failed("a"), [])

    def test_pointer_lands_in_the_named_section_and_leaves_the_rest_alone(self):
        rollup = "# Acme\n\n## Обзор\n\nЗаказчик.\n\n## Доступы\n\n- [Ворота](reference_gate.md) - старый\n"
        new, слова = mr.insert_rollup_pointer(rollup, "Обзор", "- [Ворота](reference_gate.md) - новый")
        # Строка в чужом разделе остаётся на месте и называется словами:
        # молчаливое удаление теряло принятые факты заказчика.
        self.assertIn("- [Ворота](reference_gate.md) - старый", new)
        self.assertIn("- [Ворота](reference_gate.md) - новый", new)
        self.assertTrue(any("упомянута ещё в разделах" in w and "Доступы" in w for w in слова), слова)
        same, слова = mr.insert_rollup_pointer(rollup, "Доступы",
                                               "- [Ворота](reference_gate.md) - новый")
        self.assertIn("- новый\n", same)
        self.assertNotIn("- старый", same)
        self.assertTrue(any("заменена прежняя строка" in w for w in слова), слова)
        with self.assertRaises(mr.Refusal):
            mr.insert_rollup_pointer(rollup, "Нет такого", "- [Ворота](reference_gate.md) - новый")

    def test_prose_that_merely_links_the_record_survives(self):
        rollup = ("# Acme\n\n## Обзор\n\nСхему сети смотреть в [[acme_dns]], она главная.\n"
                  "\n## Доступы\n\nПо ssh.\n")
        new, слова = mr.insert_rollup_pointer(rollup, "Доступы", "- [[acme_dns]] доступ по ssh")
        self.assertIn("Схему сети смотреть в [[acme_dns]], она главная.", new)
        self.assertIn("- [[acme_dns]] доступ по ssh", new)
        self.assertTrue(слова)

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
        # Без переменной конфигурация ищется в ~/.agent-memory-config, а на
        # машине автора она есть: домашний каталог пуст, чтобы её не найти.
        env["HOME"] = str(self.fed.base / "emptyhome")
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
        moved, _ = mr.insert_rollup_pointer(rollup, "A", "- [x](reference_x.md) - новый")
        self.assertEqual(moved,
                         "## A\nfirst\nlast\n- [x](reference_x.md) - новый\n"
                         "## B\n- [x](reference_x.md) - старый\n")

    def test_fenced_examples_are_neither_sections_nor_pointers(self):
        import memorycontext as mc
        text = ("## Обзор\n\n````md\n```\n## пример\n- [x](reference_x.md) - пример\n```\n````\n"
                "хвост\n\n## Доступы\n\nssh\n")
        sections = mc.parse_sections(text)
        self.assertEqual([s.title for s in sections], ["Обзор", "Доступы"])
        self.assertIn("хвост", sections[0].text)
        moved, _ = mr.insert_rollup_pointer(text, "Доступы", "- [x](reference_x.md) - новый")
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


class PrecheckTests(Base):
    """Волна 2, шаг 2: вердикт считается до замка, сухой прогон не оставляет
    следа, а проход под замком не проверяет то же самое дерево второй раз."""

    RED_BODY = record("reference_kettle", type="reference", title="Чайник",
                      index="как кипятить воду", body="Без происхождения.\n")

    def test_dry_run_gives_the_verdict_without_lock_commit_or_trace(self):
        root = self.fed.root("a")
        before = svodgit.head(root)
        code, result = self.dry("a", "personal", "kettle-dry", NEW_BODY,
                                {"record_slug": "reference_kettle"})
        self.assertEqual((code, result["state"]), (mr.EXIT_SAVED, "checked"), result)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["base"], before)
        self.assertEqual(svodgit.head(root), before)
        self.assertEqual(svodgit.dirty_paths(root), set())
        self.assertFalse((root / "memory" / "reference_kettle.md").exists())
        self.assertEqual(self.pending("a"), [])
        self.assertEqual(self.failed("a"), [])

    def test_dry_run_names_the_violation_and_leaves_nothing_behind(self):
        code, result = self.dry("a", "personal", "kettle-dry-red", self.RED_BODY,
                                {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertEqual(result["state"], "failed")
        self.assertIn("source", result["reason"])
        self.assertEqual(self.pending("a"), [])
        self.assertEqual(self.failed("a"), [])
        self.assertEqual(svodgit.dirty_paths(self.fed.root("a")), set())

    def test_dry_run_sees_the_whole_corpus_not_only_candidate_files(self):
        """Увод предшественника: на одних файлах кандидата стенд не запустился
        бы вовсе, на копии дерева основы он видит потерю эталона."""
        manifest = json.dumps({"changes": [{"operation": "remove",
                                            "path": "memory/reference_printer.md"}]})
        code, result = self.dry("a", "personal", "drop-printer", manifest.encode("utf-8"),
                                content_type="manifest")
        self.assertEqual(code, mr.EXIT_FAILED, result)
        self.assertIn("стенд", result["reason"])
        self.assertEqual(self.failed("a"), [])

    def test_green_candidate_is_verified_once(self):
        seen: list[str] = []
        original = mv.check

        def counting(*args, **kwargs):
            seen.append(kwargs.get("root", ""))
            return original(*args, **kwargs)

        with mock.patch.object(mv, "check", counting):
            code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                             {"record_slug": "reference_kettle"})
        self.assertEqual(result["state"], "saved", result)
        self.assertEqual(seen, ["personal"], seen)
        self.assertIn("проверено до замка, уходит то же дерево", result["notes"])

    def test_matching_red_verdict_refuses_before_touching_the_worktree(self):
        written: list[tuple] = []
        original = mr._write

        def watching(*args, **kwargs):
            written.append(args)
            return original(*args, **kwargs)

        with mock.patch.object(mr, "_write", watching):
            code, result = self.fed.remember("a", "personal", "kettle-red", self.RED_BODY,
                                             {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertEqual(written, [])
        self.assertIn("source", result["reason"])
        self.assertEqual(len(self.failed("a")), 1)
        self.assertEqual(self.pending("a"), [])
        self.assertEqual(svodgit.dirty_paths(self.fed.root("a")), set())

    def test_verdict_from_another_tree_is_not_reused(self):
        root = self.fed.root("a")
        path, candidate = mr.submit(scope="personal", candidate_id="kettle-2", source="t",
                                    session="s", content_type="markdown", body=NEW_BODY,
                                    projection={"record_slug": "reference_kettle"},
                                    root=root, state=self.fed.states["a"])
        stale = mr.Checked(report=mv.Report(ok=False, errors=["выдуманный отказ"], warnings=[]),
                           base={}, tree={}, notes=[])
        with svodgit.lock(root, exclusive=True):
            result = mr.apply(path, candidate, root=root, scope="personal",
                              config=self.fed.verify_config, today=TODAY,
                              state=self.fed.states["a"], checked=stale)
        self.assertEqual(result["state"], "saved", result)
        self.assertNotIn("выдуманный отказ", json.dumps(result, ensure_ascii=False))
        self.assertIn("memory/reference_kettle.md", self.fed.origin_tree())

    def test_command_line_dry_run_prints_the_verdict_and_writes_nothing(self):
        env = dict(os.environ, MEMORY_REPO=str(self.fed.machines["a"]),
                   MEMORYCTL_STATE_DIR=str(self.fed.states["a"]))
        body = self.fed.base / "kettle.md"
        body.write_bytes(NEW_BODY)
        done = subprocess.run([sys.executable, str(REPO_SOURCE / "bin" / "memory"), "remember",
                               "--scope", "personal", "--id", "kettle-cli", "--dry-run", "--json",
                               "--file", str(body), "--record", "reference_kettle"],
                              env=env, text=True, capture_output=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        printed = json.loads(done.stdout)
        self.assertEqual(printed["state"], "checked", printed)
        self.assertEqual(svodgit.dirty_paths(self.fed.root("a")), set())
        self.assertEqual(self.pending("a"), [])
        self.assertEqual(self.failed("a"), [])


class ViolationListTests(Base):
    """Волна 2, шаг 3: конверт называет все свои нарушения разом и говорит
    словами, где список оборвался."""

    def test_manifest_names_every_bad_change_at_once(self):
        manifest = json.dumps({"changes": [
            {"operation": "put", "path": "other/x.md", "content": "x\n"},
            {"operation": "burn", "path": "memory/y.md"},
            {"operation": "put", "path": "memory/z.txt", "content": "x\n"},
        ]})
        code, result = self.dry("a", "personal", "man-bad", manifest.encode("utf-8"),
                                content_type="manifest")
        self.assertEqual(code, mr.EXIT_FAILED)
        for expected in ("изменение 0", "изменение 1", "изменение 2"):
            self.assertIn(expected, result["reason"])

    def test_projection_names_every_bad_field_at_once(self):
        code, result = self.dry("a", "personal", "proj-bad", NEW_BODY,
                                {"record_slug": "Не Slug", "index_line": "   ",
                                 "index_section": ""})
        self.assertEqual(code, mr.EXIT_FAILED)
        # Отказ называет флаги подачи, а не поля файла проекции, которого нет.
        for expected in ("--record", "--line", "--section"):
            self.assertIn(expected, result["reason"])

    def test_envelope_says_what_it_did_not_check(self):
        code, result = self.dry("a", "personal", "плохой id", NEW_BODY, {"record_slug": "Bad"})
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("id только из букв", result["reason"])
        self.assertIn("--record", result["reason"])
        self.assertIn("дальше не проверялось", result["reason"])

    def test_pointer_names_missing_link_and_missing_section(self):
        with self.assertRaises(mr.Refusal) as caught:
            mr.insert_rollup_pointer("# Тема\n\n## Обзор\n\nТекст.\n",
                                     "Нет такого", "- строка без ссылки")
        words = str(caught.exception)
        self.assertIn("без ссылки", words)
        self.assertIn("раздела", words)

    def test_bad_path_names_both_place_and_extension(self):
        manifest = json.dumps({"changes": [
            {"operation": "put", "path": "other/x.txt", "content": "x\n"}]})
        code, result = self.dry("a", "personal", "path-bad", manifest.encode("utf-8"),
                                content_type="manifest")
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("только внутри memory/", result["reason"])
        self.assertIn("Markdown", result["reason"])


class OneCommandTests(Base):
    """Волна 2, шаг 1: имя записи флагом, короткий хеш основы, тело
    изменения ссылкой на локальный файл."""

    def test_record_name_is_a_flag_not_a_json_file(self):
        env = dict(os.environ, MEMORY_REPO=str(self.fed.machines["a"]),
                   MEMORYCTL_STATE_DIR=str(self.fed.states["a"]))
        body = self.fed.base / "kettle-flag.md"
        body.write_bytes(NEW_BODY)
        done = subprocess.run([sys.executable, str(REPO_SOURCE / "bin" / "memory"), "remember",
                               "--scope", "personal", "--id", "kettle-flag", "--json",
                               "--file", str(body), "--record", "reference_kettle"],
                              env=env, text=True, capture_output=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["state"], "saved", done.stdout)
        self.assertEqual(self.fed.origin_tree()["memory/reference_kettle.md"], NEW_BODY)

    def test_client_pointer_is_two_more_flags(self):
        env = dict(os.environ, MEMORY_REPO=str(self.fed.machines["a"]),
                   MEMORYCTL_STATE_DIR=str(self.fed.states["a"]))
        body = self.fed.base / "acme-vpn.md"
        body.write_bytes(record("acme_vpn", type="project", title="VPN", index="vpn acme",
                                source="разговор", observed_at="2026-09-04",
                                probe="какой доступ в сеть acme", body="Через ssh.\n"))
        done = subprocess.run([sys.executable, str(REPO_SOURCE / "bin" / "memory"), "remember",
                               "--scope", "clients/acme", "--id", "acme-flag", "--json",
                               "--file", str(body), "--record", "acme_vpn",
                               "--section", "Доступы", "--line", "- [[acme_vpn]] доступ по ssh"],
                              env=env, text=True, capture_output=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        rollup = self.fed.origin_tree("clients/acme")["memory/topics/acme.md"].decode("utf-8")
        self.assertIn("- [[acme_vpn]] доступ по ssh", rollup)

    def test_manifest_change_may_name_a_local_file(self):
        source = self.fed.base / "kettle-body.md"
        source.write_bytes(NEW_BODY)
        manifest = json.dumps({"changes": [
            {"operation": "put", "path": "memory/reference_kettle.md", "file": str(source)}]})
        code, result = self.fed.remember("a", "personal", "man-file", manifest.encode("utf-8"),
                                         None, content_type="manifest")
        self.assertEqual(result["state"], "saved", result)
        self.assertEqual(self.fed.origin_tree()["memory/reference_kettle.md"], NEW_BODY)
        # В ожидании лежит самодостаточное намерение: файл уже подставлен.
        source.unlink()
        code, again = self.fed.remember("a", "personal", "man-file", manifest.encode("utf-8"),
                                        None, content_type="manifest")
        self.assertEqual(again["state"], "failed", again)
        self.assertIn("не читается", again["reason"])

    def test_manifest_refuses_content_and_file_together(self):
        source = self.fed.base / "both.md"
        source.write_bytes(NEW_BODY)
        manifest = json.dumps({"changes": [
            {"operation": "put", "path": "memory/reference_kettle.md",
             "content": "x\n", "file": str(source)}]})
        code, result = self.dry("a", "personal", "man-both", manifest.encode("utf-8"),
                                content_type="manifest")
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("вместе не подаются", result["reason"])

    def test_short_base_hash_is_accepted(self):
        root = self.fed.root("a")
        manifest = json.dumps({
            "base_revision": svodgit.head(root)[:12],
            "changes": [{"operation": "put", "path": "memory/reference_kettle.md",
                         "content": NEW_BODY.decode("utf-8")}]})
        code, result = self.fed.remember("a", "personal", "man-short", manifest.encode("utf-8"),
                                         None, content_type="manifest")
        self.assertEqual(result["state"], "saved", result)


class SameNameEditTests(Base):
    """Волна 2, шаг 4: запись правится под тем же именем, когда подача
    называет версию, на которой её читали."""

    def test_declared_base_allows_rewriting_under_the_same_name(self):
        code, first = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                        {"record_slug": "reference_kettle"})
        self.assertEqual(first["state"], "saved", first)
        again = fresh_record("reference_kettle", "как кипятить воду в чайнике",
                             "кипятить воду чайник", "Чайник кипятит воду быстро.\n")
        code, second = self.fed.remember("a", "personal", "kettle-1", again,
                                         {"record_slug": "reference_kettle"},
                                         base=svodgit.head(self.fed.root("a")))
        self.assertEqual(second["state"], "saved", second)
        self.assertEqual(self.fed.origin_tree()["memory/reference_kettle.md"], again)

    def test_same_name_without_a_declared_base_is_refused_with_words(self):
        self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                          {"record_slug": "reference_kettle"})
        again = fresh_record("reference_kettle", "как кипятить воду в чайнике",
                             "кипятить воду чайник", "Другое тело.\n")
        code, result = self.fed.remember("a", "personal", "kettle-1", again,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("назови основу", result["reason"])

    def test_declared_base_older_than_the_record_still_refuses(self):
        root = self.fed.root("a")
        stale = svodgit.head(root)
        self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                          {"record_slug": "reference_kettle"})
        again = fresh_record("reference_kettle", "как кипятить воду в чайнике",
                             "кипятить воду чайник", "Третье тело.\n")
        code, result = self.fed.remember("a", "personal", "kettle-1", again,
                                         {"record_slug": "reference_kettle"}, base=stale)
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("менялась", result["reason"])


class Wave3Tests(Base):
    """Волна 3: таймер снимает исполненный отказ, кэш роутера не растёт без
    края, нечитаемое дерево не притворяется пустым корпусом."""

    def test_timer_drops_a_failure_whose_fact_is_already_in_the_corpus(self):
        self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                          {"record_slug": "reference_kettle"})
        other = fresh_record("reference_toaster", "как поджарить хлеб в тостере",
                             "поджарить хлеб тостер", "Тостер жарит хлеб.\n")
        # Имя занято в истории и основа не названа: отказ не про содержимое.
        code, refused = self.fed.remember("a", "personal", "kettle-1", other,
                                          {"record_slug": "reference_toaster"})
        self.assertEqual(code, mr.EXIT_FAILED, refused)
        self.assertEqual(len(self.failed("a")), 1)
        # Тот же факт сохранён под другим именем: отказ больше ничего не сообщает.
        code, saved = self.fed.remember("a", "personal", "toaster-1", other,
                                        {"record_slug": "reference_toaster"})
        self.assertEqual(saved["state"], "saved", saved)
        outcome = self.fed.sync("a")
        self.assertEqual(self.failed("a"), [])
        self.assertTrue(any("снят исполненный отказ" in line for line in outcome["done"]), outcome)

    def test_timer_keeps_a_failure_whose_fact_is_still_missing(self):
        body = record("reference_kettle", type="reference", title="Чайник",
                      index="как кипятить воду", body="Без происхождения.\n")
        self.fed.remember("a", "personal", "kettle-red", body,
                          {"record_slug": "reference_kettle"})
        self.assertEqual(len(self.failed("a")), 1)
        self.fed.sync("a")
        self.assertEqual(len(self.failed("a")), 1)

    def test_router_cache_older_than_a_month_is_swept(self):
        cache = self.fed.states["a"] / "claude" / "sessions"
        cache.mkdir(parents=True)
        old, fresh = cache / "old.json", cache / "fresh.json"
        old.write_text("{}")
        fresh.write_text("{}")
        stale = time.time() - 40 * 86400
        os.utime(old, (stale, stale))
        removed = ms.prune_router_cache(self.fed.states["a"])
        self.assertEqual(removed, 1)
        self.assertFalse(old.exists())
        self.assertTrue(fresh.exists())

    def test_unreadable_tree_is_a_git_error_not_an_empty_corpus(self):
        with self.assertRaises(svodgit.GitError):
            svodgit.read_tree(self.fed.root("a"), "0" * 40)

    def test_waiting_candidate_without_a_commit_does_not_claim_one(self):
        text = ms.format_human({"ok": False, "repos": [{
            "scope": "personal", "branch": "main", "head": "0" * 40,
            "pending": [{"id": "ждун", "reason": None, "commit": None}],
            "failed": [], "health": [],
        }]})
        self.assertIn("проверка ещё не выполнялась", text)
        self.assertNotIn("коммит локальный", text)


class ReviewFixTests(Base):
    """Дефекты, найденные разбором волн 2 и 3, и их закрытие."""

    def test_pruning_never_touches_a_pin(self):
        """Закрепление пишется один раз и при продолжении разговора не
        переписывается, поэтому его возраст не доказывает конец сессии."""
        claude = self.fed.states["a"] / "claude"
        (claude / "pins").mkdir(parents=True)
        (claude / "sessions").mkdir(parents=True)
        закрепление = claude / "pins" / "старая-сессия.json"
        отметка = claude / "sessions" / "старая-сессия.json"
        for файл in (закрепление, отметка):
            файл.write_text("{}")
            древность = time.time() - 90 * 86400
            os.utime(файл, (древность, древность))
        self.assertEqual(ms.prune_router_cache(self.fed.states["a"]), 1)
        self.assertTrue(закрепление.exists())
        self.assertFalse(отметка.exists())

    def test_same_id_with_another_declared_base_is_not_a_harmless_repeat(self):
        root = self.fed.root("a")
        старая = svodgit.head(root)
        other = fresh_record("reference_toaster", "как поджарить хлеб в тостере",
                             "поджарить хлеб тостер", "Тостер жарит хлеб.\n")
        self.fed.remember("a", "personal", "toaster-1", other,
                          {"record_slug": "reference_toaster"})
        свежая = svodgit.head(root)
        self.assertNotEqual(старая, свежая)
        path, _ = mr.submit(scope="personal", candidate_id="kettle-base", source="t", session="s",
                            content_type="markdown", body=NEW_BODY,
                            projection={"record_slug": "reference_kettle"}, root=root,
                            state=self.fed.states["a"], base=свежая)
        self.assertTrue(path.exists())
        with self.assertRaises(mr.Refusal) as caught:
            mr.submit(scope="personal", candidate_id="kettle-base", source="t", session="s",
                      content_type="markdown", body=NEW_BODY,
                      projection={"record_slug": "reference_kettle"}, root=root,
                      state=self.fed.states["a"], base=старая)
        self.assertIn("другой основой", str(caught.exception))

    def test_sweep_keeps_a_failure_replaced_while_it_was_checked(self):
        """Отказ пишется без общего замка: между чтением и снятием под тем же
        именем может лечь новая беда, и снимать её нельзя."""
        self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                          {"record_slug": "reference_kettle"})
        other = fresh_record("reference_toaster", "как поджарить хлеб в тостере",
                             "поджарить хлеб тостер", "Тостер жарит хлеб.\n")
        self.fed.remember("a", "personal", "kettle-1", other,
                          {"record_slug": "reference_toaster"})
        self.fed.remember("a", "personal", "toaster-1", other,
                          {"record_slug": "reference_toaster"})
        файл = self.failed("a")[0]
        original = mr.compute_files

        def подменить(*args, **kwargs):
            файл.write_text('{"id": "kettle-1", "reason": "новая беда"}', encoding="utf-8")
            return original(*args, **kwargs)

        with mock.patch.object(mr, "compute_files", подменить):
            dropped = mr.drop_settled_failures(self.fed.root("a"), "personal",
                                               self.fed.verify_config,
                                               state=self.fed.states["a"])
        self.assertEqual(dropped, [])
        self.assertTrue(файл.exists())

    def test_path_without_components_refuses_in_words(self):
        for плохой in (".", "./", ""):
            self.assertTrue(mr.path_errors(плохой), плохой)

    def test_manifest_file_over_the_limit_refuses_without_reading_it_whole(self):
        source = self.fed.base / "толстый.md"
        source.write_bytes(b"a" * (mv.MAX_RECORD_BYTES + 10))
        manifest = json.dumps({"changes": [
            {"operation": "put", "path": "memory/reference_kettle.md", "file": str(source)}]})
        code, result = self.dry("a", "personal", "man-big", manifest.encode("utf-8"),
                                content_type="manifest")
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("больше предела записи", result["reason"])

    def test_manifest_file_lands_in_the_candidate_body(self):
        source = self.fed.base / "тело.md"
        source.write_bytes(NEW_BODY)
        manifest = json.dumps({"changes": [
            {"operation": "put", "path": "memory/reference_kettle.md", "file": str(source)}]})
        candidate = mr.make_candidate(scope="personal", candidate_id="man-self", source="t",
                                      session="s", content_type="manifest",
                                      body=manifest.encode("utf-8"), projection=None,
                                      root=self.fed.root("a"))
        self.assertIn("Чайник кипятит воду", candidate["body"])
        self.assertNotIn('"file"', candidate["body"])

    def test_health_of_a_repository_without_commits_is_two_lists(self):
        пустой = self.fed.base / "пустой"
        пустой.mkdir()
        sh(пустой, "init", "--quiet", "-b", "main")
        self.assertEqual(ms.repo_health("personal", пустой, self.fed.verify_config), ([], []))

    def test_daily_line_stays_short_and_monthly_line_shows_every_note(self):
        находки = [f"сводка: раздел «Р{n}» 4000 симв при потолке 3400" for n in range(20)]
        заметки = [f"обзор: review_after прошёл у reference_{n}" for n in range(20)]
        итог = {"repos": [{"scope": "clients/acme", "health": находки, "notes": заметки,
                           "failed": [], "pending": []}]}
        ежедневная = ms.format_nudge(итог)
        self.assertNotIn("\n", ежедневная)
        self.assertIn("и ещё 19", ежедневная)
        self.assertLess(len(ежедневная), 200)
        self.assertTrue(ежедневная.endswith("/memory-compact"))
        строки = ms.format_nudge(итог, monthly=True).split("\n")
        self.assertEqual(строки[0], ежедневная)
        self.assertTrue(all(z in строки[1] for z in заметки), строки[1])

    def test_daily_nudge_names_only_breakage_and_monthly_skips_threshold_and_headroom(self):
        """Ежедневная строка только о поломках, заметки обслуживания раз в
        месяц; запас раздела и мягкий порог индекса не приходят и в месячной
        (решение владельца 24.09.2026)."""
        заметки = ["индекс 22000 симв / 160 строк выше порога 20000 / 150, потолок 28000 / 200",
                   "запас: раздел «Обзор» 5 симв до потолка 3400"]
        прочие = ["индекс 30000 симв / 160 строк выше потолка 28000 / 200",
                  "каталог сведений о владельце 3300 симв выше потолка 3200",
                  "дрейф: acme 1", "свернул бы (не выдавалась хуком 60 дней на машине x): y",
                  "автомат закрытого отстал (исполнитель x, эта машина y): z"]
        for набор in (заметки, заметки + прочие):
            self.assertEqual(ms.format_nudge({"repos": [{"scope": "personal",
                                                         "notes": набор}]}), "")
        self.assertEqual(ms.format_nudge({"repos": [{"scope": "personal", "notes": заметки}]},
                                         monthly=True), "")
        for заметка in прочие:
            строка = ms.format_nudge({"repos": [{"scope": "personal",
                                                 "notes": заметки + [заметка]}]}, monthly=True)
            self.assertEqual(строка, f"Память, раз в месяц: personal: {заметка} → /memory-compact")
        # Один итог автомата разбирать нечего: хвост ведёт в статус.
        итог = ms.AUTO_NOTE + "3"
        self.assertEqual(ms.format_nudge({"repos": [{"scope": "personal", "notes": [итог]}]},
                                         monthly=True),
                         f"Память, раз в месяц: personal: {итог} → memory status")
        # Поломка приходит каждый день; хвост ведёт в статус, если измерений нет.
        поломка = {"scope": "personal", "failed": [{"id": "bad-1"}], "notes": прочие}
        self.assertEqual(ms.format_nudge({"repos": [поломка]}),
                         "Память: personal: отказ bad-1 → memory status")
        сводка = {"scope": "clients/acme", "health": ["сводка: раздел «Обзор» 4000 симв"]}
        self.assertTrue(ms.format_nudge({"repos": [сводка]}).endswith("/memory-compact"))


class LateReviewFixTests(Base):
    """Находки второго круга разбора: контракт, доказательство доставки,
    частичная шапка."""

    def test_header_with_only_a_type_is_a_partial_header(self):
        body = record("reference_kettle", type="reference",
                      source="разговор", observed_at="2026-09-04",
                      probe="кипятить воду чайник", body="Чайник кипятит воду.\n")
        code, result = self.dry("a", "personal", "kettle-part", body,
                                {"record_slug": "reference_kettle",
                                 "index_section": "Reference",
                                 "index_line": "- [Чайник](reference_kettle.md) - как кипятить воду"})
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("часть полей индекса", result["reason"])

    def test_delivery_proof_covers_the_rollup_pointer(self):
        body = record("acme_vpn", type="project", title="VPN", index="vpn acme",
                      source="разговор", observed_at="2026-09-04",
                      probe="какой доступ в сеть acme", body="Через ssh.\n")
        code, result = self.fed.remember(
            "a", "clients/acme", "acme-1", body,
            {"record_slug": "acme_vpn", "index_section": "Доступы",
             "index_line": "- [[acme_vpn]] доступ по ssh"})
        self.assertEqual(result["state"], "saved", result)
        candidate = svodgit.read_json(
            svodgit.failed_dir("clients/acme", self.fed.states["a"]) / "нет.json")
        self.assertIsNone(candidate)
        # Кандидат уже снят, поэтому доказательство проверяем прямо: результат
        # прохода обязан покрывать и запись, и сводку темы.
        path, cand = mr.submit(scope="clients/acme", candidate_id="acme-2", source="t",
                               session="s", content_type="markdown",
                               body=record("acme_dns", type="project", title="DNS",
                                           index="dns acme", source="разговор",
                                           observed_at="2026-09-04",
                                           probe="какой доступ к dns acme",
                                           body="Через ssh.\n"),
                               projection={"record_slug": "acme_dns",
                                           "index_section": "Доступы",
                                           "index_line": "- [[acme_dns]] доступ к dns"},
                               root=self.fed.root("a", "clients/acme"),
                               state=self.fed.states["a"])
        with svodgit.lock(self.fed.root("a", "clients/acme"), exclusive=True):
            mr.apply(path, cand, root=self.fed.root("a", "clients/acme"), scope="clients/acme",
                     config=self.fed.verify_config, today=TODAY, state=self.fed.states["a"])
        self.assertIn("memory/topics/acme.md", cand["result"])
        self.assertIn("memory/acme_dns.md", cand["result"])


class SecondRoundFixTests(Base):
    """Находки второго круга разбора."""

    def test_repeat_of_the_same_command_stays_harmless_after_a_local_commit(self):
        """Основа, выведенная из ветки main, повтором управлять не должна:
        свой же локальный коммит её двигает."""
        root = self.fed.root("a")
        path, first = mr.submit(scope="personal", candidate_id="kettle-rep", source="t",
                                session="s", content_type="markdown", body=NEW_BODY,
                                projection={"record_slug": "reference_kettle"}, root=root,
                                state=self.fed.states["a"])
        self.assertFalse(first["declared"])
        other = fresh_record("reference_toaster", "как поджарить хлеб в тостере",
                             "поджарить хлеб тостер", "Тостер жарит хлеб.\n")
        self.fed.remember("a", "personal", "toaster-1", other,
                          {"record_slug": "reference_toaster"})
        again, second = mr.submit(scope="personal", candidate_id="kettle-rep", source="t",
                                  session="s", content_type="markdown", body=NEW_BODY,
                                  projection={"record_slug": "reference_kettle"}, root=root,
                                  state=self.fed.states["a"])
        self.assertEqual(again, path)
        self.assertEqual(second["base"], first["base"])

    def test_declared_base_is_stored_full_even_when_given_short(self):
        root = self.fed.root("a")
        полная = svodgit.head(root)
        _, candidate = mr.submit(scope="personal", candidate_id="kettle-short", source="t",
                                 session="s", content_type="markdown", body=NEW_BODY,
                                 projection={"record_slug": "reference_kettle"}, root=root,
                                 state=self.fed.states["a"], base=полная[:12])
        self.assertEqual(candidate["base"], полная)
        # Тот же коммит короткой записью это то же намерение, а не другое.
        _, повтор = mr.submit(scope="personal", candidate_id="kettle-short", source="t",
                              session="s", content_type="markdown", body=NEW_BODY,
                              projection={"record_slug": "reference_kettle"}, root=root,
                              state=self.fed.states["a"], base=полная)
        self.assertEqual(повтор["base"], полная)

    def test_header_with_an_empty_type_is_still_a_partial_header(self):
        body = ("---\ntype: \nsource: \"разговор\"\nobserved_at: 2026-09-04\n"
                "probe: \"кипятить воду чайник\"\n---\n\nЧайник.\n").encode("utf-8")
        code, result = self.dry("a", "personal", "kettle-empty-type", body,
                                {"record_slug": "reference_kettle",
                                 "index_section": "Reference",
                                 "index_line": "- [Чайник](reference_kettle.md) - как кипятить"})
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("часть полей индекса", result["reason"])


class ThirdRoundFixTests(Base):
    """Находки третьего круга разбора."""

    def test_pointer_to_another_record_is_refused(self):
        body = record("acme_vpn", type="project", title="VPN", index="vpn acme",
                      source="разговор", observed_at="2026-09-04",
                      probe="какой доступ в сеть acme", body="Через ssh.\n")
        code, result = self.dry("a", "clients/acme", "acme-wrong", body,
                                {"record_slug": "acme_vpn", "index_section": "Доступы",
                                 "index_line": "- [[acme_dns]] чужая запись"})
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("со ссылкой на запись acme_vpn", result["reason"])

    def test_full_header_with_listed_false_is_not_called_partial(self):
        body = record("reference_kettle", type="reference", title="Чайник",
                      index="как кипятить воду в чайнике", listed="false",
                      source="разговор", observed_at="2026-09-04",
                      probe="кипятить воду чайник", body="Чайник кипятит воду.\n")
        data, note = mr.apply_index_projection(
            body, "reference_kettle",
            {"record_slug": "reference_kettle", "index_section": "Reference",
             "index_line": "- [Чайник](reference_kettle.md) - как кипятить"})
        self.assertEqual(data, body)
        self.assertIn("--line не использована", note)

    def test_same_base_written_short_and_full_is_one_base(self):
        root = self.fed.root("a")
        полная = svodgit.head(root)
        manifest = json.dumps({
            "base_revision": полная,
            "changes": [{"operation": "put", "path": "memory/reference_kettle.md",
                         "content": NEW_BODY.decode("utf-8")}]})
        code, result = self.fed.remember("a", "personal", "man-two-forms",
                                         manifest.encode("utf-8"), None,
                                         content_type="manifest", base=полная[:12])
        self.assertEqual(result["state"], "saved", result)

    def test_two_different_bases_are_still_refused(self):
        root = self.fed.root("a")
        старая = svodgit.head(root)
        other = fresh_record("reference_toaster", "как поджарить хлеб в тостере",
                             "поджарить хлеб тостер", "Тостер жарит хлеб.\n")
        self.fed.remember("a", "personal", "toaster-1", other,
                          {"record_slug": "reference_toaster"})
        manifest = json.dumps({
            "base_revision": svodgit.head(root),
            "changes": [{"operation": "put", "path": "memory/reference_kettle.md",
                         "content": NEW_BODY.decode("utf-8")}]})
        code, result = self.dry("a", "personal", "man-conflict", manifest.encode("utf-8"),
                                content_type="manifest")
        self.assertEqual(code, mr.EXIT_SAVED, result)
        code, result = mr.run_remember(
            scope="personal", candidate_id="man-conflict", source="t", session="s",
            content_type="manifest", body=manifest.encode("utf-8"), projection=None,
            data_root=self.fed.machines["a"], state=self.fed.states["a"], today=TODAY,
            dry_run=True, base=старая)
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("дважды и по-разному", result["reason"])


class FourthRoundFixTests(Base):
    """Находки четвёртого круга: указатель узнаётся строго."""

    def test_replacing_inside_the_named_section_says_what_was_replaced(self):
        """В названном разделе замена это обычный ход: в живых сводках
        указатель и есть абзац с фактами. Но автор обязан увидеть, что
        именно уехало."""
        rollup = ("# Acme\n\n## Доступы\n\nСхему сети смотреть в [[acme_dns]], "
                  "она главная: эпик ACME-12.\n")
        new, слова = mr.insert_rollup_pointer(rollup, "Доступы", "- [[acme_dns]] доступ по ssh")
        self.assertIn("- [[acme_dns]] доступ по ssh", new)
        self.assertNotIn("эпик ACME-12", new)
        self.assertTrue(any("заменена прежняя строка" in w and "ACME-12" in w for w in слова), слова)

    def test_a_strict_pointer_wins_over_prose_inside_the_section(self):
        rollup = ("# Acme\n\n## Доступы\n\nСхему сети смотреть в [[acme_dns]], эпик ACME-12.\n"
                  "- [[acme_dns]] старый крючок\n")
        new, слова = mr.insert_rollup_pointer(rollup, "Доступы", "- [[acme_dns]] новый крючок")
        self.assertIn("эпик ACME-12", new)
        self.assertIn("- [[acme_dns]] новый крючок", new)
        self.assertNotIn("старый крючок", new)

    def test_a_real_pointer_inside_the_section_is_replaced_in_place(self):
        rollup = "# Acme\n\n## Доступы\n\n- [[acme_dns]] старый текст\n"
        new, слова = mr.insert_rollup_pointer(rollup, "Доступы", "- [[acme_dns]] новый текст")
        self.assertIn("новый текст", new)
        self.assertNotIn("старый текст", new)
        self.assertTrue(any("заменена прежняя строка" in w for w in слова), слова)

    def test_section_names_in_notes_are_counted_before_editing(self):
        rollup = ("# Acme\n\n## Обзор\n\nПро [[acme_dns]] сказано тут.\n"
                  "\n## Доступы\n\nПо ssh.\n")
        new, слова = mr.insert_rollup_pointer(rollup, "Доступы", "- [[acme_dns]] доступ по ssh")
        self.assertTrue(any("«Обзор»" in w for w in слова), слова)
        self.assertNotIn("«Доступы»", " ".join(слова))


class ManifestFileTests(Base):
    """file это источник текста, значит он бывает только у put."""

    def test_remove_with_a_file_is_refused_without_reading_it(self):
        manifest = json.dumps({"changes": [
            {"operation": "remove", "path": "memory/reference_printer.md",
             "file": "/несуществующий/путь.md"}]})
        code, result = self.dry("a", "personal", "man-remove-file",
                                manifest.encode("utf-8"), content_type="manifest")
        self.assertEqual(code, mr.EXIT_FAILED)
        self.assertIn("file несёт только операция put", result["reason"])
        self.assertNotIn("не читается", result["reason"])


class LinkOwnerTests(Base):
    """Владелец строки это самая левая ссылка, а не первая markdown."""

    def test_leftmost_link_decides_the_owner_of_the_line(self):
        self.assertEqual(mr.index_line_slug("- [[наша]] и потом [отчёт](other.md)"), "наша")
        self.assertEqual(mr.index_line_slug("- [отчёт](other.md) и потом [[наша]]"), "other")
        self.assertIsNone(mr.index_line_slug("- просто текст"))

    def test_rich_pointer_line_is_accepted_by_submission(self):
        body = record("acme_vpn", type="project", title="VPN", index="vpn acme",
                      source="разговор", observed_at="2026-09-04",
                      probe="какой доступ в сеть acme", body="Через ssh.\n")
        code, result = self.dry(
            "a", "clients/acme", "acme-rich", body,
            {"record_slug": "acme_vpn", "index_section": "Доступы",
             "index_line": "- **Доступ по ssh (10.09.2026):** через бастион, детали в [[acme_vpn]]."})
        self.assertEqual(code, mr.EXIT_SAVED, result)

    def test_pointer_is_only_a_list_item_that_starts_with_the_link(self):
        self.assertEqual(mr.pointer_slug("- [[наша]] чем полезна"), "наша")
        self.assertEqual(mr.pointer_slug("  * [Имя](наша.md) - чем полезна"), "наша")
        self.assertIsNone(mr.pointer_slug("Про [[наша]] сказано в тексте."))
        self.assertIsNone(mr.pointer_slug("- текст, а ссылка [[наша]] в середине"))
        # Пункт-задача открывается скобкой, но не ссылкой.
        self.assertIsNone(mr.pointer_slug("- [ ] проверить канал, схема в [[наша]]"))
        self.assertIsNone(mr.pointer_slug("- [x] сделано, детали в [[наша]]"))
        # Пункт открывается ВНЕШНЕЙ ссылкой: слаг пришёл бы из середины строки.
        self.assertIsNone(mr.pointer_slug("- [Инцидент](https://example.org/17) схема в [[наша]]"))


class PointerKeepsNeighboursTests(Base):
    """Из нестрогих упоминаний заменяется ровно одно, остальные живут."""

    def test_only_one_loose_mention_is_replaced_and_the_rest_survive(self):
        rollup = ("# Acme\n\n## Доступы\n\nПервый абзац про [[acme_dns]], эпик ACME-12.\n"
                  "Второй абзац про [[acme_dns]], заморозка доступа 26.06.\n")
        new, слова = mr.insert_rollup_pointer(rollup, "Доступы", "- [[acme_dns]] доступ по ssh")
        self.assertIn("заморозка доступа 26.06", new)
        self.assertNotIn("эпик ACME-12", new)
        self.assertTrue(any("заменена прежняя строка" in w and "ACME-12" in w for w in слова), слова)
        self.assertTrue(any("упомянута ещё" in w for w in слова), слова)

    def test_every_touched_line_comes_back_in_words(self):
        rollup = ("# Acme\n\n## Доступы\n\n- [[acme_dns]] первый указатель\n"
                  "- [[acme_dns]] второй указатель\n"
                  "Проза про [[acme_dns]] с фактом заморозки.\n"
                  "\n## Обзор\n\nЕщё про [[acme_dns]] в другом разделе.\n")
        new, слова = mr.insert_rollup_pointer(rollup, "Доступы", "- [[acme_dns]] новый указатель")
        текст = " | ".join(слова)
        self.assertIn("заменена прежняя строка", текст)
        self.assertIn("убран лишний указатель", текст)
        self.assertIn("упомянута ещё 1 раз", текст)
        self.assertIn("«Обзор»", текст)
        self.assertIn("заморозки", new, "проза раздела не удаляется")
        self.assertIn("в другом разделе", new)

    def test_long_replaced_line_is_marked_as_clipped(self):
        длинная = "Проза про [[acme_dns]] " + "и много фактов " * 20
        rollup = f"# Acme\n\n## Доступы\n\n{длинная}\n"
        _, слова = mr.insert_rollup_pointer(rollup, "Доступы", "- [[acme_dns]] новый")
        self.assertTrue(any("всего" in w and "знаков" in w for w in слова), слова)

    def test_repeating_the_same_submission_changes_nothing(self):
        rollup = ("# Acme\n\n## Доступы\n\nПервый абзац про [[acme_dns]], эпик ACME-12.\n"
                  "Второй абзац про [[acme_dns]], заморозка 26.06.\n")
        один, _ = mr.insert_rollup_pointer(rollup, "Доступы", "- [[acme_dns]] доступ по ssh")
        два, слова = mr.insert_rollup_pointer(один, "Доступы", "- [[acme_dns]] доступ по ssh")
        self.assertEqual(один, два)
        self.assertFalse(any("заменена прежняя строка" in w for w in слова), слова)


def expiring(slug: str, title: str, index: str, probe: str, until: str | None = "2026-09-10") -> bytes:
    поля = {"type": "project", "title": title, "index": index, "source": "разговор",
            "observed_at": "2026-09-04", "probe": probe}
    if until:
        поля["valid_until"] = until
    return record(slug, **поля, body=f"{title}.\n")


LATER = dt.date(2026, 9, 20)
BOILER_WORDS = ("project_boiler", "Бойлер котельной", "бойлер котельная нагрев воды",
                "когда менять бойлер в котельной")
BOILER = expiring(*BOILER_WORDS)
GARAGE = expiring("project_garage", "Ворота гаража", "гараж ворота привод",
                  "что с воротами гаража")
EXECUTOR = {"executor": "home-pc", "closed": "on"}


class SelfMaintenanceTests(Base):
    """Самообслуживание (решение владельца 24.09.2026): истёкшее сворачивает
    автомат одной подачей писателя, только на машине-исполнителе."""

    def configure(self, maintenance, **extra) -> mv.Config:
        topics = json.loads(json.dumps(TOPICS))
        if maintenance is not None:
            topics["maintenance"] = maintenance
        topics["topics"]["home"].update(extra)
        (self.fed.config / "topics.json").write_text(json.dumps(topics, ensure_ascii=False))
        return mv.Config(topics=json.dumps(topics).encode(),
                         questions=(self.fed.config / "eval_questions.json").read_bytes())

    def close(self, config: mv.Config, host: str = "home-pc", today=LATER, **kw) -> dict:
        with mock.patch.object(ms.socket, "gethostname", return_value=host):
            return ms.close_expired(self.fed.root("a"), config, data_root=self.fed.machines["a"],
                                    today=today, state=self.fed.states["a"], **kw)

    def sync_a(self) -> dict:
        with mock.patch.object(ms.socket, "gethostname", return_value="home-pc"):
            outcomes = ms.sync_all(data_root=self.fed.machines["a"], today=LATER,
                                   state=self.fed.states["a"])
        return next(o for o in outcomes if o["scope"] == "personal")

    def expired_tree(self, *slugs: str) -> dict[str, bytes]:
        tree = svodgit.read_tree(self.fed.root("a"), "HEAD")
        for slug in slugs:
            tree[f"memory/{slug}.md"] = expiring(slug, "Запись", "запись", "про запись")
        return tree

    def save(self, machine: str, cid: str, body: bytes, slug: str) -> None:
        code, result = mr.run_remember(
            scope="personal", candidate_id=cid, source="test", session="s",
            content_type="markdown", body=body, projection={"record_slug": slug},
            data_root=self.fed.machines[machine], state=self.fed.states[machine], today=LATER,
            base=svodgit.head(self.fed.root(machine, "personal")))
        self.assertEqual(result["state"], "saved", result)

    def boiler_on_server(self) -> dict:
        return mv.parse_frontmatter(self.fed.origin_tree()["memory/project_boiler.md"].decode())[0]

    def test_maintenance_is_parsed_apart_from_topics_and_a_typo_stops_only_the_automaton(self):
        self.assertEqual(ms.maintenance_from_config(json.dumps(TOPICS).encode()),
                         {"executor": "", "closed": "off"})
        self.assertEqual(ms.maintenance_from_config(json.dumps(
            {**TOPICS, "maintenance": {"executor": "home-pc", "closed": "observe"}}).encode()),
            {"executor": "home-pc", "closed": "observe"})
        for плохое in ({"executor": "home-pc", "closed": "Off"}, {"executor": "home-pc", "closed": False},
                       {"executor": 5, "closed": "on"}, "on"):
            with self.subTest(плохое=плохое):
                config = self.configure(плохое)
                итог = self.close(config)
                self.assertEqual(итог["done"], [])
                self.assertEqual(len(итог["problems"]), 1)
                self.assertIn("автомат закрытого выключен: topics.json: maintenance",
                              итог["problems"][0])
        # Писатели обеих областей работают при опечатке в разделе.
        code, result = self.fed.remember("a", "personal", "kettle-1", NEW_BODY,
                                         {"record_slug": "reference_kettle"})
        self.assertEqual(result["state"], "saved", result)
        body = record("acme_vpn", type="project", title="VPN Acme", index="vpn acme",
                      source="разговор", observed_at="2026-09-04",
                      probe="как попасть в сеть заказчика по ssh", listed="false",
                      body="Доступ по ssh через бастион.\n")
        code, result = self.fed.remember("a", "clients/acme", "acme-vpn-1", body,
                                         {"record_slug": "acme_vpn", "index_section": "Доступы",
                                          "index_line": "- [[acme_vpn]] ssh через бастион"})
        self.assertEqual(result["state"], "saved", result)

    def test_machine_name_ignores_case_and_local_suffix(self):
        with mock.patch.object(ms.socket, "gethostname", return_value="Work-Laptop.local"):
            self.assertTrue(ms.same_machine("work-laptop"))
            self.assertFalse(ms.same_machine("home-pc"))
            self.assertFalse(ms.same_machine(""))

    def test_off_absent_foreign_machine_and_stale_head_do_nothing(self):
        head = svodgit.head(self.fed.root("a"))
        tree = self.expired_tree("project_old")
        with mock.patch.object(svodgit, "read_tree", return_value=tree):
            for config, host, current in (
                    (self.configure(None), "home-pc", True),
                    (self.configure({"executor": "home-pc", "closed": "off"}), "home-pc", True),
                    (self.configure(EXECUTOR), "другая", True),
                    (self.configure(EXECUTOR), "home-pc", False)):
                self.assertEqual(self.close(config, host, current=current),
                                 {"done": [], "problems": []})
        self.assertEqual(svodgit.head(self.fed.root("a")), head)
        self.assertEqual(self.pending("a") + self.failed("a"), [])

    def test_observe_names_ten_without_stand_and_hotkeep(self):
        config = self.configure({"executor": "HOME-PC.local", "closed": "observe"},
                                hotKeep=["project_keep.md"])
        slugs = [f"project_old_{n:02d}" for n in range(12)]
        tree = self.expired_tree(*slugs, "project_keep")
        # Ожидаемая запись стенда тоже истекла: её автомат не трогает.
        tree["memory/reference_printer.md"] = expiring("reference_printer", "Зелёный принтер",
                                                       "как чинить зелёный принтер", "чем чинить")
        # Свои отказы автомат снимает только в режиме on.
        прежний = svodgit.failed_dir("personal", self.fed.states["a"]) / "auto-close-x.json"
        прежний.parent.mkdir(parents=True)
        прежний.write_text("{}")
        with mock.patch.object(svodgit, "read_tree", return_value=tree):
            итог = self.close(config)
        self.assertEqual(итог["problems"], [])
        self.assertEqual(итог["done"], ["свернул бы по сроку: " + ", ".join(slugs[:10])])
        self.assertEqual(self.pending("a") + self.failed("a"), [прежний])

    def test_on_folds_expired_records_through_the_writer(self):
        self.save("a", "boiler-1", BOILER, "project_boiler")
        self.save("a", "garage-1", GARAGE, "project_garage")
        self.configure(EXECUTOR)
        личный = self.sync_a()
        кэш = svodgit.read_json(svodgit.sync_cache_path("personal", self.fed.states["a"]))
        self.assertEqual(кэш["done"], личный["done"])
        self.assertEqual(личный["problems"], [])
        self.assertIn("свёрнуто по сроку: project_boiler, project_garage", личный["done"])
        tree = self.fed.origin_tree()
        for slug in ("project_boiler", "project_garage"):
            self.assertTrue(tree[f"memory/{slug}.md"].startswith(b"---\nlisted: false\ntype: project"))
        self.assertEqual(ms.dated_records(tree, LATER)[0], [])
        тема = sh(self.fed.origins / "personal.git", "log", "-1", "--format=%s", "main")
        self.assertTrue(тема.startswith("memory: auto-close-20260920-"), тема)
        self.assertEqual(self.pending("a") + self.failed("a"), [])
        # Следующий прогон видит свёрнутое и молчит; истёкшее не возвращается.
        личный = self.sync_a()
        self.assertEqual(личный["problems"], [])
        self.assertFalse(any("по сроку" in line for line in личный["done"]), личный)
        # Счёт автомата виден заметкой статуса на любой машине.
        _, notes = ms.repo_health("personal", self.fed.root("a"), self.fed.verify_config,
                                  self.fed.states["a"])
        self.assertIn("автомат за 30 дней свернул по сроку: 2", notes)

    def test_extension_offline_race_heals_itself_without_a_stale_refusal(self):
        """Исполнитель свернул без сети, другая машина продлила срок, rebase
        слил listed: false с новым сроком без конфликта: следующий прогон
        возвращает запись сам, ложного отказа не остаётся."""
        self.save("a", "boiler-1", BOILER, "project_boiler")
        self.fed.sync("b")
        config = self.configure(EXECUTOR)
        with mock.patch.object(svodgit, "fetch", return_value=(False, "нет сети")):
            итог = self.close(config)
        self.assertIn("свёрнуто по сроку локально, ждёт отправки: project_boiler", итог["done"][0])
        self.save("b", "boiler-extend", expiring(*BOILER_WORDS, until="2026-12-31"), "project_boiler")
        личный = self.sync_a()
        self.assertEqual(личный["problems"], [])
        self.assertIn("возвращено после продления срока: project_boiler", личный["done"])
        поля = self.boiler_on_server()
        self.assertEqual((поля.get("listed"), поля.get("valid_until")), (None, "2026-12-31"))
        self.assertEqual(self.pending("a") + self.failed("a"), [])
        self.assertEqual(ms.format_nudge(ms.status(data_root=self.fed.machines["a"],
                                                   state=self.fed.states["a"])), "")

    def race_in_push_window(self, edited: bytes) -> None:
        """Другая машина правит срок, пока исполнитель отправляет свёртку."""
        self.save("a", "boiler-1", BOILER, "project_boiler")
        self.fed.sync("b")
        config = self.configure(EXECUTOR)
        настоящий = svodgit.push
        сделано = []

        def push(root, commit, remote):
            if not сделано and Path(root).resolve() == self.fed.root("a").resolve():
                сделано.append(1)
                with mock.patch.object(svodgit, "push", настоящий):
                    self.save("b", "boiler-edit", edited, "project_boiler")
            return настоящий(root, commit, remote)

        with mock.patch.object(svodgit, "push", push):
            self.close(config)
        self.assertEqual(self.boiler_on_server().get("listed"), "false")

    def test_extension_in_the_push_window_is_reopened_next_run(self):
        self.race_in_push_window(expiring(*BOILER_WORDS, until="2026-12-31"))
        личный = self.sync_a()
        self.assertIn("возвращено после продления срока: project_boiler", личный["done"])
        поля = self.boiler_on_server()
        self.assertEqual((поля.get("listed"), поля.get("valid_until")), (None, "2026-12-31"))
        тема = sh(self.fed.origins / "personal.git", "log", "-1", "--format=%s", "main")
        self.assertTrue(тема.startswith("memory: auto-reopen-20260920-"), тема)
        # Возвращённое не сворачивается снова и не возвращается повторно.
        личный = self.sync_a()
        self.assertFalse(any("срока" in line for line in личный["done"]), личный)

    def test_removed_expiry_in_the_push_window_is_reopened_next_run(self):
        self.race_in_push_window(expiring(*BOILER_WORDS, until=None))
        личный = self.sync_a()
        self.assertIn("возвращено после продления срока: project_boiler", личный["done"])
        поля = self.boiler_on_server()
        self.assertEqual((поля.get("listed"), поля.get("valid_until")), (None, None))

    def test_manual_fold_racing_the_automaton_is_not_undone(self):
        """Человек на другой машине сам свернул запись (listed ниже в шапке)
        и продлил срок, пока автомат сворачивал: две строки listed, возврата
        нет, ручная свёртка остаётся."""
        продлено = expiring(*BOILER_WORDS, until="2026-12-31").replace(
            b"valid_until:", b"listed: false\nvalid_until:")
        self.race_in_push_window(продлено)
        self.assertEqual(self.fed.origin_tree()["memory/project_boiler.md"].count(b"listed: false"), 2)
        личный = self.sync_a()
        self.assertFalse(any("срока" in line for line in личный["done"]), личный)
        self.assertEqual(self.fed.origin_tree()["memory/project_boiler.md"].count(b"listed: false"), 2)

    def test_extension_rebased_over_the_fold_is_reopened(self):
        """Обратный порядок: вторая машина продлила без сети, исполнитель
        опубликовал свёртку, продление легло поверх неё. Последний коммит к
        файлу человеческий, но строку listed менял только автомат."""
        self.save("a", "boiler-1", BOILER, "project_boiler")
        self.fed.sync("b")
        self.configure(EXECUTOR)
        with mock.patch.object(svodgit, "fetch", return_value=(False, "нет сети")):
            code, result = mr.run_remember(
                scope="personal", candidate_id="boiler-extend", source="test", session="s",
                content_type="markdown", body=expiring(*BOILER_WORDS, until="2026-12-31"),
                projection={"record_slug": "project_boiler"}, data_root=self.fed.machines["b"],
                state=self.fed.states["b"], today=LATER, base=svodgit.head(self.fed.root("b")))
        self.assertEqual(result["state"], "pending", result)
        self.assertIn("свёрнуто по сроку: project_boiler", self.sync_a()["done"])
        self.fed.sync("b")
        поля = self.boiler_on_server()
        self.assertEqual((поля.get("listed"), поля.get("valid_until")), ("false", "2026-12-31"))
        тема = sh(self.fed.origins / "personal.git", "log", "-1", "--format=%s", "main")
        self.assertFalse(тема.startswith("memory: auto-"), тема)
        личный = self.sync_a()
        self.assertIn("возвращено после продления срока: project_boiler", личный["done"])
        поля = self.boiler_on_server()
        self.assertEqual((поля.get("listed"), поля.get("valid_until")), (None, "2026-12-31"))
        self.fed.sync("b")
        self.assertEqual(self.failed("b") + self.failed("a"), [])

    def test_body_line_starting_with_listed_does_not_hide_the_origin(self):
        """После свёртки человек продлил срок и поправил в теле строку,
        начинающуюся с listed: происхождение ищется по полю шапки, а не по
        любой такой строке файла, и запись возвращается."""
        исходная = BOILER.replace(b"\n\n# project_boiler",
                                  "\n\n# project_boiler\n\nlisted: старый пример".encode())
        self.save("a", "boiler-1", исходная, "project_boiler")
        self.configure(EXECUTOR)
        self.assertIn("свёрнуто по сроку: project_boiler", self.sync_a()["done"])
        self.fed.sync("b")
        правка = (self.fed.origin_tree()["memory/project_boiler.md"]
                  .replace(b"valid_until: 2026-09-10", b"valid_until: 2026-12-31")
                  .replace("listed: старый".encode(), "listed: новый".encode()))
        self.save("b", "boiler-extend", правка, "project_boiler")
        личный = self.sync_a()
        self.assertIn("возвращено после продления срока: project_boiler", личный["done"])
        текст = self.fed.origin_tree()["memory/project_boiler.md"]
        поля = mv.parse_frontmatter(текст.decode())[0]
        self.assertEqual((поля.get("listed"), поля.get("valid_until")), (None, "2026-12-31"))
        self.assertIn("listed: новый пример".encode(), текст)

    def folded_on_b(self) -> Path:
        """Автомат свернул запись, вторая машина её подтянула."""
        self.save("a", "boiler-1", BOILER, "project_boiler")
        self.configure(EXECUTOR)
        self.assertIn("свёрнуто по сроку: project_boiler", self.sync_a()["done"])
        self.fed.sync("b")
        return self.fed.root("b")

    def test_human_merge_in_the_file_history_is_not_undone(self):
        """Одна ветка сняла свёртку, другая продлила срок, человек слил их,
        выбрав свёрнутое: решение человека важнее, возврата нет."""
        root = self.folded_on_b()
        путь = "memory/project_boiler.md"
        текст = (root / путь).read_bytes()
        sh(root, "checkout", "--quiet", "-b", "снять")
        self.manual_commit(root, путь, текст.replace(b"listed: false\n", b""), "memory: x",
                           no_verify=True)
        sh(root, "checkout", "--quiet", "main")
        self.manual_commit(root, путь, текст.replace(b"2026-09-10", b"2026-12-31"), "memory: y",
                           no_verify=True)
        sh(root, "merge", "--quiet", "--no-verify", "-s", "ours", "снять", "-m", "memory: слияние")
        sh(root, "push", "--quiet", "--no-verify", "origin", "main")
        личный = self.sync_a()
        self.assertEqual(ms._fold_origin(self.fed.root("a"), путь), "")
        self.assertFalse(any("срока" in line for line in личный["done"]), личный)
        поля = self.boiler_on_server()
        self.assertEqual((поля.get("listed"), поля.get("valid_until")), ("false", "2026-12-31"))

    def test_renamed_record_is_followed_to_the_fold(self):
        root = self.folded_on_b()
        sh(root, "mv", "memory/project_boiler.md", "memory/project_heater.md")
        sh(root, "commit", "--quiet", "--no-verify", "-m", "memory: rename")
        sh(root, "push", "--quiet", "--no-verify", "origin", "main")
        текст = (root / "memory/project_heater.md").read_bytes()
        self.save("b", "heater-extend", текст.replace(b"2026-09-10", b"2026-12-31"),
                  "project_heater")
        личный = self.sync_a()
        self.assertIn("возвращено после продления срока: project_heater", личный["done"])
        поля = mv.parse_frontmatter(self.fed.origin_tree()["memory/project_heater.md"].decode())[0]
        self.assertEqual((поля.get("listed"), поля.get("valid_until")), (None, "2026-12-31"))

    def test_publication_conflict_keeps_the_automaton_away(self):
        """fetch удался, но вершина сервера не легла в HEAD (конфликт
        публикации): автомат не судит по старому."""
        self.save("a", "boiler-1", BOILER, "project_boiler")
        self.fed.sync("b")
        self.configure(EXECUTOR)
        путь = "memory/topics/home.md"
        self.manual_commit(self.fed.root("a"), путь, "# Home\n\n## Обзор\n\nA.\n".encode(),
                           "memory: a", no_verify=True)
        self.manual_commit(self.fed.root("b"), путь, "# Home\n\n## Обзор\n\nB.\n".encode(),
                           "memory: b", no_verify=True)
        sh(self.fed.root("b"), "push", "--quiet", "--no-verify", "origin", "main")
        личный = self.sync_a()
        self.assertTrue(any("конфликт" in p for p in личный["problems"]), личный)
        self.assertFalse(any("по сроку" in line for line in личный["done"]), личный)
        self.assertIsNone(self.boiler_on_server().get("listed"))
        self.assertEqual(self.pending("a") + self.failed("a"), [])

    def test_stale_head_without_network_folds_nothing(self):
        """Продление сделано заранее, исполнитель долго спал и первый прогон
        без сети: со старой вершины автомат не сворачивает."""
        self.save("a", "boiler-1", BOILER, "project_boiler")
        self.fed.sync("b")
        self.configure(EXECUTOR)
        self.save("b", "boiler-extend", expiring(*BOILER_WORDS, until="2026-12-31"), "project_boiler")
        with mock.patch.object(svodgit, "fetch", return_value=(False, "нет сети")):
            личный = self.sync_a()
        self.assertEqual(личный["done"], [])
        self.assertEqual(личный["problems"], ["сети нет: нет сети"])
        личный = self.sync_a()
        self.assertFalse(any("срок" in line for line in личный["done"]), личный)
        поля = self.boiler_on_server()
        self.assertEqual((поля.get("listed"), поля.get("valid_until")), (None, "2026-12-31"))
        self.assertEqual(self.pending("a") + self.failed("a"), [])

    def test_own_refusal_is_replaced_each_run_and_cleared_after_the_fix(self):
        self.save("a", "boiler-1", BOILER, "project_boiler")
        config = self.configure(EXECUTOR)
        self.fed.set_scanner(1)
        for день in (LATER, LATER + dt.timedelta(days=1)):
            итог = self.close(config, today=день)
            self.assertEqual(len(итог["problems"]), 1, итог)
            self.assertIn("свёртка по сроку auto-close-", итог["problems"][0])
            отказы = self.failed("a")
            self.assertEqual([f.name[:len("auto-close-20260920")] for f in отказы],
                             [f"auto-close-{день:%Y%m%d}"])
        self.fed.set_scanner(0)
        итог = self.close(config, today=LATER + dt.timedelta(days=2))
        self.assertEqual(итог, {"done": ["свёрнуто по сроку: project_boiler"], "problems": []})
        self.assertEqual(self.failed("a"), [])

    def test_crash_is_a_problem_not_a_fallen_timer(self):
        self.configure(EXECUTOR)
        with mock.patch.object(ms, "dated_records", side_effect=RuntimeError("сбой")):
            личный = self.sync_a()
        self.assertEqual(личный["problems"], ["автомат закрытого: RuntimeError: сбой"])
        кэш = svodgit.read_json(svodgit.sync_cache_path("personal", self.fed.states["a"]))
        self.assertEqual(кэш["problems"], личный["problems"])
        self.assertIn("таймер: автомат закрытого",
                      ms.format_nudge(ms.status(data_root=self.fed.machines["a"],
                                                state=self.fed.states["a"])))

    def test_usage_day_marks_older_than_120_days_are_swept(self):
        """Каталога claude/sessions нет вовсе: уборка меток дней всё равно идёт."""
        import memorycontext
        метки = self.fed.states["a"] / "claude" / "usage"
        (метки / "days").mkdir(parents=True)
        (метки / "records").mkdir(parents=True)
        self.assertFalse((self.fed.states["a"] / "claude" / "sessions").exists())
        сегодня = dt.date(2026, 9, 24)
        for смещение in (0, 100, 121, 400):
            (метки / "days" / (сегодня - dt.timedelta(days=смещение)).isoformat()).touch()
        (метки / "days" / "мусор").touch()
        запись = метки / "records" / "project_old"
        запись.touch()
        древность = time.time() - 400 * 86400
        os.utime(запись, (древность, древность))
        with mock.patch.object(memorycontext, "today_utc", return_value=сегодня):
            self.assertEqual(ms.prune_router_cache(self.fed.states["a"]), 2)
        self.assertEqual(sorted(p.name for p in (метки / "days").iterdir()),
                         ["2026-06-16", "2026-09-24", "мусор"])
        self.assertTrue(запись.exists())


class UsageObservationTests(Base):
    """Неиспользуемое только наблюдается: заметка статуса при покрытии в
    30 дней работы за 60 суток и учёте не короче 60 суток, никаких записей."""

    NOTE = "свернул бы (не выдавалась хуком 60 дней на машине work-laptop): "

    def commit(self, files: dict[str, bytes], message: str, days_ago: int) -> None:
        root = self.fed.root("a")
        for path, data in files.items():
            (root / path).write_bytes(data)
        когда = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_ago)).isoformat()
        env = {**os.environ, "GIT_COMMITTER_DATE": когда, "GIT_AUTHOR_DATE": когда}
        sh(root, "add", "-A", env=env)
        sh(root, "commit", "--quiet", "--no-verify", "-m", message, env=env)

    def setUp(self):
        super().setUp()
        def project(slug: str, **fields) -> bytes:
            return record(slug, **{"type": "project", "title": f"Проект {slug}",
                                   "index": "проект", **fields})
        names = ("project_idle", "project_used", "project_stale_mark", "project_edited",
                 "project_keep", "project_stand", "project_closed", "project_reopened",
                 "project_other_auto")
        files = {f"memory/{n}.md": project(n) for n in names}
        files["memory/project_dated.md"] = project("project_dated", valid_until="2999-01-01")
        files["memory/project_folded.md"] = project("project_folded", listed="false")
        files["memory/project_no_index.md"] = record("project_no_index", type="project")
        files["memory/reference_idle.md"] = record("reference_idle", type="reference",
                                                   title="Справка", index="справка")
        self.commit(files, "memory: fixture", 90)
        self.commit({"memory/project_edited.md": project("project_edited", body="Правка.\n")},
                    "memory: edit-1", 5)
        self.commit({"memory/project_closed.md": project("project_closed", listed="false")},
                    "memory: auto-close-20260920-abcd1234", 3)
        self.commit({"memory/project_reopened.md": project("project_reopened", body="Авто.\n")},
                    "memory: auto-reopen-20260920-abcd1234", 3)
        # Похожий префикс не делает правку автоматической.
        self.commit({"memory/project_other_auto.md": project("project_other_auto", body="Ч.\n")},
                    "memory: auto-other", 3)
        topics = json.loads(json.dumps(TOPICS))
        topics["topics"]["home"]["hotKeep"] = ["project_keep.md"]
        questions = json.loads(json.dumps(QUESTIONS))
        questions["questions"].append({"id": "q2", "group": "tuned", "text": "стенд",
                                       "expect": "project_stand", "markers": ["стенд"]})
        self.config = mv.Config(topics=json.dumps(topics).encode(),
                                questions=json.dumps(questions).encode())
        self.usage = self.fed.states["a"] / "claude" / "usage"
        (self.usage / "records").mkdir(parents=True)
        (self.usage / "days").mkdir(parents=True)
        свежо = time.time() - 86400
        давно = time.time() - 70 * 86400
        for slug, когда in (("project_used", свежо), ("project_stale_mark", давно)):
            (self.usage / "records" / slug).touch()
            os.utime(self.usage / "records" / slug, (когда, когда))

    def days(self, count: int, *, old: bool = True) -> None:
        сегодня = dt.datetime.now(dt.timezone.utc).date()
        for смещение in range(count):
            (self.usage / "days" / (сегодня - dt.timedelta(days=смещение)).isoformat()).touch()
        if old:
            # Старая метка покрытия не даёт, но доказывает учёт в 60 суток.
            (self.usage / "days" / (сегодня - dt.timedelta(days=70)).isoformat()).touch()

    def notes(self, config=None) -> list[str]:
        with mock.patch.object(ms.socket, "gethostname", return_value="work-laptop"):
            health, notes = ms.repo_health("personal", self.fed.root("a"), config or self.config,
                                           self.fed.states["a"])
        self.assertEqual(health, [])
        return notes

    def test_covered_machine_names_idle_project_records(self):
        self.days(30)
        head = svodgit.head(self.fed.root("a"))
        notes = self.notes()
        self.assertIn(self.NOTE + "project_idle, project_reopened, project_stale_mark", notes)
        self.assertIn("автомат за 30 дней свернул по сроку: 1", notes)
        # Наблюдение ничего не пишет.
        self.assertEqual(svodgit.head(self.fed.root("a")), head)
        self.assertEqual(self.pending("a") + self.failed("a"), [])
        строка = ms.format_nudge({"repos": [{"scope": "personal", "notes": notes}]}, monthly=True)
        self.assertIn("свернул бы", строка)
        self.assertIn("автомат за 30 дней", строка)
        self.assertEqual(ms.format_nudge({"repos": [{"scope": "personal", "notes": notes}]}), "")

    def test_without_coverage_there_is_no_idle_note_and_no_long_git_walk(self):
        for count, old in ((29, True), (30, False)):
            with self.subTest(count=count, old=old):
                shutil.rmtree(self.usage / "days")
                (self.usage / "days").mkdir()
                self.days(count, old=old)
                окна = []
                настоящий = ms._commits

                def считать(root, paths, *options):
                    окна.append(options)
                    return настоящий(root, paths, *options)

                with mock.patch.object(ms, "_commits", считать):
                    notes = self.notes()
                self.assertFalse(any(n.startswith("свернул бы") for n in notes), notes)
                self.assertIn("автомат за 30 дней свернул по сроку: 1", notes)
                полночь = dt.datetime.combine(dt.datetime.now(dt.timezone.utc).date(), dt.time(),
                                              dt.timezone.utc).timestamp()
                self.assertEqual(окна, [(f"--since=@{int(полночь - 30 * 86400)}",)])

    def test_lagging_automaton_is_a_note_and_protected_stay_expired(self):
        """closed: on, а незащищённое истекло больше двух суток назад:
        автомат отстал. Стенд и hotKeep остаются строкой «просрочено»."""
        import memorycontext
        сегодня = dt.date(2026, 9, 20)
        tree = svodgit.read_tree(self.fed.root("a"), "HEAD")
        for slug, срок in (("project_late", "2026-09-10"), ("project_recent", "2026-09-19"),
                           ("project_stand", "2026-09-01"), ("project_keep", "2026-09-01")):
            tree[f"memory/{slug}.md"] = expiring(slug, "Запись", "запись", "про запись", срок)
        for режим, ожидание in (
                ("on", ["автомат закрытого отстал (исполнитель home-pc, эта машина work-laptop): "
                        "project_late", "просрочено: valid_until истёк у project_keep, project_stand"]),
                ("observe", ["просрочено: valid_until истёк у project_keep, project_late, "
                             "project_recent, project_stand"])):
            topics = json.loads(self.config.topics)
            topics["maintenance"] = {"executor": "home-pc", "closed": режим}
            config = mv.Config(topics=json.dumps(topics).encode(), questions=self.config.questions)
            with mock.patch.object(svodgit, "read_tree", return_value=tree), \
                    mock.patch.object(memorycontext, "today_utc", return_value=сегодня):
                notes = self.notes(config)
            self.assertEqual([n for n in notes if n.startswith(("автомат закрытого", "просрочено"))],
                             ожидание)
