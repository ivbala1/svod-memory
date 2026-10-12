"""Проверки кандидата как чистые функции (Свод-0, шаг 2).

Вход только дерево, основа и байты конфигурации; фикстуры нейтральные,
конфигурация тем собирается в тесте, сканер секретов подменяется скриптом.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

REPO_SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_SOURCE / "lib"))

import memoryctl as mc  # noqa: E402
import memoryverify as mv  # noqa: E402

TODAY = dt.date(2026, 9, 4)

TOPICS = {
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
TOPICS_RAW = json.dumps(TOPICS, ensure_ascii=False).encode("utf-8")

QUESTIONS = {
    "questions": [
        {"id": "q1", "group": "tuned", "text": "как чинить зелёный принтер",
         "expect": "reference_printer", "markers": ["зелёный принтер"]},
    ],
    "negatives": [
        {"id": "n1", "text": "погода на марсе завтра"},
    ],
}
QUESTIONS_RAW = json.dumps(QUESTIONS, ensure_ascii=False).encode("utf-8")

PREAMBLE = ("# Индекс\n\n## Inbox\n\n## User\n\n## Feedback\n\n"
            "## Project\n\n## Reference\n\n")


def record(slug: str, *, body: str = "Факт.\n", **fields) -> bytes:
    head = "".join(f"{k}: {v}\n" for k, v in fields.items())
    return f"---\n{head}---\n\n# {slug}\n\n{body}".encode("utf-8")


def base_tree() -> dict[str, bytes]:
    return {
        "memory/MEMORY.md": PREAMBLE.encode("utf-8"),
        "memory/reference_printer.md": record(
            "reference_printer", type="reference", title="Зелёный принтер",
            index="как чинить зелёный принтер", probe="чем чинить принтер", body="Зелёный принтер чинится молотком.\n"),
        "memory/topics/home.md": ("# Home\n\n## Обзор\n\nДом.\n").encode("utf-8"),
    }


class Scanner:
    """Подменный gitleaks: код выхода задаётся тестом."""

    def __init__(self, code: int):
        self.dir = tempfile.TemporaryDirectory(prefix="fake-gitleaks-")
        self.path = Path(self.dir.name) / "gitleaks"
        self.path.write_text(f"#!/bin/sh\nexit {code}\n")
        self.path.chmod(self.path.stat().st_mode | stat.S_IXUSR)

    def __enter__(self):
        return str(self.path)

    def __exit__(self, *exc):
        self.dir.cleanup()


def check(candidate, base, root="personal", scanner_code=0, questions=True):
    with Scanner(scanner_code) as scanner:
        return mv.check(candidate, base, root=root,
                        config=mv.Config(topics=TOPICS_RAW,
                                         questions=QUESTIONS_RAW if questions else None),
                        today=TODAY, scanner=scanner)


class SecretTests(unittest.TestCase):
    def test_added_line_with_token_is_red_and_names_file(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/reference_printer.md"] = record(
            "reference_printer", type="reference", title="Зелёный принтер",
            index="как чинить зелёный принтер", source="разговор",
            observed_at="2026-09-04", probe="чем чинить принтер",
            body="Ключ ghp_" + "a" * 30 + "\n")
        report = check(cand, base)
        self.assertFalse(report.ok)
        self.assertTrue(any("reference_printer.md" in e and "секрет" in e
                            for e in report.errors), report.errors)

    def test_secret_already_in_base_is_not_a_patch_finding(self):
        base = base_tree()
        base["memory/reference_printer.md"] = record(
            "reference_printer", type="reference", title="Зелёный принтер",
            index="как чинить зелёный принтер", body="AKIA" + "A" * 16 + "\n")
        cand = dict(base)
        cand["memory/topics/home.md"] = "# Home\n\n## Обзор\n\nДом и сад.\n".encode("utf-8")
        errors = mv.secret_errors(base, cand, None)
        self.assertEqual(errors, ["сканер секретов gitleaks не найден; без него запись не принимается"])
        self.assertEqual(mv.secret_errors(base, base, None), [])

    def test_scanner_verdict_and_absence(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/topics/home.md"] = "# Home\n\n## Обзор\n\nДом и сад.\n".encode("utf-8")
        self.assertTrue(check(cand, base, scanner_code=0).ok)
        report = check(cand, base, scanner_code=9)
        self.assertTrue(any("gitleaks нашёл" in e for e in report.errors), report.errors)


class ShapeTests(unittest.TestCase):
    def test_form_rules_name_the_file(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/Bad Name.md"] = "---\ntype: user\n---\n\nтекст без перевода строки".encode("utf-8")
        cand["memory/notes.txt"] = b"x\n"
        errors = mv.shape_errors(cand)
        self.assertTrue(any("Bad Name.md" in e and "slug" in e for e in errors), errors)
        self.assertTrue(any("final newline" in e for e in errors), errors)
        self.assertTrue(any("notes.txt" in e for e in errors), errors)

    def test_index_fields_are_strict(self):
        errors = mv.index_field_errors({"type": "weird", "listed": "true", "title": "x"}, "f")
        self.assertEqual(len(errors), 3, errors)


class HeaderTests(unittest.TestCase):
    """source, observed_at, probe обязательны у новой и переписанной записи."""

    def test_new_record_without_provenance_is_red(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/user_cat.md"] = record("user_cat", type="user", title="Кот",
                                            index="как зовут кота")
        errors = mv.header_errors(base, cand)
        for name in ("source", "observed_at", "probe"):
            self.assertTrue(any("user_cat.md" in e and name in e for e in errors), errors)

    def test_rewritten_body_requires_provenance_header_only_does_not(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/reference_printer.md"] = record(
            "reference_printer", type="reference", title="Зелёный принтер",
            index="как чинить зелёный принтер", body="Зелёный принтер чинится отвёрткой.\n")
        self.assertTrue(mv.header_errors(base, cand))
        header_only = dict(base)
        header_only["memory/reference_printer.md"] = record(
            "reference_printer", type="reference", title="Зелёный принтер",
            index="как чинить зелёный принтер", review_after="2027-01-01",
            body="Зелёный принтер чинится молотком.\n")
        self.assertEqual(mv.header_errors(base, header_only), [])
        self.assertEqual(mv.touched_records(base, header_only), {})

    def test_unknown_field_and_bad_date(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/user_cat.md"] = record(
            "user_cat", type="user", title="Кот", index="как зовут кота",
            source="разговор", observed_at="вчера", probe="имя кота", colour="rыжий")
        errors = mv.header_errors(base, cand) + mv.shape_errors(cand)
        self.assertTrue(any("colour" in e for e in errors), errors)
        self.assertTrue(any("observed_at" in e and "ISO" in e for e in errors), errors)

    def test_date_passed_is_inclusive_and_broken_date_does_not_hide(self):
        """Дата действует по свой день включительно; пустая и битая не прошли."""
        день = dt.date(2026, 10, 9)
        for значение, итог in (("2026-10-09", None), ("2026-10-08", "2026-10-08"),
                               ("", None), ("вчера", None)):
            self.assertEqual(итог, mv.date_passed({"valid_until": значение}, "valid_until", день))
        self.assertIsNone(mv.date_passed({}, "review_after", день))

    def test_supersedes_checked_link_fields_have_no_reader(self):
        """Комплекты по requires и contradicts сняты 09.10.2026: поля без
        читателя у новой записи это отказ, как любая опечатка в имени поля."""
        base = base_tree()
        cand = dict(base)
        cand["memory/user_cat.md"] = record(
            "user_cat", type="user", title="Кот", index="как зовут кота",
            source="разговор", observed_at="2026-09-04", probe="имя кота",
            supersedes="user_cat", requires="nobody", contradicts="nobody")
        errors = mv.header_errors(base, cand)
        self.assertTrue(any("сам на себя" in e for e in errors), errors)
        self.assertTrue(any("без читателя: contradicts, requires" in e for e in errors), errors)


class LinkTests(unittest.TestCase):
    def test_broken_moved_external_and_owner_rollup(self):
        topics = mv.load_topics(TOPICS_RAW)
        tree = base_tree()
        tree["memory/reference_printer.md"] = record(
            "reference_printer", type="reference", title="Зелёный принтер",
            index="как чинить зелёный принтер",
            body="[a](nowhere.md) [b](topics/acme.md) [c](../../src/x.md) "
                 "[d](archive/reference_printer.md) [[ghost]]\n")
        errors, warnings = mv.link_errors(tree, topics, "personal")
        self.assertTrue(any("nowhere.md" in e and "broken" in e for e in errors), errors)
        self.assertTrue(any("moved" in e for e in errors), errors)
        self.assertFalse(any("acme.md" in e for e in errors), errors)
        self.assertFalse(any("src/x.md" in e for e in errors), errors)
        self.assertTrue(any("ghost" in w for w in warnings), warnings)


class ReachTests(unittest.TestCase):
    def test_new_orphan_is_red_old_orphan_is_tolerated(self):
        topics = mv.load_topics(TOPICS_RAW)
        base = base_tree()
        base["memory/old_orphan.md"] = record("old_orphan")
        cand = dict(base)
        cand["memory/new_orphan.md"] = record("new_orphan")
        errors = mv.reach_errors(base, cand, topics, "personal")
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("new_orphan.md", errors[0])

    def test_rollup_mention_keeps_record_reachable(self):
        topics = mv.load_topics(TOPICS_RAW)
        base = base_tree()
        cand = dict(base)
        cand["memory/project_x.md"] = record("project_x")
        cand["memory/topics/home.md"] = "# Home\n\n## Обзор\n\nСм. project_x.md\n".encode("utf-8")
        self.assertEqual(mv.reach_errors(base, cand, topics, "personal"), [])

    def test_archive_without_successor_is_red_when_new(self):
        topics = mv.load_topics(TOPICS_RAW)
        base = base_tree()
        cand = dict(base)
        cand["memory/archive/old.md"] = "# old\n\nбез пометки\n".encode("utf-8")
        errors = mv.reach_errors(base, cand, topics, "personal")
        self.assertTrue(any("archive/old.md" in e for e in errors), errors)
        cand["memory/archive/old.md"] = (
            "# old\n\nЗамещено записью [reference_printer.md](../reference_printer.md)\n").encode("utf-8")
        self.assertEqual(mv.reach_errors(base, cand, topics, "personal"), [])


class ProbeTests(unittest.TestCase):
    """Крючок probe находит запись тем же отбором, что у роутера."""

    def _tree(self, probe: str) -> dict[str, bytes]:
        tree = base_tree()
        tree["memory/reference_printer.md"] = record(
            "reference_printer", type="reference", title="Зелёный принтер",
            index="как чинить зелёный принтер", probe=probe,
            body="Зелёный принтер чинится молотком.\n")
        return tree

    def test_probe_found_and_missed(self):
        base = base_tree()
        good = check(self._tree("чем чинить принтер зелёного цвета"), base)
        self.assertTrue(good.ok, good.errors)
        bad = check(self._tree("рецепт борща на зиму"), base)
        self.assertTrue(any("не находит запись" in e for e in bad.errors), bad.errors)

    def test_expired_record_does_not_block_other_submissions(self):
        """Истёкшую запись роутер не выдаёт, её крючок молчит: иначе первый
        же прошедший valid_until отказывал бы любой подаче в личный корень."""
        base = base_tree()
        cand = self._tree("рецепт борща на зиму")
        cand["memory/reference_printer.md"] = cand["memory/reference_printer.md"].replace(
            b"---\n", b"---\nvalid_until: 2020-01-01\n", 1)
        report = check(cand, base)
        self.assertFalse(any("не находит запись" in e for e in report.errors), report.errors)
        cand["memory/reference_printer.md"] = cand["memory/reference_printer.md"].replace(
            b"valid_until: 2020-01-01", b"valid_until: 2999-12-31", 1)
        report = check(cand, base)
        self.assertTrue(any("не находит запись" in e for e in report.errors), report.errors)

    def test_tautology_is_red(self):
        report = check(self._tree("как чинить зелёный принтер"), base_tree())
        self.assertTrue(any("повторяет" in e for e in report.errors), report.errors)

    def test_all_probes_share_one_index(self):
        """Крючки всего дерева проверяются по одному индексу: чтение корпуса
        на каждую запись росло квадратично с числом записей."""
        import memorycontext as mc
        cand = self._tree("чем чинить принтер зелёного цвета")
        for name, hook, probe in (
                ("reference_kettle", "как кипятить воду в чайнике", "кипятить воду чайник"),
                ("reference_toaster", "как поджарить хлеб в тостере", "поджарить хлеб тостер")):
            cand[f"memory/{name}.md"] = record(
                name, type="reference", title=hook.capitalize(), index=hook,
                source="разговор", observed_at="2026-09-04", probe=probe, body="Факт.\n")
        with mock.patch.object(mc, "select_index_entries",
                               wraps=mc.select_index_entries) as ranked:
            report = check(cand, base_tree(), questions=False)
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(ranked.call_count, 3)
        первый = ranked.call_args_list[0].args[2]
        for вызов in ranked.call_args_list:
            self.assertIs(вызов.args[2], первый)

    def test_probes_and_stand_use_whitelist_of_config_version(self):
        """Второе место писателя и стенда видит белый список своей версии
        конфигурации, а не живого файла: иначе крючок прошёл бы у писателя и
        не сработал у роутера. Битый список отказывает словами."""
        import memorycontext as mc
        raw = json.dumps(dict(TOPICS, personal={"secondPlaceWhitelist": ["reference_old"]}),
                         ensure_ascii=False).encode("utf-8")
        self.assertEqual(mv.load_topics(raw).second_place, ("reference_old",))
        дерево = self._tree("чем чинить принтер зелёного цвета")
        дерево["memory/reference_old.md"] = record(
            "reference_old", type="reference", title="Старый принтер", index="картридж",
            listed="false", body="Картридж менять раз в год.\n")
        пул: list[str] = []
        настоящий = mc.second_place_candidates
        with Scanner(0) as scanner, mock.patch.object(
                mc, "select_index_entries", wraps=mc.select_index_entries) as ranked, \
                mock.patch.object(mc, "second_place_candidates", side_effect=lambda *a: (
                    пул.extend(e.slug for e in настоящий(*a)) or настоящий(*a))):
            mv.check(дерево, base_tree(), root="personal",
                     config=mv.Config(topics=raw, questions=QUESTIONS_RAW),
                     today=TODAY, scanner=scanner)
        self.assertGreater(ranked.call_count, 1)
        for вызов in ranked.call_args_list:
            self.assertEqual(вызов.kwargs.get("whitelist"), ("reference_old",))
        self.assertIn("reference_old.md", пул)
        for плохой in ("reference_old", ["reference_old.md"], [5], ["reference_old"] * 2):
            with self.subTest(список=плохой), self.assertRaises(mc.MemoryctlError):
                mv.load_topics(json.dumps(dict(TOPICS, personal={
                    "secondPlaceWhitelist": плохой})).encode("utf-8"))

    def test_client_probe_through_topic_delivery(self):
        rollup = ("# Acme\n\n## Обзор\n\nУстройство системы.\n\n"
                  "## Доступы\n\nSSH идёт через бастион.\n")
        base = {"memory/topics/acme.md": rollup.encode("utf-8")}
        cand = dict(base)
        cand["memory/reference_acme_bastion.md"] = record(
            "reference_acme_bastion", source="разговор", observed_at="2026-09-04",
            section="доступы", probe="как попасть по ssh на серверы", body="Бастион.\n")
        report = check(cand, base, root="clients/acme")
        self.assertTrue(report.ok, report.errors)
        cand["memory/reference_acme_bastion.md"] = record(
            "reference_acme_bastion", source="разговор", observed_at="2026-09-04",
            section="Доступы", probe="какой у нас обзор устройства", body="Бастион.\n")
        report = check(cand, base, root="clients/acme")
        self.assertTrue(any("не содержит ссылки" in e for e in report.errors), report.errors)

    def test_expired_client_record_probe_is_silent(self):
        """Истёкшей клиентской записи нет в списке раздела, её крючок молчит,
        как у личной: иначе срок отказывал бы каждой подаче (ревью 12.10.2026)."""
        rollup = "# Acme\n\n## Обзор\n\nУстройство.\n\n## Доступы\n\nSSH через бастион.\n"
        base = {"memory/topics/acme.md": rollup.encode("utf-8")}
        cand = dict(base)
        cand["memory/reference_acme_bastion.md"] = record(
            "reference_acme_bastion", source="разговор", observed_at="2026-09-04",
            section="доступы", probe="как попасть по ssh на серверы", valid_until="2020-01-01",
            body="Бастион.\n")
        import memorycontext
        self.assertEqual({}, memorycontext.section_records(self._laid_out(cand)))
        report = check(cand, base, root="clients/acme")
        self.assertFalse(any("не содержит ссылки" in e for e in report.errors), report.errors)

    def _laid_out(self, tree: dict[str, bytes]) -> Path:
        каталог = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, каталог)
        for путь, байты in tree.items():
            (каталог / путь).parent.mkdir(parents=True, exist_ok=True)
            (каталог / путь).write_bytes(байты)
        return каталог

    def test_client_probe_also_through_the_session_continuation(self):
        """Полная выдача доносит шестую строку списка, продолжение сессии с
        бюджетом 4 200 срезает её: крючок обязан дойти в обоих режимах."""
        rollup = "# Acme\n\n## Обзор\n\n" + "о" * 3380 + "\n\n## Доступы\n\nSSH.\n"
        cand = {"memory/topics/acme.md": rollup.encode("utf-8"), **{
            f"memory/acme_{c}.md": record(f"acme_{c}", section="Доступы", probe="обзор, доступ",
                                         title="Заголовок записи " + c * 100, index="запись")
            for c in "abcdef"}}
        errors = " ".join(check(cand, {}, root="clients/acme").errors)
        self.assertIn("acme_f.md: крючок «обзор, доступ» не находит", errors)
        self.assertNotIn("acme_a.md: крючок", errors)


class ProbesReportTests(unittest.TestCase):
    """`memory-eval probes` считает те же крючки, что проверяет писатель."""

    def test_expired_record_is_not_a_miss(self):
        """Истёкшую запись отбор не выдаёт, писатель её крючок пропускает, и
        отчёт её не считает: иначе до свёртки автоматом (а запись стенда,
        hotKeep и глобальную он не сворачивает вовсе) отчёт красный при
        исправном крючке. Граница та же: срок действует по свой день."""
        import memorycontext
        import memoryprobes
        for срок, считается in (("2026-09-03", False), ("2026-09-04", True),
                                ("2026-09-05", True)):
            with self.subTest(valid_until=срок), tempfile.TemporaryDirectory() as tmp:
                tree = base_tree()
                tree["memory/reference_printer.md"] = record(
                    "reference_printer", type="reference", title="Зелёный принтер",
                    index="как чинить зелёный принтер", valid_until=срок,
                    probe="чем чинить принтер зелёного цвета",
                    body="Зелёный принтер чинится молотком.\n")
                memorycontext._bm25_documents.cache_clear()
                итог = memoryprobes.probes_for_root(mv.lay_out(tree, Path(tmp)), today=TODAY)
                memorycontext._bm25_documents.cache_clear()
                self.assertEqual(итог["total"], int(считается), итог)
                self.assertEqual(итог["hit2"], int(считается), итог)
                self.assertEqual(итог["misses"], [], итог)

    def test_report_counts_both_roots_on_one_date(self):
        """Прогон через полночь UTC не считает global и personal по разным дням."""
        import memorycontext
        import memoryprobes
        корни = (Path("global"), Path("personal"))
        with mock.patch.object(memorycontext, "today_utc",
                               side_effect=[TODAY, TODAY + dt.timedelta(days=1)]), \
                mock.patch.object(memorycontext, "index_roots", return_value=корни), \
                mock.patch.object(memoryprobes, "probes_for_root", return_value={}) as корень:
            memoryprobes.report(Path("федерация"))
        self.assertEqual([вызов.kwargs["today"] for вызов in корень.call_args_list],
                         [TODAY, TODAY])

class ConfigTests(unittest.TestCase):
    def test_topics_are_parsed_once_per_bytes(self):
        """Один разбор на версию байтов: писатель и статус зовут load_topics
        по несколько раз за проход, другие байты дают другой разбор."""
        first = mv.load_topics(TOPICS_RAW)
        self.assertIs(first, mv.load_topics(TOPICS_RAW))
        self.assertEqual(first.budget, {})
        with_budget = dict(TOPICS, budget={"softBytes": 10, "softLines": 2,
                                           "hardBytes": 20, "hardLines": 4})
        other = mv.load_topics(json.dumps(with_budget, ensure_ascii=False).encode("utf-8"))
        self.assertIsNot(first, other)
        self.assertEqual(other.budget["hardBytes"], 20)
        self.assertEqual(other.placement, first.placement)


class ArchivedRollupTests(unittest.TestCase):
    """Сводка ушедшего заказчика: тема снята с роутера, а свёрнутые записи
    и архив ссылаются на неё. Ссылка законна, в темах её нет."""

    RAW = json.dumps(dict(TOPICS, archivedRollups={"_comment": "пояснение",
                                                    "gone.md": "clients/gone"}),
                     ensure_ascii=False).encode("utf-8")

    def test_links_and_archive_accept_archived_rollup(self):
        topics = mv.load_topics(self.RAW)
        self.assertNotIn("gone.md", topics.placement)
        tree = base_tree()
        tree["memory/reference_printer.md"] = record(
            "reference_printer", type="reference", title="Зелёный принтер",
            index="как чинить зелёный принтер", body="Свёрнуто в сводку [g](topics/gone.md)\n")
        self.assertEqual(mv.link_errors(tree, topics, "personal")[0], [])
        without = mv.load_topics(TOPICS_RAW)
        self.assertTrue(any("gone.md" in e for e in mv.link_errors(tree, without, "personal")[0]))
        base = base_tree()
        cand = dict(base)
        cand["memory/archive/old.md"] = "# old\n\nСвёрнуто в сводку [topics/gone.md](../topics/gone.md)\n".encode("utf-8")
        self.assertEqual(mv.reach_errors(base, cand, topics, "personal"), [])
        self.assertTrue(mv.reach_errors(base, cand, without, "personal"))

    def test_archived_rollup_copy_outside_owner_is_refused(self):
        """Сводка ушедшего заказчика не становится вторым каноном в личном
        корне и не попадает к другому заказчику."""
        topics = mv.load_topics(self.RAW)
        base = base_tree()
        cand = dict(base, **{"memory/topics/gone.md": b"# Gone\n"})
        for root in ("personal", "clients/acme"):
            with self.subTest(root=root):
                errors = mv.foreign_errors(base, cand, root, topics)
                self.assertTrue(any("topics/gone.md" in e for e in errors), errors)

    def test_bad_archived_section_is_refused(self):
        for section in ({"acme.md": "clients/zzz"}, {"x.md": "clients/acme"},
                        {"x.txt": "clients/x"}, {"x.md": "personal"}, ["x.md"]):
            with self.subTest(section=section):
                raw = json.dumps(dict(TOPICS, archivedRollups=section), ensure_ascii=False)
                with self.assertRaises(ValueError):
                    mv.load_topics(raw.encode("utf-8"))


class ForeignTests(unittest.TestCase):
    def test_owner_rollup_copy_in_common_and_foreign_rollup_in_client(self):
        topics = mv.load_topics(TOPICS_RAW)
        tree = base_tree()
        tree["memory/topics/acme.md"] = b"# Acme\n"
        errors = mv.foreign_errors(base_tree(), tree, "personal", topics)
        self.assertTrue(any("второй канон" in e for e in errors), errors)
        client = {"memory/topics/acme.md": b"# Acme\n", "memory/topics/home.md": b"# Home\n"}
        errors = mv.foreign_errors({}, client, "clients/acme", topics)
        self.assertTrue(any("утечка" in e for e in errors), errors)
        self.assertEqual(mv.foreign_errors({}, {"memory/topics/acme.md": b"# Acme\n"},
                                           "clients/acme", topics), [])

    def test_drift_ratchet(self):
        topics = mv.load_topics(TOPICS_RAW)
        base = base_tree()
        cand = dict(base)
        cand["memory/project_acme_billing.md"] = record(
            "project_acme_billing", type="project", title="Биллинг", index="счета acme")
        errors = mv.foreign_errors(base, cand, "personal", topics)
        self.assertTrue(any("project_acme_billing" in e for e in errors), errors)
        self.assertEqual(mv.foreign_errors(cand, cand, "personal", topics), [])


class SectionTests(unittest.TestCase):
    def test_changed_section_over_cap_is_red_untouched_is_not(self):
        topics = mv.load_topics(TOPICS_RAW)
        fat = "# Home\n\n## Обзор\n\n" + ("слово " * 800) + "\n"
        base = {"memory/topics/home.md": fat.encode("utf-8")}
        self.assertEqual(mv.section_errors(base, base, topics)[0], [])
        cand = {"memory/topics/home.md": (fat + "ещё\n").encode("utf-8")}
        errors, _ = mv.section_errors(base, cand, topics)
        self.assertTrue(any("потолке" in e for e in errors), errors)

    def test_unselectable_new_section_is_a_warning(self):
        topics = mv.load_topics(TOPICS_RAW)
        base = base_tree()
        cand = dict(base)
        cand["memory/topics/home.md"] = "# Home\n\n## Обзор\n\nДом.\n\n## Прочее\n\nХвост.\n".encode("utf-8")
        errors, warnings = mv.section_errors(base, cand, topics)
        self.assertEqual(errors, [])
        self.assertTrue(any("не выберет" in w for w in warnings), warnings)


class StandTests(unittest.TestCase):
    def test_question_losing_its_record_is_red(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/reference_printer.md"] = record(
            "reference_printer", type="reference", title="Зелёный принтер",
            index="как чинить зелёный принтер", listed="false",
            body="Зелёный принтер чинится молотком.\n")
        # Правка только шапки: крючка не требует, но запись ушла из индекса.
        report = check(cand, base)
        self.assertTrue(any("стенд" in e and "q1" in e for e in report.errors), report.errors)

    def test_new_record_shadowing_other_question_is_a_warning(self):
        """Новая запись перебила чужую по её вопросу: факт принимается, а
        не переписывается ради теста."""
        questions = {"questions": [{"id": "q2", "group": "tuned", "text": "принтер в офисе",
                                    "expect": "reference_printer", "markers": ["принтер"]}],
                     "negatives": []}
        config = mv.Config(topics=TOPICS_RAW,
                           questions=json.dumps(questions, ensure_ascii=False).encode("utf-8"))
        base = base_tree()
        cand = dict(base)
        cand["memory/reference_office.md"] = record(
            "reference_office", type="reference", title="Принтер в офисе",
            index="принтер в офисе сломан", source="разговор", observed_at="2026-09-04",
            probe="сломался принтер в офисе", body="Офисный принтер сдан в ремонт.\n")
        with Scanner(0) as scanner:
            report = mv.check(cand, base, root="personal", config=config,
                              today=TODAY, scanner=scanner)
        self.assertTrue(report.ok, report.errors)
        self.assertTrue(any("q2" in w and "reference_printer" in w for w in report.warnings),
                        report.warnings)

    def test_new_record_firing_negative_is_a_warning(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/reference_mars.md"] = record(
            "reference_mars", type="reference", title="Погода на Марсе",
            index="погода марс прогноз", source="разговор", observed_at="2026-09-04",
            probe="какая погода на марсе", body="На Марсе холодно.\n")
        report = check(cand, base)
        self.assertTrue(report.ok, report.errors)
        self.assertTrue(any("отрицательный" in w and "n1" in w for w in report.warnings),
                        report.warnings)

    def test_stand_skipped_without_index_or_questions(self):
        import memoryeval
        base = {"memory/topics/acme.md": b"# Acme\n", "memory/MEMORY.md": b"# I\n"}
        with mock.patch.object(memoryeval, "stand") as stand:
            report = check(base, base, root="clients/acme")
            self.assertTrue(report.ok, report.errors)
            check(base_tree(), base_tree(), questions=False)
        stand.assert_not_called()

    def test_absolute_failures_reject_writer_even_without_a_base(self):
        tree = base_tree()
        tree.pop("memory/reference_printer.md")
        for base in (tree, None):
            with self.subTest(base=base):
                report = check(tree, base)
                self.assertFalse(report.ok)
                self.assertTrue(any("эталон исчез" in e for e in report.errors), report.errors)

    def test_marker_loss_rejects_unchanged_tree(self):
        tree = base_tree()
        tree["memory/reference_printer.md"] = tree["memory/reference_printer.md"].replace(
            "Зелёный принтер чинится молотком.".encode(), b"No answer.")
        report = check(tree, tree)
        self.assertFalse(report.ok)
        self.assertTrue(any("признака ответа" in e for e in report.errors), report.errors)

    def test_deliverable_records_need_probes_but_folded_records_do_not(self):
        tree = base_tree()
        tree["memory/reference_printer.md"] = tree["memory/reference_printer.md"].replace(
            "probe: чем чинить принтер\n".encode(), b"")
        report = check(tree, tree)
        self.assertTrue(any("без крючка probe" in e for e in report.errors), report.errors)
        tree["memory/reference_printer.md"] = tree["memory/reference_printer.md"].replace(
            b"---\n", b"---\nlisted: false\n", 1)
        self.assertEqual(mv.probe_required_errors(tree, "personal"), [])
        self.assertTrue(mv.probe_required_errors(tree, "clients/acme"))


class CheckTests(unittest.TestCase):
    def test_unchanged_tree_is_green_and_stand_runs(self):
        import memoryeval
        base = base_tree()
        with mock.patch.object(memoryeval, "stand", wraps=memoryeval.stand) as stand:
            report = check(base, base)
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(stand.call_count, 2)

    def test_first_commit_has_no_base(self):
        cand = base_tree()
        cand["memory/reference_printer.md"] = record(
            "reference_printer", type="reference", title="Зелёный принтер",
            index="как чинить зелёный принтер", source="разговор",
            observed_at="2026-09-04", probe="чем чинить принтер зелёного цвета",
            body="Зелёный принтер чинится молотком.\n")
        report = check(cand, None)
        self.assertTrue(report.ok, report.errors)


class DeliveryWarningTests(unittest.TestCase):
    """Писатель предупреждает, когда изменённое до агента доедет не целиком."""

    def test_long_record_warns_short_record_does_not(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/reference_long.md"] = record(
            "reference_long", type="reference", title="Длинная справка",
            index="длинная справка про хвост", source="разговор", observed_at="2026-09-21",
            probe="что в длинной справке про хвост", body="Начало.\n" + "вода " * 900 + "\n")
        report = check(cand, base)
        self.assertTrue(report.ok, report.errors)
        предупреждения = [w for w in report.warnings if w.startswith("memory/reference_long.md:")]
        self.assertEqual(len(предупреждения), 1, report.warnings)
        self.assertIn("до агента доезжают первые", предупреждения[0])
        self.assertFalse(any(w.startswith("memory/reference_printer.md:") for w in report.warnings))

    def test_folded_and_other_roots_are_silent(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/reference_long.md"] = record(
            "reference_long", type="reference", title="Длинная справка",
            index="длинная справка", source="разговор", observed_at="2026-09-21",
            probe="что в длинной справке", listed="false", body="вода " * 900 + "\n")
        self.assertFalse(any(w.startswith("memory/reference_long.md:")
                             for w in check(cand, base).warnings))
        with tempfile.TemporaryDirectory() as tmp:
            корень = mv.lay_out(cand, Path(tmp) / "x")
            self.assertEqual(mv.delivery_warnings(base, cand, root="global", laid_out=корень), [])

    def test_inbox_long_items_and_overflow_warn(self):
        base = base_tree()
        cand = dict(base)
        пункты = ["- [2026-09-21] Длинный пункт " + "подробность " * 60]
        пункты += [f"- [2026-09-{n:02d}] Короткий пункт номер {n}" for n in range(1, 20)]
        cand["memory/personal_inbox.md"] = (
            "# Инбокс\n\n## Дела\n" + "\n".join(пункты) + "\n").encode("utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            корень = mv.lay_out(cand, Path(tmp) / "x")
            слова = mv.delivery_warnings(base, cand, root="personal", laid_out=корень)
        self.assertTrue(any("1 из 20 пунктов длиннее 360" in w for w in слова), слова)
        self.assertTrue(any("целиком до агента доезжают" in w for w in слова), слова)
        self.assertTrue(all(w.startswith("memory/personal_inbox.md:") for w in слова))


if __name__ == "__main__":
    unittest.main()


class GlobalContractTests(unittest.TestCase):
    """Свод-0, шаг 4: глобальный репозиторий это контракт целиком."""

    PREAMBLE = "# Индекс\n\n## Feedback\n".encode("utf-8")

    def rule(self, slug, index="правило", **extra):
        head = f'type: feedback\ntitle: "{slug}"\nindex: "{index}"\n' + "".join(
            f"{k}: {v}\n" for k, v in extra.items())
        return f"---\n{head}---\n\n# {slug}\n\nТекст.\n".encode("utf-8")

    def test_empty_contract_is_refused(self):
        tree = {"memory/MEMORY.md": self.PREAMBLE}
        self.assertTrue(any("пуст" in e for e in mv.contract_errors(tree)))

    def test_hidden_archive_and_topics_are_refused(self):
        tree = {"memory/MEMORY.md": self.PREAMBLE,
                "memory/feedback_a.md": self.rule("feedback_a"),
                "memory/feedback_b.md": self.rule("feedback_b", listed="false"),
                "memory/archive/feedback_c.md": self.rule("feedback_c"),
                "memory/topics/home.md": "# Home\n".encode("utf-8")}
        errors = mv.contract_errors(tree)
        self.assertTrue(any("feedback_b.md" in e for e in errors), errors)
        self.assertTrue(any("archive/feedback_c.md" in e for e in errors), errors)
        self.assertTrue(any("topics/home.md" in e for e in errors), errors)
        self.assertFalse(any("feedback_a.md" in e for e in errors), errors)

    def test_contract_over_limit_is_refused(self):
        # Строка индекса режется роутером до 300 символов, поэтому потолок
        # 2 600 набирается числом правил, а не одной длинной строкой.
        tree = {"memory/MEMORY.md": self.PREAMBLE}
        for i in range(12):
            tree[f"memory/feedback_{i}.md"] = self.rule(f"feedback_{i}", index="х" * 280)
        self.assertTrue(any("потолка" in e for e in mv.contract_errors(tree)))
        small = {"memory/MEMORY.md": self.PREAMBLE, "memory/feedback_0.md": tree["memory/feedback_0.md"]}
        self.assertFalse(any("потолка" in e for e in mv.contract_errors(small)))

    def test_unresolved_wiki_link_is_an_error_only_in_global(self):
        tree = {"memory/MEMORY.md": "# Индекс\n".encode("utf-8"),
                "memory/feedback_a.md": "---\ntype: feedback\n---\n\nСм. [[nowhere]].\n".encode("utf-8")}
        errors, warnings = mv.link_errors(tree, None, "global")
        self.assertTrue(any("unresolved wiki link" in e for e in errors))
        errors, warnings = mv.link_errors(tree, None, "personal")
        self.assertEqual(errors, [])
        self.assertTrue(any("unresolved wiki link" in w for w in warnings))


class CrossAreaLinkTests(unittest.TestCase):
    """Указатель из области в область федерации.

    Корпус разделён на области, и вики-ссылка разрешается только внутри своей
    (Свод-0, шаг 4). Но сводка заказчика законно называет личную запись, из
    которой её формулировка выросла: три десятка таких указателей висели
    предупреждениями, и на их фоне настоящий обрыв стал бы невидим.
    ⚠️ Ссылка в область ДРУГОГО заказчика предупреждением остаётся: ради
    запрета этой утечки области и разделяли.
    """

    def федерация(self, где_цель: str | None):
        корень = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, корень, True)
        for область in ("personal", "clients/acme", "clients/other"):
            (корень / область / "memory").mkdir(parents=True)
        if где_цель is not None:
            (корень / где_цель / "memory" / "reference_source.md").write_text(
                "---\ntype: reference\n---\n\nПервоисточник.\n", encoding="utf-8")
        сводка = корень / "clients/acme" / "memory" / "topics"
        сводка.mkdir()
        (сводка / "acme.md").write_text(
            "# Acme\n\n## Обзор\n\nФакт, источник [[reference_source]].\n",
            encoding="utf-8")
        return корень

    def проверить(self, корень):
        область = корень / "clients/acme"
        errors, warnings = mc.validate_links(
            область, mc.collect_memory_files(область), "clients/acme",
            topics_raw=TOPICS_RAW)
        return errors, warnings, mc.countable_link_warnings(warnings)

    def test_pointer_to_the_personal_area_is_provenance(self):
        errors, warnings, долги = self.проверить(self.федерация("personal"))
        self.assertEqual(errors, [])
        self.assertEqual(долги, set(), "провенанс долгом не является")
        self.assertTrue(any("wiki link to the personal area" in w for w in warnings), warnings)

    def test_pointer_to_another_client_stays_a_warning(self):
        _, _, долги = self.проверить(self.федерация("clients/other"))
        self.assertTrue(any("unresolved wiki link" in w for w in долги), долги)

    def test_pointer_to_nowhere_stays_a_warning(self):
        _, _, долги = self.проверить(self.федерация(None))
        self.assertTrue(any("unresolved wiki link" in w for w in долги), долги)


class FoldedReachTests(unittest.TestCase):
    """Свёрнутая личная запись (`listed: false`) достижима: её находит поиск
    по корпусу, поэтому свернуть её можно без сводки. Потерять строку
    индекса без явной свёртки нельзя. У заказчика свёрнутую держит сводка."""

    ЧАЙНИК = dict(type="reference", title="Чайник на даче",
                  index="электрический чайник, накипь", probe="чем снять накипь в чайнике")
    ТЕЛО = "Накипь снимается лимонной кислотой.\n"

    def kettle_base(self):
        tree = base_tree()
        tree["memory/reference_kettle.md"] = record("reference_kettle", body=self.ТЕЛО, **self.ЧАЙНИК)
        return tree

    def test_folding_personal_record_with_search_line_is_accepted(self):
        base = self.kettle_base()
        cand = dict(base)
        cand["memory/reference_kettle.md"] = record(
            "reference_kettle", body=self.ТЕЛО, listed="false", **self.ЧАЙНИК)
        report = check(cand, base)
        self.assertFalse(any("недостижим" in e for e in report.errors), report.errors)
        self.assertTrue(report.ok, report.errors)

    def test_record_losing_index_line_without_folding_is_lost(self):
        """Потеря строки индекса без явной свёртки это ошибка, а не свёртка."""
        base = self.kettle_base()
        cand = dict(base)
        поля = {k: v for k, v in self.ЧАЙНИК.items() if k != "index"}
        cand["memory/reference_kettle.md"] = record("reference_kettle", body=self.ТЕЛО, **поля)
        report = check(cand, base)
        self.assertTrue(any("reference_kettle.md" in e and "недостижим" in e
                            for e in report.errors), report.errors)

    def test_client_folded_record_still_needs_rollup(self):
        base = {
            "memory/MEMORY.md": PREAMBLE.encode("utf-8"),
            "memory/topics/acme.md": "# Acme\n\n## Обзор\n\nУстройство.\n".encode("utf-8"),
            "memory/reference_gate.md": record(
                "reference_gate", type="reference", title="Шлагбаум у офиса",
                index="пульт шлагбаума", probe="как открыть шлагбаум", body="Пульт у охраны.\n"),
        }
        cand = dict(base)
        cand["memory/reference_gate.md"] = record(
            "reference_gate", type="reference", title="Шлагбаум у офиса",
            index="пульт шлагбаума", probe="как открыть шлагбаум", listed="false",
            body="Пульт у охраны.\n")
        report = check(cand, base, root="clients/acme")
        self.assertTrue(any("reference_gate.md" in e and "недостижим" in e
                            for e in report.errors), report.errors)


class OctoberTwelveReviewTests(unittest.TestCase):
    """Ревью 11.10.2026: шапка, ссылки, доставка и стенд называют причину
    отказа словами, не падают исключением и не повторяют секрет."""

    TOKEN = "ghp_" + "a" * 30  # синтетический, не настоящий (ревью 11.10.2026)
    ACME = "# Acme\n\n## Обзор\n\nУстройство системы.\n\n## Доступы\n\nSSH идёт через бастион.\n"

    def client_record(self, slug="reference_acme_bastion", body="Бастион.\n", **extra):
        поля = dict(source="разговор", observed_at="2026-09-04", section="Доступы",
                    probe="как попасть по ssh на серверы")
        поля.update(extra)
        return record(slug, body=body, **поля)

    def test_header_only_edit_with_field_typo_is_refused(self):
        base = base_tree()
        old = base["memory/reference_printer.md"].decode("utf-8")
        for поле in ("valid_untill", "vaild_until", "review-after"):
            cand = dict(base)
            cand["memory/reference_printer.md"] = old.replace(
                "probe:", f"{поле}: 2026-09-04\nprobe:", 1).encode("utf-8")
            errors = mv.header_errors(base, cand)
            self.assertTrue(any(поле in e and "без читателя" in e for e in errors), errors)
        # Прежнее поле правку одной шапки не останавливает (ревью 11.10.2026).
        base["memory/reference_printer.md"] = old.replace(
            "probe:", "legacy: x\nprobe:", 1).encode("utf-8")
        cand = dict(base)
        cand["memory/reference_printer.md"] = base["memory/reference_printer.md"].replace(
            b"probe:", b"valid_until: 2026-09-04\nprobe:", 1)
        self.assertEqual(mv.header_errors(base, cand), [])

    def test_title_with_bracket_is_named_in_common_roots_only(self):
        # Скобки в title индекс разбирает (ревью 11.10.2026, S20); отказ только
        # там, где строка индекса всё же не разбирается: title со ссылкой внутри.
        base = base_tree()
        cand = dict(base)
        cand["memory/reference_nas.md"] = record(
            "reference_nas", type="reference", title="Доступ к хранилищу [NAS] дома",
            index="адрес и порт файлового хранилища", probe="как зайти на домашнее хранилище",
            source="разговор", observed_at="2026-09-01", body="Хранилище по адресу.\n")
        report = check(cand, base)
        self.assertFalse(any("скобку ]" in e for e in report.errors), report.errors)
        cand["memory/reference_nas.md"] = record(
            "reference_nas", type="reference", title="Хранилище](other.md) дома",
            index="адрес и порт файлового хранилища", probe="как зайти на домашнее хранилище",
            source="разговор", observed_at="2026-09-01", body="Хранилище по адресу.\n")
        report = check(cand, base)
        self.assertTrue(any("reference_nas.md" in e and "скобку ]" in e
                            for e in report.errors), report.errors)
        правило = {"memory/MEMORY.md": "# Индекс\n\n## Feedback\n".encode("utf-8"),
                   "memory/feedback_a.md": record("feedback_a", type="feedback",
                                                  title="Правило](other.md) [важно]", index="правило")}
        with Scanner(0) as scanner:
            report = mv.check(правило, {}, root="global", today=TODAY, scanner=scanner,
                              config=mv.Config(topics=json.dumps(dict(
                                  TOPICS, federationMembers=["acme"])).encode()))
        self.assertTrue(any("скобку ]" in e for e in report.errors), report.errors)
        правило["memory/feedback_a.md"] = правило["memory/feedback_a.md"].replace(
            "Правило](other.md) [важно]".encode("utf-8"), "Правило важно".encode("utf-8"))
        self.assertEqual(mv.contract_errors(правило), [])
        base = {"memory/topics/acme.md": self.ACME.encode("utf-8")}
        cand = dict(base)
        cand["memory/reference_acme_bastion.md"] = self.client_record(
            type="reference", title="Бастион [SSH]", index="вход по ssh")
        report = check(cand, base, root="clients/acme")
        self.assertFalse(any("скобку" in e for e in report.errors), report.errors)

    def test_multiline_header_value_is_refused(self):
        base = base_tree()
        text = ("---\ntype: reference\ntitle: Роутер на даче\nindex: >-\n  микротик, wifi,\n"
                "  провайдер ростелеком\nprobe: как перезагрузить роутер на даче\n"
                "source: разговор\nobserved_at: 2026-09-01\n---\n\n# Роутер\n\nВ шкафу.\n")
        cand = dict(base, **{"memory/reference_router.md": text.encode("utf-8")})
        errors = mv.header_errors(base, cand)
        self.assertTrue(any("reference_router.md" in e and "поля index" in e for e in errors), errors)
        continued = text.replace("index: >-\n  микротик, wifi,", "index: микротик, wifi,")
        cand["memory/reference_router.md"] = continued.encode("utf-8")
        self.assertTrue(any("поля index" in e for e in mv.header_errors(base, cand)))
        nested = text.replace("index: >-\n  микротик, wifi,\n  провайдер ростелеком\n",
                              "index: микротик, wifi\nmetadata:\n  # заметка\n  author: x\n")
        cand["memory/reference_router.md"] = nested.encode("utf-8")
        self.assertEqual(mv.header_errors(base, cand), [])
        # Правка одной шапки тоже не сохраняет теряемое значение (ревью 11.10.2026).
        base["memory/reference_router.md"] = text.encode("utf-8")
        cand["memory/reference_router.md"] = text.replace(
            "probe:", "listed: false\nprobe:", 1).encode("utf-8")
        self.assertTrue(any("поля index" in e for e in mv.header_errors(base, cand)))

    def test_empty_or_commented_multiline_value_is_refused(self):
        base = base_tree()
        old = base["memory/reference_printer.md"].decode()
        for value in ("", ">- # продолжение", "|2+ # продолжение"):
            with self.subTest(value=value):
                text = old.replace("index: как чинить зелёный принтер",
                                   f"index: {value}\n  как чинить зелёный принтер")
                cand = dict(base, **{"memory/reference_printer.md": text.encode()})
                self.assertTrue(any("поля index" in e for e in mv.header_errors(base, cand)))

    def test_fence_clipped_in_earlier_section_does_not_hide_record_list(self):
        обзор = ("## Обзор\n\nУстройство системы.\n\n```\n"
                 + "\n".join(f"команда номер {i:04d} для устройства" for i in range(120))
                 + "\n```\n\nХвост.\n")
        base = {"memory/topics/acme.md": ("# Acme\n\n" + обзор
                                          + "\n## Доступы\n\nSSH идёт через бастион.\n").encode("utf-8")}
        cand = dict(base)
        cand["memory/reference_acme_bastion.md"] = self.client_record(
            probe="обзор устройства и доступ по ssh")
        report = check(cand, base, root="clients/acme")
        self.assertTrue(report.ok, report.errors)
        self.assertFalse(mv.delivered_link_present(
            "Записи раздела:\n- [[reference_acme_basti", "reference_acme_bastion"))
        self.assertFalse(mv.delivered_link_present(
            "Проза\n```\n- [[reference_acme_bastion]]\n```\n", "reference_acme_bastion"))

    def test_missing_client_rollup_refuses_in_words(self):
        base = {"memory/topics/acme.md": self.ACME.encode("utf-8"),
                "memory/reference_acme_bastion.md": self.client_record()}
        cand = dict(base)
        del cand["memory/topics/acme.md"]
        report = check(cand, base, root="clients/acme")
        self.assertTrue(any("каноническая сводка" in e for e in report.errors), report.errors)

    def test_empty_client_tree_refuses_in_words(self):
        base = {"memory/topics/acme.md": self.ACME.encode("utf-8"),
                "memory/reference_acme_bastion.md": self.client_record()}
        report = check({}, base, root="clients/acme")
        self.assertTrue(any("каноническая сводка" in e for e in report.errors), report.errors)

    def test_base_without_index_can_be_repaired(self):
        base = base_tree()
        del base["memory/MEMORY.md"]
        report = check(base_tree(), base)
        self.assertTrue(report.ok, report.errors)

    def test_bom_and_crlf_are_named_instead_of_missing_fields(self):
        base = base_tree()
        good = record("reference_router", type="reference", title="Роутер на даче",
                      index="микротик, wifi", probe="как перезагрузить роутер на даче",
                      source="разговор", observed_at="2026-09-01", body="В шкафу.\n").decode("utf-8")
        for name, text in (("CRLF", good.replace("\n", "\r\n")), ("BOM", "\ufeff" + good)):
            with self.subTest(name=name):
                cand = dict(base, **{"memory/reference_router.md": text.encode("utf-8")})
                report = check(cand, base)
                errors = report.errors
                self.assertFalse(report.ok)
                # Единственная причина, без дубля проверки всего дерева
                # (ревью 11.10.2026).
                self.assertEqual(len([e for e in errors if name in e]), 1, errors)
                self.assertFalse(any("обязана нести" in e for e in errors), errors)
                self.assertFalse(any(name in e for e in mv.file_errors("reference_router.md", text)))

    def test_legacy_bom_and_crlf_do_not_block_unrelated_record(self):
        # Старые запись, архив, индекс и сводка не останавливают новую
        # постороннюю запись (ревью 11.10.2026).
        for path in ("memory/reference_printer.md", "memory/archive/reference_old.md",
                     "memory/MEMORY.md", "memory/topics/home.md"):
            for name in ("BOM", "CRLF"):
                with self.subTest(path=path, name=name):
                    base = base_tree()
                    good = base.get(path, "# Архив\n\nСтарый факт.\n".encode("utf-8"))
                    base[path] = (b"\xef\xbb\xbf" + good if name == "BOM"
                                  else good.replace(b"\n", b"\r\n"))
                    cand = dict(base)
                    cand["memory/reference_router.md"] = record(
                        "reference_router", type="reference", title="Роутер на даче",
                        index="микротик, wifi", probe="как перезагрузить роутер на даче",
                        source="разговор", observed_at="2026-09-01", body="В шкафу.\n")
                    report = check(cand, base, questions=False)
                    self.assertTrue(report.ok, report.errors)
                    if path == "memory/reference_printer.md":
                        cand[path] += "Ещё факт.\n".encode("utf-8")
                        report = check(cand, base, questions=False)
                        self.assertFalse(report.ok)
                        self.assertEqual(len([e for e in report.errors
                                              if path in e and name in e]), 1, report.errors)

    def test_secret_refusal_does_not_quote_field_values(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/reference_ci.md"] = record(
            "reference_ci", type="reference", title="Сборка в CI", index="конвейер сборки",
            probe=f"какой токен {self.TOKEN} у сборки", source="разговор",
            observed_at="2026-09-01", valid_until=self.TOKEN, body="Сборка идёт ночью.\n")
        report = check(cand, base)
        reason = "; ".join(report.errors)
        self.assertFalse(report.ok)
        self.assertIn("на секрет", reason)
        self.assertNotIn(self.TOKEN, reason)

    def test_secret_refusal_does_not_quote_links_in_warnings(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/reference_ci.md"] = record(
            "reference_ci", type="reference", title="Сборка в CI", index="конвейер сборки",
            probe="как работает сборка ci", source="разговор", observed_at="2026-09-01",
            body=f"Сборка, подробности [[{self.TOKEN}]].\n")
        report = check(cand, base)
        self.assertFalse(report.ok)
        self.assertNotIn(self.TOKEN, str(report))
        self.assertEqual(report.warnings, [])

    def test_markdown_link_to_other_client_rollup_stays_a_warning(self):
        topics = dict(TOPICS, topics=dict(TOPICS["topics"], beta=dict(
            TOPICS["topics"]["acme"], rollup="beta.md", owner="clients/beta", label="Beta",
            tokens=["beta"], aliases=["beta"], cwdNames=["beta"])))
        topics["topicOrder"] = TOPICS["topicOrder"] + ["beta"]
        topics["archivedRollups"] = {"gone.md": "clients/gone"}
        raw = json.dumps(topics, ensure_ascii=False).encode("utf-8")
        loaded = mv.load_topics(raw)
        # Предупреждение и для прежней ссылки, и для новой либо изменённой,
        # в действующей записи и архиве (ревью 11.10.2026).
        for path in ("memory/reference_old.md", "memory/archive/reference_old.md"):
            for target in ("beta.md", "gone.md"):
                with self.subTest(path=path, target=target):
                    link = ("../" if "/archive/" in path else "") + "topics/" + target
                    old = self.client_record(
                        "reference_old", body=f"Свёрнуто в сводку [topics/{target}]({link}).\n")
                    base = {"memory/topics/acme.md": self.ACME.encode("utf-8"), path: old}
                    cand = dict(base)
                    cand["memory/reference_acme_bastion.md"] = self.client_record()
                    for state in ("legacy", "new", "changed"):
                        before = dict(base)
                        if state == "new":
                            del before[path]
                        cand[path] = old + ("Ещё факт.\n".encode("utf-8")
                                            if state == "changed" else b"")
                        with Scanner(0) as scanner:
                            report = mv.check(cand, before, root="clients/acme", today=TODAY,
                                              scanner=scanner, config=mv.Config(topics=raw))
                        self.assertTrue(report.ok, (state, report.errors))
                        self.assertTrue(any(path in w and target in w and "межклиентская" in w
                                            for w in report.warnings), (state, report.warnings))
                    self.assertEqual(mv.link_errors(cand, loaded, "personal"), ([], []))

    def test_global_title_or_index_longer_than_contract_line_is_refused(self):
        def tree(index):
            return {"memory/MEMORY.md": "# Индекс\n\n## Feedback\n".encode("utf-8"),
                    "memory/feedback_rule.md": record("feedback_rule", type="feedback",
                                                      title="Правило", index=index)}
        errors = mv.contract_errors(tree("принтер " * 45 + "не слать пароль"))
        self.assertTrue(any("feedback_rule.md" in e and "index длиннее" in e for e in errors), errors)
        self.assertEqual(mv.contract_errors(tree("принтер " * 30)), [])
        cand = tree("правило")
        cand["memory/feedback_rule.md"] = cand["memory/feedback_rule.md"].replace(
            "title: Правило".encode(), ("title: " + "правило " * 45).encode())
        self.assertTrue(any("title длиннее" in e for e in mv.contract_errors(cand)))

    def test_legacy_long_contract_fields_do_not_block_unrelated_rule(self):
        # Любая правка длинного правила, в том числе одной шапки, всё ещё
        # отказывает; нетронутое правило подаче не мешает (ревью 11.10.2026).
        config = mv.Config(topics=json.dumps(dict(TOPICS, federationMembers=["acme"])).encode())

        def global_check(candidate, base):
            with Scanner(0) as scanner:
                return mv.check(candidate, base, root="global", config=config,
                                today=TODAY, scanner=scanner)

        for key in ("title", "index"):
            with self.subTest(key=key):
                fields = dict(type="feedback", title="Принтер", index="зелёный принтер",
                              probe="как настроить зелёный принтер", source="разговор",
                              observed_at="2026-09-01")
                fields[key] = "принтер " * 45
                path = "memory/feedback_printer.md"
                base = {"memory/MEMORY.md": "# Индекс\n\n## Feedback\n".encode("utf-8"),
                        path: record("feedback_printer", **fields)}
                cand = dict(base)
                cand["memory/feedback_router.md"] = record(
                    "feedback_router", type="feedback", title="Роутер",
                    index="дачный роутер", probe="как настроить роутер на даче",
                    source="разговор", observed_at="2026-09-01")
                report = global_check(cand, base)
                self.assertTrue(report.ok, report.errors)
                for body in ("Факт.\n", "Новый факт.\n"):
                    cand[path] = record("feedback_printer", body=body,
                                        valid_until="2026-10-31", **fields)
                    report = global_check(cand, base)
                    self.assertFalse(report.ok)
                    self.assertTrue(any(path in e and f"{key} длиннее" in e
                                        for e in report.errors), report.errors)
