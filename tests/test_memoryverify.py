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

    def test_supersedes_and_link_fields_still_checked(self):
        base = base_tree()
        cand = dict(base)
        cand["memory/user_cat.md"] = record(
            "user_cat", type="user", title="Кот", index="как зовут кота",
            source="разговор", observed_at="2026-09-04", probe="имя кота",
            supersedes="user_cat", requires="nobody")
        errors = mv.header_errors(base, cand)
        self.assertTrue(any("сам на себя" in e for e in errors), errors)
        self.assertTrue(any("nobody" in e for e in errors), errors)


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
        self.assertEqual(good.facts["probes"], {"reference_printer": True})
        bad = check(self._tree("рецепт борща на зиму"), base)
        self.assertTrue(any("не находит запись" in e for e in bad.errors), bad.errors)

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
        with mock.patch.object(mc, "build_index", wraps=mc.build_index) as reads:
            report = check(cand, base_tree(), questions=False)
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(report.facts["probes"], {"reference_printer": True,
                                                  "reference_kettle": True,
                                                  "reference_toaster": True})
        self.assertEqual(reads.call_count, 1)

    def test_client_probe_through_topic_delivery(self):
        rollup = ("# Acme\n\n## Обзор\n\nУстройство системы.\n\n"
                  "## Доступы\n\nSSH идёт через бастион, см. [[reference_acme_bastion]].\n")
        base = {"memory/topics/acme.md": rollup.encode("utf-8")}
        cand = dict(base)
        cand["memory/reference_acme_bastion.md"] = record(
            "reference_acme_bastion", source="разговор", observed_at="2026-09-04",
            probe="как попасть по ssh на серверы", body="Бастион.\n")
        report = check(cand, base, root="clients/acme")
        self.assertTrue(report.ok, report.errors)
        cand["memory/reference_acme_bastion.md"] = record(
            "reference_acme_bastion", source="разговор", observed_at="2026-09-04",
            probe="какой у нас обзор устройства", body="Бастион.\n")
        report = check(cand, base, root="clients/acme")
        self.assertTrue(any("не содержит ссылки" in e for e in report.errors), report.errors)


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
        facts = {}
        self.assertEqual(mv.section_errors(base, base, topics, facts)[0], [])
        cand = {"memory/topics/home.md": (fat + "ещё\n").encode("utf-8")}
        errors, _ = mv.section_errors(base, cand, topics, facts)
        self.assertTrue(any("потолке" in e for e in errors), errors)

    def test_unselectable_new_section_is_a_warning(self):
        topics = mv.load_topics(TOPICS_RAW)
        base = base_tree()
        cand = dict(base)
        cand["memory/topics/home.md"] = "# Home\n\n## Обзор\n\nДом.\n\n## Прочее\n\nХвост.\n".encode("utf-8")
        errors, warnings = mv.section_errors(base, cand, topics, {})
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

    def test_stand_skipped_without_index_or_questions(self):
        base = {"memory/topics/acme.md": b"# Acme\n", "memory/MEMORY.md": b"# I\n"}
        report = check(base, base, root="clients/acme")
        self.assertTrue(report.ok, report.errors)
        self.assertNotIn("stand", report.facts)
        report = check(base_tree(), base_tree(), questions=False)
        self.assertNotIn("stand", report.facts)

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
    def test_unchanged_tree_is_green_and_facts_are_words(self):
        base = base_tree()
        report = check(base, base)
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(report.facts["touched"], {})
        self.assertEqual(report.facts["stand"]["tuned"], {"found": 1, "of": 1})

    def test_first_commit_has_no_base(self):
        cand = base_tree()
        cand["memory/reference_printer.md"] = record(
            "reference_printer", type="reference", title="Зелёный принтер",
            index="как чинить зелёный принтер", source="разговор",
            observed_at="2026-09-04", probe="чем чинить принтер зелёного цвета",
            body="Зелёный принтер чинится молотком.\n")
        report = check(cand, None)
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(report.facts["touched"], {"reference_printer": "new"})


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
