"""Отчёт находимости по крючкам: probe каждой записи как золотой набор.

Писатель проверяет крючки всего корня при каждой подаче и отказывает
поимённо, но цифр не даёт. Здесь тот же отбор (`select_index_entries`)
по живому корню и три числа: hit@1 (запись первой в выдаче), hit@2 (в
выдаче вообще, ровно то, что требует писатель) и hit@5 (в первой пятёрке
по счёту первого места). Модуль намеренно вне отпечатка измерения стенда:
он ничего не меняет в отборе, только считает.
"""
from __future__ import annotations

from pathlib import Path

import memorycontext as mc
import memoryverify as mv


def probes_for_root(laid_out: Path, *, today=None) -> dict:
    """Крючки одного корня общего индекса (global или personal). Свёрнутые
    и истёкшие (valid_until) записи не считаются: их автоматический отбор не
    выдаёт по построению, и писатель их крючки пропускает (probe_errors)."""
    сегодня = today if today is not None else mc.today_utc()
    записи = mc.parse_index(mc.build_index(laid_out))
    по_слагу = {Path(e.slug).stem: e for e in записи}
    итог = {"total": 0, "hit1": 0, "hit2": 0, "hit5": 0, "misses": [], "second_place": []}
    for файл in sorted((laid_out / "memory").glob("*.md")):
        if файл.name in mv.SERVICE_FILES:
            continue
        поля, ошибка = mv.parse_frontmatter(файл.read_text(encoding="utf-8", errors="replace"))
        probe = (поля.get("probe") or "").strip()
        if (ошибка or not probe or поля.get("listed") == "false"
                or mv.date_passed(поля, "valid_until", сегодня)):
            continue
        slug = файл.stem
        if slug not in по_слагу:
            continue
        итог["total"] += 1
        выдано = [Path(e.slug).stem for e, _ in mc.select_index_entries(
            laid_out, probe, записи, today=сегодня)]
        по_счёту = sorted(((mc._entry_score(probe, e), e) for e in записи),
                          key=lambda p: (-p[0], p[1].index))
        ранг = next((i + 1 for i, (_, e) in enumerate(по_счёту)
                     if Path(e.slug).stem == slug), None)
        if выдано and выдано[0] == slug:
            итог["hit1"] += 1
        elif slug in выдано:
            итог["second_place"].append(slug)
        if slug in выдано:
            итог["hit2"] += 1
        else:
            итог["misses"].append({"slug": slug, "probe": probe, "rank": ранг,
                                   "delivered": выдано})
        if ранг is not None and ранг <= 5:
            итог["hit5"] += 1
    return итог


def report(root: Path, *, today=None) -> dict:
    """По обоим корням общего индекса этой машины, на одну дату: прогон
    через полночь UTC не считает корни по разным дням."""
    сегодня = today if today is not None else mc.today_utc()
    try:
        global_root, personal = mc.index_roots(root)
    except ValueError as exc:
        # Битый federationMembers: отказ словами, как у стенда.
        raise mc.MemoryctlError(str(exc)) from exc
    out = {"global": probes_for_root(global_root, today=сегодня)}
    if personal is not None:
        out["personal"] = probes_for_root(personal, today=сегодня)
    return out


def format_report(result: dict) -> str:
    строки = []
    for область, r in result.items():
        n = r["total"] or 1
        строки.append(f"{область}: крючков {r['total']}; hit@1 {r['hit1']}/{r['total']} "
                      f"({100 * r['hit1'] // n}%), hit@2 {r['hit2']}/{r['total']} "
                      f"({100 * r['hit2'] // n}%), hit@5 по счёту {r['hit5']}/{r['total']}")
        for m in r["misses"]:
            строки.append(f"  не находится: {m['slug']} (ранг по счёту {m['rank']}); "
                          f"выдано {', '.join(m['delivered']) or 'ничего'}")
        if r["second_place"]:
            строки.append("  вторым местом (BM25): " + ", ".join(r["second_place"]))
    return "\n".join(строки)
