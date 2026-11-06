#!/usr/bin/env python3
"""Section 5（周辺諸国動向・第2段階）の受入基準を検査する。

依存は Python 3 標準ライブラリのみ。ネットワークへは出ない。

検査する受入基準:
  A. 走査（neighbor_scan.py）
     1. 語の照合: ASCII/キリルは単語境界・'*' は前方一致・CJK は部分一致
     2. 国名がタイトルにあれば high、要約のみなら medium、アクター名のみは actor_hint_only
     3. 『Korea』単独は北朝鮮にも韓国にも一致しない
     4. 窓内判定・重複集約・ゲート対象の算出・周辺諸国タグ未一致の計数
     5. config に未定義の国コードは失敗する／国が空なら disabled
  B. 検証（validate_neighbor_context.py）
     6. 正例が通る
     7. 事実への『（推測）』混在・評価の『（推測）』欠落・確度欠落を落とす
     8. 帰属: 明示なしの attribution／明示ありで attribution 欠落／原文の言い回し欠落を落とす
     9. TTP・観測・予報の項目を持つエントリを落とす
    10. 国営メディア参照で state_affiliated=false／caveat 欠落を落とす
    11. entry_id 形式・日付不一致・重複、info_id 不一致を落とす
    12. 地政学区分で非サイバー関連が無いものを落とす
    13. ゲート: 未処理を落とす／重複側は不要／宣言値の転記ずれを落とす
    14. 予報との分離: 観測テキスト・予報に nbr- が現れたら落とす
    15. statistics の不一致を落とす／neighbor_context 無しは警告（--require でエラー）
  C. 出力
    16. レンダラーは決定論的で、JSON 専用項目をテキストに出さない
    17. 整合チェッカーは neighbor_context を持つ日だけ追加テキストを要求する（履歴日は不変）
  D. 設計の不変条件
    18. レジストリの語がすべてコンパイルでき、国をまたいだ重複語が無い
    19. config.yml の有効な国がすべてレジストリに定義されている
    20. スキャン・検証・描画が config.yml と forecaster/knowledge/ を書き換えない

使い方:
    python3 scripts/test_neighbor_context.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPTS)
sys.path.insert(0, SCRIPTS)

import check_report_consistency as crc  # noqa: E402
import neighbor_scan as ns  # noqa: E402
import render_neighbor_section as rns  # noqa: E402
import validate_neighbor_context as vn  # noqa: E402
import watchlist as wl  # noqa: E402

with open(os.path.join(REPO_ROOT, "neighbor", "states.json"), encoding="utf-8") as _fh:
    REGISTRY = json.load(_fh)
CONFIG = {"neighbor_states": {"primary": ["CN", "RU", "KP"], "regional": ["KR", "TW"],
                              "gate_min_relevance": "high"}}
ENABLED = {"CN": "primary", "RU": "primary", "KP": "primary", "KR": "regional", "TW": "regional"}
DATE = "2026-11-06"


def _sha(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# --------------------------------------------------------------------------
# A. 走査
# --------------------------------------------------------------------------

class TermTests(unittest.TestCase):
    def match(self, term: str, text: str) -> bool:
        return bool(ns.compile_term(term).search(ns.clean_text(text)))

    def test_ascii_uses_word_boundaries(self) -> None:
        self.assertTrue(self.match("GRU", "The GRU unit was named"))
        self.assertFalse(self.match("GRU", "A large group of hackers"))
        self.assertFalse(self.match("PLA", "A plan to adapt"))
        self.assertTrue(self.match("PLA", "PLA's cyber force"))

    def test_trailing_star_is_prefix_match(self) -> None:
        self.assertTrue(self.match("Russia*", "Russian hackers"))
        self.assertTrue(self.match("Russia*", "Russia-linked group"))
        self.assertFalse(self.match("Russia*", "Prussian history"))

    def test_cjk_is_substring_and_cyrillic_prefix(self) -> None:
        self.assertTrue(self.match("北朝鮮", "米政府は北朝鮮の関与を公表"))
        self.assertTrue(self.match("росси*", "Российские хакеры"))
        self.assertTrue(self.match("Северн* Коре*", "лидер Северной Кореи"))
        self.assertFalse(self.match("ГРУ", "группа хакеров"))

    def test_curly_apostrophe_is_normalized(self) -> None:
        self.assertTrue(self.match("People's Liberation Army", "the People’s Liberation Army said"))


class MatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.matchers = {m.code: m for m in ns.build_matchers(REGISTRY, CONFIG)}

    def test_title_vs_summary_vs_actor_hint(self) -> None:
        kp = self.matchers["KP"]
        self.assertEqual(kp.scan("North Korean hackers steal crypto", "")["relevance"], "high")
        hit = kp.scan("Crypto theft report", "Pyongyang denied involvement")
        self.assertEqual((hit["relevance"], hit["country_signal"]), ("medium", "state_term"))
        hint = kp.scan("Lazarus targets developers", "")
        self.assertEqual((hint["relevance"], hint["country_signal"]), ("high", "actor_hint_only"))
        self.assertIsNone(kp.scan("Unrelated vulnerability disclosure", "buffer overflow"))

    def test_bare_korea_matches_neither_korea(self) -> None:
        for code in ("KP", "KR"):
            self.assertIsNone(self.matchers[code].scan("Korean firms hit by outage", "Korea"))
        self.assertIsNotNone(self.matchers["KR"].scan("South Korean agency warns", ""))
        self.assertIsNotNone(self.matchers["KP"].scan("North Korea tests missile", ""))


def _item(i: str, title: str, published: str, *, summary: str = "", tags=None,
          source: str = "Feed", language: str = "en") -> dict:
    return {"id": i, "title": title, "summary": summary, "url": f"https://x.example/{i}",
            "source": source, "language": language, "tags": tags or ["security_news"],
            "published_at": published}


class BuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="pythia-nbr-raw-")
        items = [
            _item("a", "Chinese hackers breach telecom", "2026-11-05T01:00:00+00:00"),
            _item("b", "New cyber unit announced", "2026-11-05T02:00:00+00:00",
                  summary="<p>Moscow said the unit will start in spring.</p>"),
            _item("c", "APT29 campaign hits embassies", "2026-11-05T03:00:00+00:00"),
            _item("d", "Chinese hackers breach telecom!", "2026-11-04T23:30:00+00:00", source="Other"),
            _item("e", "Generic malware analysis", "2026-11-05T04:00:00+00:00", tags=["neighbor_region"],
                  language="ko"),
            _item("f", "Korean firms hit by outage", "2026-11-05T05:00:00+00:00"),
            _item("g", "North Korea indictment unsealed", "2026-10-30T00:00:00+00:00"),
            _item("h", "Weather report", "2026-11-05T06:00:00+00:00"),
        ]
        with open(os.path.join(self.tmp, "news-2026-11-05.json"), "w", encoding="utf-8") as fh:
            json.dump({"items": items}, fh)
        self.window = (ns.ws.parse_jst("2026-11-05 07:00"), ns.ws.parse_jst("2026-11-06 07:00"))

    def build(self, config=CONFIG, gate_min="high") -> dict:
        return ns.build(date(2026, 11, 6), self.tmp, REGISTRY, config, self.window, gate_min)

    def test_window_duplicates_gate_and_unmatched(self) -> None:
        data = self.build()
        by_id = {c["candidate_id"]: c for c in data["candidates"]}
        self.assertEqual(set(by_id), {"a", "b", "c", "d", "g"})
        self.assertEqual(by_id["a"]["relevance"], "high")
        self.assertEqual(by_id["b"]["relevance"], "medium")
        self.assertEqual(by_id["c"]["countries"][0]["country_signal"], "actor_hint_only")
        self.assertEqual(by_id["d"]["duplicate_of"], "a")  # 新しい方が代表になる
        self.assertIs(by_id["g"]["in_window"], False)
        gated = {cid for cid, c in by_id.items() if c["gated"]}
        self.assertEqual(gated, {"a", "c"})  # b は medium、d は重複、g は窓外
        self.assertEqual(data["counts"]["gated"], 2)
        self.assertEqual(data["counts"]["neighbor_feed_unmatched"], 1)
        self.assertEqual(data["counts"]["duplicates"], 1)

    def test_gate_min_medium_includes_summary_only(self) -> None:
        data = self.build(gate_min="medium")
        gated = {c["candidate_id"] for c in data["candidates"] if c["gated"]}
        self.assertEqual(gated, {"a", "b", "c"})

    def test_undefined_country_code_fails(self) -> None:
        bad = {"neighbor_states": {"primary": ["CN", "ZZ"]}}
        with self.assertRaises(SystemExit):
            self.build(config=bad)

    def test_no_countries_is_disabled(self) -> None:
        data = self.build(config={"neighbor_states": {"primary": [], "regional": []}})
        self.assertEqual((data["status"], data["counts"]["candidates"]), ("disabled", 0))
        self.assertIn("無効", ns.render_markdown(data))

    def test_markdown_marks_actor_hint_only(self) -> None:
        md = ns.render_markdown(self.build())
        self.assertIn("アクター名のみで一致", md)
        self.assertIn("RU*", md)


# --------------------------------------------------------------------------
# B. 検証
# --------------------------------------------------------------------------

def good_entry(n: int = 1, country: str = "KP") -> dict:
    title = "北朝鮮系グループによる暗号資産窃取を米政府が公表"
    url = "https://www.justice.gov/example"
    return {
        "entry_id": f"nbr-{DATE}-{n:03d}",
        "info_id": vn.info_id_for(DATE, title, url),
        "country": country, "tier": ENABLED[country],
        "category": "activity", "title": title,
        "original_title": "Justice Department announces action", "original_language": "en",
        "country_basis": "state_attributed_by_source",
        "attribution": {"stated_by": "US DOJ", "wording": "North Korean actors stole virtual currency",
                        "confidence": "high"},
        "facts": [{"statement": "米司法省は暗号資産の窃取に関する措置を公表した", "ref": 0}],
        "assessment": {"text": "（推測）資金調達目的の活動が継続している可能性がある", "confidence": "low"},
        "non_cyber_linkage": {
            "context_type": "military_org",
            "fact": {"statement": "同国は同週に弾道ミサイルを発射した", "ref": 0},
            "assessment": {"text": "（推測）資金調達と軍事活動の時期的な重なりがある", "confidence": "low"}},
        "source_assessment": {"primary_source": True, "independent_sources": 2,
                              "state_affiliated": False, "caveat": None},
        "references": [{"url": url, "title": None, "language": "en", "source": "US DOJ",
                        "source_class": "government"}],
        "candidate_ids": ["cand1"], "related_apt_campaign_ids": [], "related_cves": [],
        "forecast_input": False,
    }


def good_report(entries=None, dispositions=None) -> dict:
    entries = [good_entry()] if entries is None else entries
    if dispositions is None:
        dispositions = [{"candidate_id": "cand1", "decision": "adopted", "entry_id": entries[0]["entry_id"]}]
    by_cat = {c: sum(1 for e in entries if e["category"] == c) for c in vn.CATEGORIES}
    return {
        "meta": {"report_date": DATE},
        "neighbor_context": {
            "schema_version": "1.0",
            "scan": {"status": "ok", "countries": sorted(ENABLED), "scanned_items": 10,
                     "candidates": 3, "gated": 1, "handled": 1, "unhandled": 0},
            "entries": entries,
            "dispositions": dispositions,
        },
        "statistics": {"neighbor_context": {"entries": len(entries), "excluded": 0, "by_category": by_cat}},
        "forecasts": [], "tactical_forecast": {"mode": "shadow"},
    }


def good_scan() -> dict:
    return {"date": DATE, "scanned_items": 10, "counts": {"candidates": 3, "gated": 1},
            "candidates": [{"candidate_id": "cand1", "gated": True, "duplicate_of": None},
                           {"candidate_id": "cand2", "gated": False, "duplicate_of": None},
                           {"candidate_id": "cand3", "gated": False, "duplicate_of": "cand2"}]}


def run(report=None, scan="default", obs=None, require=False):
    report = good_report() if report is None else report
    scan = good_scan() if scan == "default" else scan
    return vn.validate(report, date=DATE, enabled=ENABLED, scan=scan, observation_text=obs, require=require)


class ValidatorTests(unittest.TestCase):
    def assertError(self, report=None, needle: str = "", **kw) -> None:
        errors, _ = run(report, **kw)
        self.assertTrue(any(needle in e for e in errors), f"{needle!r} が見つからない: {errors}")

    def mutated(self, fn) -> dict:
        report = good_report()
        fn(report["neighbor_context"]["entries"][0])
        return report

    def test_good_report_passes(self) -> None:
        errors, warnings = run()
        self.assertEqual((errors, warnings), ([], []))

    def test_fact_assessment_separation(self) -> None:
        self.assertError(self.mutated(lambda e: e["facts"][0].update(statement="（推測）関与は確実である")),
                         "混在")
        self.assertError(self.mutated(lambda e: e["assessment"].update(text="関与は確実である")),
                         "（推測）")
        self.assertError(self.mutated(lambda e: e["assessment"].update(confidence="certain")), "confidence")
        self.assertError(self.mutated(lambda e: e["facts"][0].update(ref=5)), "範囲外")
        self.assertError(self.mutated(lambda e: e.update(facts=[])), "facts が空")

    def test_attribution_rules(self) -> None:
        def explicit_without_attr(e):
            e["attribution"] = None
        self.assertError(self.mutated(explicit_without_attr), "attribution")

        def attr_without_explicit(e):
            e["country_basis"] = "target_country"
        self.assertError(self.mutated(attr_without_explicit), "TTP の類似や国名の言及だけで帰属を記録しない")

        self.assertError(self.mutated(lambda e: e["attribution"].update(wording="")), "wording")
        self.assertError(self.mutated(lambda e: e["attribution"].update(stated_by="")), "stated_by")
        self.assertError(self.mutated(lambda e: e["attribution"].update(wording="あ" * 301)), "字以内")

        def policy_with_explicit(e):
            e["category"] = "policy"
        self.assertError(self.mutated(policy_with_explicit), "category=activity")

    def test_no_forecast_layer_fields(self) -> None:
        for key in ("techniques", "actor_group", "base_rate_estimate", "forecast_id"):
            self.assertError(self.mutated(lambda e, k=key: e.update({k: "x"})), "予報の入力層")
        self.assertError(self.mutated(lambda e: e.update(forecast_input=True)), "forecast_input")

    def test_state_media_requires_caveat(self) -> None:
        def state_media(e):
            e["references"][0]["source_class"] = "state_media"
        self.assertError(self.mutated(state_media), "state_affiliated")

        def affiliated_no_caveat(e):
            state_media(e)
            e["source_assessment"].update(state_affiliated=True, caveat=None)
        self.assertError(self.mutated(affiliated_no_caveat), "caveat")

        def ok(e):
            state_media(e)
            e["source_assessment"].update(state_affiliated=True, caveat="当該国政府の主張であり事実の裏付けではない")
        errors, _ = run(self.mutated(ok))
        self.assertEqual(errors, [])

    def test_ids(self) -> None:
        self.assertError(self.mutated(lambda e: e.update(entry_id="nbr-2026-11-05-001")), "日付")
        self.assertError(self.mutated(lambda e: e.update(entry_id="n-1")), "形式")
        self.assertError(self.mutated(lambda e: e.update(info_id="20261106-NBRC-00000000")), "info_id")
        report = good_report([good_entry(1), good_entry(1)])
        self.assertError(report, "重複", scan=None)

    def test_country_and_tier(self) -> None:
        self.assertError(self.mutated(lambda e: e.update(country="US")), "有効な国ではない")
        self.assertError(self.mutated(lambda e: e.update(tier="regional")), "tier")

    def test_geopolitical_requires_linkage(self) -> None:
        def geo(e):
            e.update(category="geopolitical", country_basis="context_only", attribution=None,
                     non_cyber_linkage=None)
        self.assertError(self.mutated(geo), "non_cyber_linkage が必須")

    def test_references_required(self) -> None:
        self.assertError(self.mutated(lambda e: e.update(references=[])), "references が空")
        self.assertError(self.mutated(lambda e: e["references"][0].update(url="ftp://x")), "URL")
        self.assertError(self.mutated(lambda e: e["references"][0].update(source_class="blog")), "source_class")

    def test_gate(self) -> None:
        report = good_report(dispositions=[])
        self.assertError(report, "未処理", scan=good_scan())
        # 除外でも理由が要る
        excluded = good_report(dispositions=[{"candidate_id": "cand1", "decision": "excluded"}])
        self.assertError(excluded, "reason")
        ok = good_report(dispositions=[{"candidate_id": "cand1", "decision": "excluded",
                                        "reason": "mentioned_only"}])
        ok["neighbor_context"]["entries"] = []
        ok["statistics"]["neighbor_context"] = {"entries": 0, "excluded": 1,
                                                 "by_category": {c: 0 for c in vn.CATEGORIES}}
        errors, _ = run(ok)
        self.assertEqual(errors, [])

    def test_gate_ignores_duplicate_side(self) -> None:
        # cand3 は cand2 の重複でゲート対象外。処理記録が無くても未処理にならない
        errors, _ = run()
        self.assertFalse(any("cand3" in e for e in errors))

    def test_declared_values_must_match_scan(self) -> None:
        report = good_report()
        report["neighbor_context"]["scan"]["gated"] = 0
        self.assertError(report, "scan.gated")
        report = good_report()
        report["neighbor_context"]["scan"]["unhandled"] = 2
        self.assertError(report, "unhandled")
        self.assertError(good_report(), "日付", scan={**good_scan(), "date": "2026-11-05"})

    def test_disposition_links(self) -> None:
        bad = good_report(dispositions=[{"candidate_id": "cand1", "decision": "adopted", "entry_id": "nbr-x"}])
        self.assertError(bad, "entries に無い")
        report = good_report()
        report["neighbor_context"]["entries"][0]["candidate_ids"] = []
        self.assertError(report, "candidate_ids に無い")

    def test_isolation_from_forecast_layer(self) -> None:
        self.assertError(good_report(), "観測ファイル", obs='{"related": "nbr-2026-11-06-001"}')
        report = good_report()
        report["forecasts"] = [{"basis": "see nbr-2026-11-06-001"}]
        self.assertError(report, "forecasts")
        report = good_report()
        report["tactical_forecast"] = {"note": "nbr-2026-11-06-001"}
        self.assertError(report, "tactical_forecast")
        errors, _ = run(obs='{"observations": []}')
        self.assertEqual(errors, [])

    def test_statistics_mismatch(self) -> None:
        report = good_report()
        report["statistics"]["neighbor_context"]["entries"] = 3
        self.assertError(report, "statistics.neighbor_context.entries")
        report = good_report()
        report["statistics"]["neighbor_context"]["by_category"]["policy"] = 1
        self.assertError(report, "by_category")

    def test_missing_section_is_warning_unless_required(self) -> None:
        errors, warnings = vn.validate({"meta": {}}, date=DATE, enabled=ENABLED)
        self.assertEqual((errors, len(warnings)), ([], 1))
        errors, _ = vn.validate({"meta": {}}, date=DATE, enabled=ENABLED, require=True)
        self.assertEqual(len(errors), 1)

    def test_failed_scan_is_warning(self) -> None:
        report = good_report()
        report["neighbor_context"]["scan"] = {"status": "failed"}
        errors, warnings = run(report)
        self.assertFalse(any("unhandled" in e for e in errors))
        self.assertTrue(any("failed" in w for w in warnings))


# --------------------------------------------------------------------------
# C. 出力
# --------------------------------------------------------------------------

class RenderTests(unittest.TestCase):
    def test_deterministic_and_hides_json_only_fields(self) -> None:
        report = good_report()
        text = rns.render(report, ["CN", "RU", "KP", "KR", "TW"])
        self.assertEqual(text, rns.render(copy.deepcopy(report), ["CN", "RU", "KP", "KR", "TW"]))
        self.assertIn("nbr-2026-11-06-001", text)
        self.assertIn("【事実】", text)
        self.assertIn("（推測）", text)
        self.assertIn("US DOJ は次のように述べている", text)
        self.assertIn("本レポートが帰属を判断したものではなく", text)
        self.assertIn("■ 中国（CN）", text)
        self.assertIn("（本日の該当なし）", text)
        for hidden in ("NBRC", "forecast_input", "cand1", "info_id"):
            self.assertNotIn(hidden, text)

    def test_caveat_and_exclusion_summary(self) -> None:
        report = good_report()
        entry = report["neighbor_context"]["entries"][0]
        entry["references"][0]["source_class"] = "state_media"
        entry["source_assessment"].update(state_affiliated=True, caveat="政府の主張であり裏付けではない")
        report["neighbor_context"]["dispositions"].append(
            {"candidate_id": "cand2", "decision": "excluded", "reason": "marketing"})
        text = rns.render(report)
        self.assertIn("注意: 政府の主張であり裏付けではない", text)
        self.assertIn("・宣伝・広報: 1件", text)
        self.assertIn("除外1件", text)


class ConsistencyTests(unittest.TestCase):
    def make_root(self, with_neighbor_json: bool, with_neighbor_text: bool, entry_in_full: bool = True) -> Path:
        root = Path(tempfile.mkdtemp(prefix="pythia-consistency-"))
        base = root / "outputs" / DATE
        base.mkdir(parents=True)
        report = {"meta": {"report_date": DATE, "sweep": {"status": "ok", "unhandled": 0}},
                  "statistics": {}}
        if with_neighbor_json:
            report = {**good_report(), "meta": report["meta"]}
        (base / f"{DATE}-security-report.json").write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        eid = "nbr-2026-11-06-001"
        for suffix in crc.TEXT_SUFFIXES:
            body = "本文\n" + (eid if (suffix == "" and with_neighbor_json and entry_in_full) else "")
            (base / f"{DATE}-security-report{suffix}.txt").write_text(body, encoding="utf-8")
        if with_neighbor_text:
            (base / f"{DATE}-security-report-neighbor.txt").write_text(eid, encoding="utf-8")
        return root

    def test_history_day_without_neighbor_context_is_unchanged(self) -> None:
        errors, _ = crc.check_date(self.make_root(False, False), DATE)
        self.assertEqual(errors, [])

    def test_neighbor_text_required_when_section_present(self) -> None:
        errors, _ = crc.check_date(self.make_root(True, False), DATE)
        self.assertTrue(any("security-report-neighbor.txt" in e for e in errors), errors)

    def test_entry_ids_must_appear_in_both_texts(self) -> None:
        errors, _ = crc.check_date(self.make_root(True, True, entry_in_full=False), DATE)
        self.assertTrue(any("security-report.txt に出現しない" in e for e in errors), errors)
        errors, _ = crc.check_date(self.make_root(True, True), DATE)
        self.assertEqual(errors, [])


# --------------------------------------------------------------------------
# D. 設計の不変条件
# --------------------------------------------------------------------------

class InvariantTests(unittest.TestCase):
    def test_registry_terms_compile_and_do_not_collide_across_countries(self) -> None:
        owner: dict[str, str] = {}
        for code, spec in REGISTRY["countries"].items():
            self.assertTrue(spec["state_terms"], f"{code}: state_terms が空")
            seen_here: set[str] = set()
            for term in spec["state_terms"] + spec["actor_hints"]:
                self.assertTrue(term.strip(), f"{code}: 空の語")
                ns.compile_term(term)
                key = term.lower()
                self.assertNotIn(key, seen_here, f"{code}: 語 {term!r} が重複")
                seen_here.add(key)
                if key in owner and owner[key] != code:
                    self.fail(f"語 {term!r} が {owner[key]} と {code} に重複（国の判別が曖昧になる）")
                owner[key] = code

    def test_repo_config_enables_only_defined_countries(self) -> None:
        config = wl.load_config(os.path.join(REPO_ROOT, "config.yml"))
        section = config["neighbor_states"]
        codes = list(section["primary"]) + list(section["regional"])
        self.assertTrue(codes)
        for code in codes:
            self.assertIn(code, REGISTRY["countries"])
        self.assertIn(section["gate_min_relevance"], ns.RELEVANCE_RANK)
        self.assertEqual(vn.enabled_countries(config, REGISTRY).keys(), set(codes))

    def test_repo_config_parses_identically_without_pyyaml(self) -> None:
        try:
            import yaml  # type: ignore
        except ImportError:
            self.skipTest("PyYAML 無し")
        text = Path(REPO_ROOT, "config.yml").read_text(encoding="utf-8")
        self.assertEqual(wl.parse_minimal_yaml(text), yaml.safe_load(text))

    def test_scan_validate_render_do_not_write_protected_files(self) -> None:
        protected = [os.path.join(REPO_ROOT, "config.yml"), os.path.join(REPO_ROOT, "neighbor", "states.json")]
        know = os.path.join(REPO_ROOT, "forecaster", "knowledge")
        protected += [os.path.join(know, n) for n in sorted(os.listdir(know))
                      if os.path.isfile(os.path.join(know, n))]
        before = {p: _sha(p) for p in protected}
        raw = os.path.join(REPO_ROOT, "security-intel-collector", "data", "raw")
        if os.path.isdir(raw):
            ns.build(date.today(), raw, REGISTRY, wl.load_config(os.path.join(REPO_ROOT, "config.yml")),
                     None, "high")
        run()
        rns.render(good_report())
        self.assertEqual(before, {p: _sha(p) for p in protected})


if __name__ == "__main__":
    unittest.main(verbosity=1)
