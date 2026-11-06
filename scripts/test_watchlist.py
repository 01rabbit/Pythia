#!/usr/bin/env python3
"""ウォッチリスト機構（第1段階・2026-11-06）の受入基準を検査する。

依存は Python 3 標準ライブラリのみ。ネットワークへは出ない。

検査する受入基準:
  1. config.yml の watchlist 節を読める（PyYAML の有無によらず同じ結果）
  2. scope.priority_groups が actors に自動的に含まれる
  3. 照合は大文字小文字を無視した部分一致で、該当語を全件返す
  4. CVE ID は説明文中の言及でも明示 ID でも照合できる
  5. スイープ突合: ウォッチリスト該当（閾値未満）が母集団に入り、未処理なら検出される
  6. スイープ突合: ウォッチリスト該当は件数が多くてもバッチ集約されない
  7. 旧形式スイープ JSON（watchlist_in_window 無し）でも突合が壊れない
  8. watchlist_scan: raw を走査して該当記事を窓内 / 窓外に分けて返し、言語を保持する
  9. watchlist が空なら sweep / scan とも何も加えない（status: disabled）
 10. 既存ファイル（config.yml・knowledge/）を変更しない

使い方:
    python3 scripts/test_watchlist.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import date

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPTS)
sys.path.insert(0, SCRIPTS)

import watchlist as wl  # noqa: E402
import watchlist_scan  # noqa: E402
import nvd_window_sweep as sweep  # noqa: E402

SAMPLE_YAML = """\
persona:
  role: "SOC Analyst"
scope:
  target_geos:
    - "JP"
  priority_groups:
    - "Lazarus Group"        # Phase 1
watchlist:
  cves: ["CVE-2026-10001", "cve-2026-10002"]   # 小文字も正規化する
  products:
    - "Ivanti Connect Secure"
    - "Zyxel"
  actors: ["Volt Typhoon"]
  topics: ["defense industrial base", "防衛産業"]
"""


def _sha(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class LoadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="pythia-watchlist-")
        self.cfg = os.path.join(self.tmp, "config.yml")
        with open(self.cfg, "w", encoding="utf-8") as fh:
            fh.write(SAMPLE_YAML)

    def test_minimal_parser_matches_pyyaml(self) -> None:
        minimal = wl.parse_minimal_yaml(SAMPLE_YAML)
        try:
            import yaml  # type: ignore
        except ImportError:
            self.skipTest("PyYAML 無し（最小パーサのみ検査）")
        self.assertEqual(minimal, yaml.safe_load(SAMPLE_YAML))

    def test_minimal_parser_reads_repo_config(self) -> None:
        with open(os.path.join(REPO_ROOT, "config.yml"), encoding="utf-8") as fh:
            text = fh.read()
        data = wl.parse_minimal_yaml(text)
        self.assertIn("watchlist", data)
        self.assertEqual(set(wl.CATEGORIES), set(data["watchlist"].keys()))

    def test_load_watchlist_merges_priority_groups_and_normalizes(self) -> None:
        w = wl.load_watchlist(self.cfg)
        self.assertEqual(w["cves"], ["CVE-2026-10001", "CVE-2026-10002"])
        self.assertIn("Volt Typhoon", w["actors"])
        self.assertIn("Lazarus Group", w["actors"])  # scope.priority_groups 由来
        self.assertEqual(w["topics"], ["defense industrial base", "防衛産業"])
        self.assertEqual(w["_source"], self.cfg)

    def test_missing_config_is_empty(self) -> None:
        w = wl.load_watchlist(os.path.join(self.tmp, "nope.yml"))
        self.assertTrue(wl.is_empty(w))
        self.assertTrue(wl.is_empty(wl.load_watchlist(None)))


class MatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.w = {"cves": ["CVE-2026-10001"], "products": ["Ivanti Connect Secure", "Zyxel"],
                  "actors": ["Volt Typhoon", "Lazarus Group"], "topics": ["防衛産業"]}

    def test_case_insensitive_substring(self) -> None:
        hits = wl.match_item(self.w, text="New ZYXEL  switch bug abused by volt typhoon")
        self.assertEqual(hits, {"products": ["Zyxel"], "actors": ["Volt Typhoon"]})

    def test_cve_by_mention_and_by_id(self) -> None:
        self.assertEqual(wl.match_item(self.w, text="patched cve-2026-10001 today"), {"cves": ["CVE-2026-10001"]})
        self.assertEqual(wl.match_item(self.w, text="", cve_ids=["CVE-2026-10001"]), {"cves": ["CVE-2026-10001"]})
        self.assertEqual(wl.match_item(self.w, text="CVE-2026-99999 unrelated"), {})

    def test_cjk_topic(self) -> None:
        self.assertEqual(wl.match_item(self.w, text="国内の防衛産業を狙う攻撃"), {"topics": ["防衛産業"]})

    def test_flatten(self) -> None:
        self.assertEqual(wl.flatten_matches({"actors": ["Volt Typhoon"], "cves": ["CVE-2026-10001"]}),
                         ["cves:CVE-2026-10001", "actors:Volt Typhoon"])


def _row(cve_id: str, cvss: float | None, src: str = "psirt@vendor.example", **extra) -> dict:
    row = {"cve_id": cve_id, "cvss_max": cvss, "source_identifier": src, "ghsa_origin": False,
           "in_kev": False, "kev_date_added": None, "description": f"desc of {cve_id}",
           "sweep_reason": "published_in_window"}
    row.update(extra)
    return row


class ReconcileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="pythia-reconcile-")

    def _report(self, text: str) -> str:
        path = os.path.join(self.tmp, "report.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_watchlist_rows_join_population_and_are_detected_when_unhandled(self) -> None:
        data = {
            "over_threshold_published": [_row("CVE-2026-10001", 9.8)],
            "kev_added_in_window": [],
            "watchlist_in_window": [_row("CVE-2026-10002", 5.3, sweep_reason="watchlist_match",
                                         watchlist_matched=["products:Zyxel"])],
            "euvd_in_window": [],
        }
        report = self._report(json.dumps({"main_cve": [{"cve_id": "CVE-2026-10001"}]}))
        result = sweep.reconcile(data, report)
        self.assertEqual(result["sweep_candidates"], 2)
        self.assertEqual([r["cve_id"] for r in result["unhandled"]], ["CVE-2026-10002"])
        self.assertEqual(result["watchlist_unhandled"], 1)
        text = sweep.render_reconcile(result)
        self.assertIn("★CVE-2026-10002", text)
        self.assertIn("watchlist: products:Zyxel", text)

    def test_watchlist_rows_never_batched(self) -> None:
        rows = [_row(f"CVE-2026-2000{i}", 4.0, src="psirt@big.example", sweep_reason="watchlist_match",
                     watchlist_matched=["products:Big"]) for i in range(10)]
        data = {"over_threshold_published": [], "kev_added_in_window": [],
                "watchlist_in_window": rows, "euvd_in_window": []}
        result = sweep.reconcile(data, self._report("{}"))
        self.assertEqual(result["unhandled_batches"], [])
        self.assertEqual(len(result["unhandled_individual"]), 10)

    def test_non_watchlist_rows_still_batched(self) -> None:
        rows = [_row(f"CVE-2026-2000{i}", 9.1, src="psirt@big.example") for i in range(6)]
        data = {"over_threshold_published": rows, "kev_added_in_window": [], "euvd_in_window": []}
        result = sweep.reconcile(data, self._report("{}"))
        self.assertEqual(len(result["unhandled_batches"]), 1)
        self.assertEqual(result["watchlist_unhandled"], 0)

    def test_legacy_sweep_json_without_watchlist(self) -> None:
        data = {"over_threshold_published": [_row("CVE-2026-10001", 9.8)], "kev_added_in_window": []}
        result = sweep.reconcile(data, self._report(json.dumps({"x": "CVE-2026-10001"})))
        self.assertEqual(result["unhandled"], [])
        md = sweep.render_markdown({
            "window": {"from": "a", "to": "b"}, "threshold": 9.0, "kev_catalog_version": "v",
            "counts": {"nvd_published_total": 1, "over_threshold_published": 1,
                       "ghsa_origin_over_threshold": 0, "kev_added_in_window": 0},
            "over_threshold_published": [_row("CVE-2026-10001", 9.8)], "kev_added_in_window": [],
        })
        self.assertIn("ウォッチリスト: なし（旧形式スイープ）", md)

    def test_render_markdown_lists_watchlist_rows(self) -> None:
        data = {
            "window": {"from": "a", "to": "b"}, "threshold": 9.0, "kev_catalog_version": "v",
            "counts": {"nvd_published_total": 2, "over_threshold_published": 0,
                       "ghsa_origin_over_threshold": 0, "kev_added_in_window": 0, "watchlist_in_window": 1},
            "over_threshold_published": [], "kev_added_in_window": [],
            "watchlist": {"status": "ok", "terms": {"cves": 0, "products": 1, "actors": 0, "topics": 0}},
            "watchlist_in_window": [_row("CVE-2026-10002", 5.3, sweep_reason="watchlist_match",
                                         watchlist_matched=["products:Zyxel"])],
        }
        md = sweep.render_markdown(data)
        self.assertIn("ウォッチリスト該当（1件・無条件採用）", md)
        self.assertIn("| CVE-2026-10002 | 5.3 | — | watchlist_match | products:Zyxel |", md)


class SweepMatchTests(unittest.TestCase):
    def test_cve_record_matching_uses_description_cpe_and_id(self) -> None:
        w = {"cves": ["CVE-2026-10005"], "products": ["ivanti connect secure"], "actors": [], "topics": []}
        cve = {"id": "CVE-2026-10009", "descriptions": [{"lang": "en", "value": "A flaw in a VPN appliance"}],
               "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:ivanti:connect_secure:*"}]}]}],
               "sourceIdentifier": "x"}
        self.assertEqual(sweep.watchlist_match_cve(w, cve), {})  # CPE は下線区切りで不一致＝語の揺れはリスト側で持つ
        cve["descriptions"][0]["value"] = "Ivanti Connect Secure allows ..."
        self.assertEqual(sweep.watchlist_match_cve(w, cve), {"products": ["ivanti connect secure"]})
        self.assertEqual(sweep.watchlist_match_cve(w, {"id": "CVE-2026-10005", "descriptions": []}), {"cves": ["CVE-2026-10005"]})

    def test_kev_matching(self) -> None:
        w = {"cves": [], "products": ["Zyxel"], "actors": [], "topics": []}
        self.assertEqual(sweep.watchlist_match_kev(w, "CVE-2026-10007", {"vendorProject": "Zyxel", "product": "GS1900"}),
                         {"products": ["Zyxel"]})

    def test_watchlist_sweep_adds_rows_below_threshold_and_marks_threshold_rows(self) -> None:
        w = {"cves": [], "products": ["Zyxel"], "actors": [], "topics": [], "_source": "t"}
        published = [
            {"cve": {"id": "CVE-2026-10001", "descriptions": [{"lang": "en", "value": "Zyxel low"}],
                     "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]}}},
            {"cve": {"id": "CVE-2026-10002", "descriptions": [{"lang": "en", "value": "Zyxel critical"}],
                     "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}},
            {"cve": {"id": "CVE-2026-10003", "descriptions": [{"lang": "en", "value": "Other"}],
                     "metrics": {}}},
        ]
        threshold_rows = [sweep.summarize(published[1]["cve"], {})]
        rows, meta = sweep.watchlist_sweep(w, published, {}, [], threshold_rows,
                                           "2026-11-05T00:00:00.000", "2026-11-06T00:00:00.000")
        self.assertEqual([r["cve_id"] for r in rows], ["CVE-2026-10001"])
        self.assertEqual(rows[0]["sweep_reason"], "watchlist_match")
        self.assertEqual(threshold_rows[0]["watchlist_matched"], ["products:Zyxel"])
        self.assertEqual(meta["status"], "ok")
        self.assertEqual(meta["explicit_cves_checked"], 0)


class ScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="pythia-scan-")
        items = [
            {"id": "a", "title": "Volt Typhoon targets utilities", "url": "https://x/a", "source": "S",
             "language": "en", "published_at": "2026-11-05T10:00:00+00:00", "summary": ""},
            {"id": "b", "title": "旧記事: 防衛産業への攻撃", "url": "https://x/b", "source": "J",
             "language": "ja", "published_at": "2026-11-01T10:00:00+00:00", "summary": ""},
            {"id": "c", "title": "Unrelated", "url": "https://x/c", "source": "S",
             "language": "en", "published_at": "2026-11-05T11:00:00+00:00", "summary": "nothing"},
            {"id": "d", "title": "No date, mentions CVE-2026-10001", "url": "https://x/d", "source": "S",
             "language": None, "published_at": None, "summary": ""},
        ]
        with open(os.path.join(self.tmp, "news-2026-11-05.json"), "w", encoding="utf-8") as fh:
            json.dump({"source_type": "rss", "items": items[:2]}, fh)
        with open(os.path.join(self.tmp, "news-2026-11-06.json"), "w", encoding="utf-8") as fh:
            json.dump({"source_type": "rss", "items": items[1:]}, fh)  # b は両日に重複
        self.w = {"cves": ["CVE-2026-10001"], "products": [], "actors": ["Volt Typhoon"],
                  "topics": ["防衛産業"], "_source": "t"}

    def test_scan_dedups_marks_window_and_keeps_language(self) -> None:
        window = (watchlist_scan.parse_jst("2026-11-05 07:00"), watchlist_scan.parse_jst("2026-11-06 07:00"))
        data = watchlist_scan.build(date(2026, 11, 6), self.tmp, self.w, window)
        self.assertEqual(data["scanned_items"], 4)
        ids = {m["id"]: m for m in data["matched"]}
        self.assertEqual(set(ids), {"a", "b", "d"})
        self.assertTrue(ids["a"]["in_window"])
        self.assertFalse(ids["b"]["in_window"])
        self.assertFalse(ids["d"]["in_window"])  # 日付不明は窓内と主張しない
        self.assertEqual(ids["b"]["language"], "ja")
        self.assertEqual(data["counts"]["in_window"], 1)
        self.assertEqual(data["matched"][0]["id"], "a")  # 窓内が先頭
        md = watchlist_scan.render_markdown(data)
        self.assertIn("actors:Volt Typhoon", md)
        self.assertIn("無条件", md.replace("採用条件（P〜W / α〜η 等）を満たさなくても採用候補", "無条件"))

    def test_scan_without_window_and_fallback_to_latest(self) -> None:
        data = watchlist_scan.build(date(2026, 11, 6), self.tmp, self.w, None)
        self.assertTrue(all(m["in_window"] is None for m in data["matched"]))
        empty = tempfile.mkdtemp(prefix="pythia-scan-empty-")
        with open(os.path.join(empty, "news-latest.json"), "w", encoding="utf-8") as fh:
            json.dump({"items": [{"id": "z", "title": "Volt Typhoon", "url": "u", "source": "S"}]}, fh)
        data = watchlist_scan.build(date(2026, 11, 6), empty, self.w, None)
        self.assertEqual([os.path.basename(f) for f in data["files"]], ["news-latest.json"])
        self.assertEqual(data["counts"]["matched"], 1)

    def test_empty_watchlist_is_disabled(self) -> None:
        data = watchlist_scan.build(date(2026, 11, 6), self.tmp, {c: [] for c in wl.CATEGORIES}, None)
        self.assertEqual(data["watchlist"]["status"], "disabled")
        self.assertEqual(data["matched"], [])
        self.assertIn("無効", watchlist_scan.render_markdown(data))


class NoWriteTests(unittest.TestCase):
    def test_repo_config_and_knowledge_untouched(self) -> None:
        cfg = os.path.join(REPO_ROOT, "config.yml")
        know = os.path.join(REPO_ROOT, "forecaster", "knowledge")
        before = {cfg: _sha(cfg)}
        for name in sorted(os.listdir(know)):
            path = os.path.join(know, name)
            if os.path.isfile(path):
                before[path] = _sha(path)
        wl.load_watchlist(cfg)
        watchlist_scan.build(date.today(), os.path.join(REPO_ROOT, "security-intel-collector", "data", "raw"),
                             wl.load_watchlist(cfg), None)
        after = {p: _sha(p) for p in before}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=1)
