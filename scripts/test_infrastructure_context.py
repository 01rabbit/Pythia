#!/usr/bin/env python3
"""Section 6（攻撃基盤プロファイル・第3段階）の受入基準を検査する。

依存は Python 3 標準ライブラリのみ。**テスト中は通信を物理的に遮断する**（socket を差し替える）。
応答はすべて固定データで与える。

検査する受入基準:
  A. 正規化と抽出
     1. 無害化表記・日本語注釈・URL のホスト・IPv6・日本語ドメインを正しく正規化する
     2. 予約アドレス・予約名・正規サービスは照会せずスキップ理由を付ける。ファイル名・パスのみは解析不能
     3. 同一指標は 1 件にまとめ、報告元・原文の表記・注記を全件残す。本層自身の出力は再走査しない
  B. 応答の抽出（純関数）
     4. 国が不明（?）なら空。vcard からレジストラを取る。urlscan は対象ドメインだけを数え非公開IPを除く
     5. パッシブ DNS の非公開アドレス（127.0.0.1 等）はホスティング先に混ぜず別項目に残す
  C. 照会と受動性
     6. 200→ok / 404→no_data / 空→no_data / 不正JSON・通信失敗→failed。取得時刻・ハッシュを残す
     7. IoC 自身への接続とリダイレクトを拒否する。一過性の失敗は 1 回再試行する
  D. オーケストレーション
     8. IP と ドメインで照会先が分かれ、上限超過・有効ソースなしは理由付きでスキップ
     9. 一部失敗は partial、全失敗は failed、IoC なしは no_indicators、無効は disabled
    10. 登録から 30 日以内・共有基盤・脆弱性・ホスト名の目印と注意書きが応答から再計算される
  E. 検証器（改ざん・欠落・捏造の検出）
    11. 正例が通る
    12. summary の改ざん・プロファイルの欠落／捏造・転記ミス・非公開IPの照会・IoC 自身への照会を落とす
    13. 取得証跡（時刻・ハッシュ・理由）・集計・実行状態・予報側への混入・予報層の項目を落とす
  F. 出力と不変条件
    14. レンダラーは決定論的・無害化表記・JSON 専用項目を出さない
    15. 整合チェッカーは infrastructure_context を持つ日だけ追加テキストを要求する
    16. ポリシー・config・ソース表の整合。保護ファイルを書き換えない

使い方:
    python3 scripts/test_infrastructure_context.py
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import socket
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPTS)
sys.path.insert(0, SCRIPTS)

import check_report_consistency as crc  # noqa: E402
import enrich_infrastructure as ei  # noqa: E402
import render_infrastructure_section as ris  # noqa: E402
import validate_infrastructure_context as vic  # noqa: E402
import watchlist as wl  # noqa: E402

DATE = "2026-11-06"
POLICY = ei.load_policy()
_REAL_CONNECT = socket.socket.connect
_REAL_CREATE = socket.create_connection


def setUpModule() -> None:
    def blocked(*args, **kwargs):
        raise RuntimeError("network is disabled in these tests")
    socket.socket.connect = blocked  # type: ignore[assignment]
    socket.create_connection = blocked  # type: ignore[assignment]


def tearDownModule() -> None:
    socket.socket.connect = _REAL_CONNECT  # type: ignore[assignment]
    socket.create_connection = _REAL_CREATE  # type: ignore[assignment]


def _sha(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# --------------------------------------------------------------------------
# 固定データ
# --------------------------------------------------------------------------

IP = "45.9.148.10"
PREFIX_DOC = {"data": {"resource": "45.9.148.0/24", "announced": True,
                       "asns": [{"asn": 211252, "holder": "EXAMPLE-AS - Example Hosting"}],
                       "block": {"desc": "RIPE NCC (Status: ALLOCATED)"}}}
GEO_DOC = {"data": {"located_resources": [{"resource": "45.9.148.10/32", "locations": [
    {"country": "NL", "city": "", "latitude": 52.0, "longitude": 5.0, "covered_percentage": 100.0}]}]}}
GEO_UNKNOWN = {"data": {"located_resources": [{"locations": [{"country": "?"}]}]}}
INTERNETDB_DOC = {"ip": IP, "ports": [8080, 22, 443], "cpes": ["cpe:/a:openbsd:openssh:8.9"],
                  "hostnames": ["host.example.net"], "tags": ["self-signed"], "vulns": ["CVE-2023-1234"]}
RDAP_DOC = {"objectClassName": "domain", "ldhName": "EVIL-UPDATE.COM", "status": ["client transfer prohibited"],
            "events": [{"eventAction": "registration", "eventDate": "2026-11-01T04:00:00Z"},
                       {"eventAction": "expiration", "eventDate": "2027-11-01T04:00:00Z"},
                       {"eventAction": "last changed", "eventDate": "2026-11-02T08:00:00Z"}],
            "nameservers": [{"ldhName": "NS1.EXAMPLE-DNS.NET"}, {"ldhName": "NS2.EXAMPLE-DNS.NET"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                                          ["fn", {}, "text", "Example Registrar, Inc."]]]},
                         {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED PERSON"]]]}]}
URLSCAN_DOC = {"total": 3, "search_date_limit_days": 30, "results": [
    {"task": {"time": "2026-11-05T10:00:00.000Z", "tags": ["phishing"]},
     "page": {"domain": "evil-update.com", "ip": IP, "asn": "AS211252", "asnname": "EXAMPLE-AS, NL", "server": "nginx"}},
    {"task": {"time": "2026-11-04T09:00:00.000Z"},
     "page": {"domain": "www.evil-update.com", "ip": IP, "asn": "AS211252", "asnname": "EXAMPLE-AS, NL", "server": "nginx"}},
    {"task": {"time": "2026-11-03T09:00:00.000Z"},
     "page": {"domain": "evil-update.com", "ip": "127.0.0.1", "asn": "AS0", "server": "x"}},
    {"task": {"time": "2026-11-03T09:00:00.000Z"},
     "page": {"domain": "other.example", "ip": "8.8.8.8", "asn": "AS15169", "server": "gws"}}]}
MNEMONIC_DOC = {"count": 12, "data": [
    {"rrtype": "a", "answer": IP, "times": 5, "lastUpdatedTimestamp": 1793952610806},
    {"rrtype": "a", "answer": "127.0.0.1", "times": 1, "lastUpdatedTimestamp": 1793900000000},
    {"rrtype": "ns", "answer": "ns1.example-dns.net", "times": 9, "lastUpdatedTimestamp": 1793800000000},
    {"rrtype": "a", "answer": "not-an-ip", "times": 1, "lastUpdatedTimestamp": 1793700000000},
    {"rrtype": "txt", "answer": "v=spf1", "times": 1, "lastUpdatedTimestamp": 1793600000000}]}


def make_report() -> dict:
    return {
        "meta": {"report_date": DATE}, "statistics": {}, "forecasts": [], "tactical_forecast": {"mode": "shadow"},
        "apt_main": [{"campaign_id": "APT-2026-X", "info_id": "20261106-APTC-aaaaaaaa",
                      "ioc": {"confirmed": True, "ips": ["45.9.148[.]10", "10.1.2.3"],
                              "domains": ["evil-update.com（C2）", "github.com", "setup.exe"],
                              "urls": ["hxxp://45.9.148[.]10:8080/a", "/admin/login.php"], "hashes": ["abc"],
                              "filenames": []}}],
        "zero_day_special": [{"cve_id": "CVE-2026-10001", "info_id": "20261106-CVEP-bbbbbbbb",
                              "ioc": {"confirmed": True, "ips": [IP], "domains": [], "urls": [], "hashes": [],
                                      "filenames": []}}],
    }


def make_routes(overrides=None):
    routes = [
        ("https://stat.ripe.net/data/prefix-overview", (200, PREFIX_DOC)),
        ("https://stat.ripe.net/data/maxmind-geo-lite", (200, GEO_DOC)),
        ("https://internetdb.shodan.io/", (200, INTERNETDB_DOC)),
        ("https://rdap.org/domain/", (200, RDAP_DOC)),
        ("https://urlscan.io/api/v1/search/", (200, URLSCAN_DOC)),
        ("https://api.mnemonic.no/pdns/v3/", (200, MNEMONIC_DOC)),
    ]
    return list((overrides or [])) + routes


def make_fetch(routes, log=None):
    def fetch(url):
        if log is not None:
            log.append(url)
        for prefix, resp in routes:
            if url.startswith(prefix):
                if isinstance(resp, dict):
                    return resp
                status, doc = resp
                body = b"" if doc is None else json.dumps(doc).encode("utf-8")
                return {"http_status": status, "body": body, "error": None if status in (200, 404) else f"HTTP {status}"}
        return {"http_status": 404, "body": b"", "error": None}
    return fetch


def make_clock():
    base = datetime(2026, 11, 6, 13, 0, 0, tzinfo=timezone.utc)
    state = {"n": 0}

    def now():
        state["n"] += 1
        return (base + timedelta(seconds=state["n"])).strftime("%Y-%m-%dT%H:%M:%SZ")
    return now


def run_enrich(report=None, routes=None, section=None, log=None):
    report = make_report() if report is None else report
    return ei.enrich(report, policy=POLICY, section=section or {"enabled": True, "max_indicators": 40},
                     fetch=make_fetch(routes if routes is not None else make_routes(), log),
                     report_date=DATE, now=make_clock())


# --------------------------------------------------------------------------
# A. 正規化と抽出
# --------------------------------------------------------------------------

class NormalizeTests(unittest.TestCase):
    def kind(self, raw):
        c = ei.classify_token(raw, POLICY)
        return (c["kind"], c.get("value") or c.get("reason"), c.get("skip_reason"))

    def test_defang_annotation_and_url(self) -> None:
        self.assertEqual(self.kind("198.13.53[.]226"), ("ip", "198.13.53.226", None))
        self.assertEqual(self.kind("98aiblog.com（SoftEther VPN）"), ("domain", "98aiblog.com", None))
        self.assertEqual(ei.classify_token("98aiblog.com（SoftEther VPN）", POLICY)["annotation"], "SoftEther VPN")
        self.assertEqual(self.kind("hxxps://evil[.]example[.]org:8443/a/b（C2）"), ("domain", "evil.example.org", None))
        self.assertEqual(self.kind("http://1.2.3.4/x"), ("ip", "1.2.3.4", None))
        self.assertEqual(self.kind("1.2.3.4:443"), ("ip", "1.2.3.4", None))
        self.assertEqual(self.kind("*.badsite.xyz"), ("domain", "badsite.xyz", None))
        self.assertEqual(self.kind("[2606:4700:4700::1111]"), ("ip", "2606:4700:4700::1111", None))
        self.assertEqual(self.kind("例え.jp"), ("domain", "xn--r8jz45g.jp", None))

    def test_skips_and_unparsed(self) -> None:
        self.assertEqual(self.kind("10.0.0.1")[2], "non_public")
        self.assertEqual(self.kind("192.0.2.5")[2], "non_public")
        self.assertEqual(self.kind("2001:db8::1")[2], "non_public")
        self.assertEqual(self.kind("foo.test")[2], "non_public")
        self.assertEqual(self.kind("raw.githubusercontent.com")[2], "legitimate_or_shared_platform")
        self.assertEqual(self.kind("x.workers.dev")[2], "legitimate_or_shared_platform")
        self.assertEqual(self.kind("notgithub.com")[2], None)  # サフィックス一致は境界を見る
        self.assertEqual(self.kind("update.exe")[:2], ("unparsed", "not_a_domain"))
        self.assertEqual(self.kind("/dana-na/auth/welcome.cgi（大量）")[:2], ("unparsed", "url_path_only"))
        for bad in ("", "not a domain", "foo", "a..b"):
            self.assertEqual(self.kind(bad)[:2], ("unparsed", "unparseable"), bad)


class ExtractTests(unittest.TestCase):
    def test_merge_and_order(self) -> None:
        indicators, unparsed = ei.extract_indicators(make_report(), POLICY)
        self.assertEqual([(i["type"], i["indicator"]) for i in indicators],
                         [("ip", IP), ("ip", "10.1.2.3"), ("domain", "evil-update.com"), ("domain", "github.com")])
        first = indicators[0]
        self.assertEqual({r["ref"] for r in first["reported_in"]}, {"APT-2026-X", "CVE-2026-10001"})
        self.assertIn("45.9.148[.]10", first["as_reported"])
        self.assertIn(IP, first["as_reported"])
        self.assertEqual(indicators[2]["annotations"], ["C2"])
        self.assertEqual(sorted((u["as_reported"], u["reason"]) for u in unparsed),
                         [("/admin/login.php", "url_path_only"), ("setup.exe", "not_a_domain")])

    def test_own_output_is_not_rescanned(self) -> None:
        report = make_report()
        report["infrastructure_context"] = {"profiles": [{"ioc": {"ips": ["8.8.8.8"]}}]}
        report["neighbor_context"] = {"entries": [{"ioc": {"ips": ["9.9.9.9"]}}]}
        indicators, _ = ei.extract_indicators(report, POLICY)
        self.assertNotIn("8.8.8.8", [i["indicator"] for i in indicators])
        self.assertNotIn("9.9.9.9", [i["indicator"] for i in indicators])


# --------------------------------------------------------------------------
# B. 応答の抽出
# --------------------------------------------------------------------------

class ExtractorTests(unittest.TestCase):
    def test_ripestat(self) -> None:
        self.assertEqual(ei.extract_ripestat_prefix(PREFIX_DOC)["asns"],
                         [{"asn": 211252, "holder": "EXAMPLE-AS - Example Hosting"}])
        self.assertEqual(ei.extract_ripestat_geo(GEO_DOC), {"countries": ["NL"], "approximate": True})
        self.assertEqual(ei.extract_ripestat_geo(GEO_UNKNOWN)["countries"], [])  # '?' は国ではない
        self.assertEqual(ei.extract_ripestat_prefix({}), {})
        self.assertNotIn("latitude", json.dumps(ei.extract_ripestat_geo(GEO_DOC)))  # 座標は保存しない

    def test_internetdb(self) -> None:
        out = ei.extract_internetdb(INTERNETDB_DOC)
        self.assertEqual(out["ports"], [22, 443, 8080])
        self.assertEqual(out["vulns"], ["CVE-2023-1234"])
        self.assertEqual(ei.extract_internetdb({"detail": "No information available"}), {})

    def test_rdap_keeps_organisation_not_people(self) -> None:
        out = ei.extract_rdap_domain(RDAP_DOC, "evil-update.com")
        self.assertEqual(out["registrar"], "Example Registrar, Inc.")
        self.assertEqual(out["nameservers"], ["ns1.example-dns.net", "ns2.example-dns.net"])
        self.assertEqual(out["registered_at"], "2026-11-01T04:00:00Z")
        self.assertNotIn("REDACTED PERSON", json.dumps(out))  # 登録者の氏名は保存しない
        self.assertEqual(ei.extract_rdap_domain({"errorCode": 404}, "x"), {})

    def test_urlscan_counts_only_target_and_public(self) -> None:
        out = ei.extract_urlscan(URLSCAN_DOC, "evil-update.com")
        self.assertEqual(out["matched_results"], 2)  # 他ドメイン・127.0.0.1 は数えない
        self.assertEqual([o["ip"] for o in out["observed"]], [IP])
        obs = out["observed"][0]
        self.assertEqual((obs["asn"], obs["count"], obs["server"]), (211252, 2, "nginx"))
        self.assertEqual((obs["first_seen"], obs["last_seen"]), ("2026-11-04T09:00:00.000Z", "2026-11-05T10:00:00.000Z"))
        self.assertNotIn("phishing", json.dumps(out))  # 投稿者のラベルは事実として扱わない
        self.assertEqual(ei.extract_urlscan({"total": 0, "results": []}, "x.com"), {})

    def test_mnemonic_separates_non_public_answers(self) -> None:
        out = ei.extract_mnemonic(MNEMONIC_DOC)
        self.assertEqual(out["resolved_ips"], [IP])
        self.assertEqual(out["non_public_answers"], ["127.0.0.1"])
        self.assertEqual({r["rrtype"] for r in out["records"]}, {"a", "ns"})  # txt と不正な A は落とす
        self.assertNotIn("not-an-ip", json.dumps(out))
        self.assertEqual(ei.extract_mnemonic({"data": []}), {})


# --------------------------------------------------------------------------
# C. 照会と受動性
# --------------------------------------------------------------------------

class LookupTests(unittest.TestCase):
    def lookup(self, resp):
        return ei.run_lookup(lambda url: resp, "internetdb", "https://internetdb.shodan.io/1.2.3.4",
                             ei.extract_internetdb, make_clock())

    def test_status_mapping_and_evidence(self) -> None:
        body = json.dumps(INTERNETDB_DOC).encode()
        ok = self.lookup({"http_status": 200, "body": body, "error": None})
        self.assertEqual((ok["status"], ok["http_status"], ok["host"]), ("ok", 200, "internetdb.shodan.io"))
        self.assertEqual(ok["response_sha256"], hashlib.sha256(body).hexdigest())
        self.assertRegex(ok["queried_at_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(self.lookup({"http_status": 404, "body": b"", "error": None})["status"], "no_data")
        self.assertEqual(self.lookup({"http_status": 200, "body": b"{}", "error": None})["status"], "no_data")
        bad = self.lookup({"http_status": 200, "body": b"<html>", "error": None})
        self.assertEqual((bad["status"], bad["error"]), ("failed", "invalid JSON"))
        net = self.lookup({"http_status": None, "body": None, "error": "URLError: timed out"})
        self.assertEqual((net["status"], net["response_sha256"]), ("failed", None))
        self.assertEqual(self.lookup({"http_status": 503, "body": b"", "error": "HTTP 503"})["status"], "failed")


class _Resp:
    def __init__(self, status, body):
        self.status, self._body = status, body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FetcherTests(unittest.TestCase):
    LIMITS = {"timeout_seconds": 1, "retries": 1, "retry_wait_seconds": 0, "min_interval_seconds": 0}

    def test_never_contacts_reported_indicators(self) -> None:
        f = ei.Fetcher(self.LIMITS, never_contact={IP, "evil-update.com"}, sleep=lambda s: None)
        for url in (f"https://{IP}/x", "https://evil-update.com/y"):
            res = f(url)
            self.assertEqual((res["http_status"], res["body"]), (None, None))
            self.assertIn("refused", res["error"])

    def test_redirect_to_indicator_or_http_is_refused(self) -> None:
        handler = ei._GuardedRedirect({"evil-update.com"})
        req = urllib.request.Request("https://rdap.org/domain/x")
        for target in ("https://evil-update.com/", "http://registry.example/", "https://EVIL-UPDATE.com/z"):
            with self.assertRaises(urllib.error.URLError):
                handler.redirect_request(req, None, 302, "Found", {}, target)
        ok = handler.redirect_request(req, None, 302, "Found", {}, "https://rdap.verisign.com/com/v1/domain/x")
        self.assertEqual(ok.full_url, "https://rdap.verisign.com/com/v1/domain/x")

    def test_retry_once_on_transient_errors(self) -> None:
        f = ei.Fetcher(self.LIMITS, sleep=lambda s: None)
        calls = []

        class Opener:
            def open(self, req, timeout=None):
                calls.append(1)
                if len(calls) == 1:
                    raise urllib.error.URLError("connection reset")
                return _Resp(200, b'{"ok": true}')
        f.opener = Opener()
        self.assertEqual(f("https://internetdb.shodan.io/1.2.3.4")["http_status"], 200)
        self.assertEqual(len(calls), 2)

        calls.clear()

        class Always429:
            def open(self, req, timeout=None):
                calls.append(1)
                raise urllib.error.HTTPError(req.full_url, 429, "Too Many", {}, io.BytesIO(b""))
        f.opener = Always429()
        res = f("https://internetdb.shodan.io/1.2.3.4")
        self.assertEqual((res["http_status"], res["error"], len(calls)), (429, "HTTP 429", 2))  # 再試行は 1 回だけ

    def test_404_is_not_an_error(self) -> None:
        f = ei.Fetcher(self.LIMITS, sleep=lambda s: None)

        class Opener:
            def open(self, req, timeout=None):
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b"{}"))
        f.opener = Opener()
        res = f("https://internetdb.shodan.io/1.2.3.4")
        self.assertEqual((res["http_status"], res["error"]), (404, None))


# --------------------------------------------------------------------------
# D. オーケストレーション
# --------------------------------------------------------------------------

class EnrichTests(unittest.TestCase):
    def test_routing_and_profiles(self) -> None:
        log: list = []
        ctx = run_enrich(log=log)
        self.assertEqual(ctx["run"]["status"], "ok")
        self.assertIs(ctx["forecast_input"], False)
        by_id = {p["indicator"]: p for p in ctx["profiles"]}
        self.assertEqual([p["profile_id"] for p in ctx["profiles"]],
                         [f"inf-{DATE}-00{i}" for i in range(1, 5)])
        self.assertEqual([l["source"] for l in by_id[IP]["lookups"]],
                         ["ripestat.prefix", "ripestat.geolocation", "internetdb"])
        self.assertEqual([l["source"] for l in by_id["evil-update.com"]["lookups"]],
                         ["rdap.domain", "urlscan.search", "mnemonic.pdns"])
        self.assertEqual(by_id["10.1.2.3"]["skip_reason"], "non_public")
        self.assertEqual(by_id["github.com"]["skip_reason"], "legitimate_or_shared_platform")
        self.assertEqual((by_id["10.1.2.3"]["lookups"], by_id["github.com"]["lookups"]), ([], []))
        self.assertEqual(ctx["run"]["indicators"], {"extracted": 4, "enriched": 2, "skipped": 2, "unparsed": 2})
        self.assertEqual(ctx["run"]["lookups"], {"total": 6, "ok": 6, "no_data": 0, "failed": 0})
        # 非公開・共有プラットフォームには一切問い合わせない
        self.assertFalse(any("10.1.2.3" in u or "github.com" in u for u in log))
        self.assertEqual(len(log), 6)

    def test_summary_flags_and_caveats(self) -> None:
        by_id = {p["indicator"]: p for p in run_enrich()["profiles"]}
        ip = by_id[IP]
        self.assertEqual(ip["summary"]["countries"], ["NL"])
        self.assertEqual(ip["summary"]["ports"], [22, 443, 8080])
        self.assertEqual(ip["caveats"], ["geolocation_approximate", "source_vulns_unverified", "hostnames_source_asserted"])
        self.assertTrue(ip["flags"]["has_source_vulns"])
        self.assertFalse(ip["flags"]["shared_infrastructure"])
        dom = by_id["evil-update.com"]
        self.assertTrue(dom["flags"]["newly_registered"])  # 2026-11-01 登録・報告日 2026-11-06
        self.assertEqual(dom["summary"]["observed_ips"], [IP])
        self.assertEqual(dom["summary"]["non_public_answers"], ["127.0.0.1"])
        self.assertEqual(dom["summary"]["registrar"], "Example Registrar, Inc.")
        self.assertEqual(dom["caveats"], ["urlscan_30d_window", "passive_dns_partial"])

    def test_shared_infrastructure_and_new_registration_window(self) -> None:
        cloudflare = {"data": {"resource": "104.16.0.0/13", "announced": True,
                               "asns": [{"asn": 13335, "holder": "CLOUDFLARENET"}], "block": {"desc": "ARIN"}}}
        ctx = run_enrich(routes=make_routes([("https://stat.ripe.net/data/prefix-overview", (200, cloudflare))]))
        ip = next(p for p in ctx["profiles"] if p["indicator"] == IP)
        self.assertEqual(ip["flags"]["shared_infrastructure_providers"], ["Cloudflare"])
        self.assertIn("shared_infrastructure_not_attribution", ip["caveats"])
        old = copy.deepcopy(RDAP_DOC)
        old["events"][0]["eventDate"] = "2026-09-01T04:00:00Z"  # 66 日前
        ctx = run_enrich(routes=make_routes([("https://rdap.org/domain/", (200, old))]))
        dom = next(p for p in ctx["profiles"] if p["indicator"] == "evil-update.com")
        self.assertFalse(dom["flags"]["newly_registered"])

    def test_budget_and_disabled_sources(self) -> None:
        ctx = run_enrich(section={"enabled": True, "max_indicators": 1})
        reasons = {p["indicator"]: p["skip_reason"] for p in ctx["profiles"]}
        self.assertEqual(reasons[IP], None)
        self.assertEqual(reasons["evil-update.com"], "over_budget")
        ctx = run_enrich(section={"enabled": True, "sources": ["ripestat"]})
        reasons = {p["indicator"]: p["skip_reason"] for p in ctx["profiles"]}
        self.assertEqual(reasons["evil-update.com"], "no_enabled_source")
        self.assertEqual([l["source"] for l in next(p for p in ctx["profiles"] if p["indicator"] == IP)["lookups"]],
                         ["ripestat.prefix", "ripestat.geolocation"])

    def test_failure_modes(self) -> None:
        down = {"http_status": None, "body": None, "error": "URLError: timed out"}
        partial = run_enrich(routes=make_routes([("https://api.mnemonic.no/", down)]))
        self.assertEqual(partial["run"]["status"], "partial")
        self.assertEqual(partial["run"]["by_source"]["mnemonic.pdns"]["failed"], 1)
        self.assertIn("some_sources_failed", next(p for p in partial["profiles"] if p["indicator"] == "evil-update.com")["caveats"])
        every = [(p, down) for p in ("https://stat.ripe.net", "https://internetdb.shodan.io", "https://rdap.org",
                                     "https://urlscan.io", "https://api.mnemonic.no")]
        self.assertEqual(run_enrich(routes=every)["run"]["status"], "failed")
        self.assertEqual(run_enrich(report={"meta": {"report_date": DATE}})["run"]["status"], "no_indicators")
        self.assertEqual(run_enrich(section={"enabled": False})["run"]["status"], "disabled")
        self.assertEqual(run_enrich(section={"enabled": False})["profiles"], [])

    def test_rdap_falls_back_to_parent_domain(self) -> None:
        report = {"meta": {"report_date": DATE}, "apt_main": [{"campaign_id": "X", "ioc": {
            "ips": [], "domains": ["a.b.evil-update.com"], "urls": []}}]}
        log: list = []
        routes = make_routes([("https://rdap.org/domain/a.b.evil-update.com", (404, None)),
                              ("https://rdap.org/domain/b.evil-update.com", (404, None))])
        ctx = run_enrich(report=report, routes=routes, log=log)
        rdap = ctx["profiles"][0]["lookups"][0]
        self.assertEqual((rdap["status"], rdap["extract"]["queried_name"]), ("ok", "evil-update.com"))
        self.assertEqual(sum(1 for u in log if "rdap.org" in u), 3)

    def test_inject_is_idempotent(self) -> None:
        report = make_report()
        first = ei.inject(report, run_enrich(report=report))
        self.assertEqual(first["statistics"]["infrastructure_context"],
                         {"profiles": 4, "enriched": 2, "skipped": 2, "unparsed": 2})
        again = ei.inject(copy.deepcopy(first), run_enrich(report=first))
        self.assertEqual([p["indicator"] for p in again["infrastructure_context"]["profiles"]],
                         [p["indicator"] for p in first["infrastructure_context"]["profiles"]])


# --------------------------------------------------------------------------
# E. 検証器
# --------------------------------------------------------------------------

def good_report() -> dict:
    report = make_report()
    ei.inject(report, run_enrich(report=report))
    return json.loads(json.dumps(report, ensure_ascii=False))  # 実運用と同じくファイルを経由した形にする


def check(report, *, obs=None, require=False):
    return vic.validate(report, date=DATE, policy=POLICY, observation_text=obs, require=require)


class ValidatorTests(unittest.TestCase):
    def assertError(self, report, needle, **kw):
        errors, _ = check(report, **kw)
        self.assertTrue(any(needle in e for e in errors), f"{needle!r} が無い: {errors}")

    def mutate(self, fn):
        report = good_report()
        fn(report["infrastructure_context"])
        return report

    def profile(self, ctx, indicator):
        return next(p for p in ctx["profiles"] if p["indicator"] == indicator)

    def test_good_report_passes(self) -> None:
        self.assertEqual(check(good_report()), ([], []))

    def test_tampered_summary_flags_caveats(self) -> None:
        self.assertError(self.mutate(lambda c: self.profile(c, IP)["summary"]["ports"].append(3389)), "summary")
        self.assertError(self.mutate(lambda c: self.profile(c, IP)["summary"].update(owner="Evil Corp")), "summary")
        self.assertError(self.mutate(lambda c: self.profile(c, IP)["flags"].update(shared_infrastructure=True)), "flags")
        self.assertError(self.mutate(lambda c: self.profile(c, IP)["caveats"].clear()), "caveats")

    def test_completeness_and_traceability(self) -> None:
        self.assertError(self.mutate(lambda c: c["profiles"].pop(0)), "プロファイルに無い")

        def invent(c):
            p = copy.deepcopy(self.profile(c, IP))
            p.update(indicator="8.8.8.8", defanged="8[.]8[.]8[.]8", profile_id=f"inf-{DATE}-099")
            c["profiles"].append(p)
        self.assertError(self.mutate(invent), "レポートに無い指標")
        self.assertError(self.mutate(lambda c: c["unparsed"].pop()), "解析不能")

        def typo(c):
            p = self.profile(c, IP)
            p["indicator"], p["defanged"] = "45.9.148.11", "45[.]9[.]148[.]11"
        self.assertError(self.mutate(typo), "正規化しても")
        self.assertError(self.mutate(lambda c: self.profile(c, IP).update(reported_in=[])), "reported_in")

    def test_passive_only_and_non_public(self) -> None:
        self.assertError(self.mutate(lambda c: self.profile(c, IP)["lookups"][0].update(host="evil.example")), "既知のホスト")

        def self_query(c):
            self.profile(c, "evil-update.com")["lookups"][0].update(host="evil-update.com")
        self.assertError(self.mutate(self_query), "IoC 自身")

        def enrich_private(c):
            self.profile(c, "10.1.2.3")["skip_reason"] = None
        self.assertError(self.mutate(enrich_private), "非公開")

        def enrich_platform(c):
            self.profile(c, "github.com")["skip_reason"] = None
        self.assertError(self.mutate(enrich_platform), "共有基盤を照会していない")

        def skipped_with_lookups(c):
            self.profile(c, "10.1.2.3")["lookups"] = copy.deepcopy(self.profile(c, IP)["lookups"])
        self.assertError(self.mutate(skipped_with_lookups), "スキップしたのに照会記録")
        self.assertError(self.mutate(lambda c: self.profile(c, IP)["lookups"][0].update(source="ripestat.nope")), "未知のソース")
        self.assertError(self.mutate(lambda c: self.profile(c, "evil-update.com")["lookups"].append(
            copy.deepcopy(self.profile(c, IP)["lookups"][0]))), "適用しないソース")

    def test_evidence_fields(self) -> None:
        self.assertError(self.mutate(lambda c: self.profile(c, IP)["lookups"][0].update(
            queried_at_utc="2026-11-06T09:00:00Z")), "実行区間")
        self.assertError(self.mutate(lambda c: self.profile(c, IP)["lookups"][0].update(queried_at_utc="yesterday")), "形式")
        self.assertError(self.mutate(lambda c: self.profile(c, IP)["lookups"][0].update(response_sha256="zz")), "64 桁")
        self.assertError(self.mutate(lambda c: self.profile(c, IP)["lookups"][0].update(extract={})), "extract が空")
        self.assertError(self.mutate(lambda c: self.profile(c, IP)["lookups"][0].update(status="maybe")), "status")

        def failed_without_reason(c):
            self.profile(c, IP)["lookups"][0].update(status="failed", extract={}, error=None)
        self.assertError(self.mutate(failed_without_reason), "error")

    def test_aggregates_and_status(self) -> None:
        self.assertError(self.mutate(lambda c: c["run"]["lookups"].update(ok=99)), "run.lookups")
        self.assertError(self.mutate(lambda c: c["run"]["indicators"].update(enriched=0)), "run.indicators")
        self.assertError(self.mutate(lambda c: c["run"].update(status="failed")), "run.status")
        self.assertError(self.mutate(lambda c: c["run"]["by_source"]["internetdb"].update(ok=7)), "by_source")
        report = good_report()
        report["statistics"]["infrastructure_context"]["profiles"] = 9
        self.assertError(report, "statistics.infrastructure_context")

    def test_isolation_and_forbidden_fields(self) -> None:
        self.assertError(self.mutate(lambda c: c.update(forecast_input=True)), "forecast_input")
        self.assertError(self.mutate(lambda c: self.profile(c, IP).update(forecast_input=True)), "forecast_input")
        self.assertError(self.mutate(lambda c: self.profile(c, IP).update(techniques=["T1190"])), "予報の入力層")
        self.assertError(good_report(), "観測ファイル", obs=f'{{"note": "inf-{DATE}-001"}}')
        report = good_report()
        report["forecasts"] = [{"basis": f"see inf-{DATE}-001"}]
        self.assertError(report, "forecasts")
        report = good_report()
        report["tactical_forecast"] = {"note": f"inf-{DATE}-002"}
        self.assertError(report, "tactical_forecast")
        self.assertEqual(check(good_report(), obs='{"observations": [], "x": "info-2026"}')[0], [])

    def test_missing_disabled_and_degraded(self) -> None:
        errors, warnings = vic.validate({"meta": {}}, date=DATE, policy=POLICY)
        self.assertEqual((errors, len(warnings)), ([], 1))
        self.assertEqual(len(vic.validate({"meta": {}}, date=DATE, policy=POLICY, require=True)[0]), 1)
        disabled = make_report()
        ei.inject(disabled, run_enrich(report=disabled, section={"enabled": False}))
        self.assertEqual(check(disabled), ([], []))
        disabled["infrastructure_context"]["profiles"] = [{"x": 1}]
        self.assertError(disabled, "無効")
        down = {"http_status": None, "body": None, "error": "URLError: boom"}
        degraded = make_report()
        ei.inject(degraded, run_enrich(report=degraded, routes=make_routes([("https://api.mnemonic.no/", down)])))
        errors, warnings = check(degraded)
        self.assertEqual(errors, [])
        self.assertTrue(any("partial" in w for w in warnings))


# --------------------------------------------------------------------------
# F. 出力と不変条件
# --------------------------------------------------------------------------

class RenderTests(unittest.TestCase):
    def test_deterministic_defanged_and_hides_json_only(self) -> None:
        report = good_report()
        text = ris.render(report)
        self.assertEqual(text, ris.render(copy.deepcopy(report)))
        for needle in ("【攻撃基盤プロファイル】", "45[.]9[.]148[.]10", "evil-update[.]com", "AS211252",
                       "登録から30日以内", "非公開アドレスへの解決履歴: 127[.]0[.]0[.]1", "【照会しなかった指標】",
                       "10[.]1[.]2[.]3: 非公開アドレス", "github[.]com: 正規サービス", "setup[.]exe: ファイル名",
                       "/admin/login[.]php: パスのみ", "受動照会", "ripestat.prefix 2026-11-06T13:00:",
                       "報告時の表記: 45[.]9[.]148[.]10 / hxxp://45[.]9[.]148[.]10:8080/a"):
            self.assertIn(needle, text)
        self.assertNotIn("45.9.148.10", text)  # 本文の IP は報告時の表記を含めてすべて無害化表記
        self.assertNotIn("evil-update.com", text)
        profile = report["infrastructure_context"]["profiles"][0]
        for hidden in (profile["lookups"][0]["response_sha256"], "forecast_input", "response_sha256"):
            self.assertNotIn(hidden, text)

    def test_empty_and_shared_caveat(self) -> None:
        report = make_report()
        ei.inject(report, run_enrich(report={"meta": {"report_date": DATE}}))
        self.assertIn("補強の対象となる IoC はありません", ris.render(report))
        cloudflare = {"data": {"resource": "104.16.0.0/13", "announced": True,
                               "asns": [{"asn": 13335, "holder": "CLOUDFLARENET"}], "block": {"desc": "ARIN"}}}
        shared = make_report()
        ei.inject(shared, run_enrich(report=shared, routes=make_routes(
            [("https://stat.ripe.net/data/prefix-overview", (200, cloudflare))])))
        self.assertIn("共有基盤（Cloudflare）上にあり", ris.render(shared))


class ConsistencyTests(unittest.TestCase):
    def make_root(self, with_text: bool, in_full: bool = True) -> Path:
        root = Path(tempfile.mkdtemp(prefix="pythia-infra-consistency-"))
        base = root / "outputs" / DATE
        base.mkdir(parents=True)
        report = good_report()
        (base / f"{DATE}-security-report.json").write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        pids = " ".join(p["profile_id"] for p in report["infrastructure_context"]["profiles"])
        for suffix in crc.TEXT_SUFFIXES:
            # fixture の zero_day_special に載せた CVE は全セクション版と CVE 版に出現している必要がある
            body = "本文 CVE-2026-10001\n" + (pids if (suffix == "" and in_full) else "")
            (base / f"{DATE}-security-report{suffix}.txt").write_text(body, encoding="utf-8")
        if with_text:
            (base / f"{DATE}-security-report-infra.txt").write_text(pids, encoding="utf-8")
        return root

    def test_extra_text_required_only_when_section_present(self) -> None:
        errors, _ = crc.check_date(self.make_root(False), DATE)
        self.assertTrue(any("security-report-infra.txt" in e for e in errors), errors)
        errors, _ = crc.check_date(self.make_root(True, in_full=False), DATE)
        self.assertTrue(any("security-report.txt に出現しない" in e for e in errors), errors)
        errors, _ = crc.check_date(self.make_root(True), DATE)
        self.assertEqual(errors, [])


class InvariantTests(unittest.TestCase):
    def test_policy_is_well_formed(self) -> None:
        for key in ("legitimate_or_shared_platform_suffixes", "non_domain_extensions"):
            for item in POLICY[key]:
                self.assertEqual(item, item.lower(), item)
                self.assertFalse(item.startswith("."), item)
        self.assertTrue(all(k.isdigit() for k in POLICY["shared_infrastructure_asns"]))
        self.assertTrue(set(POLICY["limits"]) >= {"timeout_seconds", "retries", "min_interval_seconds", "max_list_items"})

    def test_repo_config_and_source_tables(self) -> None:
        section = wl.load_config(os.path.join(REPO_ROOT, "config.yml"))["infrastructure"]
        self.assertIsInstance(section["enabled"], bool)
        self.assertGreater(section["max_indicators"], 0)
        self.assertTrue(set(section["sources"]) <= set(ei.SOURCE_FAMILIES))
        self.assertEqual(set(vic.SOURCE_HOSTS), set(ei.LOOKUP_FAMILY))
        self.assertEqual(ei.CAVEAT_KEYS, tuple(ris.CAVEAT_JA))
        self.assertTrue(set(ei.SKIP_REASONS) <= set(ris.SKIP_JA))
        self.assertTrue(set(ei.UNPARSED_REASONS) <= set(ris.UNPARSED_JA))

    def test_urls_only_target_declared_hosts(self) -> None:
        log: list = []
        run_enrich(log=log)
        hosts = {u.split("/")[2] for u in log}
        allowed = set().union(*vic.SOURCE_HOSTS.values())
        self.assertTrue(hosts <= allowed, hosts - allowed)

    def test_does_not_write_protected_files(self) -> None:
        know = os.path.join(REPO_ROOT, "forecaster", "knowledge")
        protected = [os.path.join(REPO_ROOT, "config.yml"), os.path.join(REPO_ROOT, "infra", "policy.json")]
        protected += [os.path.join(know, n) for n in sorted(os.listdir(know)) if os.path.isfile(os.path.join(know, n))]
        before = {p: _sha(p) for p in protected}
        report = good_report()
        check(report)
        ris.render(report)
        self.assertEqual(before, {p: _sha(p) for p in protected})


if __name__ == "__main__":
    unittest.main(verbosity=1)
