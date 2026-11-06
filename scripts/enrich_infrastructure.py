#!/usr/bin/env python3
"""レポートに載った IoC を公開データベースへの『受動照会』だけで補強する（Step 3.1・Section 6）。

要件「攻撃者の攻撃プラットフォームに関する詳細情報（国・ドメイン・URL・IP・管理者・稼働サービスと
バージョン・OS・開放ポート・脆弱性・ノード種別）」に対応する層。日次レポート JSON の `ioc` に
載った IP・ドメイン・URL のホストを抽出し、次の 5 ソースで補強して `infrastructure_context` を作る。

  ripestat   IP → 経路広告のプレフィックス・ASN・保有者・国（近似）
  internetdb IP → Shodan が既に保有する開放ポート・CPE・タグ・脆弱性
  rdap       ドメイン → 登録日・レジストラ・ネームサーバ
  urlscan    ドメイン → 過去 30 日の他者スキャンが観測した IP・ASN・Server ヘッダ
  mnemonic   ドメイン → パッシブ DNS の A/AAAA/NS 履歴

★設計上の約束
- 『受動』= 公開データベースへ尋ねるだけである。IoC の指す IP・ドメイン自体へは接続しない。
  ドメインの名前解決も行わない（再帰解決は権威サーバへ到達しうるため）。リダイレクト先が
  IoC 自身なら拒否する（Fetcher の _GuardedRedirect と never_contact）
- プロファイルは LLM が書かず、このスクリプトが API 応答から機械的に作る。要約・フラグ・注意書きは
  応答の extract から再計算できる純関数（build_summary）で、検証器が同じ関数で再計算して照合する
- 全照会に取得時刻（UTC）・HTTP 状態・応答本文の SHA-256 を残す。ソースの取得失敗は記録して続行
  （フェイルソフト）。レポートの IoC は原文の表記（as_reported）をそのまま残す
- 予報の入力層から分離した『報告専用』の文脈層。観測・ベースライン・base_rate・予報には入れない
  （forecast_input は false 固定）
- 個人情報は保存しない（RDAP は登録者の連絡先を保存せず、レジストラ名・日付・NS のみ）
- 国は近似である。共有基盤（CDN・大手クラウド）上の IP は同一基盤であることが同一運用者の根拠に
  ならない。いずれも注意書き（caveats）としてプロファイルに付く
- forecaster/knowledge/ は読み書きしない。書き込み先は当日のレポート JSON だけ

依存: 標準ライブラリのみ

使い方:
    python3 scripts/enrich_infrastructure.py --date 2026-11-06            # レポート JSON へ注入
    python3 scripts/enrich_infrastructure.py --date 2026-11-06 --print    # 注入せず標準出力へ
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import watchlist as wl  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(REPO_ROOT, "infra", "policy.json")
JST = timezone(timedelta(hours=9))
USER_AGENT = "pythia-infra-enrichment/1.0"
MAX_BODY_BYTES = 2_000_000

SOURCE_FAMILIES = ("ripestat", "internetdb", "rdap", "urlscan", "mnemonic")
# 照会 1 回ごとの識別子（ファミリ名.呼び出し名）→ ファミリ
LOOKUP_FAMILY = {
    "ripestat.prefix": "ripestat",
    "ripestat.geolocation": "ripestat",
    "internetdb": "internetdb",
    "rdap.domain": "rdap",
    "urlscan.search": "urlscan",
    "mnemonic.pdns": "mnemonic",
}
LOOKUP_STATUSES = ("ok", "no_data", "failed")
SKIP_REASONS = ("non_public", "legitimate_or_shared_platform", "over_budget", "no_enabled_source")
UNPARSED_REASONS = ("url_path_only", "not_a_domain", "unparseable")
CAVEAT_KEYS = ("geolocation_approximate", "shared_infrastructure_not_attribution", "source_vulns_unverified",
               "hostnames_source_asserted", "urlscan_30d_window", "passive_dns_partial", "some_sources_failed")
RUN_STATUSES = ("ok", "partial", "failed", "disabled", "no_indicators")
RESERVED_TLDS = {"test", "invalid", "example", "localhost", "local", "internal", "onion", "arpa"}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")


# --------------------------------------------------------------------------
# ポリシー
# --------------------------------------------------------------------------

def load_policy(path: str = POLICY_PATH) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# IoC の抽出と正規化
# --------------------------------------------------------------------------

_ANNOTATION_START = re.compile(r"[（(\s　、,;]")
_REFANG = (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":"), ("[://]", "://"), ("[@]", "@"))


def split_annotation(raw: str):
    """『98aiblog.com（SoftEther VPN）』→ ('98aiblog.com', 'SoftEther VPN')。"""
    text = raw.strip()
    m = _ANNOTATION_START.search(text)
    if not m:
        return text, None
    note = text[m.start():].strip().strip("（）() 　、,;")
    return text[:m.start()], (note or None)


def refang(text: str) -> str:
    out = text
    for old, new in _REFANG:
        out = out.replace(old, new)
    return re.sub(r"^hxxp", "http", out, flags=re.IGNORECASE)


def defang(value: str) -> str:
    return value.replace(".", "[.]")


def _suffix_match(domain: str, suffixes) -> bool:
    return any(domain == s or domain.endswith("." + s) for s in suffixes)


def classify_token(raw: str, policy: dict) -> dict:
    """1 つの IoC 文字列を分類する。

    戻り値:
      {"kind": "ip"|"domain", "value": str, "annotation": str|None, "via_url": bool,
       "skip_reason": None|"non_public"|"legitimate_or_shared_platform"}
      {"kind": "unparsed", "reason": "url_path_only"|"not_a_domain"|"unparseable", "annotation": ...}
    """
    token, annotation = split_annotation(raw)
    result_unparsed = {"kind": "unparsed", "annotation": annotation}
    if not token:
        return {**result_unparsed, "reason": "unparseable"}
    text = refang(token).strip()
    via_url = False
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", text):
        try:
            host = urllib.parse.urlsplit(text).hostname
        except ValueError:
            host = None
        if not host:
            return {**result_unparsed, "reason": "unparseable"}
        text, via_url = host, True
    elif text.startswith("/"):
        return {**result_unparsed, "reason": "url_path_only"}
    else:
        if text.count(":") == 1:
            text = re.sub(r":\d{1,5}$", "", text)
        text = re.sub(r"^\*\.", "", text)
        text = text.split("/", 1)[0]
    text = text.strip("[]").rstrip(".")
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        ip = None
    if ip is not None:
        reason = None if ip.is_global else "non_public"
        return {"kind": "ip", "value": str(ip), "annotation": annotation, "via_url": via_url, "skip_reason": reason}

    domain = text.lower()
    if any(ord(c) > 127 for c in domain):
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            return {**result_unparsed, "reason": "unparseable"}
    if not DOMAIN_RE.match(domain):
        return {**result_unparsed, "reason": "unparseable"}
    tld = domain.rsplit(".", 1)[1]
    if not re.search(r"[a-z]", tld):
        return {**result_unparsed, "reason": "unparseable"}
    if tld in set(policy.get("non_domain_extensions", [])):
        return {**result_unparsed, "reason": "not_a_domain"}
    skip = None
    if tld in RESERVED_TLDS:
        skip = "non_public"
    elif _suffix_match(domain, policy.get("legitimate_or_shared_platform_suffixes", [])):
        skip = "legitimate_or_shared_platform"
    return {"kind": "domain", "value": domain, "annotation": annotation, "via_url": via_url, "skip_reason": skip}


def _entry_ref(parent: dict) -> dict:
    ref = parent.get("cve_id") or parent.get("campaign_id") or parent.get("title") or parent.get("group_name")
    return {"ref": str(ref) if ref else None, "info_id": parent.get("info_id")}


def _find_ioc_containers(node, path, out) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if path == "" and key in ("infrastructure_context", "neighbor_context"):
                continue  # 本層が生成した／無関係の層は走査しない
            if key in ("ioc", "iocs") and isinstance(value, dict):
                out.append((path, node, value))
            else:
                _find_ioc_containers(value, f"{path}.{key}", out)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _find_ioc_containers(item, f"{path}[{i}]", out)


def extract_indicators(report: dict, policy: dict):
    """レポート JSON の ioc から (indicators, unparsed) を返す。同一指標は 1 件にまとめる。"""
    containers: list = []
    _find_ioc_containers(report, "", containers)
    merged: dict = {}
    unparsed: list = []
    for path, parent, ioc in containers:
        ref = {"path": path or ".", **_entry_ref(parent)}
        for field in ("ips", "domains", "urls"):
            values = ioc.get(field) or []
            if not isinstance(values, list):
                continue
            for raw in values:
                if not isinstance(raw, str) or not raw.strip():
                    continue
                c = classify_token(raw, policy)
                if c["kind"] == "unparsed":
                    unparsed.append({"as_reported": raw, "reason": c["reason"], "reported_in": [ref]})
                    continue
                key = (c["kind"], c["value"])
                item = merged.setdefault(key, {
                    "indicator": c["value"], "type": c["kind"], "as_reported": [], "annotations": [],
                    "reported_in": [], "skip_reason": c["skip_reason"]})
                if raw not in item["as_reported"]:
                    item["as_reported"].append(raw)
                if c["annotation"] and c["annotation"] not in item["annotations"]:
                    item["annotations"].append(c["annotation"])
                if ref not in item["reported_in"]:
                    item["reported_in"].append(ref)
    indicators = sorted(merged.values(), key=lambda i: (-len(i["reported_in"]), 0 if i["type"] == "ip" else 1,
                                                       i["indicator"]))
    return indicators, unparsed


# --------------------------------------------------------------------------
# HTTP（受動のみ・IoC 自体へは接続しない）
# --------------------------------------------------------------------------

class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, never_contact):
        self.never_contact = never_contact

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" or host in self.never_contact:
            raise urllib.error.URLError(f"redirect refused: {parts.scheme}://{host}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Fetcher:
    """urllib の薄いラッパ。間隔・再試行・サイズ上限・IoC への接続拒否を担う。"""

    def __init__(self, limits: dict, never_contact=(), sleep=time.sleep):
        self.timeout = limits.get("timeout_seconds", 25)
        self.retries = limits.get("retries", 1)
        self.wait = limits.get("retry_wait_seconds", 3)
        self.interval = limits.get("min_interval_seconds", 0.4)
        self.never_contact = {str(h).lower() for h in never_contact}
        self.sleep = sleep
        self._last = 0.0
        self.opener = urllib.request.build_opener(_GuardedRedirect(self.never_contact))

    def _throttle(self) -> None:
        gap = self.interval - (time.monotonic() - self._last)
        if gap > 0:
            self.sleep(gap)
        self._last = time.monotonic()

    def __call__(self, url: str) -> dict:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if host in self.never_contact:
            return {"http_status": None, "body": None, "error": "refused: target is a reported indicator"}
        attempts = 1 + max(0, self.retries)
        for i in range(attempts):
            self._throttle()
            request = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT, "Accept": "application/json, application/rdap+json"})
            try:
                with self.opener.open(request, timeout=self.timeout) as resp:
                    return {"http_status": resp.status, "body": resp.read(MAX_BODY_BYTES), "error": None}
            except urllib.error.HTTPError as err:
                body = err.read(MAX_BODY_BYTES)
                if err.code in (429, 500, 502, 503, 504) and i < attempts - 1:
                    self.sleep(self.wait)
                    continue
                return {"http_status": err.code, "body": body, "error": None if err.code == 404 else f"HTTP {err.code}"}
            except (urllib.error.URLError, OSError, TimeoutError) as err:
                if i < attempts - 1:
                    self.sleep(self.wait)
                    continue
                return {"http_status": None, "body": None, "error": f"{type(err).__name__}: {err}"[:200]}
        return {"http_status": None, "body": None, "error": "unreachable"}


# --------------------------------------------------------------------------
# 応答の抽出（純関数）。保存するのは必要な項目だけ（応答の全文は保存しない）
# --------------------------------------------------------------------------

def _iso_from_ms(value):
    if isinstance(value, (int, float)) and value > 0:
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def _cap(items, limit):
    return list(items)[:limit]


def extract_ripestat_prefix(doc, limit=10):
    data = (doc or {}).get("data") or {}
    if not data:
        return {}
    asns = []
    for a in data.get("asns") or []:
        if isinstance(a, dict) and str(a.get("asn", "")).isdigit():
            asns.append({"asn": int(a["asn"]), "holder": a.get("holder")})
    block = data.get("block") or {}
    return {"prefix": data.get("resource"), "announced": bool(data.get("announced")),
            "asns": _cap(asns, limit), "rir_block": block.get("desc")}


def extract_ripestat_geo(doc, limit=10):
    data = (doc or {}).get("data") or {}
    if not data:
        return {}
    countries = set()
    for res in data.get("located_resources") or []:
        for loc in (res or {}).get("locations") or []:
            c = (loc or {}).get("country")
            if isinstance(c, str) and re.fullmatch(r"[A-Za-z]{2}", c):
                countries.add(c.upper())
    return {"countries": _cap(sorted(countries), limit), "approximate": True}


def extract_internetdb(doc, limit=10):
    if not isinstance(doc, dict) or "ip" not in doc:
        return {}
    def strs(key):
        return sorted({s for s in (doc.get(key) or []) if isinstance(s, str) and s})
    ports = sorted({p for p in (doc.get("ports") or []) if isinstance(p, int) and not isinstance(p, bool)})
    return {"ports": ports[:50], "cpes": _cap(strs("cpes"), limit), "hostnames": _cap(strs("hostnames"), limit),
            "tags": _cap(strs("tags"), limit), "vulns": _cap(strs("vulns"), 30)}


def _vcard_fn(entity):
    vcard = (entity or {}).get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
        for row in vcard[1]:
            if isinstance(row, list) and len(row) >= 4 and row[0] == "fn" and isinstance(row[3], str):
                return row[3]
    return None


def extract_rdap_domain(doc, queried_name, limit=10):
    if not isinstance(doc, dict) or doc.get("objectClassName") != "domain":
        return {}
    events = {e.get("eventAction"): e.get("eventDate") for e in doc.get("events") or [] if isinstance(e, dict)}
    registrar = None
    for ent in doc.get("entities") or []:
        if isinstance(ent, dict) and "registrar" in (ent.get("roles") or []):
            registrar = _vcard_fn(ent)
            break
    ns = sorted({(n.get("ldhName") or "").lower() for n in doc.get("nameservers") or [] if isinstance(n, dict)} - {""})
    return {"queried_name": queried_name, "registered_at": events.get("registration"),
            "expires_at": events.get("expiration"), "last_changed": events.get("last changed"),
            "registrar": registrar, "nameservers": _cap(ns, limit),
            "status": sorted(s for s in doc.get("status") or [] if isinstance(s, str))}


def extract_urlscan(doc, domain, limit=10):
    if not isinstance(doc, dict) or not doc.get("total"):
        return {}
    observed: dict = {}
    matched = 0
    for r in doc.get("results") or []:
        page, task = (r or {}).get("page") or {}, (r or {}).get("task") or {}
        pd = str(page.get("domain") or "").lower()
        if not (pd == domain or pd.endswith("." + domain)):
            continue
        ip = page.get("ip")
        try:
            if not ipaddress.ip_address(ip).is_global:
                continue
        except ValueError:
            continue
        matched += 1
        asn_text = str(page.get("asn") or "")
        t = str(task.get("time") or "")
        e = observed.setdefault(ip, {"ip": ip, "asn": int(asn_text[2:]) if re.fullmatch(r"AS\d+", asn_text) else None,
                                     "asn_name": page.get("asnname"), "server": page.get("server"),
                                     "first_seen": t or None, "last_seen": t or None, "count": 0})
        e["count"] += 1
        if t and (not e["first_seen"] or t < e["first_seen"]):
            e["first_seen"] = t
        if t and (not e["last_seen"] or t > e["last_seen"]):
            e["last_seen"] = t
    ordered = sorted(observed.values(), key=lambda e: (-e["count"], e["ip"]))
    return {"window_days": doc.get("search_date_limit_days"), "total": doc.get("total"),
            "matched_results": matched, "observed": _cap(ordered, limit)}


def extract_mnemonic(doc, limit=10):
    if not isinstance(doc, dict) or not doc.get("data"):
        return {}
    records = []
    for r in doc["data"]:
        if not isinstance(r, dict):
            continue
        rrtype, answer = str(r.get("rrtype") or "").lower(), r.get("answer")
        if rrtype not in ("a", "aaaa", "cname", "ns") or not isinstance(answer, str):
            continue
        if rrtype in ("a", "aaaa"):
            try:
                answer = str(ipaddress.ip_address(answer))
            except ValueError:
                continue
        elif not DOMAIN_RE.match(answer.lower().rstrip(".")):
            continue
        records.append({"rrtype": rrtype, "answer": answer.lower().rstrip("."), "times": r.get("times"),
                        "last_updated": _iso_from_ms(r.get("lastUpdatedTimestamp"))})
    records.sort(key=lambda x: (x["last_updated"] or "", x["answer"]), reverse=True)
    # ホスティング先の一覧には公開アドレスだけを入れる。127.0.0.1 などへの解決履歴は事実として別に残す
    # （無害化された可能性を示すが、ここでは断定しない）
    answers = {x["answer"] for x in records if x["rrtype"] in ("a", "aaaa")}
    public = sorted(a for a in answers if ipaddress.ip_address(a).is_global)
    non_public = sorted(a for a in answers if not ipaddress.ip_address(a).is_global)
    return {"count": doc.get("count"), "records": _cap(records, limit), "resolved_ips": _cap(public, limit),
            "non_public_answers": _cap(non_public, limit)}


# --------------------------------------------------------------------------
# 照会の実行
# --------------------------------------------------------------------------

def run_lookup(fetch, source: str, url: str, parse, now=utc_now_iso) -> dict:
    """1 回の照会を実行して、取得時刻・状態・応答ハッシュ付きの記録にする。"""
    queried_at = now()
    res = fetch(url)
    body = res.get("body")
    record = {"source": source, "kind": "passive_database", "host": urllib.parse.urlsplit(url).hostname,
              "queried_at_utc": queried_at, "http_status": res.get("http_status"),
              "response_sha256": hashlib.sha256(body).hexdigest() if body is not None else None,
              "status": "failed", "extract": {}, "error": res.get("error")}
    status = res.get("http_status")
    if status == 404:
        record.update(status="no_data", error=None)
    elif status == 200 and body is not None:
        try:
            doc = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            record["error"] = "invalid JSON"
            return record
        extract = parse(doc)
        record.update(status="ok" if extract else "no_data", extract=extract, error=None)
    elif record["error"] is None:
        record["error"] = f"HTTP {status}"
    return record


def lookups_for_ip(ip: str, families, fetch, limit, now) -> list:
    out = []
    q = urllib.parse.quote(ip, safe="")
    if "ripestat" in families:
        out.append(run_lookup(fetch, "ripestat.prefix",
                              f"https://stat.ripe.net/data/prefix-overview/data.json?resource={q}",
                              lambda d: extract_ripestat_prefix(d, limit), now))
        out.append(run_lookup(fetch, "ripestat.geolocation",
                              f"https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource={q}",
                              lambda d: extract_ripestat_geo(d, limit), now))
    if "internetdb" in families:
        out.append(run_lookup(fetch, "internetdb", f"https://internetdb.shodan.io/{q}",
                              lambda d: extract_internetdb(d, limit), now))
    return out


def lookups_for_domain(domain: str, families, fetch, limit, now) -> list:
    out = []
    if "rdap" in families:
        labels = domain.split(".")
        # 登録ドメインを公開サフィックス表なしで推定する: 完全名 → 親の順に最大 3 回、2 ラベルまで
        candidates = [".".join(labels[i:]) for i in range(0, max(1, min(len(labels) - 1, 3)))]
        rec = None
        for name in candidates:
            rec = run_lookup(fetch, "rdap.domain", f"https://rdap.org/domain/{urllib.parse.quote(name, safe='')}",
                             lambda d, n=name: extract_rdap_domain(d, n, limit), now)
            if rec["status"] != "no_data":
                break
        out.append(rec)
    if "urlscan" in families:
        out.append(run_lookup(fetch, "urlscan.search",
                              "https://urlscan.io/api/v1/search/?q=" + urllib.parse.quote(f"domain:{domain}", safe="")
                              + "&size=100", lambda d: extract_urlscan(d, domain, limit), now))
    if "mnemonic" in families:
        out.append(run_lookup(fetch, "mnemonic.pdns",
                              f"https://api.mnemonic.no/pdns/v3/{urllib.parse.quote(domain, safe='')}?limit=100",
                              lambda d: extract_mnemonic(d, limit), now))
    return out


# --------------------------------------------------------------------------
# 要約・フラグ・注意書き（応答の extract から再計算できる純関数。検証器と共有する）
# --------------------------------------------------------------------------

def _parse_date(text):
    try:
        return datetime.strptime(str(text)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def build_summary(itype: str, lookups: list, policy: dict, report_date: str):
    """(summary, flags, caveats) を返す。入力は照会記録だけ（ほかの情報を足さない）。"""
    limits = policy.get("limits", {})
    cap = limits.get("max_list_items", 10)
    # 複製して作る: 要約が照会記録のリストと同じオブジェクトを共有すると、片方の書き換えが
    # もう一方に及び、検証器の再計算が改ざんを見逃す
    ok = {l["source"]: copy.deepcopy(l.get("extract") or {}) for l in lookups if l.get("status") == "ok"}
    summary: dict = {}
    if itype == "ip":
        pre, geo, db = ok.get("ripestat.prefix"), ok.get("ripestat.geolocation"), ok.get("internetdb")
        if pre:
            summary.update(prefix=pre.get("prefix"), announced=pre.get("announced"),
                           asns=pre.get("asns", []), rir_block=pre.get("rir_block"))
        if geo:
            summary["countries"] = geo.get("countries", [])
        if db:
            summary.update(ports=db.get("ports", []), cpes=db.get("cpes", []), hostnames=db.get("hostnames", []),
                           tags=db.get("tags", []), vulns=db.get("vulns", []))
    else:
        rd, us, pd = ok.get("rdap.domain"), ok.get("urlscan.search"), ok.get("mnemonic.pdns")
        if rd:
            summary.update(registrar=rd.get("registrar"), registered_at=rd.get("registered_at"),
                           expires_at=rd.get("expires_at"), nameservers=rd.get("nameservers", []),
                           rdap_status=rd.get("status", []), rdap_queried_name=rd.get("queried_name"))
        ips = {o["ip"] for o in (us or {}).get("observed", [])} | set((pd or {}).get("resolved_ips", []))
        if ips:
            summary["observed_ips"] = sorted(ips)[:cap]
        if us:
            asns = {(o["asn"], o.get("asn_name")) for o in us.get("observed", []) if o.get("asn") is not None}
            summary["observed_asns"] = [{"asn": a, "name": n} for a, n in sorted(asns, key=lambda x: (x[0], str(x[1])))][:cap]
            servers = sorted({o["server"] for o in us.get("observed", []) if o.get("server")})
            if servers:
                summary["servers"] = servers[:cap]
            summary["urlscan_total"] = us.get("total")
        if pd:
            summary["pdns_count"] = pd.get("count")
            if pd.get("non_public_answers"):
                summary["non_public_answers"] = pd["non_public_answers"]
    shared_map = policy.get("shared_infrastructure_asns", {})
    asn_nums = {a["asn"] for a in summary.get("asns", [])} | {a["asn"] for a in summary.get("observed_asns", [])}
    providers = sorted({shared_map[str(n)] for n in asn_nums if str(n) in shared_map})
    registered = _parse_date(summary.get("registered_at"))
    rep = _parse_date(report_date)
    newly = bool(registered and rep and 0 <= (rep - registered).days <= limits.get("newly_registered_days", 30))
    flags = {"shared_infrastructure": bool(providers), "shared_infrastructure_providers": providers,
             "newly_registered": newly, "has_source_vulns": bool(summary.get("vulns"))}
    caveats = []
    if summary.get("countries"):
        caveats.append("geolocation_approximate")
    if providers:
        caveats.append("shared_infrastructure_not_attribution")
    if summary.get("vulns"):
        caveats.append("source_vulns_unverified")
    if summary.get("hostnames"):
        caveats.append("hostnames_source_asserted")
    if "urlscan.search" in ok:
        caveats.append("urlscan_30d_window")
    if "mnemonic.pdns" in ok:
        caveats.append("passive_dns_partial")
    if any(l.get("status") == "failed" for l in lookups):
        caveats.append("some_sources_failed")
    return summary, flags, caveats


# --------------------------------------------------------------------------
# オーケストレーション
# --------------------------------------------------------------------------

def run_status(counts: dict, n_reported: int) -> str:
    """実行状態を照会の件数から導く（検証器も同じ規則で再計算する。disabled はここでは扱わない）。"""
    if n_reported == 0:
        return "no_indicators"
    if counts.get("failed") and not (counts.get("ok") or counts.get("no_data")):
        return "failed"
    if counts.get("failed"):
        return "partial"
    return "ok"


def enrich(report: dict, *, policy: dict, section: dict, fetch, report_date: str, now=utc_now_iso) -> dict:
    """レポート JSON から infrastructure_context を作る（ネットワークは fetch 経由のみ）。"""
    started = now()
    enabled = section.get("enabled", True) is not False
    families = [f for f in (section.get("sources") or list(SOURCE_FAMILIES)) if f in SOURCE_FAMILIES]
    max_indicators = section.get("max_indicators", 40)
    ctx = {"schema_version": "1.0", "forecast_input": False,
           "run": {"status": "disabled" if not enabled else "no_indicators", "started_at_utc": started,
                   "finished_at_utc": started, "sources_enabled": families if enabled else [],
                   "indicators": {"extracted": 0, "enriched": 0, "skipped": 0, "unparsed": 0},
                   "lookups": {"total": 0, "ok": 0, "no_data": 0, "failed": 0}, "by_source": {}},
           "profiles": [], "unparsed": []}
    if not enabled:
        return ctx
    indicators, unparsed = extract_indicators(report, policy)
    ctx["unparsed"] = unparsed
    cap = policy.get("limits", {}).get("max_list_items", 10)
    by_source: dict = {}
    budget = max_indicators
    for n, ind in enumerate(indicators, 1):
        profile = {"profile_id": f"inf-{report_date}-{n:03d}", "indicator": ind["indicator"], "type": ind["type"],
                   "defanged": defang(ind["indicator"]), "as_reported": ind["as_reported"],
                   "annotations": ind["annotations"], "reported_in": ind["reported_in"],
                   "skip_reason": ind["skip_reason"], "lookups": [], "summary": {}, "flags": {}, "caveats": [],
                   "forecast_input": False}
        applicable = [f for f in families if (f in ("ripestat", "internetdb")) == (ind["type"] == "ip")]
        if profile["skip_reason"] is None and not applicable:
            profile["skip_reason"] = "no_enabled_source"
        if profile["skip_reason"] is None:
            if budget <= 0:
                profile["skip_reason"] = "over_budget"
            else:
                budget -= 1
                fn = lookups_for_ip if ind["type"] == "ip" else lookups_for_domain
                profile["lookups"] = fn(ind["indicator"], applicable, fetch, cap, now)
        summary, flags, caveats = build_summary(ind["type"], profile["lookups"], policy, report_date)
        flags["legitimate_or_shared_platform"] = profile["skip_reason"] == "legitimate_or_shared_platform"
        profile.update(summary=summary, flags=flags, caveats=caveats)
        for rec in profile["lookups"]:
            stats = by_source.setdefault(rec["source"], {"ok": 0, "no_data": 0, "failed": 0, "last_error": None})
            stats[rec["status"]] += 1
            if rec["status"] == "failed":
                stats["last_error"] = rec.get("error")
        ctx["profiles"].append(profile)

    lookups_all = [rec for p in ctx["profiles"] for rec in p["lookups"]]
    counts = {s: sum(1 for r in lookups_all if r["status"] == s) for s in LOOKUP_STATUSES}
    enriched = sum(1 for p in ctx["profiles"] if any(r["status"] == "ok" for r in p["lookups"]))
    skipped = sum(1 for p in ctx["profiles"] if p["skip_reason"])
    ctx["run"].update(
        status=run_status(counts, len(indicators) + len(unparsed)), finished_at_utc=now(),
        by_source=dict(sorted(by_source.items())),
        indicators={"extracted": len(indicators), "enriched": enriched, "skipped": skipped,
                    "unparsed": len(unparsed)},
        lookups={"total": len(lookups_all), **counts})
    return ctx


def statistics_for(ctx: dict) -> dict:
    ind = ctx["run"]["indicators"]
    return {"profiles": len(ctx["profiles"]), "enriched": ind["enriched"], "skipped": ind["skipped"],
            "unparsed": ind["unparsed"]}


def inject(report: dict, ctx: dict) -> dict:
    report["infrastructure_context"] = ctx
    report.setdefault("statistics", {})["infrastructure_context"] = statistics_for(ctx)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="IoC を受動照会で補強して infrastructure_context を作る")
    parser.add_argument("--date", help="レポート日付 YYYY-MM-DD（既定: JST の本日）")
    parser.add_argument("--root", default=REPO_ROOT)
    parser.add_argument("--config", help="config.yml のパス（既定: <root>/config.yml）")
    parser.add_argument("--policy", help="infra/policy.json のパス")
    parser.add_argument("--print", dest="print_only", action="store_true", help="レポートへ注入せず標準出力へ出す")
    args = parser.parse_args()

    root = args.root
    day = args.date or datetime.now(JST).strftime("%Y-%m-%d")
    report_path = os.path.join(root, "outputs", day, f"{day}-security-report.json")
    if not os.path.isfile(report_path):
        print(f"レポート JSON が無い: {report_path}", file=sys.stderr)
        return 1
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
    policy = load_policy(args.policy or os.path.join(root, "infra", "policy.json"))
    config_path = args.config or os.path.join(root, "config.yml")
    section = (wl.load_config(config_path).get("infrastructure") or {}) if os.path.isfile(config_path) else {}

    indicators, _ = extract_indicators(report, policy)
    fetch = Fetcher(policy.get("limits", {}), never_contact={i["indicator"] for i in indicators})
    report_date = (report.get("meta") or {}).get("report_date") or day
    ctx = enrich(report, policy=policy, section=section, fetch=fetch, report_date=report_date)

    run = ctx["run"]
    print(f"[infra] status={run['status']} indicators={run['indicators']} lookups={run['lookups']}", file=sys.stderr)
    if args.print_only:
        print(json.dumps(ctx, ensure_ascii=False, indent=2))
        return 0
    inject(report, ctx)
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"注入: {report_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
