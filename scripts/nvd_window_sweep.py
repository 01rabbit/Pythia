#!/usr/bin/env python3
"""調査ウィンドウ内に公開・更新されたCVEを NVD / CISA KEV / EUVD から機械的に全件列挙する。

Step 1 の CVE 調査が、報道系ソース（RSS 収集記事）に載らない OSS / GitHub Advisory
由来のCVEを構造的に取りこぼす問題への対策。

**Pythia でこれが観測の取りこぼし以上の意味を持つ理由**:
Pythia の観測（forecaster/observations/）は日次レポート JSON から正規化して生成され、
そこからベースライン統計（technique-freq / group-activity）と予報の base_rate が算出される。
収集が特定の情報源クラス（報道系）に偏ると、観測母集団そのものが偏り、
**ベースラインと base_rate が系統的に歪む**。予報の確度は歪んだ分布の上に乗るため、
検証ループでは「予報ロジックの誤り」と「観測母集団の欠損」を区別できない。
さらに E1（CISA KEV 初回追加）は Pythia の主要な観測出口チャネルであり、
窓内 KEV 追加の全件把握は的中判定の前提条件である。

姉妹リポジトリ（security-intel / fdns-intel）では 2026-08-04〜07 の窓で
Misskey / OpenEMR / osTicket / kotaemon / Flowise / Grav CMS / Apache Airflow の計9件
（CVSS 9.0以上が5件、公開PoCありを含む）が**レポート本体にも除外サマリーにも
一切現れない**という取りこぼしが実測された。いずれも GHSA / VulnCheck / MITRE 起点で
BleepingComputer / The Hacker News / SecurityWeek には載らないため、
調査ソースに「GitHub Advisory Database」と名前を書くだけでは構造的に拾えない。

このスクリプトは「窓内に公開されたCVEの母集団」を確定させる。パイプライン側は
この母集団の各件を **採用 / 除外（理由付き）/ バッチ集約のいずれかに必ず割り当てる**
（pipeline-1-cve.md「網羅スイープ」節・SKILL.md Step 0.7 / Step 3.9 参照）。

**EUVD 補完列挙（フェイルソフト）**:
ENISA の EU Vulnerability Database（EUVD・NIS2指令に基づき運営）を補完ソースとして列挙する。
EUVD は MITRE CVE / NVD / GHSA / 各国CSIRT を集約しており、NVD の分析遅延・障害時にも
CNA 提供スコア付きでレコードを提供する（NVD 未反映のCVEを EUVD が先に載せる事例を実測済み）。
役割は以下に限定する:

1. NVD 母集団の**冗長化**: 窓内公開の閾値以上を EUVD 側でも列挙し、NVD 側に無いものだけを
   `euvd_added` 候補として母集団へ追加する（NVD と重複するものは候補に重複計上しない）
2. **CVE未採番レコードの捕捉**: CVE エイリアスを持たない EUVD-only レコードを候補化する
3. **exploited フラグの突合**: EUVD の exploited 印は大半が CISA KEV 由来の集約であり
   **独立した悪用観測シグナルとして扱わない**。KEV 窓内追加に無い exploited のみ候補化する

EUVD の取得失敗は NVD+KEV スイープを止めない（`euvd.status: failed` を記録して続行する）。
NVD / KEV は従来どおり必須（取得失敗はスイープ全体の失敗）。

★このスクリプトは forecaster/knowledge/ を一切書き換えない（CLAUDE.md 行動原則5）。
出力は .cache/ 配下のスイープ結果 JSON と標準出力のみである。

使い方:

    # 窓内の CVSS 9.0以上 + KEV 窓内追加 + EUVD 補完を全件列挙（JSON保存）
    python3 scripts/nvd_window_sweep.py \
        --window-start "2026-08-17 07:00" --window-end "2026-08-18 07:00" \
        --output ".cache/daily-security-intel/2026-08-18/step1-sweep.json"

    # Step 1 サブエージェント指示文に貼る Markdown 表
    python3 scripts/nvd_window_sweep.py \
        --window-start "2026-08-17 07:00" --window-end "2026-08-18 07:00" \
        --format markdown

    # 生成済みレポートとの突合（未処理CVEの検出。未処理があれば終了コード1）
    python3 scripts/nvd_window_sweep.py \
        --from-json ".cache/daily-security-intel/2026-08-18/step1-sweep.json" \
        --reconcile "outputs/2026-08-18/2026-08-18-security-report.json"

環境変数:
    NVD_API_KEY    設定するとレート制限が 5req/30s → 50req/30s に緩和される（任意）

依存: 標準ライブラリのみ
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

JST = timezone(timedelta(hours=9))

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EUVD_API = "https://euvdservices.enisa.europa.eu/api"

GHSA_SOURCE_ID = "security-advisories@github.com"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
EUVD_RE = re.compile(r"EUVD-\d{4}-\d{1,7}")

# CVSS v2 は閾値判定に使わない。v2 の 10.0 は v3.1/v4.0 の Critical と等価ではなく、
# v2 しか付いていない古いCNAのCVEを大量に拾ってノイズになる（2026-08-04 窓の
# GL.iNet 系11件が該当）。閾値判定は v3.1 / v4.0 のいずれか高い方で行う。
THRESHOLD_METRICS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30")


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def _http_json(url: str, *, attempts: int = 5, timeout: int = 90) -> dict:
    """NVD / CISA を叩く。レート制限・一時障害は指数バックオフで再試行する。"""
    headers = {"User-Agent": "pythia-daily-security-intel/nvd_window_sweep"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key and url.startswith(NVD_API):
        headers["apiKey"] = api_key

    delay = 3.0
    last_err: Exception | None = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except Exception as err:  # noqa: BLE001 — HTTPError/URLError/JSONDecodeError を一括で再試行
            last_err = err
            if i < attempts - 1:
                print(f"  retry {i + 1}/{attempts - 1} ({err}) — {delay:.0f}s 待機", file=sys.stderr)
                time.sleep(delay)
                delay *= 2
    raise SystemExit(f"取得失敗: {url}\n  {last_err}")


# --------------------------------------------------------------------------
# NVD
# --------------------------------------------------------------------------

def _nvd_page(params: dict, start_index: int) -> dict:
    query = dict(params, resultsPerPage=2000, startIndex=start_index)
    return _http_json(f"{NVD_API}?{urllib.parse.urlencode(query)}")


def fetch_nvd(params: dict) -> list[dict]:
    """1クエリぶんの vulnerabilities を全ページ取得する。

    重要: cvssV3Severity / cvssV4Severity などの severity フィルタは **使わない**。
    公開直後（vulnStatus=Received）のCVEには NVD 一次評価が未付与で、severity
    フィルタが CNA 提供スコアと噛み合わず取りこぼす。2026-08-04 窓の実測では
    `cvssV3Severity=CRITICAL` が2件しか返さず（うち1件は実スコア7.4）、
    osTicket 9.8 / kotaemon 9.8 / OpenEMR 9.4 / Misskey 9.2 がすべて欠落した。
    フィルタなしで全件取得し、閾値判定はクライアント側で行う。
    """
    out: list[dict] = []
    start_index = 0
    while True:
        page = _nvd_page(params, start_index)
        out.extend(page.get("vulnerabilities", []))
        total = page.get("totalResults", 0)
        per_page = page.get("resultsPerPage", 0)
        start_index += per_page
        if per_page == 0 or start_index >= total:
            return out
        time.sleep(1.0 if os.environ.get("NVD_API_KEY") else 6.5)


def max_score(cve: dict) -> tuple[float | None, str | None, str | None]:
    """v3.1 / v4.0 / v3.0 のうち最大の baseScore を返す。→ (score, metric, vector)"""
    best: tuple[float | None, str | None, str | None] = (None, None, None)
    for metric in THRESHOLD_METRICS:
        for entry in cve.get("metrics", {}).get(metric, []):
            data = entry.get("cvssData", {})
            score = data.get("baseScore")
            if score is not None and (best[0] is None or score > best[0]):
                best = (float(score), metric, data.get("vectorString"))
    return best


def description(cve: dict) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return " ".join(desc.get("value", "").split())
    return ""


def summarize(cve: dict, kev: dict) -> dict:
    score, metric, vector = max_score(cve)
    cve_id = cve["id"]
    kev_entry = kev.get(cve_id)
    return {
        "cve_id": cve_id,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "cvss_max": score,
        "cvss_metric": metric,
        "cvss_vector": vector,
        "source_identifier": cve.get("sourceIdentifier"),
        "ghsa_origin": cve.get("sourceIdentifier") == GHSA_SOURCE_ID,
        "in_kev": kev_entry is not None,
        "kev_date_added": kev_entry.get("dateAdded") if kev_entry else None,
        "kev_due_date": kev_entry.get("dueDate") if kev_entry else None,
        "description": description(cve)[:400],
    }


# --------------------------------------------------------------------------
# KEV
# --------------------------------------------------------------------------

def fetch_kev() -> tuple[dict, str | None]:
    data = _http_json(KEV_JSON)
    catalog = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    return catalog, data.get("catalogVersion")


# --------------------------------------------------------------------------
# EUVD（ENISA EU Vulnerability Database）— 補完列挙・フェイルソフト
# --------------------------------------------------------------------------

class EuvdError(RuntimeError):
    """EUVD 取得失敗。NVD+KEV スイープは止めず euvd.status=failed として続行する。"""


def _euvd_json(path: str, params: dict | None = None, *, attempts: int = 4) -> dict | list:
    """EUVD API を叩く。連続アクセスで 403 を返すことが実測されているため、
    リクエスト間に必ず間隔を置き、403/429 も含めて指数バックオフで再試行する。
    失敗しても SystemExit にせず EuvdError を投げる（フェイルソフト）。
    """
    url = f"{EUVD_API}/{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "pythia-daily-security-intel/nvd_window_sweep"}
    delay = 5.0
    last_err: Exception | None = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.load(resp)
            time.sleep(2.0)  # 次リクエストとの間隔（403対策）
            return data
        except Exception as err:  # noqa: BLE001
            last_err = err
            if i < attempts - 1:
                print(f"  EUVD retry {i + 1}/{attempts - 1} ({err}) — {delay:.0f}s 待機",
                      file=sys.stderr)
                time.sleep(delay)
                delay *= 2
    raise EuvdError(f"EUVD 取得失敗: {url} — {last_err}")


def _parse_euvd_dt(text: str | None) -> datetime | None:
    """EUVD の日時（例: "Aug 19, 2026, 4:55:14 PM"）を UTC として解釈する。

    NVD 公開時刻との突合（CVE-2026-72529: EUVD 16:55 → NVD 17:21 UTC）から
    UTC 表記と判断している。API はタイムゾーンを明示しないため、窓の境界判定が
    数時間ずれる可能性は候補の過剰包含側に倒して吸収する（取りこぼし側に倒さない）。
    """
    if not text:
        return None
    normalized = text.replace("\u202f", " ").replace("\u00a0", " ").strip()  # 特殊空白を正規化
    for fmt in ("%b %d, %Y, %I:%M:%S %p", "%b %d, %Y %I:%M:%S %p"):
        try:
            return datetime.strptime(normalized, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _euvd_search_all(params: dict, *, max_pages: int = 20) -> list[dict]:
    """/api/search を page/size でページングし全件取得する（size 上限 100）。"""
    out: list[dict] = []
    page = 0
    while page < max_pages:
        data = _euvd_json("search", dict(params, size=100, page=page))
        items = data.get("items", []) if isinstance(data, dict) else []
        out.extend(items)
        total = data.get("total", 0) if isinstance(data, dict) else 0
        page += 1
        if not items or len(out) >= total:
            break
    return out


def _euvd_row(item: dict, reason: str) -> dict:
    aliases = [a.strip() for a in (item.get("aliases") or "").split() if a.strip()]
    cves = [a for a in aliases if CVE_RE.fullmatch(a)]
    pub = _parse_euvd_dt(item.get("datePublished"))
    exploited_since = _parse_euvd_dt(item.get("exploitedSince"))
    return {
        "euvd_id": item.get("id"),
        "cve_id": cves[0] if cves else None,
        "aliases": aliases,
        "cvss_max": item.get("baseScore"),
        "cvss_metric": f"euvd:v{item.get('baseScoreVersion')}" if item.get("baseScoreVersion") else None,
        "cvss_vector": item.get("baseScoreVector"),
        "epss": item.get("epss"),
        "assigner": item.get("assigner"),
        "published": pub.isoformat() if pub else item.get("datePublished"),
        "exploited_since": exploited_since.isoformat() if exploited_since else None,
        "sweep_reason": reason,
        "description": " ".join((item.get("description") or "").split())[:400],
    }


def euvd_sweep(window_start: datetime, window_end: datetime, threshold: float,
               nvd_published_ids: set[str], kev: dict) -> tuple[dict, list[dict], dict]:
    """EUVD を補完列挙する。→ (euvd_meta, euvd_added候補, cve→euvd_id 対応表)

    - 窓内公開かつ閾値以上（fromScore）→ NVD 窓内母集団に無いものだけ候補化
    - exploited（窓内公開分 + 最新 exploited フィードの窓内 exploitedSince 分）
      → CISA KEV 掲載済みCVEは候補化しない（EUVD exploited は大半が KEV 由来の集約）
    - CVE エイリアスを持たないレコードは EUVD ID を識別子として候補化する
    """
    utc_start = window_start.astimezone(timezone.utc)
    utc_end = window_end.astimezone(timezone.utc)
    # fromDate/toDate は日付粒度のため前後1日広げて取得し、時刻判定はクライアント側で行う
    date_params = {
        "fromDate": (utc_start - timedelta(days=1)).strftime("%Y-%m-%d"),
        "toDate": (utc_end + timedelta(days=1)).strftime("%Y-%m-%d"),
    }

    print("EUVD: 窓内公開（閾値以上）を取得中…", file=sys.stderr)
    over_items = _euvd_search_all(dict(date_params, fromScore=threshold, toScore=10))
    print(f"  閾値以上 {len(over_items)}件（日付粒度・窓判定前）", file=sys.stderr)

    print("EUVD: exploited を取得中…", file=sys.stderr)
    exploited_items = _euvd_search_all(dict(date_params, exploited="true"))
    latest_exploited = _euvd_json("exploitedvulnerabilities")
    if not isinstance(latest_exploited, list):
        latest_exploited = []
    print(f"  exploited 窓内公開 {len(exploited_items)}件 / 最新フィード {len(latest_exploited)}件",
          file=sys.stderr)

    def in_window(item: dict) -> bool:
        pub = _parse_euvd_dt(item.get("datePublished"))
        return pub is not None and window_start <= pub < window_end

    start_date, end_date = window_start.date(), window_end.date()

    def exploited_in_window(item: dict) -> bool:
        # exploitedSince は日付粒度（12:00 AM 固定）のため KEV dateAdded と同様に日付で判定する
        since = _parse_euvd_dt(item.get("exploitedSince"))
        return since is not None and start_date <= since.date() <= end_date

    alias_map: dict[str, str] = {}
    candidates: dict[str, dict] = {}
    over_in_window = 0
    exploited_seen = 0

    def consider(item: dict, reason: str) -> None:
        row = _euvd_row(item, reason)
        if not row["euvd_id"]:
            return
        for cve in row["aliases"]:
            if CVE_RE.fullmatch(cve):
                alias_map[cve] = row["euvd_id"]
        if reason == "euvd_exploited_in_window":
            # KEV 掲載済み（窓内外を問わず）は KEV 側で扱う。独立シグナル扱いしない
            if row["cve_id"] and row["cve_id"] in kev:
                return
        else:
            # NVD 窓内母集団と重複するCVEは候補に重複計上しない（冗長化のみが目的）
            if row["cve_id"] and row["cve_id"] in nvd_published_ids:
                return
        existing = candidates.get(row["euvd_id"])
        if existing is None or reason == "euvd_exploited_in_window":
            row["sweep_reason"] = reason if existing is None else "euvd_exploited_in_window"
            candidates[row["euvd_id"]] = row

    for item in over_items:
        if in_window(item):
            over_in_window += 1
            consider(item, "euvd_published_over_threshold")
    for item in exploited_items:
        if in_window(item):
            exploited_seen += 1
            consider(item, "euvd_exploited_in_window")
    for item in latest_exploited:
        if exploited_in_window(item):
            exploited_seen += 1
            consider(item, "euvd_exploited_in_window")

    added = sorted(candidates.values(),
                   key=lambda r: (-(r["cvss_max"] or 0), r["cve_id"] or r["euvd_id"]))
    meta = {
        "status": "ok",
        "api": EUVD_API,
        "counts": {
            "over_threshold_in_window": over_in_window,
            "exploited_seen_in_window": exploited_seen,
            "added_candidates": len(added),
        },
        "note": "時刻はUTCとして解釈。exploited は大半が CISA KEV 由来の集約であり"
                "独立した悪用観測シグナルとして扱わない（E1 の正は CISA KEV）",
    }
    return meta, added, alias_map


# --------------------------------------------------------------------------
# スイープ本体
# --------------------------------------------------------------------------

def parse_jst(text: str) -> datetime:
    text = text.strip().replace("/", "-")
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=JST)
        except ValueError:
            continue
    raise SystemExit(f'日時の書式が不正: "{text}"（例: "2026-08-04 07:00"）')


def to_nvd_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def sweep(window_start: datetime, window_end: datetime, threshold: float,
          include_modified: bool = False, no_euvd: bool = False) -> dict:
    if window_end <= window_start:
        raise SystemExit("--window-end は --window-start より後である必要がある")

    utc_start, utc_end = to_nvd_utc(window_start), to_nvd_utc(window_end)
    print(f"調査窓(JST): {window_start:%Y-%m-%d %H:%M} 〜 {window_end:%Y-%m-%d %H:%M}", file=sys.stderr)
    print(f"NVDクエリ(UTC): {utc_start} 〜 {utc_end}", file=sys.stderr)

    kev, kev_version = fetch_kev()
    print(f"KEVカタログ: {kev_version}（{len(kev)}件）", file=sys.stderr)

    print("NVD: 窓内の新規公開を取得中…", file=sys.stderr)
    published = fetch_nvd({"pubStartDate": utc_start, "pubEndDate": utc_end})
    print(f"  新規公開 {len(published)}件", file=sys.stderr)

    # 既定では取得しない。NVD は古いCVEのCPE付与・参照タグ整理で日常的に
    # 数千件を lastModified 更新するため、このトラックはノイズが支配的になる。
    # 2026-08-05 窓の実測で 2,507件（うち Linux kernel の一括再更新216件、
    # 2024年以前のKEV既報CVEが多数）が返り、突合結果が実用にならなかった。
    # 状態変化のうち実務上重要な「KEV新規追加」は kev_added_in_window で
    # 別途拾えているので、既定は新規公開＋KEV追加に絞る。
    modified: list[dict] = []
    if include_modified:
        print("NVD: 窓内の更新（状態変化）を取得中…（ノイズ多。監査用）", file=sys.stderr)
        modified = fetch_nvd({"lastModStartDate": utc_start, "lastModEndDate": utc_end})
        print(f"  更新 {len(modified)}件", file=sys.stderr)

    published_ids = {v["cve"]["id"] for v in published}

    over: list[dict] = []
    for item in published:
        row = summarize(item["cve"], kev)
        if row["cvss_max"] is not None and row["cvss_max"] >= threshold:
            row["sweep_reason"] = "published_in_window"
            over.append(row)

    # 窓内に更新されたCVE。窓内公開ぶんは上で拾っているので除外し、
    # 「既存CVEの状態変化」（再スコアリング・参照追加・KEV追加）だけを残す。
    changed: list[dict] = []
    for item in modified:
        cve = item["cve"]
        if cve["id"] in published_ids:
            continue
        row = summarize(cve, kev)
        if row["cvss_max"] is not None and row["cvss_max"] >= threshold:
            row["sweep_reason"] = "modified_in_window"
            changed.append(row)

    # KEV 新規追加は CVSS 閾値に関係なく必ず採用条件D。窓の日付で拾う。
    kev_in_window: list[dict] = []
    start_date, end_date = window_start.date(), window_end.date()
    for cve_id, entry in kev.items():
        try:
            added = datetime.strptime(entry["dateAdded"], "%Y-%m-%d").date()
        except (KeyError, ValueError):
            continue
        if start_date <= added <= end_date:
            kev_in_window.append({
                "cve_id": cve_id,
                "kev_date_added": entry["dateAdded"],
                "kev_due_date": entry.get("dueDate"),
                "vendor_project": entry.get("vendorProject"),
                "product": entry.get("product"),
                "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
                "sweep_reason": "kev_added_in_window",
            })

    over.sort(key=lambda r: (-(r["cvss_max"] or 0), r["cve_id"]))
    changed.sort(key=lambda r: (-(r["cvss_max"] or 0), r["cve_id"]))
    kev_in_window.sort(key=lambda r: r["cve_id"])

    # EUVD 補完列挙（フェイルソフト: 失敗しても NVD+KEV の結果で続行する）
    euvd_meta: dict = {"status": "skipped", "api": EUVD_API}
    euvd_added: list[dict] = []
    if not no_euvd:
        try:
            euvd_meta, euvd_added, alias_map = euvd_sweep(
                window_start, window_end, threshold, published_ids, kev)
            for row in over + changed + kev_in_window:
                if row["cve_id"] in alias_map:
                    row["euvd_id"] = alias_map[row["cve_id"]]
            print(f"EUVD: 追加候補 {len(euvd_added)}件", file=sys.stderr)
        except EuvdError as err:
            print(f"EUVD: 取得失敗 — NVD+KEV のみで続行する（{err}）", file=sys.stderr)
            euvd_meta = {"status": "failed", "api": EUVD_API, "error": str(err)}

    return {
        "generated_at": datetime.now(JST).isoformat(timespec="seconds"),
        "window": {
            "from": window_start.isoformat(),
            "to": window_end.isoformat(),
            "nvd_utc_from": utc_start,
            "nvd_utc_to": utc_end,
        },
        "threshold": threshold,
        "threshold_note": "CVSS v3.1 / v4.0 / v3.0 のうち最大値で判定。v2 は判定に使わない",
        "include_modified": include_modified,
        "kev_catalog_version": kev_version,
        "counts": {
            "nvd_published_total": len(published),
            "nvd_modified_total": len(modified),
            "over_threshold_published": len(over),
            "over_threshold_modified": len(changed),
            "ghsa_origin_over_threshold": sum(1 for r in over + changed if r["ghsa_origin"]),
            "kev_added_in_window": len(kev_in_window),
            "euvd_added_candidates": len(euvd_added),
        },
        "over_threshold_published": over,
        "over_threshold_modified": changed,
        "kev_added_in_window": kev_in_window,
        "euvd": euvd_meta,
        "euvd_added": euvd_added,
    }


# --------------------------------------------------------------------------
# 突合（reconcile）
# --------------------------------------------------------------------------

def ids_in_report(path: str) -> tuple[set[str], set[str]]:
    """レポートJSON全体に出現する CVE ID / EUVD ID を集める（採用・除外サマリー双方を含む）。

    採用セクション名・除外セクション名はリポジトリごとにスキーマが異なるため、
    構造を仮定せずファイル全体を走査する。「レポートに一度も現れないID」＝未処理。
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    return set(CVE_RE.findall(text)), set(EUVD_RE.findall(text))


BATCH_MIN = 5  # 同一CNAがこの件数以上を同一窓で一括公開したら「バッチ」として集約可

# 複数ベンダーのCVEを横断的に採番するアグリゲータCNA。
# これらは「同一ベンダーの同一リリース」ではないため、件数が多くても
# 絶対にバッチ集約してはならない。
#
# ここを間違えると、まさに取りこぼしたCVEが集約で消える。2026-08-05 窓では
# GHSA が12件を採番しており、その中に Misskey / kotaemon / Flowise / OpenSIPS /
# Sequelize という無関係な製品が同居していた。GHSA を単一ベンダー扱いして
# 集約すると、代表1件（OpenSIPS）だけが残り残り11件が記録から消える。
AGGREGATOR_CNAS = {
    "security-advisories@github.com",  # GitHub Advisory Database（OSS全般）
    "cve@mitre.org",                   # MITRE 直接採番
    "cna@vuldb.com",                   # VulDB
    "disclosure@vulncheck.com",        # VulnCheck
    "cret@cert.org",                   # CERT/CC
    "support@hackerone.com",           # HackerOne 経由の各社
    "contact@wpscan.com",              # WordPress プラグイン（作者は別々）
    "iletisim@usom.gov.tr",            # USOM（トルコ・複数ベンダー）
    "patrick@puiterwijk.org",          # Fedora/OSS 汎用
}


def reconcile(sweep_data: dict, report_path: str) -> dict:
    """スイープ母集団のうち、レポートに一度も現れないCVEを列挙する。

    未処理は sourceIdentifier ごとにまとめる。Chrome / Oracle CPU / Adobe 等の
    ベンダーPSIRTは同一窓で数十件を一括公開するため、1件ずつ除外理由を書かせると
    除外サマリーが実質的に読めなくなる。単一ベンダーPSIRTが BATCH_MIN 件以上を
    公開したかたまりは「代表1件＋件数」で1エントリに集約してよい。

    AGGREGATOR_CNAS（GHSA / MITRE / VulDB 等の複数ベンダー横断CNA）は件数に
    関わらず集約せず、必ず個別判断に回す。EUVD 由来の候補（euvd_added）も
    集約対象外＝必ず個別判断に回す（CVE未採番レコードは EUVD ID で突合する）。
    """
    handled_cves, handled_euvd = ids_in_report(report_path)
    rows = (
        sweep_data.get("over_threshold_published", [])
        + sweep_data.get("kev_added_in_window", [])
        + sweep_data.get("euvd_added", [])
    )
    if sweep_data.get("include_modified"):
        rows += sweep_data.get("over_threshold_modified", [])

    def row_id(row: dict) -> str:
        return row.get("cve_id") or row.get("euvd_id") or "(不明ID)"

    def is_handled(row: dict) -> bool:
        return (row.get("cve_id") in handled_cves) or (row.get("euvd_id") in handled_euvd)

    seen: set[str] = set()
    unhandled: list[dict] = []
    handled_count = 0
    all_ids: set[str] = set()
    for row in rows:
        rid = row_id(row)
        all_ids.add(rid)
        if rid in seen:
            continue
        seen.add(rid)
        if is_handled(row):
            handled_count += 1
            continue
        unhandled.append(row)
    unhandled.sort(key=lambda r: (-(r.get("cvss_max") or 0), row_id(r)))

    groups: dict[str, list[dict]] = {}
    for row in unhandled:
        if row.get("euvd_id") and not row.get("source_identifier"):
            continue  # EUVD 由来候補はバッチ集約対象外（下の individual に必ず残る）
        groups.setdefault(row.get("source_identifier") or "(不明)", []).append(row)

    batches = [
        {
            "source_identifier": src,
            "count": len(members),
            "representative": members[0]["cve_id"],
            "cvss_max": members[0].get("cvss_max"),
            "cve_ids": [m["cve_id"] for m in members],
            "description": members[0].get("description", "")[:200],
        }
        for src, members in sorted(groups.items(), key=lambda kv: -len(kv[1]))
        if len(members) >= BATCH_MIN and src not in AGGREGATOR_CNAS
    ]
    batch_ids = {cve_id for b in batches for cve_id in b["cve_ids"]}
    individual = [r for r in unhandled if row_id(r) not in batch_ids]

    return {
        "report": report_path,
        "sweep_candidates": len(all_ids),
        "handled_in_report": handled_count,
        "unhandled": unhandled,
        "unhandled_batches": batches,
        "unhandled_individual": individual,
    }


# --------------------------------------------------------------------------
# 出力
# --------------------------------------------------------------------------

def _euvd_status_line(data: dict) -> str:
    euvd = data.get("euvd") or {}
    status = euvd.get("status", "なし（旧形式スイープ）")
    if status == "ok":
        c = euvd.get("counts", {})
        return (f"実行済み（追加候補 **{c.get('added_candidates', 0)}件** / "
                f"窓内閾値以上 {c.get('over_threshold_in_window', 0)}件 / "
                f"exploited {c.get('exploited_seen_in_window', 0)}件）")
    if status == "failed":
        return f"**取得失敗**（NVD+KEV のみで列挙。error: {euvd.get('error', '不明')}）"
    return status


def render_markdown(data: dict) -> str:
    win, counts = data["window"], data["counts"]
    lines = [
        f"### Step 1 網羅スイープ（{win['from']} 〜 {win['to']}）",
        "",
        f"- NVD 窓内新規公開: **{counts['nvd_published_total']}件**",
        f"- CVSS {data['threshold']} 以上（新規公開）: **{counts['over_threshold_published']}件**",
        f"- うち GitHub Advisory (GHSA) 起点: **{counts['ghsa_origin_over_threshold']}件**",
        f"- CISA KEV 窓内新規追加: **{counts['kev_added_in_window']}件**",
        f"- KEVカタログ版: {data['kev_catalog_version']}",
        f"- EUVD 補完: {_euvd_status_line(data)}",
        "",
        "**この一覧の各CVEは、採用または除外サマリー（理由付き）のいずれかに必ず割り当てること。**",
        "同一CNAが同一窓で5件以上を一括公開したものは、代表1件＋件数で1エントリに集約してよい。",
        "",
    ]

    def table(title: str, rows: list[dict]) -> None:
        if not rows:
            lines.extend([f"#### {title}", "", "（該当なし）", ""])
            return
        lines.extend([
            f"#### {title}（{len(rows)}件）", "",
            "| CVE | CVSS | 版 | KEV | GHSA | 概要 |",
            "|---|---|---|---|---|---|",
        ])
        for r in rows:
            metric = (r.get("cvss_metric") or "").replace("cvssMetric", "")
            kev = f"○ {r['kev_date_added']}" if r.get("in_kev") else "—"
            desc = r.get("description", "")[:100].replace("|", "\\|")
            lines.append(
                f"| {r['cve_id']} | {r.get('cvss_max')} | {metric} | {kev} |"
                f" {'○' if r.get('ghsa_origin') else '—'} | {desc} |"
            )
        lines.append("")

    table("窓内新規公開（閾値以上）", data.get("over_threshold_published", []))
    if data.get("include_modified"):
        lines.extend([
            f"> 窓内更新（既存CVE）総数: {counts['nvd_modified_total']}件。"
            "NVDの定常再更新を多く含むため、以下は参考情報。", "",
        ])
        table("窓内の状態変化（既存CVE・閾値以上）", data.get("over_threshold_modified", []))

    kev_rows = data.get("kev_added_in_window", [])
    lines.extend([f"#### CISA KEV 窓内新規追加（{len(kev_rows)}件）", ""])
    if kev_rows:
        lines.extend(["| CVE | 追加日 | 期限 | ベンダー | 製品 | ランサム利用 |", "|---|---|---|---|---|---|"])
        for r in kev_rows:
            lines.append(
                f"| {r['cve_id']} | {r['kev_date_added']} | {r.get('kev_due_date') or '—'} |"
                f" {r.get('vendor_project') or '—'} | {r.get('product') or '—'} |"
                f" {r.get('known_ransomware_use') or '—'} |"
            )
    else:
        lines.append("（該当なし）")
    lines.append("")

    euvd_rows = data.get("euvd_added", [])
    if (data.get("euvd") or {}).get("status") in ("ok", "failed") or euvd_rows:
        lines.extend([f"#### EUVD 補完候補（{len(euvd_rows)}件・NVD/KEV に無いもののみ）", ""])
        if euvd_rows:
            lines.extend([
                "NVD 母集団に無い、または CVE 未採番の EUVD レコード。"
                "他候補と同様に**採用または除外サマリー（理由付き）へ必ず割り当てること**"
                "（CVE 未採番のものは EUVD ID で記録して突合する）。",
                "",
                "| ID | CVE | CVSS | 理由 | CNA | 概要 |",
                "|---|---|---|---|---|---|",
            ])
            for r in euvd_rows:
                desc = (r.get("description") or "")[:100].replace("|", "\\|")
                lines.append(
                    f"| {r.get('euvd_id')} | {r.get('cve_id') or '—'} | {r.get('cvss_max') or '—'} |"
                    f" {r.get('sweep_reason')} | {r.get('assigner') or '—'} | {desc} |"
                )
        else:
            lines.append("（該当なし）")
        lines.append("")
    return "\n".join(lines)


def render_reconcile(result: dict) -> str:
    lines = [
        "### 網羅スイープ突合結果",
        "",
        f"- 対象レポート: `{result['report']}`",
        f"- スイープ候補: {result['sweep_candidates']}件"
        f" / レポートに出現（採用または除外記録済み）: {result['handled_in_report']}件",
        f"- **未処理: {len(result['unhandled'])}件**",
        "",
    ]
    if not result["unhandled"]:
        lines.append("未処理なし。スイープ候補はすべて採用または除外サマリーに反映済み。")
        return "\n".join(lines)

    batches = result.get("unhandled_batches", [])
    individual = result.get("unhandled_individual", result["unhandled"])

    if batches:
        lines.extend([
            f"#### 一括公開バッチ（{len(batches)}グループ）",
            "",
            f"単一ベンダーPSIRTが同一窓で{BATCH_MIN}件以上を一括公開したもの。"
            "除外サマリーには**代表1件＋件数**で1エントリとして集約してよい。"
            "（GHSA / MITRE / VulDB 等の複数ベンダー横断CNAは集約対象外＝下の個別判断へ）",
            "",
            "| CNA | 件数 | 代表CVE | CVSS | 概要 |",
            "|---|---|---|---|---|",
        ])
        for b in batches:
            desc = (b.get("description") or "")[:90].replace("|", "\\|")
            lines.append(
                f"| {b['source_identifier']} | {b['count']} | {b['representative']} |"
                f" {b.get('cvss_max') or '—'} | {desc} |"
            )
        lines.append("")

    lines.extend([
        f"#### 個別に判断が必要なCVE（{len(individual)}件）",
        "",
        "レポート本体にも除外サマリーにも現れていない。"
        "採用するか、除外理由を明記して除外サマリーへ追記すること。",
        "",
        "| ID | CVSS | KEV | GHSA | CNA | 概要 |",
        "|---|---|---|---|---|---|",
    ])
    for r in individual:
        rid = r.get("cve_id") or r.get("euvd_id") or "(不明ID)"
        if r.get("euvd_id") and r.get("cve_id"):
            rid = f"{r['cve_id']} ({r['euvd_id']})"
        kev = f"○ {r.get('kev_date_added')}" if r.get("in_kev") or r.get("kev_date_added") else "—"
        desc = (r.get("description") or r.get("product") or "")[:90].replace("|", "\\|")
        cna = r.get("source_identifier") or r.get("assigner") or "—"
        lines.append(
            f"| {rid} | {r.get('cvss_max') or '—'} | {kev} |"
            f" {'○' if r.get('ghsa_origin') else '—'} | {cna} | {desc} |"
        )
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="調査ウィンドウ内のCVEを NVD / CISA KEV / EUVD から機械的に全件列挙する",
    )
    parser.add_argument("--window-start", help='調査窓の開始（JST。例: "2026-08-03 07:00"）')
    parser.add_argument("--window-end", help='調査窓の終了（JST。例: "2026-08-04 07:00"）')
    parser.add_argument("--threshold", type=float, default=9.0,
                        help="列挙するCVSS下限（既定 9.0 = トラックB採用条件）")
    parser.add_argument("--include-modified", action="store_true",
                        help="窓内に lastModified が更新された既存CVEも列挙する"
                             "（NVDの定常再更新でノイズが支配的。監査目的の任意オプション）")
    parser.add_argument("--no-euvd", action="store_true",
                        help="EUVD 補完列挙をスキップする（既定は実行。取得失敗時は"
                             "自動的に NVD+KEV のみで続行するため通常は不要）")
    parser.add_argument("--from-json", help="スイープ結果JSONを再読み込みする（API再取得なし）")
    parser.add_argument("--reconcile", metavar="REPORT_JSON",
                        help="生成済み security-report.json と突合し未処理CVEを列挙する")
    parser.add_argument("--output", help="スイープ結果JSONの保存先")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown",
                        help="標準出力の形式（既定 markdown）")
    args = parser.parse_args()

    if args.from_json:
        with open(args.from_json, encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        if not (args.window_start and args.window_end):
            parser.error("--window-start と --window-end、または --from-json が必要")
        data = sweep(parse_jst(args.window_start), parse_jst(args.window_end),
                     args.threshold, include_modified=args.include_modified,
                     no_euvd=args.no_euvd)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"保存: {args.output}", file=sys.stderr)

    if args.reconcile:
        result = reconcile(data, args.reconcile)
        if args.format == "json":
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(render_reconcile(result))
        return 1 if result["unhandled"] else 0

    if args.format == "json":
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(render_markdown(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
