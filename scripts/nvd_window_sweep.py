#!/usr/bin/env python3
"""調査ウィンドウ内に公開・更新されたCVEを NVD / CISA KEV から機械的に全件列挙する。

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

★このスクリプトは forecaster/knowledge/ を一切書き換えない（CLAUDE.md 行動原則5）。
出力は .cache/ 配下のスイープ結果 JSON と標準出力のみである。

使い方:

    # 窓内の CVSS 9.0以上 + KEV 窓内追加を全件列挙（JSON保存）
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

GHSA_SOURCE_ID = "security-advisories@github.com"

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
          include_modified: bool = False) -> dict:
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
        },
        "over_threshold_published": over,
        "over_threshold_modified": changed,
        "kev_added_in_window": kev_in_window,
    }


# --------------------------------------------------------------------------
# 突合（reconcile）
# --------------------------------------------------------------------------

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def cves_in_report(path: str) -> set[str]:
    """レポートJSON全体に出現するCVE IDを集める（採用・除外サマリー双方を含む）。

    採用セクション名・除外セクション名はリポジトリごとにスキーマが異なるため、
    構造を仮定せずファイル全体を走査する。「レポートに一度も現れないCVE」＝未処理。
    """
    with open(path, encoding="utf-8") as fh:
        return set(CVE_RE.findall(fh.read()))


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
    関わらず集約せず、必ず個別判断に回す。
    """
    handled = cves_in_report(report_path)
    rows = (
        sweep_data.get("over_threshold_published", [])
        + sweep_data.get("kev_added_in_window", [])
    )
    if sweep_data.get("include_modified"):
        rows += sweep_data.get("over_threshold_modified", [])
    seen: set[str] = set()
    unhandled: list[dict] = []
    for row in rows:
        cve_id = row["cve_id"]
        if cve_id in seen or cve_id in handled:
            continue
        seen.add(cve_id)
        unhandled.append(row)
    unhandled.sort(key=lambda r: (-(r.get("cvss_max") or 0), r["cve_id"]))

    groups: dict[str, list[dict]] = {}
    for row in unhandled:
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
    individual = [r for r in unhandled if r["cve_id"] not in batch_ids]

    return {
        "report": report_path,
        "sweep_candidates": len({r["cve_id"] for r in rows}),
        "handled_in_report": len({r["cve_id"] for r in rows} & handled),
        "unhandled": unhandled,
        "unhandled_batches": batches,
        "unhandled_individual": individual,
    }


# --------------------------------------------------------------------------
# 出力
# --------------------------------------------------------------------------

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
        "| CVE | CVSS | KEV | GHSA | CNA | 概要 |",
        "|---|---|---|---|---|---|",
    ])
    for r in individual:
        kev = f"○ {r.get('kev_date_added')}" if r.get("in_kev") or r.get("kev_date_added") else "—"
        desc = (r.get("description") or r.get("product") or "")[:90].replace("|", "\\|")
        lines.append(
            f"| {r['cve_id']} | {r.get('cvss_max') or '—'} | {kev} |"
            f" {'○' if r.get('ghsa_origin') else '—'} | {r.get('source_identifier') or '—'} | {desc} |"
        )
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="調査ウィンドウ内のCVEを NVD / CISA KEV から機械的に全件列挙する",
    )
    parser.add_argument("--window-start", help='調査窓の開始（JST。例: "2026-08-03 07:00"）')
    parser.add_argument("--window-end", help='調査窓の終了（JST。例: "2026-08-04 07:00"）')
    parser.add_argument("--threshold", type=float, default=9.0,
                        help="列挙するCVSS下限（既定 9.0 = トラックB採用条件）")
    parser.add_argument("--include-modified", action="store_true",
                        help="窓内に lastModified が更新された既存CVEも列挙する"
                             "（NVDの定常再更新でノイズが支配的。監査目的の任意オプション）")
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
                     args.threshold, include_modified=args.include_modified)

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
