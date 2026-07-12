#!/usr/bin/env python3
"""KEV / NVD 較正スクリプト共通のデータ取得・統計ヘルパ。

scripts/build_kev_leadtime_stats.py と scripts/build_epss_kev_calibration.py が
共有する。取得先 URL・ページネーション・パーセンタイル計算を一箇所に置き、
兄弟スクリプト間のコピー乖離（レビュー指摘）を防ぐ。

注意: 本モジュールは knowledge/ 生成系スクリプト専用。日次ルーチンからは
実行しない（SKILL.md Step 3.5 の注意書き参照）。
"""

import json
import urllib.request

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_KEV_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
    "?hasKev&resultsPerPage=2000&startIndex={start_index}"
)

# NVD CVSS メトリクスの優先順（新しい版を優先・Primary を優先）
CVSS_PREFERENCE = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]


def fetch_json(url, timeout=120, user_agent="pythia-calibration/1.0"):
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def load_kev(kev_file=None):
    """CISA KEV catalog を読み込む（ローカルファイルまたはネット取得）。"""
    if kev_file:
        with open(kev_file) as f:
            return json.load(f)
    print(f"[fetch] CISA KEV: {KEV_FEED_URL}")
    return fetch_json(KEV_FEED_URL)


def load_nvd_kev_vulnerabilities(nvd_file=None):
    """NVD hasKev 一括照会の vulnerabilities 配列を返す（ページネーション対応）。"""
    if nvd_file:
        with open(nvd_file) as f:
            return json.load(f).get("vulnerabilities", [])
    vulns = []
    start_index = 0
    while True:
        print(f"[fetch] NVD hasKev: startIndex={start_index}")
        data = fetch_json(NVD_KEV_URL.format(start_index=start_index), timeout=180)
        page = data.get("vulnerabilities", [])
        vulns.extend(page)
        start_index += len(page)
        if start_index >= data.get("totalResults", 0) or not page:
            break
    return vulns


def primary_cvss_score(cve_obj):
    """NVD の cve オブジェクトから CVSS baseScore を返す（Primary 優先・なければ None）。"""
    metrics = cve_obj.get("metrics", {})
    for key in CVSS_PREFERENCE:
        entries = metrics.get(key) or []
        if entries:
            primary = next(
                (e for e in entries if e.get("type") == "Primary"), entries[0]
            )
            return primary.get("cvssData", {}).get("baseScore")
    return None


def percentile(sorted_vals, p, ndigits=4):
    """線形補間パーセンタイル（0 <= p <= 100）。両分岐とも ndigits で丸める。"""
    if not sorted_vals:
        return None
    k = (len(sorted_vals) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return round(float(sorted_vals[f]), ndigits)
    return round(sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f), ndigits)
