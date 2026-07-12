#!/usr/bin/env python3
"""CISA KEV 全件から「NVD公開→KEV追加」リードタイムの実測分布を機械算出する。

目的:
  E1（KEV初回追加）予報の検証窓（fast_72h / slow_7d）設定と
  base_rate_estimate 記入の参考統計を、n=1（kev-initial-add-timelines.json の
  現状）から KEV 全母集団規模の実測分布に引き上げる。

本統計が測るもの・測らないもの（誤用防止・厳守）:
  - 測るもの: 「最終的に KEV に追加された CVE が、NVD 公開から KEV 追加まで
    に要した日数」の条件付き分布（KEV 追加が確定した集合の中でのラグ分布）。
  - 測らないもの:
    (1) P(KEV追加 | CVE公開) — 生存バイアス: KEV に追加されなかった大多数の
        CVE は母集団に含まれない。E1 予報の base_rate そのものではない。
    (2) 「実悪用確認→KEV追加」ラグ — kev-initial-add-timelines.json が
        測っているものとは意味論が異なる（NVD 公開時点で悪用が始まっている
        とは限らない）。両ファイルは補完関係であり代替関係ではない。
  - 用途は fast_72h / slow_7d の窓設定・base_rate_estimate 記入時の参考に
    限定し、的中判定基準（hit_criteria）の変更には使わない。

設計原則:
  - 日付スタンプ付き一次データのみ使用（KEV dateAdded / NVD published）。
  - 出力は forecaster/knowledge/ の機械生成ファイル。knowledge/ の自動書き換え
    禁止ルールに従い、再生成は日次ルーチンからは行わず PR 提案+人間レビュー経由のみ。
  - 平均値はロングテール（数年越しの KEV 追加）に引きずられるため、
    中央値・パーセンタイル・閾値内割合を主とし mean は参考値とする。

入力:
  - CISA KEV catalog（--kev-file 指定またはネット取得）
  - NVD API hasKev 一括照会（--nvd-file 指定またはネット取得。published 日付と CVSS）
  - forecaster/knowledge/product-categories.json（製品カテゴリ層別・読み取りのみ）

出力:
  forecaster/knowledge/kev-leadtime-stats.json

使い方:
    python3 scripts/build_kev_leadtime_stats.py \
        --kev-file kev.json --nvd-file nvd-kev.json
"""

import argparse
import json
import os
import sys
import urllib.request
from collections import defaultdict
from datetime import date, datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(REPO_ROOT, "forecaster", "knowledge", "kev-leadtime-stats.json")
PRODUCT_CATEGORIES_PATH = os.path.join(
    REPO_ROOT, "forecaster", "knowledge", "product-categories.json"
)

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_KEV_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
    "?hasKev&resultsPerPage=2000&startIndex={start_index}"
)

MIN_SAMPLE_PER_STRATUM = 10  # 層別統計の最小サンプル数（下回る層は insufficient 扱い）
ERA_STABLE_START_YEAR = "2023"  # KEV遡及一括登録期（2021-2022）を除いた推奨参照層の開始年


def fetch_json(url, timeout=180):
    req = urllib.request.Request(url, headers={"User-Agent": "pythia-leadtime/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def load_kev(kev_file):
    if kev_file:
        with open(kev_file) as f:
            return json.load(f)
    print(f"[fetch] CISA KEV: {KEV_FEED_URL}")
    return fetch_json(KEV_FEED_URL)


def load_nvd(nvd_file):
    """NVD hasKev 一括照会から {CVE-ID: {published, cvss}} を作る。"""
    vulns = []
    if nvd_file:
        with open(nvd_file) as f:
            vulns = json.load(f).get("vulnerabilities", [])
    else:
        start_index = 0
        while True:
            print(f"[fetch] NVD hasKev: startIndex={start_index}")
            data = fetch_json(NVD_KEV_URL.format(start_index=start_index))
            vulns.extend(data.get("vulnerabilities", []))
            start_index += len(data.get("vulnerabilities", []))
            if start_index >= data.get("totalResults", 0) or not data.get(
                "vulnerabilities"
            ):
                break

    preference = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    result = {}
    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id")
        published = (cve.get("published") or "")[:10]
        score = None
        for key in preference:
            entries = cve.get("metrics", {}).get(key) or []
            if entries:
                primary = next(
                    (e for e in entries if e.get("type") == "Primary"), entries[0]
                )
                score = primary.get("cvssData", {}).get("baseScore")
                break
        result[cve_id] = {"published": published or None, "cvss": score}
    return result


def build_category_resolver():
    """product-categories.json の cve_overrides + product_keyword_map を使う
    （retrieve_similar_cases.py の resolver と同一ロジック）。"""
    data = json.load(open(PRODUCT_CATEGORIES_PATH))
    cve_overrides = {
        k: v for k, v in data.get("cve_overrides", {}).items() if not k.startswith("_")
    }
    keyword_map = {
        k: v
        for k, v in data.get("product_keyword_map", {}).items()
        if not k.startswith("_")
    }

    def resolver(cve, text):
        if cve in cve_overrides:
            return {cve_overrides[cve]}
        hay = (text or "").lower()
        return {cat for kw, cat in keyword_map.items() if kw in hay}

    return resolver


def percentile(sorted_vals, p):
    """線形補間パーセンタイル（0 <= p <= 100）。"""
    if not sorted_vals:
        return None
    k = (len(sorted_vals) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return float(sorted_vals[f])
    return round(sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f), 1)


def summarize(lags):
    """非負ラグ集合のサマリー統計。lags は日数の list。"""
    n = len(lags)
    if n == 0:
        return {"n": 0}
    s = sorted(lags)
    within = lambda d: round(sum(1 for x in s if x <= d) / n, 3)
    return {
        "n": n,
        "median_days": percentile(s, 50),
        "p25_days": percentile(s, 25),
        "p75_days": percentile(s, 75),
        "p90_days": percentile(s, 90),
        "mean_days_reference_only": round(sum(s) / n, 1),
        "pct_same_day": within(0),
        "pct_within_3d": within(3),
        "pct_within_7d": within(7),
        "pct_within_30d": within(30),
        "pct_within_365d": within(365),
    }


def stratum_stats(items_by_key):
    out = {}
    for key in sorted(items_by_key, key=lambda k: str(k)):
        lags = items_by_key[key]
        stats = summarize(lags)
        if stats["n"] < MIN_SAMPLE_PER_STRATUM:
            stats["insufficient_sample"] = True
            stats["note"] = (
                f"n<{MIN_SAMPLE_PER_STRATUM} のため参考値。単独で判断根拠にしない。"
            )
        out[str(key)] = stats
    return out


def cvss_band(score):
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical_9.0+"
    if score >= 7.0:
        return "high_7.0-8.9"
    return "below_7.0"


def main():
    ap = argparse.ArgumentParser(
        description="KEV 全件から NVD公開→KEV追加リードタイム分布を算出する。"
    )
    ap.add_argument("--kev-file", help="KEV catalog JSON のローカルパス（省略時はネット取得）")
    ap.add_argument("--nvd-file", help="NVD hasKev 応答 JSON のローカルパス（省略時はネット取得）")
    ap.add_argument("--out", default=OUT_PATH, help=f"出力先（既定: {OUT_PATH}）")
    args = ap.parse_args()

    kev = load_kev(args.kev_file)
    catalog_version = kev.get("catalogVersion", "unknown")
    nvd = load_nvd(args.nvd_file)
    resolver = build_category_resolver()

    entries = []
    n_missing_nvd = 0
    negative = []  # KEV追加がNVD公開より先（収録遅延・非公開悪用の痕跡）
    for e in kev.get("vulnerabilities", []):
        cve_id = e.get("cveID")
        date_added = e.get("dateAdded")
        meta = nvd.get(cve_id)
        if not meta or not meta.get("published") or not date_added:
            n_missing_nvd += 1
            continue
        lag = (
            date.fromisoformat(date_added) - date.fromisoformat(meta["published"])
        ).days
        cats = resolver(
            cve_id,
            " ".join(
                [
                    e.get("vendorProject") or "",
                    e.get("product") or "",
                    e.get("vulnerabilityName") or "",
                    e.get("shortDescription") or "",
                ]
            ),
        )
        rec = {
            "cve": cve_id,
            "lag": lag,
            "year_added": date_added[:4],
            "ransomware": e.get("knownRansomwareCampaignUse") == "Known",
            "cvss_band": cvss_band(meta["cvss"]),
            "categories": cats,
        }
        if lag < 0:
            negative.append(rec)
        else:
            entries.append(rec)

    lags = [r["lag"] for r in entries]
    by_year = defaultdict(list)
    by_ransom = defaultdict(list)
    by_band = defaultdict(list)
    by_cat = defaultdict(list)
    for r in entries:
        by_year[r["year_added"]].append(r["lag"])
        by_ransom["known_ransomware" if r["ransomware"] else "other"].append(r["lag"])
        by_band[r["cvss_band"]].append(r["lag"])
        for c in r["categories"]:
            by_cat[c].append(r["lag"])

    n_all = len(entries) + len(negative)
    out = {
        "_comment": (
            "CISA KEV 全件の「NVD公開→KEV追加」リードタイム実測分布。"
            "E1（KEV初回追加）予報の検証窓設定・base_rate_estimate 記入の参考統計。"
            "★測っているのは『KEV追加が確定した集合の条件付きラグ分布』であり、"
            "P(KEV追加|公開) でも『実悪用確認→KEV追加』ラグ"
            "（kev-initial-add-timelines.json の対象）でもない。下記 _limitations 厳守。"
        ),
        "_schema_version": "1.0",
        "_machine_generated": True,
        "_generator": "scripts/build_kev_leadtime_stats.py",
        "_generated_on": date.today().isoformat(),
        "_source": {
            "kev_catalog_version": catalog_version,
            "kev_feed": KEV_FEED_URL,
            "nvd_api": "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev",
        },
        "_governance": (
            "knowledge/ の自動書き換え禁止ルールに従い、再生成は日次ルーチンからは"
            "行わず、必ず PR として提案し人間レビューを経てコミットする。"
        ),
        "_limitations": [
            "生存バイアス: 母集団は KEV に追加された CVE のみ。KEV に追加されない大多数の"
            "CVE を含まないため、P(KEV追加|公開) や E1 予報の base_rate そのものではない。",
            "意味論: NVD published は NVD 収録日であり、実悪用確認日・脆弱性公表日と"
            "乖離しうる。「実悪用確認→KEV追加」ラグは kev-initial-add-timelines.json を参照。",
            "ロングテール: 公開から数年後に KEV 追加される事例が mean を大きく歪めるため、"
            "mean_days_reference_only は参考値。判断には median / percentile / 閾値内割合を使う。",
            "運用変化: KEV は BOD 22-01（2021-11）開始。初期の一括登録年（2021-2022）は"
            "過去 CVE の遡及登録を大量に含みラグが構造的に長い。直近年の層を優先参照する。",
            "negative_lag: KEV 追加が NVD 公開より先の事例（NVD 収録遅延・ゼロデイ等）は"
            "本分布から分離して集計した。",
            "用途制限: fast_72h/slow_7d の窓設定・base_rate_estimate の参考に限る。"
            "hit_criteria（的中判定基準）の変更・緩和には使わない。",
        ],
        "population": {
            "kev_total": len(kev.get("vulnerabilities", [])),
            "with_nvd_published": n_all,
            "missing_nvd_data": n_missing_nvd,
            "negative_lag_count": len(negative),
            "nonnegative_lag_count": len(entries),
        },
        "overall": summarize(lags),
        "era_2023_plus_recommended": {
            "_note": (
                f"dateAdded が {ERA_STABLE_START_YEAR} 年以降のエントリのみの合算。"
                "BOD 22-01 初期の遡及一括登録（2021-2022）を除いた推奨参照層。"
            ),
            **summarize(
                [r["lag"] for r in entries if r["year_added"] >= ERA_STABLE_START_YEAR]
            ),
        },
        "by_year_added": stratum_stats(by_year),
        "by_ransomware_use": stratum_stats(by_ransom),
        "by_cvss_band": stratum_stats(by_band),
        "by_product_category": stratum_stats(by_cat),
        "negative_lag_cves": sorted(
            ({"cve": r["cve"], "lag_days": r["lag"]} for r in negative),
            key=lambda x: x["lag_days"],
        ),
    }
    with open(args.out, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
        f.write("\n")
    rel = os.path.relpath(args.out, REPO_ROOT)
    print(
        f"[done] {rel}: n={n_all} (nonneg={len(entries)}, negative={len(negative)}, "
        f"missing_nvd={n_missing_nvd})"
    )
    o = out["overall"]
    print(
        f"[overall] median={o['median_days']}d p75={o['p75_days']}d "
        f"within3d={o['pct_within_3d']:.1%} within7d={o['pct_within_7d']:.1%}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
