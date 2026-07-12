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
import re
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
    """product-categories.json の cve_overrides + product_keyword_map を使う。

    辞書は retrieve_similar_cases.py と同一だが、マッチングは意図的に厳格化
    している: 単純部分一致では nsd→nsDOMSVGZoomEvent（Firefox）、
    sap→WhatsApp、unifi→Cisco Unified 等の偽陽性が KEV 英文コーパスで実際に
    発生するため、単語境界付き一致とする。このため同一 CVE でも Step C''
    （日本語観測サマリ対象・部分一致）とはカテゴリが異なりうる。"""
    data = json.load(open(PRODUCT_CATEGORIES_PATH))
    cve_overrides = {
        k: v for k, v in data.get("cve_overrides", {}).items() if not k.startswith("_")
    }
    compiled = [
        (
            re.compile(
                r"(?<![a-z0-9])" + re.escape(kw.lower()) + r"(?![a-z0-9])"
            ),
            cat,
        )
        for kw, cat in data.get("product_keyword_map", {}).items()
        if not kw.startswith("_")
    ]

    def resolver(cve, text):
        if cve in cve_overrides:
            return {cve_overrides[cve]}
        hay = (text or "").lower()
        return {cat for pat, cat in compiled if pat.search(hay)}

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
        # カテゴリ判定は製品を指すフィールドに限定する（shortDescription を
        # 含めると sapi/cgi→sap 等の本文由来の偽陽性が発生するため除外）
        cats = resolver(
            cve_id,
            " ".join(
                [
                    e.get("vendorProject") or "",
                    e.get("product") or "",
                    e.get("vulnerabilityName") or "",
                ]
            ),
        )
        rec = {
            "cve": cve_id,
            "lag": lag,
            "date_added": date_added,
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
            "product_categories_schema_version": json.load(
                open(PRODUCT_CATEGORIES_PATH)
            ).get("_schema_version"),
        },
        "_governance": (
            "knowledge/ の自動書き換え禁止ルールに従い、再生成は日次ルーチンからは"
            "行わず、必ず PR として提案し人間レビューを経てコミットする。"
        ),
        "_limitations": [
            "生存バイアス: 母集団は KEV に追加された CVE のみ。KEV に追加されない大多数の"
            "CVE を含まないため、P(KEV追加|公開) や E1 予報の base_rate そのものではない。"
            "また過去に収載後削除されたエントリ（誤収載等）も現行カタログから欠落する。",
            "時間原点の不一致（最重要）: 本分布の時計は NVD 公開で始まる。E1 予報の時計は"
            "予報発行時（実悪用観測時・公開から任意日数後）で始まり、必要なのは経過時間で"
            "条件付けたハザード率である。公開起点の CDF はこれを推定できない。生存バイアス"
            "（上振れ要因）と negative_lag 除外・時間原点差（下振れ要因）が混在するため、"
            "本統計は方向未定の参考値であり base_rate の代替アンカーにしない。",
            "意味論: NVD published は NVD 収録日であり、実悪用確認日・脆弱性公表日と"
            "乖離しうる（REJECT→再収録時の published の挙動は非保証）。"
            "「実悪用確認→KEV追加」ラグは kev-initial-add-timelines.json を参照。",
            "ロングテール: 公開から数年後に KEV 追加される事例が mean を大きく歪めるため、"
            "mean_days_reference_only は参考値。判断には median / percentile / 閾値内割合を使う。",
            "運用変化と残存混合: KEV は BOD 22-01（2021-11）開始。初期の一括登録年"
            "（2021-2022）は遡及登録が支配的。era_2023_plus 推奨層でも公開後1年超の遅延"
            "追加が約25%残る二峰混合分布であり、fresh_subset_lag_le_90d を併読する。",
            "negative_lag: KEV 追加が NVD 公開より先の事例（ゼロデイ型・NVD 収録遅延）は"
            "本分布から分離した。この群は『最速で KEV 入りする型』であり、除外は"
            "pct_within_3d を過小方向に歪める（era 層でクランプ感度値を併記）。"
            "ゼロデイ型の予報ではこの分布より速い。",
            "日付粒度: KEV dateAdded（米東部基準の暦日）と NVD published（タイムスタンプ"
            "先頭10文字）の差は ±1日の系統誤差を含む。pct_within_3d は連続時間で最大約96"
            "時間に相当し、fast_72h の『+3日固定』慣行とは整合するが厳密な72時間ではない。",
            "事後値層別: cvss_band は現在の NVD 値（事後付与・事後改訂・v2/v3/v4/CNA 混合）、"
            "ransomware フラグも追加後に更新される値による層別であり、予報発行時に観測"
            "可能な層別ではない。参考情報に留める。",
            "カテゴリ被覆: 製品カテゴリ辞書は自観測由来（現在の関心領域の選択バイアス）で、"
            "本統計でのマッチは単語境界付き・製品フィールド限定（Step C'' の部分一致とは"
            "異なり同一 CVE で別カテゴリになりうる）。未分類が大半を占めるため "
            "population のカテゴリ被覆率を必ず併読する。",
            "用途制限: fast_72h/slow_7d の窓設定・base_rate_estimate の参考に限る。"
            "hit_criteria（的中判定基準）の変更・緩和には使わない。",
        ],
        "population": {
            "kev_total": len(kev.get("vulnerabilities", [])),
            "with_nvd_published": n_all,
            "missing_nvd_data": n_missing_nvd,
            "negative_lag_count": len(negative),
            "nonnegative_lag_count": len(entries),
            "categorized_count": sum(1 for r in entries if r["categories"]),
            "uncategorized_count": sum(1 for r in entries if not r["categories"]),
        },
        "overall": summarize(lags),
        "era_2023_plus_recommended": (lambda era, era_neg: {
            "_note": (
                f"dateAdded が {ERA_STABLE_START_YEAR} 年以降のエントリのみの合算。"
                "BOD 22-01 初期の遡及一括登録（2021-2022）を除いた参照層だが、"
                "本層も公開後1年超の遅延追加を含む二峰混合分布である"
                "（fresh_subset_lag_le_90d と negative_lag クランプ値を併読）。"
            ),
            **summarize([r["lag"] for r in era]),
            "fresh_subset_lag_le_90d": {
                "_note": (
                    "公開後90日以内に追加された部分集合（遡及登録を除いた"
                    "『新規公開CVEの即応追加』母集団の近似）。P(lag≤3|lag≤90) 等の"
                    "条件付き割合であり、さらに強い条件付けが入る点に注意。"
                ),
                **summarize([r["lag"] for r in era if r["lag"] <= 90]),
            },
            "pct_within_3d_negative_clamped": (
                round(
                    (
                        sum(1 for r in era if r["lag"] <= 3) + len(era_neg)
                    )
                    / (len(era) + len(era_neg)),
                    3,
                )
                if era or era_neg
                else None
            ),
            "_clamp_note": (
                "negative_lag（ゼロデイ型）を lag=0 として含めた場合の pct_within_3d"
                "（感度上限の参考値）。"
            ),
        })(
            [r for r in entries if r["year_added"] >= ERA_STABLE_START_YEAR],
            [r for r in negative if r["year_added"] >= ERA_STABLE_START_YEAR],
        ),
        "by_year_added": stratum_stats(by_year),
        "by_ransomware_use": stratum_stats(by_ransom),
        "by_cvss_band": stratum_stats(by_band),
        "by_product_category": stratum_stats(by_cat),
        "negative_lag_cves": sorted(
            (
                {
                    "cve": r["cve"],
                    "lag_days": r["lag"],
                    "date_added": r["date_added"],
                }
                for r in negative
            ),
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
    if o.get("n"):
        print(
            f"[overall] median={o['median_days']}d p75={o['p75_days']}d "
            f"within3d={o['pct_within_3d']:.1%} within7d={o['pct_within_7d']:.1%}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
