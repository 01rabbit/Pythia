#!/usr/bin/env python3
"""KEV 追加前日時点の EPSS パーセンタイルを実測し、M3 確度アンカーを較正する。

目的:
  03-forecast.md の M3 ルール「確度=高は KEV AND EPSS%ile≥0.95 AND SSVC=Act/Attend」
  の EPSS 条件は、外部の一般則を借りた閾値であり自データ較正されていない。
  本スクリプトは KEV 全エントリについて「KEV 追加の前日時点で EPSS パーセンタイルが
  いくつだったか」を FIRST API の履歴照会で実測し、閾値 0.95 の妥当性を検証する
  統計を生成する。

本統計が測るもの・測らないもの（誤用防止・厳守）:
  - 測るもの: P(EPSS%ile ≥ τ | 翌日 KEV 追加) — 実際に KEV 追加された CVE のうち、
    追加前日に EPSS 条件を満たしていた割合（M3 の EPSS 条件の「感度」）。
  - 測らないもの: P(KEV 追加 | EPSS%ile ≥ τ) — パーセンタイルの定義上、任意時点で
    全 CVE の約5%が %ile≥0.95 に存在する。その大多数は KEV に追加されない。
    本統計を「EPSS が高ければ KEV 追加される」という予測精度の根拠にしないこと。

測定日を dateAdded の前日とする理由:
  EPSS（v3 以降）は CISA KEV 収載を入力特徴の一つとして使用するため、追加当日以降の
  スコアは KEV 追加自体に反応した事後値になりうる。前日値を使うことで
  「予報者が KEV 追加前に観測できた値」を再現する（as-of 汚染の防止）。

設計原則:
  - 出力は forecaster/knowledge/ の機械生成ファイル。自動書き換え禁止ルールに従い、
    再生成は日次ルーチンからは行わず PR 提案+人間レビュー経由のみ。
  - 全エントリの実測値を entries[] に監査証跡として残す。
  - EPSS モデル版（v1/v2/v3/v4）でパーセンタイルの意味が変わるため版別に層別する。

入力:
  - CISA KEV catalog（--kev-file 指定またはネット取得）
  - FIRST EPSS API（https://api.first.org/data/v1/epss・日付指定履歴照会）

出力:
  forecaster/knowledge/epss-kev-calibration.json

使い方:
    python3 scripts/build_epss_kev_calibration.py --kev-file kev.json \
        --cache /path/to/epss-cache.jsonl
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import date, timedelta

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(
    REPO_ROOT, "forecaster", "knowledge", "epss-kev-calibration.json"
)

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_API = "https://api.first.org/data/v1/epss"

# EPSS モデル版の適用開始日（FIRST 公表のモデル切替日）
MODEL_ERAS = [
    ("2025-03-17", "v4"),
    ("2023-03-07", "v3"),
    ("2022-02-04", "v2"),
    ("2021-04-14", "v1"),
]

THRESHOLDS = [0.95, 0.90, 0.75, 0.50]
REQUEST_INTERVAL_SEC = 0.6
MAX_RETRIES = 4


def model_era(query_date):
    for start, name in MODEL_ERAS:
        if query_date >= start:
            return name
    return "pre_epss"


def fetch_json(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "pythia-epss-cal/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def fetch_epss_batch(cves, query_date):
    """指定日の EPSS を複数 CVE 一括照会する。{cve: {epss, percentile}}"""
    params = urllib.parse.urlencode({"cve": ",".join(cves), "date": query_date})
    url = f"{EPSS_API}?{params}"
    for attempt in range(MAX_RETRIES):
        try:
            data = fetch_json(url)
            return {
                d["cve"]: {
                    "epss": float(d["epss"]),
                    "percentile": float(d["percentile"]),
                }
                for d in data.get("data", [])
            }
        except urllib.error.HTTPError as e:
            # 422 = 照会した全CVEがその日に未収録（NVD収録前にKEV追加された
            # ゼロデイ等）。エラーではなく「スコアなし」として扱う。
            if e.code == 422:
                return {}
            wait = 2 ** (attempt + 1)
            print(f"[warn] EPSS 取得失敗（{query_date}, retry in {wait}s）: {e}")
            time.sleep(wait)
        except Exception as e:
            wait = 2 ** (attempt + 1)
            print(f"[warn] EPSS 取得失敗（{query_date}, retry in {wait}s）: {e}")
            time.sleep(wait)
    raise RuntimeError(f"EPSS API 照会が {MAX_RETRIES} 回失敗: date={query_date}")


def load_cache(path):
    cache = {}
    if path and os.path.exists(path):
        with open(path) as f:
            for line in f:
                rec = json.loads(line)
                cache[rec["cve"]] = rec
    return cache


def percentile_of(sorted_vals, p):
    if not sorted_vals:
        return None
    k = (len(sorted_vals) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return round(float(sorted_vals[f]), 4)
    return round(sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f), 4)


def summarize(percentiles, n_no_score):
    n = len(percentiles)
    out = {"n_measured": n, "n_no_score": n_no_score}
    if n == 0:
        return out
    s = sorted(percentiles)
    out["median_percentile"] = percentile_of(s, 50)
    out["p25_percentile"] = percentile_of(s, 25)
    for t in THRESHOLDS:
        out[f"pct_ge_{t}"] = round(sum(1 for x in s if x >= t) / n, 3)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="KEV 追加前日時点の EPSS パーセンタイル分布を実測する。"
    )
    ap.add_argument("--kev-file", help="KEV catalog JSON のローカルパス（省略時はネット取得）")
    ap.add_argument("--cache", help="実測値キャッシュ（JSONL・レジューム用）")
    ap.add_argument("--out", default=OUT_PATH, help=f"出力先（既定: {OUT_PATH}）")
    args = ap.parse_args()

    if args.kev_file:
        kev = json.load(open(args.kev_file))
    else:
        print(f"[fetch] CISA KEV: {KEV_FEED_URL}")
        kev = fetch_json(KEV_FEED_URL, timeout=120)
    catalog_version = kev.get("catalogVersion", "unknown")

    cache = load_cache(args.cache)
    cache_f = open(args.cache, "a") if args.cache else None

    # dateAdded ごとにまとめ、前日を照会日とする
    by_query_date = defaultdict(list)
    date_added_of = {}
    for e in kev.get("vulnerabilities", []):
        cve, added = e.get("cveID"), e.get("dateAdded")
        if not cve or not added:
            continue
        date_added_of[cve] = added
        if cve in cache:
            continue
        qd = (date.fromisoformat(added) - timedelta(days=1)).isoformat()
        by_query_date[qd].append(cve)

    total_dates = len(by_query_date)
    print(f"[plan] 照会対象日数: {total_dates}（キャッシュ済み {len(cache)} 件を除く）")

    for i, qd in enumerate(sorted(by_query_date), 1):
        cves = by_query_date[qd]
        scores = {}
        for j in range(0, len(cves), 100):
            scores.update(fetch_epss_batch(cves[j : j + 100], qd))
            time.sleep(REQUEST_INTERVAL_SEC)
        for cve in cves:
            rec = {
                "cve": cve,
                "date_added": date_added_of[cve],
                "query_date": qd,
                "model_era": model_era(qd),
                "epss": scores.get(cve, {}).get("epss"),
                "percentile": scores.get(cve, {}).get("percentile"),
            }
            cache[cve] = rec
            if cache_f:
                cache_f.write(json.dumps(rec) + "\n")
                cache_f.flush()
        if i % 25 == 0 or i == total_dates:
            print(f"[progress] {i}/{total_dates} 日分照会済み")

    if cache_f:
        cache_f.close()

    entries = sorted(cache.values(), key=lambda r: (r["date_added"], r["cve"]))
    measured = [r for r in entries if r["percentile"] is not None]
    no_score = [r for r in entries if r["percentile"] is None]

    by_era = defaultdict(lambda: ([], 0))
    by_year = defaultdict(lambda: ([], 0))
    for r in entries:
        for key, bucket in (
            (r["model_era"], by_era),
            (r["date_added"][:4], by_year),
        ):
            vals, miss = bucket[key]
            if r["percentile"] is None:
                bucket[key] = (vals, miss + 1)
            else:
                vals.append(r["percentile"])
                bucket[key] = (vals, miss)

    out = {
        "_comment": (
            "KEV 追加前日時点の EPSS パーセンタイル実測分布（M3 確度アンカー較正データ）。"
            "測っているのは P(EPSS%ile≥τ | 翌日KEV追加)＝M3 の EPSS 条件の感度であり、"
            "P(KEV追加 | EPSS%ile≥τ) ではない。下記 _limitations 厳守。"
        ),
        "_schema_version": "1.0",
        "_machine_generated": True,
        "_generator": "scripts/build_epss_kev_calibration.py",
        "_generated_on": date.today().isoformat(),
        "_source": {
            "kev_catalog_version": catalog_version,
            "epss_api": EPSS_API,
            "measurement": "dateAdded の前日時点の EPSS（履歴照会）",
        },
        "_governance": (
            "knowledge/ の自動書き換え禁止ルールに従い、再生成は日次ルーチンからは"
            "行わず、必ず PR として提案し人間レビューを経てコミットする。"
        ),
        "_limitations": [
            "方向性: 本統計は M3 の EPSS 条件の感度（KEV追加されたCVEのうち事前に条件を"
            "満たしていた割合）である。パーセンタイルの定義上、任意時点で全CVEの約5%が"
            "%ile≥0.95 に存在し、その大多数は KEV に追加されない。P(KEV|EPSS高) の根拠に"
            "使わない。",
            "前日測定: EPSS（v3以降）は KEV 収載を入力特徴に含むため、追加当日以降の値は"
            "事後値になりうる。前日値の採用により予報者が事前に観測できた値を再現した。"
            "ただし前日値にも KEV 追加の引き金となった悪用証拠自体は反映されうる"
            "（それは意図した測定である）。",
            "モデル版差: EPSS v1/v2/v3/v4 でパーセンタイルの意味が変わるため by_model_era で"
            "層別した。現行運用の較正には v4（2025-03-17以降）層を優先参照する。",
            "no_score: 照会日に EPSS スコアが存在しない CVE（NVD 収録前に KEV 追加された"
            "ゼロデイ等）。この欠測は無作為ではなく『公開前に悪用された事例』に偏るため、"
            "感度の分母からの除外はやや楽観方向のバイアスを持つ。n_no_score を必ず併記する。",
            "用途制限: M3 の EPSS 閾値の妥当性検証・base_rate_estimate の参考に限る。"
            "hit_criteria の変更・確度の引き上げ根拠には使わない。",
        ],
        "population": {
            "kev_total": len(entries),
            "measured": len(measured),
            "no_score": len(no_score),
        },
        "overall": summarize([r["percentile"] for r in measured], len(no_score)),
        "by_model_era": {
            era: summarize(vals, miss)
            for era, (vals, miss) in sorted(by_era.items())
        },
        "by_year_added": {
            y: summarize(vals, miss) for y, (vals, miss) in sorted(by_year.items())
        },
        "entries": entries,
    }
    with open(args.out, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
        f.write("\n")
    rel = os.path.relpath(args.out, REPO_ROOT)
    o = out["overall"]
    print(f"[done] {rel}: measured={len(measured)} no_score={len(no_score)}")
    print(
        f"[overall] median%ile={o.get('median_percentile')} "
        f"ge0.95={o.get('pct_ge_0.95')} ge0.90={o.get('pct_ge_0.90')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
