#!/usr/bin/env python3
"""KEV 追加前日時点の EPSS パーセンタイルを実測し、M3 確度アンカーを較正する。

目的:
  03-forecast.md の M3 ルール「確度=高は KEV AND EPSS%ile≥0.95 AND SSVC=Act/Attend」
  の EPSS 条件は、外部の一般則を借りた閾値であり自データ較正されていない。
  本スクリプトは KEV 全エントリについて「KEV 追加の前日時点で EPSS パーセンタイルが
  いくつだったか」を FIRST API の履歴照会で実測し、閾値 0.95 の感度
  （KEV 追加の事前予見可能性）を実測する統計を生成する。
  ★これは M3 が運用上参照する「KEV 登録後の EPSS 値」の充足率とは別の量である
  （EPSS v3+ は KEV 収載自体を特徴量に含むため登録後の値は事後的に押し上がる）。
  前日感度の低さを根拠に閾値を引き下げるのはカテゴリエラーであり禁止。

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
            # 422 は実測上「照会した全CVEがその日に未収録」（NVD収録前にKEV追加
            # されたゼロデイ等）で返るが、公式に文書化された仕様ではない。
            # 無警告で握りつぶさず、警告ログを残した上で「スコアなし」として扱う
            # （呼び出し元が no_score_reason: http_422 を記録する）。
            if e.code == 422:
                print(
                    f"[warn] EPSS 422 No records: date={query_date} "
                    f"cves={len(cves)}件（全件 no_score 扱い・要因は http_422 として記録）"
                )
                return None
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
        # キー名を2桁固定（pct_ge_0.90）にする。f"{0.90}" は "0.9" になり
        # 下流が pct_ge_0.90 を期待すると None を踏むため。
        out[f"pct_ge_{t:.2f}"] = round(sum(1 for x in s if x >= t) / n, 3)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="KEV 追加前日時点の EPSS パーセンタイル分布を実測する。"
    )
    ap.add_argument("--kev-file", help="KEV catalog JSON のローカルパス（省略時はネット取得）")
    ap.add_argument("--cache", help="実測値キャッシュ（JSONL・レジューム用）")
    ap.add_argument(
        "--nvd-file",
        help=(
            "NVD hasKev 応答 JSON のローカルパス（任意）。指定時は NVD 公開日から"
            "鮮度層（公開→KEV追加ラグ別）の感度クロス集計を追加する"
        ),
    )
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

    # dateAdded ごとにまとめ、前日を照会日とする。
    # キャッシュは (a) 現行カタログに存在し (b) date_added が一致し
    # (c) 実測値が入っている場合のみ採用する（カタログ改訂・一時的な空応答の
    # 恒久キャッシュ化を防ぐ。percentile=None は再照会し、422 なら再び None になる）。
    by_query_date = defaultdict(list)
    date_added_of = {}
    for e in kev.get("vulnerabilities", []):
        cve, added = e.get("cveID"), e.get("dateAdded")
        if not cve or not added:
            continue
        date_added_of[cve] = added
        rec = cache.get(cve)
        if rec and rec.get("date_added") == added and rec.get("percentile") is not None:
            continue
        qd = (date.fromisoformat(added) - timedelta(days=1)).isoformat()
        by_query_date[qd].append(cve)

    total_dates = len(by_query_date)
    print(f"[plan] 照会対象日数: {total_dates}（キャッシュ済み {len(cache)} 件を除く）")

    for i, qd in enumerate(sorted(by_query_date), 1):
        cves = by_query_date[qd]
        scores = {}
        got_422 = False
        for j in range(0, len(cves), 100):
            batch = fetch_epss_batch(cves[j : j + 100], qd)
            if batch is None:
                got_422 = True
            else:
                scores.update(batch)
            time.sleep(REQUEST_INTERVAL_SEC)
        for cve in cves:
            hit = scores.get(cve)
            rec = {
                "cve": cve,
                "date_added": date_added_of[cve],
                "query_date": qd,
                "model_era": model_era(qd),
                "epss": hit.get("epss") if hit else None,
                "percentile": hit.get("percentile") if hit else None,
            }
            if hit is None:
                rec["no_score_reason"] = (
                    "http_422" if got_422 else "not_scored_on_date"
                )
            cache[cve] = rec
            if cache_f:
                cache_f.write(json.dumps(rec) + "\n")
                cache_f.flush()
        if i % 25 == 0 or i == total_dates:
            print(f"[progress] {i}/{total_dates} 日分照会済み")

    if cache_f:
        cache_f.close()

    # 集計は現行カタログに存在する CVE のみ（KEV から削除されたエントリの
    # 古いキャッシュを母集団に混入させない）
    entries = sorted(
        (
            cache[c]
            for c in date_added_of
            if c in cache and cache[c].get("date_added") == date_added_of[c]
        ),
        key=lambda r: (r["date_added"], r["cve"]),
    )
    measured = [r for r in entries if r["percentile"] is not None]
    no_score = [r for r in entries if r["percentile"] is None]

    # 鮮度層: NVD 公開→KEV追加ラグで層別（遡及登録された古い CVE は前日 EPSS が
    # 高くて当然であり、感度を上振れさせる。M3 が実際に適用される「新規公開直後の
    # CVE への予報」に近いのは fresh 層である）
    published_of = {}
    if args.nvd_file:
        for v in json.load(open(args.nvd_file)).get("vulnerabilities", []):
            cve_obj = v.get("cve", {})
            pub = (cve_obj.get("published") or "")[:10]
            if pub:
                published_of[cve_obj.get("id")] = pub

    def freshness(r):
        pub = published_of.get(r["cve"])
        if not pub:
            return "unknown"
        lag = (date.fromisoformat(r["date_added"]) - date.fromisoformat(pub)).days
        if lag < 0:
            return "negative_lag_zero_day_type"
        if lag <= 30:
            return "fresh_lag_le_30d"
        if lag <= 365:
            return "lag_31_365d"
        return "lag_gt_365d"

    by_era = defaultdict(lambda: ([], 0))
    by_year = defaultdict(lambda: ([], 0))
    by_fresh = defaultdict(lambda: ([], 0))
    for r in entries:
        buckets = [(r["model_era"], by_era), (r["date_added"][:4], by_year)]
        if published_of:
            buckets.append((freshness(r), by_fresh))
        for key, bucket in buckets:
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
            "pre/post の別（最重要）: 本統計は KEV 追加前日の値＝『追加の事前予見可能性』"
            "の感度である。M3 が運用上参照するのは KEV 登録後の EPSS 値であり、EPSS v3+ は"
            "KEV 収載自体を特徴量に含むため登録後の値は事後的に押し上がる。運用条件の"
            "充足率は本統計より高く、前日感度の低さを根拠に閾値 0.95 を引き下げるのは"
            "カテゴリエラーであり単独根拠として使用禁止。",
            "前日測定: 前日値の採用は EPSS の KEV 特徴量反応（as-of 汚染）の回避が目的。"
            "ただし前日値にも KEV 追加の引き金となった悪用証拠自体は反映されうる"
            "（それは意図した測定である）。また CISA が KEV 追加に先立ち同一 CVE の"
            "アラートを出す場合、EPSS の『リスト掲載・言及』特徴が先に反応する部分循環が"
            "残る（頻度は低い）。",
            "上振れ推定: E1 予報は追加の72時間以上前に発行されうる。EPSS は悪用証拠に"
            "日次で反応するため、追加前日の値は予報発行時点で観測できた値の上振れ側の"
            "推定である。",
            "遡及登録の混合: 公開から年単位で悪用されてきた CVE の前日 EPSS が高いのは"
            "自明であり、全体感度を上振れさせる。M3 が実際に適用される『新規公開直後の"
            "CVE への予報』の較正には by_freshness の fresh_lag_le_30d 層を主参照とする。",
            "モデル版差: EPSS モデル切替（v1/v2/v3/v4）で順位付けに使う特徴量とスコア"
            "モデルが変わるため by_model_era で層別した。現行運用には v4（2025-03-17以降）"
            "層を優先参照する（n が小さい場合はその旨を明記して扱う）。",
            "no_score: 照会日に EPSS スコアが存在しない CVE。大半は NVD 収録前に KEV "
            "追加されたゼロデイ型で、この欠測は無作為ではなく『公開前に悪用された事例』に"
            "偏るため、感度の分母からの除外はやや楽観方向のバイアスを持つ。"
            "no_score_reason（http_422 / not_scored_on_date）の内訳を population に併記。",
            "KEV 削除エントリ: 集計は現行カタログ収載分のみ。過去に収載後削除された"
            "エントリ（誤収載等）は母集団から欠落する。",
            "用途制限: M3 の EPSS 条件の感度実測・base_rate_estimate の参考に限る。"
            "hit_criteria の変更・確度の引き上げ根拠には使わない。",
        ],
        "population": {
            "kev_catalog_total": len(kev.get("vulnerabilities", [])),
            "aggregated": len(entries),
            "measured": len(measured),
            "no_score": len(no_score),
            "no_score_reasons": {
                reason: sum(
                    1 for r in no_score if r.get("no_score_reason", "unknown") == reason
                )
                for reason in sorted(
                    {r.get("no_score_reason", "unknown") for r in no_score}
                )
            },
        },
        "overall": summarize([r["percentile"] for r in measured], len(no_score)),
        "by_freshness": (
            {
                k: summarize(vals, miss)
                for k, (vals, miss) in sorted(by_fresh.items())
            }
            if published_of
            else {
                "_note": "--nvd-file 未指定のため鮮度層クロスなし。M3 較正には鮮度層が必須。"
            }
        ),
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
