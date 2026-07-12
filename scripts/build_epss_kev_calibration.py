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
  正確な定義・限界は出力 JSON の _limitations が正。

測定日を dateAdded の前日とする理由:
  EPSS（v3 以降）は CISA KEV 収載を入力特徴の一つとして使用するため、追加当日以降の
  スコアは KEV 追加自体に反応した事後値になりうる。前日値を使うことで
  「予報者が KEV 追加前に観測できた値」を再現する（as-of 汚染の防止）。

設計原則:
  - 出力は forecaster/knowledge/ の機械生成ファイル。自動書き換え禁止ルールに従い、
    再生成は日次ルーチンからは行わず PR 提案+人間レビュー経由のみ。
  - サマリー統計は epss-kev-calibration.json（日次予報ステージが読む・小サイズ）、
    全件の実測値（監査証跡）は epss-kev-calibration-entries.json に分離する。
  - EPSS モデル版（v1/v2/v3/v4）と鮮度（NVD公開→KEV追加ラグ）で層別する。
    鮮度層は必須（NVD データは --nvd-file 省略時ネット取得）。

入力:
  - CISA KEV catalog（--kev-file 指定またはネット取得）
  - NVD API hasKev 一括照会（--nvd-file 指定またはネット取得。鮮度層に必須）
  - FIRST EPSS API（https://api.first.org/data/v1/epss・日付指定履歴照会）

出力:
  forecaster/knowledge/epss-kev-calibration.json（サマリー）
  forecaster/knowledge/epss-kev-calibration-entries.json（全件監査証跡）

使い方:
    python3 scripts/build_epss_kev_calibration.py \
        --kev-file kev.json --nvd-file nvd-kev.json --cache /path/to/epss-cache.jsonl
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import date, timedelta

from kev_data_sources import fetch_json, load_kev, load_nvd_kev_vulnerabilities, percentile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(
    REPO_ROOT, "forecaster", "knowledge", "epss-kev-calibration.json"
)
ENTRIES_OUT_PATH = os.path.join(
    REPO_ROOT, "forecaster", "knowledge", "epss-kev-calibration-entries.json"
)

EPSS_API = "https://api.first.org/data/v1/epss"

# EPSS モデル版の適用開始日（FIRST 公表のモデル切替日）。
# 層別は測定日（query_date = dateAdded の前日）で行う: 測定値を生成したモデルで
# 分類するのが正であり、dateAdded 基準とは境界が1日ずれる（_limitations 参照）。
MODEL_ERAS = [
    ("2025-03-17", "v4"),
    ("2023-03-07", "v3"),
    ("2022-02-04", "v2"),
    ("2021-04-14", "v1"),
]

THRESHOLDS = [0.95, 0.90, 0.75, 0.50]
REQUEST_INTERVAL_SEC = 0.6
MAX_RETRIES = 4
MIN_SAMPLE_PER_STRATUM = 10
FRESH_LAG_MAX_DAYS = 30


def model_era(query_date):
    for start, name in MODEL_ERAS:
        if query_date >= start:
            return name
    return "pre_epss"


def fetch_epss_batch(cves, query_date):
    """指定日の EPSS を複数 CVE 一括照会する。

    戻り値: {cve: {epss, percentile}}（応答に無い CVE はキー欠落）。
    HTTP 422（No records available）の場合は None を返す — 呼び出し元は
    そのバッチ全体を no_score_reason: http_422 として記録すること。"""
    params = urllib.parse.urlencode({"cve": ",".join(cves), "date": query_date})
    url = f"{EPSS_API}?{params}"
    for attempt in range(MAX_RETRIES):
        try:
            data = fetch_json(url, timeout=60, user_agent="pythia-epss-cal/1.0")
            return {
                d["cve"]: {
                    "epss": float(d["epss"]),
                    "percentile": float(d["percentile"]),
                }
                for d in data.get("data", [])
            }
        except urllib.error.HTTPError as e:
            # 422 は実測上「照会した全CVEがその日に未収録」（NVD収録前にKEV追加
            # されたゼロデイ等）で返るが、公式に文書化された仕様ではないため
            # 警告ログを残し、恒久キャッシュはしない（再実行時に再照会される）。
            if e.code == 422:
                print(
                    f"[warn] EPSS 422 No records: date={query_date} "
                    f"cves={len(cves)}件（no_score_reason: http_422 として記録）"
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


def summarize(percentiles, n_no_score, flag_insufficient=False):
    n = len(percentiles)
    out = {"n_measured": n, "n_no_score": n_no_score}
    if n == 0:
        return out
    s = sorted(percentiles)
    out["median_percentile"] = percentile(s, 50, ndigits=4)
    out["p25_percentile"] = percentile(s, 25, ndigits=4)
    for t in THRESHOLDS:
        # キー名を2桁固定（pct_ge_0.90）にする。f"{0.90}" は "0.9" になり
        # 下流が pct_ge_0.90 を期待すると None を踏むため。
        out[f"pct_ge_{t:.2f}"] = round(sum(1 for x in s if x >= t) / n, 3)
    if flag_insufficient and n < MIN_SAMPLE_PER_STRATUM:
        out["insufficient_sample"] = True
        out["note"] = (
            f"n_measured<{MIN_SAMPLE_PER_STRATUM} のため参考値。単独で判断根拠にしない。"
        )
    return out


def group_stats(records_by_key):
    """{key: [record]} から {key: summarize(...)} を作る（層別は不足フラグ付き）。"""
    out = {}
    for key in sorted(records_by_key, key=str):
        recs = records_by_key[key]
        vals = [r["percentile"] for r in recs if r["percentile"] is not None]
        miss = sum(1 for r in recs if r["percentile"] is None)
        out[str(key)] = summarize(vals, miss, flag_insufficient=True)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="KEV 追加前日時点の EPSS パーセンタイル分布を実測する。"
    )
    ap.add_argument("--kev-file", help="KEV catalog JSON のローカルパス（省略時はネット取得）")
    ap.add_argument("--cache", help="実測値キャッシュ（JSONL・レジューム用）")
    ap.add_argument(
        "--nvd-file",
        help="NVD hasKev 応答 JSON のローカルパス（省略時はネット取得。鮮度層に必須のため常に読み込む）",
    )
    ap.add_argument("--out", default=OUT_PATH, help=f"出力先（既定: {OUT_PATH}）")
    ap.add_argument(
        "--entries-out",
        default=ENTRIES_OUT_PATH,
        help=f"全件監査証跡の出力先（既定: {ENTRIES_OUT_PATH}）",
    )
    args = ap.parse_args()

    kev = load_kev(args.kev_file)
    catalog_version = kev.get("catalogVersion", "unknown")

    # 鮮度層に使う NVD 公開日（必須入力: --nvd-file 省略時はネット取得）
    published_of = {}
    for v in load_nvd_kev_vulnerabilities(args.nvd_file):
        cve_obj = v.get("cve", {})
        pub = (cve_obj.get("published") or "")[:10]
        if pub:
            published_of[cve_obj.get("id")] = pub

    cache = load_cache(args.cache)
    cache_f = open(args.cache, "a") if args.cache else None

    # dateAdded ごとにまとめ、前日を照会日とする。
    # キャッシュは (a) 現行カタログに存在し (b) date_added が一致し、かつ
    # (c) 実測値あり または 恒久欠測（not_scored_on_date）の場合に採用する。
    # http_422 由来の欠測（API仕様が非公式・一時異常の可能性）のみ再照会する。
    by_query_date = defaultdict(list)
    date_added_of = {}
    reused = 0
    for e in kev.get("vulnerabilities", []):
        cve, added = e.get("cveID"), e.get("dateAdded")
        if not cve or not added:
            continue
        date_added_of[cve] = added
        rec = cache.get(cve)
        if (
            rec
            and rec.get("date_added") == added
            and (
                rec.get("percentile") is not None
                or rec.get("no_score_reason") == "not_scored_on_date"
            )
        ):
            reused += 1
            continue
        qd = (date.fromisoformat(added) - timedelta(days=1)).isoformat()
        by_query_date[qd].append(cve)

    total_dates = len(by_query_date)
    print(f"[plan] 照会対象日数: {total_dates}（キャッシュ再利用 {reused} 件）")

    for i, qd in enumerate(sorted(by_query_date), 1):
        cves = by_query_date[qd]
        scores = {}
        cves_in_422_batch = set()  # 422 はバッチ単位で帰属させる（日単位にしない）
        for j in range(0, len(cves), 100):
            batch = cves[j : j + 100]
            result = fetch_epss_batch(batch, qd)
            if result is None:
                cves_in_422_batch.update(batch)
            else:
                scores.update(result)
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
                    "http_422" if cve in cves_in_422_batch else "not_scored_on_date"
                )
            cache[cve] = rec
            if cache_f:
                cache_f.write(json.dumps(rec) + "\n")
        if cache_f:
            cache_f.flush()
        if i % 25 == 0 or i == total_dates:
            print(f"[progress] {i}/{total_dates} 日分照会済み")

    if cache_f:
        cache_f.close()

    # 集計は現行カタログに存在する CVE のみ（削除エントリの古いキャッシュを除外）
    entries = sorted(
        (cache[c] for c in date_added_of if c in cache),
        key=lambda r: (r["date_added"], r["cve"]),
    )
    measured = [r for r in entries if r["percentile"] is not None]
    no_score = [r for r in entries if r["percentile"] is None]

    def freshness(r):
        pub = published_of.get(r["cve"])
        if not pub:
            return "unknown"
        lag = (date.fromisoformat(r["date_added"]) - date.fromisoformat(pub)).days
        if lag < 0:
            return "negative_lag_zero_day_type"
        if lag <= FRESH_LAG_MAX_DAYS:
            return "fresh_lag_le_30d"
        if lag <= 365:
            return "lag_31_365d"
        return "lag_gt_365d"

    by_era = defaultdict(list)
    by_year = defaultdict(list)
    by_fresh = defaultdict(list)
    by_fresh_v4 = defaultdict(list)  # 鮮度×v4測定のクロス（M3 主参照層）
    for r in entries:
        by_era[r["model_era"]].append(r)
        by_year[r["date_added"][:4]].append(r)
        fr = freshness(r)
        by_fresh[fr].append(r)
        if r["model_era"] == "v4":
            by_fresh_v4[fr].append(r)

    out = {
        "_comment": (
            "KEV 追加前日時点の EPSS パーセンタイル実測分布（M3 確度アンカー較正データ）。"
            "測っているのは P(EPSS%ile≥τ | 翌日KEV追加)＝M3 の EPSS 条件の感度であり、"
            "P(KEV追加 | EPSS%ile≥τ) ではない。下記 _limitations 厳守。"
            "全件の実測値（監査証跡）は epss-kev-calibration-entries.json に分離。"
        ),
        "_schema_version": "1.1",
        "_machine_generated": True,
        "_generator": "scripts/build_epss_kev_calibration.py",
        "_generated_on": date.today().isoformat(),
        "_source": {
            "kev_catalog_version": catalog_version,
            "epss_api": EPSS_API,
            "measurement": "dateAdded の前日時点の EPSS（履歴照会）",
            "entries_file": "forecaster/knowledge/epss-kev-calibration-entries.json",
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
            "遡及登録の混合と主参照層: 公開から年単位で悪用されてきた CVE の前日 EPSS が"
            "高いのは自明であり、全体感度を上振れさせる。較正の主参照は "
            "by_freshness_v4_era.fresh_lag_le_30d（現行モデル v4 での測定×新規公開30日"
            "以内）。同層が insufficient_sample の場合は by_freshness.fresh_lag_le_30d"
            "（全期間・モデル版混合）と by_model_era.v4 を併読し、限界を明記して使う。",
            "モデル版の層別基準: by_model_era は測定日（query_date = dateAdded の前日）が"
            "属するモデル版で層別した（測定値を生成したモデルで分類するのが正）。"
            "dateAdded 基準の解釈とは各切替日で1日ずれる（例: dateAdded=2025-03-17 の"
            "エントリの測定日は 2025-03-16 で v3 層に入る）。",
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
            "no_score_reasons": dict(
                sorted(
                    Counter(
                        r.get("no_score_reason", "unknown") for r in no_score
                    ).items()
                )
            ),
        },
        "overall": summarize([r["percentile"] for r in measured], len(no_score)),
        "by_freshness_v4_era": {
            "_note": (
                "M3 較正の主参照層: 測定日が EPSS v4 期（2025-03-17以降）×鮮度別。"
                "insufficient_sample の層は by_freshness / by_model_era.v4 を併読。"
            ),
            **group_stats(by_fresh_v4),
        },
        "by_freshness": group_stats(by_fresh),
        "by_model_era": group_stats(by_era),
        "by_year_added": group_stats(by_year),
    }
    entries_out = {
        "_comment": (
            "epss-kev-calibration.json の全件実測値（監査証跡）。"
            "サマリー統計の再検証・監査専用であり、日次予報ステージの入力ではない。"
        ),
        "_schema_version": "1.1",
        "_machine_generated": True,
        "_generator": "scripts/build_epss_kev_calibration.py",
        "_generated_on": date.today().isoformat(),
        "_summary_file": "forecaster/knowledge/epss-kev-calibration.json",
        "_governance": (
            "knowledge/ の自動書き換え禁止ルールに従い、再生成は PR 提案+人間レビュー経由のみ。"
        ),
        "entries": entries,
    }
    with open(args.out, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
        f.write("\n")
    with open(args.entries_out, "w") as f:
        json.dump(entries_out, f, ensure_ascii=False, indent=2)
        f.write("\n")
    o = out["overall"]
    print(
        f"[done] {os.path.relpath(args.out, REPO_ROOT)}: "
        f"measured={len(measured)} no_score={len(no_score)}"
    )
    fresh_v4 = out["by_freshness_v4_era"].get("fresh_lag_le_30d", {})
    print(
        f"[overall] median%ile={o.get('median_percentile')} "
        f"ge0.95={o.get('pct_ge_0.95')} ge0.90={o.get('pct_ge_0.90')} | "
        f"v4×fresh: n={fresh_v4.get('n_measured')} ge0.95={fresh_v4.get('pct_ge_0.95')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
