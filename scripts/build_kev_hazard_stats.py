#!/usr/bin/env python3
"""E1（CISA KEV 初回追加）の窓内発生率を、母集団を明示して機械実測する。

背景（2026-08-07 の精度分析・PR #126 の後続）:
  PR #126 で E3 の実測ハザード（0.015）を測り M1-b 頻度ゲートを新設した際、
  E1 の判定値には `kev-leadtime-stats.json` の `pct_within_3d`（0.30）を暫定採用した。
  しかし同値は時間原点が NVD 公開日であり、かつ「最終的に KEV へ追加された CVE」に
  条件付けられている（生存バイアス）ため、E3 の 0.015 とは**別の量**である。
  本スクリプトは E1 を E3 と同じ形式（リスク集合 → 窓 → 初回発火）で測り直す。

★本スクリプトが明らかにする最重要の論点:
  「ベースレート」はチャネル単体の性質ではなく、**チャネル × 条件付け**の性質である。
  同じ E1 でも、母集団を「EPSS 上位の全 CVE」に取るか「予報候補として実悪用証拠が
  観測された CVE」に取るかで、窓内発生率は3桁変わる。したがって以下の2つの量を
  混同してはならない（PR #126 はこれを混同していた。詳細は _limitations 参照）:

    (1) p_channel（M1-b 頻度ゲートの判定値）
        = P(イベントが窓内 | Pythia が予報を発行する条件)
        予報を出す価値があるかの判定に使う。本スクリプトは測らない
        （内部実績＝verification 記録が唯一の直接推定であり、集計は
        summarize_internal_channel_rates() で行う）。
    (2) base_rate（予報の情報量測定の基準）
        = P(イベントが窓内 | 予報のスキルなし＝広い候補母集団)
        「その予報がベースレート対比でどれだけ優れているか」の分母に使う。
        本スクリプトが測るのはこちらである。

測るもの:
  サンプル日 D ごとに、
    リスク集合 = EPSS スナップショット D で層の条件を満たし、かつ D 時点で KEV 未収載の CVE
    発火        = KEV 初回追加日が [D+1, D+3]（fast_72h の検証窓）に入る
  を数え、全サンプル日でプールしてハザードを算出する。

測らないもの:
  - P(KEV追加|公開) の全 CVE 母集団版（EPSS 層別なしの値）。
  - 「実悪用確認→KEV追加」ラグ（kev-initial-add-timelines.json の対象）。
  - 予報の主題選別スキルそのもの（内部実績との差分として事後に現れる）。

設計原則:
  - 日付スタンプ付き一次データのみ（EPSS 日次スナップショット / KEV dateAdded）。
  - サンプル日は週次固定間隔。検証窓が3日なので週次なら窓が重ならず、
    サンプル間の独立性が保たれる（日次サンプリングは窓が重複し分散を過小評価する）。
  - 出力は forecaster/knowledge/ の機械生成ファイル。knowledge/ の自動書き換え禁止
    （行動原則5）に従い、再生成は日次ルーチンからは行わず PR 提案+人間レビュー経由のみ。

入力:
  - EPSS 日次スナップショット https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz
  - CISA KEV catalog（--kev-file 指定またはネット取得）
  - forecaster/verification/YYYY-MM.json（内部実績のチャネル別集計）

出力:
  forecaster/knowledge/kev-hazard-stats.json

使い方:
    python3 scripts/build_kev_hazard_stats.py --start 2025-08-01 --end 2026-08-01 \
        --cache-dir /tmp/epss-cache
"""

import argparse
import glob
import gzip
import json
import os
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import date, datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kev_data_sources import KEV_FEED_URL, load_kev

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(REPO_ROOT, "forecaster", "knowledge", "kev-hazard-stats.json")
VERIFICATION_GLOB = os.path.join(REPO_ROOT, "forecaster", "verification", "*.json")

EPSS_SNAPSHOT_URL = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
USER_AGENT = "pythia-calibration/1.0"

FAST_WINDOW_DAYS = 3
SAMPLE_INTERVAL_DAYS = 7  # 窓（3日）が重ならない最小間隔。独立サンプルを保つ
JUMP_LOOKBACK_DAYS = 7  # EPSS 急騰層の比較元スナップショット
MIN_FIRED_FOR_STABLE = 10  # ハザードを「安定」と見なす最小発火数


# --------------------------------------------------------------------------
# データ取得
# --------------------------------------------------------------------------


def fetch_snapshot(d, cache_dir):
    """EPSS 日次スナップショットを {cve: (score, percentile)} で返す。取得失敗は None。"""
    ds = d.isoformat()
    path = os.path.join(cache_dir, f"epss-{ds}.csv.gz") if cache_dir else None
    if not path or not os.path.exists(path):
        url = EPSS_SNAPSHOT_URL.format(d=ds)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=120) as resp:
                blob = resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            print(f"[warn] EPSS スナップショット取得失敗 {ds}: {exc}", file=sys.stderr)
            return None
        if path:
            os.makedirs(cache_dir, exist_ok=True)
            with open(path, "wb") as f:
                f.write(blob)
        raw = gzip.decompress(blob).decode("utf-8", errors="replace").splitlines()
    else:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            raw = f.read().splitlines()

    out = {}
    for line in raw:
        if not line or line.startswith("#") or line.startswith("cve,"):
            continue
        parts = line.split(",")
        if len(parts) != 3:
            continue
        try:
            out[parts[0]] = (float(parts[1]), float(parts[2]))
        except ValueError:
            continue
    return out or None


def kev_first_added(kev):
    """{CVE-ID: 初回 dateAdded}。同一CVEの重複エントリは最も早い日付を採る。"""
    out = {}
    for e in kev.get("vulnerabilities", []):
        cve = e.get("cveID")
        d = (e.get("dateAdded") or "")[:10]
        if cve and d and (cve not in out or d < out[cve]):
            out[cve] = d
    return out


# --------------------------------------------------------------------------
# 層の定義
# --------------------------------------------------------------------------


def build_strata(snapshot, prev_snapshot, sample_date):
    """層名 -> リスク集合候補（KEV 未収載条件は呼び出し側で適用）を返す。

    層は「Pythia の予報候補にどれだけ近いか」の順に並べる。上ほど広く（＝ベースレートが
    低く）、下ほど条件付けが強い（＝予報の発行条件に近い）。
    """
    strata = {
        "epss_pctile_ge_0.90": [c for c, v in snapshot.items() if v[1] >= 0.90],
        "epss_pctile_ge_0.95": [c for c, v in snapshot.items() if v[1] >= 0.95],
        "epss_pctile_ge_0.99": [c for c, v in snapshot.items() if v[1] >= 0.99],
        "epss_score_ge_0.5": [c for c, v in snapshot.items() if v[0] >= 0.5],
    }
    # CVE 採番年による新しさ層（NVD 公開日を引かずに済む粗い近似）
    fresh_years = {str(sample_date.year), str(sample_date.year - 1)}
    strata["epss_pctile_ge_0.95_cve_year_recent"] = [
        c
        for c, v in snapshot.items()
        if v[1] >= 0.95 and len(c.split("-")) > 1 and c.split("-")[1] in fresh_years
    ]

    # EPSS 急騰層: 直近 JUMP_LOOKBACK_DAYS で score が大きく上昇した CVE。
    # 「新たな悪用情報が出た」ことの外部プロキシであり、Pythia の発行条件に最も近い。
    if prev_snapshot:
        jump = []
        for c, v in snapshot.items():
            old = prev_snapshot.get(c)
            if old is not None and v[0] - old[0] >= 0.20:
                jump.append(c)
        strata["epss_score_jump_ge_0.20_in_7d"] = jump
    return strata


# --------------------------------------------------------------------------
# 集計
# --------------------------------------------------------------------------


def measure(sample_dates, kadd, cache_dir):
    """サンプル日ごとに層別のリスク集合と発火数を数え、プール集計する。"""
    pooled = defaultdict(lambda: {"risk": 0, "fired": 0, "sample_days": 0})
    per_day = []
    snapshots = {}

    for d in sample_dates:
        snap = snapshots.get(d) or fetch_snapshot(d, cache_dir)
        if not snap:
            continue
        snapshots[d] = snap
        prev_d = d - timedelta(days=JUMP_LOOKBACK_DAYS)
        prev = snapshots.get(prev_d) or fetch_snapshot(prev_d, cache_dir)
        if prev:
            snapshots[prev_d] = prev

        ds = d.isoformat()
        window = {(d + timedelta(days=i)).isoformat() for i in range(1, FAST_WINDOW_DAYS + 1)}

        day_row = {"date": ds, "strata": {}}
        for name, cves in build_strata(snap, prev, d).items():
            # リスク集合: サンプル日時点で KEV 未収載（＝まだ発火していない）
            risk = [c for c in cves if not (c in kadd and kadd[c] <= ds)]
            fired = [c for c in risk if kadd.get(c) in window]
            pooled[name]["risk"] += len(risk)
            pooled[name]["fired"] += len(fired)
            pooled[name]["sample_days"] += 1
            day_row["strata"][name] = {"risk": len(risk), "fired": len(fired)}
        per_day.append(day_row)

        # メモリ節約: 2世代より古いスナップショットは破棄する
        for k in [k for k in snapshots if k < prev_d]:
            del snapshots[k]

    result = {}
    for name, v in pooled.items():
        hz = v["fired"] / v["risk"] if v["risk"] else None
        result[name] = {
            "sample_days": v["sample_days"],
            "risk_set_total": v["risk"],
            "risk_set_mean_per_day": round(v["risk"] / v["sample_days"], 1)
            if v["sample_days"]
            else None,
            "fired_total": v["fired"],
            "hazard": round(hz, 7) if hz is not None else None,
            "stable": v["fired"] >= MIN_FIRED_FOR_STABLE,
            "_stable_note": (
                f"fired_total >= {MIN_FIRED_FOR_STABLE} を安定の目安とする。"
                "下回る層の hazard は点推定の信頼区間が広く、桁の目安としてのみ読む。"
            ),
        }
    return result, per_day


def summarize_internal_channel_rates():
    """verification 記録から出口チャネル別の内部実績を集計する。

    これが p_channel（M1-b の判定値＝Pythia の発行条件を条件とする窓内発生率）の
    唯一の直接推定である。外部測定（本スクリプトの hazard）は母集団が異なるため
    p_channel の代替にはならない。
    """
    by_channel = defaultdict(lambda: {"total": 0, "hit": 0, "partial": 0, "miss": 0})
    for path in sorted(glob.glob(VERIFICATION_GLOB)):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for e in data.get("entries", []):
            ch = e.get("outcome_channel")
            if not ch:
                continue
            row = by_channel[ch]
            row["total"] += 1
            outcome = e.get("outcome")
            if outcome in ("hit", "partial", "miss"):
                row[outcome] += 1

    out = {}
    for ch, row in sorted(by_channel.items()):
        n = row["total"]
        out[ch] = dict(
            row,
            hit_rate_strict=round(row["hit"] / n, 4) if n else None,
            hit_rate_including_partial=round((row["hit"] + row["partial"]) / n, 4)
            if n
            else None,
            wilson_95ci=wilson(row["hit"], n) if n else None,
        )
    return out


def wilson(k, n, z=1.96):
    """Wilson 95% 信頼区間。小標本で正規近似より妥当。"""
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    center = (p + z * z / (2 * n)) / d
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return [round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)]


# --------------------------------------------------------------------------
# 出力
# --------------------------------------------------------------------------


def build_document(strata_stats, per_day, internal, kev, sample_dates):
    return {
        "_comment": (
            "E1（CISA KEV 初回追加）の窓内発生率を母集団を明示して実測したもの。"
            "★『ベースレート』はチャネル単体の性質ではなく チャネル×条件付け の性質である。"
            "本ファイルの hazard は『広い候補母集団を条件とする発生確率』＝ base_rate であり、"
            "M1-b 頻度ゲートの判定値 p_channel（＝Pythia の発行条件を条件とする発生確率）とは"
            "別の量である。両者を混同してはならない（_limitations 参照）。"
        ),
        "_schema_version": "1.0",
        "_machine_generated": True,
        "_generator": "scripts/build_kev_hazard_stats.py",
        "_generated_on": date.today().isoformat(),
        "_source": {
            "epss_snapshots": EPSS_SNAPSHOT_URL,
            "kev_feed": KEV_FEED_URL,
            "kev_catalog_version": kev.get("catalogVersion"),
            "sample_dates_first": sample_dates[0].isoformat() if sample_dates else None,
            "sample_dates_last": sample_dates[-1].isoformat() if sample_dates else None,
            "sample_interval_days": SAMPLE_INTERVAL_DAYS,
            "window_days": FAST_WINDOW_DAYS,
        },
        "_governance": (
            "knowledge/ の自動書き換え禁止ルール（行動原則5）に従い、再生成は日次ルーチンからは"
            "行わず、必ず PR として提案し人間レビューを経てコミットする。"
        ),
        "_definitions": {
            "risk_set": (
                "サンプル日 D の EPSS スナップショットで層の条件を満たし、かつ D 時点で"
                "KEV 未収載（＝まだ発火していない）CVE。E3 の advisory-cadence-stats.json と"
                "同じ『未発火条件付き』の考え方である。"
            ),
            "fired": f"KEV 初回追加日が [D+1, D+{FAST_WINDOW_DAYS}] に入ること。",
            "hazard": "fired_total / risk_set_total（全サンプル日でプール）。",
            "p_channel_vs_base_rate": (
                "p_channel = P(窓内発火 | Pythia の発行条件)。M1-b 頻度ゲートの判定値。"
                "本ファイルでは internal_channel_rates が唯一の直接推定。"
                "base_rate = P(窓内発火 | 広い候補母集団・予報スキルなし)。"
                "本ファイルの strata[].hazard がこれに当たる。"
                "両者の比が予報の情報量（スキル）である。"
            ),
        },
        "_limitations": [
            "★最重要: 本ファイルの hazard を M1-b 頻度ゲートの p_channel に代入してはならない。"
            "母集団が『EPSS 上位の全 CVE』であり、Pythia が予報を発行する条件"
            "（今日の調査で実悪用証拠・PoC公開・ベンダー勧告を確認した CVE）とは大きく異なる。"
            "代入すると全 E1 予報がゲートを通らなくなるが、それは E1 が機能していない"
            "ことを意味しない（内部実績 internal_channel_rates.E1 を参照）。",
            "PR #126 では E1 の p_channel に kev-leadtime-stats.json の pct_within_3d（0.30）を"
            "暫定採用したが、同値は時間原点が NVD 公開日で生存バイアス条件付き（KEV 追加が"
            "確定した集合）であり、本ファイルの hazard とも E3 の 0.015 とも異なる第3の量である。"
            "3者を同一表で比較することはできない。",
            "EPSS 層は Pythia の予報候補の近似として粗い。EPSS は30日窓・グローバル指標であり、"
            "『今日新たに悪用証拠が出た』という時間的条件を持たない。"
            "epss_score_jump_ge_0.20_in_7d 層はその時間的条件を近似する試みだが、"
            "EPSS モデルの更新（model_version 変更時の一斉再計算）でも急騰が発生するため"
            "悪用証拠の出現と1対1ではない。",
            "EPSS のモデル版はサンプル期間内で変わりうる（スナップショット1行目の"
            "model_version 参照）。版跨ぎでスコア分布が不連続に変わるため、"
            "percentile 層は版に対して比較的頑健だが score 層・jump 層は影響を受ける。",
            "サンプルは週次固定間隔であり、KEV 追加の曜日偏り（CISA は平日に追加する）と"
            "位相が固定される。曜日を変えた再測定で hazard が変動しうる。",
            "fired_total が少ない層（stable=false）の hazard は点推定の信頼区間が広い。"
            "桁の目安としてのみ読み、閾値判定の根拠にしない。",
            "本統計は的中条件（hit_criteria）を緩める根拠には使用禁止（原則D・教訓12）。"
            "使ってよいのは base_rate_estimate の情報量測定と、母集団依存性の documentation のみ。",
        ],
        "strata": strata_stats,
        "internal_channel_rates": {
            "_note": (
                "verification 記録から集計した出口チャネル別の内部実績。"
                "★これが p_channel（M1-b の判定値）の唯一の直接推定である。"
                "n が小さく信頼区間は広いので wilson_95ci を必ず併読すること。"
            ),
            "channels": internal,
        },
        "per_sample_day": per_day,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--start", default="2025-08-01", help="サンプル開始日 YYYY-MM-DD")
    ap.add_argument("--end", default=date.today().isoformat(), help="サンプル終了日 YYYY-MM-DD")
    ap.add_argument("--kev-file", help="CISA KEV catalog のローカルパス")
    ap.add_argument("--cache-dir", help="EPSS スナップショットのディスクキャッシュ")
    ap.add_argument("--out", default=OUT_PATH)
    args = ap.parse_args()

    start = datetime.strptime(args.start, "%Y-%m-%d").date()
    end = datetime.strptime(args.end, "%Y-%m-%d").date()
    sample_dates = []
    d = start
    while d <= end:
        sample_dates.append(d)
        d += timedelta(days=SAMPLE_INTERVAL_DAYS)
    print(f"[sample] {len(sample_dates)} 日（週次・{start} 〜 {sample_dates[-1]}）")

    kev = load_kev(args.kev_file)
    kadd = kev_first_added(kev)
    print(f"[kev] 収載 {len(kadd)} CVE")

    strata_stats, per_day = measure(sample_dates, kadd, args.cache_dir)
    if not per_day:
        raise SystemExit("[fatal] EPSS スナップショットを1日も取得できませんでした。")

    internal = summarize_internal_channel_rates()
    doc = build_document(strata_stats, per_day, internal, kev, sample_dates)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print(f"\n[out] {args.out}")
    print("  外部測定（広い候補母集団＝base_rate）:")
    for name, v in sorted(strata_stats.items(), key=lambda x: -(x[1]["hazard"] or 0)):
        flag = "" if v["stable"] else "  ※fired少・桁の目安のみ"
        print(
            f"    {name:36s} hazard={v['hazard']:.7f} "
            f"(risk {v['risk_set_total']:,} / fired {v['fired_total']}){flag}"
        )
    print("  内部実績（Pythia の発行条件＝p_channel）:")
    for ch, v in doc["internal_channel_rates"]["channels"].items():
        print(
            f"    {ch}: {v['hit']}/{v['total']} = {v['hit_rate_strict']} "
            f"95%CI {v['wilson_95ci']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
