#!/usr/bin/env python3
"""類似過去事例検索（Case-Based Retrieval）の較正データ収集器。

検証ステージ（04-verify.md 手順8c）から呼び、確定した各予報について
forecaster/case-based-retrieval-design.md §8（ホールドアウト較正）に必要なデータを
forecaster/verification/retrieval-calibration.json へ凍結保存する。将来の閾値
（min_similarity）・最小サンプル数・スコア重みの見直しの一次データになる。

各レコードに保存するもの:
- 実際の的中結果（realized_outcome / realized_hit_binary）
- 発行時サイドカーの retrieval 集計（あれば凍結。retrieval_present_at_issue でアーム分け）
- 発行日as-ofで retrieve_similar_cases.py を min_similarity=0 で再実行した決定論的再計算
  （閾値未満も含む全ランク・各事例の similarity と実績 outcome と一致要素）

決定論的再計算は『過去事例のみ対象』のため遡及的にも有効で、本機能導入前の予報にも
付与できる（＝既存の全検証済み予報を較正母集団としてブートストラップできる）。

濫用防止（design §6・原則D）:
- 本スクリプトは較正『入口データ』の収集のみ。発行済み予報の再採点・hit_criteria 変更はしない。
- 書き込み先は forecaster/verification/ 配下のみ（週次検証スキルの許可範囲）。
- 実際の結果（realized_outcome）は既存の検証エントリ（verification/*.json）から読むだけで、
  本スクリプトが verified_outcome を新規に判定することはない（CLAUDE.md 行動原則4）。

使い方:
    # 既存の全検証済み予報を較正データへ一括ブートストラップ（初回・遡及）
    python3 scripts/record_retrieval_calibration.py --all

    # 単一予報を記録（検証ステージが確定直後に呼ぶ想定）
    python3 scripts/record_retrieval_calibration.py --date 2026-07-07 --index 1

    # 中身を書かずに標準出力で確認
    python3 scripts/record_retrieval_calibration.py --all --dry-run
"""

import argparse
import glob
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
import retrieve_similar_cases as rsc  # noqa: E402

REPO_ROOT = rsc.REPO_ROOT
VERIFICATION_DIR = rsc.VERIFICATION_DIR
FORECASTS_DIR = rsc.FORECASTS_DIR
DATASET_PATH = os.path.join(VERIFICATION_DIR, "retrieval-calibration.json")

COUNTED_OUTCOMES = rsc.COUNTED_OUTCOMES  # {"hit","partial","miss"}
THRESHOLD_FOR_AGGREGATE = 0.5  # 現行の本番 min_similarity
RANKED_CASES_CAP = 50


def load_all_verification_entries_with_source():
    """(entry) のリストを返す。"""
    entries = []
    for path in sorted(glob.glob(os.path.join(VERIFICATION_DIR, "*.json"))):
        base = os.path.basename(path)
        # 較正データセット自身は検証エントリファイルではないので除外
        if base == os.path.basename(DATASET_PATH):
            continue
        try:
            data = rsc.load_json(path)
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        for e in data.get("entries", []):
            entries.append(e)
    return entries


def load_sidecar(forecast_date, forecast_index):
    return rsc.load_forecast_sidecar(forecast_date, forecast_index)


def build_candidate_from_entry(entry, sidecar, obs_by_id):
    """検証エントリ + サイドカー + 関連観測から、retrieve() 用の raw 候補キーを組み立てる。
    これは発行時の予報候補キーを事後に忠実再構成したものである。"""
    related_ids = entry.get("related_observation_ids") or []
    related_obs = [obs_by_id[i] for i in related_ids if i in obs_by_id]

    cves = set()
    diff = entry.get("kev_snapshot_diff") or {}
    if diff.get("cve_id"):
        cves.add(diff["cve_id"])
    if sidecar:
        snap = sidecar.get("kev_snapshot") or {}
        if snap.get("cve"):
            cves.add(snap["cve"])
    for obs in related_obs:
        for c in obs.get("cve") or []:
            cves.add(c)

    actors = []
    if sidecar and sidecar.get("related_group"):
        actors.append(sidecar["related_group"])
    for obs in related_obs:
        if obs.get("actor_group"):
            actors.append(obs["actor_group"])

    techniques = set()
    tactics = set()
    for obs in related_obs:
        for t in obs.get("techniques") or []:
            if t.get("technique_id"):
                techniques.add(t["technique_id"])
            if t.get("tactic"):
                tactics.add(t["tactic"])

    stage_priority = ["active_exploitation", "kev_listed", "poc_public",
                      "limited_exploitation", "none", "unknown"]
    stages = [obs.get("exploitation_stage") for obs in related_obs if obs.get("exploitation_stage")]
    exploitation_stage = None
    for s in stage_priority:
        if s in stages:
            exploitation_stage = s
            break

    return {
        "outcome_channel": entry.get("outcome_channel") or (sidecar or {}).get("outcome_channel"),
        "forecast_class": entry.get("forecast_class") or (sidecar or {}).get("forecast_class"),
        "tier": entry.get("tier") or (sidecar or {}).get("tier"),
        "cve": sorted(cves),
        "related_group": actors,
        "techniques": sorted(techniques),
        "tactics": sorted(tactics),
        "exploitation_stage": exploitation_stage,
    }


def aggregate_at(ranked, threshold, min_sample=rsc.DEFAULT_MIN_SAMPLE):
    sel = [c for c in ranked if c["similarity"] >= threshold]
    n = len(sel)
    n_hit = sum(1 for c in sel if c["outcome"] == "hit")
    n_partial = sum(1 for c in sel if c["outcome"] == "partial")
    n_miss = sum(1 for c in sel if c["outcome"] == "miss")
    emp = round((n_hit + n_partial) / n, 4) if n else None
    return {
        "n_cases": n,
        "n_hit": n_hit,
        "n_partial": n_partial,
        "n_miss": n_miss,
        "empirical_hit_rate": emp,
        "observed_gate_passed": n >= min_sample,
    }


def build_record(entry, obs_by_id):
    outcome = entry.get("outcome")
    if outcome not in COUNTED_OUTCOMES:
        return None  # unverifiable/未確定は較正母集団に入れない

    fdate = entry.get("forecast_date")
    findex = entry.get("forecast_index")
    if not rsc.is_valid_date(fdate) or not findex:
        return None
    fid = f"fc-{fdate.replace('-', '')}-{findex}"

    sidecar = load_sidecar(fdate, findex)
    cand = build_candidate_from_entry(entry, sidecar, obs_by_id)

    # 発行日as-of・min_similarity=0 で全ランクを再計算（過去事例のみ・未来リークなし）
    result = rsc.retrieve(cand, fdate, top_n=RANKED_CASES_CAP,
                          min_similarity=0.0, min_sample=rsc.DEFAULT_MIN_SAMPLE)
    ranked = [
        {
            "forecast_id": c["forecast_id"],
            "similarity": c["similarity"],
            "outcome": c["outcome"],
            "matched_on": c["matched_on"],
        }
        for c in result["matched_cases"]
    ]

    snapshot = sidecar.get("retrieval") if sidecar else None
    verified_at = (entry.get("kev_snapshot_diff") or {}).get("checked_at")

    return {
        "forecast_id": fid,
        "forecast_date": fdate,
        "forecast_index": findex,
        "verified_at": verified_at,
        "confidence": entry.get("confidence") or (sidecar or {}).get("confidence"),
        "tier": cand["tier"],
        "forecast_class": cand["forecast_class"],
        "outcome_channel": cand["outcome_channel"],
        "base_rate_estimate": (sidecar or {}).get("base_rate_estimate"),
        "realized_outcome": outcome,
        "realized_hit_binary": 1 if outcome in ("hit", "partial") else 0,
        "retrieval_present_at_issue": snapshot is not None,
        "retrieval_snapshot_at_issue": snapshot,
        "retrieval_recompute": {
            "recomputed": True,
            "note": ("発行日as-ofの決定論的再計算（過去事例のみ）。product-categories.json 等の"
                     "辞書進化により発行時点の retrieval と厳密一致しない場合がある。"),
            "threshold_for_aggregate": THRESHOLD_FOR_AGGREGATE,
            "params": result["params"],
            "aggregate_at_threshold": aggregate_at(ranked, THRESHOLD_FOR_AGGREGATE),
            "ranked_cases": ranked,
        },
    }


def load_dataset():
    if os.path.isfile(DATASET_PATH):
        try:
            data = rsc.load_json(DATASET_PATH)
            if isinstance(data, dict) and isinstance(data.get("records"), list):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "_schema_version": "1.0",
        "_comment": ("類似過去事例検索（Case-Based Retrieval）の閾値・重み較正用データセット。"
                     "forecaster/case-based-retrieval-design.md §8 の一次データ。"
                     "各レコードは検証確定した予報の『発行時 retrieval 集計』『発行日as-of再計算の類似曲線』"
                     "『実際の的中結果』を凍結する。発行済み予報の再採点には使わない（原則D）。"),
        "_governance": "書き込みは検証ステージ（04-verify.md 手順8c）のみ。scripts/record_retrieval_calibration.py が生成。",
        "_generator": "scripts/record_retrieval_calibration.py",
        "records": [],
    }


def upsert(dataset, record):
    """forecast_id で重複排除（既存を置換）。"""
    records = dataset["records"]
    for i, r in enumerate(records):
        if r.get("forecast_id") == record["forecast_id"]:
            records[i] = record
            return "updated"
    records.append(record)
    return "added"


def main():
    parser = argparse.ArgumentParser(
        description="Case-Based Retrieval の較正データを verification/retrieval-calibration.json へ収集する。"
    )
    parser.add_argument("--all", action="store_true", help="既存の全検証済み予報を一括記録（遡及ブートストラップ）。")
    parser.add_argument("--date", help="単一予報の発行日（YYYY-MM-DD）。--index と併用。")
    parser.add_argument("--index", type=int, help="単一予報の forecast_index。--date と併用。")
    parser.add_argument("--dry-run", action="store_true", help="ファイルに書かず結果を標準出力する。")
    args = parser.parse_args()

    if not args.all and not (args.date and args.index):
        print("エラー: --all か（--date と --index の両方）を指定する。", file=sys.stderr)
        sys.exit(2)

    obs_by_id = rsc.build_observation_index()
    entries = load_all_verification_entries_with_source()

    if args.all:
        targets = entries
    else:
        if not rsc.is_valid_date(args.date):
            print(f"エラー: --date は YYYY-MM-DD 形式: {args.date!r}", file=sys.stderr)
            sys.exit(2)
        targets = [e for e in entries
                   if e.get("forecast_date") == args.date and e.get("forecast_index") == args.index]
        if not targets:
            print(f"エラー: 該当する検証エントリが見つからない: {args.date} idx={args.index}", file=sys.stderr)
            sys.exit(2)

    dataset = load_dataset()
    added = updated = skipped = 0
    built = []
    for entry in targets:
        rec = build_record(entry, obs_by_id)
        if rec is None:
            skipped += 1
            continue
        built.append(rec)
        if not args.dry_run:
            action = upsert(dataset, rec)
            added += action == "added"
            updated += action == "updated"

    # 決定論的な安定ソート（forecast_date, forecast_index）
    dataset["records"].sort(key=lambda r: (r.get("forecast_date", ""), r.get("forecast_index", 0)))

    if args.dry_run:
        print(json.dumps({"built": len(built), "skipped_unverifiable": skipped,
                          "sample": built[:2]}, ensure_ascii=False, indent=2))
        return

    os.makedirs(VERIFICATION_DIR, exist_ok=True)
    with open(DATASET_PATH, "w", encoding="utf-8") as f:
        f.write(json.dumps(dataset, ensure_ascii=False, indent=2) + "\n")

    rel = os.path.relpath(DATASET_PATH, REPO_ROOT)
    print(f"OK: {rel} — 追加 {added} / 更新 {updated} / 対象外(未確定) {skipped}"
          f" / 総レコード {len(dataset['records'])}")


if __name__ == "__main__":
    main()
