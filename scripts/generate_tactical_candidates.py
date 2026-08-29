#!/usr/bin/env python3
"""許可遷移から TF-1 の COA 候補を全件生成する（設計 §4.2 / §4.6 / §12 第1段階）。

出力: forecaster/candidates/tactical/YYYY-MM-DD.json

★第1段階では発行しない（shadow）。目的は母集団を作ることである。
  当たりそうな候補だけを残す分母操作を防ぐため、**棄権した候補も理由付きで全件保存**
  する（設計 §4.6）。candidate coverage / abstention の集計を毎回出す。

確率について（設計 §4.4 / §8）:
  LLM は確率を書かない。本スクリプトが参照クラスの事後平均を確率として置く。
  第1段階のモデル版は `tf1-reference-only-v0` であり、**特徴量による弁別は行わない**。
  これは「まだ弁別できることを実証していない」という事実の率直な表現である。
  E1 の実測（AUC 0.5125・BSS −0.0464）が示すとおり、弁別を主張するには
  それを支える実績が要る。

時間軸（設計 §5.4）: 72h / 7d / 30d の累積確率を出し、P72h <= P7d <= P30d を強制する。

棄権理由（reason code）:
  NO_ALLOWED_TRANSITION   … 終端状態で予報対象の遷移がない
  STATE_UNCERTAIN         … 根拠が矛盾しており状態を固定できない
  LOW_VISIBILITY          … 非観測が非発生を意味しない（設計 §9.3）→ shadow/収集要求へ
  NO_REFERENCE_RATE       … 参照クラスに参照率がない（観測手段がない等）
  ALREADY_IN_TARGET_STATE … 既に遷移先の状態に到達している

使い方:
    python3 scripts/generate_tactical_candidates.py --date 2026-08-29
"""

import argparse
import glob
import json
import os
import sys
from collections import Counter
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tactical_states import (  # noqa: E402
    HORIZON_LABELS, HORIZONS_DAYS, STATE_RANK, allowed_transitions,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_ROOT = os.path.join(REPO_ROOT, "forecaster", "state", "tactical")
CAND_ROOT = os.path.join(REPO_ROOT, "forecaster", "candidates", "tactical")
RATES_PATH = os.path.join(REPO_ROOT, "forecaster", "models", "reference-rates.json")
JST = timezone(timedelta(hours=9))

MODEL_VERSION = "tf1-reference-only-v0"
MATCHING_RULE_VERSION = "tf1-exploitation-v1"

# 一次確認源（設計 §7 verification_sources）。event type ごとに固定する。
VERIFICATION_SOURCES = {
    "TF1_POC_PUBLICATION": ["vendor", "exploit_db", "github"],
    "TF1_INDEPENDENT_EXPLOITATION_CONFIRMATION": ["vendor", "cert", "telemetry_provider"],
    "TF1_BROADER_EXPLOITATION_CONFIRMATION": ["vendor", "cert", "telemetry_provider"],
    "TF1_POST_EXPLOIT_ACTIVITY_PUBLICATION": ["vendor", "cert"],
    "TF1_BROAD_CAMPAIGN": ["vendor", "cert"],
}


def load_states(day):
    path = os.path.join(STATE_ROOT, f"{day.year:04d}", f"{day.month:02d}",
                        f"{day.isoformat()}.json")
    if not os.path.exists(path):
        raise SystemExit(f"[fatal] 状態ファイルがない: {path}"
                         "（先に build_tactical_state.py を実行する）")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_rates():
    if not os.path.exists(RATES_PATH):
        raise SystemExit(f"[fatal] 参照率がない: {RATES_PATH}"
                         "（先に build_reference_rates.py を実行する）")
    with open(RATES_PATH, encoding="utf-8") as f:
        return json.load(f)["reference_rates"]


def monotonic(probs):
    """P72h <= P7d <= P30d を強制する（設計 §5.4）。"""
    out, prev = {}, 0.0
    for h in HORIZONS_DAYS:
        p = probs.get(h)
        if p is None:
            out[HORIZON_LABELS[h]] = None
            continue
        p = max(p, prev)
        out[HORIZON_LABELS[h]] = round(p, 4)
        prev = p
    return out


def build(day, state_doc, rates):
    issued = datetime.combine(day, datetime.min.time(), tzinfo=JST).astimezone(timezone.utc)
    issued_s = issued.isoformat().replace("+00:00", "Z")
    candidates = []
    seq = 0

    for st in state_doc["states"]:
        cur = st["current_state"]
        trans = allowed_transitions(cur)

        if not trans:
            seq += 1
            candidates.append(_abstain(day, seq, st, None, "NO_ALLOWED_TRANSITION",
                                       f"{cur} は TF-1 の終端状態で予報対象の遷移がない",
                                       issued_s))
            continue

        for event_type, next_state, visibility in trans:
            seq += 1
            if STATE_RANK.get(next_state, -1) <= STATE_RANK.get(cur, 0):
                candidates.append(_abstain(day, seq, st, event_type,
                                           "ALREADY_IN_TARGET_STATE",
                                           f"既に {cur} に到達しており {next_state} は前進ではない",
                                           issued_s))
                continue
            if st["state_confidence"] == "uncertain":
                candidates.append(_abstain(day, seq, st, event_type, "STATE_UNCERTAIN",
                                           "同日に前進度の異なる状態が併存し現在状態を固定できない",
                                           issued_s, visibility))
                continue

            probs, refs = {}, {}
            missing = False
            for h in HORIZONS_DAYS:
                key = f"TF1|{cur}|{HORIZON_LABELS[h]}"
                r = rates.get(key)
                if not r or not r.get("estimate"):
                    missing = True
                    probs[h] = None
                    continue
                probs[h] = r["estimate"]["posterior_mean"]
                refs[HORIZON_LABELS[h]] = {
                    "key": key,
                    "status": r["status"],
                    "n": r["observed"]["n"],
                    "events": r["observed"]["events"],
                    "posterior_mean": r["estimate"]["posterior_mean"],
                    "lower": r["estimate"]["lower"],
                    "upper": r["estimate"]["upper"],
                    "pooled_from": r.get("pooled_from"),
                }
            if missing:
                candidates.append(_abstain(day, seq, st, event_type, "NO_REFERENCE_RATE",
                                           f"参照クラス TF1|{cur}|* に使える参照率がない",
                                           issued_s, visibility))
                continue

            status = "shadow"
            reason = None
            if visibility == "low":
                status = "abstained"
                reason = "LOW_VISIBILITY"

            candidates.append({
                "candidate_id": f"tc-{day.isoformat().replace('-', '')}-{seq:03d}",
                "issued_at_utc": issued_s,
                "cutoff_at_utc": issued_s,
                "forecast_family": "TF-1",
                "subject": {"type": st["subject_type"], "id": st["subject_id"]},
                "current_state_id": st["state_id"],
                "current_state": cur,
                "state_confidence": st["state_confidence"],
                "target_event": {
                    "event_type": event_type,
                    "next_state": next_state,
                    "window_start_utc": issued_s,
                    "window_end_utc": (issued + timedelta(days=max(HORIZONS_DAYS)))
                        .isoformat().replace("+00:00", "Z"),
                    "verification_sources": VERIFICATION_SOURCES.get(event_type, []),
                    "matching_rule_version": MATCHING_RULE_VERSION,
                    "visibility_model": visibility,
                },
                "probability_by_horizon": monotonic(probs),
                "reference_class": refs,
                "model_version": MODEL_VERSION,
                "observation_ids": st["observation_ids"],
                "selection": {
                    "status": status,
                    "reason_code": reason,
                    "reason": ("非観測が非発生を意味しないため本番確率予報にしない"
                               "（設計 §9.3）。収集要求へ回す。" if reason else
                               "第1段階は全件 shadow。発行しない。"),
                },
                "verified_outcome": None,
            })
    return candidates


def _abstain(day, seq, st, event_type, code, reason, issued_s, visibility=None):
    return {
        "candidate_id": f"tc-{day.isoformat().replace('-', '')}-{seq:03d}",
        "issued_at_utc": issued_s,
        "cutoff_at_utc": issued_s,
        "forecast_family": "TF-1",
        "subject": {"type": st["subject_type"], "id": st["subject_id"]},
        "current_state_id": st["state_id"],
        "current_state": st["current_state"],
        "state_confidence": st["state_confidence"],
        "target_event": ({"event_type": event_type,
                          "visibility_model": visibility} if event_type else None),
        "probability_by_horizon": None,
        "reference_class": None,
        "model_version": MODEL_VERSION,
        "observation_ids": st["observation_ids"],
        "selection": {"status": "abstained", "reason_code": code, "reason": reason},
        "verified_outcome": None,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", help="基準日 YYYY-MM-DD（既定: JST の本日）")
    ap.add_argument("--print-only", action="store_true")
    args = ap.parse_args()

    day = date.fromisoformat(args.date) if args.date else datetime.now(JST).date()
    state_doc = load_states(day)
    cands = build(day, state_doc, load_rates())

    doc = {
        "_schema_version": "1.0",
        "_candidate_date": day.isoformat(),
        "_generator": "scripts/generate_tactical_candidates.py",
        "_model_version": MODEL_VERSION,
        "_comment": (
            "TF-1 の COA 候補。第1段階では全件 shadow で発行しない（設計 §12）。"
            "★棄権した候補も理由付きで全件保存する — 当たりそうな候補だけを残す"
            "分母操作を防ぐため（設計 §4.6・§13）。"
        ),
        "_coverage": {
            "candidates_total": len(cands),
            "shadow": sum(1 for c in cands if c["selection"]["status"] == "shadow"),
            "abstained": sum(1 for c in cands if c["selection"]["status"] == "abstained"),
            "published": 0,
            "abstention_reasons": dict(Counter(
                c["selection"]["reason_code"] for c in cands
                if c["selection"]["status"] == "abstained")),
        },
        "candidates": cands,
    }

    cov = doc["_coverage"]
    print(f"[candidates] {day}: 全候補 {cov['candidates_total']} 件 "
          f"（shadow {cov['shadow']} / 棄権 {cov['abstained']} / 発行 {cov['published']}）")
    print("  棄権理由:", cov["abstention_reasons"])
    print("  内訳（shadow のイベント種別）:",
          dict(Counter(c["target_event"]["event_type"] for c in cands
                       if c["selection"]["status"] == "shadow")))

    if args.print_only:
        return 0
    out = os.path.join(CAND_ROOT, f"{day.isoformat()}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"\n[out] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
