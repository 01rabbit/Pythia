#!/usr/bin/env python3
"""TF-1 の target_event を決定論的に採点する（設計 §9 / §12 第1段階の完了条件）。

第1段階の完了条件のひとつが「target event をコードで採点できる」ことである。
本スクリプトはその実装であり、**自然言語の解釈を一切挟まない**。

採点規則:
  発火 = 予報窓内に、同じ subject について next_state 以上の状態を導出できる観測が
        存在すること。状態の導出は scripts/tactical_states.py の derive_state()
        （候補生成・参照率測定と同一実装）を使う。
        ★候補生成側と採点側で状態の解釈がずれると測定系が壊れるため、実装は共有する。

判定値:
  hit            … 窓内に発火した
  miss           … 窓が満了し、発火しなかった
  pending        … 窓が未満了（右打ち切り）。miss にしない（設計 §9.3）
  unobservable   … visibility=low。非観測が非発生を意味しないため採点しない
  abstained      … 候補生成時に棄権済み。分子にも分母にも入れない

★複合命題を partial で逃がさない（設計 §9.2）。判定は二値のみである。

使い方:
    python3 scripts/verify_tactical_forecasts.py --date 2026-08-29
    python3 scripts/verify_tactical_forecasts.py --all
"""

import argparse
import glob
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tactical_states import (  # noqa: E402
    HORIZONS_DAYS, HORIZON_LABELS, STATE_RANK, derive_state,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBS_GLOB = os.path.join(REPO_ROOT, "forecaster", "observations", "*", "*", "*.json")
CAND_GLOB = os.path.join(REPO_ROOT, "forecaster", "candidates", "tactical", "*.json")
JST = timezone(timedelta(hours=9))


def load_subject_states():
    """subject_id -> [(observed_date, state)] を返す（採点用の全期間インデックス）。"""
    per = defaultdict(list)
    latest = date.min
    for path in sorted(glob.glob(OBS_GLOB)):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for o in doc.get("observations", []):
            st, _b = derive_state(o)
            d = o.get("observed_date")
            if not st or not d:
                continue
            try:
                dd = date.fromisoformat(d)
            except ValueError:
                continue
            latest = max(latest, dd)
            for cve in (o.get("cve") or []):
                per[cve].append((dd, st))
    return {k: sorted(set(v)) for k, v in per.items()}, latest


def score(candidate, index, corpus_end):
    """1候補を時間軸ごとに採点し {horizon: verdict} を返す。"""
    sel = candidate["selection"]
    if sel["status"] == "abstained":
        return {HORIZON_LABELS[h]: "abstained" for h in HORIZONS_DAYS}

    te = candidate["target_event"]
    if te.get("visibility_model") == "low":
        return {HORIZON_LABELS[h]: "unobservable" for h in HORIZONS_DAYS}

    start = date.fromisoformat(candidate["issued_at_utc"][:10])
    subject = candidate["subject"]["id"]
    target_rank = STATE_RANK.get(te["next_state"], 99)
    points = index.get(subject, [])

    out = {}
    for h in HORIZONS_DAYS:
        deadline = start + timedelta(days=h)
        fired = any(
            start < d <= deadline and STATE_RANK.get(s, -1) >= target_rank
            for d, s in points
        )
        if fired:
            out[HORIZON_LABELS[h]] = "hit"
        elif deadline > corpus_end:
            out[HORIZON_LABELS[h]] = "pending"
        else:
            out[HORIZON_LABELS[h]] = "miss"
    return out


def brier(pairs):
    """(probability, outcome01) から Brier score を返す。"""
    if not pairs:
        return None
    return round(sum((p - y) ** 2 for p, y in pairs) / len(pairs), 4)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", help="対象日 YYYY-MM-DD")
    ap.add_argument("--all", action="store_true", help="全候補ファイルを採点する")
    ap.add_argument("--json", action="store_true", help="機械可読出力")
    args = ap.parse_args()

    if args.all:
        paths = sorted(glob.glob(CAND_GLOB))
    else:
        target = args.date or datetime.now(JST).date().isoformat()
        p = os.path.join(REPO_ROOT, "forecaster", "candidates", "tactical", f"{target}.json")
        if not os.path.exists(p):
            print(f"[skip] 候補ファイルがない: {p}")
            return 0
        paths = [p]

    index, corpus_end = load_subject_states()
    rows, tally = [], defaultdict(Counter)
    scored = defaultdict(list)

    for path in paths:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        for c in doc.get("candidates", []):
            verdicts = score(c, index, corpus_end)
            rows.append({"candidate_id": c["candidate_id"],
                         "subject": c["subject"]["id"],
                         "current_state": c["current_state"],
                         "event_type": (c.get("target_event") or {}).get("event_type"),
                         "verdicts": verdicts})
            for hl, v in verdicts.items():
                tally[hl][v] += 1
                if v in ("hit", "miss") and c.get("probability_by_horizon"):
                    prob = c["probability_by_horizon"].get(hl)
                    if prob is not None:
                        scored[hl].append((prob, 1 if v == "hit" else 0))

    result = {
        "_comment": "TF-1 候補の決定論的採点（設計 §9）。partial 判定は作らない。",
        "_corpus_end": corpus_end.isoformat(),
        "_candidate_files": len(paths),
        "by_horizon": {},
        "entries": rows,
    }
    for hl in [HORIZON_LABELS[h] for h in HORIZONS_DAYS]:
        t = tally[hl]
        n = t["hit"] + t["miss"]
        # ★右打ち切りの誤読を防ぐ（設計 §13）。窓が未満了の候補が残っている間、
        #   hit は先に判明し miss は後から判明するため、hit/(hit+miss) は上方に偏る。
        #   窓が全件満了するまで的中率を「確定値」として出さない。
        censored = t["pending"] > 0
        result["by_horizon"][hl] = {
            **{k: t[k] for k in ("hit", "miss", "pending", "unobservable", "abstained")},
            "scored_n": n,
            "right_censored": censored,
            "hit_rate": round(t["hit"] / n, 4) if n else None,
            "hit_rate_is_provisional": censored,
            "brier": brier(scored[hl]),
            "_censoring_note": (
                "窓未満了の候補が残っているため、この的中率と Brier は暫定値であり"
                "上方に偏る（外れは窓が満了して初めて判明する）。確定は全件満了後。"
                if censored else None
            ),
        }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    print(f"=== TF-1 決定論採点（コーパス終端 {corpus_end}）===")
    for hl, v in result["by_horizon"].items():
        mark = "（暫定・上方バイアス）" if v["right_censored"] else "（確定）"
        print(f"  {hl:4s} 的中{v['hit']:4d} 外れ{v['miss']:4d} 窓未満了{v['pending']:4d} "
              f"観測不能{v['unobservable']:4d} 棄権{v['abstained']:4d}"
              f"  → n={v['scored_n']} 的中率={v['hit_rate']} Brier={v['brier']} {mark}")
    print("\n★窓未満了は miss に数えない（右打ち切り・設計 §9.3）。"
          "観測不能（visibility=low）は分子にも分母にも入れない。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
