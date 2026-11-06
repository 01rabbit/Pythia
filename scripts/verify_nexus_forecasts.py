#!/usr/bin/env python3
"""NX-1 の候補台帳を、固定した matching rule と実時刻で決定論的に採点する。

対象は『国別 nexus の確認が記録されたか』であり、攻撃の発生そのものではない。

判定の規則（nexus_family.score_window）:
  hit           窓 (issued, issued+H] に、as_of までに利用可能になった国別 nexus 観測がある
  pending       窓がまだ満了していない（右打ち切りを miss にしない）
  miss          窓が満了し、窓内のすべての日次ランが記録されている
  not_observed  窓が満了したが、日次ランの欠測日を含む（『起きなかった』と断定できない）
  abstained     台帳で棄権した

昇格ゲートは forecaster/config/promotion-gates.json を TF-1 と共有する。ただし NX-1 の候補は
窓が重なり独立ではないため、resolved_n と positive_events は **独立標本数の推定（÷H）**で数える。
Brier skill は『標本平均を定数予測した基準』と『nx1-climatology-v1』の両方に勝つことを要する。

--walkforward は遡及診断（各グリッド日にその日までの情報だけで確率を作って突き合わせる）。
診断であり、昇格の母集団には入れない。式は固定で、診断の結果を見て変更しない。

使い方:
  python3 scripts/verify_nexus_forecasts.py [--as-of-utc ...] [--json] [--write] [--walkforward]
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_family as nf  # noqa: E402
import validate_nexus_integrity as vni  # noqa: E402
from build_promotion_summary import auc_lower_95, calibration_logistic  # noqa: E402
from tactical_time import iso_utc, parse_utc  # noqa: E402
from validate_model_promotion import passes  # noqa: E402

ROOT = nf.ROOT
UTC = timezone.utc
OUT_ROOT = os.path.join(ROOT, "forecaster", "verification", "nexus")
GATES_PATH = os.path.join(ROOT, "forecaster", "config", "promotion-gates.json")
VERDICTS = ("hit", "miss", "pending", "not_observed", "abstained")


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def collect(root, data, as_of):
    """全台帳の候補×地平を採点して行にする（除外されていない前向きの台帳だけ）。"""
    rows = []
    for path in sorted(glob.glob(os.path.join(root, "forecaster", "candidates", "nexus", "*.json"))):
        for c in load_json(path).get("candidates", []):
            issued = parse_utc(c["issued_at_utc"])
            nexus = (c.get("subject") or {}).get("id")
            for h in nf.HORIZONS_DAYS:
                label = nf.HORIZON_LABELS[h]
                p0 = (c["models"][nf.MODEL_CLIMATOLOGY]["probability_by_horizon"] or {}).get(label)
                p1 = (c["models"][nf.MODEL_RECENCY]["probability_by_horizon"] or {}).get(label)
                if c["selection"]["status"] == "abstained" or p0 is None:
                    verdict = "abstained"
                else:
                    verdict = nf.score_window(data, nexus, issued, h, as_of)
                rows.append({"candidate_id": c["candidate_id"], "nexus": nexus, "horizon": h, "label": label,
                             "verdict": verdict, nf.MODEL_CLIMATOLOGY: p0, nf.MODEL_RECENCY: p1,
                             "issued_at_utc": c["issued_at_utc"]})
    return rows


def model_metrics(rows, model, horizon, gates, temporal_errors):
    label = nf.HORIZON_LABELS[horizon]
    subset = [r for r in rows if r["label"] == label]
    counts = Counter(r["verdict"] for r in subset)
    pairs = [(r[model], int(r["verdict"] == "hit")) for r in subset if r["verdict"] in ("hit", "miss")]
    clim_pairs = [(r[nf.MODEL_CLIMATOLOGY], y) for r, (_p, y) in
                  zip([r for r in subset if r["verdict"] in ("hit", "miss")], pairs)]
    scored, hits = len(pairs), counts["hit"]
    b = nf.brier(pairs)
    bss_mean = nf.skill(b, nf.sample_mean_brier(pairs))
    bss_clim = nf.skill(b, nf.brier(clim_pairs)) if model != nf.MODEL_CLIMATOLOGY else None
    independent_n = math.ceil(scored / horizon) if scored else 0
    positives_independent = math.ceil(hits / horizon) if hits else 0
    intercept, slope = calibration_logistic(pairs) if scored >= 2 else (None, None)
    denominator = scored + counts["not_observed"]
    profile = "reference_only_calibration" if model == nf.MODEL_CLIMATOLOGY else "discriminative"
    # ゲートに渡す Brier skill は、比較対象すべてに勝つことを要する（厳しい方）
    skills = [s for s in (bss_mean, bss_clim) if s is not None]
    gate_metrics = {
        "resolved_n": independent_n,
        "positive_events": positives_independent,
        "brier_skill_score": min(skills) if len(skills) == (2 if model != nf.MODEL_CLIMATOLOGY else 1) else None,
        "auc_lower_95": auc_lower_95(pairs) if scored >= 2 else None,
        "calibration_intercept": intercept,
        "calibration_slope": slope,
        "evidence_coverage": (scored / denominator) if denominator else None,
        "temporal_integrity_errors": temporal_errors,
        "metric_status": {"auc_lower_95": "not_applicable_reference_only"} if profile == "reference_only_calibration" else {},
    }
    ok, checks = passes(gate_metrics, gates, profile)
    rnd = lambda v, n=6: None if v is None else round(v, n)  # noqa: E731
    return {
        **{k: counts[k] for k in VERDICTS},
        "scored_n": scored,
        "independent_n_estimate": independent_n,
        "positive_events_independent_estimate": positives_independent,
        "positive_rate": rnd(hits / scored if scored else None),
        "brier": rnd(b),
        "log_loss": rnd(nf.log_loss(pairs)),
        "auc": rnd(nf.auc(pairs)),
        "brier_skill_vs_sample_mean": rnd(bss_mean),
        "brier_skill_vs_climatology": rnd(bss_clim),
        "auc_lower_95": rnd(gate_metrics["auc_lower_95"]),
        "calibration_intercept": rnd(intercept),
        "calibration_slope": rnd(slope),
        "evidence_coverage": rnd(gate_metrics["evidence_coverage"]),
        "right_censored": counts["pending"] > 0,
        "evaluation_profile": profile,
        "gates": {k: bool(v) for k, v in checks.items()},
        "gates_pass": bool(ok),
    }


def verify(root, as_of, with_walkforward=False):
    data = nf.load_data(root)
    rows = collect(root, data, as_of)
    gates = load_json(os.path.join(root, "forecaster", "config", "promotion-gates.json"))["gates"]
    errors, _warnings = vni.run(root, None, False, as_of)
    result = {
        "_schema_version": "1.0",
        "_generated_at_utc": iso_utc(as_of),
        "_family": nf.FAMILY,
        "_matching_rule_version": nf.MATCHING_RULE_VERSION,
        "_ledgers": len(glob.glob(os.path.join(root, "forecaster", "candidates", "nexus", "*.json"))),
        "_independence_note": "候補の窓は重なる。resolved_n・positive_events は ÷H の推定（独立標本数）で数える",
        "models": {m: {nf.HORIZON_LABELS[h]: model_metrics(rows, m, h, gates, len(errors))
                       for h in nf.HORIZONS_DAYS} for m in nf.MODELS},
    }
    if with_walkforward:
        wf = nf.walkforward(data, as_of)
        result["retrospective_diagnostic"] = {
            "_note": "遡及診断。各グリッド日にその日までの情報だけで確率を作って突き合わせた。"
                     "昇格の母集団には入れない。式は固定で、結果を見て変更しない。",
            "history_start": nf.HISTORY_START.isoformat(),
            "by_horizon": nf.summarize_rows(wf) if wf else {},
        }
    return result


def render(result):
    lines = [f"NX-1 verification as_of={result['_generated_at_utc']} ledgers={result['_ledgers']}"]
    for model, by_h in result["models"].items():
        lines.append(f"  [{model}]")
        for label, m in by_h.items():
            lines.append(
                f"    {label}: hit={m['hit']} miss={m['miss']} pending={m['pending']} not_observed={m['not_observed']} "
                f"abstained={m['abstained']} | scored={m['scored_n']} (独立≈{m['independent_n_estimate']}, "
                f"陽性≈{m['positive_events_independent_estimate']}) brier={m['brier']} auc={m['auc']} "
                f"skill(vs平均)={m['brier_skill_vs_sample_mean']} skill(vs気候値)={m['brier_skill_vs_climatology']} "
                f"| ゲート={'通過' if m['gates_pass'] else '未達'}")
    diag = result.get("retrospective_diagnostic")
    if diag:
        lines += ["", "  [遡及診断（昇格の母集団に入れない）]"]
        for label, d in diag["by_horizon"].items():
            lines.append(f"    {label}: rows={d['rows']} 独立≈{d['independent_n_estimate']} 陽性率={d['positive_rate']} "
                         f"BSS(挑戦者 vs 気候値)={d['bss_recency_vs_climatology']} 95%区間={d['bss_ci95']} "
                         f"AUC={d['auc_recency']} 後退率={d['fallback_share']}")
    lines += ["", "未確認は not_observed。miss へ変換しない。右打ち切りは pending。"]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--as-of-utc", help="採点時点。既定は現在 UTC")
    parser.add_argument("--root", default=ROOT)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--write", action="store_true", help="forecaster/verification/nexus/ へ保存する")
    parser.add_argument("--walkforward", action="store_true", help="遡及診断も出す（昇格の母集団には入れない）")
    args = parser.parse_args()
    as_of = parse_utc(args.as_of_utc) if args.as_of_utc else datetime.now(UTC).replace(microsecond=0)
    result = verify(args.root, as_of, args.walkforward)
    if args.write:
        out_dir = os.path.join(args.root, "forecaster", "verification", "nexus")
        os.makedirs(out_dir, exist_ok=True)
        out = os.path.join(out_dir, f"verification-{as_of.strftime('%Y%m%dT%H%M%SZ')}.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"[out] {os.path.relpath(out, args.root)}", file=sys.stderr)
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else render(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
