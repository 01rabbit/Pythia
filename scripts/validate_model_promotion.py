#!/usr/bin/env python3
"""モデル昇格が前向き評価ゲートに裏付けられているかfail-closed検証する。

★被覆記録が1件も無い間は昇格を許さない（PR #175 レビュー指摘2）。
  negative_outcome_allowed=coverage_proven の universe で被覆記録が無ければ
  miss は原理的に立たず、Brier も AUC も hit だけで計算されることになる。
  その状態の指標で昇格させてはならない。
"""

import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(ROOT, "forecaster", "models", "model-registry.json")
GATES = os.path.join(ROOT, "forecaster", "config", "promotion-gates.json")
SUMMARIES = os.path.join(ROOT, "forecaster", "verification", "tactical", "promotion-*.json")
COVERAGE_GLOB = os.path.join(ROOT, "forecaster", "evidence", "source-coverage", "*.json")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def passes(metrics, gates, profile):
    slope = metrics.get("calibration_slope")
    lo, hi = gates["calibration_slope_range"]
    reference_only = profile == "reference_only_calibration"
    checks = {
        "resolved_n": metrics.get("resolved_n", 0) >= gates["minimum_resolved_n"],
        "positive_events": metrics.get("positive_events", 0) >= gates["minimum_positive_events"],
        "brier_skill_score": metrics.get("brier_skill_score", -999) > gates["minimum_brier_skill_score"],
        # reference-only は特徴量で候補を順位付けするモデルではない。AUCを0等として
        # 擬似的にfailさせず、not applicable を明示する。ただし registry の
        # public_forecast_eligible=false により公開昇格は別途禁止する。
        "auc_lower_95": (
            metrics.get("metric_status", {}).get("auc_lower_95") == "not_applicable_reference_only"
            if reference_only else metrics.get("auc_lower_95", 0) > gates["minimum_auc_lower_95"]
        ),
        "calibration_intercept": abs(metrics.get("calibration_intercept", 999)) <=
                                   gates["maximum_calibration_intercept_abs"],
        "calibration_slope": slope is not None and lo <= slope <= hi,
        "evidence_coverage": metrics.get("evidence_coverage", 0) >= gates["minimum_evidence_coverage"],
        "temporal_integrity": metrics.get("temporal_integrity_errors", 999) <=
                              gates["maximum_temporal_integrity_errors"],
    }
    return all(checks.values()), checks


def main():
    registry, gates = load(REGISTRY), load(GATES)["gates"]
    summaries = {}
    for path in sorted(glob.glob(SUMMARIES)):
        row = load(path)
        summaries[(row.get("model_version"), row.get("forecast_family"), row.get("horizon"))] = row
    errors = []
    approved = [m for m in registry.get("models", []) if m.get("approved_for_publication")]
    if approved and not glob.glob(COVERAGE_GLOB):
        errors.append(
            "被覆記録（forecaster/evidence/source-coverage/）が1件も無いのに"
            "approved_for_publication のモデルがある。miss が立たない状態の指標では昇格できない"
        )
    for model in registry.get("models", []):
        matched = [row for key, row in summaries.items()
                   if key[0] == model.get("model_version") and key[1] == model.get("forecast_family")]
        expected_horizons = {"72h", "7d", "30d"}
        if not matched:
            errors.append(f"{model.get('model_version')}: promotion summaryがない（生成経路未接続）")
            continue
        got_horizons = {row.get("horizon") for row in matched}
        if got_horizons != expected_horizons:
            errors.append(f"{model.get('model_version')}: promotion summaryのhorizonが不完全 {sorted(got_horizons)}")
        if not model.get("approved_for_publication"):
            continue
        if not model.get("public_forecast_eligible", True):
            errors.append(
                f"{model.get('model_version')}: {model.get('evaluation_profile')} は"
                "弁別モデルではないため公開予報へ昇格できない"
            )
        for row in matched:
            ok, checks = passes(row, gates, model.get("evaluation_profile", "discriminative"))
            if not ok:
                failed = sorted(name for name, passed in checks.items() if not passed)
                errors.append(f"{model.get('model_version')}:{row.get('horizon')}: gate未達 {failed}")
    for error in errors:
        print(f"  [E] {error}")
    print(f"model promotion: approved={sum(bool(m.get('approved_for_publication')) for m in registry.get('models', []))} "
          f"errors={len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
