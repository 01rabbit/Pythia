#!/usr/bin/env python3
"""モデル昇格が前向き評価ゲートに裏付けられているかfail-closed検証する。"""

import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(ROOT, "forecaster", "models", "model-registry.json")
GATES = os.path.join(ROOT, "forecaster", "config", "promotion-gates.json")
SUMMARIES = os.path.join(ROOT, "forecaster", "verification", "tactical", "promotion-*.json")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def passes(metrics, gates):
    slope = metrics.get("calibration_slope")
    lo, hi = gates["calibration_slope_range"]
    checks = {
        "resolved_n": metrics.get("resolved_n", 0) >= gates["minimum_resolved_n"],
        "positive_events": metrics.get("positive_events", 0) >= gates["minimum_positive_events"],
        "brier_skill_score": metrics.get("brier_skill_score", -999) > gates["minimum_brier_skill_score"],
        "auc_lower_95": metrics.get("auc_lower_95", 0) > gates["minimum_auc_lower_95"],
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
    for model in registry.get("models", []):
        if not model.get("approved_for_publication"):
            continue
        matched = [row for key, row in summaries.items()
                   if key[0] == model.get("model_version") and key[1] == model.get("forecast_family")]
        if not matched:
            errors.append(f"{model.get('model_version')}: promotion summaryがない")
            continue
        for row in matched:
            ok, checks = passes(row, gates)
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
