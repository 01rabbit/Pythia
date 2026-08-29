#!/usr/bin/env python3
"""凍結候補から公開portfolioを決定論的に選ぶ。shadowでは公開0件を強制する。"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "forecaster", "config", "tactical-mode.json")
REGISTRY = os.path.join(ROOT, "forecaster", "models", "model-registry.json")
CAND_ROOT = os.path.join(ROOT, "forecaster", "candidates", "tactical")


def utility(candidate, policy):
    """事前登録rubricだけでutilityを計算する。欠損をLLM推定で埋めない。"""
    probabilities = candidate.get("probability_by_horizon") or {}
    features = candidate.get("decision_features") or {}
    required = ("consequence", "lead_time_value", "actionability", "novelty")
    if probabilities.get("7d") is None or any(name not in features for name in required):
        return None
    rubric = policy["rubric"]
    values = [rubric[name].get(features[name]) for name in required]
    if any(value is None for value in values):
        return None
    score = probabilities["7d"]
    for value in values:
        score *= value
    return round(score, 6)


def select(doc, config, registry, policy=None):
    policy = policy or {
        "rubric": {
            "consequence": {}, "lead_time_value": {}, "actionability": {}, "novelty": {}
        }
    }
    mode = config["mode"]
    approved = {m["model_version"] for m in registry["models"] if m.get("approved_for_publication")}
    eligible = []
    for c in doc.get("candidates", []):
        if c.get("selection", {}).get("status") == "abstained":
            continue
        score = utility(c, policy)
        if (score is not None and c.get("model_version") in approved
                and c["forecast_family"] in config["published_families"]):
            eligible.append({
                "candidate_id": c["candidate_id"],
                "content_sha256": c.get("content_sha256"),
                "model_version": c["model_version"],
                "forecast_family": c["forecast_family"],
                "utility_score": score,
            })
    eligible.sort(key=lambda c: (-c["utility_score"], c["candidate_id"]))
    limit = config["max_tactical_forecasts"] if mode in {"limited", "active"} else 0
    return eligible[:limit]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", required=True)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    with open(CONFIG, encoding="utf-8") as f:
        config = json.load(f)
    with open(REGISTRY, encoding="utf-8") as f:
        registry = json.load(f)
    policy_path = os.path.join(ROOT, "forecaster", "models", "selection-policy.json")
    with open(policy_path, encoding="utf-8") as f:
        policy = json.load(f)
    path = os.path.join(CAND_ROOT, f"{args.date}.json")
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    selected = select(doc, config, registry, policy)
    print(f"[portfolio] mode={config['mode']} selected={len(selected)}")
    if config["mode"] == "shadow" and selected:
        raise SystemExit("[fatal] shadow modeで公開候補が選ばれた")
    if args.write:
        out = os.path.join(CAND_ROOT, f"{args.date}-portfolio.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"mode": config["mode"], "selected": selected}, f,
                      ensure_ascii=False, indent=2)
            f.write("\n")
        print(f"[out] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
