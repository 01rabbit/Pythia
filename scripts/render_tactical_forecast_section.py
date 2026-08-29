#!/usr/bin/env python3
"""日次レポート用の戦況・予報sectionを候補台帳から生成する。"""

import argparse
import json
import os
import tempfile
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_section(state_doc, candidate_doc, mode):
    published = [c for c in candidate_doc.get("candidates", [])
                 if c.get("selection", {}).get("status") == "published"]
    states = Counter(s["current_state"] for s in state_doc.get("states", []))
    statuses = Counter(c.get("selection", {}).get("status")
                       for c in candidate_doc.get("candidates", []))
    event_types = Counter((c.get("target_event") or {}).get("event_type")
                          for c in candidate_doc.get("candidates", [])
                          if c.get("selection", {}).get("status") == "shadow")
    return {
        "section_type": "tactical_forecast_v2",
        "mode": mode,
        "cutoff_at_utc": state_doc["_cutoff_at_utc"],
        "operational_picture": {
            "subjects_tracked": len(state_doc.get("states", [])),
            "state_counts": dict(sorted(states.items())),
        },
        "published_forecasts": published,
        "shadow_evaluation": ({
            "candidate_status_counts": dict(sorted(statuses.items())),
            "event_type_counts": {str(k): v for k, v in sorted(event_types.items())},
            "individual_predictions_exposed": False,
        } if mode == "shadow" else None),
        "caveat": (
            "shadow中。以下は予測ロジックの前向き検証用で、公開予報ではない。"
            if mode == "shadow" else None
        ),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", required=True)
    ap.add_argument("--out")
    ap.add_argument("--inject-report", help="既存security-report.jsonへsectionを追加する")
    args = ap.parse_args()
    y, m = args.date[:4], args.date[5:7]
    state_path = os.path.join(ROOT, "forecaster", "state", "tactical", y, m,
                              f"{args.date}.json")
    cand_path = os.path.join(ROOT, "forecaster", "candidates", "tactical", f"{args.date}.json")
    config_path = os.path.join(ROOT, "forecaster", "config", "tactical-mode.json")
    with open(state_path, encoding="utf-8") as f:
        state_doc = json.load(f)
    with open(cand_path, encoding="utf-8") as f:
        candidate_doc = json.load(f)
    with open(config_path, encoding="utf-8") as f:
        mode = json.load(f)["mode"]
    section = build_section(state_doc, candidate_doc, mode)
    if args.inject_report:
        with open(args.inject_report, encoding="utf-8") as f:
            report = json.load(f)
        report["tactical_forecast"] = section
        target = args.out or args.inject_report
        directory = os.path.dirname(os.path.abspath(target))
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory,
                                         delete=False) as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
            f.write("\n")
            temp_name = f.name
        os.replace(temp_name, target)
    elif args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(section, f, ensure_ascii=False, indent=2)
            f.write("\n")
    else:
        print(json.dumps(section, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
