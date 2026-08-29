#!/usr/bin/env python3
"""MITRE ATT&CK由来の既存attack-group-historyを監査可能なCase Libraryへ投影する。"""

import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(REPO_ROOT, "forecaster", "knowledge", "attack-group-history.json")
OUT = os.path.join(REPO_ROOT, "forecaster", "cases", "mitre-attack-campaigns.json")


def build(doc):
    cases = []
    version = str(doc.get("_attack_version", "unknown"))
    for group_name, group in sorted((doc.get("groups") or {}).items()):
        for campaign in group.get("campaigns") or []:
            citation = campaign.get("citation") or {}
            cases.append({
                "case_id": f"case-mitre-{campaign['campaign_id']}",
                "case_type": "campaign",
                "time_range": {
                    "start": campaign.get("first_seen"),
                    "end": campaign.get("last_seen"),
                    "precision": "day",
                },
                "actor_refs": [{"type": "actor", "id": group_name,
                                "attack_id": group.get("attack_id")}],
                "campaign_refs": [{"type": "campaign", "id": campaign["campaign_id"],
                                   "name": campaign.get("name")}],
                "products": [],
                "initial_access": [],
                "ordered_events": [{"technique_id": tid, "order_status": "unknown"}
                                   for tid in campaign.get("technique_ids") or []],
                "targets": {"sectors": [], "geos": []},
                "outcomes": [],
                "source_references": [{"source": citation.get("source"),
                                       "url": citation.get("url")}],
                "selection_bias_notes": [
                    "MITRE ATT&CKへ収載された公表済み事例であり、非公表・失敗事例を含まない",
                    "Techniqueの列挙順は時間順ではないため遷移学習へ使用禁止",
                ],
                "review_status": "cited",
            })
    return {"_schema_version": "1.0", "_attack_version": version,
            "_generator": "scripts/build_case_library.py", "cases": cases}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--print-only", action="store_true")
    args = ap.parse_args()
    with open(SOURCE, encoding="utf-8") as f:
        doc = build(json.load(f))
    print(f"[cases] {len(doc['cases'])}")
    if args.print_only:
        return 0
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"[out] {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
