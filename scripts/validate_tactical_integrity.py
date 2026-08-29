#!/usr/bin/env python3
"""Tactical state/candidate の時刻・参照率・凍結hashをfail-closed検証する。"""

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tactical_integrity import hash_without, sha256_value  # noqa: E402
from tactical_states import HORIZONS_DAYS, HORIZON_LABELS, reference_key  # noqa: E402
from tactical_time import parse_utc  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_ROOT = os.path.join(ROOT, "forecaster", "state", "tactical")
CAND_ROOT = os.path.join(ROOT, "forecaster", "candidates", "tactical")
EXCLUSIONS = os.path.join(ROOT, "forecaster", "verification", "tactical", "exclusions.json")


def excluded_paths():
    if not os.path.exists(EXCLUSIONS):
        return set()
    with open(EXCLUSIONS, encoding="utf-8") as f:
        return {x["artifact"] for x in json.load(f).get("exclusions", [])}


def rel(path):
    return os.path.relpath(path, ROOT)


def check_state(path, errors):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if doc.get("_schema_version") != "2.0":
        errors.append(f"{rel(path)}: tactical state schema v2ではない")
        return
    manifest = doc.get("_input_manifest")
    expected = doc.get("_input_manifest_sha256")
    if not manifest or sha256_value(manifest) != expected:
        errors.append(f"{rel(path)}: input manifest hash不一致")
    cutoff = parse_utc(doc.get("_cutoff_at_utc"))
    for state in doc.get("states", []):
        if parse_utc(state.get("as_of_utc")) != cutoff:
            errors.append(f"{state.get('state_id')}: as_ofとcutoffが不一致")
        if state.get("input_manifest_sha256") != expected:
            errors.append(f"{state.get('state_id')}: manifest hash継承不一致")


def check_candidate_file(path, errors):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if doc.get("_schema_version") != "2.0":
        errors.append(f"{rel(path)}: tactical forecast schema v2ではない")
        return
    if hash_without(doc, "_ledger_sha256") != doc.get("_ledger_sha256"):
        errors.append(f"{rel(path)}: ledger hash不一致")
    cutoff = parse_utc(doc.get("_cutoff_at_utc"))
    issued = parse_utc(doc.get("_issued_at_utc"))
    if issued < cutoff:
        errors.append(f"{rel(path)}: issued_atがcutoffより前")
    for c in doc.get("candidates", []):
        cid = c.get("candidate_id")
        if hash_without(c, "content_sha256") != c.get("content_sha256"):
            errors.append(f"{cid}: content hash不一致")
        if parse_utc(c.get("cutoff_at_utc")) != cutoff:
            errors.append(f"{cid}: candidate cutoff不一致")
        if parse_utc(c.get("issued_at_utc")) != issued:
            errors.append(f"{cid}: candidate issued_at不一致")
        te = c.get("target_event") or {}
        if c.get("selection", {}).get("status") == "abstained":
            continue
        for h in HORIZONS_DAYS:
            ref = (c.get("reference_class") or {}).get(HORIZON_LABELS[h]) or {}
            expected = reference_key(
                c.get("current_state"), te.get("event_type"), te.get("next_state"), h)
            if ref.get("key") != expected:
                errors.append(f"{cid}: target-event参照率key不一致({HORIZON_LABELS[h]})")
        if te.get("matching_rule_version") not in {"tf1-poc-v2", "tf1-exploitation-v2"}:
            errors.append(f"{cid}: 未固定または旧matching rule")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--date")
    args = ap.parse_args()
    errors, skipped = [], []
    exclusions = excluded_paths()
    if args.all:
        state_paths = sorted(glob.glob(os.path.join(STATE_ROOT, "*", "*", "*.json")))
        cand_paths = sorted(glob.glob(os.path.join(CAND_ROOT, "*.json")))
    else:
        if not args.date:
            ap.error("--date または --all が必要")
        y, m = args.date[:4], args.date[5:7]
        state_paths = [os.path.join(STATE_ROOT, y, m, f"{args.date}.json")]
        cand_paths = [os.path.join(CAND_ROOT, f"{args.date}.json")]
    for path in state_paths + cand_paths:
        if not os.path.exists(path):
            continue
        if rel(path) in exclusions:
            skipped.append(rel(path))
            continue
        (check_state if f"{os.sep}state{os.sep}" in path else check_candidate_file)(path, errors)
    for item in skipped:
        print(f"  [X] excluded: {item}")
    for error in errors:
        print(f"  [E] {error}")
    print(f"tactical integrity: errors={len(errors)} excluded={len(skipped)}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
