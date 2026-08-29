#!/usr/bin/env python3
"""Observation Eventからvulnerability/campaign episodeを構成する。"""

import argparse
import glob
import hashlib
import json
import os
import sys
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVENT_GLOB = os.path.join(REPO_ROOT, "forecaster", "events", "*", "*", "*.json")
OUT_ROOT = os.path.join(REPO_ROOT, "forecaster", "episodes")


def short_hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def load_events():
    out = []
    for path in sorted(glob.glob(EVENT_GLOB)):
        try:
            with open(path, encoding="utf-8") as f:
                out.extend(json.load(f).get("events", []))
        except (OSError, json.JSONDecodeError):
            continue
    return out


def build(events):
    vulnerabilities, campaigns = defaultdict(list), defaultdict(list)
    for event in events:
        for ref in event.get("subject_refs", []):
            if ref.get("type") == "vulnerability":
                vulnerabilities[ref["id"]].append(event)
        campaign = event.get("campaign_id")
        if campaign:
            campaigns[campaign].append(event)

    episodes = []
    for cve, rows in sorted(vulnerabilities.items()):
        episodes.append(_episode("vulnerability", cve, rows))
    for campaign, rows in sorted(campaigns.items()):
        episodes.append(_episode("campaign", campaign, rows))
    return episodes


def _episode(kind, entity_id, rows):
    rows = sorted(rows, key=lambda e: (
        (e.get("event_time") or {}).get("start_utc") or "9999",
        e.get("available_at_utc") or "9999", e["event_id"]))
    by_time = defaultdict(list)
    for e in rows:
        key = (e.get("event_time") or {}).get("start_utc") or "unknown"
        by_time[key].append(e)
    order_groups = {key: i + 1 for i, key in enumerate(sorted(by_time))}
    event_refs = []
    for e in rows:
        key = (e.get("event_time") or {}).get("start_utc") or "unknown"
        group = by_time[key]
        event_refs.append({
            "event_id": e["event_id"],
            "order_group": order_groups[key],
            "order_status": "known" if len(group) == 1 and key != "unknown" else "same_time_unknown",
        })
    times = [(e.get("event_time") or {}).get("start_utc") for e in rows]
    times = [t for t in times if t]
    visibility_order = {"low": 0, "medium": 1, "high": 2}
    visibility = min((e.get("visibility", "low") for e in rows),
                     key=lambda v: visibility_order.get(v, 0))
    return {
        "episode_id": f"ep-{kind[:4]}-{short_hash(entity_id)}",
        "episode_type": kind,
        "entity_refs": [{"type": kind, "id": entity_id}],
        "first_seen_utc": min(times) if times else None,
        "last_seen_utc": max(times) if times else None,
        "events": event_refs,
        "current_objective": None,
        "visibility": visibility,
        "open": True,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--print-only", action="store_true")
    args = ap.parse_args()
    episodes = build(load_events())
    doc = {"_schema_version": "1.0", "_generator": "scripts/build_episodes.py",
           "episodes": episodes}
    print(f"[episodes] {len(episodes)}")
    if args.print_only:
        return 0
    os.makedirs(OUT_ROOT, exist_ok=True)
    out = os.path.join(OUT_ROOT, "episodes.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"[out] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
