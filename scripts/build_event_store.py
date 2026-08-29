#!/usr/bin/env python3
"""observation v1.1を不変のObservation Event v2へ変換する互換adapter。"""

import argparse
import hashlib
import json
import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tactical_time import iso_utc, load_evidence_index, observation_available_at  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBS_ROOT = os.path.join(REPO_ROOT, "forecaster", "observations")
EVENT_ROOT = os.path.join(REPO_ROOT, "forecaster", "events")
HISTORY_PATH = os.path.join(REPO_ROOT, "forecaster", "knowledge", "attack-group-history.json")
GENERATOR_VERSION = "observation-event-adapter-v1"

STAGE_EVENT = {
    "none": "VULNERABILITY_DISCLOSED",
    "unknown": "VULNERABILITY_DISCLOSED",
    "poc_public": "POC_PUBLISHED",
    "limited_exploitation": "EXPLOITATION_LIMITED",
    "active_exploitation": "EXPLOITATION_CONFIRMED",
    "kev_listed": "INSTITUTIONAL_PUBLICATION",
}


def canonical_hash(value):
    blob = json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def attack_version():
    try:
        with open(HISTORY_PATH, encoding="utf-8") as f:
            return f"MITRE ATT&CK v{json.load(f).get('_attack_version', 'unknown')}"
    except (OSError, json.JSONDecodeError):
        return "repository-attack-version-unknown"


def observation_cohort(doc):
    mode = doc.get("_normalization_mode", "")
    return ("machine_backfill" if doc.get("_retro_normalized") or
            mode.startswith("machine_backfill") else "prospective_live")


def event_type_for(observation):
    if observation.get("cve"):
        return STAGE_EVENT.get(observation.get("exploitation_stage"),
                               "VULNERABILITY_DISCLOSED")
    if observation.get("actor_group"):
        return "TARGETING_OBSERVED"
    if observation.get("iocs"):
        return "INFRASTRUCTURE_OBSERVED"
    return "THREAT_REPORT_PUBLISHED"


def make_event(observation, subject, doc, evidence_index):
    source = observation.get("source") or {}
    claim = canonical_hash({
        "url": source.get("url"),
        "summary": observation.get("summary"),
        "subject": subject,
    })
    event_type = event_type_for(observation)
    event_key = {
        "event_type": event_type,
        "subject": subject,
        "observed_date": observation.get("observed_date"),
        "claim": claim,
    }
    cves = observation.get("cve") or []
    techniques = []
    for t in observation.get("techniques") or []:
        row = dict(t)
        if len(cves) == 1:
            row["scope_ref"] = cves[0]
        techniques.append(row)

    confidence = observation.get("confidence")
    assertion = "confirmed" if confidence == "high" else "probable"
    visibility = "high" if source.get("type") in ("vendor_report", "advisory") else "medium"
    observability = "closed_world" if event_type == "INSTITUTIONAL_PUBLICATION" else "bounded_open_world"
    return {
        "event_id": f"evt-{canonical_hash(event_key)[:16]}",
        "event_type": event_type,
        "event_time": {
            "start_utc": observation.get("observed_date"),
            "end_utc": observation.get("observed_date"),
            "precision": "day",
        },
        "available_at_utc": iso_utc(observation_available_at(observation, evidence_index)),
        "evidence_ids": observation.get("evidence_ids") or [],
        "legacy_observation_ids": [observation["observation_id"]],
        "subject_refs": [subject],
        "object_refs": [],
        "actor_refs": ([{"type": "actor", "id": observation["actor_group"]}]
                       if observation.get("actor_group") else []),
        "campaign_id": None,
        "techniques": techniques,
        "targets": observation.get("target") or {"sectors": [], "geos": []},
        "visibility": visibility,
        "outcome_observability": observability,
        "assertion_status": assertion,
        "claim_fingerprint": claim,
        "upstream_claim_id": None,
        "supersedes_event_id": None,
        "summary_fact": observation.get("summary", ""),
        "cohort": observation_cohort(doc),
        "attack_version": attack_version(),
        "generator_version": GENERATOR_VERSION,
    }


def build_for_date(day, evidence_index=None):
    path = os.path.join(OBS_ROOT, f"{day.year:04d}", f"{day.month:02d}",
                        f"{day.isoformat()}.json")
    if not os.path.exists(path):
        raise SystemExit(f"[fatal] observation fileがない: {path}")
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    evidence_index = evidence_index if evidence_index is not None else load_evidence_index(REPO_ROOT)
    events = []
    for obs in doc.get("observations", []):
        cves = obs.get("cve") or []
        if cves:
            subjects = [{"type": "vulnerability", "id": cve} for cve in cves]
        elif obs.get("actor_group"):
            subjects = [{"type": "actor", "id": obs["actor_group"]}]
        else:
            subjects = [{"type": "report", "id": obs["observation_id"]}]
        events.extend(make_event(obs, subject, doc, evidence_index) for subject in subjects)

    # 同じcanonical eventの再取得を一件へ統合し、lineageは和集合で保持する。
    unique = {}
    for event in events:
        eid = event["event_id"]
        if eid not in unique:
            unique[eid] = event
            continue
        prior = unique[eid]
        prior["evidence_ids"] = sorted(set(prior["evidence_ids"] + event["evidence_ids"]))
        prior["legacy_observation_ids"] = sorted(set(
            prior["legacy_observation_ids"] + event["legacy_observation_ids"]))
    return {
        "_schema_version": "2.0",
        "_event_date": day.isoformat(),
        "_generator": GENERATOR_VERSION,
        "_source_observation_path": os.path.relpath(path, REPO_ROOT),
        "events": [unique[k] for k in sorted(unique)],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", required=True, help="YYYY-MM-DD")
    ap.add_argument("--print-only", action="store_true")
    args = ap.parse_args()
    day = date.fromisoformat(args.date)
    doc = build_for_date(day)
    print(f"[events] {day}: {len(doc['events'])} events")
    if args.print_only:
        return 0
    out = os.path.join(EVENT_ROOT, f"{day.year:04d}", f"{day.month:02d}",
                       f"{day.isoformat()}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"[out] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
