#!/usr/bin/env python3
"""Event/Case/Episode/configのv3契約を標準ライブラリだけで検証する。"""

import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tactical_time import parse_utc  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVENT_GLOB = os.path.join(ROOT, "forecaster", "events", "*", "*", "*.json")
CASE_GLOB = os.path.join(ROOT, "forecaster", "cases", "*.json")
EPISODES = os.path.join(ROOT, "forecaster", "episodes", "episodes.json")
MODE = os.path.join(ROOT, "forecaster", "config", "tactical-mode.json")
REGISTRY = os.path.join(ROOT, "forecaster", "models", "model-registry.json")
UNIVERSES = os.path.join(ROOT, "forecaster", "knowledge", "source-universes.json")

EVENT_KEYS = {
    "event_id", "event_type", "event_time", "available_at_utc", "evidence_ids",
    "legacy_observation_ids", "subject_refs", "object_refs", "actor_refs", "campaign_id",
    "techniques", "targets", "visibility", "outcome_observability", "assertion_status",
    "claim_fingerprint", "upstream_claim_id", "supersedes_event_id", "summary_fact",
    "cohort", "attack_version", "generator_version",
}


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    errors, event_ids = [], set()
    for path in sorted(glob.glob(EVENT_GLOB)):
        doc = load(path)
        if doc.get("_schema_version") != "2.0":
            errors.append(f"{path}: event schema version")
        for event in doc.get("events", []):
            eid = event.get("event_id")
            if not eid or eid in event_ids:
                errors.append(f"{path}: duplicate/missing event_id {eid}")
            event_ids.add(eid)
            unknown = set(event) - EVENT_KEYS
            if unknown:
                errors.append(f"{eid}: unknown fields {sorted(unknown)}")
            try:
                parse_utc(event.get("available_at_utc"))
            except ValueError:
                errors.append(f"{eid}: invalid available_at_utc")
            if not event.get("subject_refs") or not event.get("claim_fingerprint"):
                errors.append(f"{eid}: subject/claim lineage missing")
            if event.get("cohort") not in {"prospective_live", "machine_backfill", "historical_case"}:
                errors.append(f"{eid}: invalid cohort")

    case_ids = set()
    for path in sorted(glob.glob(CASE_GLOB)):
        for case in load(path).get("cases", []):
            cid = case.get("case_id")
            if not cid or cid in case_ids:
                errors.append(f"{path}: duplicate/missing case_id {cid}")
            case_ids.add(cid)
            for event in case.get("ordered_events") or []:
                if event.get("order_status") != "unknown":
                    errors.append(f"{cid}: ATT&CK列挙順を時間順へ昇格している")
            if not case.get("selection_bias_notes"):
                errors.append(f"{cid}: selection bias note missing")

    if os.path.exists(EPISODES):
        seen_episodes = set()
        for episode in load(EPISODES).get("episodes", []):
            eid = episode.get("episode_id")
            if not eid or eid in seen_episodes:
                errors.append(f"duplicate/missing episode_id {eid}")
            seen_episodes.add(eid)
            for ref in episode.get("events") or []:
                if ref.get("event_id") not in event_ids:
                    errors.append(f"{eid}: unknown event ref {ref.get('event_id')}")
                if ref.get("order_status") not in {"known", "same_time_unknown", "unknown"}:
                    errors.append(f"{eid}: invalid order status")

    mode, registry, universes = load(MODE), load(REGISTRY), load(UNIVERSES)
    if mode.get("mode") == "shadow" and (
            mode.get("published_families") or mode.get("max_tactical_forecasts") != 0):
        errors.append("shadow modeはpublished_families=[]かつmax=0でなければならない")
    models = registry.get("models") or []
    if len({m.get("model_version") for m in models}) != len(models):
        errors.append("model_versionが重複")
    for uid, universe in (universes.get("universes") or {}).items():
        negative = universe.get("negative_outcome_allowed")
        if negative is True and universe.get("observability") != "closed_world":
            errors.append(f"{uid}: open worldで無条件missを許可している")
        if negative not in {False, True, "coverage_proven"}:
            errors.append(f"{uid}: negative_outcome_allowedが不正")

    for error in errors:
        print(f"  [E] {error}")
    print(f"tactical schemas: events={len(event_ids)} cases={len(case_ids)} errors={len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
