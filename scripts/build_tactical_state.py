#!/usr/bin/env python3
"""observations から TF-1 の現在戦術状態を構成する（設計 §4.1 / §12 第1段階）。

出力: forecaster/state/tactical/YYYY/MM/YYYY-MM-DD.json

★LLM は状態名を自由生成しない（設計 §8）。状態は scripts/tactical_states.py の
  有限集合から、次の2つの機械的根拠だけで決まる:
    1. observation.exploitation_stage の対応表
    2. 侵入後 tactic の Technique が付いていれば POST_EXPLOIT_ACTIVITY
       （Technique は 01-normalize.md R3 により「情報源が具体的手口を記述して
         いる場合のみ」付与されているので、記録された事実であって推測ではない）
  本文のキーワードから状態を推定することはしない（原則1）。

state_confidence（設計 §4.1）:
  confirmed  … 複数の独立した観測、または CERT/政府機関・ベンダー一次情報が根拠
  probable   … 単一の信頼できる観測が根拠
  uncertain  … 根拠が矛盾する（同日に前進度の異なる状態が併存する）
  ★根拠が矛盾する場合は上位状態へ進めず uncertain とする（設計 §4.1）。

使い方:
    python3 scripts/build_tactical_state.py --date 2026-08-29 \
      --cutoff-at-utc 2026-08-29T06:00:00Z
    python3 scripts/build_tactical_state.py --date 2026-08-29 \
      --cutoff-at-utc 2026-08-29T06:00:00Z --print-only
"""

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tactical_states import STATE_RANK, derive_state  # noqa: E402
from tactical_time import (  # noqa: E402
    iso_utc, load_evidence_index, observation_available_at as _observation_available_at,
    parse_utc,
)
from tactical_integrity import sha256_value  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBS_GLOB = os.path.join(REPO_ROOT, "forecaster", "observations", "*", "*", "*.json")
EVENT_GLOB = os.path.join(REPO_ROOT, "forecaster", "events", "*", "*", "*.json")
STATE_ROOT = os.path.join(REPO_ROOT, "forecaster", "state", "tactical")
JST = timezone(timedelta(hours=9))

# 状態を構成するときに遡る日数。これより古い観測は「現在の状態」とみなさない。
LOOKBACK_DAYS = 30

# 一次情報とみなす source.type（confirmed への昇格条件）
PRIMARY_SOURCE_TYPES = {"advisory", "vendor_report"}


def observation_available_at_compat(observation, evidence_index=None):
    """テストと外部呼び出し向けの後方互換alias。"""
    return _observation_available_at(observation, evidence_index)


# 受入テストが参照する公開名。
observation_available_at = observation_available_at_compat


def load_observations(cutoff, lookback=LOOKBACK_DAYS, evidence_index=None):
    """cutoff以前に利用可能だったlookback日以内の観測だけを返す。"""
    cutoff = parse_utc(cutoff)
    upto = cutoff.astimezone(JST).date()
    lo = upto - timedelta(days=lookback)
    evidence_index = evidence_index if evidence_index is not None else load_evidence_index(REPO_ROOT)
    out = []
    for path in sorted(glob.glob(OBS_GLOB)):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for o in doc.get("observations", []):
            d = o.get("observed_date")
            if not d:
                continue
            try:
                dd = date.fromisoformat(d)
            except ValueError:
                continue
            if lo <= dd <= upto and observation_available_at(o, evidence_index) <= cutoff:
                out.append((dd, o))
    return out


def load_event_lineage(cutoff):
    """legacy observation ID -> event/evidence refs。cutoff後のeventは使わない。"""
    cutoff = parse_utc(cutoff)
    out = defaultdict(lambda: {"events": set(), "evidence": set()})
    for path in sorted(glob.glob(EVENT_GLOB)):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for event in doc.get("events", []):
            try:
                if parse_utc(event["available_at_utc"]) > cutoff:
                    continue
            except (KeyError, ValueError):
                continue
            for oid in event.get("legacy_observation_ids") or []:
                out[oid]["events"].add(event["event_id"])
                out[oid]["evidence"].update(event.get("evidence_ids") or [])
    return out


def build_states(as_of, observations, cutoff_at_utc, event_lineage=None):
    """CVE ごとに tactical_state を構成する。"""
    per = defaultdict(list)
    for dd, o in observations:
        for cve in (o.get("cve") or []):
            st, basis = derive_state(o, subject_id=cve)
            if not st:
                continue
            per[cve].append((dd, st, basis, o))

    states = []
    event_lineage = event_lineage or {}
    for cve, points in sorted(per.items()):
        points.sort(key=lambda x: (x[0], STATE_RANK.get(x[1], 0)))
        best_rank = max(STATE_RANK[s] for _d, s, _b, _o in points)
        top = [p for p in points if STATE_RANK[p[1]] == best_rank]
        current = top[-1][1]
        started = min(p[0] for p in top)

        latest_day = max(p[0] for p in points)
        same_day_states = {p[1] for p in points if p[0] == latest_day}
        contradictory = len(same_day_states) > 1

        obs_ids = [p[3]["observation_id"] for p in points]
        sources = {(p[3].get("source") or {}).get("type") for p in points}
        confidences = {p[3].get("confidence") for p in points}

        if contradictory:
            confidence = "uncertain"
        elif len(obs_ids) >= 2 or (sources & PRIMARY_SOURCE_TYPES) or "high" in confidences:
            confidence = "confirmed"
        else:
            confidence = "probable"

        targets = {"sectors": set(), "geos": set()}
        techniques, unknowns = set(), []
        for _d, _s, _b, o in points:
            t = o.get("target") or {}
            targets["sectors"].update(t.get("sectors") or [])
            targets["geos"].update(t.get("geos") or [])
            for tech in (o.get("techniques") or []):
                scope = tech.get("scope_ref")
                cves = o.get("cve") or []
                applies = (scope == cve) if scope else (len(cves) == 1 and cves[0] == cve)
                if applies and tech.get("technique_id"):
                    techniques.add(tech["technique_id"])
            if o.get("techniques_note"):
                unknowns.append(o["techniques_note"])

        event_ids, evidence_ids = set(), set()
        for oid in obs_ids:
            lineage = event_lineage.get(oid) or {}
            event_ids.update(lineage.get("events") or [])
            evidence_ids.update(lineage.get("evidence") or [])

        states.append({
            "state_id": f"state-{as_of.isoformat().replace('-', '')}-{cve}",
            "subject_type": "vulnerability",
            "subject_id": cve,
            "as_of_utc": iso_utc(cutoff_at_utc),
            "current_state": current,
            "state_basis": sorted({p[2] for p in top if p[2]}),
            "state_started_at_utc": started.isoformat(),
            "observation_ids": sorted(set(obs_ids)),
            "basis_event_ids": sorted(event_ids),
            "basis_evidence_ids": sorted(evidence_ids),
            "state_confidence": confidence,
            "known_targets": {k: sorted(v) for k, v in targets.items()},
            "known_techniques": sorted(techniques),
            "unknowns": unknowns,
            "_contradictory_same_day_states": sorted(same_day_states) if contradictory else [],
        })
    return states


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", help="基準日 YYYY-MM-DD（既定: JST の本日）")
    ap.add_argument("--cutoff-at-utc", required=True,
                    help="入力を固定した実時刻（UTC ISO 8601）。この時刻より後の観測は使わない")
    ap.add_argument("--print-only", action="store_true")
    args = ap.parse_args()

    cutoff = parse_utc(args.cutoff_at_utc)
    cutoff_date = cutoff.astimezone(JST).date()
    as_of = date.fromisoformat(args.date) if args.date else cutoff_date
    if as_of != cutoff_date:
        raise SystemExit(
            f"[fatal] --date {as_of} は cutoff のJST日付 {cutoff_date} と一致しない")
    evidence_index = load_evidence_index(REPO_ROOT)
    obs = load_observations(cutoff, evidence_index=evidence_index)
    states = build_states(as_of, obs, cutoff, load_event_lineage(cutoff))

    manifest = {
        "cutoff_at_utc": iso_utc(cutoff),
        "lookback_days": LOOKBACK_DAYS,
        "observations": sorted((
            {"observation_id": o["observation_id"], "content_sha256": sha256_value(o)}
            for _d, o in obs
        ), key=lambda row: row["observation_id"]),
    }
    manifest_hash = sha256_value(manifest)
    for state in states:
        state["counterevidence_event_ids"] = []
        state["input_manifest_sha256"] = manifest_hash
        state["state_model_version"] = "tf1-state-v2"

    doc = {
        "_schema_version": "2.0",
        "_as_of_date": as_of.isoformat(),
        "_cutoff_at_utc": iso_utc(cutoff),
        "_generator": "scripts/build_tactical_state.py",
        "_lookback_days": LOOKBACK_DAYS,
        "_input_manifest": manifest,
        "_input_manifest_sha256": manifest_hash,
        "_comment": (
            "TF-1 の現在戦術状態。observations から機械的に導出したものであり、"
            "本文のキーワード推定は行っていない。date-onlyの旧観測は翌日00:00 JST"
            "まで利用しない保守的as-of規則を適用する。"
        ),
        "states": states,
    }

    from collections import Counter
    print(f"[state] as_of={as_of} 観測 {len(obs)} 件（直近{LOOKBACK_DAYS}日）"
          f" → 状態 {len(states)} 件")
    print("  現在状態の分布:", dict(Counter(s["current_state"] for s in states)))
    print("  確度の分布    :", dict(Counter(s["state_confidence"] for s in states)))

    if args.print_only:
        return 0
    out = os.path.join(STATE_ROOT, f"{as_of.year:04d}", f"{as_of.month:02d}",
                       f"{as_of.isoformat()}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"\n[out] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
