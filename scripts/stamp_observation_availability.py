#!/usr/bin/env python3
"""正規化済みobservationへ機械時刻とEvidence Ledger参照を付けv1.2へ昇格する。"""

import argparse
import json
import os
import tempfile
from datetime import date, datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def iso(value):
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timezoneが必要")
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", required=True)
    ap.add_argument("--available-at-utc", help="テスト/再現用。既定は実行時UTC")
    args = ap.parse_args()
    day = date.fromisoformat(args.date)
    at = iso(args.available_at_utc or datetime.now(timezone.utc))
    obs_path = os.path.join(ROOT, "forecaster", "observations", f"{day.year:04d}",
                            f"{day.month:02d}", f"{day.isoformat()}.json")
    manifest_path = os.path.join(ROOT, "forecaster", "evidence", "manifests",
                                 f"{day.year:04d}", f"{day.month:02d}", f"{day.isoformat()}.json")
    with open(obs_path, encoding="utf-8") as f:
        doc = json.load(f)
    by_url = {}
    if os.path.exists(manifest_path):
        with open(manifest_path, encoding="utf-8") as f:
            for evidence in json.load(f).get("evidence", []):
                by_url.setdefault(evidence.get("source_url"), []).append(evidence["evidence_id"])
    for observation in doc.get("observations", []):
        observation["available_at_utc"] = at
        url = (observation.get("source") or {}).get("url")
        observation["evidence_ids"] = sorted(set(by_url.get(url, [])))
    doc["_schema_version"] = "1.2"
    doc["_generated_at_utc"] = at
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=os.path.dirname(obs_path),
                                     delete=False) as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
        temp_name = f.name
    os.replace(temp_name, obs_path)
    linked = sum(bool(o["evidence_ids"]) for o in doc.get("observations", []))
    print(f"[availability] {day}: {len(doc.get('observations', []))} observations, "
          f"evidence-linked={linked}, at={at}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
