#!/usr/bin/env python3
"""matching ruleの監視成否を記録し、負の判定を監査可能にする。"""

import argparse
import hashlib
import json
import os
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_ROOT = os.path.join(ROOT, "forecaster", "evidence", "source-coverage")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rule", required=True)
    ap.add_argument("--window-start-utc", required=True)
    ap.add_argument("--window-end-utc", required=True)
    ap.add_argument("--source-status", action="append", required=True,
                    help="source=ok|error。ruleの全sourceを列挙する")
    args = ap.parse_args()
    statuses = {}
    for item in args.source_status:
        source, sep, status = item.partition("=")
        if not sep or status not in {"ok", "error"}:
            ap.error(f"不正な --source-status: {item}")
        statuses[source] = status
    payload = {
        "_schema_version": "1.0", "matching_rule_version": args.rule,
        "window_start_utc": args.window_start_utc, "window_end_utc": args.window_end_utc,
        "sources": statuses,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"))
                            .encode("utf-8")).hexdigest()
    payload["content_sha256"] = digest
    os.makedirs(OUT_ROOT, exist_ok=True)
    out = os.path.join(OUT_ROOT, f"coverage-{digest[:16]}.json")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=OUT_ROOT, delete=False) as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
        temp_name = f.name
    os.replace(temp_name, out)
    print(f"[out] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
