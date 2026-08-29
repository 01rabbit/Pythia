#!/usr/bin/env python3
"""検証系が実際に採点できているかを機械的に監視する fail-closed ゲート。

★なぜ必要か（Blocker 1b）:
  TF-1 の universe は `negative_outcome_allowed: "coverage_proven"` であり、
  source coverage の記録が無い間は窓が満了した非 hit がすべて not_observed になる。
  さらに確認観測のチャネルが universe の宣言集合に無ければ hit も立たない。
  その結果「hit 0 / miss 0」という一見静かな出力になるが、これは
  **予報が当たっている**のでも**まだ蓄積中**でもなく、**採点が起動していない**状態である。
  沈黙と正常を区別できないので、機械的に落とす。

検査（[E] は1件でもあれば終了コード1）:
  1. [E] 窓が満了した候補があるのに hit も miss も0件（採点が1件も成立していない）
  2. [E] resolved（hit+miss+not_observed）のうち not_observed の比率が閾値超
  3. [W] blocked_by_channel > 0（事象は起きたが宣言チャネルで確認できなかった）
  4. [W] source coverage の記録が1件も無い（record_source_coverage.py 未接続）

`--effective-from` より前の日付では [E] を [W] に落とす（接続作業の猶予）。

使い方:
    python3 scripts/verify_tactical_forecasts.py --all --json > /tmp/v.json
    python3 scripts/check_verification_health.py --from-json /tmp/v.json
"""

import argparse
import glob
import json
import os
import subprocess
import sys
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COVERAGE_GLOB = os.path.join(ROOT, "forecaster", "evidence", "source-coverage", "*.json")
DEFAULT_MAX_NOT_OBSERVED = 0.90
DEFAULT_EFFECTIVE_FROM = "2026-09-30"


def load_result(args):
    if args.from_json:
        with open(args.from_json, encoding="utf-8") as f:
            return json.load(f)
    cmd = [sys.executable, os.path.join(ROOT, "scripts", "verify_tactical_forecasts.py"),
           "--all", "--json"]
    if args.as_of_utc:
        cmd += ["--as-of-utc", args.as_of_utc]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--from-json", help="verify_tactical_forecasts.py --json の出力")
    ap.add_argument("--as-of-utc")
    ap.add_argument("--max-not-observed-ratio", type=float, default=DEFAULT_MAX_NOT_OBSERVED)
    ap.add_argument("--effective-from", default=DEFAULT_EFFECTIVE_FROM,
                    help="この日以降は警告をエラーへ昇格する")
    args = ap.parse_args()

    result = load_result(args)
    enforce = date.today().isoformat() >= args.effective_from
    errors, warnings = [], []

    if not glob.glob(COVERAGE_GLOB):
        warnings.append(
            "source coverage の記録が1件も無い。record_source_coverage.py が"
            "日次パイプラインへ接続されていないと miss は原理的に成立しない"
        )

    for label, row in (result.get("by_horizon") or {}).items():
        hit, miss = row.get("hit", 0), row.get("miss", 0)
        not_obs = row.get("not_observed", 0)
        resolved = hit + miss + not_obs
        if resolved and hit + miss == 0:
            (errors if enforce else warnings).append(
                f"{label}: 窓が満了した候補が {resolved} 件あるのに hit も miss も0件。"
                "採点が1件も成立していない（沈黙を正常と区別できない）"
            )
        elif resolved:
            ratio = not_obs / resolved
            if ratio > args.max_not_observed_ratio:
                (errors if enforce else warnings).append(
                    f"{label}: not_observed が resolved の {ratio:.1%}"
                    f"（上限 {args.max_not_observed_ratio:.0%}）。"
                    "確認チャネルか source coverage の被覆が不足している"
                )
        if row.get("blocked_by_channel"):
            warnings.append(
                f"{label}: 窓内に target が成立したが宣言チャネルで確認できなかった候補が"
                f" {row['blocked_by_channel']} 件（{row.get('blocked_channels')}）"
            )

    for m in errors:
        print(f"  [E] {m}")
    for m in warnings:
        print(f"  [W] {m}")
    print(f"\n検証健全性: エラー {len(errors)} 件 / 警告 {len(warnings)} 件"
          f"（enforce={enforce} / effective_from={args.effective_from}）")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
