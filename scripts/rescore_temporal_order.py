#!/usr/bin/env python3
"""既存の検証記録を書き換えずに、時刻順序を厳格化した再集計ビューを出す（読み取り専用）。

改善計画 §4.4 / Phase 0。

背景:
  2026-08-29 の監査で、E1 的中6件すべてで CISA KEV の `dateAdded` が予報日と同日で
  あることが確認された。`dateAdded` は日付であって時刻ではないため、その日のうちの
  どの時点で追加されたかは分からない。したがって「予報を固定したのが結果より前か」
  を日付だけからは決められない。

  これは漏洩や誤採点の断定ではない。**先見性を証明できないという監査上の結論**である。
  新基準ではこの状態を `temporal_order_unknown` と呼び、厳格的中率の分子にも
  外れにも数えず、別枠で報告する。

  ★既存の判定記録（forecaster/verification/*.json）は一切書き換えない（原則D・教訓12）。
  本スクリプトは「もし新基準で数え直したらどう見えるか」を示すビューを出すだけである。

順序が決められるケース（git のコミット時刻で救えるもの）:
  予報ファイルの初出コミット時刻（author date・UTC）が、KEV `dateAdded` の
  米国東部日が始まる時刻より前であれば、結果より前に予報が固定されていたことが
  git だけで立証できる。この場合は `temporal_order_provable_by_git` とする。
  ただしリポジトリ履歴は 2026-08-07 の単一コミット（741ファイル）で一括インポート
  されており、それ以前の予報にはこの救済が効かない（コミット時刻＝インポート時刻）。

使い方:
    python3 scripts/rescore_temporal_order.py
    python3 scripts/rescore_temporal_order.py --kev-file /path/to/kev.json  # ネット不使用
    python3 scripts/rescore_temporal_order.py --json                        # 機械可読出力
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORECASTS_DIR = os.path.join(REPO_ROOT, "forecaster", "forecasts", "daily")
VERIFICATION_GLOB = os.path.join(REPO_ROOT, "forecaster", "verification", "*.json")
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# リポジトリ履歴が一括インポートされたコミットの日付。これ以前を発行日とする予報は
# git のコミット時刻が「発行時刻」を表さないため、順序の救済に使えない。
HISTORY_IMPORT_DATE = "2026-08-07"

# KEV の dateAdded は米国東部日付として読む（CISA は米国機関）。夏時間は UTC-4。
ET_OFFSET_HOURS = 4

RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / den
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def load_kev(kev_file=None):
    if kev_file:
        with open(kev_file, encoding="utf-8") as f:
            catalog = json.load(f)
    else:
        req = urllib.request.Request(KEV_FEED_URL, headers={"User-Agent": "pythia-rescore/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            catalog = json.load(resp)
    return catalog, {v["cveID"]: v["dateAdded"] for v in catalog.get("vulnerabilities", [])}


def load_sidecars():
    side = {}
    for path in glob.glob(os.path.join(FORECASTS_DIR, "*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for fc in d.get("forecasts", []):
            side[(d.get("_forecast_date"), fc.get("forecast_index"))] = (fc, path)
    return side


def first_commit_utc(path):
    """そのパスに触れた最古のコミットの author date（UTC）を返す。"""
    if not path:
        return None
    rel = os.path.relpath(path, REPO_ROOT)
    out = subprocess.run(
        ["git", "-C", REPO_ROOT, "log", "--format=%aI", "--", rel],
        capture_output=True, text=True,
    ).stdout.strip().splitlines()
    if not out:
        return None
    try:
        return datetime.fromisoformat(out[-1]).astimezone(timezone.utc)
    except ValueError:
        return None


def et_day_start_utc(date_str):
    """米国東部日付 date_str が始まる瞬間を UTC で返す。"""
    d = datetime.strptime(date_str, "%Y-%m-%d")
    return d.replace(tzinfo=timezone.utc) + timedelta(hours=ET_OFFSET_HOURS)


def classify(entry, side, kev_added):
    """1 エントリを再分類し (label, detail) を返す。"""
    fdate = entry["forecast_date"]
    fc, path = side.get((fdate, entry.get("forecast_index")), ({}, None))
    outcome = entry.get("outcome")

    if outcome != "hit":
        return outcome, {}

    cves = sorted(set(RE_CVE.findall(fc.get("hit_criteria", "") or ""))) or \
        sorted(set(RE_CVE.findall(entry.get("forecast_title", "") or "")))
    dates = [kev_added[c] for c in cves if c in kev_added]
    if not dates:
        return "hit_unresolved", {"cves": cves, "note": "現行KEVに対象CVEが見つからない"}

    added = min(dates)
    if added != fdate:
        return "hit", {"cves": cves, "date_added": added, "note": "結果日が予報日と異なる"}

    # 同日 — git のコミット時刻で順序を救えるか
    commit = first_commit_utc(path) or first_commit_utc(
        (path or "").replace(".json", ".md") if path else None
    )
    detail = {"cves": cves, "date_added": added,
              "first_commit_utc": commit.isoformat() if commit else None}

    if fdate <= HISTORY_IMPORT_DATE:
        detail["note"] = (
            f"リポジトリ履歴は {HISTORY_IMPORT_DATE} に一括インポートされており、"
            "コミット時刻は発行時刻を表さない。順序を救済できない"
        )
        return "temporal_order_unknown", detail

    if commit is None:
        detail["note"] = "コミット時刻を取得できない"
        return "temporal_order_unknown", detail

    boundary = et_day_start_utc(added)
    if commit < boundary:
        detail["note"] = (
            f"コミット {commit.isoformat()} は結果日の米国東部日が始まる "
            f"{boundary.isoformat()} より前。順序は git で立証できる"
        )
        detail["margin_hours"] = round((boundary - commit).total_seconds() / 3600, 2)
        return "temporal_order_provable_by_git", detail

    detail["note"] = f"コミット {commit.isoformat()} は結果日の米東部日開始後"
    return "temporal_order_unknown", detail


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kev-file", help="CISA KEV catalog のローカルパス（ネット不使用）")
    ap.add_argument("--json", action="store_true", help="機械可読なJSONで出力する")
    args = ap.parse_args()

    catalog, kev_added = load_kev(args.kev_file)
    side = load_sidecars()

    entries = []
    for path in sorted(glob.glob(VERIFICATION_GLOB)):
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for e in d.get("entries", []):
            entries.append(e)

    rows = []
    for e in entries:
        label, detail = classify(e, side, kev_added)
        rows.append({
            "forecast_date": e["forecast_date"],
            "forecast_index": e.get("forecast_index"),
            "outcome_channel": e.get("outcome_channel"),
            "recorded_outcome": e.get("outcome"),
            "rescored": label,
            "detail": detail,
        })

    def agg(subset):
        n = len(subset)
        hit = sum(1 for r in subset if r["rescored"] == "hit")
        prov = sum(1 for r in subset if r["rescored"] == "temporal_order_provable_by_git")
        unk = sum(1 for r in subset if r["rescored"] == "temporal_order_unknown")
        scored = n - unk
        num = hit + prov
        return {
            "n_recorded": n,
            "hit_ordered": num,
            "temporal_order_unknown": unk,
            "denominator_after_exclusion": scored,
            "strict_hit_rate_recorded": round(
                sum(1 for r in subset if r["recorded_outcome"] == "hit") / n, 4) if n else None,
            "strict_hit_rate_temporal_strict": round(num / scored, 4) if scored else None,
            "wilson_95ci_temporal_strict": wilson(num, scored) if scored else None,
        }

    e1 = [r for r in rows if r["outcome_channel"] == "E1"]
    result = {
        "_comment": (
            "同日結果を temporal_order_unknown として厳格的中の分子から外した再集計ビュー。"
            "★既存の検証記録は書き換えていない（原則D）。"
        ),
        "_generated_on": datetime.now(timezone.utc).date().isoformat(),
        "_kev_catalog_version": catalog.get("catalogVersion"),
        "_history_import_date": HISTORY_IMPORT_DATE,
        "all_channels": agg(rows),
        "E1": agg(e1),
        "entries": rows,
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    print("=== 時刻順序を厳格化した再集計ビュー（既存記録は不変） ===")
    print(f"KEV catalogVersion: {catalog.get('catalogVersion')}")
    for label, a in (("全チャネル", result["all_channels"]), ("E1", result["E1"])):
        print(f"\n[{label}]")
        print(f"  記録上の厳格的中率      : {a['strict_hit_rate_recorded']} （n={a['n_recorded']}）")
        print(f"  順序不明で除外          : {a['temporal_order_unknown']} 件")
        print(f"  順序が立証できる的中    : {a['hit_ordered']} 件")
        print(f"  厳格化後の的中率        : {a['strict_hit_rate_temporal_strict']} "
              f"（n={a['denominator_after_exclusion']}）  95%CI={a['wilson_95ci_temporal_strict']}")
    print("\n[的中エントリの内訳]")
    for r in rows:
        if r["recorded_outcome"] != "hit":
            continue
        d = r["detail"]
        print(f"  {r['forecast_date']} idx{r['forecast_index']} [{r['outcome_channel']}] "
              f"→ {r['rescored']}")
        print(f"      CVE={d.get('cves')} dateAdded={d.get('date_added')} "
              f"commit={d.get('first_commit_utc')}")
        print(f"      {d.get('note','')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
