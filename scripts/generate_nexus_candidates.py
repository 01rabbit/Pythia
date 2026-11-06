#!/usr/bin/env python3
"""NX-1（国別 nexus 活動の確認予報）の候補台帳を発行する（shadow）。

予報の中身（確率）はコードが観測の履歴から計算する。LLM に確率を書かせない。
発行時にハッシュで凍結し、発行済みの台帳は書き換えない。履歴が足りない場合は棄権し、
理由を台帳に残す（分母操作の防止）。

★Section 5（周辺諸国動向）・Section 6（攻撃基盤プロファイル）の文脈層は入力にしない。
  inputs.context_inputs は常に空で、検証器がそれを確認する。

使い方:
  # 発行（日次 Routine・SKILL.md Step 3.7）
  python3 scripts/generate_nexus_candidates.py --date 2026-11-07 \\
      --cutoff-at-utc 2026-11-06T22:31:06Z --issued-at-utc 2026-11-06T22:31:07Z
  # 台帳に書かず、現在の影の確率を表で確認する
  python3 scripts/generate_nexus_candidates.py --print
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_family as nf  # noqa: E402
import watchlist as wl  # noqa: E402
from tactical_integrity import hash_without  # noqa: E402
from tactical_time import iso_utc, parse_utc  # noqa: E402

ROOT = nf.ROOT
OUT_DIR = os.path.join(ROOT, "forecaster", "candidates", "nexus")
JST = nf.JST
UTC = nf.UTC


def active_subjects(config: dict) -> list:
    """config.yml neighbor_states.primary のうち nexus タグを持つ国（CN・RU・KP）を、定義順で返す。"""
    section = (config or {}).get("neighbor_states") or {}
    primary = section.get("primary")
    if isinstance(primary, str):
        primary = [primary]
    wanted = {str(c).upper() for c in primary} if primary else set(nf.NEXUS_COUNTRY.values())
    return [n for n, code in nf.NEXUS_COUNTRY.items() if code in wanted]


def _label(horizon: int) -> str:
    return nf.HORIZON_LABELS[horizon]


def build_candidate(day: str, nexus: str, data: nf.Data, cutoff: datetime, issued: datetime) -> dict:
    country = nf.NEXUS_COUNTRY[nexus]
    per_h = {h: nf.forecast(data, nexus, h, cutoff) for h in nf.HORIZONS_DAYS}
    clim, rec, fallback = {}, {}, {}
    estimates, states, abstained = {}, {}, []
    for h, fc in per_h.items():
        label = _label(h)
        est = fc["estimate"]
        estimates[label] = {
            "grid_days": est["n"], "events": est["k"], "excluded_uncovered": est["excluded_uncovered"],
            "classes": {str(s): c for s, c in est["classes"].items()},
        }
        if fc["abstain"]:
            clim[label] = rec[label] = None
            states[label] = None
            abstained.append(label)
            continue
        clim[label] = round(fc[nf.MODEL_CLIMATOLOGY], 6)
        rec[label] = round(fc[nf.MODEL_RECENCY], 6)
        states[label] = fc["state"]
        if fc["fallback"]:
            fallback[label] = fc["fallback"]
    times = [t for t in data.events[nexus] if t <= cutoff]
    all_abstained = len(abstained) == len(nf.HORIZONS_DAYS)
    candidate = {
        "candidate_id": f"nx-{day.replace('-', '')}-{country}",
        "issued_at_utc": iso_utc(issued),
        "cutoff_at_utc": iso_utc(cutoff),
        "forecast_family": nf.FAMILY,
        "target_mode": "observable_confirmation",
        "probability_type": "observable_confirmation",
        "subject": {"type": "country_nexus", "id": nexus, "country": country},
        "target_event": {
            "event_type": nf.EVENT_TYPE,
            "matching_rule_version": nf.MATCHING_RULE_VERSION,
            "signal": nexus,
            "window_rule": "(issued_at, issued_at + H] の観測の available_at で数える。machine_backfill は除く。"
                           "miss は窓内のすべての日次ランが記録されているときだけ（不足は not_observed）",
        },
        "model_version": nf.PRIMARY_MODEL,
        "primary_model": nf.PRIMARY_MODEL,
        # 同じ辞書を共有しない（メモリ上の編集が片方だけに及ばないようにする）
        "probability_by_horizon": dict(clim),
        "models": {
            nf.MODEL_CLIMATOLOGY: {"probability_by_horizon": dict(clim)},
            nf.MODEL_RECENCY: {"probability_by_horizon": rec, "fallback_by_horizon": fallback,
                               "recent_activity_by_horizon": states},
        },
        "inputs": {
            "sources": ["forecaster/observations"],
            "context_inputs": [],
            "history_start": nf.HISTORY_START.isoformat(),
            "estimate_by_horizon": estimates,
            "event_count_at_cutoff": len(times),
            "last_event_available_at_utc": iso_utc(times[-1]) if times else None,
        },
        "selection": (
            {"status": "abstained", "reason_code": "INSUFFICIENT_HISTORY",
             "reason": f"被覆済み・満了済みのグリッド日が {nf.MIN_GRID_DAYS} 日に満たない"}
            if all_abstained else {"status": "shadow", "reason_code": None, "reason": None}),
        "abstained_horizons": abstained,
        "verified_outcome": None,
    }
    candidate["content_sha256"] = hash_without(candidate, "content_sha256")
    return candidate


def build_ledger(day: str, data: nf.Data, cutoff: datetime, issued: datetime, subjects: list) -> dict:
    candidates = [build_candidate(day, n, data, cutoff, issued) for n in subjects]
    status = {}
    for c in candidates:
        status[c["selection"]["status"]] = status.get(c["selection"]["status"], 0) + 1
    doc = {
        "_schema_version": "1.0",
        "_candidate_date": day,
        "_cutoff_at_utc": iso_utc(cutoff),
        "_issued_at_utc": iso_utc(issued),
        "_generator": nf.GENERATOR,
        "_mode": "shadow",
        "_matching_rule_version": nf.MATCHING_RULE_VERSION,
        "_model_versions": list(nf.MODELS),
        "_comment": "NX-1 は『国別 nexus の確認が記録されるか』の確率で、攻撃の発生確率ではない。shadow のため公開しない。",
        "_coverage": {"candidates": len(candidates), "by_status": dict(sorted(status.items())),
                      "subjects": [nf.NEXUS_COUNTRY[n] for n in subjects]},
        "candidates": candidates,
    }
    doc["_ledger_sha256"] = hash_without(doc, "_ledger_sha256")
    return doc


def render_table(doc: dict) -> str:
    lines = [f"NX-1 shadow outlook（cutoff {doc['_cutoff_at_utc']}）— 確認が記録される確率。公開しない。", "",
             f"{'国':<4}{'地平':<5}{'気候値':>8}{'直近活動条件付き':>16}  直近活動  標本(グリッド日/事象)  備考"]
    for c in doc["candidates"]:
        for h in nf.HORIZONS_DAYS:
            label = _label(h)
            p0 = c["models"][nf.MODEL_CLIMATOLOGY]["probability_by_horizon"][label]
            p1 = c["models"][nf.MODEL_RECENCY]["probability_by_horizon"][label]
            est = c["inputs"]["estimate_by_horizon"][label]
            state = c["models"][nf.MODEL_RECENCY]["recent_activity_by_horizon"][label]
            note = c["models"][nf.MODEL_RECENCY]["fallback_by_horizon"].get(label, "")
            fmt = lambda p: "棄権" if p is None else f"{p:.3f}"  # noqa: E731
            lines.append(f"{c['subject']['country']:<4}{label:<5}{fmt(p0):>8}{fmt(p1):>16}  "
                         f"{'あり' if state == 1 else 'なし' if state == 0 else '不明':<8}  "
                         f"{est['grid_days']:>3}/{est['events']:<3}  {note}")
    lines += ["", "※ 直近活動条件付きは挑戦者。遡及診断では気候値に勝てていない（nexus-registry.json 参照）。",
              "※ グリッド日は窓が重なり独立ではない。判定は前向きの台帳の独立標本で行う。"]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="NX-1 候補台帳を発行する（shadow）")
    parser.add_argument("--date", help="候補日 YYYY-MM-DD（JST）。既定: 発行時刻の JST 日付")
    parser.add_argument("--cutoff-at-utc", help="入力の締切（UTC）。既定: 現在時刻")
    parser.add_argument("--issued-at-utc", help="発行時刻（UTC）。既定: 現在時刻")
    parser.add_argument("--root", default=ROOT)
    parser.add_argument("--config", help="config.yml のパス")
    parser.add_argument("--print", dest="print_only", action="store_true", help="台帳に書かず表で出す")
    args = parser.parse_args()

    now = datetime.now(UTC).replace(microsecond=0)
    cutoff = parse_utc(args.cutoff_at_utc) if args.cutoff_at_utc else now
    issued = parse_utc(args.issued_at_utc) if args.issued_at_utc else max(now, cutoff)
    if issued < cutoff:
        print(f"issued_at_utc {iso_utc(issued)} が cutoff {iso_utc(cutoff)} より前", file=sys.stderr)
        return 1
    day = args.date or issued.astimezone(JST).date().isoformat()
    config_path = args.config or os.path.join(args.root, "config.yml")
    config = wl.load_config(config_path) if os.path.isfile(config_path) else {}
    subjects = active_subjects(config)
    data = nf.load_data(args.root)
    doc = build_ledger(day, data, cutoff, issued, subjects)

    if args.print_only:
        print(render_table(doc))
        return 0
    out_dir = os.path.join(args.root, "forecaster", "candidates", "nexus")
    path = os.path.join(out_dir, f"{day}.json")
    if os.path.exists(path):
        print(f"発行済みの台帳は書き換えない: {os.path.relpath(path, args.root)}", file=sys.stderr)
        return 1
    os.makedirs(out_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"発行: {os.path.relpath(path, args.root)}（{doc['_coverage']['by_status']}）", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
