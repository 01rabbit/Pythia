#!/usr/bin/env python3
"""TF-1 の参照クラス事前確率を観測実績から実測する（設計 §4.3）。

出力: forecaster/models/reference-rates.json

★実測してわかった最重要の制約:
  記事件数は遷移件数ではない。同一CVE・同日の再報道を一つのepisode entryへ統合し、
  日をまたぐ前進だけを遷移として数える。正確な最新値は出力の `_corpus` を正とする。

  つまり「stage ラベルが 481 件ある」ことは「遷移が 481 件観測された」ことを
  意味しない。TF-1 の参照率を内部実績だけから点推定することは現時点では
  できない。これは TF-1 を shadow で始める判断（設計 §12 第1段階）を裏づける
  事実であり、shadow 運用の目的そのものが**この母集団を作ること**である。

したがって本スクリプトは:
  - 観測できたセルは Beta-Binomial 事後分布（平均と 80% 信用区間）で出す
  - 0/n や n/n を 0% / 100% として出さない（設計 §4.3）
  - 標本が閾値未満のセルは insufficient_sample とし、
    上位クラス（from-state → forecast family → 全体）へ部分プーリングする
  - 右打ち切り（窓の終端が観測期間の外にある遷移）を発生なしと数えない

使い方:
    python3 scripts/build_reference_rates.py
    python3 scripts/build_reference_rates.py --print-only   # 書き出さず表示のみ

★このスクリプトは forecaster/knowledge/ を一切書き換えない（行動原則5）。
  出力先 forecaster/models/ は機械生成物であり、再生成は PR + 人間レビュー経由とする。
"""

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tactical_states import (  # noqa: E402
    HORIZONS_DAYS, HORIZON_LABELS, STATE_RANK, allowed_transitions,
    derive_state, is_forward, reference_key, transition_fired,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBS_GLOB = os.path.join(REPO_ROOT, "forecaster", "observations", "*", "*", "*.json")
OUT_PATH = os.path.join(REPO_ROOT, "forecaster", "models", "reference-rates.json")

# セルを「実測値として出してよい」とみなす最小標本。これ未満は上位へプールする。
MIN_N_FOR_CELL = 10
# Beta 事前（弱情報事前）。0/n を 0% にしないためのもの。
PRIOR_ALPHA, PRIOR_BETA = 1.0, 4.0  # 平均 0.20 の弱い事前


def _beta_quantiles(a, b, level=0.80, grid=200001):
    """Beta(a,b) の信用区間を数値積分で求める（scipy 非依存）。

    連分数による不完全ベータ関数は対称条件の扱いを誤ると壊れるため、
    ここでは対数スケールの密度をグリッド積分して CDF を作る。
    a,b は高々数百なので、この精度・速度で十分である。
    """
    import math

    lo_tail = (1 - level) / 2
    xs = [i / (grid - 1) for i in range(grid)]
    logpdf = []
    for x in xs:
        if x <= 0 or x >= 1:
            logpdf.append(float("-inf"))
        else:
            logpdf.append((a - 1) * math.log(x) + (b - 1) * math.log(1 - x))
    m = max(v for v in logpdf if v != float("-inf"))
    w = [0.0 if v == float("-inf") else math.exp(v - m) for v in logpdf]
    total = sum(w)
    if total <= 0:
        return 0.0, 1.0
    acc, lower, upper = 0.0, None, None
    for x, wi in zip(xs, w):
        acc += wi / total
        if lower is None and acc >= lo_tail:
            lower = x
        if upper is None and acc >= 1 - lo_tail:
            upper = x
            break
    return (lower if lower is not None else 0.0,
            upper if upper is not None else 1.0)


def beta_summary(events, n, alpha=PRIOR_ALPHA, beta=PRIOR_BETA, level=0.80):
    """Beta-Binomial 事後の平均と信用区間を返す。0/n や n/n を 0%/100% にしない。"""
    a, b = alpha + events, beta + (n - events)
    lo, hi = _beta_quantiles(a, b, level)
    return {
        "posterior_mean": round(a / (a + b), 4),
        "lower": round(lo, 4),
        "upper": round(hi, 4),
        "interval_level": level,
        "events": events,
        "n": n,
        "prior": {"alpha": alpha, "beta": beta},
    }


def load_cve_timelines():
    """CVE ごとに (observed_date, state, observation_id) を時間順で返す。"""
    per = defaultdict(list)
    latest = date.min
    for path in sorted(glob.glob(OBS_GLOB)):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if doc.get("_retro_normalized") or str(doc.get("_normalization_mode", "")).startswith(
                "machine_backfill"):
            continue
        for o in doc.get("observations", []):
            d = o.get("observed_date")
            if not d:
                continue
            try:
                dd = date.fromisoformat(d)
            except ValueError:
                continue
            latest = max(latest, dd)
            for cve in (o.get("cve") or []):
                st, _basis = derive_state(o, subject_id=cve)
                if st:
                    per[cve].append((dd, st, o["observation_id"]))
    return {c: collapse_episode_timeline(v) for c, v in per.items()}, latest


def collapse_episode_timeline(points):
    """同一CVEの報道を、日次・単調な状態entryへ統合する。

    同日同状態の複数記事は一単位。同日の複数状態は順序不明なので最上位の状態だけを
    その日のスナップショットとして残し、同日内遷移は学習しない。後退・同一状態の
    再報道は新しいリスク単位にしない。
    """
    by_day = defaultdict(list)
    for dd, state, oid in points:
        by_day[dd].append((state, oid))

    out, current_rank = [], -1
    for dd in sorted(by_day):
        rows = by_day[dd]
        state = max((s for s, _oid in rows), key=lambda s: STATE_RANK.get(s, -1))
        rank = STATE_RANK.get(state, -1)
        if rank <= current_rank:
            continue
        ids = tuple(sorted({oid for s, oid in rows if s == state}))
        out.append((dd, state, ids))
        current_rank = rank
    return out


def measure(timelines, corpus_end):
    """from-state×target-eventごとに、各時間軸の発生率を数える。

    右打ち切りの扱い: 起点観測日 + horizon が corpus_end を超える区間は、
    「起きなかった」ことを確認できないためリスク集合から外す（設計 §9.3）。
    """
    cells = defaultdict(lambda: {"n": 0, "events": 0})
    censored = defaultdict(int)

    for cve, points in timelines.items():
        for i, (d0, s0, _oid) in enumerate(points):
            later = [(d, s) for d, s in ((p[0], p[1]) for p in points[i + 1:])]
            for event_type, next_state, visibility in allowed_transitions(s0):
                for h in HORIZONS_DAYS:
                    cell = (s0, event_type, next_state, visibility, h)
                    if d0 + timedelta(days=h) > corpus_end:
                        censored[cell] += 1
                        continue
                    cells[cell]["n"] += 1
                    fired = any(
                        0 < (d - d0).days <= h
                        and transition_fired(event_type, s, next_state)
                        for d, s in later
                    )
                    if fired:
                        cells[cell]["events"] += 1
    return cells, censored


def build(cells, censored, timelines, corpus_end):
    # コーパス中で実際に導出できた状態の集合。ある from_state の許可遷移先が
    # ひとつも導出できないなら、そのセルの 0 発火は「起きなかった」ではなく
    # 「観測手段がない」である。両者を混同すると偽の低確率を作る。
    derived_states = {s for v in timelines.values() for _d, s, _o in v}
    family_totals = defaultdict(lambda: {"n": 0, "events": 0})
    for (_s0, event_type, next_state, visibility, h), v in cells.items():
        pool_key = (event_type, next_state, visibility, h)
        family_totals[pool_key]["n"] += v["n"]
        family_totals[pool_key]["events"] += v["events"]

    rates = {}
    from_states = sorted({cell[0] for cell in cells}, key=lambda s: STATE_RANK.get(s, 99))
    for s0 in from_states:
        for event_type, next_state, visibility in allowed_transitions(s0):
            for h in HORIZONS_DAYS:
                cell = (s0, event_type, next_state, visibility, h)
                v = cells.get(cell, {"n": 0, "events": 0})
                key = reference_key(s0, event_type, next_state, h)
                entry = {
                    "from_state": s0,
                    "event_type": event_type,
                    "next_state": next_state,
                    "visibility": visibility,
                    "horizon_days": h,
                    "observed": {"n": v["n"], "events": v["events"]},
                    "right_censored_excluded": censored.get(cell, 0),
                }
                if next_state not in derived_states:
                    entry["status"] = "structurally_unobservable"
                    entry["estimate"] = None
                    entry["pooled_from"] = None
                    entry["_unobservable_note"] = (
                        f"{s0} からの遷移先 {next_state} は、現行の観測スキーマから"
                        "導出できない。"
                        f"発火0件は『起きなかった』ではなく『観測手段がない』である。"
                        "参照率として使ってはならず、shadow で観測手段を作ることが先。"
                    )
                elif v["n"] >= MIN_N_FOR_CELL:
                    entry["status"] = "measured"
                    entry["estimate"] = beta_summary(v["events"], v["n"])
                    entry["pooled_from"] = None
                else:
                    pool_key = (event_type, next_state, visibility, h)
                    ft = family_totals[pool_key]
                    entry["status"] = "insufficient_sample"
                    entry["estimate"] = beta_summary(ft["events"], ft["n"])
                    entry["pooled_from"] = "|".join((
                        "TF1", "ALL_STATES", event_type, next_state, HORIZON_LABELS[h]))
                    entry["_pooling_note"] = (
                        f"セル標本 n={v['n']} が最小標本 {MIN_N_FOR_CELL} 未満のため、"
                        f"forecast family 全体（n={ft['n']}・events={ft['events']}）へ"
                        "部分プーリングした推定値を使う。セル固有の点推定は出さない。"
                    )
                rates[key] = entry

    for (event_type, next_state, visibility, h), ft in family_totals.items():
        pool_name = "|".join((
            "TF1", "ALL_STATES", event_type, next_state, HORIZON_LABELS[h]))
        observable = next_state in derived_states
        rates[pool_name] = {
            "from_state": "ALL_STATES",
            "event_type": event_type,
            "next_state": next_state,
            "visibility": visibility,
            "horizon_days": h,
            "observed": {"n": ft["n"], "events": ft["events"]},
            "status": ("measured" if ft["n"] >= MIN_N_FOR_CELL else "insufficient_sample")
                      if observable else "structurally_unobservable",
            "estimate": beta_summary(ft["events"], ft["n"]) if observable else None,
            "pooled_from": None,
        }

    multi = sum(1 for v in timelines.values() if len(v) > 1)
    forward = sum(
        1
        for v in timelines.values()
        for (d1, s1, _), (d2, s2, _) in zip(v, v[1:])
        if is_forward(s1, s2)
    )
    return {
        "_comment": (
            "TF-1（悪用状態遷移）の参照クラス事前確率。設計 §4.3 の prior_key = "
            "forecast_family × current_state × target_event × next_state × horizon "
            "に対応する。バックフィルは除外する。"
        ),
        "_schema_version": "2.0",
        "_machine_generated": True,
        "_generator": "scripts/build_reference_rates.py",
        "_generated_on": datetime.now(timezone.utc).date().isoformat(),
        "_governance": (
            "機械生成物。再生成は日次ルーチンからは行わず、PR + 人間レビューを経る"
            "（knowledge/ と同じ扱い・CLAUDE.md 行動原則5に準じる）。"
        ),
        "_corpus": {
            "observation_end": corpus_end.isoformat(),
            "cve_with_stage": len(timelines),
            "cve_with_multiple_state_entries": multi,
            "forward_transitions_observed": forward,
        },
        "_limitations": [
            "★最重要: 前進した状態遷移は全コーパスで "
            f"{forward} 件しか観測されていない（同一CVEに複数の状態entryがあるのは "
            f"{len(timelines)} CVE 中 {multi} 件）。exploitation_stage を持つ観測が"
            "多いことは遷移が多く観測されたことを意味しない。TF-1 の参照率を内部実績"
            "だけから点推定することは現時点ではできず、shadow 運用でこの母集団を"
            "作ることが第1段階の目的である。",
            "Pythia は「その日に報じられた」CVE だけを観測するため、状態が変わっても"
            "報じられなければ遷移として記録されない。したがって本統計の発生率は"
            "真の遷移率ではなく『公開情報として観測される遷移率』の下限に近い"
            "（設計 §9.3 の visibility の問題）。",
            "右打ち切り（起点 + horizon がコーパス終端を超える区間）はリスク集合から"
            "除いている。窓が完了していないものを『起きなかった』と数えない。",
            "バックフィル由来の観測（machine_backfill_*）は単発の点であることが多く、"
            "遷移の分母を膨らませて発生率を下方に歪める可能性がある。",
            "本統計を hit_criteria の緩和根拠に使ってはならない（原則D・教訓12）。",
        ],
        "min_n_for_cell": MIN_N_FOR_CELL,
        "reference_rates": rates,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--print-only", action="store_true", help="書き出さず表示のみ")
    ap.add_argument("--out", default=OUT_PATH)
    args = ap.parse_args()

    timelines, corpus_end = load_cve_timelines()
    cells, censored = measure(timelines, corpus_end)
    doc = build(cells, censored, timelines, corpus_end)

    print(f"[corpus] stage付きCVE {doc['_corpus']['cve_with_stage']} / "
          f"複数状態entry {doc['_corpus']['cve_with_multiple_state_entries']} / "
          f"前進遷移 {doc['_corpus']['forward_transitions_observed']} 件 "
          f"（終端 {corpus_end}）")
    NOTE = {
        "measured": "",
        "insufficient_sample": "  ※標本不足→上位へプーリング",
        "structurally_unobservable": "  ※遷移先を観測する手段がない（発火0は非発生ではない）",
        "no_forecastable_transition": "  ※終端状態・予報候補を作らない",
    }
    for key, v in doc["reference_rates"].items():
        est = v["estimate"]
        head = (f"  {key:34s} n={v['observed']['n']:4d} "
                f"発火={v['observed']['events']:3d}")
        if est is None:
            print(f"{head} 参照率なし{NOTE.get(v['status'], '')}")
        else:
            print(f"{head} 事後平均={est['posterior_mean']:.4f} "
                  f"[{est['lower']:.3f},{est['upper']:.3f}]{NOTE.get(v['status'], '')}")

    if args.print_only:
        return 0
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"\n[out] {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
