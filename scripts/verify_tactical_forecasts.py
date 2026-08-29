#!/usr/bin/env python3
"""TF-1候補を固定matching ruleと実時刻で決定論的に検証する。

対象は「現実に悪用が起きたか」ではなく、予報時に宣言したsource universeで
確認できたかである。bounded open worldでは未確認をmissにせずnot_observedとする。

使い方:
  python3 scripts/verify_tactical_forecasts.py --all --as-of-utc 2026-09-30T00:00:00Z
  python3 scripts/verify_tactical_forecasts.py --date 2026-08-30 --write
"""

import argparse
import glob
import json
import math
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tactical_states import HORIZONS_DAYS, HORIZON_LABELS, derive_state, transition_fired  # noqa: E402
from tactical_time import (  # noqa: E402
    JST, conservative_date_availability, iso_utc, load_evidence_index,
    observation_available_at, parse_utc,
)
from source_channels import (  # noqa: E402
    load_evidence_records, load_registry, needs_primary_reference, resolve,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBS_GLOB = os.path.join(ROOT, "forecaster", "observations", "*", "*", "*.json")
CAND_GLOB = os.path.join(ROOT, "forecaster", "candidates", "tactical", "*.json")
UNIVERSES = os.path.join(ROOT, "forecaster", "knowledge", "source-universes.json")
EXCLUSIONS = os.path.join(ROOT, "forecaster", "verification", "tactical", "exclusions.json")
OUT_ROOT = os.path.join(ROOT, "forecaster", "verification", "tactical")
COVERAGE_GLOB = os.path.join(ROOT, "forecaster", "evidence", "source-coverage", "*.json")
UTC = timezone.utc
JST = timezone(timedelta(hours=9))


def load_universes():
    with open(UNIVERSES, encoding="utf-8") as f:
        return json.load(f)["universes"]


def excluded_paths():
    if not os.path.exists(EXCLUSIONS):
        return set()
    with open(EXCLUSIONS, encoding="utf-8") as f:
        return {x["artifact"] for x in json.load(f).get("exclusions", [])}


def load_coverage():
    rows = []
    for path in sorted(glob.glob(COVERAGE_GLOB)):
        try:
            with open(path, encoding="utf-8") as f:
                rows.append(json.load(f))
        except (OSError, json.JSONDecodeError):
            continue
    return rows


def source_coverage_proven(records, rule, universe, start, deadline):
    """各必須sourceについて、**そのチャネル自身の**成功区間が予報窓を切れ目なく覆うか。

    ★チャネル別の区間だけを使う。全チャネル共通の単一窓を使うと、取得時刻の
      早いチャネルの区間が、まだ取得していないチャネルにも適用され、監視して
      いない時間帯を根拠に miss を記録できてしまう（PR #177 レビュー指摘）。

    ★status が ok の区間だけを使う。partial（宣言フィードの一部しか取得できて
      いない）は可視化のために記録するが、miss の根拠には使わない。

    ★チャネル別区間を持たない古い形式の記録は使わない（fail-closed）。
    """
    for source in universe.get("sources") or []:
        intervals = []
        for row in records:
            if row.get("matching_rule_version") != rule:
                continue
            channel = (row.get("channels") or {}).get(source)
            if not channel or channel.get("status") != "ok":
                continue
            try:
                intervals.append((parse_utc(channel["window_start_utc"]),
                                  parse_utc(channel["window_end_utc"])))
            except (KeyError, ValueError):
                continue
        cursor = start
        for lo, hi in sorted(intervals):
            if hi <= cursor:
                continue
            if lo > cursor:
                break
            cursor = max(cursor, hi)
            if cursor >= deadline:
                break
        if cursor < deadline:
            return False
    return True


def load_subject_states():
    """subject -> [(available_at,event_day_start,state,id,channel)] を返す。

    ★5番目は source.type ではなく解決済みの確認チャネルである（Blocker 1a）。
      source.type は媒体種別ではなく記事内容で付与されており、同一媒体でも値が割れる。
      type を採用条件に使うと一次機関の記録が型の誤りで検証から外れるため、
      source_channels.resolve() が掲載元ホスト（または構造化された原典URL）から
      決定論的に解決する。source.name の組織名の言及では昇格させない。
    """
    per = defaultdict(list)
    evidence = load_evidence_index(ROOT)
    channels = load_registry()
    ev_records = load_evidence_records()
    for path in sorted(glob.glob(OBS_GLOB)):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for obs in doc.get("observations", []):
            available = observation_available_at(obs, evidence)
            # date-onlyの事象は同日内の前後を証明できない。日初を下限とする。
            event_start = conservative_date_availability(obs["observed_date"]) - timedelta(days=1)
            channel, basis = resolve(obs.get("source"), channels, ev_records)
            if basis == "primary_reference_unverified":
                # 原典URLはあるが Evidence Ledger の取得証跡が無い。昇格させない。
                channel = "primary_reference_unverified"
            elif needs_primary_reference(obs.get("source"), channels, ev_records):
                # 集約ニュース掲載だが一次組織を引用しており、原典URLが未記録。
                # 昇格はしないが、構造化すれば受理できることを診断で示す。
                channel = "aggregator_news_citing_primary"
            for cve in obs.get("cve") or []:
                state, _basis = derive_state(obs, subject_id=cve)
                if state:
                    per[cve].append((available, event_start, state,
                                     obs.get("observation_id"), channel))
    return {key: sorted(set(values)) for key, values in per.items()}


def score(candidate, index, as_of, universes, coverage_records=None, diagnostics=None):
    """1候補を時間軸ごとに採点する。

    diagnostics に dict を渡すと、「窓内に状態が前進し target も成立したが、
    確認した観測のチャネルが universe の宣言集合に無いため発火しなかった」件数を
    horizon 別に記録する。これを沈黙させると hit 0 の原因が測れない（Blocker 1a）。
    """
    labels = [HORIZON_LABELS[h] for h in HORIZONS_DAYS]
    if candidate.get("selection", {}).get("status") == "abstained":
        return {label: "abstained" for label in labels}
    te = candidate.get("target_event") or {}
    universe = universes.get(te.get("matching_rule_version"))
    if not universe:
        return {label: "invalid_rule" for label in labels}
    if te.get("visibility_model") == "low":
        return {label: "unobservable" for label in labels}

    start = parse_utc(candidate["issued_at_utc"])
    subject = candidate["subject"]["id"]
    points = index.get(subject, [])
    # ★fail-closed: universe が確認チャネルを宣言していなければ何も受理しない。
    accepted_channels = set(universe.get("sources") or [])
    out = {}
    for horizon in HORIZONS_DAYS:
        label = HORIZON_LABELS[horizon]
        deadline = start + timedelta(days=horizon)
        fired = False
        blocked = []
        for available, event_start, state, _oid, channel in points:
            if not (start < event_start and start < available <= deadline):
                continue
            if not transition_fired(te.get("event_type"), state, te.get("next_state")):
                continue
            if channel in accepted_channels:
                fired = True
                break
            blocked.append(channel)
        if diagnostics is not None and not fired and blocked:
            diagnostics.setdefault(label, Counter()).update(blocked)
        if fired:
            out[label] = "hit"
        elif as_of < deadline:
            out[label] = "pending"
        elif universe.get("negative_outcome_allowed") is True:
            out[label] = "miss"
        elif (universe.get("negative_outcome_allowed") == "coverage_proven"
              and source_coverage_proven(coverage_records or [], te.get("matching_rule_version"),
                                         universe, start, deadline)):
            out[label] = "miss"
        else:
            out[label] = "not_observed"
    return out


def metric(pairs, fn):
    return round(sum(fn(p, y) for p, y in pairs) / len(pairs), 6) if pairs else None


def auc(pairs):
    pos = [p for p, y in pairs if y == 1]
    neg = [p for p, y in pairs if y == 0]
    if not pos or not neg:
        return None
    wins = sum(1 if p > n else 0.5 if p == n else 0 for p in pos for n in neg)
    return round(wins / (len(pos) * len(neg)), 6)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--as-of-utc", help="採点時点。既定は現在UTC")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    as_of = parse_utc(args.as_of_utc) if args.as_of_utc else datetime.now(UTC)
    if args.all:
        paths = sorted(glob.glob(CAND_GLOB))
    else:
        target = args.date or datetime.now(JST).date().isoformat()
        paths = [os.path.join(ROOT, "forecaster", "candidates", "tactical", f"{target}.json")]
    exclusions = excluded_paths()
    paths = [p for p in paths if os.path.exists(p) and os.path.relpath(p, ROOT) not in exclusions]
    index, universes, coverage = load_subject_states(), load_universes(), load_coverage()
    rows, tally, scored = [], defaultdict(Counter), defaultdict(list)
    blocked = {}
    for path in paths:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        for candidate in doc.get("candidates", []):
            verdicts = score(candidate, index, as_of, universes, coverage, blocked)
            rows.append({
                "candidate_id": candidate["candidate_id"],
                "content_sha256": candidate.get("content_sha256"),
                "matching_rule_version": (candidate.get("target_event") or {}).get("matching_rule_version"),
                "verdicts": verdicts,
            })
            for label, verdict in verdicts.items():
                tally[label][verdict] += 1
                probability = (candidate.get("probability_by_horizon") or {}).get(label)
                if verdict in {"hit", "miss"} and probability is not None:
                    scored[label].append((probability, int(verdict == "hit")))
    result = {
        "_schema_version": "2.0",
        "_generated_at_utc": iso_utc(as_of),
        "_candidate_files": len(paths),
        "_excluded_files": sorted(exclusions),
        "by_horizon": {},
        "entries": rows,
    }
    for label in [HORIZON_LABELS[h] for h in HORIZONS_DAYS]:
        counts = tally[label]
        pairs = scored[label]
        result["by_horizon"][label] = {
            **{k: counts[k] for k in (
                "hit", "miss", "pending", "not_observed", "unobservable", "abstained", "invalid_rule")},
            "scored_n": len(pairs),
            "brier": metric(pairs, lambda p, y: (p - y) ** 2),
            "log_loss": metric(pairs, lambda p, y: -(y * math.log(max(p, 1e-15)) +
                                                       (1-y) * math.log(max(1-p, 1e-15)))),
            "auc": auc(pairs),
            "coverage": round(len(pairs) / sum(counts.values()), 6) if sum(counts.values()) else None,
            "right_censored": counts["pending"] > 0,
            # ★窓内に target が成立したのに、確認観測のチャネルが universe の宣言集合に
            #   無いため発火しなかった件数。hit 0 の原因を「起きなかった」と
            #   「確認チャネルに載らなかった」に分離するための計器（Blocker 1a）。
            "blocked_by_channel": sum(blocked.get(label, Counter()).values()),
            "blocked_channels": dict(blocked.get(label, Counter())),
        }
    if args.write:
        stamp = as_of.strftime("%Y%m%dT%H%M%SZ")
        out = os.path.join(OUT_ROOT, f"verification-{stamp}.json")
        os.makedirs(OUT_ROOT, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print(f"[out] {out}")
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"TF-1 verification as_of={iso_utc(as_of)} files={len(paths)}")
        for label, row in result["by_horizon"].items():
            print(f"  {label}: {row}")
        print("未確認はbounded open worldではnot_observed。missへ変換しない。")
        print("blocked_by_channel > 0 は、事象は起きたが宣言チャネルで確認できなかったことを示す。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
