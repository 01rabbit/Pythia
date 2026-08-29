#!/usr/bin/env python3
"""前向き検証結果から model × horizon の昇格指標を決定論的に生成する。

昇格ゲートに手入力の数値を渡さないための唯一の生成経路。候補台帳の凍結確率と
verify_tactical_forecasts.py の hit/miss だけを結合し、未確認・棄権・右打切りは
scored_n に入れない。reference-only モデルは弁別を主張しないため AUC 下限を
not_applicable と明記する。公開昇格の可否は validate_model_promotion.py が判定する。
"""

import argparse
import glob
import json
import math
import os
import random
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tactical_time import iso_utc, parse_utc  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(ROOT, "forecaster", "models", "model-registry.json")
CAND_GLOB = os.path.join(ROOT, "forecaster", "candidates", "tactical", "*.json")
EXCLUSIONS = os.path.join(ROOT, "forecaster", "verification", "tactical", "exclusions.json")
OUT_ROOT = os.path.join(ROOT, "forecaster", "verification", "tactical")
LABELS = ("72h", "7d", "30d")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def excluded_paths():
    if not os.path.exists(EXCLUSIONS):
        return set()
    return {row.get("artifact") for row in load(EXCLUSIONS).get("exclusions", [])}


def candidate_index():
    """除外されていない候補だけを content hash と共に返す。"""
    excluded = excluded_paths()
    out = {}
    for path in sorted(glob.glob(CAND_GLOB)):
        if os.path.relpath(path, ROOT) in excluded:
            continue
        for candidate in load(path).get("candidates", []):
            out[candidate.get("candidate_id")] = candidate
    return out


def auc(pairs):
    pos = [p for p, y in pairs if y]
    neg = [p for p, y in pairs if not y]
    if not pos or not neg:
        return None
    wins = sum(1 if p > n else .5 if p == n else 0 for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def auc_lower_95(pairs, samples=1000):
    """候補単位の決定論的bootstrap下限。片側の標本が無いresampleは除く。"""
    if auc(pairs) is None:
        return None
    rng = random.Random(0)
    values = []
    for _ in range(samples):
        value = auc([pairs[rng.randrange(len(pairs))] for _ in pairs])
        if value is not None:
            values.append(value)
    if not values:
        return None
    return sorted(values)[max(0, math.floor(.025 * len(values)) - 1)]


def calibration_logistic(pairs):
    """logit(p) への二項ロジスティック較正切片・傾き（標準ライブラリ実装）。"""
    if len(pairs) < 2 or len({p for p, _ in pairs}) < 2 or len({y for _, y in pairs}) < 2:
        return None, None
    xs = [math.log(min(max(p, 1e-6), 1 - 1e-6) /
                   (1 - min(max(p, 1e-6), 1 - 1e-6))) for p, _ in pairs]
    ys = [y for _, y in pairs]
    intercept, slope = 0.0, 1.0
    for _ in range(50):
        probs = [1 / (1 + math.exp(-max(-35, min(35, intercept + slope * x)))) for x in xs]
        w = [max(p * (1 - p), 1e-9) for p in probs]
        g0 = sum(y - p for y, p in zip(ys, probs))
        g1 = sum((y - p) * x for y, p, x in zip(ys, probs, xs))
        h00 = sum(w)
        h01 = sum(wi * x for wi, x in zip(w, xs))
        h11 = sum(wi * x * x for wi, x in zip(w, xs))
        det = h00 * h11 - h01 * h01
        if det <= 1e-12:
            return None, None
        d0 = (h11 * g0 - h01 * g1) / det
        d1 = (-h01 * g0 + h00 * g1) / det
        intercept += d0
        slope += d1
        if max(abs(d0), abs(d1)) < 1e-8:
            return intercept, slope
    return intercept, slope


def brier_skill(pairs):
    if not pairs:
        return None
    mean = sum(y for _p, y in pairs) / len(pairs)
    baseline = sum((mean - y) ** 2 for _p, y in pairs) / len(pairs)
    if baseline == 0:
        return None
    score = sum((p - y) ** 2 for p, y in pairs) / len(pairs)
    return 1 - score / baseline


def temporal_integrity_errors():
    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "validate_temporal_integrity.py"), "--all"],
        cwd=ROOT, capture_output=True, text=True,
    )
    return 0 if result.returncode == 0 else 1


def verification_result(as_of):
    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "verify_tactical_forecasts.py"),
         "--all", "--as-of-utc", iso_utc(as_of), "--json"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    return json.loads(result.stdout)


def summary_rows(registry, verification, candidates, as_of):
    by_model = defaultdict(lambda: defaultdict(list))
    for entry in verification.get("entries", []):
        candidate = candidates.get(entry.get("candidate_id"))
        if not candidate:
            raise ValueError(
                f"検証entry {entry.get('candidate_id')!r} に対応する凍結candidateがない"
            )
        if entry.get("content_sha256") != candidate.get("content_sha256"):
            raise ValueError(
                f"{entry.get('candidate_id')}: 検証entryと候補台帳のcontent_sha256が不一致"
            )
        for label, verdict in (entry.get("verdicts") or {}).items():
            probability = (candidate.get("probability_by_horizon") or {}).get(label)
            if verdict in {"hit", "miss"} and probability is not None:
                by_model[candidate.get("model_version")][label].append(
                    (float(probability), int(verdict == "hit"))
                )

    temporal_errors = temporal_integrity_errors()
    rows = []
    for model in registry.get("models", []):
        version = model.get("model_version")
        profile = model.get("evaluation_profile", "discriminative")
        for label in LABELS:
            pairs = by_model[version][label]
            resolved = len(pairs)
            positives = sum(y for _p, y in pairs)
            intercept, slope = calibration_logistic(pairs)
            reference_only = profile == "reference_only_calibration"
            status = {
                "brier_skill_score": "ok" if brier_skill(pairs) is not None else "not_evaluable",
                "auc_lower_95": "not_applicable_reference_only" if reference_only else
                                ("ok" if auc_lower_95(pairs) is not None else "not_evaluable"),
                "calibration": "ok" if intercept is not None else "not_evaluable",
            }
            rows.append({
                "_schema_version": "1.0",
                "_generator": "scripts/build_promotion_summary.py",
                "evaluation_as_of_utc": iso_utc(as_of),
                "model_version": version,
                "forecast_family": model.get("forecast_family"),
                "horizon": label,
                "evaluation_profile": profile,
                "resolved_n": resolved,
                "positive_events": positives,
                "brier_skill_score": (round(brier_skill(pairs), 6)
                                      if brier_skill(pairs) is not None else None),
                "auc_lower_95": (None if reference_only else
                                  (round(auc_lower_95(pairs), 6)
                                   if auc_lower_95(pairs) is not None else None)),
                "calibration_intercept": (round(intercept, 6) if intercept is not None else None),
                "calibration_slope": (round(slope, 6) if slope is not None else None),
                "evidence_coverage": verification.get("by_horizon", {}).get(label, {}).get("coverage"),
                "temporal_integrity_errors": temporal_errors,
                "metric_status": status,
                "source": {
                    "candidate_files": verification.get("_candidate_files", 0),
                    "excluded_files": verification.get("_excluded_files", []),
                },
            })
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--as-of-utc", required=True, help="前向き評価の固定時刻")
    ap.add_argument("--out-dir", default=OUT_ROOT)
    ap.add_argument("--check", action="store_true", help="既存summaryと一致することを検証")
    args = ap.parse_args()
    as_of = parse_utc(args.as_of_utc)
    registry = load(REGISTRY)
    rows = summary_rows(registry, verification_result(as_of), candidate_index(), as_of)
    errors = []
    for row in rows:
        filename = "promotion-{}-{}.json".format(
            row["model_version"], row["horizon"].replace("/", "-"))
        path = os.path.join(args.out_dir, filename)
        rendered = json.dumps(row, ensure_ascii=False, indent=2) + "\n"
        if args.check:
            current = open(path, encoding="utf-8").read() if os.path.exists(path) else None
            if current != rendered:
                errors.append(path)
        else:
            os.makedirs(args.out_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(rendered)
            print(f"[out] {path}")
    if errors:
        for path in errors:
            print(f"  [E] promotion summaryが再生成結果と不一致: {path}")
        return 1
    print(f"promotion summaries: {len(rows)} rows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
