#!/usr/bin/env python3
"""NX-1（国別 nexus 活動の確認予報）の共有ライブラリ。

設計契約（docs/tactical-forecaster-v3.md「Actor・標的・インフラ・影響への展開予報は、別 family・
別 matching rule・別評価母集団として追加する。TF-1 の数字を流用しない」）に従う独立した予報 family。
TF-1 の状態機械・参照率・被覆記録には依存しない。

予報する事象（matching rule `nx1-rule-v1`・発行時に固定する）:
  「発行から H 日以内（H = 3, 7）に、国別 nexus（china / russia / north_korea）の
    geopolitical_signal を持つ **日次ラン由来の** 観測（機械バックフィルを除く）が新たに記録されるか」
  対象は adversary の発生そのものではなく **『確認が記録されるか』**である（TF-1 と同じ公開確認確率）。
  タグ付けは正規化（01-normalize.md R9）が観測ごとに行う。

モデル（パラメータ調整なし・as-of 計算・LLM は確率を書かない）:
  nx1-climatology-v1  基準線。過去の発行日グリッドで窓内に事象が起きた割合（Jeffreys 事前）
  nx1-recency-v1      挑戦者。直近 H 日に事象があったか（0/1）で条件づけた割合。標本が小さい
                      クラスは climatology へ後退する（fallback を記録）

誠実さの規則:
- 欠測日（日次ファイルが無い日）を含む窓は『起きなかった』と断定できない。被覆が証明できない
  窓は miss にせず not_observed とし、参照率の標本にも入れない
- 窓がまだ満了していないものは pending（右打ち切りを miss にしない）
- グリッド日は互いに窓が重なり独立ではない。標本数は **独立標本数の推定（÷H）**で数える
- 履歴は HISTORY_START（正規化モード source_explicit_all 以降）から。それ以前は nexus タグの
  付け方が異なるため基準率に混ぜない
- 事象の利用可能時刻は observation_available_at（スタンプが無い旧観測は翌日 00:00 JST に保守的に倒す）

このモジュールは何も書き込まない（読み取り専用の純関数群）。
"""

from __future__ import annotations

import glob
import json
import math
import os
import random
import sys
from bisect import bisect_right
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tactical_time import (  # noqa: E402
    load_evidence_index, observation_available_at, parse_utc,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBS_GLOB = os.path.join(ROOT, "forecaster", "observations", "*", "*", "*.json")
UTC = timezone.utc
JST = timezone(timedelta(hours=9))

FAMILY = "NX-1"
EVENT_TYPE = "NX1_NEXUS_ACTIVITY_CONFIRMATION"
MATCHING_RULE_VERSION = "nx1-rule-v1"
GENERATOR = "generate_nexus_candidates.py/1.0"
MODEL_CLIMATOLOGY = "nx1-climatology-v1"
MODEL_RECENCY = "nx1-recency-v1"
MODELS = (MODEL_CLIMATOLOGY, MODEL_RECENCY)
PRIMARY_MODEL = MODEL_CLIMATOLOGY

# 観測の geopolitical_signal → 国コード（config.yml neighbor_states.primary と対応）
NEXUS_COUNTRY = {"china_nexus": "CN", "russia_nexus": "RU", "north_korea_nexus": "KP"}
HORIZONS_DAYS = (3, 7)
HORIZON_LABELS = {3: "72h", 7: "7d"}

HISTORY_START = date(2026, 6, 29)   # 正規化モード source_explicit_all（2026-06-28）以降の最初の日
GRID_ISSUE_HOUR_JST = (7, 30)       # 履歴グリッドの発行時刻（日次 Routine の起動時刻に合わせる）
JEFFREYS = 0.5
MIN_GRID_DAYS = 30                  # climatology を出すのに要る被覆済み・満了済みのグリッド日数
MIN_CLASS_DAYS = 14                 # 直近活動クラスの確率を出すのに要るグリッド日数
BOOTSTRAP_BLOCK_DAYS = 14
BOOTSTRAP_SAMPLES = 1000


# --------------------------------------------------------------------------
# 観測の読み込み（読み取り専用）
# --------------------------------------------------------------------------

class Data:
    """国別 nexus 事象の利用可能時刻（昇順）と、日次ランの被覆日。"""

    def __init__(self, events=None, covered=None, ids=None):
        self.events = {n: sorted(events.get(n, [])) if events else [] for n in NEXUS_COUNTRY}
        self.covered = set(covered or [])
        self.ids = ids or {n: [] for n in NEXUS_COUNTRY}


def load_data(root: str = ROOT, evidence_index=None) -> Data:
    evidence_index = load_evidence_index(root) if evidence_index is None else evidence_index
    events = {n: [] for n in NEXUS_COUNTRY}
    ids = {n: [] for n in NEXUS_COUNTRY}
    covered = set()
    pattern = os.path.join(root, "forecaster", "observations", "*", "*", "*.json")
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if str(doc.get("_normalization_mode") or "").startswith("machine_backfill"):
            continue  # 日次ランの被覆でも nexus 事象でもない（過去の機械取り込み）
        day = doc.get("_observation_date") or os.path.basename(path)[:10]
        covered.add(day)
        for obs in doc.get("observations", []):
            signal = obs.get("geopolitical_signal")
            if signal not in events:
                continue
            at = observation_available_at(obs, evidence_index)
            if at.year >= 9999:
                continue  # 時刻を証明できない観測は入力にしない
            events[signal].append(at)
            ids[signal].append(obs.get("observation_id"))
    return Data(events, covered, ids)


# --------------------------------------------------------------------------
# 時刻・窓・被覆
# --------------------------------------------------------------------------

def jst_date(value: datetime) -> date:
    return value.astimezone(JST).date()


def issue_instant(day: date) -> datetime:
    """履歴グリッド上の発行時刻（その日の 07:30 JST・UTC aware）。"""
    h, m = GRID_ISSUE_HOUR_JST
    return datetime(day.year, day.month, day.day, h, m, tzinfo=JST).astimezone(UTC)


def required_days(start: datetime, end: datetime) -> list:
    """窓 (start, end] に含まれる日次ランの日付（JST）。発行日 D から D+H−1 の H 日分。"""
    days, cursor, last = [], jst_date(start), jst_date(end)
    while cursor < last:
        days.append(cursor.isoformat())
        cursor += timedelta(days=1)
    return days


def window_covered(data: Data, start: datetime, end: datetime) -> bool:
    return all(d in data.covered for d in required_days(start, end))


def has_event(times: list, start: datetime, end: datetime) -> bool:
    """start < t <= end の事象があるか（times は昇順）。"""
    return bisect_right(times, start) < bisect_right(times, end)


def recent_state(times: list, at: datetime, horizon: int) -> int:
    """直近 H 日（at−H, at]に事象があれば 1。"""
    return int(has_event(times, at - timedelta(days=horizon), at))


# --------------------------------------------------------------------------
# 参照率（as-of）
# --------------------------------------------------------------------------

def jeffreys(k: int, n: int) -> float:
    return (k + JEFFREYS) / (n + 2 * JEFFREYS)


def estimate(data: Data, nexus: str, horizon: int, cutoff: datetime,
             history_start: date = HISTORY_START) -> dict:
    """cutoff 時点で満了済み・被覆済みのグリッド日から、事象の割合を数える。

    返り値: {"n","k","classes":{0:{"n","k"},1:{"n","k"}}, "excluded_uncovered"}
    classes は直近活動クラス別。クラスの判定には窓の前の H 日（lookback）も被覆済みであることを要する。
    """
    times = data.events[nexus]
    n = k = excluded = 0
    classes = {0: {"n": 0, "k": 0}, 1: {"n": 0, "k": 0}}
    day = history_start
    while True:
        g = issue_instant(day)
        deadline = g + timedelta(days=horizon)
        if deadline > cutoff:
            break
        if not window_covered(data, g, deadline):
            excluded += 1
            day += timedelta(days=1)
            continue
        y = int(has_event(times, g, deadline))
        n += 1
        k += y
        look = g - timedelta(days=horizon)
        if day - timedelta(days=horizon) >= history_start and window_covered(data, look, g):
            s = recent_state(times, g, horizon)
            classes[s]["n"] += 1
            classes[s]["k"] += y
        day += timedelta(days=1)
    return {"n": n, "k": k, "classes": classes, "excluded_uncovered": excluded}


def forecast(data: Data, nexus: str, horizon: int, cutoff: datetime,
             history_start: date = HISTORY_START):
    """cutoff 時点の 2 モデルの確率。履歴が足りなければ None（棄権）。"""
    est = estimate(data, nexus, horizon, cutoff, history_start)
    if est["n"] < MIN_GRID_DAYS:
        return {"abstain": "INSUFFICIENT_HISTORY", "estimate": est}
    p0 = jeffreys(est["k"], est["n"])
    times = data.events[nexus]
    look_ok = window_covered(data, cutoff - timedelta(days=horizon), cutoff)
    state = recent_state(times, cutoff, horizon) if look_ok else None
    fallback, p1 = None, p0
    if state is None:
        fallback = "LOOKBACK_NOT_COVERED"
    else:
        cls = est["classes"][state]
        if cls["n"] >= MIN_CLASS_DAYS:
            p1 = jeffreys(cls["k"], cls["n"])
        else:
            fallback = "CLASS_SAMPLE_SMALL"
    return {"abstain": None, "estimate": est, "state": state, "fallback": fallback,
            MODEL_CLIMATOLOGY: p0, MODEL_RECENCY: p1}


# --------------------------------------------------------------------------
# 採点（決定論）
# --------------------------------------------------------------------------

def score_window(data: Data, nexus: str, issued: datetime, horizon: int, as_of: datetime) -> str:
    """hit / miss / pending / not_observed。

    as_of より後に利用可能になった観測は使わない（固定 --as-of-utc の再現性）。
    miss は『窓が満了し、窓内のすべての日次ランが記録されている』ときだけ。
    """
    deadline = issued + timedelta(days=horizon)
    times = data.events[nexus]
    if has_event(times, issued, min(deadline, as_of)):
        return "hit"
    if as_of < deadline:
        return "pending"
    if window_covered(data, issued, deadline):
        return "miss"
    return "not_observed"


# --------------------------------------------------------------------------
# 指標（標準ライブラリのみ）
# --------------------------------------------------------------------------

def brier(pairs) -> float | None:
    return sum((p - y) ** 2 for p, y in pairs) / len(pairs) if pairs else None


def log_loss(pairs) -> float | None:
    if not pairs:
        return None
    eps = 1e-15
    return -sum(y * math.log(max(p, eps)) + (1 - y) * math.log(max(1 - p, eps)) for p, y in pairs) / len(pairs)


def auc(pairs) -> float | None:
    pos = [p for p, y in pairs if y == 1]
    neg = [p for p, y in pairs if y == 0]
    if not pos or not neg:
        return None
    wins = sum(1 if a > b else 0.5 if a == b else 0 for a in pos for b in neg)
    return wins / (len(pos) * len(neg))


def skill(score: float | None, reference: float | None) -> float | None:
    """Brier skill = 1 − score / reference。基準が 0 または未算出なら None。"""
    if score is None or reference in (None, 0):
        return None
    return 1 - score / reference


def sample_mean_brier(pairs) -> float | None:
    """標本平均を定数予測した Brier（事後的な基準線。厳しい比較対象）。"""
    if not pairs:
        return None
    mean = sum(y for _p, y in pairs) / len(pairs)
    return sum((mean - y) ** 2 for _p, y in pairs) / len(pairs)


# --------------------------------------------------------------------------
# ウォークフォワード診断（遡及・昇格の母集団には使わない）
# --------------------------------------------------------------------------

def walkforward(data: Data, as_of: datetime, nexuses=None, horizons=HORIZONS_DAYS,
                history_start: date = HISTORY_START) -> list:
    """各グリッド日について、**その日の時点までの情報だけで**確率を作り、結果と突き合わせる。

    これは遡及的な診断であり、予報の台帳ではない。モデルはパラメータ調整なしの固定式で、
    診断の結果を見てから式を変えない。昇格の母集団（前向きの台帳）には入れない。
    """
    rows = []
    for nexus in nexuses or NEXUS_COUNTRY:
        times = data.events[nexus]
        for horizon in horizons:
            day = history_start
            while True:
                g = issue_instant(day)
                deadline = g + timedelta(days=horizon)
                if deadline > as_of:
                    break
                if window_covered(data, g, deadline):
                    fc = forecast(data, nexus, horizon, g, history_start)
                    if fc["abstain"] is None:
                        rows.append({
                            "nexus": nexus, "horizon": horizon, "day": day.isoformat(),
                            "y": int(has_event(times, g, deadline)), "state": fc["state"],
                            "fallback": fc["fallback"],
                            MODEL_CLIMATOLOGY: fc[MODEL_CLIMATOLOGY], MODEL_RECENCY: fc[MODEL_RECENCY],
                        })
                day += timedelta(days=1)
    return rows


def block_bootstrap_skill(rows: list, model: str = MODEL_RECENCY, reference: str = MODEL_CLIMATOLOGY,
                          block_days: int = BOOTSTRAP_BLOCK_DAYS, samples: int = BOOTSTRAP_SAMPLES,
                          seed: int = 0):
    """model の reference に対する Brier skill の点推定と 95% 区間（日付ブロックのブートストラップ）。

    隣り合う日は窓が重なり相関するため、行ではなく連続した日付ブロックを単位に再標本化する。
    """
    if not rows:
        return None, None, None
    base = min(date.fromisoformat(r["day"]) for r in rows)
    blocks: dict = {}
    for r in rows:
        blocks.setdefault((date.fromisoformat(r["day"]) - base).days // block_days, []).append(r)
    keys = sorted(blocks)

    def bss(selected):
        a = sum((r[model] - r["y"]) ** 2 for r in selected)
        b = sum((r[reference] - r["y"]) ** 2 for r in selected)
        return None if b == 0 else 1 - a / b

    point = bss(rows)
    rng = random.Random(seed)
    values = []
    for _ in range(samples):
        chosen = [r for key in (keys[rng.randrange(len(keys))] for _ in keys) for r in blocks[key]]
        v = bss(chosen)
        if v is not None:
            values.append(v)
    if len(values) < 20:
        return point, None, None
    values.sort()
    return point, values[int(0.025 * len(values))], values[min(len(values) - 1, int(0.975 * len(values)))]


def summarize_rows(rows: list) -> dict:
    """診断行を国×地平別・全体で集計する。"""
    out = {}
    for horizon in sorted({r["horizon"] for r in rows}):
        subset = [r for r in rows if r["horizon"] == horizon]
        pairs0 = [(r[MODEL_CLIMATOLOGY], r["y"]) for r in subset]
        pairs1 = [(r[MODEL_RECENCY], r["y"]) for r in subset]
        point, lo, hi = block_bootstrap_skill(subset)
        out[HORIZON_LABELS[horizon]] = {
            "rows": len(subset),
            "independent_n_estimate": math.ceil(len(subset) / horizon),
            "positive_rate": round(sum(r["y"] for r in subset) / len(subset), 4),
            "brier_climatology": round(brier(pairs0), 6),
            "brier_recency": round(brier(pairs1), 6),
            "brier_sample_mean": round(sample_mean_brier(pairs0), 6),
            "bss_recency_vs_climatology": None if point is None else round(point, 4),
            "bss_ci95": None if lo is None else [round(lo, 4), round(hi, 4)],
            "auc_recency": None if auc(pairs1) is None else round(auc(pairs1), 4),
            "fallback_share": round(sum(1 for r in subset if r["fallback"]) / len(subset), 4),
        }
    return out
