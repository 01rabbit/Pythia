#!/usr/bin/env python3
"""NX-1（国別 nexus 活動の確認予報・第4段階）の受入基準を検査する。

依存は Python 3 標準ライブラリのみ。ネットワークへは出ない。観測は合成データで与え、
期待値は『独立に書いた力任せの実装』と突き合わせる（ライブラリの関数で期待値を作らない）。

検査する受入基準:
  A. 窓と被覆
     1. 窓は (start, end]。日次ラン H 日分が揃わない窓は miss にせず not_observed
     2. 窓が満了していなければ pending（右打ち切りを miss にしない）
     3. 固定 as_of より後に利用可能になった観測は採点に使わない
  B. 参照率（as-of）
     4. n・k・直近活動クラスが力任せの実装と一致する。欠測日を含む窓は標本から除く
     5. cutoff より後の観測を足しても発行時点の確率は変わらない（未来情報の非混入）
     6. 履歴が足りなければ棄権。クラスの標本が小さければ climatology へ後退する
  C. 読み込み
     7. 機械バックフィルは事象にも被覆にも数えない。未スタンプの観測は翌日 00:00 JST に倒す
  D. 台帳
     8. 発行は決定論的で、ハッシュで凍結される。発行済みの台帳は書き換えない
  E. 検証器
     9. 正例が通り、確率・ハッシュ・時刻・根拠の分離・公開・verified_outcome の改ざんを落とす
    10. 観測からの再計算が合わない台帳（確率を書き換えて再ハッシュしたもの）を落とす
    11. 登録簿: shadow で承認済み・context_inputs_allowed が空でない・承認の根拠が無いものを落とす
  F. 採点と診断
    12. 採点器の集計・独立標本数（÷H）・ゲート判定
    13. ウォークフォワードは未来を見ない。ブロックブートストラップは決定論的
  G. 不変条件
    14. Section 5・6（neighbor_context / infrastructure_context）を読む予報コードが無い
    15. 保護ファイルを書き換えない

使い方:
    python3 scripts/test_nexus_family.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPTS)
sys.path.insert(0, SCRIPTS)

import generate_nexus_candidates as gen  # noqa: E402
import nexus_family as nf  # noqa: E402
import validate_nexus_integrity as vni  # noqa: E402
import verify_nexus_forecasts as ver  # noqa: E402
from tactical_integrity import hash_without  # noqa: E402

UTC, JST = timezone.utc, timezone(timedelta(hours=9))
START = nf.HISTORY_START
CN = "china_nexus"


def at_jst(day: date, hour: int = 12, minute: int = 0) -> datetime:
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=JST).astimezone(UTC)


def days_range(first: date, last: date):
    d = first
    while d <= last:
        yield d
        d += timedelta(days=1)


def make_data(event_days, first=START, last=START + timedelta(days=100), missing=()):
    """事象日（その日の 12:00 JST に利用可能）と被覆日から Data を作る。"""
    events = {n: [] for n in nf.NEXUS_COUNTRY}
    events[CN] = sorted(at_jst(d) for d in event_days)
    covered = {d.isoformat() for d in days_range(first, last)} - {m.isoformat() for m in missing}
    return nf.Data(events, covered)


# --------------------------------------------------------------------------
# A. 窓と被覆
# --------------------------------------------------------------------------

class WindowTests(unittest.TestCase):
    def test_window_is_open_closed(self) -> None:
        t0 = at_jst(date(2026, 8, 1), 7, 30)
        times = [t0, t0 + timedelta(days=3)]
        self.assertFalse(nf.has_event(times, t0, t0))                       # 開始は含まない
        self.assertTrue(nf.has_event(times, t0, t0 + timedelta(days=3)))    # 終了は含む
        self.assertFalse(nf.has_event(times, t0, t0 + timedelta(days=3, seconds=-1)))

    def test_required_days_are_H_daily_runs(self) -> None:
        g = nf.issue_instant(date(2026, 8, 10))
        self.assertEqual(nf.required_days(g, g + timedelta(days=3)), ["2026-08-10", "2026-08-11", "2026-08-12"])
        self.assertEqual(len(nf.required_days(g, g + timedelta(days=7))), 7)

    def test_miss_hit_pending_not_observed(self) -> None:
        issued = nf.issue_instant(date(2026, 8, 10))
        event_day = date(2026, 8, 11)
        data = make_data({event_day}, missing=[])
        after = issued + timedelta(days=4)
        self.assertEqual(nf.score_window(data, CN, issued, 3, after), "hit")
        quiet = make_data(set())
        self.assertEqual(nf.score_window(quiet, CN, issued, 3, after), "miss")
        self.assertEqual(nf.score_window(quiet, CN, issued, 3, issued + timedelta(days=2)), "pending")  # 右打ち切り
        gap = make_data(set(), missing=[date(2026, 8, 11)])
        self.assertEqual(nf.score_window(gap, CN, issued, 3, after), "not_observed")  # 欠測日を含む
        gap_hit = make_data({event_day}, missing=[date(2026, 8, 12)])
        self.assertEqual(nf.score_window(gap_hit, CN, issued, 3, after), "hit")  # 事象があれば欠測日があっても hit

    def test_as_of_hides_later_observations(self) -> None:
        issued = nf.issue_instant(date(2026, 8, 10))
        data = make_data({date(2026, 8, 12)})  # 8/12 12:00 JST に利用可能
        as_of_early = at_jst(date(2026, 8, 12), 9)
        self.assertEqual(nf.score_window(data, CN, issued, 3, as_of_early), "pending")
        self.assertEqual(nf.score_window(data, CN, issued, 3, issued + timedelta(days=4)), "hit")


# --------------------------------------------------------------------------
# B. 参照率（as-of）
# --------------------------------------------------------------------------

def brute_estimate(event_days: set, covered: set, horizon: int, cutoff: datetime):
    """日単位の力任せの実装（事象は D 日 12:00 JST・発行は D 日 07:30 JST）。"""
    n = k = excluded = 0
    classes = {0: [0, 0], 1: [0, 0]}
    d = START
    while True:
        if nf.issue_instant(d) + timedelta(days=horizon) > cutoff:
            break
        window = [d + timedelta(days=i) for i in range(horizon)]            # D .. D+H-1
        look = [d - timedelta(days=i) for i in range(1, horizon + 1)]       # D-H .. D-1
        if not all(x.isoformat() in covered for x in window):
            excluded += 1
            d += timedelta(days=1)
            continue
        y = int(any(x in event_days for x in window))
        n += 1
        k += y
        if d - timedelta(days=horizon) >= START and all(x.isoformat() in covered for x in look):
            s = int(any(x in event_days for x in look))
            classes[s][0] += 1
            classes[s][1] += y
        d += timedelta(days=1)
    return n, k, classes, excluded


class EstimateTests(unittest.TestCase):
    def setUp(self) -> None:
        rng = random.Random(7)
        self.event_days = {START + timedelta(days=i) for i in range(0, 100) if rng.random() < 0.18}
        self.missing = [START + timedelta(days=20), START + timedelta(days=51)]
        self.data = make_data(self.event_days, missing=self.missing)
        self.cutoff = at_jst(START + timedelta(days=90), 7, 31)

    def test_matches_brute_force(self) -> None:
        for horizon in nf.HORIZONS_DAYS:
            n, k, classes, excluded = brute_estimate(self.event_days, self.data.covered, horizon, self.cutoff)
            got = nf.estimate(self.data, CN, horizon, self.cutoff)
            self.assertEqual((got["n"], got["k"], got["excluded_uncovered"]), (n, k, excluded), horizon)
            self.assertEqual({s: (c["n"], c["k"]) for s, c in got["classes"].items()},
                             {s: tuple(v) for s, v in classes.items()}, horizon)
            self.assertGreater(excluded, 0)  # 欠測日を含む窓が実際に除かれている

    def test_forecast_formula(self) -> None:
        fc = nf.forecast(self.data, CN, 3, self.cutoff)
        est = fc["estimate"]
        self.assertAlmostEqual(fc[nf.MODEL_CLIMATOLOGY], (est["k"] + 0.5) / (est["n"] + 1))
        if fc["fallback"] is None:
            cls = est["classes"][fc["state"]]
            self.assertAlmostEqual(fc[nf.MODEL_RECENCY], (cls["k"] + 0.5) / (cls["n"] + 1))
        for p in (fc[nf.MODEL_CLIMATOLOGY], fc[nf.MODEL_RECENCY]):
            self.assertTrue(0 < p < 1)

    def test_future_observations_do_not_change_the_forecast(self) -> None:
        base = nf.forecast(self.data, CN, 7, self.cutoff)
        future = set(self.event_days) | {START + timedelta(days=d) for d in (91, 92, 95, 97)}
        leaked = nf.forecast(make_data(future, missing=self.missing), CN, 7, self.cutoff)
        for key in (nf.MODEL_CLIMATOLOGY, nf.MODEL_RECENCY, "state", "fallback"):
            self.assertEqual(base[key], leaked[key], key)
        self.assertEqual(base["estimate"], leaked["estimate"])

    def test_abstains_without_history_and_falls_back_on_small_classes(self) -> None:
        short = make_data({START + timedelta(days=3)}, last=START + timedelta(days=20))
        fc = nf.forecast(short, CN, 3, at_jst(START + timedelta(days=20), 7, 31))
        self.assertEqual(fc["abstain"], "INSUFFICIENT_HISTORY")
        # 事象が1件だけの履歴では片方のクラスが MIN_CLASS_DAYS に届かない
        sparse = make_data({START + timedelta(days=40), START + timedelta(days=59)},
                           last=START + timedelta(days=60))
        fc = nf.forecast(sparse, CN, 3, at_jst(START + timedelta(days=60), 7, 31))
        self.assertIsNone(fc["abstain"])
        self.assertEqual(fc["state"], 1)  # 直近 3 日に事象がある
        self.assertEqual(fc["fallback"], "CLASS_SAMPLE_SMALL")  # 直近活動ありのクラスは 3 日分しかない
        self.assertEqual(fc[nf.MODEL_RECENCY], fc[nf.MODEL_CLIMATOLOGY])

    def test_lookback_gap_falls_back(self) -> None:
        data = make_data(set(), missing=[START + timedelta(days=58)])
        fc = nf.forecast(data, CN, 3, at_jst(START + timedelta(days=60), 7, 31))
        self.assertEqual(fc["fallback"], "LOOKBACK_NOT_COVERED")
        self.assertIsNone(fc["state"])


# --------------------------------------------------------------------------
# C. 読み込み
# --------------------------------------------------------------------------

def write_obs(root: str, day: date, observations, mode="source_explicit_all") -> None:
    path = os.path.join(root, "forecaster", "observations", f"{day:%Y}", f"{day:%m}", f"{day.isoformat()}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"_schema_version": "1.2", "_observation_date": day.isoformat(),
                   "_normalization_mode": mode, "observations": observations}, fh, ensure_ascii=False)


class LoadTests(unittest.TestCase):
    def test_backfill_excluded_and_unstamped_is_conservative(self) -> None:
        root = tempfile.mkdtemp(prefix="pythia-nx-load-")
        d = date(2026, 8, 5)
        write_obs(root, d, [
            {"observation_id": "a", "observed_date": d.isoformat(), "ingested_date": d.isoformat(),
             "geopolitical_signal": "china_nexus"},                                           # 未スタンプ
            {"observation_id": "b", "observed_date": d.isoformat(), "ingested_date": d.isoformat(),
             "geopolitical_signal": "russia_nexus", "available_at_utc": "2026-08-05T01:00:00Z"},
            {"observation_id": "c", "observed_date": d.isoformat(), "geopolitical_signal": "iran_nexus",
             "available_at_utc": "2026-08-05T01:00:00Z"},                                    # 対象外の国
            {"observation_id": "d", "observed_date": d.isoformat(), "geopolitical_signal": None,
             "available_at_utc": "2026-08-05T01:00:00Z"},
        ])
        write_obs(root, date(2026, 7, 1), [
            {"observation_id": "z", "observed_date": "2026-07-01", "geopolitical_signal": "china_nexus",
             "available_at_utc": "2026-07-01T01:00:00Z"}], mode="machine_backfill_kev")
        data = nf.load_data(root, evidence_index={})
        self.assertEqual(data.covered, {"2026-08-05"})              # バックフィル日は被覆に数えない
        self.assertEqual(data.events["china_nexus"], [at_jst(date(2026, 8, 6), 0, 0)])  # 翌日 00:00 JST
        self.assertEqual(data.events["russia_nexus"], [datetime(2026, 8, 5, 1, 0, tzinfo=UTC)])
        self.assertEqual(data.events["north_korea_nexus"], [])
        self.assertEqual(sum(len(v) for v in data.events.values()), 2)


# --------------------------------------------------------------------------
# D・E. 台帳と検証器
# --------------------------------------------------------------------------

def make_root(days: int = 90) -> str:
    """合成した観測（約 5 日ごとに nexus 事象）と登録簿を持つ使い捨てのルートを作る。"""
    root = tempfile.mkdtemp(prefix="pythia-nx-root-")
    for rel in (os.path.join("forecaster", "models", "nexus-registry.json"),
                os.path.join("forecaster", "config", "promotion-gates.json"), "config.yml"):
        os.makedirs(os.path.dirname(os.path.join(root, rel)) or root, exist_ok=True)
        shutil.copy(os.path.join(REPO_ROOT, rel), os.path.join(root, rel))
    for i in range(days):
        d = START + timedelta(days=i)
        obs = []
        for j, sig in enumerate(nf.NEXUS_COUNTRY):
            if (i + 2 * j) % 5 == 0:
                obs.append({"observation_id": f"obs-{d.isoformat()}-{j}", "observed_date": d.isoformat(),
                            "geopolitical_signal": sig, "available_at_utc": at_jst(d, 8).isoformat().replace("+00:00", "Z")})
        write_obs(root, d, obs)
    return root


def issue(root: str, day: date):
    cutoff = nf.issue_instant(day)
    issued = cutoff + timedelta(seconds=1)
    data = nf.load_data(root, evidence_index={})
    doc = gen.build_ledger(day.isoformat(), data, cutoff, issued, list(nf.NEXUS_COUNTRY))
    path = os.path.join(root, "forecaster", "candidates", "nexus", f"{day.isoformat()}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
    with open(path, encoding="utf-8") as fh:
        return path, json.load(fh)  # 実運用と同じくファイルを経由した形で返す


def rehash(doc):
    """候補と台帳のハッシュを付け直す（改ざん後に整合した体裁を作る攻撃者の想定）。"""
    for c in doc["candidates"]:
        c["content_sha256"] = hash_without(c, "content_sha256")
    doc["_ledger_sha256"] = hash_without(doc, "_ledger_sha256")
    return doc


class LedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = make_root()
        cls.day = START + timedelta(days=88)
        cls.path, cls.doc = issue(cls.root, cls.day)

    def test_structure_and_determinism(self) -> None:
        doc = self.doc
        self.assertEqual(len(doc["candidates"]), 3)
        self.assertEqual(doc["_coverage"]["by_status"], {"shadow": 3})
        c = doc["candidates"][0]
        self.assertEqual(c["candidate_id"], "nx-20260925-CN")
        self.assertEqual(set(c["probability_by_horizon"]), {"72h", "7d"})
        self.assertEqual(c["probability_by_horizon"], c["models"][nf.MODEL_CLIMATOLOGY]["probability_by_horizon"])
        self.assertEqual(c["inputs"]["context_inputs"], [])
        self.assertIsNone(c["verified_outcome"])
        data = nf.load_data(self.root, evidence_index={})
        again = gen.build_ledger(self.day.isoformat(), data, nf.issue_instant(self.day),
                                 nf.issue_instant(self.day) + timedelta(seconds=1), list(nf.NEXUS_COUNTRY))
        self.assertEqual(again, self.doc)  # 同じ入力から同じ台帳

    def test_cli_refuses_to_overwrite(self) -> None:
        args = [sys.executable, os.path.join(SCRIPTS, "generate_nexus_candidates.py"), "--root", self.root,
                "--date", self.day.isoformat(), "--cutoff-at-utc", "2026-09-25T22:31:06Z",
                "--issued-at-utc", "2026-09-25T22:31:07Z"]
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("書き換えない", result.stderr)

    def test_abstains_when_history_is_short(self) -> None:
        root = make_root(days=15)
        _path, doc = issue(root, START + timedelta(days=14))
        self.assertEqual(doc["_coverage"]["by_status"], {"abstained": 3})
        c = doc["candidates"][0]
        self.assertEqual(c["selection"]["reason_code"], "INSUFFICIENT_HISTORY")
        self.assertEqual(sorted(c["abstained_horizons"]), ["72h", "7d"])
        self.assertEqual(vni.run(root, (START + timedelta(days=14)).isoformat())[0], [])


class ValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = make_root()
        cls.day = START + timedelta(days=88)
        cls.path, cls.doc = issue(cls.root, cls.day)

    def check(self, doc, recompute=True):
        data = nf.load_data(self.root, evidence_index={})
        return vni.check_ledger(self.path, doc, "shadow", data, recompute)[0]

    def assertCaught(self, mutate, needle, *, rehashed=False, recompute=True):
        doc = copy.deepcopy(self.doc)
        mutate(doc)
        if rehashed:
            rehash(doc)
        errors = self.check(doc, recompute)
        self.assertTrue(any(needle in e for e in errors), f"{needle!r} が無い: {errors}")

    def test_good_ledger_passes_with_recompute(self) -> None:
        self.assertEqual(self.check(copy.deepcopy(self.doc)), [])
        self.assertEqual(vni.run(self.root, self.day.isoformat())[0], [])
        self.assertEqual(vni.run(self.root, None, True)[0], [])

    def test_tampering_is_caught(self) -> None:
        self.assertCaught(lambda d: d["candidates"][0]["probability_by_horizon"].update({"72h": 0.99}),
                          "content_sha256")
        self.assertCaught(lambda d: d["candidates"][0].update({"selection": {"status": "shadow", "reason_code": "x"}}),
                          "content_sha256")
        # 候補を直して候補ハッシュも付け直したが、台帳ハッシュは古いまま
        def only_candidate_hash(d):
            d["candidates"][0]["probability_by_horizon"]["72h"] = 0.5
            d["candidates"][0]["content_sha256"] = hash_without(d["candidates"][0], "content_sha256")
        self.assertCaught(only_candidate_hash, "_ledger_sha256")

    def test_recompute_catches_rewritten_probabilities(self) -> None:
        def rewrite(d):
            c = d["candidates"][0]
            c["probability_by_horizon"]["72h"] = 0.9
            c["models"][nf.MODEL_CLIMATOLOGY]["probability_by_horizon"]["72h"] = 0.9
        # ハッシュを付け直して体裁を整えても、観測から再現できない
        self.assertCaught(rewrite, "再現できない", rehashed=True)
        # 再計算を省略すると見逃す（だから日次では --date で再計算する）
        doc = copy.deepcopy(self.doc)
        rewrite(doc)
        rehash(doc)
        self.assertEqual(self.check(doc, recompute=False), [])

    def test_structure_rules(self) -> None:
        self.assertCaught(lambda d: d.update({"_cutoff_at_utc": "2026-09-26T23:00:00Z"}), "issued_at が cutoff より前")
        self.assertCaught(lambda d: d.update({"_candidate_date": "2026-09-24"}), "一致しない", rehashed=True, recompute=False)
        self.assertCaught(lambda d: d["candidates"][0]["inputs"].update({"context_inputs": ["neighbor_context"]}),
                          "context_inputs は空", rehashed=True, recompute=False)
        self.assertCaught(lambda d: d["candidates"][0]["inputs"].update({"sources": ["forecaster/observations", "outputs"]}),
                          "inputs.sources", rehashed=True, recompute=False)
        self.assertCaught(lambda d: d["candidates"][0]["selection"].update({"status": "published"}),
                          "公開しない", rehashed=True, recompute=False)
        self.assertCaught(lambda d: d["candidates"][0].update({"verified_outcome": {"hit": True}}),
                          "verified_outcome", rehashed=True, recompute=False)
        def out_of_range(d):
            c = d["candidates"][0]
            c["probability_by_horizon"]["7d"] = 1.2
            c["models"][nf.MODEL_CLIMATOLOGY]["probability_by_horizon"]["7d"] = 1.2
        self.assertCaught(out_of_range, "(0,1)", rehashed=True, recompute=False)
        def null_primary(d):
            c = d["candidates"][0]
            c["probability_by_horizon"]["7d"] = None
            c["models"][nf.MODEL_CLIMATOLOGY]["probability_by_horizon"]["7d"] = None
        self.assertCaught(null_primary, "abstained_horizons", rehashed=True, recompute=False)
        self.assertCaught(lambda d: d["candidates"][0]["probability_by_horizon"].update({"7d": None}),
                          "primary モデルの確率と一致しない", rehashed=True, recompute=False)
        self.assertCaught(lambda d: d["candidates"][0].update({"forecast_family": "TF-1"}),
                          "forecast_family", rehashed=True, recompute=False)
        self.assertCaught(lambda d: d["candidates"][0]["target_event"].update({"matching_rule_version": "nx1-rule-v2"}),
                          "matching_rule_version", rehashed=True, recompute=False)
        self.assertCaught(lambda d: d["candidates"][1].update({"candidate_id": d["candidates"][0]["candidate_id"]}),
                          "candidate_id", rehashed=True, recompute=False)

    def test_history_drift_is_a_warning_but_same_day_is_an_error(self) -> None:
        root = make_root()
        path, doc = issue(root, self.day)
        c = doc["candidates"][0]
        c["probability_by_horizon"]["72h"] = 0.9
        c["models"][nf.MODEL_CLIMATOLOGY]["probability_by_horizon"]["72h"] = 0.9
        rehash(doc)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
        errors, warnings = vni.run(root, None, True)  # 全履歴の再計算: 履歴の観測は正当に変わりうる
        self.assertEqual(errors, [])
        self.assertTrue(any("[履歴の変化]" in w and "再現できない" in w for w in warnings), warnings)
        errors, _ = vni.run(root, self.day.isoformat())  # 発行当日: 厳格
        self.assertTrue(any("再現できない" in e for e in errors), errors)

    def test_future_issue_is_caught(self) -> None:
        errors, _ = vni.check_ledger(self.path, copy.deepcopy(self.doc), "shadow", None, False,
                                     now=datetime(2026, 9, 1, tzinfo=UTC))
        self.assertTrue(any("未来" in e for e in errors), errors)


class RegistryTests(unittest.TestCase):
    def registry(self):
        with open(os.path.join(REPO_ROOT, "forecaster", "models", "nexus-registry.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def test_repo_registry_is_valid(self) -> None:
        self.assertEqual(vni.check_registry(self.registry(), REPO_ROOT), [])

    def test_rules(self) -> None:
        reg = self.registry()
        reg["models"][1]["approved_for_publication"] = True
        self.assertTrue(any("mode=shadow なのに" in e for e in vni.check_registry(reg, REPO_ROOT)))
        reg = self.registry()
        reg["context_inputs_allowed"] = ["neighbor_context"]
        self.assertTrue(any("context_inputs_allowed" in e for e in vni.check_registry(reg, REPO_ROOT)))
        reg = self.registry()
        reg["mode"] = "active"
        self.assertTrue(any("承認済みのモデルが無い" in e for e in vni.check_registry(reg, REPO_ROOT)))
        reg = self.registry()
        reg["mode"] = "limited"
        reg["models"][1]["approved_for_publication"] = True
        errors = vni.check_registry(reg, REPO_ROOT)
        self.assertTrue(any("approval" in e for e in errors), errors)
        # 基準線は弁別を主張しないため公開昇格できない
        reg["models"][0]["approved_for_publication"] = True
        self.assertTrue(any("public_forecast_eligible=false" in e for e in vni.check_registry(reg, REPO_ROOT)))

    def test_approval_requires_passing_gates_in_the_cited_file(self) -> None:
        root = tempfile.mkdtemp(prefix="pythia-nx-approval-")
        vf = os.path.join(root, "verification.json")
        reg = self.registry()
        reg["mode"] = "limited"
        reg["models"][1]["approved_for_publication"] = True
        reg["models"][1]["approval"] = {"approved_by": "reviewer", "approved_at_utc": "2026-12-01T00:00:00Z",
                                         "verification_file": "verification.json"}
        with open(vf, "w", encoding="utf-8") as fh:
            json.dump({"models": {nf.MODEL_RECENCY: {"72h": {"gates_pass": True}, "7d": {"gates_pass": False}}}}, fh)
        errors = vni.check_registry(reg, root)
        self.assertTrue(any("7d" in e and "ゲート" in e for e in errors), errors)
        with open(vf, "w", encoding="utf-8") as fh:
            json.dump({"models": {nf.MODEL_RECENCY: {"72h": {"gates_pass": True}, "7d": {"gates_pass": True}}}}, fh)
        self.assertEqual(vni.check_registry(reg, root), [])


# --------------------------------------------------------------------------
# F. 採点と診断
# --------------------------------------------------------------------------

class VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = make_root(days=100)
        for offset in (60, 68, 76):
            issue(cls.root, START + timedelta(days=offset))
        cls.as_of = at_jst(START + timedelta(days=100), 12)

    def test_counts_independence_and_gates(self) -> None:
        result = ver.verify(self.root, self.as_of)
        for model in nf.MODELS:
            for label, horizon in (("72h", 3), ("7d", 7)):
                m = result["models"][model][label]
                self.assertEqual(sum(m[k] for k in ("hit", "miss", "pending", "not_observed", "abstained")), 9)
                self.assertEqual(m["scored_n"], m["hit"] + m["miss"])
                self.assertEqual(m["independent_n_estimate"], -(-m["scored_n"] // horizon))  # ceil(scored / H)
                self.assertFalse(m["gates_pass"])  # 標本が足りない（resolved_n < 100）
                self.assertFalse(m["gates"]["resolved_n"])
        self.assertEqual(result["models"][nf.MODEL_CLIMATOLOGY]["72h"]["evaluation_profile"], "reference_only_calibration")
        self.assertIsNone(result["models"][nf.MODEL_CLIMATOLOGY]["72h"]["brier_skill_vs_climatology"])

    def test_scoring_matches_brute_force(self) -> None:
        result = ver.verify(self.root, self.as_of)
        data = nf.load_data(self.root, evidence_index={})
        events = {n: [t for t in ts] for n, ts in data.events.items()}
        hits = 0
        for offset in (60, 68, 76):
            issued = nf.issue_instant(START + timedelta(days=offset)) + timedelta(seconds=1)
            for nexus in nf.NEXUS_COUNTRY:
                if any(issued < t <= issued + timedelta(days=3) for t in events[nexus]):
                    hits += 1
        self.assertEqual(result["models"][nf.MODEL_CLIMATOLOGY]["72h"]["hit"], hits)

    def test_unobserved_gap_is_not_a_miss(self) -> None:
        root = make_root(days=100)
        issue(root, START + timedelta(days=60))
        gap_day = START + timedelta(days=61)
        os.remove(os.path.join(root, "forecaster", "observations", f"{gap_day:%Y}", f"{gap_day:%m}",
                               gap_day.isoformat() + ".json"))
        result = ver.verify(root, self.as_of)
        for model in nf.MODELS:
            m = result["models"][model]["72h"]
            self.assertEqual(m["hit"] + m["miss"] + m["not_observed"], 3)
            self.assertGreater(m["not_observed"], 0)

    def test_walkforward_never_looks_ahead(self) -> None:
        events = {START + timedelta(days=i) for i in range(0, 100, 4)}
        data = make_data(events)
        as_of = at_jst(START + timedelta(days=100), 12)
        rows = nf.walkforward(data, as_of, nexuses=[CN])
        self.assertGreater(len(rows), 50)
        # 後半の事象を全部消しても、前半の各日の確率は変わらない
        trimmed = make_data({d for d in events if d < START + timedelta(days=60)})
        by_key = {(r["day"], r["horizon"]): r for r in nf.walkforward(trimmed, as_of, nexuses=[CN])}
        compared = 0
        for a in rows:
            if date.fromisoformat(a["day"]) + timedelta(days=a["horizon"]) <= START + timedelta(days=60):
                b = by_key[(a["day"], a["horizon"])]
                self.assertEqual((a[nf.MODEL_CLIMATOLOGY], a[nf.MODEL_RECENCY]),
                                 (b[nf.MODEL_CLIMATOLOGY], b[nf.MODEL_RECENCY]))
                compared += 1
        self.assertGreater(compared, 30)

    def test_bootstrap_is_deterministic_and_ordered(self) -> None:
        rows = nf.walkforward(make_data({START + timedelta(days=i) for i in range(0, 100, 3)}),
                              at_jst(START + timedelta(days=100), 12), nexuses=[CN])
        first = nf.block_bootstrap_skill(rows)
        self.assertEqual(first, nf.block_bootstrap_skill(rows))
        point, lo, hi = first
        self.assertIsNotNone(lo)
        self.assertLessEqual(lo, hi)
        self.assertEqual(nf.block_bootstrap_skill([]), (None, None, None))
        summary = nf.summarize_rows(rows)
        self.assertEqual(set(summary), {"72h", "7d"})

    def test_metrics(self) -> None:
        pairs = [(0.9, 1), (0.8, 1), (0.2, 0), (0.1, 0)]
        self.assertAlmostEqual(nf.brier(pairs), (0.01 + 0.04 + 0.04 + 0.01) / 4)
        self.assertEqual(nf.auc(pairs), 1.0)
        self.assertEqual(nf.auc([(0.5, 1), (0.5, 0)]), 0.5)
        self.assertIsNone(nf.auc([(0.5, 1)]))
        self.assertIsNone(nf.skill(0.1, 0))
        self.assertAlmostEqual(nf.skill(0.1, 0.2), 0.5)


# --------------------------------------------------------------------------
# G. 不変条件
# --------------------------------------------------------------------------

class InvariantTests(unittest.TestCase):
    ALLOWED = {
        # Section 5・6 を作る／検証する／描画するスクリプトと、それらのテスト・整合チェッカー
        "validate_neighbor_context.py", "render_neighbor_section.py", "neighbor_scan.py",
        "enrich_infrastructure.py", "validate_infrastructure_context.py", "render_infrastructure_section.py",
        "check_report_consistency.py", "test_neighbor_context.py", "test_infrastructure_context.py",
        "test_nexus_family.py",
    }

    def test_no_forecasting_code_reads_section_5_or_6(self) -> None:
        offenders = []
        for name in sorted(os.listdir(SCRIPTS)):
            if not name.endswith(".py") or name in self.ALLOWED:
                continue
            with open(os.path.join(SCRIPTS, name), encoding="utf-8") as fh:
                text = fh.read()
            if "neighbor_context" in text or "infrastructure_context" in text:
                offenders.append(name)
        self.assertEqual(offenders, [], "予報側のコードが Section 5・6 を参照している。"
                                        "取り込みは nexus-context-preregistration.json の手続き（PR・前向き標本・ゲート）を経る")

    def test_preregistration_is_not_active(self) -> None:
        with open(os.path.join(REPO_ROOT, "forecaster", "config", "nexus-context-preregistration.json"),
                  encoding="utf-8") as fh:
            prereg = json.load(fh)
        self.assertEqual(prereg["status"], "not_active")
        self.assertTrue(prereg["protocol"]["forward_only"])
        for h in prereg["hypotheses"]:
            for name in sorted(os.listdir(SCRIPTS)):
                if name.endswith(".py") and name != "test_nexus_family.py":
                    with open(os.path.join(SCRIPTS, name), encoding="utf-8") as fh:
                        self.assertNotIn(h["feature"], fh.read(), f"{name} が未採用の特徴量 {h['feature']} を実装している")

    def test_subjects_follow_config(self) -> None:
        self.assertEqual(gen.active_subjects({"neighbor_states": {"primary": ["CN", "KP"]}}),
                         ["china_nexus", "north_korea_nexus"])
        self.assertEqual(gen.active_subjects({}), list(nf.NEXUS_COUNTRY))
        import watchlist as wl
        config = wl.load_config(os.path.join(REPO_ROOT, "config.yml"))
        self.assertEqual(gen.active_subjects(config), list(nf.NEXUS_COUNTRY))

    def test_horizon_labels_match_tf1_labels(self) -> None:
        from tactical_states import HORIZON_LABELS as TF1
        for h, label in nf.HORIZON_LABELS.items():
            self.assertEqual(TF1[h], label)

    def test_library_does_not_write_protected_files(self) -> None:
        know = os.path.join(REPO_ROOT, "forecaster", "knowledge")
        paths = [os.path.join(REPO_ROOT, "config.yml"), os.path.join(REPO_ROOT, "forecaster", "models", "nexus-registry.json")]
        paths += [os.path.join(know, n) for n in sorted(os.listdir(know)) if os.path.isfile(os.path.join(know, n))]

        def sha(p):
            with open(p, "rb") as fh:
                return hashlib.sha256(fh.read()).hexdigest()
        before = {p: sha(p) for p in paths}
        data = nf.load_data(REPO_ROOT)
        cutoff = datetime(2026, 11, 6, 22, 31, tzinfo=UTC)
        for nexus in nf.NEXUS_COUNTRY:
            nf.forecast(data, nexus, 3, cutoff)
        gen.build_ledger("2026-11-07", data, cutoff, cutoff + timedelta(seconds=1), list(nf.NEXUS_COUNTRY))
        vni.run(REPO_ROOT, None)
        self.assertEqual(before, {p: sha(p) for p in paths})


if __name__ == "__main__":
    unittest.main(verbosity=1)
