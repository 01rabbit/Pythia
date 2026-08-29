#!/usr/bin/env python3
"""TF-1 shadow（第1段階）の受入基準を機械的に検査する（設計 §14）。

依存は Python 3 標準ライブラリのみ。ネットワークへは出ない。

検査する受入基準:
  1. LLM が確率を書き込めない（確率は参照クラスから決定論的に決まり、同一入力で再現する）
  2. placeholder transition を根拠に使うと拒否される
  3. 許可 transition にない遷移は拒否される
  4. 後退遷移は拒否される
  5. actor 不明案件へ actor 固有予報を出すと拒否される
  6. 候補に current_state と visibility_model がある
  7. 棄権を含む全候補母集団が保存される（採用+棄権 = 生成された候補総数）
  8. 状態導出が本文キーワードではなく構造化フィールドだけに依存する
  9. 複合命題を partial で逃がさない（採点値が二値＋pending/unobservable/abstained のみ）
 10. 右打ち切りを miss に数えない
 11. 確率が時間軸に対して単調（P72h <= P7d <= P30d）

使い方:
    python3 scripts/test_tf1_shadow.py
"""

import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO_ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

from tactical_states import (  # noqa: E402
    ACTIVE_EXPLOITATION, DISCLOSED, POC_PUBLIC, POST_EXPLOIT_ACTIVITY,
    allowed_transitions, derive_state, is_forward,
)
import validate_transition_claims as vtc  # noqa: E402
import verify_tactical_forecasts as vtf  # noqa: E402

PASS, FAIL = [], []


def ok(name):
    PASS.append(name)


def ng(name, detail):
    FAIL.append((name, detail))


def base_candidate(**over):
    c = {
        "candidate_id": "tc-20260830-001",
        "issued_at_utc": "2026-08-30T00:00:00Z",
        "cutoff_at_utc": "2026-08-30T00:00:00Z",
        "forecast_family": "TF-1",
        "subject": {"type": "vulnerability", "id": "CVE-2026-99999"},
        "current_state_id": "state-x",
        "current_state": ACTIVE_EXPLOITATION,
        "state_confidence": "confirmed",
        "target_event": {
            "event_type": "TF1_POST_EXPLOIT_ACTIVITY_PUBLICATION",
            "next_state": POST_EXPLOIT_ACTIVITY,
            "window_start_utc": "2026-08-30T00:00:00Z",
            "window_end_utc": "2026-09-29T00:00:00Z",
            "verification_sources": ["vendor", "cert"],
            "matching_rule_version": "tf1-exploitation-v1",
            "visibility_model": "medium",
        },
        "probability_by_horizon": {"72h": 0.04, "7d": 0.07, "30d": 0.07},
        "reference_class": {},
        "model_version": "tf1-reference-only-v0",
        "observation_ids": [],
        "selection": {"status": "shadow", "reason_code": None, "reason": ""},
        "verified_outcome": None,
    }
    c.update(over)
    return c


def run_validator(candidates):
    errors, warnings = [], []
    actors = vtc.established_actors()
    for c in candidates:
        vtc.check_candidate(c, actors, True, errors, warnings)
    return errors, warnings


def main():
    # 1. 確率の決定論（同一入力から同じ確率が出る）
    out1 = subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "generate_tactical_candidates.py"),
         "--date", "2026-08-29", "--print-only"],
        capture_output=True, text=True).stdout
    out2 = subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "generate_tactical_candidates.py"),
         "--date", "2026-08-29", "--print-only"],
        capture_output=True, text=True).stdout
    if out1 == out2 and out1.strip():
        ok("同一入力から候補と確率が再現する（LLM が確率を書かない）")
    else:
        ng("同一入力から候補と確率が再現する", f"{out1[:200]}\n!=\n{out2[:200]}")

    # 2. placeholder transition を根拠に使うと拒否
    bad = base_candidate()
    bad["reference_class"] = {
        "72h": {"key": "forecaster/knowledge/technique-chains.json#transition_matrix"}
    }
    e, _ = run_validator([bad])
    (ok("placeholder transition を根拠に使うと拒否される") if e else
     ng("placeholder transition を根拠に使うと拒否される", "エラーが出なかった"))

    # 3. 許可されていない遷移は拒否
    bad = base_candidate()
    bad["target_event"]["next_state"] = "BROAD_CAMPAIGN"
    bad["target_event"]["event_type"] = "TF1_POST_EXPLOIT_ACTIVITY_PUBLICATION"
    e, _ = run_validator([bad])
    (ok("許可されていない遷移は拒否される") if e else
     ng("許可されていない遷移は拒否される", "エラーが出なかった"))

    # 4. 後退遷移は拒否
    bad = base_candidate(current_state=POST_EXPLOIT_ACTIVITY)
    bad["target_event"]["next_state"] = POC_PUBLIC
    e, _ = run_validator([bad])
    (ok("後退遷移は拒否される") if e else
     ng("後退遷移は拒否される", "エラーが出なかった"))

    # 5. actor 不明案件への actor 固有予報は拒否
    bad = base_candidate()
    bad["actor_group"] = "UNKNOWN_CLUSTER_X"
    e, _ = run_validator([bad])
    (ok("established でない actor への actor 固有予報は拒否される") if e else
     ng("established でない actor への actor 固有予報は拒否される", "エラーが出なかった"))

    # 6. current_state / visibility_model の必須
    for field, mut in (("current_state", {"current_state": None}),
                       ("visibility_model", None)):
        bad = base_candidate(**(mut or {}))
        if field == "visibility_model":
            bad["target_event"].pop("visibility_model")
        e, _ = run_validator([bad])
        (ok(f"{field} がないと拒否される") if e else
         ng(f"{field} がないと拒否される", "エラーが出なかった"))

    # 7. 全候補母集団が保存される
    path = os.path.join(REPO_ROOT, "forecaster", "candidates", "tactical", "2026-08-29.json")
    if os.path.exists(path):
        doc = json.load(open(path, encoding="utf-8"))
        cov = doc["_coverage"]
        total = cov["shadow"] + cov["abstained"] + cov["published"]
        (ok("棄権を含む全候補母集団が保存されている") if total == cov["candidates_total"]
         else ng("棄権を含む全候補母集団が保存されている",
                 f"{total} != {cov['candidates_total']}"))
        # 11. 確率の単調性
        bad_mono = [c["candidate_id"] for c in doc["candidates"]
                    if c.get("probability_by_horizon")
                    and not (c["probability_by_horizon"]["72h"]
                             <= c["probability_by_horizon"]["7d"]
                             <= c["probability_by_horizon"]["30d"])]
        (ok("確率が時間軸に対して単調（P72h<=P7d<=P30d）") if not bad_mono
         else ng("確率の単調性", f"違反: {bad_mono[:5]}"))
    else:
        ng("棄権を含む全候補母集団が保存されている", f"{path} がない")

    # 8. 状態導出が構造化フィールドだけに依存する
    o_kw = {"summary": "PoC が公開され実悪用が確認された", "exploitation_stage": None,
            "techniques": []}
    st, _ = derive_state(o_kw)
    (ok("本文キーワードから状態を推定しない") if st is None
     else ng("本文キーワードから状態を推定しない", f"state={st} が導出された"))
    o_struct = {"summary": "", "exploitation_stage": "poc_public", "techniques": []}
    st2, _ = derive_state(o_struct)
    (ok("構造化フィールドからは状態を導出する") if st2 == POC_PUBLIC
     else ng("構造化フィールドからは状態を導出する", f"state={st2}"))

    # 9/10. 採点値の集合と右打ち切り
    idx = {"CVE-2026-99999": []}
    from datetime import date
    verdicts = vtf.score(base_candidate(), idx, date(2026, 8, 30))
    allowed_verdicts = {"hit", "miss", "pending", "unobservable", "abstained"}
    (ok("採点値が二値＋pending/unobservable/abstained のみ（partial を作らない）")
     if set(verdicts.values()) <= allowed_verdicts
     else ng("採点値の集合", str(verdicts)))
    (ok("窓未満了を miss に数えない（右打ち切り）")
     if all(v == "pending" for v in verdicts.values())
     else ng("右打ち切り", str(verdicts)))

    for n in PASS:
        print(f"  [OK] {n}")
    for n, d in FAIL:
        print(f"  [NG] {n}: {d}")
    print(f"\n{len(PASS)} 件成功 / {len(FAIL)} 件失敗")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
