#!/usr/bin/env python3
"""根拠のない遷移主張・帰属を拒否する fail-closed ゲート（設計 §10 / §13 / §14）。

設計 §14 の受入基準のうち次を機械的に守る:
  - placeholder transition を使うと CI が失敗する
  - 同一記事内の Technique 順を時間遷移に使わない
  - actor 不明案件へ actor 固有予報を出さない
  - 許可 transition にない状態遷移を本番発行しない

検査項目（[E] は1件でもあれば終了コード1）:
  1. [E] 候補の (current_state → next_state) が tactical_states.TRANSITIONS にある
  2. [E] 前進遷移である（後退・自己ループを予報にしない）
  3. [E] technique-chains.json の transition_matrix を根拠に使っていない
        （同ファイルの matrix_evidence_basis は placeholder / 初期推定であり、
          cited / observed へ昇格するまで予報根拠に使えない）
  4. [E] actor 固有の予報が、baseline で established でない actor に出ていない
  5. [E] 候補に visibility_model と current_state がある（第1段階の完了条件）
  6. [W] state_confidence=uncertain の候補が shadow に残っている

★なぜ placeholder を拒否するか:
  forecaster/knowledge/technique-chains.json の遷移確率は明示的に初期推定値であり、
  「0.60 ゲート」で次段階 Technique 予測の根拠に使われうる形になっている。
  根拠のない数値を確率として再生産することを防ぐため、v2 ではこの行列を
  candidate generator の参考にも使わない（設計 §6.1）。

使い方:
    python3 scripts/validate_transition_claims.py --date 2026-08-29
    python3 scripts/validate_transition_claims.py --all
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tactical_states import (  # noqa: E402
    HORIZONS_DAYS, HORIZON_LABELS, VISIBILITY_CLASSES, allowed_transitions, is_forward,
    reference_key,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAND_DIR = os.path.join(REPO_ROOT, "forecaster", "candidates", "tactical")
CHAINS_PATH = os.path.join(REPO_ROOT, "forecaster", "knowledge", "technique-chains.json")
GROUP_BASELINE = os.path.join(REPO_ROOT, "forecaster", "baseline", "group-activity.json")
JST = timezone(timedelta(hours=9))

# 予報根拠として引用してはならないファイル/キー（placeholder 由来）
FORBIDDEN_BASIS = [
    ("forecaster/knowledge/technique-chains.json", "transition_matrix"),
]


def established_actors():
    """baseline で established の actor 集合を返す（actor 固有予報を許す唯一の根拠）。"""
    if not os.path.exists(GROUP_BASELINE):
        return set()
    with open(GROUP_BASELINE, encoding="utf-8") as f:
        doc = json.load(f)
    out = set()
    for section in ("groups", "parent_rollups"):
        for name, v in (doc.get(section) or {}).items():
            if name.startswith("_"):
                continue
            if isinstance(v, dict) and v.get("baseline_status") == "established":
                out.add(name)
    return out


def chains_are_placeholder():
    """technique-chains.json が placeholder 段階かを判定する。"""
    if not os.path.exists(CHAINS_PATH):
        return False
    with open(CHAINS_PATH, encoding="utf-8") as f:
        blob = f.read()
    doc = json.loads(blob)
    basis = json.dumps(doc.get("matrix_evidence_basis", {}), ensure_ascii=False)
    return ("placeholder" in basis) or ("初期推定" in basis) or ("placeholder" in blob[:4000])


def check_candidate(c, actors, placeholder, errors, warnings):
    cid = c.get("candidate_id", "-")
    sel = c.get("selection") or {}
    te = c.get("target_event") or {}

    if not c.get("current_state"):
        errors.append(f"{cid}: current_state がない（第1段階の完了条件）")

    if sel.get("status") == "abstained":
        return  # 棄権候補は遷移主張をしていないので以降の検査対象外

    if not te.get("visibility_model"):
        errors.append(f"{cid}: visibility_model がない（設計 §9.3・第1段階の完了条件）")
    elif te["visibility_model"] not in VISIBILITY_CLASSES:
        errors.append(f"{cid}: visibility_model が不正: {te['visibility_model']!r}")

    cur, nxt = c.get("current_state"), te.get("next_state")
    if cur and nxt:
        allowed = {(et, ns) for et, ns, _v in allowed_transitions(cur)}
        if (te.get("event_type"), nxt) not in allowed:
            errors.append(
                f"{cid}: 許可されていない遷移 {cur} → {nxt}"
                f"（event_type={te.get('event_type')}）。"
                "tactical_states.TRANSITIONS にない遷移を予報にしてはならない"
            )
        if not is_forward(cur, nxt):
            errors.append(f"{cid}: 前進遷移ではない {cur} → {nxt}")

    for path, key in FORBIDDEN_BASIS:
        blob = json.dumps(c, ensure_ascii=False)
        if path in blob and key in blob and placeholder:
            errors.append(
                f"{cid}: placeholder 段階の {path}#{key} を根拠に使っている。"
                "cited / observed へ昇格するまで予報根拠に使えない（設計 §6.1）"
            )

    actor = (c.get("subject") or {}).get("actor") or c.get("actor_group")
    if actor and actor not in actors:
        errors.append(
            f"{cid}: actor 固有の予報だが {actor!r} は baseline で established ではない。"
            "actor 固有係数・actor 固有予報は禁止し上位クラスへプーリングする（設計 §13）"
        )

    if c.get("state_confidence") == "uncertain" and sel.get("status") == "shadow":
        warnings.append(f"{cid}: state_confidence=uncertain のまま shadow に残っている")

    if c.get("model_version") == "tf1-reference-only-v1":
        required = ("alternative_coas", "counterevidence", "falsifiers",
                    "early_warning_signals", "defensive_implication", "content_sha256")
        for field in required:
            if field not in c:
                errors.append(f"{cid}: v1契約の必須field {field} がない")
        if te.get("matching_rule_version") not in {"tf1-poc-v2", "tf1-exploitation-v2"}:
            errors.append(f"{cid}: v1候補のmatching ruleが未固定または旧版")
        if cur and nxt:
            for horizon in HORIZONS_DAYS:
                row = (c.get("reference_class") or {}).get(HORIZON_LABELS[horizon]) or {}
                expected = reference_key(cur, te.get("event_type"), nxt, horizon)
                if row.get("key") != expected:
                    errors.append(
                        f"{cid}: {HORIZON_LABELS[horizon]} の参照率がtarget event固有でない")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", help="対象日 YYYY-MM-DD")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    if args.all:
        paths = sorted(glob.glob(os.path.join(CAND_DIR, "*.json")))
    else:
        target = args.date or datetime.now(JST).date().isoformat()
        p = os.path.join(CAND_DIR, f"{target}.json")
        if not os.path.exists(p):
            print(f"[skip] 候補ファイルがない: {p}")
            return 0
        paths = [p]

    actors = established_actors()
    placeholder = chains_are_placeholder()
    errors, warnings, n = [], [], 0

    for path in paths:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        for c in doc.get("candidates", []):
            n += 1
            check_candidate(c, actors, placeholder, errors, warnings)

    for m in errors:
        print(f"  [E] {m}")
    for m in warnings:
        print(f"  [W] {m}")
    print(f"\n候補 {n} 件 / エラー {len(errors)} 件 / 警告 {len(warnings)} 件")
    print(f"  established actor: {sorted(actors) or 'なし'}")
    print(f"  technique-chains.json は placeholder 段階か: {placeholder}"
          "（True の間、遷移行列を予報根拠に使うと拒否する）")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
