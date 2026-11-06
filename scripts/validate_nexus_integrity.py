#!/usr/bin/env python3
"""NX-1 の候補台帳とモデル登録簿を fail-closed で検証する（読み取り専用）。

検査項目（エラー = コミットしてはならない）:
  [E] 台帳ハッシュ（_ledger_sha256）と候補ハッシュ（content_sha256）の一致
  [E] 時刻: cutoff ≤ issued、候補日 = ファイル名 = 発行時刻の JST 日付、未来に発行していない
  [E] 構造: family・matching rule・事象型・主体・確率の範囲・棄権の整合・verified_outcome は null
  [E] 予報の根拠の分離: inputs.sources は観測だけ、inputs.context_inputs は空
      （Section 5・6 を予報へ入れていない。取り込みは nexus-context-preregistration.json の手続きのみ）
  [E] shadow の間は公開しない（status は shadow / abstained だけ）
  [E] 再計算（--date）: 観測を cutoff 時点で読み直して同じ候補が再現できる
      （確率は LLM でなくコードが観測から計算する。式を後から書き換えていない）
  [W] 再計算（--all --recompute）: 履歴の観測は欠測日の補完などで正当に変わりうるため、不一致は警告
  [E] 登録簿: 昇格は承認記録と、検証出力の全ゲート通過を要する。context_inputs_allowed は空
  [W] --all で再計算を省略した

★発行済みの台帳の改ざんは、PR の差分で『既存台帳の変更・削除を拒否する』CI（追記専用）が防ぐ。

使い方:
  python3 scripts/validate_nexus_integrity.py --date 2026-11-07
  python3 scripts/validate_nexus_integrity.py --all [--recompute]

★書き込みはしない。forecaster/knowledge/ には触れない（行動原則5）。
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nexus_family as nf  # noqa: E402
import generate_nexus_candidates as gen  # noqa: E402
from tactical_integrity import hash_without  # noqa: E402
from tactical_time import parse_utc  # noqa: E402

ROOT = nf.ROOT
LABELS = tuple(nf.HORIZON_LABELS[h] for h in nf.HORIZONS_DAYS)
ALLOWED_STATUS_SHADOW = {"shadow", "abstained"}
REGISTRY_REL = os.path.join("forecaster", "models", "nexus-registry.json")
CANDIDATE_ID_RE = re.compile(r"^nx-(\d{8})-([A-Z]{2})$")


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def check_candidate(c, doc, day, registry_mode, tag):
    errors = []

    def err(msg):
        errors.append(f"{tag}: {msg}")

    expected_id = f"nx-{day.replace('-', '')}-{nf.NEXUS_COUNTRY.get((c.get('subject') or {}).get('id'), '??')}"
    m = CANDIDATE_ID_RE.match(c.get("candidate_id") or "")
    if not m or c.get("candidate_id") != expected_id:
        err(f"candidate_id は {expected_id} 形式")
    if hash_without(c, "content_sha256") != c.get("content_sha256"):
        err("content_sha256 が内容と一致しない（発行後に書き換えられた）")
    try:
        if parse_utc(c.get("cutoff_at_utc")) != parse_utc(doc.get("_cutoff_at_utc")):
            err("cutoff_at_utc が台帳と一致しない")
        if parse_utc(c.get("issued_at_utc")) != parse_utc(doc.get("_issued_at_utc")):
            err("issued_at_utc が台帳と一致しない")
    except ValueError as exc:
        err(f"時刻が不正: {exc}")
    if c.get("forecast_family") != nf.FAMILY:
        err(f"forecast_family は {nf.FAMILY}")
    subject = c.get("subject") or {}
    if subject.get("type") != "country_nexus" or subject.get("id") not in nf.NEXUS_COUNTRY:
        err(f"subject が不正: {subject}")
    elif subject.get("country") != nf.NEXUS_COUNTRY[subject["id"]]:
        err("subject.country が nexus と対応しない")
    te = c.get("target_event") or {}
    if te.get("event_type") != nf.EVENT_TYPE or te.get("matching_rule_version") != nf.MATCHING_RULE_VERSION:
        err("target_event の event_type / matching_rule_version が固定値と異なる")
    if te.get("signal") != subject.get("id"):
        err("target_event.signal が subject.id と一致しない")
    if c.get("model_version") != nf.PRIMARY_MODEL or c.get("primary_model") != nf.PRIMARY_MODEL:
        err(f"model_version / primary_model は {nf.PRIMARY_MODEL}")
    models = c.get("models") or {}
    if set(models) != set(nf.MODELS):
        err(f"models は {sorted(nf.MODELS)} をすべて持つ")
    primary = (models.get(nf.PRIMARY_MODEL) or {}).get("probability_by_horizon")
    if c.get("probability_by_horizon") != primary:
        err("probability_by_horizon が primary モデルの確率と一致しない")
    all_null = True
    for model_name, body in models.items():
        probs = (body or {}).get("probability_by_horizon") or {}
        if set(probs) != set(LABELS):
            err(f"{model_name}: 地平は {LABELS} をすべて持つ")
        for label, p in probs.items():
            if p is None:
                continue
            all_null = False
            if not isinstance(p, (int, float)) or isinstance(p, bool) or not (0 < p < 1):
                err(f"{model_name}.{label}: 確率は (0,1) の数値または null（実際: {p!r}）")
    status = (c.get("selection") or {}).get("status")
    if registry_mode == "shadow" and status not in ALLOWED_STATUS_SHADOW:
        err(f"shadow の間は status を {sorted(ALLOWED_STATUS_SHADOW)} に限る（実際: {status!r}）。公開しない")
    if status == "abstained":
        if not all_null:
            err("棄権なのに確率がある")
        if not (c.get("selection") or {}).get("reason_code"):
            err("棄権は reason_code が必要")
    elif status == "shadow" and all_null:
        err("shadow なのに全地平の確率が null（棄権にすべき）")
    nulls = sorted(l for l, p in (primary or {}).items() if p is None)
    if sorted(c.get("abstained_horizons") or []) != nulls:
        err("abstained_horizons が確率 null の地平と一致しない")
    inputs = c.get("inputs") or {}
    if inputs.get("sources") != ["forecaster/observations"]:
        err("inputs.sources は ['forecaster/observations'] だけ（観測以外を予報の根拠にしない）")
    if inputs.get("context_inputs") != []:
        err("inputs.context_inputs は空（Section 5・6 を予報へ入れない）")
    if c.get("verified_outcome") is not None:
        err("verified_outcome は検証ステージだけが書く（発行時は null）")
    return errors


def check_ledger(path, doc, registry_mode, data=None, recompute=False, now=None, strict_recompute=True):
    """台帳 1 件を検査する。

    strict_recompute=True（発行当日の --date）では、再計算の不一致はエラー。False（--all の履歴）では
    警告にする。履歴の観測は、欠測日のファイルが後から補われる等で正当に変わりうるため、再計算の
    不一致をコミットの拒否理由にしない。台帳の改ざん（ハッシュの付け直しを含む）は、発行済みの台帳を
    PR で変更しないこと（追記専用）を CI が差分で検査して防ぐ。
    """
    rel = os.path.relpath(path, ROOT) if path.startswith(ROOT) else path
    errors, warnings = [], []
    day = doc.get("_candidate_date")
    if hash_without(doc, "_ledger_sha256") != doc.get("_ledger_sha256"):
        errors.append(f"{rel}: _ledger_sha256 が内容と一致しない（発行後に書き換えられた）")
    if doc.get("_schema_version") != "1.0":
        errors.append(f"{rel}: _schema_version は '1.0'")
    if doc.get("_mode") != registry_mode:
        errors.append(f"{rel}: _mode={doc.get('_mode')!r} が登録簿の mode {registry_mode!r} と一致しない")
    if doc.get("_matching_rule_version") != nf.MATCHING_RULE_VERSION:
        errors.append(f"{rel}: _matching_rule_version が固定値と異なる")
    try:
        cutoff, issued = parse_utc(doc.get("_cutoff_at_utc")), parse_utc(doc.get("_issued_at_utc"))
    except ValueError as exc:
        return errors + [f"{rel}: 時刻が不正: {exc}"], warnings
    if issued < cutoff:
        errors.append(f"{rel}: issued_at が cutoff より前")
    if now is not None and issued > now + timedelta(minutes=5):
        errors.append(f"{rel}: 未来の時刻で発行している")
    if day != os.path.basename(path)[:10] or day != issued.astimezone(nf.JST).date().isoformat():
        errors.append(f"{rel}: _candidate_date・ファイル名・発行時刻の JST 日付が一致しない")
    ids = set()
    for i, c in enumerate(doc.get("candidates") or []):
        tag = f"{rel}:candidates[{i}]({c.get('candidate_id')})"
        if c.get("candidate_id") in ids:
            errors.append(f"{tag}: candidate_id が重複している")
        ids.add(c.get("candidate_id"))
        errors.extend(check_candidate(c, doc, day, registry_mode, tag))
        if recompute and data is not None and (c.get("subject") or {}).get("id") in nf.NEXUS_COUNTRY:
            rebuilt = gen.build_candidate(day, c["subject"]["id"], data, cutoff, issued)
            if rebuilt["content_sha256"] != c.get("content_sha256"):
                diff = [k for k in ("probability_by_horizon", "models", "inputs", "selection")
                        if rebuilt.get(k) != c.get(k)]
                message = (f"{tag}: 観測を cutoff 時点で読み直しても同じ候補が再現できない（差分: {diff}）。"
                           "確率は観測からコードが計算する。観測や式を後から書き換えていない必要がある")
                if strict_recompute:
                    errors.append(message)
                else:
                    warnings.append("[履歴の変化] " + message)
    return errors, warnings


def check_registry(registry, root):
    errors = []
    if registry.get("forecast_family") != nf.FAMILY:
        errors.append(f"{REGISTRY_REL}: forecast_family は {nf.FAMILY}")
    mode = registry.get("mode")
    if mode not in registry.get("allowed_modes", []):
        errors.append(f"{REGISTRY_REL}: mode={mode!r} は allowed_modes に無い")
    if registry.get("context_inputs_allowed") != []:
        errors.append(f"{REGISTRY_REL}: context_inputs_allowed は空（Section 5・6 の取り込みは"
                      "事前登録の手続きと検証器の変更を伴う別 PR で行う）")
    versions = [m.get("model_version") for m in registry.get("models", [])]
    if sorted(versions) != sorted(nf.MODELS):
        errors.append(f"{REGISTRY_REL}: models は {sorted(nf.MODELS)} をすべて持つ（実際: {sorted(versions)}）")
    approved = [m for m in registry.get("models", []) if m.get("approved_for_publication")]
    if mode == "shadow" and approved:
        errors.append(f"{REGISTRY_REL}: mode=shadow なのに approved_for_publication のモデルがある")
    if mode in ("limited", "active") and not approved:
        errors.append(f"{REGISTRY_REL}: mode={mode} なのに承認済みのモデルが無い")
    for m in approved:
        name = m.get("model_version")
        if not m.get("public_forecast_eligible"):
            errors.append(f"{name}: public_forecast_eligible=false のモデルは公開昇格できない")
        approval = m.get("approval") or {}
        if not (approval.get("approved_by") and approval.get("approved_at_utc") and approval.get("verification_file")):
            errors.append(f"{name}: approval（approved_by / approved_at_utc / verification_file）が必要")
            continue
        vf = os.path.join(root, approval["verification_file"])
        if not os.path.isfile(vf):
            errors.append(f"{name}: 承認の根拠 {approval['verification_file']} が存在しない")
            continue
        models = (_load(vf).get("models") or {}).get(name) or {}
        for label in LABELS:
            if not (models.get(label) or {}).get("gates_pass"):
                errors.append(f"{name}:{label}: 検証出力で昇格ゲートを通過していない")
    return errors


def run(root=ROOT, date=None, recompute=False, now=None):
    errors, warnings = [], []
    reg_path = os.path.join(root, REGISTRY_REL)
    if not os.path.isfile(reg_path):
        return [f"{REGISTRY_REL} が無い"], warnings
    registry = _load(reg_path)
    errors.extend(check_registry(registry, root))
    mode = registry.get("mode")
    paths = sorted(glob.glob(os.path.join(root, "forecaster", "candidates", "nexus", "*.json")))
    if date:
        paths = [p for p in paths if os.path.basename(p) == f"{date}.json"]
        if not paths:
            errors.append(f"forecaster/candidates/nexus/{date}.json が無い（Step 3.7 未実施）")
    do_recompute = recompute or bool(date)
    data = nf.load_data(root) if do_recompute else None
    for path in paths:
        # 発行当日（--date）は厳格。全履歴の再計算は、観測が後から正当に変わりうるため警告にとどめる
        e, w = check_ledger(path, _load(path), mode, data, do_recompute, now, strict_recompute=bool(date))
        errors.extend(e)
        warnings.extend(w)
    if not do_recompute and paths:
        warnings.append("再計算を省略した（--recompute で観測から候補を再現して照合する）")
    return errors, warnings


def main():
    parser = argparse.ArgumentParser(description="NX-1 の台帳と登録簿を検証する（読み取り専用）")
    parser.add_argument("--date", help="検査する候補日 YYYY-MM-DD（再計算も行う）")
    parser.add_argument("--all", action="store_true", help="全台帳を検査する")
    parser.add_argument("--recompute", action="store_true", help="全台帳でも観測から再計算して照合する")
    parser.add_argument("--root", default=ROOT)
    args = parser.parse_args()
    if not (args.date or args.all):
        parser.error("--date か --all が必要")
    errors, warnings = run(args.root, args.date, args.recompute, datetime.now(timezone.utc))
    for w in warnings:
        print(f"  [W] {w}")
    for e in errors:
        print(f"  [E] {e}")
    n = len(glob.glob(os.path.join(args.root, "forecaster", "candidates", "nexus", "*.json")))
    print(f"NX-1 integrity: ledgers={n} errors={len(errors)} warnings={len(warnings)}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
