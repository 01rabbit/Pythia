#!/usr/bin/env python3
"""予報の時間整合を検査する（未来情報の混入と順序不明を落とす fail-closed ゲート）。

改善計画 Phase 0 / §11 の CI ゲートに対応する。

なぜ必要か:
  2026-08-29 の監査で、E1 的中6件すべてで KEV の `dateAdded` が予報日と同日であり、
  `dateAdded` は日付であって時刻ではないため「結果より前に予報を固定した」ことを
  データだけからは立証できなかった。さらにリポジトリ履歴は 2026-08-07 の単一コミット
  （741ファイル・779,211行）で一括インポートされており、2026-06〜08上旬の予報には
  同時性の証跡が存在しない。
  本スクリプトは、新規予報について同じ状況が二度と起きないようにするための門である。

検査項目（すべて [E]・1件でもあれば終了コード1 = 予報を公開しない）:
  1. v2.0 予報に issued_at_utc / cutoff_at_utc がある
  2. cutoff_at_utc <= issued_at_utc（発行後に取得した証拠を入力にできない）
  3. evidence_ids がすべて Evidence Ledger に実在する
  4. 参照証拠の retrieved_at_utc <= cutoff_at_utc（★未来情報の混入検査）
  5. target_event の検証窓が issued_at_utc 以降に始まる
  6. content_sha256 が予報本文の実ハッシュと一致する
  7. E1 予報の対象CVEが、発行時点のKEVスナップショットで未収載である
     （既に収載済みなら「初回追加」は起こりえず、的中しえない）

[W] 警告:
  - 結果の時刻精度が日付までしかなく、発行日と結果日が同日になる可能性がある構成

★既存履歴（_schema_version=1.0）は検査対象外とする。時刻証跡がそもそも存在せず、
  遡って作ることもできないため、violation にしても直せない（原則D・遡及修正禁止）。
  過去分の扱いは scripts/rescore_temporal_order.py の再集計ビューで別途示す。

使い方:
    python3 scripts/validate_temporal_integrity.py --date 2026-08-30
    python3 scripts/validate_temporal_integrity.py --all
"""

import argparse
import glob
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORECASTS_DIR = os.path.join(REPO_ROOT, "forecaster", "forecasts", "daily")
MANIFEST_GLOB = os.path.join(REPO_ROOT, "forecaster", "evidence", "manifests", "*", "*", "*.json")

JST = timezone(timedelta(hours=9))


def parse_utc(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def canonical_forecast_hash(forecast):
    """scripts/validate_forecasts.py と同一の計算（両者がずれると門が意味を失う）。"""
    payload = {k: v for k, v in forecast.items()
               if k not in ("content_sha256", "verified_outcome")}
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def load_evidence_index():
    """全 manifest を読み、{evidence_id: entry} を返す。"""
    index = {}
    for path in sorted(glob.glob(MANIFEST_GLOB)):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for ev in doc.get("evidence", []):
            if ev.get("evidence_id"):
                index[ev["evidence_id"]] = ev
    return index


def load_kev_from_evidence(ev):
    """証拠のスナップショットから KEV の cveID→dateAdded を復元する。"""
    import gzip

    rel = ev.get("snapshot_path")
    if not rel:
        return None
    abs_path = os.path.join(REPO_ROOT, rel)
    if not os.path.exists(abs_path):
        return None
    with gzip.open(abs_path, "rb") as f:
        blob = f.read()
    if hashlib.sha256(blob).hexdigest() != ev.get("content_sha256"):
        return None
    catalog = json.loads(blob.decode("utf-8"))
    return {v["cveID"]: v["dateAdded"] for v in catalog.get("vulnerabilities", [])}


def check_forecast(fc, fname, evidence, errors, warnings):
    fid = fc.get("forecast_id", "-")

    issued = parse_utc(fc.get("issued_at_utc"))
    cutoff = parse_utc(fc.get("cutoff_at_utc"))
    if issued is None:
        errors.append(f"{fname}:{fid}: issued_at_utc が無い/解釈できない")
    if cutoff is None:
        errors.append(f"{fname}:{fid}: cutoff_at_utc が無い/解釈できない")
    if issued and cutoff and cutoff > issued:
        errors.append(
            f"{fname}:{fid}: cutoff_at_utc が issued_at_utc より後 "
            f"（{cutoff.isoformat()} > {issued.isoformat()}）。"
            "発行後に取得した証拠を入力にできてしまう"
        )

    # content_sha256
    digest = fc.get("content_sha256")
    if digest:
        actual = canonical_forecast_hash(fc)
        if actual != digest:
            errors.append(
                f"{fname}:{fid}: content_sha256 が本文と一致しない"
                f"（記録={digest[:12]}… 実体={actual[:12]}…）"
            )

    # evidence_ids の実在と時刻
    kev_snapshot_map = None
    for eid in fc.get("evidence_ids") or []:
        ev = evidence.get(eid)
        if ev is None:
            errors.append(f"{fname}:{fid}: evidence_id が Evidence Ledger に存在しない: {eid}")
            continue
        got = parse_utc(ev.get("retrieved_at_utc"))
        if got is None:
            errors.append(f"{fname}:{fid}: {eid} の retrieved_at_utc が解釈できない")
            continue
        if cutoff and got > cutoff:
            errors.append(
                f"{fname}:{fid}: ★未来情報の混入 — {eid} の取得時刻 {got.isoformat()} が "
                f"cutoff_at_utc {cutoff.isoformat()} より後"
            )
        if ev.get("source_type") == "cisa_kev" and kev_snapshot_map is None:
            kev_snapshot_map = load_kev_from_evidence(ev)

    # target_event の窓
    te = fc.get("target_event") or {}
    start = parse_utc(te.get("window_start_utc"))
    end = parse_utc(te.get("window_end_utc"))
    if start and issued and start < issued:
        errors.append(
            f"{fname}:{fid}: 検証窓が発行時刻より前に始まっている"
            f"（{start.isoformat()} < {issued.isoformat()}）"
        )
    if start and end and end <= start:
        errors.append(f"{fname}:{fid}: 検証窓の終端が始端以前")

    # E1: 発行時点で既に KEV 収載なら「初回追加」は起こりえない
    if te.get("event_type") == "cisa_kev_initial_add":
        entity = te.get("entity_id")
        if kev_snapshot_map is None:
            errors.append(
                f"{fname}:{fid}: E1 予報だが、発行時点の KEV スナップショットを"
                "参照する証拠（source_type=cisa_kev）が evidence_ids に無い。"
                "『発行時点で未収載だった』ことを後から再検証できない"
            )
        elif entity in kev_snapshot_map:
            errors.append(
                f"{fname}:{fid}: ★E1 対象 {entity} は発行時点の KEV スナップショットに"
                f"既に収載されている（dateAdded={kev_snapshot_map[entity]}）。"
                "初回追加は起こりえず的中しえない"
            )

    # 結果の時刻精度に由来する順序不明の可能性
    if te.get("event_type") == "cisa_kev_initial_add" and issued and start:
        # KEV dateAdded は日付（米国東部）であり時刻を持たない。窓の始端が
        # 発行と同じ米東部日に入る場合、結果が発行前だったか後だったかを
        # 日付だけでは決められない。
        et_day_issued = (issued - timedelta(hours=4)).date()
        et_day_start = (start - timedelta(hours=4)).date()
        if et_day_issued == et_day_start:
            warnings.append(
                f"{fname}:{fid}: 検証窓の始端が発行と同じ米国東部日（{et_day_start}）にある。"
                "KEV の dateAdded は日付までしか無いため、この日に追加された場合は"
                "順序不明（temporal_order_unknown）として厳格的中の分子に入らない"
            )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", help="対象日 YYYY-MM-DD（既定: JST の本日）")
    ap.add_argument("--all", action="store_true", help="全予報ファイルを検査する")
    args = ap.parse_args()

    if args.all:
        paths = sorted(glob.glob(os.path.join(FORECASTS_DIR, "*.json")))
    else:
        target = args.date or datetime.now(JST).date().isoformat()
        p = os.path.join(FORECASTS_DIR, f"{target}.json")
        if not os.path.exists(p):
            print(f"[skip] 予報ファイルが存在しない: {p}")
            return 0
        paths = [p]

    evidence = load_evidence_index()
    errors, warnings = [], []
    checked = 0

    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{os.path.basename(path)}: 読み取り失敗: {exc}")
            continue
        # v1.0（既存履歴）は時刻証跡を持ちえないため検査対象外
        if data.get("_schema_version") != "2.0":
            continue
        for fc in data.get("forecasts", []):
            checked += 1
            check_forecast(fc, os.path.basename(path), evidence, errors, warnings)

    for m in errors:
        print(f"  [E] {m}")
    for m in warnings:
        print(f"  [W] {m}")
    print(
        f"\n検査 v2.0 予報 {checked} 件 / 証拠台帳 {len(evidence)} 件 "
        f"/ エラー {len(errors)} 件 / 警告 {len(warnings)} 件"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
