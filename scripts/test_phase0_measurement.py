#!/usr/bin/env python3
"""Phase 0（測定固定）の受入基準を機械的に検査する（改善計画 §14）。

依存は Python 3 標準ライブラリのみ。ネットワークへは出ない。
一時ディレクトリに正例・負例のフィクスチャを作り、各ゲートが期待どおり
通る／落ちることを確認する。

検査する受入基準:
  1. 正例の v2.0 予報がバリデータを通る
  2. 発行後に取得した証拠を混ぜると必ず失敗する（未来情報の混入）
  3. cutoff_at_utc が issued_at_utc より後だと失敗する
  4. 予報本文を書き換えると content_sha256 不一致で失敗する
  5. 既に KEV 収載済みの CVE を E1 対象にすると失敗する
  6. 検証窓が発行時刻より前に始まると失敗する
  7. evidence_ids が Evidence Ledger に無いと失敗する
  8. v1.0 のファイルに v2 専用フィールドを混ぜると失敗する
  9. 2026-08-30 以降の発行日で _schema_version=1.0 だと失敗する
 10. 同一入力から content_sha256 が再現する（決定論）
 11. 既存の検証記録・予報ファイルが本スクリプトで変更されない

使い方:
    python3 scripts/test_phase0_measurement.py
"""

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO_ROOT, "scripts")

PASS, FAIL = [], []


def canonical_hash(fc):
    payload = {k: v for k, v in fc.items() if k not in ("content_sha256", "verified_outcome")}
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def base_forecast():
    fc = {
        "forecast_id": "fc-20260830-1",
        "forecast_index": 1,
        "subject": "テスト用予報",
        "tier": "T1",
        "confidence": "low",
        "forecast_class": "fast_72h",
        "outcome_channel": "E1",
        "window": "fast_72h",
        "deadline_date": "2026-09-02",
        "hit_criteria": "CISA が CVE-2026-99999 を KEV へ初回追加（表示用）",
        "exclusions": "再登録は非的中",
        "related_observation_ids": [],
        "issued_at_utc": "2026-08-29T22:00:00Z",
        "cutoff_at_utc": "2026-08-29T21:55:00Z",
        "model_version": "test-v1",
        "forecast_probability": 0.3,
        "reference_base_rate": 0.0003,
        "evidence_ids": ["ev-20260829-aaaaa"],
        "target_event": {
            "channel": "E1",
            "entity_id": "CVE-2026-99999",
            "event_type": "cisa_kev_initial_add",
            "window_start_utc": "2026-08-29T22:00:00Z",
            "window_end_utc": "2026-09-01T22:00:00Z",
            "primary_source": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "matching_rule_version": "e1-initial-add-v2",
        },
    }
    fc["content_sha256"] = canonical_hash(fc)
    return fc


def write_case(root, forecast, schema_version="2.0", date="2026-08-30",
               kev_cves=("CVE-2026-00001",), retrieved="2026-08-29T21:50:00Z"):
    """一時リポジトリに予報ファイルと Evidence Ledger を書く。"""
    fdir = os.path.join(root, "forecaster", "forecasts", "daily")
    mdir = os.path.join(root, "forecaster", "evidence", "manifests", "2026", "08")
    sdir = os.path.join(root, "forecaster", "evidence", "snapshots", "kev", "2026", "08")
    for d in (fdir, mdir, sdir):
        os.makedirs(d, exist_ok=True)

    catalog = {
        "catalogVersion": "test",
        "dateReleased": "2026-08-29T17:00:00.000Z",
        "count": len(kev_cves),
        "vulnerabilities": [{"cveID": c, "dateAdded": "2026-08-01"} for c in kev_cves],
    }
    blob = json.dumps(catalog, ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(blob).hexdigest()
    with gzip.open(os.path.join(sdir, f"{digest}.json.gz"), "wb") as f:
        f.write(blob)

    ev_id = forecast.get("evidence_ids", ["ev-20260829-aaaaa"])[0]
    manifest = {
        "_schema_version": "1.0",
        "_evidence_date": "2026-08-29",
        "_generated_at_utc": "2026-08-29T22:00:00Z",
        "_generator": "test",
        "evidence": [{
            "evidence_id": ev_id,
            "source_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "source_type": "cisa_kev",
            "published_at_utc": "2026-08-29T17:00:00.000Z",
            "retrieved_at_utc": retrieved,
            "content_sha256": digest,
            "http_etag": None,
            "http_last_modified": None,
            "snapshot_path": os.path.join(
                "forecaster", "evidence", "snapshots", "kev", "2026", "08", f"{digest}.json.gz"),
            "extract": {"catalog_version": "test"},
            "parser_version": "kev-extract-v1",
        }],
    }
    with open(os.path.join(mdir, "2026-08-29.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    doc = {"_schema_version": schema_version, "_forecast_date": date,
           "forecasts": [forecast]}
    with open(os.path.join(fdir, f"{date}.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return date


def run(script, root, *args):
    """一時リポジトリを対象にスクリプトを実行し (rc, out) を返す。"""
    dst = os.path.join(root, "scripts")
    os.makedirs(dst, exist_ok=True)
    for name in ("validate_forecasts.py", "validate_temporal_integrity.py"):
        shutil.copy(os.path.join(SCRIPTS, name), os.path.join(dst, name))
    p = subprocess.run([sys.executable, os.path.join(dst, script), *args],
                       capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr)


def case(name, expect_pass, mutate=None, **kw):
    with tempfile.TemporaryDirectory() as root:
        fc = base_forecast()
        if mutate:
            fc = mutate(fc)
        date = write_case(root, fc, **kw)
        rc1, out1 = run("validate_forecasts.py", root, "--date", date)
        rc2, out2 = run("validate_temporal_integrity.py", root, "--date", date)
        ok = (rc1 == 0 and rc2 == 0)
        if ok == expect_pass:
            PASS.append(name)
        else:
            FAIL.append((name, f"期待={'通過' if expect_pass else '失敗'} "
                               f"実際 validate_forecasts={rc1} temporal={rc2}\n{out1}\n{out2}"))


def rehash(fc):
    fc["content_sha256"] = canonical_hash(fc)
    return fc


def main():
    # 1. 正例
    case("正例の v2.0 予報が通る", True)

    # 2. 未来情報の混入（証拠の取得が cutoff より後）
    case("発行後に取得した証拠は拒否される", False,
         retrieved="2026-08-29T23:30:00Z")

    # 3. cutoff > issued
    def m_cutoff(fc):
        fc["cutoff_at_utc"] = "2026-08-29T23:00:00Z"
        return rehash(fc)
    case("cutoff_at_utc が issued_at_utc より後だと拒否される", False, m_cutoff)

    # 4. 本文改ざん（ハッシュを更新しない）
    def m_tamper(fc):
        fc["subject"] = "発行後に書き換えた本文"
        return fc  # あえて rehash しない
    case("発行後の本文改ざんは content_sha256 不一致で拒否される", False, m_tamper)

    # 5. 既に KEV 収載済みの CVE を E1 対象にする
    case("既に KEV 収載済みの CVE は E1 対象にできない", False,
         kev_cves=("CVE-2026-99999",))

    # 6. 窓が発行より前に始まる
    def m_window(fc):
        fc["target_event"]["window_start_utc"] = "2026-08-29T12:00:00Z"
        return rehash(fc)
    case("検証窓が発行時刻より前に始まると拒否される", False, m_window)

    # 7. 存在しない evidence_id
    def m_evid(fc):
        fc["evidence_ids"] = ["ev-20260829-zzzzz"]
        return rehash(fc)
    case("Evidence Ledger に無い evidence_id は拒否される", False, m_evid)

    # 8. v1.0 に v2 専用フィールドを混ぜる
    def m_mix(fc):
        fc["base_rate_estimate"] = 0.3
        return rehash(fc)
    case("v1.0 に v2 専用フィールドを混ぜると拒否される", False, m_mix,
         schema_version="1.0", date="2026-08-29")

    # 9. 2026-08-30 以降で v1.0
    def m_v1(fc):
        for k in ("issued_at_utc", "cutoff_at_utc", "content_sha256", "target_event",
                  "forecast_probability", "reference_base_rate", "model_version",
                  "evidence_ids"):
            fc.pop(k, None)
        fc["base_rate_estimate"] = 0.3
        return fc
    case("2026-08-30 以降の発行日で v1.0 だと拒否される", False, m_v1,
         schema_version="1.0")

    # 10. ハッシュの決定論
    a, b = canonical_hash(base_forecast()), canonical_hash(base_forecast())
    (PASS if a == b else FAIL).append(
        "同一入力から content_sha256 が再現する" if a == b
        else ("content_sha256 の決定論", f"{a} != {b}"))

    # 11. 既存履歴が変更されていない
    status_lines = subprocess.run(
        ["git", "-C", REPO_ROOT, "status", "--porcelain",
         "forecaster/verification", "forecaster/forecasts"],
        capture_output=True, text=True).stdout.splitlines()
    # tactical/ は新v3の名前空間。既存の制度予報検証記録を不変に保つ契約とは分離する。
    dirty = "\n".join(
        line for line in status_lines
        if not line.startswith("?? forecaster/verification/tactical/")
    ).strip()
    if dirty:
        FAIL.append(("既存の検証記録・予報が変更されていない", dirty))
    else:
        PASS.append("既存の検証記録・予報が変更されていない")

    for n in PASS:
        print(f"  [OK] {n}")
    for n, d in FAIL:
        print(f"  [NG] {n}\n{d}")
    print(f"\n{len(PASS)} 件成功 / {len(FAIL)} 件失敗")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
