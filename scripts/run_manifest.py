#!/usr/bin/env python3
"""日次実行の各ステップを run-manifest へ記録する（改善計画 §10）。

Phase 0 の完了条件は「新規予報1日分で、入力からコミットまでの時系列を第三者が
再現できる」ことである。個々の成果物に時刻とハッシュが付いていても、それらが
**どの順序でどれだけの時間をかけて作られたか**が残っていなければ、
「結果を見てから予報を作ったのではない」ことを第三者が追跡できない。
run-manifest はその時系列そのものを残す。

出力:
  outputs/YYYY-MM-DD/YYYY-MM-DD-run-manifest.json

ライブラリとして使う:
    from run_manifest import step
    with step("2026-08-30", "snapshot_sources",
              inputs=["https://www.cisa.gov/.../known_exploited_vulnerabilities.json"],
              outputs=["forecaster/evidence/manifests/2026/08/2026-08-30.json"],
              version="snapshot_sources/1.0"):
        ...

CLI として使う（シェルから1ステップを記録する）:
    python3 scripts/run_manifest.py --date 2026-08-30 --step nvd_window_sweep \\
        --status ok --started 2026-08-29T22:01:00Z --ended 2026-08-29T22:04:00Z \\
        --output .cache/daily-security-intel/2026-08-30/step1-sweep.json

    # 記録済みの成果物ハッシュを取り直して整合を確認する
    python3 scripts/run_manifest.py --date 2026-08-30 --verify
"""

import argparse
import contextlib
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUTS_DIR = os.path.join(REPO_ROOT, "outputs")
JST = timezone(timedelta(hours=9))
UTC = timezone.utc
SCHEMA_VERSION = "1.0"


def iso(dt):
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utcnow():
    return datetime.now(UTC).replace(microsecond=0)


def manifest_path(day):
    return os.path.join(OUTPUTS_DIR, day, f"{day}-run-manifest.json")


def file_sha256(rel_or_abs):
    """リポジトリ相対または絶対パスのファイルの SHA-256 を返す。無ければ None。"""
    path = rel_or_abs
    if not os.path.isabs(path):
        path = os.path.join(REPO_ROOT, rel_or_abs)
    if not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(day):
    path = manifest_path(day)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {
        "_schema_version": SCHEMA_VERSION,
        "_run_date": day,
        "_comment": (
            "日次実行の各ステップの入出力・時刻・内容ハッシュ・版。"
            "予報の先見性を第三者が追跡できるようにするための実行記録（改善計画 §10）。"
        ),
        "steps": [],
    }


def save(day, doc):
    path = manifest_path(day)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return path


def record(day, name, status="ok", started=None, ended=None,
           inputs=None, outputs=None, version=None, note=None):
    """1ステップを追記する。outputs の内容ハッシュはこの時点で計算する。"""
    doc = load(day)
    entry = {
        "step": name,
        "status": status,
        "started_at_utc": started or iso(utcnow()),
        "ended_at_utc": ended or iso(utcnow()),
        "version": version,
        "inputs": list(inputs or []),
        "outputs": [],
    }
    for rel in outputs or []:
        entry["outputs"].append({"path": rel, "sha256": file_sha256(rel)})
    if note:
        entry["note"] = note
    doc["steps"].append(entry)
    return save(day, doc)


@contextlib.contextmanager
def step(day, name, inputs=None, outputs=None, version=None):
    """with 文でステップの開始/終了時刻を自動記録する。例外時は status=error。"""
    started = iso(utcnow())
    status = "ok"
    try:
        yield
    except Exception:
        status = "error"
        raise
    finally:
        record(day, name, status=status, started=started, ended=iso(utcnow()),
               inputs=inputs, outputs=outputs, version=version)


def verify(day):
    """記録された outputs のハッシュが現在の実体と一致するか検査する。"""
    path = manifest_path(day)
    if not os.path.exists(path):
        print(f"[E] run-manifest が存在しない: {path}", file=sys.stderr)
        return 1
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    errors = 0
    for s in doc.get("steps", []):
        for o in s.get("outputs", []):
            actual = file_sha256(o["path"])
            if actual is None:
                print(f"[E] {s['step']}: 成果物が存在しない: {o['path']}", file=sys.stderr)
                errors += 1
            elif o.get("sha256") and actual != o["sha256"]:
                print(
                    f"[E] {s['step']}: {o['path']} のハッシュ不一致"
                    f"（記録={o['sha256'][:12]}… 実体={actual[:12]}…）",
                    file=sys.stderr,
                )
                errors += 1
    print(f"[verify] {day}: ステップ {len(doc.get('steps', []))} 件 / 不整合 {errors} 件")
    return 1 if errors else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", help="対象日 YYYY-MM-DD（既定: JST の本日）")
    ap.add_argument("--step", help="記録するステップ名")
    ap.add_argument("--status", default="ok", choices=["ok", "error", "skipped"])
    ap.add_argument("--started", help="開始時刻 ISO8601(UTC)")
    ap.add_argument("--ended", help="終了時刻 ISO8601(UTC)")
    ap.add_argument("--input", action="append", default=[], help="入力（複数可）")
    ap.add_argument("--output", action="append", default=[], help="出力パス（複数可）")
    ap.add_argument("--version", help="ステップ実装の版")
    ap.add_argument("--note", help="注記")
    ap.add_argument("--verify", action="store_true", help="記録済みハッシュの整合を検査する")
    args = ap.parse_args()

    day = args.date or datetime.now(JST).date().isoformat()
    if args.verify:
        return verify(day)
    if not args.step:
        ap.error("--step か --verify のどちらかが必要")
    path = record(day, args.step, status=args.status, started=args.started,
                  ended=args.ended, inputs=args.input, outputs=args.output,
                  version=args.version, note=args.note)
    print(f"[out] {path}  （step={args.step} status={args.status}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
