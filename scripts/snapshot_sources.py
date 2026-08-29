#!/usr/bin/env python3
"""一次ソースを取得時刻・内容ハッシュ付きで固定し、Evidence Ledger を書き出す。

改善計画 §4.1 / Phase 0（測定固定）の中核。

なぜ必要か:
  2026-08-29 の監査で、E1 的中6件すべてで KEV の dateAdded が予報日と同日である
  ことが確認された。日付境界では整合しているが、`dateAdded` は日付であって時刻では
  ないため、**「結果より前に予報を固定した」ことをデータだけからは立証できない**。
  さらにリポジトリ履歴は 2026-08-07 の単一コミット（741ファイル）で一括インポート
  されており、2026-06〜08上旬の予報には同時性の証跡が存在しない。
  不正の断定ではなく、測定系を反証可能にするために本スクリプトを置く。

何を固定するか:
  - retrieved_at_utc … 取得が完了した実時刻。予報の cutoff より後の証拠は使えない
  - content_sha256   … 取得応答そのもののハッシュ。後から同一性を再検証できる
  - snapshot         … KEV は内容ハッシュが変わったときだけ圧縮保存（重複排除）
  - extract          … 判定に使う最小限の構造化事実（KEV なら cveID→dateAdded 全件）

★負の事実（「その CVE は KEV に未収載だった」）を後から再検証できることが重要で
  あり、そのためにカタログ全件の cveID→dateAdded を extract に残す。URL だけの
  保存では「あの日どうだったか」を再現できない。

出力:
  forecaster/evidence/manifests/YYYY/MM/YYYY-MM-DD.json   （日次 manifest）
  forecaster/evidence/snapshots/kev/YYYY/MM/<sha256>.json.gz（内容変化時のみ）

使い方:
    # 当日分の一次ソースを取得して Evidence Ledger へ追記（既定は CISA KEV）
    python3 scripts/snapshot_sources.py

    # 日付を指定（JST）
    python3 scripts/snapshot_sources.py --date 2026-08-29

    # ネットワークを使わず、既存 manifest の整合だけ確認する
    python3 scripts/snapshot_sources.py --verify-only

本スクリプトは forecaster/knowledge/ を一切書き換えない（CLAUDE.md 行動原則5）。
"""

import argparse
import gzip
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_ROOT = os.path.join(REPO_ROOT, "forecaster", "evidence")
MANIFEST_DIR = os.path.join(EVIDENCE_ROOT, "manifests")
SNAPSHOT_DIR = os.path.join(EVIDENCE_ROOT, "snapshots")

JST = timezone(timedelta(hours=9))
UTC = timezone.utc

SCHEMA_VERSION = "1.0"
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_PARSER_VERSION = "kev-extract-v1"
USER_AGENT = "pythia-evidence/1.0"


def utcnow():
    return datetime.now(UTC).replace(microsecond=0)


def iso(dt):
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def manifest_path(day):
    return os.path.join(MANIFEST_DIR, f"{day[:4]}", f"{day[5:7]}", f"{day}.json")


def load_manifest(day):
    path = manifest_path(day)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {
        "_schema_version": SCHEMA_VERSION,
        "_evidence_date": day,
        "_generated_at_utc": iso(utcnow()),
        "_generator": "scripts/snapshot_sources.py",
        "evidence": [],
    }


def write_manifest(day, doc):
    path = manifest_path(day)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    doc["_generated_at_utc"] = iso(utcnow())
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return path


# --------------------------------------------------------------------------
# 取得
# --------------------------------------------------------------------------


def fetch(url, timeout=120):
    """URL を取得し (body_bytes, headers, retrieved_at_utc) を返す。

    retrieved_at_utc は**取得完了後**に記録する。取得開始時刻ではない理由は、
    証拠として保証したいのが「この時点でこの内容が存在した」ことだからである。
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        headers = dict(resp.headers)
    return body, headers, utcnow()


def snapshot_relpath(kind, day, digest, suffix=".json.gz"):
    return os.path.join(
        "forecaster", "evidence", "snapshots", kind, day[:4], day[5:7], f"{digest}{suffix}"
    )


def save_snapshot(kind, day, digest, blob, suffix=".json.gz"):
    """内容ハッシュ名で圧縮保存する。既存なら書かずにパスだけ返す（重複排除）。"""
    rel = snapshot_relpath(kind, day, digest, suffix)
    abs_path = os.path.join(REPO_ROOT, rel)
    if os.path.exists(abs_path):
        return rel, False
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with gzip.open(abs_path, "wb") as f:
        f.write(blob)
    return rel, True


def find_existing_snapshot(kind, digest, suffix=".json.gz"):
    """同一ハッシュのスナップショットが過去日に既にあればそのパスを返す。"""
    base = os.path.join(SNAPSHOT_DIR, kind)
    if not os.path.isdir(base):
        return None
    name = f"{digest}{suffix}"
    for root, _dirs, files in os.walk(base):
        if name in files:
            return os.path.relpath(os.path.join(root, name), REPO_ROOT)
    return None


def capture_url(day, url, source_type):
    """任意の一次公表URLを取得し evidence エントリを作る。

    ★なぜ必要か:
      observation の source.primary_reference は、集約ニュース掲載の記事から
      一次公表を確認したと主張するための構造化フィールドで、受理には
      Evidence Ledger の取得証跡（evidence_id）が必須である
      （source_channels.evidence_backs_reference が URL 単位で突合する）。
      KEV しか取得できないと、この経路は書けるが実際には使えない。

    ★内容は本文を解釈せず生バイトのまま保存する。ここは「この時刻にこのURLに
      この内容があった」ことだけを保証する層であり、意味づけは正規化の仕事である。
    """
    try:
        body, headers, at = fetch(url)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        print(f"[warn] 取得失敗 {url}: {exc}", file=sys.stderr)
        return None

    digest = sha256_bytes(body)
    existing = find_existing_snapshot("primary", digest, ".bin.gz")
    if existing:
        rel, wrote = existing, False
    else:
        rel, wrote = save_snapshot("primary", day, digest, body, ".bin.gz")
    print(f"[primary] {url} bytes={len(body)} sha256={digest[:12]}… "
          f"snapshot={'新規保存' if wrote else '既存を再利用'}")

    return {
        "evidence_id": evidence_id(day, digest),
        "source_url": url,
        "source_type": source_type,
        "retrieved_at_utc": iso(at),
        "content_sha256": digest,
        "http_etag": headers.get("ETag"),
        "http_last_modified": headers.get("Last-Modified"),
        "snapshot_path": rel,
        "extract": {
            "content_type": headers.get("Content-Type"),
            "content_length": len(body),
            "_note": "本文は解釈せず生バイトで保存している。意味づけは正規化が行う。",
        },
        "parser_version": "raw-capture-v1",
    }


def evidence_id(day, digest):
    return f"ev-{day.replace('-', '')}-{digest[:5]}"


def load_kev_snapshot(evidence_entry):
    """evidence エントリのスナップショットから KEV カタログ全件を読む。

    検証ステージ（verify_forecasts_v2）が「発行時点で未収載だったか」を
    再現するために使う。ネットワークへは出ない — 証拠台帳だけで完結する。
    """
    rel = evidence_entry.get("snapshot_path")
    if not rel:
        raise ValueError(f"{evidence_entry.get('evidence_id')}: snapshot_path がない")
    with gzip.open(os.path.join(REPO_ROOT, rel), "rb") as f:
        blob = f.read()
    if sha256_bytes(blob) != evidence_entry["content_sha256"]:
        raise ValueError(
            f"{evidence_entry['evidence_id']}: スナップショットの内容ハッシュが manifest と一致しない"
        )
    return json.loads(blob.decode("utf-8"))


def load_manifest_readonly(day):
    """指定日の manifest を読む（存在しなければ None）。他スクリプトから使う。"""
    path = manifest_path(day)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------
# ソース別ハンドラ
# --------------------------------------------------------------------------


def capture_kev(day):
    """CISA KEV カタログを取得し evidence エントリを作る。

    負の事実（「この時刻に CVE-X は未収載だった」）の再検証は、全件を含む
    **スナップショット**が担う。スナップショットは内容ハッシュ名で重複排除される
    ため、CISA が更新した回数分しか増えない。
    manifest の extract は要約に留める（全件マップを両方に持つと日次で 70KB 以上の
    純粋な重複になり、台帳が読めなくなるため）。全件が要るときは
    load_kev_snapshot() でスナップショットから読む。
    """
    try:
        body, headers, at = fetch(KEV_FEED_URL)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        print(f"[warn] CISA KEV 取得失敗: {exc}", file=sys.stderr)
        return None

    digest = sha256_bytes(body)
    catalog = json.loads(body.decode("utf-8"))
    added = {v["cveID"]: v["dateAdded"] for v in catalog.get("vulnerabilities", [])}

    existing = find_existing_snapshot("kev", digest)
    if existing:
        rel, wrote = existing, False
    else:
        rel, wrote = save_snapshot("kev", day, digest, body)
    print(
        f"[kev] catalogVersion={catalog.get('catalogVersion')} count={len(added)} "
        f"sha256={digest[:12]}… snapshot={'新規保存' if wrote else '既存を再利用'}"
    )

    return {
        "evidence_id": evidence_id(day, digest),
        "source_url": KEV_FEED_URL,
        "source_type": "cisa_kev",
        "published_at_utc": catalog.get("dateReleased"),
        "retrieved_at_utc": iso(at),
        "content_sha256": digest,
        "http_etag": headers.get("ETag"),
        "http_last_modified": headers.get("Last-Modified"),
        "snapshot_path": rel,
        "extract": {
            "catalog_version": catalog.get("catalogVersion"),
            "date_released": catalog.get("dateReleased"),
            "count": catalog.get("count", len(added)),
            "max_date_added": max(added.values()) if added else None,
            "_full_catalog_note": (
                "全件の cveID→dateAdded は snapshot_path のスナップショットに入っている。"
                "load_kev_snapshot() で読むこと（manifest へは重複保存しない）。"
            ),
        },
        "parser_version": KEV_PARSER_VERSION,
    }


# --------------------------------------------------------------------------
# 検証
# --------------------------------------------------------------------------


def verify_manifest(day):
    """manifest が指すスナップショットの実ハッシュが一致するか検査する。"""
    path = manifest_path(day)
    if not os.path.exists(path):
        print(f"[E] manifest が存在しない: {path}", file=sys.stderr)
        return 1
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    errors = 0
    for ev in doc.get("evidence", []):
        rel = ev.get("snapshot_path")
        if not rel:
            continue
        abs_path = os.path.join(REPO_ROOT, rel)
        if not os.path.exists(abs_path):
            print(f"[E] {ev['evidence_id']}: スナップショット不在 {rel}", file=sys.stderr)
            errors += 1
            continue
        with gzip.open(abs_path, "rb") as f:
            actual = sha256_bytes(f.read())
        if actual != ev["content_sha256"]:
            print(
                f"[E] {ev['evidence_id']}: 内容ハッシュ不一致 "
                f"（manifest={ev['content_sha256'][:12]}… 実体={actual[:12]}…）",
                file=sys.stderr,
            )
            errors += 1
    print(f"[verify] {day}: 証拠 {len(doc.get('evidence', []))} 件 / 不整合 {errors} 件")
    return 1 if errors else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", help="対象日 YYYY-MM-DD（既定: JST の本日）")
    ap.add_argument(
        "--sources",
        default="cisa_kev",
        help="取得するソースのカンマ区切り（現状 cisa_kev のみ実装）",
    )
    ap.add_argument(
        "--capture-url",
        help="任意の一次公表URLを取得して evidence 化する"
             "（observation の source.primary_reference から参照するため）",
    )
    ap.add_argument(
        "--source-type",
        choices=["vendor", "cert", "nvd", "epss", "news", "telemetry"],
        help="--capture-url で取得する原典の種別",
    )
    ap.add_argument(
        "--verify-only",
        action="store_true",
        help="取得せず、既存 manifest とスナップショットの整合だけ検査する",
    )
    args = ap.parse_args()

    day = args.date or datetime.now(JST).date().isoformat()

    if args.verify_only:
        return verify_manifest(day)

    doc = load_manifest(day)
    known = {e["evidence_id"] for e in doc["evidence"]}
    added_now = 0

    if args.capture_url:
        if not args.source_type:
            ap.error("--capture-url には --source-type が必要")
        ev = capture_url(day, args.capture_url, args.source_type)
        if ev is None:
            return 1
        if ev["evidence_id"] in known:
            print(f"[skip] {ev['evidence_id']}: 同日に同一内容を取得済み")
        else:
            doc["evidence"].append(ev)
            added_now += 1
        path = write_manifest(day, doc)
        print(f"\n[out] {path}  （新規 {added_now} 件 / 累計 {len(doc['evidence'])} 件）")
        print(f"[evidence_id] {ev['evidence_id']}"
              "  ← observation の source.primary_reference.evidence_id に書く")
        return 0

    for src in [s.strip() for s in args.sources.split(",") if s.strip()]:
        if src == "cisa_kev":
            ev = capture_kev(day)
        else:
            print(f"[warn] 未実装のソース: {src}", file=sys.stderr)
            continue
        if ev is None:
            continue
        if ev["evidence_id"] in known:
            # 同日・同一内容の再取得。retrieved_at_utc は最初の取得を正とする
            # （後の取得で時刻を上書きすると先見性の主張が弱くなるため）。
            print(f"[skip] {ev['evidence_id']}: 同日に同一内容を取得済み")
            continue
        doc["evidence"].append(ev)
        known.add(ev["evidence_id"])
        added_now += 1

    path = write_manifest(day, doc)
    print(f"\n[out] {path}  （新規 {added_now} 件 / 累計 {len(doc['evidence'])} 件）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
