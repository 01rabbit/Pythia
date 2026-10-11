#!/usr/bin/env python3
"""宣言済みフィードを取得して Evidence Ledger へ記録する（確認チャネルの監視）。

★なぜ必要か:
  TF-1 の universe は `negative_outcome_allowed: "coverage_proven"` で、
  `record_source_coverage.py --from-evidence` は Evidence Ledger の取得証跡から
  channel ごとの監視成否を導出する。取得しているのが CISA KEV だけだと cert しか
  ok にならず、vendor / telemetry_provider は永久に error のまま
  → `coverage_proven` が成立しない → **miss が1件も立たない**。
  「予報が当たっている」と「miss を記録できない」が区別できない状態が続く。

★何を取るか:
  取得対象は forecaster/knowledge/channel-feeds.json が宣言したフィードだけである。
  任意URLの取得入口は設けない（c145a48 の方針）。増減は PR と人間レビューを経る。

★何を主張するか（限界）:
  被覆が証明するのは「宣言したフィードを取得できた」ことだけで、
  「そのチャネルの全発信者を監視できた」ことではない。miss は
  「宣言したフィードに載らなかった」という意味であり、真の非発生ではない。
  この限界は channel-feeds.json の _scope_limitation にも書いてある。

★失敗は隠さない:
  取得に失敗したフィードは evidence を作らない。結果としてそのチャネルは
  record_source_coverage 側で error になり、被覆を主張しない（fail-closed）。

使い方:
    python3 scripts/collect_channel_evidence.py --date 2026-08-30
    python3 scripts/collect_channel_evidence.py --date 2026-08-30 --channels vendor,cert
"""

import argparse
import json
import os
import sys
import urllib.error
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snapshot_sources import (  # noqa: E402
    evidence_id, fetch, find_existing_snapshot, iso, load_manifest,
    note_reconfirmation, save_snapshot, sha256_bytes, write_manifest,
)
from source_channels import host_of, load_registry  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEEDS = os.path.join(REPO_ROOT, "forecaster", "knowledge", "channel-feeds.json")
JST = timezone(timedelta(hours=9))

# 確認チャネル → Evidence Ledger の source_type。
# record_source_coverage.EVIDENCE_TYPE_TO_CHANNEL の逆写像であり、両者は一致させる。
CHANNEL_TO_EVIDENCE_TYPE = {
    "cert": "cert", "vendor": "vendor", "telemetry_provider": "telemetry",
}


def assert_date_is_today(day, what="--date"):
    """証跡を後付けの日付へ書かせない。

    ★Evidence Ledger は「いつ監視できていたか」の台帳で、被覆窓はこの日付と
      retrieved_at_utc から導かれる。取得している“今”と違う日付へ書けると、
      監視していなかった期間を監視していたことにできてしまう。
      build_tactical_state.py が cutoff に対して行っているのと同じ種類のガード。
    """
    today = datetime.now(JST).date().isoformat()
    if day != today:
        raise SystemExit(
            f"[fatal] {what} {day} は取得時点のJST日付 {today} と一致しない。"
            "証跡を後付けの日付へ記録することはできない")


def load_feeds():
    with open(FEEDS, encoding="utf-8") as f:
        return json.load(f)


def check_hosts_registered(doc, table):
    """宣言フィードのホストが source-channels.json に、正しいチャネルで載っているか。"""
    problems = []
    for channel, feeds in (doc.get("channels") or {}).items():
        for feed in feeds:
            host = host_of(feed.get("url"))
            registered = table["hosts"].get(host)
            if registered is None:
                problems.append(f"{feed.get('name')}: ホスト {host} が source-channels.json に無い")
            elif registered != channel:
                problems.append(
                    f"{feed.get('name')}: ホスト {host} は登録簿で {registered} だが "
                    f"channel-feeds.json では {channel} として宣言されている")
    return problems


def capture_feed(day, channel, feed):
    """1フィードを取得して evidence エントリを返す。失敗時は None。"""
    url = feed["url"]
    try:
        body, headers, at = fetch(url)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        print(f"[warn] {channel} / {feed['name']}: 取得失敗 {exc}", file=sys.stderr)
        return None

    digest = sha256_bytes(body)
    existing = find_existing_snapshot("feed", digest, ".xml.gz")
    rel, wrote = (existing, False) if existing else save_snapshot(
        "feed", day, digest, body, ".xml.gz")
    print(f"[{channel}] {feed['name']}: {len(body)}B sha256={digest[:12]}… "
          f"snapshot={'新規保存' if wrote else '既存を再利用'}")
    return {
        "evidence_id": evidence_id(day, digest),
        "source_url": url,
        "source_type": CHANNEL_TO_EVIDENCE_TYPE[channel],
        "retrieved_at_utc": iso(at),
        "content_sha256": digest,
        "http_etag": headers.get("ETag"),
        "http_last_modified": headers.get("Last-Modified"),
        "snapshot_path": rel,
        "extract": {
            "feed_name": feed["name"],
            "confirmation_channel": channel,
            "content_length": len(body),
            "_note": "本文は解釈せず生バイトで保存している。意味づけは正規化が行う。",
        },
        "parser_version": "channel-feed-v1",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", help="対象日 YYYY-MM-DD（既定: JST の本日）")
    ap.add_argument("--channels", help="取得するチャネルのカンマ区切り（既定: 全部）")
    ap.add_argument("--verify-registry", action="store_true",
                    help="取得せず、宣言フィードのホスト登録だけ検査する")
    args = ap.parse_args()

    doc, table = load_feeds(), load_registry()
    problems = check_hosts_registered(doc, table)
    for problem in problems:
        print(f"  [E] {problem}")
    if problems:
        return 1
    if args.verify_registry:
        total = sum(len(v) for v in doc["channels"].values())
        print(f"channel-feeds: {total} フィード / ホスト登録の不整合なし")
        return 0

    day = args.date or datetime.now(JST).date().isoformat()
    assert_date_is_today(day)
    wanted = ([c.strip() for c in args.channels.split(",")] if args.channels
              else list(doc["channels"]))

    manifest = load_manifest(day)
    known = {e["evidence_id"] for e in manifest["evidence"]}
    added, failed = 0, []
    for channel in wanted:
        for feed in doc["channels"].get(channel, []):
            entry = capture_feed(day, channel, feed)
            if entry is None:
                failed.append(f"{channel}/{feed['name']}")
                continue
            if entry["evidence_id"] in known:
                # 再確認時刻は extract に残す（snapshot_sources.note_reconfirmation 参照）
                note_reconfirmation(manifest, entry["evidence_id"], entry["retrieved_at_utc"])
                print(f"[skip] {entry['evidence_id']}: 同日に同一内容を取得済み（再確認時刻を記録）")
                continue
            manifest["evidence"].append(entry)
            known.add(entry["evidence_id"])
            added += 1

    path = write_manifest(day, manifest)
    print(f"\n[out] {path}  （新規 {added} 件 / 累計 {len(manifest['evidence'])} 件）")
    if failed:
        # 失敗は握りつぶさない。該当チャネルは被覆を主張できない（fail-closed）。
        print(f"[warn] 取得できなかったフィード: {', '.join(failed)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
