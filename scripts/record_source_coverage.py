#!/usr/bin/env python3
"""matching ruleの監視成否を記録し、負の判定を監査可能にする。

★被覆記録が無い限り、窓が満了した未確認を miss にできない（negative_outcome_allowed
  = coverage_proven）。手で ok を打つのではなく、実際の取得証跡（Evidence Ledger）から
  導出できるようにする（--from-evidence）。導出元の evidence_id を derived_from に残し、
  「監視できていた」という主張を後から検証可能にする。

使い方:
    # 取得証跡から導出（日次パイプラインはこちらを使う）
    python3 scripts/record_source_coverage.py --rule tf1-exploitation-v3 --from-evidence 2026-08-30

    # 手動記録（証跡が無い場合の例外。derived_from は残らない）
    python3 scripts/record_source_coverage.py --rule tf1-poc-v3 \
      --window-start-utc ... --window-end-utc ... --source-status vendor=ok --source-status cert=error
"""

import argparse
import glob
import hashlib
import json
import os
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_ROOT = os.path.join(ROOT, "forecaster", "evidence", "source-coverage")
MANIFEST_GLOB = os.path.join(ROOT, "forecaster", "evidence", "manifests", "*", "*", "*.json")
UNIVERSES = os.path.join(ROOT, "forecaster", "knowledge", "source-universes.json")
CHANNEL_FEEDS = os.path.join(ROOT, "forecaster", "knowledge", "channel-feeds.json")

# Evidence Ledger の source_type → 確認チャネル。取得証跡だけを根拠にする。
EVIDENCE_TYPE_TO_CHANNEL = {
    "cisa_kev": "cert", "cert": "cert", "nvd": "cert",
    "vendor": "vendor", "telemetry": "telemetry_provider",
}


def _parse(ts):
    from datetime import datetime, timezone
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def _manifests():
    """[(date, doc)] を日付昇順で返す。"""
    out = []
    for path in sorted(glob.glob(MANIFEST_GLOB)):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if doc.get("_evidence_date"):
            out.append((doc["_evidence_date"], doc))
    return sorted(out)


def _required_feeds():
    """channel -> 宣言済みフィード名の集合。宣言が無いチャネルは空集合。"""
    if not os.path.exists(CHANNEL_FEEDS):
        return {}
    with open(CHANNEL_FEEDS, encoding="utf-8") as f:
        doc = json.load(f)
    return {ch: {x["name"] for x in feeds}
            for ch, feeds in (doc.get("channels") or {}).items()}


def _channel_retrievals(doc):
    """manifest 1日分から channel -> {feed_name: (取得時刻, evidence_id)} を作る。

    ★フィード単位で保持する。チャネルに1件でも証跡があれば ok にすると、
      宣言3フィードのうち1件しか取れていない vendor を「監視できていた」ことに
      してしまう（PR #177 レビュー指摘）。
    """
    per = {}
    for entry in doc.get("evidence", []):
        channel = EVIDENCE_TYPE_TO_CHANNEL.get(entry.get("source_type"))
        if not channel or not entry.get("retrieved_at_utc"):
            continue
        feed = ((entry.get("extract") or {}).get("feed_name")
                or entry.get("source_url") or entry.get("evidence_id"))
        per.setdefault(channel, {})[feed] = (
            _parse(entry["retrieved_at_utc"]), entry.get("evidence_id"))
    return per


def _channel_state(retrievals, channel, required):
    """(status, 取得完了時刻, feed別成否, evidence_ids) を返す。

    status:
      ok      … 宣言済みフィードが全て取得できた。この区間だけが miss の根拠になる
      partial … 一部だけ取得できた。可視化はするが miss の根拠にしない
      error   … 1件も取得できていない
    完了時刻は**全フィードが揃った時刻**＝取得時刻の最大値とする（最早ではない）。
    最早を使うと、まだ取れていないフィードの分まで監視済みにしてしまう。
    """
    got = retrievals.get(channel) or {}
    need = required.get(channel) or set()
    feeds = {name: ("ok" if name in got else "error") for name in sorted(need)}
    for name in got:
        feeds.setdefault(name, "ok")
    if not got:
        return "error", None, feeds, []
    if need and not need <= set(got):
        return "partial", None, feeds, []
    completed = max(at for at, _eid in got.values())
    ids = sorted(eid for _at, eid in got.values() if eid)
    return "ok", completed, feeds, ids


def derive_from_evidence(rule, day):
    """Evidence Ledger から被覆記録の payload を導出する。

    ★被覆区間は**チャネルごと**に持つ。全チャネル共通の1区間にまとめると、
      取得時刻の早いチャネルの開始時刻が、まだ取得していないチャネルにも
      適用され、監視していない時間帯を監視済みにしてしまう（PR #177 レビュー指摘）。

    各チャネルの区間は「前回そのチャネルが ok になった完了時刻 → 今回の完了時刻」。
    前回 ok が無ければ長さ0とし、証跡の無い過去を覆ったと主張しない
    （被覆の連鎖は ok が2日連続して初めて成立する）。
    partial / error のチャネルは区間を出さない。
    """
    with open(UNIVERSES, encoding="utf-8") as f:
        universe = json.load(f)["universes"][rule]
    required = _required_feeds()
    manifests = _manifests()
    index = {d: _channel_retrievals(doc) for d, doc in manifests}
    if day not in index:
        raise SystemExit(f"[error] {day} の Evidence manifest が無い。先に snapshot_sources.py を実行すること")
    prior_days = sorted((d for d in index if d < day), reverse=True)

    channels = {}
    for channel in universe.get("sources") or []:
        status, completed, feeds, ids = _channel_state(index[day], channel, required)
        row = {"status": status, "feeds": feeds, "derived_from": ids}
        if status == "ok":
            previous = None
            for d in prior_days:
                prev_status, prev_completed, _f, _i = _channel_state(index[d], channel, required)
                if prev_status == "ok":
                    previous = prev_completed
                    break
            start = previous or completed
            row["window_start_utc"] = start.strftime("%Y-%m-%dT%H:%M:%SZ")
            row["window_end_utc"] = completed.strftime("%Y-%m-%dT%H:%M:%SZ")
        channels[channel] = row
    if not any(r["status"] == "ok" for r in channels.values()):
        print(f"[warn] {rule}: ok になったチャネルが無い。被覆は主張しない", file=sys.stderr)
    return channels


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rule", required=True)
    ap.add_argument("--from-evidence", metavar="YYYY-MM-DD",
                    help="Evidence Ledger から被覆を導出する（日次パイプラインはこちら）")
    ap.add_argument("--window-start-utc")
    ap.add_argument("--window-end-utc")
    ap.add_argument("--source-status", action="append",
                    help="source=ok|error。ruleの全sourceを列挙する（手動記録時のみ）")
    args = ap.parse_args()

    if args.from_evidence:
        if args.source_status or args.window_start_utc or args.window_end_utc:
            ap.error("--from-evidence と手動指定は併用できない")
        channels = derive_from_evidence(args.rule, args.from_evidence)
    else:
        if not (args.source_status and args.window_start_utc and args.window_end_utc):
            ap.error("--from-evidence か、--window-start-utc/--window-end-utc/--source-status が要る")
        channels = {}
        for item in args.source_status:
            source, sep, status = item.partition("=")
            if not sep or status not in {"ok", "error"}:
                ap.error(f"不正な --source-status: {item}")
            row = {"status": status, "feeds": {}, "derived_from": []}
            if status == "ok":
                row["window_start_utc"] = args.window_start_utc
                row["window_end_utc"] = args.window_end_utc
            channels[source] = row

    payload = {
        # 1.2: 全チャネル共通の単一窓を廃止し、チャネル別の区間を持つ
        "_schema_version": "1.2", "matching_rule_version": args.rule,
        "channels": channels,
        "derivation": "evidence_ledger" if args.from_evidence else "manual",
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"))
                            .encode("utf-8")).hexdigest()
    payload["content_sha256"] = digest
    os.makedirs(OUT_ROOT, exist_ok=True)
    out = os.path.join(OUT_ROOT, f"coverage-{digest[:16]}.json")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=OUT_ROOT, delete=False) as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
        temp_name = f.name
    os.replace(temp_name, out)
    print(f"[out] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
