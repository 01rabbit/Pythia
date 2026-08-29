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


def _channel_retrievals(doc):
    """manifest 1日分から channel -> (最早取得時刻, [evidence_id]) を作る。"""
    per = {}
    for entry in doc.get("evidence", []):
        channel = EVIDENCE_TYPE_TO_CHANNEL.get(entry.get("source_type"))
        if not channel or not entry.get("retrieved_at_utc"):
            continue
        at = _parse(entry["retrieved_at_utc"])
        cur = per.get(channel)
        if cur is None or at < cur[0]:
            per[channel] = (at, [entry.get("evidence_id")])
        else:
            cur[1].append(entry.get("evidence_id"))
    return per


def derive_from_evidence(rule, day):
    """Evidence Ledger から被覆記録の payload を導出する。

    窓は「前回その channel を取得した時刻 → 今回取得した時刻」とし、
    日をまたいで連続するようにする。前回取得が無い場合は長さ0の窓とし、
    証跡の無い過去を覆ったと主張しない。
    取得証跡が無い channel は error とし、被覆を主張しない。
    """
    with open(UNIVERSES, encoding="utf-8") as f:
        universe = json.load(f)["universes"][rule]
    manifests = _manifests()
    index = {d: _channel_retrievals(doc) for d, doc in manifests}
    if day not in index:
        raise SystemExit(f"[error] {day} の Evidence manifest が無い。先に snapshot_sources.py を実行すること")
    today = index[day]
    prior_days = [d for d in index if d < day]

    statuses, windows, derived = {}, [], {}
    for channel in universe.get("sources") or []:
        if channel not in today:
            statuses[channel] = "error"
            continue
        at, ids = today[channel]
        previous = None
        for d in sorted(prior_days, reverse=True):
            if channel in index[d]:
                previous = index[d][channel][0]
                break
        # ★前回取得が無ければ窓は長さ0にする。「初回取得より前も監視できていた」は
        #   証跡が無い主張であり、fail-closed で覆わない。連鎖は2日目から成立する。
        start = previous or at
        statuses[channel] = "ok"
        windows.append((start, at))
        derived[channel] = sorted(x for x in ids if x)
    if not windows:
        raise SystemExit(f"[error] {rule} の宣言 channel に取得証跡が1つも無い。被覆は主張できない")
    start = min(w[0] for w in windows)
    end = max(w[1] for w in windows)
    return statuses, start, end, derived


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

    derived = None
    if args.from_evidence:
        if args.source_status or args.window_start_utc or args.window_end_utc:
            ap.error("--from-evidence と手動指定は併用できない")
        statuses, start, end, derived = derive_from_evidence(args.rule, args.from_evidence)
        window_start = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        window_end = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        if not (args.source_status and args.window_start_utc and args.window_end_utc):
            ap.error("--from-evidence か、--window-start-utc/--window-end-utc/--source-status が要る")
        statuses = {}
        for item in args.source_status:
            source, sep, status = item.partition("=")
            if not sep or status not in {"ok", "error"}:
                ap.error(f"不正な --source-status: {item}")
            statuses[source] = status
        window_start, window_end = args.window_start_utc, args.window_end_utc

    payload = {
        "_schema_version": "1.1", "matching_rule_version": args.rule,
        "window_start_utc": window_start, "window_end_utc": window_end,
        "sources": statuses,
        "derivation": "evidence_ledger" if derived is not None else "manual",
        "derived_from": derived,
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
