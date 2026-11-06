#!/usr/bin/env python3
"""Section 6（攻撃基盤プロファイル）の `infrastructure_context` を検証する fail-closed ゲート。

プロファイルは scripts/enrich_infrastructure.py が API 応答から機械的に作る。この検証器は
『LLM やその後の編集が、応答に無い情報を足していない／IoC を落としていない』ことを、
同じ純関数を使った再計算で確認する。

検査項目（エラー = コミットしてはならない）:
  [E] 構造と語彙（実行状態・照会の状態・スキップ理由・注意書き）。forecast_input は false 固定
  [E] 完全性: レポート本体の ioc から再抽出した指標の集合が、プロファイル＋解析不能の集合と一致する
      （IoC を黙って落とさない・存在しない指標を足さない）
  [E] 追跡可能性: 各プロファイルの as_reported を正規化し直すと indicator に一致する
      （転記ミス・捏造の検出）。スキップ理由も再分類と一致する（over_budget / no_enabled_source を除く）
  [E] 受動のみ: 照会先ホストが各ソースの既知のホストと一致し、IoC 自身ではない
  [E] 取得証跡: 取得時刻（UTC）が実行区間内・HTTP 状態・応答ハッシュ（64桁）・失敗時の理由
  [E] 再計算: summary / flags / caveats が照会記録から build_summary で再計算した値と一致する
  [E] 集計: run の件数・by_source・実行状態・statistics が再計算値と一致する
  [E] 予報との分離: 当日の観測ファイルと forecasts / tactical_forecast に inf- ID が現れない
  [W] infrastructure_context が無い（段階導入中は警告。--require でエラーにする）
  [W] 実行状態が failed / partial

使い方:
    python3 scripts/validate_infrastructure_context.py --date 2026-11-06 --require

終了コード: 0=エラーなし / 1=エラーあり（警告のみなら 0）

★読み取り専用。forecaster/knowledge/ を含む一切のファイルを書き換えない（行動原則5）。
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import enrich_infrastructure as ei  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
JST = timezone(timedelta(hours=9))

PROFILE_ID_RE = re.compile(r"^inf-(\d{4}-\d{2}-\d{2})-(\d{3})$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
INF_ID_RE = re.compile(r"\binf-\d{4}-\d{2}-\d{2}-\d{3}\b")
SOURCE_HOSTS = {
    "ripestat.prefix": {"stat.ripe.net"}, "ripestat.geolocation": {"stat.ripe.net"},
    "internetdb": {"internetdb.shodan.io"}, "rdap.domain": {"rdap.org"},
    "urlscan.search": {"urlscan.io"}, "mnemonic.pdns": {"api.mnemonic.no"},
}
IP_SOURCES = {"ripestat.prefix", "ripestat.geolocation", "internetdb"}
FORBIDDEN_KEYS = ("techniques", "ttps", "actor_group", "mitre_id", "observation_id", "forecast_id",
                  "base_rate", "base_rate_estimate", "verified_outcome")


def _walk_keys(node, path=""):
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else key
            yield here, key
            yield from _walk_keys(value, here)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _walk_keys(item, f"{path}[{i}]")


def _validate_lookup(tag: str, rec, ptype: str, enabled: set, run_start: str, run_end: str, indicators: set) -> list:
    errors: list = []
    if not isinstance(rec, dict):
        return [f"{tag}: 照会記録がオブジェクトでない"]
    source = rec.get("source")
    if source not in ei.LOOKUP_FAMILY:
        return [f"{tag}: 未知のソース {source!r}"]
    if ei.LOOKUP_FAMILY[source] not in enabled:
        errors.append(f"{tag}: {source} は run.sources_enabled に無い")
    if (source in IP_SOURCES) != (ptype == "ip"):
        errors.append(f"{tag}: {source} は {ptype} には適用しないソース")
    if rec.get("kind") != "passive_database":
        errors.append(f"{tag}: kind は passive_database 固定")
    host = (rec.get("host") or "").lower()
    if host not in SOURCE_HOSTS[source]:
        errors.append(f"{tag}: 照会先 {host!r} が {source} の既知のホスト {sorted(SOURCE_HOSTS[source])} と一致しない")
    if host in indicators:
        errors.append(f"{tag}: 照会先が報告された IoC 自身（受動のみ・IoC へ接続しない）")
    ts = rec.get("queried_at_utc")
    if not isinstance(ts, str) or not TS_RE.match(ts):
        errors.append(f"{tag}: queried_at_utc は YYYY-MM-DDTHH:MM:SSZ 形式")
    elif not (run_start <= ts <= run_end):
        errors.append(f"{tag}: queried_at_utc {ts} が実行区間 [{run_start}, {run_end}] の外")
    status = rec.get("status")
    if status not in ei.LOOKUP_STATUSES:
        errors.append(f"{tag}: status は {ei.LOOKUP_STATUSES} のいずれか")
        return errors
    http = rec.get("http_status")
    if http is not None and (not isinstance(http, int) or isinstance(http, bool)):
        errors.append(f"{tag}: http_status は整数または null")
    sha = rec.get("response_sha256")
    if sha is not None and not (isinstance(sha, str) and SHA_RE.match(sha)):
        errors.append(f"{tag}: response_sha256 は 64 桁の 16 進または null")
    if status == "ok":
        if not rec.get("extract"):
            errors.append(f"{tag}: status=ok だが extract が空")
        if http != 200 or sha is None:
            errors.append(f"{tag}: status=ok は HTTP 200 と応答ハッシュが必要")
    elif status == "no_data":
        if rec.get("extract"):
            errors.append(f"{tag}: status=no_data だが extract がある")
    else:
        if not (isinstance(rec.get("error"), str) and rec["error"].strip()):
            errors.append(f"{tag}: status=failed は error（理由）が必要")
    return errors


def validate(report: dict, *, date: str, policy: dict, observation_text=None, require: bool = False):
    """infrastructure_context を検査し (errors, warnings) を返す。純関数（I/O なし）。"""
    errors: list = []
    warnings: list = []
    ctx = report.get("infrastructure_context")
    if ctx is None:
        msg = f"{date}: infrastructure_context が無い（Step 3.1 未実施の可能性）"
        (errors if require else warnings).append(msg)
        return errors, warnings
    if not isinstance(ctx, dict):
        return [f"{date}: infrastructure_context がオブジェクトでない"], warnings

    if ctx.get("schema_version") != "1.0":
        errors.append(f"{date}: schema_version は '1.0'")
    if ctx.get("forecast_input") is not False:
        errors.append(f"{date}: forecast_input は false 固定（Section 6 は予報の入力に使わない）")
    run = ctx.get("run")
    if not isinstance(run, dict):
        return errors + [f"{date}: run が無い"], warnings
    status = run.get("status")
    if status not in ei.RUN_STATUSES:
        errors.append(f"{date}: run.status は {ei.RUN_STATUSES} のいずれか")
    if status in ("failed", "partial"):
        warnings.append(f"{date}: infrastructure_context の実行状態が {status}（一部のソースの取得に失敗）")
    start, end = run.get("started_at_utc"), run.get("finished_at_utc")
    if not (isinstance(start, str) and TS_RE.match(start) and isinstance(end, str) and TS_RE.match(end) and start <= end):
        errors.append(f"{date}: run.started_at_utc / finished_at_utc が不正")
        start, end = "0000", "9999"
    enabled = set(run.get("sources_enabled") or [])
    if not enabled <= set(ei.SOURCE_FAMILIES):
        errors.append(f"{date}: run.sources_enabled に未知のソース {sorted(enabled - set(ei.SOURCE_FAMILIES))}")

    for path, key in _walk_keys(ctx):
        if key in FORBIDDEN_KEYS:
            errors.append(f"{date}: {path}: 予報の入力層の項目は持てない")

    profiles = ctx.get("profiles")
    unparsed = ctx.get("unparsed")
    if not isinstance(profiles, list) or not isinstance(unparsed, list):
        return errors + [f"{date}: profiles / unparsed が配列でない"], warnings

    if status == "disabled":
        if profiles or unparsed:
            errors.append(f"{date}: 無効（disabled）なのにプロファイルがある")
        return errors, warnings

    # --- 完全性: レポート本体の ioc から再抽出した指標と一致するか ---
    expected, expected_unparsed = ei.extract_indicators(report, policy)
    exp_set = {(i["type"], i["indicator"]) for i in expected}
    got_set = {(p.get("type"), p.get("indicator")) for p in profiles if isinstance(p, dict)}
    if exp_set != got_set:
        missing, extra = sorted(exp_set - got_set), sorted(got_set - exp_set)
        if missing:
            errors.append(f"{date}: レポートの IoC がプロファイルに無い {missing[:5]}（黙って落とさない）")
        if extra:
            errors.append(f"{date}: レポートに無い指標のプロファイルがある {extra[:5]}")
    exp_unparsed = sorted(u["as_reported"] for u in expected_unparsed)
    got_unparsed = sorted(u.get("as_reported") for u in unparsed if isinstance(u, dict))
    if exp_unparsed != got_unparsed:
        errors.append(f"{date}: 解析不能の IoC の一覧がレポートからの再抽出と一致しない")
    for i, u in enumerate(unparsed):
        if not isinstance(u, dict) or u.get("reason") not in ei.UNPARSED_REASONS:
            errors.append(f"{date}: unparsed[{i}].reason は {ei.UNPARSED_REASONS} のいずれか")

    indicators = {p.get("indicator") for p in profiles if isinstance(p, dict)}
    seen_ids: set = set()
    counts = {s: 0 for s in ei.LOOKUP_STATUSES}
    by_source: dict = {}
    enriched = skipped = 0
    report_date = (report.get("meta") or {}).get("report_date") or date

    for idx, p in enumerate(profiles):
        pid = p.get("profile_id") if isinstance(p, dict) else None
        tag = f"{date}: profiles[{idx}]({pid})"
        if not isinstance(p, dict):
            errors.append(f"{tag}: オブジェクトでない")
            continue
        m = PROFILE_ID_RE.match(pid or "")
        if not m or m.group(1) != date:
            errors.append(f"{tag}: profile_id は inf-{date}-NNN 形式")
        if pid in seen_ids:
            errors.append(f"{tag}: profile_id が重複している")
        seen_ids.add(pid)
        if p.get("forecast_input") is not False:
            errors.append(f"{tag}: forecast_input は false 固定")
        ptype, value = p.get("type"), p.get("indicator")
        if ptype not in ("ip", "domain") or not isinstance(value, str):
            errors.append(f"{tag}: type は ip / domain、indicator は文字列")
            continue
        if p.get("defanged") != ei.defang(value):
            errors.append(f"{tag}: defanged が indicator の無害化表記と一致しない")
        if ptype == "ip":
            try:
                global_ip = ipaddress.ip_address(value).is_global
            except ValueError:
                errors.append(f"{tag}: indicator が IP として不正")
                continue
        else:
            global_ip = None
        # 追跡可能性: as_reported を正規化し直すと indicator に一致する
        reported = p.get("as_reported")
        if not isinstance(reported, list) or not reported:
            errors.append(f"{tag}: as_reported（報告時の表記）が空")
            reported = []
        classes = [ei.classify_token(r, policy) for r in reported if isinstance(r, str)]
        for r, c in zip(reported, classes):
            if c["kind"] != ptype or c.get("value") != value:
                errors.append(f"{tag}: as_reported {r!r} を正規化しても indicator {value!r} にならない（転記ミスの疑い）")
        if not p.get("reported_in"):
            errors.append(f"{tag}: reported_in（どの報告で出たか）が空")
        skip = p.get("skip_reason")
        if skip is not None and skip not in ei.SKIP_REASONS:
            errors.append(f"{tag}: skip_reason は {ei.SKIP_REASONS} のいずれか")
        classed_skip = classes[0].get("skip_reason") if classes and classes[0]["kind"] != "unparsed" else None
        if skip in ("non_public", "legitimate_or_shared_platform") and classed_skip != skip:
            errors.append(f"{tag}: skip_reason {skip} が再分類（{classed_skip}）と一致しない")
        if skip is None and classed_skip is not None:
            errors.append(f"{tag}: 再分類は {classed_skip} だが skip_reason が空（非公開・共有基盤を照会していない）")
        if ptype == "ip" and skip is None and not global_ip:
            errors.append(f"{tag}: 非公開アドレスを照会している")
        lookups = p.get("lookups")
        if not isinstance(lookups, list):
            errors.append(f"{tag}: lookups が配列でない")
            continue
        if skip and lookups:
            errors.append(f"{tag}: スキップしたのに照会記録がある")
        if skip:
            skipped += 1
        for j, rec in enumerate(lookups):
            errors.extend(_validate_lookup(f"{tag}.lookups[{j}]", rec, ptype, enabled, start, end, indicators))
            if isinstance(rec, dict) and rec.get("status") in counts:
                counts[rec["status"]] += 1
                st = by_source.setdefault(rec.get("source"), {"ok": 0, "no_data": 0, "failed": 0, "last_error": None})
                st[rec["status"]] += 1
                if rec["status"] == "failed":
                    st["last_error"] = rec.get("error")
        if any(isinstance(r, dict) and r.get("status") == "ok" for r in lookups):
            enriched += 1
        # 再計算: 要約・フラグ・注意書き
        if all(isinstance(r, dict) and r.get("source") in ei.LOOKUP_FAMILY for r in lookups):
            summary, flags, caveats = ei.build_summary(ptype, lookups, policy, report_date)
            flags["legitimate_or_shared_platform"] = skip == "legitimate_or_shared_platform"
            if p.get("summary") != summary:
                errors.append(f"{tag}: summary が照会記録からの再計算と一致しない（応答に無い情報を足していないこと）")
            if p.get("flags") != flags:
                errors.append(f"{tag}: flags が照会記録からの再計算と一致しない")
            if p.get("caveats") != caveats:
                errors.append(f"{tag}: caveats が照会記録からの再計算と一致しない")

    # --- 集計 ---
    ind = run.get("indicators") or {}
    expect_ind = {"extracted": len(profiles), "enriched": enriched, "skipped": skipped, "unparsed": len(unparsed)}
    if ind != expect_ind:
        errors.append(f"{date}: run.indicators={ind} だが再計算は {expect_ind}")
    expect_lookups = {"total": sum(counts.values()), **counts}
    if run.get("lookups") != expect_lookups:
        errors.append(f"{date}: run.lookups={run.get('lookups')} だが再計算は {expect_lookups}")
    if run.get("by_source") != dict(sorted(by_source.items())):
        errors.append(f"{date}: run.by_source が照会記録からの再計算と一致しない")
    expect_status = ei.run_status(counts, len(profiles) + len(unparsed))
    if status != expect_status:
        errors.append(f"{date}: run.status={status!r} だが照会結果からの導出は {expect_status!r}")
    stats = (report.get("statistics") or {}).get("infrastructure_context")
    if stats is not None and stats != ei.statistics_for(ctx):
        errors.append(f"{date}: statistics.infrastructure_context={stats} だが再計算は {ei.statistics_for(ctx)}")

    # --- 予報との分離 ---
    if observation_text and INF_ID_RE.search(observation_text):
        errors.append(f"{date}: 当日の観測ファイルに inf- ID が現れる（Section 6 は観測へ取り込まない）")
    for key in ("forecasts", "tactical_forecast"):
        if INF_ID_RE.search(json.dumps(report.get(key), ensure_ascii=False)):
            errors.append(f"{date}: {key} が inf- ID を参照している（Section 6 は予報の根拠にしない）")
    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Section 6（infrastructure_context）を検証する（読み取り専用）")
    parser.add_argument("--date", help="検査する日付 YYYY-MM-DD（既定: JST の本日）")
    parser.add_argument("--root", default=str(REPO_ROOT), help="リポジトリルート")
    parser.add_argument("--policy", help="infra/policy.json のパス")
    parser.add_argument("--require", action="store_true", help="infrastructure_context が無い場合をエラーにする")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    date = args.date or datetime.now(JST).strftime("%Y-%m-%d")
    report_path = root / "outputs" / date / f"{date}-security-report.json"
    if not report_path.is_file():
        print(f"[ERROR] {date}: JSON が存在しない: {report_path}")
        return 1
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        print(f"[ERROR] {date}: JSON をパースできない: {err}")
        return 1
    policy = ei.load_policy(args.policy or str(root / "infra" / "policy.json"))
    obs = root / "forecaster" / "observations" / date[:4] / date[5:7] / f"{date}.json"
    obs_text = obs.read_text(encoding="utf-8") if obs.is_file() else None

    errors, warnings = validate(report, date=date, policy=policy, observation_text=obs_text, require=args.require)
    for message in warnings:
        print(f"[WARN] {message}")
    for message in errors:
        print(f"[ERROR] {message}")
    if not args.quiet:
        ctx = report.get("infrastructure_context")
        n = len(ctx.get("profiles", [])) if isinstance(ctx, dict) else 0
        print(f"\n{date}: infrastructure_context プロファイル {n}件 / エラー {len(errors)}件 / 警告 {len(warnings)}件")
        if not errors:
            print("Section 6 の検査に問題なし。")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
