#!/usr/bin/env python3
"""`infrastructure_context`（Section 6・攻撃基盤プロファイル）を JSON からテキストへ決定論的に変換する。

プロファイルはスクリプトが API 応答から機械的に作ったものなので、テキストも手で書き起こさず
このスクリプトで生成する（JSON との乖離を構造的に避ける。render_neighbor_section.py と同じ方針）。

出力:
  outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-infra.txt   （Section 6 単体）
  --append-to-full 指定時: YYYY-MM-DD-security-report.txt の末尾へ追記する（見出しが既にあれば何もしない）

IP・ドメインは無害化表記（1[.]2[.]3[.]4 / evil[.]com）で出す。応答本文のハッシュ・forecast_input・
照会の生の extract は JSON 専用でテキストに出さない。

★forecaster/ 配下には一切書き込まない。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

JST = timezone(timedelta(hours=9))

HEADING = "【攻撃基盤プロファイル】"
RULE = "━" * 28
SEP = "-" * 60

SKIP_JA = {
    "non_public": "非公開アドレス・予約名のため照会しない",
    "legitimate_or_shared_platform": "正規サービスまたは共有プラットフォームのため照会しない",
    "over_budget": "1回あたりの上限を超えたため照会していない",
    "no_enabled_source": "有効なソースが無いため照会していない",
}
UNPARSED_JA = {
    "url_path_only": "パスのみで、ホストが分からない",
    "not_a_domain": "ファイル名であり、ドメインではない",
    "unparseable": "解析できない表記",
}
STATUS_JA = {"ok": "成功", "no_data": "データなし", "failed": "失敗"}
RUN_JA = {"ok": "正常", "partial": "一部失敗", "failed": "全件失敗", "disabled": "無効", "no_indicators": "対象のIoCなし"}
CAVEAT_JA = {
    "geolocation_approximate": "国は位置情報データベースによる近似であり、攻撃者の所在を示さない。",
    "shared_infrastructure_not_attribution": "共有基盤（{providers}）上にあり、同一基盤であることは同一運用者の根拠にならない。",
    "source_vulns_unverified": "脆弱性の一覧は情報源（Shodan）の推定であり、検証されていない。",
    "hostnames_source_asserted": "ホスト名は情報源の記述であり、当該 IP の所有者を示すとは限らない。",
    "urlscan_30d_window": "urlscan の履歴は過去30日の他者のスキャンに限られる。",
    "passive_dns_partial": "パッシブ DNS は観測された範囲の履歴であり、網羅ではない。",
    "some_sources_failed": "取得に失敗したソースがあり、情報が不足している。",
}


def d(value: str) -> str:
    return str(value).replace(".", "[.]")


def _join(items, *, defang=False) -> str:
    return ", ".join(d(x) if defang else str(x) for x in items) if items else "なし"


def render_profile(p: dict) -> list[str]:
    s, flags = p.get("summary") or {}, p.get("flags") or {}
    lines = [SEP, f"[{p['profile_id']}] {p['defanged']}（{'IPアドレス' if p['type'] == 'ip' else 'ドメイン'}）", SEP, ""]
    refs = [r.get("ref") or r.get("path") for r in p.get("reported_in", [])]
    lines.append("報告元: " + " / ".join(str(r) for r in refs))
    # 報告時の表記も無害化して出す（レポートが無害化せず書いた生の IP・ドメインをそのまま出さない）
    shown = [d(str(s).replace("[.]", ".")) for s in p.get("as_reported", [])]
    if shown != [p["defanged"]]:
        lines.append("報告時の表記: " + " / ".join(shown))
    if p.get("annotations"):
        lines.append("報告時の注記: " + " / ".join(p["annotations"]))
    if p.get("type") == "ip":
        if "prefix" in s:
            asn = "; ".join(f"AS{a['asn']} {a.get('holder') or ''}".strip() for a in s.get("asns", [])) or "広告なし"
            lines += ["", "【経路・保有者（RIPEstat）】",
                      f"プレフィックス: {s['prefix']}（{'広告中' if s.get('announced') else '広告なし'}）",
                      f"ASN・保有者: {asn}", f"アドレス割当: {s.get('rir_block') or '不明'}"]
        if "countries" in s:
            lines += ["", "【国（近似）】", _join(s["countries"]) if s["countries"] else "不明"]
        if "ports" in s:
            lines += ["", "【稼働状況（Shodan InternetDB が保有する情報）】",
                      f"開放ポート: {_join(s['ports'])}", f"CPE（ソフトウェア・バージョン）: {_join(s['cpes'])}",
                      f"タグ: {_join(s['tags'])}"]
            if s.get("vulns"):
                lines.append(f"脆弱性（情報源の推定・未検証）: {_join(s['vulns'])}")
            if s.get("hostnames"):
                lines.append(f"ホスト名（情報源の記述）: {_join(s['hostnames'], defang=True)}")
    else:
        if "registered_at" in s or "registrar" in s:
            lines += ["", "【登録情報（RDAP）】",
                      f"レジストラ: {s.get('registrar') or '不明'}",
                      f"登録日: {s.get('registered_at') or '不明'}" + ("（登録から30日以内）" if flags.get("newly_registered") else ""),
                      f"有効期限: {s.get('expires_at') or '不明'}",
                      f"ネームサーバ: {_join(s.get('nameservers'), defang=True)}",
                      f"状態: {_join(s.get('rdap_status'))}"]
            if s.get("rdap_queried_name") not in (None, p["indicator"]):
                lines.append(f"※ 登録情報は上位のドメイン {d(s['rdap_queried_name'])} で照会した")
        if "observed_ips" in s or "observed_asns" in s:
            lines += ["", "【観測されたホスティング先（urlscan・パッシブDNS）】",
                      f"IPアドレス: {_join(s.get('observed_ips'), defang=True)}"]
            if s.get("observed_asns"):
                lines.append("ASN: " + "; ".join(f"AS{a['asn']} {a.get('name') or ''}".strip() for a in s["observed_asns"]))
            if s.get("servers"):
                lines.append(f"Server ヘッダ: {_join(s['servers'])}")
        if s.get("non_public_answers"):
            lines.append(f"非公開アドレスへの解決履歴: {_join(s['non_public_answers'], defang=True)}")
        stats = []
        if "urlscan_total" in s:
            stats.append(f"urlscan の該当スキャン {s['urlscan_total']}件")
        if s.get("pdns_count") is not None:
            stats.append(f"パッシブDNSの記録 {s['pdns_count']}件")
        if stats:
            lines.append("件数: " + " / ".join(stats))
    notes = []
    for key in p.get("caveats", []):
        text = CAVEAT_JA.get(key, key)
        if "{providers}" in text:
            text = text.format(providers=" / ".join(flags.get("shared_infrastructure_providers", [])) or "共有基盤")
        notes.append(text)
    if notes:
        lines += ["", "【注意】"] + [f"・{n}" for n in notes]
    if p.get("lookups"):
        lines += ["", "【照会】（公開データベースへの受動照会・IoC 自体へは接続していない）"]
        for rec in p["lookups"]:
            tail = f"・{rec['error']}" if rec.get("error") else ""
            lines.append(f"・{rec['source']} {rec['queried_at_utc']} {STATUS_JA.get(rec['status'], rec['status'])}{tail}")
    lines.append("")
    return lines


def render(report: dict) -> str:
    ctx = report.get("infrastructure_context")
    if not isinstance(ctx, dict):
        raise SystemExit("infrastructure_context が無い")
    run = ctx.get("run") or {}
    ind, lk = run.get("indicators") or {}, run.get("lookups") or {}
    meta = report.get("meta") or {}
    lines = [RULE, HEADING + "（報告専用・予報の入力には使用しない）", RULE, ""]
    if meta.get("report_date"):
        lines.append(f"対象日: {meta['report_date']}")
    lines.append("状態: {} / 指標 {}件（補強 {} / スキップ {} / 解析不能 {}）/ 照会 {}回（成功 {} / データなし {} / 失敗 {}）".format(
        RUN_JA.get(run.get("status"), run.get("status")), ind.get("extracted", 0), ind.get("enriched", 0),
        ind.get("skipped", 0), ind.get("unparsed", 0), lk.get("total", 0), lk.get("ok", 0),
        lk.get("no_data", 0), lk.get("failed", 0)))
    lines += ["※ すべて公開データベースへの受動照会である。IoC の指す IP・ドメインへは接続していない。",
              "※ 取得時刻は照会した時点であり、攻撃が行われた時点の状態ではない。",
              "※ 要約はスクリプトが応答から機械的に作ったもので、推測は含まない。インフラの類似だけで帰属しない。", ""]
    profiles = ctx.get("profiles") or []
    active = [p for p in profiles if not p.get("skip_reason")]
    skipped = [p for p in profiles if p.get("skip_reason")]
    for title, kind in (("■ IPアドレス", "ip"), ("■ ドメイン", "domain")):
        group = [p for p in active if p["type"] == kind]
        if group:
            lines += [title, ""]
            for p in group:
                lines += render_profile(p)
    if not active:
        lines += ["（本日、補強の対象となる IoC はありません）", ""]
    if skipped:
        lines.append("【照会しなかった指標】")
        for p in skipped:
            lines.append(f"・{p['defanged']}: {SKIP_JA.get(p['skip_reason'], p['skip_reason'])}")
        lines.append("")
    if ctx.get("unparsed"):
        lines.append("【解析できなかった IoC の表記】")
        for u in ctx["unparsed"]:
            lines.append(f"・{d(str(u['as_reported']).replace('[.]', '.'))}: {UNPARSED_JA.get(u['reason'], u['reason'])}")
        lines.append("")
    lines.append(f"攻撃基盤プロファイル — 補強{ind.get('enriched', 0)}件 / スキップ{ind.get('skipped', 0)}件"
                 f" / 解析不能{ind.get('unparsed', 0)}件")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="infrastructure_context を Section 6 テキストへ変換する")
    parser.add_argument("--date", help="対象日 YYYY-MM-DD（既定: JST の本日）")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument("--append-to-full", action="store_true",
                        help="security-report.txt の末尾へも追記する（見出しが既にあれば何もしない）")
    parser.add_argument("--stdout", action="store_true", help="ファイルへ書かず標準出力へ出す")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    date = args.date or datetime.now(JST).strftime("%Y-%m-%d")
    base = root / "outputs" / date
    report = json.loads((base / f"{date}-security-report.json").read_text(encoding="utf-8"))
    text = render(report)
    if args.stdout:
        sys.stdout.write(text)
        return 0
    out = base / f"{date}-security-report-infra.txt"
    out.write_text(text, encoding="utf-8")
    print(f"保存: {out}", file=sys.stderr)
    if args.append_to_full:
        full = base / f"{date}-security-report.txt"
        body = full.read_text(encoding="utf-8") if full.is_file() else ""
        if HEADING in body:
            print(f"{full.name} には既に {HEADING} がある（追記しない）", file=sys.stderr)
        else:
            full.write_text(body.rstrip("\n") + "\n\n" + text, encoding="utf-8")
            print(f"追記: {full}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
