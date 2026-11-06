#!/usr/bin/env python3
"""`neighbor_context`（Section 5）を JSON からプレーンテキストへ決定論的に変換する。

日次レポートの派生テキストは、これまでエージェントが JSON から書き起こしていた。
その過程で JSON と食い違う事故（テキストにだけ存在する情報）が実測されている
（scripts/check_report_consistency.py の docstring 参照）。Section 5 はこの失敗モードを
構造的に避けるため、JSON からスクリプトで生成する。同じ JSON からは常に同じ文章が出る。

出力:
  outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-neighbor.txt   （Section 5 単体）
  --append-to-full 指定時: YYYY-MM-DD-security-report.txt の末尾へ同じ内容を追記する
  （見出し行が既にあれば追記しない＝冪等）

テキストには JSON 専用フィールド（info_id・forecast_input・candidate_ids・scan の
内部値の一部）を出さない（pipeline-output-schema.md「変換時の注意点」と同じ扱い）。

★forecaster/ 配下には一切書き込まない。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

JST = timezone(timedelta(hours=9))

HEADING = "【周辺諸国動向】"
RULE = "━" * 28
SEP = "-" * 60

CATEGORY_JA = {
    "activity": "サイバー関連活動",
    "policy": "政策・法制",
    "organization": "組織",
    "company": "サイバーセキュリティ関連企業",
    "geopolitical": "地政学（非サイバー情勢）",
}
BASIS_JA = {
    "state_attributed_by_source": "国家との関係を情報源が明示",
    "located_in_country": "当該国に所在する組織・当該国の政策",
    "target_country": "当該国が標的",
    "context_only": "文脈情報（国との関係の主張なし）",
}
CONFIDENCE_JA = {"low": "低", "medium": "中", "high": "高"}
CONTEXT_JA = {
    "strategy": "国家戦略",
    "politics": "政治動向",
    "national_sentiment": "国家心理・世論",
    "military_org": "軍と組織の関係",
}
CLASS_JA = {
    "government": "政府・公的機関",
    "vendor": "ベンダー",
    "research": "研究機関",
    "news": "報道",
    "state_media": "国営メディア",
    "other": "その他",
}
REASON_JA = {
    "no_neighbor_relation": "周辺諸国との関係なし",
    "out_of_scope": "対象外",
    "duplicate_of_entry": "既存エントリと重複",
    "insufficient_evidence": "根拠不足",
    "marketing": "宣伝・広報",
    "mentioned_only": "言及のみ",
}
COUNTRY_JA = {"CN": "中国", "RU": "ロシア", "KP": "北朝鮮", "KR": "韓国", "TW": "台湾"}


def _confidence(value: str | None) -> str:
    return CONFIDENCE_JA.get(value or "", "不明")


def render_entry(entry: dict) -> list[str]:
    refs = entry.get("references") or []
    lines = [SEP, f"[{entry['entry_id']}] {entry['title']}", SEP, ""]
    lines.append(f"区分: {CATEGORY_JA.get(entry['category'], entry['category'])}")
    lines.append(f"国との関係: {BASIS_JA.get(entry['country_basis'], entry['country_basis'])}")
    if entry.get("original_title"):
        lang = entry.get("original_language") or "不明"
        lines.append(f"原題: {entry['original_title']}（言語: {lang}）")
    attribution = entry.get("attribution")
    if attribution:
        lines += ["", "【帰属（情報源の記述）】",
                  f"{attribution['stated_by']} は次のように述べている: 「{attribution['wording']}」"
                  f"（確度: {_confidence(attribution.get('confidence'))}）",
                  "※ 本レポートが帰属を判断したものではなく、情報源の記述の引用である。"]
    lines += ["", "【事実】"]
    for fact in entry.get("facts", []):
        lines.append(f"・{fact['statement']} [{fact['ref'] + 1}]")
    assessment = entry.get("assessment")
    if assessment:
        lines += ["", "【評価】",
                  f"{assessment['text']}（確度: {_confidence(assessment.get('confidence'))}）"]
    linkage = entry.get("non_cyber_linkage")
    if linkage:
        lines += ["", f"【非サイバー情勢との関連: {CONTEXT_JA.get(linkage['context_type'], linkage['context_type'])}】",
                  f"事実: {linkage['fact']['statement']} [{linkage['fact']['ref'] + 1}]",
                  f"{linkage['assessment']['text']}"
                  f"（確度: {_confidence(linkage['assessment'].get('confidence'))}）"]
    sa = entry.get("source_assessment") or {}
    lines += ["", "【出典の評価】",
              "一次情報: {} / 独立した情報源: {}件 / 国営メディア等の政府系: {}".format(
                  "はい" if sa.get("primary_source") else "いいえ",
                  sa.get("independent_sources", "不明"),
                  "はい" if sa.get("state_affiliated") else "いいえ")]
    if sa.get("caveat"):
        lines.append(f"注意: {sa['caveat']}")
    related = list(entry.get("related_apt_campaign_ids") or []) + list(entry.get("related_cves") or [])
    if related:
        lines += ["", "【関連】", "・" + " / ".join(related)]
    lines += ["", "【参照】"]
    for i, ref in enumerate(refs, 1):
        meta = [CLASS_JA.get(ref.get("source_class"), "その他")]
        if ref.get("source"):
            meta.insert(0, ref["source"])
        if ref.get("language"):
            meta.append(ref["language"])
        lines.append(f"[{i}] {ref['url']}（{' / '.join(meta)}）")
    lines.append("")
    return lines


def render(report: dict, enabled_order: list[str] | None = None) -> str:
    """neighbor_context を Section 5 のテキストにする。"""
    nc = report.get("neighbor_context")
    if not isinstance(nc, dict):
        raise SystemExit("neighbor_context が無い")
    meta = report.get("meta") or {}
    entries = nc.get("entries") or []
    scan = nc.get("scan") or {}
    lines = [RULE, HEADING + "（報告専用・予報の入力には使用しない）", RULE, ""]
    if meta.get("report_date"):
        lines.append(f"対象日: {meta['report_date']}")
    lines.append("走査: 候補 {}件 / ゲート対象 {}件 / 処理済 {}件 / 未処理 {}件（状態: {}）".format(
        scan.get("candidates", "—"), scan.get("gated", "—"), scan.get("handled", "—"),
        scan.get("unhandled", "—"), scan.get("status", "—")))
    lines += ["※ 国への該当は『記事がその国に言及している』ことを示すだけで、攻撃の主体を意味しない。",
              "※ 事実は出典番号付きで記し、推測は『（推測）』と確度を付けて分けている。", ""]

    order = list(enabled_order or [])
    for entry in entries:
        if entry["country"] not in order:
            order.append(entry["country"])
    for code in order:
        group = [e for e in entries if e["country"] == code]
        tier = group[0].get("tier") if group else None
        lines.append(f"■ {COUNTRY_JA.get(code, code)}（{code}）" + (f" [{tier}]" if tier else ""))
        lines.append("")
        if not group:
            lines += ["（本日の該当なし）", ""]
            continue
        for entry in group:
            lines += render_entry(entry)

    dispositions = nc.get("dispositions") or []
    excluded = [d for d in dispositions if d.get("decision") == "excluded"]
    if excluded:
        reasons: dict[str, int] = {}
        for d in excluded:
            reasons[d["reason"]] = reasons.get(d["reason"], 0) + 1
        lines += ["【除外サマリー（周辺諸国動向）】"]
        for reason, n in sorted(reasons.items()):
            lines.append(f"・{REASON_JA.get(reason, reason)}: {n}件")
        lines.append("")

    by_cat = {c: sum(1 for e in entries if e["category"] == c) for c in CATEGORY_JA}
    lines.append("周辺諸国動向 — " + " / ".join(f"{CATEGORY_JA[c]}{n}件" for c, n in by_cat.items())
                 + f" / 除外{len(excluded)}件")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="neighbor_context を Section 5 テキストへ変換する")
    parser.add_argument("--date", help="対象日 YYYY-MM-DD（既定: JST の本日）")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument("--append-to-full", action="store_true",
                        help="security-report.txt の末尾へも追記する（見出しが既にあれば何もしない）")
    parser.add_argument("--stdout", action="store_true", help="ファイルへ書かず標準出力へ出す")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    date = args.date or datetime.now(JST).strftime("%Y-%m-%d")
    base = root / "outputs" / date
    report_path = base / f"{date}-security-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))

    # 国の表示順は config の primary → regional（テストでは registry が無くても動く）
    order: list[str] = []
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import watchlist as wl  # noqa: E402
        section = wl.load_config(str(root / "config.yml")).get("neighbor_states") or {}
        for tier in ("primary", "regional"):
            codes = section.get(tier) or []
            order += [str(c).upper() for c in ([codes] if isinstance(codes, str) else codes)]
    except Exception:  # noqa: BLE001 — 順序は表示だけの都合。失敗しても本文は生成する
        order = []

    text = render(report, order)
    if args.stdout:
        sys.stdout.write(text)
        return 0
    out = base / f"{date}-security-report-neighbor.txt"
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
