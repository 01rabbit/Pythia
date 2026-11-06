#!/usr/bin/env python3
"""RSS 機械収集 raw から周辺諸国（Section 5）の候補を列挙する（Step 0.9）。

要件「わが国周辺諸国に関するサイバー関連活動・政策・組織・企業の情報」の収集層。
`neighbor/states.json`（語彙の定義）と `config.yml` の `neighbor_states`（有効にする国）に
従って `security-intel-collector/data/raw/news-*.json` を走査し、国別の候補を作る。

★設計上の約束
- 出力は『報告専用』の候補である。観測（forecaster/observations/）・ベースライン・
  base_rate には入れない。既存の geopolitical_signal 経路（pipeline-1b-apt.md）は変更しない
- 国への該当は『記事がその国に言及している』ことだけを意味する。その国が事象の主体であること
  （帰属）を意味しない。アクター名（actor_hints）だけで一致した候補は
  `country_signal: "actor_hint_only"` として区別し、国名の言及は無かったことを明示する
- 関連度: high = 国の語がタイトルに出現 / medium = 要約のみに出現。
  `config.yml neighbor_states.gate_min_relevance` 以上かつ調査窓内の候補が、Step 2c で
  『採用または理由付き除外』を必須とする対象（ゲート）になる。同一タイトルの重複は
  先頭の候補に集約され、重複側は個別の処理を要しない
- 走査対象は機械収集 raw だけ（Web 検索結果は対象外）。読んだファイルは出力に残る。
  raw の日付は UTC で、JST 実施日 D の当日分は news-(D-1).json にある（watchlist_scan と同じ規則）
- 何も書き換えない（出力は .cache/ のみ）。forecaster/knowledge/ には触れない
- 依存: 標準ライブラリのみ

使い方:
    python3 scripts/neighbor_scan.py --date 2026-11-06 \\
        --window-start "2026-11-05 07:00" --window-end "2026-11-06 07:00" \\
        --output ".cache/daily-security-intel/2026-11-06/neighbor-scan.json"
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from datetime import date, datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import watchlist as wl  # noqa: E402
import watchlist_scan as ws  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_REGISTRY = os.path.join(REPO_ROOT, "neighbor", "states.json")
RELEVANCE_RANK = {"low": 0, "medium": 1, "high": 2}
DEFAULT_GATE_MIN = "high"

_NON_BOUNDARY = re.compile(r"[぀-ヿ㐀-鿿豈-﫿가-힯]")
_TAG = re.compile(r"<[^>]+>")
_SPACE = re.compile(r"\s+")


# --------------------------------------------------------------------------
# 照合
# --------------------------------------------------------------------------

def compile_term(term: str) -> re.Pattern:
    """語を正規表現にする（neighbor/states.json _term_syntax 参照）。

    - 日本語・中国語・ハングルを含む語は部分一致（単語境界の概念がない）
    - それ以外（ASCII・キリル文字）は単語境界。'*' は前方一致（\\w*）
    - 空白は任意個の空白に一致
    """
    parts = term.strip().split("*")
    body = r"\w*".join(re.escape(p).replace(r"\ ", r"\s+") for p in parts)
    if _NON_BOUNDARY.search(term):
        return re.compile(body, re.IGNORECASE)
    return re.compile(rf"(?<!\w){body}(?!\w)", re.IGNORECASE)


def clean_text(text: str | None) -> str:
    """要約の HTML を落とし、空白と引用符を正規化する。"""
    if not text:
        return ""
    plain = html.unescape(_TAG.sub(" ", str(text)))
    plain = plain.replace("’", "'").replace("‘", "'")
    return _SPACE.sub(" ", plain).strip()


def title_key(title: str | None) -> str:
    """重複判定用のタイトル正規化キー（英数字と CJK 以外を落として小文字化）。"""
    return re.sub(r"[\W_]+", "", clean_text(title).lower())


class CountryMatcher:
    def __init__(self, code: str, spec: dict, tier: str):
        self.code = code
        self.tier = tier
        self.name_ja = spec.get("name_ja", code)
        self.state = [(t, compile_term(t)) for t in spec.get("state_terms", [])]
        self.hints = [(t, compile_term(t)) for t in spec.get("actor_hints", [])]

    def scan(self, title: str, summary: str) -> dict | None:
        hits = {"state_terms": {"title": [], "summary": []},
                "actor_hints": {"title": [], "summary": []}}
        for kind, patterns in (("state_terms", self.state), ("actor_hints", self.hints)):
            for term, pat in patterns:
                if pat.search(title):
                    hits[kind]["title"].append(term)
                elif pat.search(summary):
                    hits[kind]["summary"].append(term)
        has_state = bool(hits["state_terms"]["title"] or hits["state_terms"]["summary"])
        has_hint = bool(hits["actor_hints"]["title"] or hits["actor_hints"]["summary"])
        if not (has_state or has_hint):
            return None
        in_title = bool(hits["state_terms"]["title"] or hits["actor_hints"]["title"])
        return {
            "country": self.code,
            "name_ja": self.name_ja,
            "tier": self.tier,
            "relevance": "high" if in_title else "medium",
            # 国名の言及がある（state_term）か、アクター名のみ（actor_hint_only）か
            "country_signal": "state_term" if has_state else "actor_hint_only",
            "matched": hits,
        }


def build_matchers(registry: dict, config: dict) -> list[CountryMatcher]:
    section = config.get("neighbor_states") or {}
    countries = registry.get("countries") or {}
    matchers: list[CountryMatcher] = []
    seen: set[str] = set()
    for tier in ("primary", "regional"):
        codes = section.get(tier) or []
        if isinstance(codes, str):
            codes = [codes]
        for code in codes:
            code = str(code).upper()
            if code in seen:
                continue
            if code not in countries:
                raise SystemExit(f"config.yml neighbor_states.{tier} の '{code}' が "
                                 f"neighbor/states.json に定義されていない")
            seen.add(code)
            matchers.append(CountryMatcher(code, countries[code], tier))
    return matchers


# --------------------------------------------------------------------------
# 走査
# --------------------------------------------------------------------------

def scan_items(items: list[dict], matchers: list[CountryMatcher],
               window) -> tuple[list[dict], int]:
    candidates: list[dict] = []
    neighbor_feed_unmatched = 0
    for item in items:
        title = clean_text(item.get("title"))
        summary = clean_text(item.get("summary"))
        tags = [str(t) for t in (item.get("tags") or [])]
        hits = [m for m in (mt.scan(title, summary) for mt in matchers) if m]
        if not hits:
            if "neighbor_region" in tags:
                neighbor_feed_unmatched += 1
            continue
        published = ws.parse_iso(item.get("published_at"))
        in_window: bool | None = None
        if window is not None:
            in_window = (published is not None) and (window[0] <= published <= window[1])
        best = max(RELEVANCE_RANK[h["relevance"]] for h in hits)
        candidates.append({
            "candidate_id": item.get("id") or item.get("url"),
            "title": item.get("title"),
            "url": item.get("url"),
            "source": item.get("source"),
            "language": item.get("language"),
            "tags": tags,
            "source_flags": {
                "state_media": "state_media" in tags,
                "neighbor_region": "neighbor_region" in tags,
                "government": "government" in tags,
            },
            "published_at": item.get("published_at"),
            "in_window": in_window,
            "relevance": next(k for k, v in RELEVANCE_RANK.items() if v == best),
            "countries": hits,
            "title_key": title_key(item.get("title")),
            "duplicate_of": None,
        })
    # 同一タイトルは先頭（窓内・新しい順で並べた最初）の候補に集約する
    candidates.sort(key=lambda c: (
        0 if c["in_window"] in (True, None) else 1,
        -(ws.parse_iso(c["published_at"]) or datetime.min.replace(tzinfo=timezone.utc)).timestamp(),
    ))
    first_by_key: dict[str, str] = {}
    for cand in candidates:
        key = cand["title_key"]
        if not key:
            continue
        if key in first_by_key:
            cand["duplicate_of"] = first_by_key[key]
        else:
            first_by_key[key] = cand["candidate_id"]
    return candidates, neighbor_feed_unmatched


def is_gated(cand: dict, gate_min: str) -> bool:
    """Step 2c で『採用または理由付き除外』を必須とする候補か。"""
    return (cand["in_window"] is True
            and cand["duplicate_of"] is None
            and RELEVANCE_RANK[cand["relevance"]] >= RELEVANCE_RANK[gate_min])


def build(day: date, raw_dir: str, registry: dict, config: dict, window,
          gate_min: str, registry_path: str = DEFAULT_REGISTRY) -> dict:
    matchers = build_matchers(registry, config)
    paths = ws.candidate_files(raw_dir, day)
    items = ws.load_items(paths)
    candidates, unmatched = scan_items(items, matchers, window) if matchers else ([], 0)
    for cand in candidates:
        cand["gated"] = is_gated(cand, gate_min)
    by_country: dict[str, dict] = {m.code: {"high": 0, "medium": 0, "tier": m.tier} for m in matchers}
    for cand in candidates:
        for hit in cand["countries"]:
            by_country[hit["country"]][hit["relevance"]] += 1
    return {
        "generated_at": datetime.now(ws.JST).isoformat(timespec="seconds"),
        "date": day.isoformat(),
        "window": ({"from": window[0].isoformat(), "to": window[1].isoformat()} if window else None),
        "status": "ok" if matchers else "disabled",
        "registry": {"path": os.path.relpath(registry_path, REPO_ROOT),
                     "schema_version": registry.get("_schema_version")},
        "countries": [{"code": m.code, "tier": m.tier} for m in matchers],
        "gate_min_relevance": gate_min,
        "files": [os.path.relpath(p, REPO_ROOT) for p in paths],
        "scanned_items": len(items),
        "counts": {
            "candidates": len(candidates),
            "in_window": sum(1 for c in candidates if c["in_window"]),
            "duplicates": sum(1 for c in candidates if c["duplicate_of"]),
            "gated": sum(1 for c in candidates if c["gated"]),
            "actor_hint_only": sum(1 for c in candidates
                                   if all(h["country_signal"] == "actor_hint_only" for h in c["countries"])),
            "neighbor_feed_unmatched": unmatched,
            "by_country": by_country,
        },
        "candidates": candidates,
    }


# --------------------------------------------------------------------------
# 出力
# --------------------------------------------------------------------------

def render_markdown(data: dict) -> str:
    lines = [f"### Step 0.9 周辺諸国候補の走査（{data['date']}）", ""]
    if data["status"] != "ok":
        lines.append("- 周辺諸国: 無効（config.yml の neighbor_states が空）")
        return "\n".join(lines)
    c = data["counts"]
    enabled = ", ".join("%s(%s)" % (x["code"], x["tier"]) for x in data["countries"])
    lines += [
        f"- 有効な国: {enabled}",
        f"- 走査ファイル: {', '.join(data['files']) or '（なし）'}（記事 {data['scanned_items']}件）",
        f"- 候補: **{c['candidates']}件**（窓内 {c['in_window']} / 重複 {c['duplicates']} /"
        f" アクター名のみ {c['actor_hint_only']}）",
        f"- **ゲート対象（関連度 {data['gate_min_relevance']} 以上・窓内・重複除く）: {c['gated']}件**",
        f"- 国別（high/medium）: " + " / ".join(
            f"{k} {v['high']}/{v['medium']}" for k, v in c["by_country"].items()),
        f"- 周辺諸国タグのフィードで語に一致しなかった記事: {c['neighbor_feed_unmatched']}件",
        "",
        "**ゲート対象は Step 2c で必ず『採用』または『除外（理由付き）』に割り当てること。**",
        "国への該当は『記事がその国に言及している』だけを意味し、帰属ではない。",
        "`アクター名のみ` は国名の言及が無い候補で、国家帰属を記録してはならない（行動原則3）。",
        "",
    ]
    gated = [x for x in data["candidates"] if x["gated"]]
    if not gated:
        lines.append("（ゲート対象なし）")
        return "\n".join(lines)
    lines += ["| ID | 国 | 関連度 | 言語 | ソース | 区分 | タイトル |", "|---|---|---|---|---|---|---|"]
    for cand in gated:
        countries = ",".join(
            h["country"] + ("*" if h["country_signal"] == "actor_hint_only" else "")
            for h in cand["countries"])
        flags = ",".join(k for k, v in cand["source_flags"].items() if v) or "—"
        title = (cand.get("title") or "")[:70].replace("|", "\\|")
        lines.append(f"| {cand['candidate_id']} | {countries} | {cand['relevance']} |"
                     f" {cand.get('language') or '—'} | {cand.get('source') or ''} | {flags} | {title} |")
    lines += ["", "（国名の * はアクター名のみで一致。国名の言及なし）", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="周辺諸国（Section 5）の候補を列挙する")
    parser.add_argument("--date", required=True, help="レポート日付（JST・YYYY-MM-DD）")
    parser.add_argument("--raw-dir", default=ws.DEFAULT_RAW_DIR)
    parser.add_argument("--config", default=wl.DEFAULT_CONFIG_PATH, help="config.yml のパス")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY, help="neighbor/states.json のパス")
    parser.add_argument("--window-start", help='調査窓の開始（JST。例: "2026-11-05 07:00"）')
    parser.add_argument("--window-end", help='調査窓の終了（JST。例: "2026-11-06 07:00"）')
    parser.add_argument("--gate-min", choices=sorted(RELEVANCE_RANK, key=RELEVANCE_RANK.get),
                        help="ゲート対象の関連度下限（既定: config.yml の gate_min_relevance）")
    parser.add_argument("--output", help="結果 JSON の保存先（.cache/ 配下を推奨）")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    args = parser.parse_args()

    day = date.fromisoformat(args.date)
    window = None
    if args.window_start or args.window_end:
        if not (args.window_start and args.window_end):
            parser.error("--window-start と --window-end は両方指定する")
        window = (ws.parse_jst(args.window_start), ws.parse_jst(args.window_end))
    with open(args.registry, encoding="utf-8") as fh:
        registry = json.load(fh)
    config = wl.load_config(args.config)
    gate_min = args.gate_min or (config.get("neighbor_states") or {}).get(
        "gate_min_relevance", DEFAULT_GATE_MIN)
    if gate_min not in RELEVANCE_RANK:
        parser.error(f"gate_min_relevance が不正: {gate_min!r}")

    data = build(day, args.raw_dir, registry, config, window, gate_min, args.registry)
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"保存: {args.output}", file=sys.stderr)
    print(json.dumps(data, ensure_ascii=False, indent=2) if args.format == "json"
          else render_markdown(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
