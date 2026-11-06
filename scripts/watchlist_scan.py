#!/usr/bin/env python3
"""RSS 機械収集 raw（news-*.json）をウォッチリストで走査し、無条件採用候補を列挙する（Step 0.8）。

`config.yml` の `watchlist:`（cves / products / actors / topics）に該当する記事を
`security-intel-collector/data/raw/news-YYYY-MM-DD.json` から拾い、Step 1b（APT）・
Step 2（動向）・Step 1（CVE 言及）へ「採用条件を満たさなくても採用する候補」として渡す。

★設計上の約束
- 走査対象は機械収集 raw だけ（Web 検索結果は対象外。再現性のため）
- raw ファイル名は UTC 日付。JST 実施日 D の当日分は news-(D-1).json に入っている
  （SKILL.md Step 0.5）ため、既定で news-(D-1).json と news-(D).json の両方を読み、
  無ければ news-latest.json に後退する。読んだファイルは出力に残す
- 調査窓（--window-start / --window-end・JST）を与えると published_at で窓内判定し、
  窓外の該当は「継続フォロー」として分けて出す（捨てない）
- 照合は scripts/watchlist.py の部分一致（大文字小文字無視）。該当語を全件残す
- 何も書き換えない（出力は .cache/ 配下の JSON と標準出力のみ）。knowledge/ 非書込
- 依存: 標準ライブラリのみ

使い方:
    python3 scripts/watchlist_scan.py --date 2026-11-06 \\
        --window-start "2026-11-05 07:00" --window-end "2026-11-06 07:00" \\
        --output ".cache/daily-security-intel/2026-11-06/watchlist-scan.json"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import watchlist as wl  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RAW_DIR = os.path.join(REPO_ROOT, "security-intel-collector", "data", "raw")
JST = timezone(timedelta(hours=9))


def parse_jst(text: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=JST)
        except ValueError:
            continue
    raise SystemExit(f"日時の形式が不正: {text!r}（例: \"2026-11-05 07:00\"）")


def parse_iso(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def candidate_files(raw_dir: str, day: date) -> list[str]:
    """既定の読み込み順: news-(D-1).json, news-(D).json。無ければ news-latest.json。"""
    names = [f"news-{(day - timedelta(days=1)).isoformat()}.json", f"news-{day.isoformat()}.json"]
    paths = [os.path.join(raw_dir, n) for n in names if os.path.exists(os.path.join(raw_dir, n))]
    if not paths:
        latest = os.path.join(raw_dir, "news-latest.json")
        if os.path.exists(latest):
            paths = [latest]
    return paths


def load_items(paths: list[str]) -> list[dict]:
    items: dict[str, dict] = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as err:
            print(f"[warn] 読み込み失敗 {path}: {err}", file=sys.stderr)
            continue
        for item in data.get("items") or []:
            if not isinstance(item, dict):
                continue
            key = item.get("id") or item.get("url")
            if key and key not in items:
                items[key] = item
    return list(items.values())


def scan(watch: dict, items: list[dict], window: tuple[datetime, datetime] | None) -> list[dict]:
    matched: list[dict] = []
    for item in items:
        text = " ".join(str(part) for part in (item.get("title"), item.get("summary")) if part)
        hits = wl.match_item(watch, text=text)
        if not hits:
            continue
        published = parse_iso(item.get("published_at"))
        in_window: bool | None = None
        if window is not None:
            in_window = (published is not None) and (window[0] <= published <= window[1])
        matched.append({
            "id": item.get("id"),
            "title": item.get("title"),
            "url": item.get("url"),
            "source": item.get("source"),
            "language": item.get("language"),
            "published_at": item.get("published_at"),
            "in_window": in_window,
            "matched": hits,
            "matched_flat": wl.flatten_matches(hits),
        })
    # 窓内を先頭に、同じ区分では新しい順
    matched.sort(key=lambda m: ((0 if m["in_window"] in (True, None) else 1),
                                -(parse_iso(m.get("published_at")) or datetime.min.replace(tzinfo=timezone.utc)).timestamp()))
    return matched


def build(day: date, raw_dir: str, watch: dict, window: tuple[datetime, datetime] | None) -> dict:
    paths = candidate_files(raw_dir, day)
    items = load_items(paths)
    matched = scan(watch, items, window) if not wl.is_empty(watch) else []
    by_cat = {cat: 0 for cat in wl.CATEGORIES}
    for m in matched:
        for cat in m["matched"]:
            by_cat[cat] += 1
    return {
        "generated_at": datetime.now(JST).isoformat(timespec="seconds"),
        "date": day.isoformat(),
        "window": ({"from": window[0].isoformat(), "to": window[1].isoformat()} if window else None),
        "watchlist": {
            "status": "disabled" if wl.is_empty(watch) else "ok",
            "source": watch.get("_source"),
            "terms": wl.term_counts(watch),
        },
        "files": [os.path.relpath(p, REPO_ROOT) for p in paths],
        "scanned_items": len(items),
        "counts": {
            "matched": len(matched),
            "in_window": sum(1 for m in matched if m["in_window"]),
            "out_of_window": sum(1 for m in matched if m["in_window"] is False),
            "by_category": by_cat,
        },
        "matched": matched,
    }


def render_markdown(data: dict) -> str:
    c, w = data["counts"], data["watchlist"]
    lines = [f"### Step 0.8 ウォッチリスト走査（{data['date']}）", ""]
    if w["status"] != "ok":
        lines.append("- ウォッチリスト: 無効（config.yml の watchlist が空）")
        return "\n".join(lines)
    t = w["terms"]
    lines += [
        f"- 走査ファイル: {', '.join(data['files']) or '（なし）'}（記事 {data['scanned_items']}件）",
        f"- 語数: cves {t['cves']} / products {t['products']} / actors {t['actors']} / topics {t['topics']}",
        f"- 該当: **{c['matched']}件**"
        + (f"（窓内 {c['in_window']} / 窓外 {c['out_of_window']}）" if data.get("window") else ""),
        "",
        "**該当記事は採用条件（P〜W / α〜η 等）を満たさなくても採用候補とし、**",
        "**Step 1b / Step 2 で必ず「採用」または「除外（理由付き）」のいずれかに割り当てること。**",
        "Technique・帰属の付与は根拠がある場合のみ（行動原則1・3）。ウォッチリスト該当は根拠にならない。",
        "",
    ]
    if not data["matched"]:
        lines.append("（該当なし）")
        return "\n".join(lines)
    lines += ["| 窓 | 公開(UTC) | ソース | 言語 | 該当語 | タイトル | URL |", "|---|---|---|---|---|---|---|"]
    for m in data["matched"]:
        mark = "—" if m["in_window"] is None else ("○" if m["in_window"] else "窓外")
        title = (m.get("title") or "")[:80].replace("|", "\\|")
        lines.append(
            f"| {mark} | {(m.get('published_at') or '')[:16]} | {m.get('source') or ''} |"
            f" {m.get('language') or '—'} | {', '.join(m['matched_flat'])} | {title} | {m.get('url') or ''} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="RSS 機械収集 raw をウォッチリストで走査する")
    parser.add_argument("--date", required=True, help="レポート日付（JST・YYYY-MM-DD）")
    parser.add_argument("--raw-dir", default=DEFAULT_RAW_DIR)
    parser.add_argument("--watchlist", default=wl.DEFAULT_CONFIG_PATH, help="config.yml のパス")
    parser.add_argument("--window-start", help='調査窓の開始（JST。例: "2026-11-05 07:00"）')
    parser.add_argument("--window-end", help='調査窓の終了（JST。例: "2026-11-06 07:00"）')
    parser.add_argument("--output", help="結果 JSON の保存先（.cache/ 配下を推奨）")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    args = parser.parse_args()

    day = date.fromisoformat(args.date)
    window = None
    if args.window_start or args.window_end:
        if not (args.window_start and args.window_end):
            parser.error("--window-start と --window-end は両方指定する")
        window = (parse_jst(args.window_start), parse_jst(args.window_end))
    watch = wl.load_watchlist(args.watchlist)
    data = build(day, args.raw_dir, watch, window)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"保存: {args.output}", file=sys.stderr)
    print(json.dumps(data, ensure_ascii=False, indent=2) if args.format == "json" else render_markdown(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
