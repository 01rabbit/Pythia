#!/usr/bin/env python3
"""Google Project Zero「0-day In the Wild」データセットからゼロデイの過去分布を抽出する。

目的:
  「どのベンダー・製品カテゴリで in-the-wild ゼロデイが出やすいか」の過去分布を
  出典付き（cited）の知識として蓄積する。Section 2 ゼロデイ特報の文脈付け・
  Step C'''（一次出典付き過去事案）の参照材料。

本統計が測るもの・測らないもの（誤用防止）:
  - 測るもの: 「in-the-wild 悪用が確認され、かつ検知・公表されたゼロデイ」の
    ベンダー・製品・脆弱性種別ごとの過去分布（検知集合の条件付き分布）。
  - 測らないもの: ゼロデイの真の発生率。検知バイアス（検知能力の高いベンダー
    製品ほど計上されやすい）と公表バイアスを含む。予測確率の直接根拠にしない。

設計原則:
  - 出典は Google Project Zero が維持する公開データセット（各行に CVE・ベンダー
    advisory URL 付き）。推測による追加はしない。
  - 出力は forecaster/knowledge/ の機械生成ファイル。自動書き換え禁止ルールに
    従い、再生成は日次ルーチンからは行わず PR 提案+人間レビュー経由のみ。
  - 日次予報ステージの必須入力にはしない（参照は Step C''' の過去事案文脈のみ）。

入力:
  Google Sheets（P0 0day ITW）を年シートごとに gviz JSON で取得
  （--cache-dir 指定でローカルキャッシュ利用可）

出力:
  forecaster/knowledge/zeroday-itw-priors.json

使い方:
    python3 scripts/build_zeroday_itw_priors.py
    python3 scripts/build_zeroday_itw_priors.py --cache-dir /path/to/cache
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import date

from product_categories import build_resolver

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(REPO_ROOT, "forecaster", "knowledge", "zeroday-itw-priors.json")
PRODUCT_CATEGORIES_PATH = os.path.join(
    REPO_ROOT, "forecaster", "knowledge", "product-categories.json"
)

SHEET_ID = "1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY"
GVIZ_URL = (
    "https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq"
    "?tqx=out:json&sheet={sheet}"
)
DATASET_HOME = (
    "https://googleprojectzero.blogspot.com/p/0day.html"
)
FIRST_YEAR = 2014
REQUEST_INTERVAL_SEC = 0.5

GVIZ_DATE_RE = re.compile(r"^Date\((\d+),(\d+),(\d+)")


def fetch_sheet(year, cache_dir):
    """年シートの gviz JSON を取得して table dict を返す（無ければ None）。"""
    cache_path = os.path.join(cache_dir, f"p0-{year}.json") if cache_dir else None
    if cache_path and os.path.exists(cache_path):
        raw = open(cache_path).read()
    else:
        url = GVIZ_URL.format(sheet_id=SHEET_ID, sheet=year)
        req = urllib.request.Request(
            url, headers={"User-Agent": "pythia-zeroday-priors/1.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode("utf-8", "replace")
        except Exception as e:
            print(f"[warn] {year} シート取得失敗: {e}")
            return None
        if cache_path:
            with open(cache_path, "w") as f:
                f.write(raw)
        time.sleep(REQUEST_INTERVAL_SEC)
    m = re.search(r"setResponse\((.*)\);?\s*$", raw, re.S)
    if not m:
        return None
    data = json.loads(m.group(1))
    if data.get("status") != "ok":
        return None
    return data.get("table")


def cell_value(cell):
    """gviz セルから値を取り出す。Date(YYYY,M,D) は ISO 日付へ（月は0始まり）。"""
    if not cell:
        return None
    v = cell.get("v")
    if isinstance(v, str):
        m = GVIZ_DATE_RE.match(v)
        if m:
            y, mo, d = (int(x) for x in m.groups())
            return f"{y:04d}-{mo + 1:02d}-{d:02d}"
        return v.strip() or None
    return v


def build_category_resolver():
    """product-categories.json から resolver を返す（cve なしの text 照合）。
    照合ロジックは scripts/product_categories.py に集約。
    辞書が読めない場合は fail-fast（無言で全カテゴリ空のファイルを生成しない）。"""
    match, schema_version = build_resolver(PRODUCT_CATEGORIES_PATH)
    if schema_version is None:
        raise SystemExit(
            f"[fatal] {PRODUCT_CATEGORIES_PATH} を読み込めません。"
            "カテゴリ分布が全て空になるため中断します。"
        )
    return (lambda text: match(text)), schema_version


def main():
    ap = argparse.ArgumentParser(
        description="P0 0-day ITW データセットからゼロデイの過去分布を抽出する。"
    )
    ap.add_argument("--cache-dir", help="年シート gviz JSON のキャッシュディレクトリ")
    ap.add_argument("--out", default=OUT_PATH, help=f"出力先（既定: {OUT_PATH}）")
    args = ap.parse_args()

    resolver, categories_schema_version = build_category_resolver()

    entries = []
    years_fetched = []
    current_year = date.today().year
    for year in range(FIRST_YEAR, current_year + 1):
        table = fetch_sheet(year, args.cache_dir)
        if table is None:
            print(f"[warn] {year} シートなし・スキップ")
            continue
        labels = [c.get("label") or "" for c in table.get("cols", [])]
        idx = {label: i for i, label in enumerate(labels)}
        required = ["CVE", "Vendor", "Product"]
        if not all(k in idx for k in required):
            print(f"[warn] {year} シートの列構成が想定外・スキップ: {labels}")
            continue
        n_rows = 0
        for row in table.get("rows", []):
            cells = row.get("c") or []

            def col(label):
                i = idx.get(label)
                return cell_value(cells[i]) if i is not None and i < len(cells) else None

            cve = col("CVE")
            if not cve or not re.match(r"^CVE-\d{4}-\d{4,}$", str(cve)):
                continue
            entries.append(
                {
                    "cve": cve,
                    "year_sheet": year,
                    "vendor": col("Vendor"),
                    "product": col("Product"),
                    "type": col("Type"),
                    "description": col("Description"),
                    "date_discovered": col("Date Discovered"),
                    "date_patched": col("Date Patched"),
                    "advisory_url": col("Advisory"),
                    "analysis_url": col("Analysis URL"),
                }
            )
            n_rows += 1
        years_fetched.append({"year": year, "n": n_rows})
        print(f"[sheet] {year}: {n_rows} 件")

    by_year = Counter(e["year_sheet"] for e in entries)
    by_vendor = Counter((e["vendor"] or "unknown") for e in entries)
    by_product = Counter((e["product"] or "unknown") for e in entries)
    by_type = Counter((e["type"] or "unknown") for e in entries)

    by_category = defaultdict(Counter)  # category -> year counter
    n_categorized = 0
    for e in entries:
        cats = resolver(" ".join(filter(None, [e["vendor"], e["product"]])))
        if cats:
            n_categorized += 1
        for c in cats:
            by_category[c][e["year_sheet"]] += 1

    recent_start = current_year - 2  # 直近3年（当年含む）
    by_vendor_recent = Counter(
        (e["vendor"] or "unknown")
        for e in entries
        if e["year_sheet"] >= recent_start
    )

    out = {
        "_comment": (
            "Google Project Zero「0-day In the Wild」データセット由来の"
            "ゼロデイ過去分布（cited 知識）。Section 2 ゼロデイ特報の文脈付け・"
            "Step C''' の一次出典付き過去事案参照用。★検知・公表された集合の"
            "条件付き分布であり、ゼロデイの真の発生率ではない。_limitations 厳守。"
        ),
        "_schema_version": "1.0",
        "_machine_generated": True,
        "_generator": "scripts/build_zeroday_itw_priors.py",
        "_generated_on": date.today().isoformat(),
        "_source": {
            "dataset": "Google Project Zero — 0day In the Wild (公開スプレッドシート)",
            "spreadsheet_id": SHEET_ID,
            "dataset_home": DATASET_HOME,
            "product_categories_schema_version": categories_schema_version,
        },
        "_governance": (
            "knowledge/ の自動書き換え禁止ルールに従い、再生成は日次ルーチンからは"
            "行わず、必ず PR として提案し人間レビューを経てコミットする。"
        ),
        "_limitations": [
            "検知バイアス: 計上されるのは『in-the-wild 悪用が検知・公表された』"
            "ゼロデイのみ。検知能力の高いベンダー（Google/Apple/Microsoft 等）の"
            "製品ほど計上されやすく、ベンダー別分布は攻撃面と検知能力の両方を反映する。"
            "検知されないゼロデイは母集団に存在しない。",
            "キュレーション依存: データセットは Google Project Zero（第三者）の"
            "収載基準に依存する。年途中のシートは未確定（今後も追記される）。",
            "用途制限: ゼロデイ報道の文脈付け・過去事例参照（Step C'''）に限る。"
            "『このカテゴリでゼロデイが出る確率』の定量根拠・予報の確度引き上げ・"
            "hit_criteria の変更には使わない。",
            "カテゴリ被覆: 製品カテゴリは product-categories.json の単語境界マッチ"
            "（自観測由来の辞書・選択バイアスあり）。P0 データはブラウザ・OS・"
            "モバイル中心のため未分類が残る。categorized_count を必ず併読する。",
            "日付欄: date_discovered は『???』等の欠測を含む（P0 原文のまま）。",
        ],
        "population": {
            "total_entries": len(entries),
            "years": years_fetched,
            "categorized_count": n_categorized,
            "uncategorized_count": len(entries) - n_categorized,
            "category_coverage": (
                round(n_categorized / len(entries), 3) if entries else None
            ),
            "low_coverage_warning": (
                len(entries) > 0 and n_categorized / len(entries) < 0.5
            ),
            "coverage_note": (
                "製品カテゴリ辞書は自観測由来で P0 主力（Android/iOS/WebKit/Windows単独/"
                "Adobe/Qualcomm 等）を収録しないため被覆率は低い。ベンダー別分布"
                "（by_vendor_*）の方が P0 データでは情報量が大きい。"
            ),
        },
        "by_year": {str(y): by_year[y] for y in sorted(by_year)},
        "by_vendor_alltime_top": dict(by_vendor.most_common(20)),
        "by_vendor_recent_3y": dict(by_vendor_recent.most_common(15)),
        "by_product_alltime_top": dict(by_product.most_common(20)),
        "by_vuln_type": dict(by_type.most_common()),
        "by_product_category_yearly": {
            cat: {str(y): c[y] for y in sorted(c)}
            for cat, c in sorted(by_category.items())
        },
        "entries": entries,
    }
    with open(args.out, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(
        f"[done] {os.path.relpath(args.out, REPO_ROOT)}: "
        f"{len(entries)} 件（{FIRST_YEAR}〜{current_year}）"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
