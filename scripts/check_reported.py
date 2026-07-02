#!/usr/bin/env python3
"""既報リスト（reported-*.md）の整合性チェッカー。

reported-cves.md / reported-apts.md / reported-ai-attacks.md の Markdown テーブルを
機械的に検査し、以下の違反を検出する:

  (a) 重複キー検知
      - reported-cves.md: CVE-ID 列（1セル内の複数CVE-IDはそれぞれ個別キーとして展開）
      - reported-apts.md: 活動ID / キャンペーン名 列
      - reported-ai-attacks.md: インシデント名 / CVE等 列
  (b) 1行複数 CVE-ID 検知
      - reported-cves.md の CVE-ID 列に " / " 区切りで複数の CVE-ID が入っている行
        （campaign_id 側の複数グループ関連URL等は対象外・CVE-ID 列のみ検査）
  (c) exploitation_stage 語彙違反検知
      - reported-cves.md の exploitation_stage 列が
        active_exploitation / kev_listed / poc_public / none の4値以外

違反は「ファイル:行番号: 内容」形式で列挙し exit 1、違反なしで exit 0 とする。
自動修正は行わない（データ側の修復は別作業）。

依存: Python 3 標準ライブラリのみ。

使い方:
    python3 scripts/check_reported.py
"""

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CVES_FILE = os.path.join(REPO_ROOT, "reported-cves.md")
APTS_FILE = os.path.join(REPO_ROOT, "reported-apts.md")
AI_ATTACKS_FILE = os.path.join(REPO_ROOT, "reported-ai-attacks.md")

# reported-cves.md の exploitation_stage 許容語彙（4値のみ）
ALLOWED_EXPLOITATION_STAGES = {
    "active_exploitation",
    "kev_listed",
    "poc_public",
    "none",
}

# CVE-ID の正規表現（1トークン）
RE_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Markdown テーブル区切り行（| --- | --- | ...）の判定
RE_TABLE_SEPARATOR = re.compile(r"^\|[\s:-]+\|[\s:|-]*$")


class Reporter:
    def __init__(self):
        self.violations = []

    def add(self, fname, lineno, message):
        rel = os.path.relpath(fname, REPO_ROOT)
        self.violations.append(f"{rel}:{lineno}: {message}")

    @property
    def count(self):
        return len(self.violations)


def split_row(line):
    """`| a | b | c |` 形式の行をセル配列に分解する。先頭・末尾の空セルは除去する。"""
    stripped = line.strip()
    if not stripped.startswith("|"):
        return None
    cells = stripped.split("|")
    # 先頭・末尾は `|` の外側にできる空文字列
    cells = cells[1:-1] if len(cells) >= 2 else cells
    return [c.strip() for c in cells]


def iter_table_rows(path):
    """Markdown テーブルのデータ行を (行番号, セル配列) で列挙する。
    ヘッダ行・区切り行（|---|---|）はスキップする。
    """
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()

    header_seen = False
    for i, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\n")
        if not line.strip().startswith("|"):
            continue
        if RE_TABLE_SEPARATOR.match(line.strip()):
            header_seen = True
            continue
        cells = split_row(line)
        if cells is None:
            continue
        if not header_seen:
            # ヘッダ行そのもの（区切り行の前）はスキップ
            continue
        yield i, cells


def check_duplicate_keys(rep, path, key_col_index, label):
    """指定列をキーとして重複検知する。同一キーが複数行に出現したら違反として報告する。"""
    seen = {}
    for lineno, cells in iter_table_rows(path):
        if key_col_index >= len(cells):
            continue
        key = cells[key_col_index]
        if not key:
            continue
        if key in seen:
            rep.add(
                path, lineno,
                f"重複キー検知（{label}）: {key!r}（初出: 行{seen[key]}）",
            )
        else:
            seen[key] = lineno


def check_multi_cve_per_line(rep, path, cve_col_index):
    """CVE-ID 列に複数の CVE-ID が ' / ' 区切りで入っている行を検知する。"""
    for lineno, cells in iter_table_rows(path):
        if cve_col_index >= len(cells):
            continue
        cell = cells[cve_col_index]
        if not cell:
            continue
        tokens = [t.strip() for t in cell.split("/")]
        cve_tokens = [t for t in tokens if RE_CVE_ID.match(t)]
        if len(cve_tokens) > 1:
            rep.add(
                path, lineno,
                f"1行複数CVE-ID検知: {cell!r}（{len(cve_tokens)}件のCVE-IDを検出。"
                f"1行1CVE-IDに分割が必要）",
            )


def check_exploitation_stage(rep, path, stage_col_index):
    """exploitation_stage 列が許容4値以外を検知する。"""
    for lineno, cells in iter_table_rows(path):
        if stage_col_index >= len(cells):
            continue
        stage = cells[stage_col_index]
        if not stage:
            continue
        if stage not in ALLOWED_EXPLOITATION_STAGES:
            rep.add(
                path, lineno,
                f"exploitation_stage 語彙違反: {stage!r}"
                f"（許容値: {sorted(ALLOWED_EXPLOITATION_STAGES)}）",
            )


def main():
    rep = Reporter()

    # --- reported-cves.md ---
    # | CVE-ID | 製品名 | 初報日 | exploitation_stage | 最終更新日 | 継続監視 | 備考 |
    #     0        1        2            3                 4           5        6
    check_duplicate_keys(rep, CVES_FILE, 0, "CVE-ID")
    check_multi_cve_per_line(rep, CVES_FILE, 0)
    check_exploitation_stage(rep, CVES_FILE, 3)

    # --- reported-apts.md ---
    # | グループ名 | 活動ID / キャンペーン名 | 初報日 | 最終状態 | 最終更新日 | 継続監視 | 備考 |
    #      0                  1                    2         3          4           5        6
    check_duplicate_keys(rep, APTS_FILE, 1, "活動ID/キャンペーン名")

    # --- reported-ai-attacks.md ---
    # | インシデント名 / CVE等 | カテゴリ | 初報日 | 最終状態 | 最終更新日 | 継続監視 | 備考 |
    #            0                 1         2         3          4           5        6
    check_duplicate_keys(rep, AI_ATTACKS_FILE, 0, "インシデント名/CVE等")

    if rep.violations:
        for line in rep.violations:
            print(line)
        print(f"\nNG: 違反 {rep.count} 件。", file=sys.stderr)
        sys.exit(1)

    print("OK: 違反 0 件。")
    sys.exit(0)


if __name__ == "__main__":
    main()
