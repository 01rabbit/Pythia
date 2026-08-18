#!/usr/bin/env python3
"""日次レポートの JSON と派生テキスト5種の整合性を機械的に検査する。

Pythia では `security-report.json` が唯一の一次出力（source of truth）であり、
観測（forecaster/observations/）→ ベースライン → 予報の base_rate はすべてこの JSON から
派生する。一方、配布されるテキスト5種は Step 3 でエージェントが JSON から書き起こしている。
**書き起こしの過程で両者が食い違うと、人が読む記録と機械が学習する記録が乖離する。**

過去実績（51日分）を調査したところ、5日分で「テキストにあって JSON に存在しない CVE ID」が
検出された。例:

  2026-07-28  ISC BIND 同時修正9件のうち8件（CVE-2026-10822 ほか）がテキスト本文にのみ存在
  2026-08-17  繰り越し予報の言及（fc-20260816-1 / CVE-2026-8452）がテキスト本文にのみ存在

いずれもテキスト側のほうが情報が多く、その差分は観測に取り込まれない。
本スクリプトはこの乖離をコミット前に検出する（SKILL.md Step 4 のバリデーション群）。

検査項目:
  [E] 必須ファイル（JSON + テキスト5種）の存在
  [E] statistics の各カウントと配列長の一致
  [E] テキストにあって JSON に存在しない CVE ID（＝書き起こし時に増えた情報）
  [E] 採用CVEが全セクション版テキストおよび対応する分割テキストに出現すること
  [E] meta.sweep.unhandled が 0 であること（網羅スイープ突合の結果・SKILL.md Step 3.9）
  [W] meta.sweep 自体が無い（スイープ未実施の可能性）

使い方:
    # 当日分を検査（既定は JST の本日）
    python3 scripts/check_report_consistency.py

    # 日付を指定
    python3 scripts/check_report_consistency.py --date 2026-08-18

    # 全履歴を一括検査（回帰確認用）
    python3 scripts/check_report_consistency.py --all

既知の未修正分（本スクリプト導入時点の実測ベースライン・`--all` で再現する）:
  2026-06-30 / 2026-07-28 / 2026-08-08 / 2026-08-09 / 2026-08-17  テキストのみに存在するCVE ID
  2026-07-14  statistics.soc_recommendations.excluded=8 だが exclusions.soc_recommendations は空

過去レポートは当時の観測記録であり Git 履歴が長期記憶であるため（行動原則6）、
本スクリプトは過去分を遡って書き換えない。日次実行では `--date` で当日分のみを検査する。

終了コード: 0=エラーなし / 1=エラーあり（警告のみなら 0）

★このスクリプトは読み取り専用であり、forecaster/knowledge/ を含む一切のファイルを
書き換えない（CLAUDE.md 行動原則5）。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

JST = timezone(timedelta(hours=9))

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

# 採用CVEを格納するトップレベル配列 → 出現すべき分割テキストの接尾辞
CVE_SECTIONS = {
    "zero_day_special": "-cve",
    "main_cve": "-cve",
    "reference_a": "-cve",
    "reference_b": "-cve",
}

TEXT_SUFFIXES = ("", "-cve", "-zeroday-trends", "-ai", "-soc")

# statistics のキー → 対応する配列のパス（トップレベル名、またはネスト）
STAT_CHECKS = [
    ("cve", "zero_day", ("zero_day_special",)),
    ("cve", "main", ("main_cve",)),
    ("cve", "reference_a", ("reference_a",)),
    ("cve", "reference_b", ("reference_b",)),
    ("apt", "main", ("apt_main",)),
    ("apt", "notable", ("apt_notable",)),
    ("ai_attacks", "main", ("ai_attacks_main",)),
    ("ai_attacks", "reference_a", ("ai_attacks_reference_a",)),
    ("ai_attacks", "reference_b", ("ai_attacks_reference_b",)),
]

EXCLUSION_CHECKS = [
    ("cve", "excluded", "cve"),
    ("apt", "excluded", "apt"),
    ("ai_attacks", "excluded", "ai_attacks"),
    ("soc_recommendations", "excluded", "soc_recommendations"),
]


def dig(data: dict, path: tuple[str, ...]) -> object:
    node: object = data
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def report_paths(root: Path, date: str) -> dict[str, Path]:
    base = root / "outputs" / date
    paths = {"json": base / f"{date}-security-report.json"}
    for suffix in TEXT_SUFFIXES:
        paths[suffix or "full"] = base / f"{date}-security-report{suffix}.txt"
    return paths


def check_date(root: Path, date: str, *, skip_if_no_json: bool = False) -> tuple[list[str], list[str]]:
    """1日分を検査し (errors, warnings) を返す。

    skip_if_no_json=True のときは JSON が無い日を検査対象外として扱う
    （--all での一括検査用。JSON 出力を導入する以前の旧形式レポートが outputs/ に残っている）。
    """
    errors: list[str] = []
    warnings: list[str] = []
    paths = report_paths(root, date)

    if not paths["json"].is_file():
        if skip_if_no_json:
            return ([], [])
        return ([f"{date}: JSON が存在しない: {paths['json']}"], [])

    raw = paths["json"].read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as err:
        return ([f"{date}: JSON をパースできない: {err}"], [])

    json_cves = set(CVE_RE.findall(raw))

    missing_texts = [key for key, path in paths.items() if key != "json" and not path.is_file()]
    for key in missing_texts:
        errors.append(f"{date}: テキストが存在しない: {paths[key].name}")

    # --- statistics と配列長の一致 ---
    stats = data.get("statistics") or {}
    for group, key, path in STAT_CHECKS:
        declared = dig(stats, (group, key))
        if declared is None:
            continue
        actual = dig(data, path)
        actual_len = len(actual) if isinstance(actual, list) else 0
        if declared != actual_len:
            errors.append(
                f"{date}: statistics.{group}.{key}={declared} だが {'.'.join(path)} の要素数は {actual_len}"
            )

    exclusions = data.get("exclusions") or {}
    for group, key, excl_key in EXCLUSION_CHECKS:
        declared = dig(stats, (group, key))
        if declared is None:
            continue
        actual = exclusions.get(excl_key)
        actual_len = len(actual) if isinstance(actual, list) else 0
        if declared != actual_len:
            errors.append(
                f"{date}: statistics.{group}.{key}={declared} だが exclusions.{excl_key} の要素数は {actual_len}"
            )

    # --- テキストにあって JSON に無い CVE ID ---
    # 逆方向（JSON にあってテキストに無い）は下の採用CVE検査で個別に見る。
    # ここで検出されるのは「書き起こし時に増えた情報」であり、観測に取り込まれない差分である。
    for key, path in paths.items():
        if key == "json" or not path.is_file():
            continue
        text_cves = set(CVE_RE.findall(path.read_text(encoding="utf-8")))
        orphans = sorted(text_cves - json_cves)
        if orphans:
            errors.append(
                f"{date}: {path.name} に JSON へ存在しない CVE ID がある "
                f"({len(orphans)}件: {', '.join(orphans[:6])}{' ほか' if len(orphans) > 6 else ''})"
                " — JSON 側へ反映するかテキストから除くこと"
            )

    # --- 採用CVEがテキストへ出現するか ---
    full_path = paths["full"]
    full_text = full_path.read_text(encoding="utf-8") if full_path.is_file() else ""
    for section, suffix in CVE_SECTIONS.items():
        entries = data.get(section)
        if not isinstance(entries, list):
            continue
        split_path = paths[suffix]
        split_text = split_path.read_text(encoding="utf-8") if split_path.is_file() else ""
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            cve_id = entry.get("cve_id")
            if not cve_id:
                continue
            if full_text and cve_id not in full_text:
                errors.append(f"{date}: {section} の {cve_id} が {full_path.name} に出現しない")
            if split_text and cve_id not in split_text:
                errors.append(f"{date}: {section} の {cve_id} が {split_path.name} に出現しない")

    # --- 網羅スイープ突合の結果（SKILL.md Step 3.9）---
    sweep = (data.get("meta") or {}).get("sweep")
    if sweep is None:
        warnings.append(
            f"{date}: meta.sweep が無い（Step 0.7 の網羅スイープ未実施の可能性。"
            "pipeline-output-schema.md「meta.sweep」参照）"
        )
    elif isinstance(sweep, dict):
        status = sweep.get("status")
        if status == "failed":
            warnings.append(f"{date}: meta.sweep.status=failed（スイープ取得失敗が記録されている）")
        else:
            unhandled = sweep.get("unhandled")
            if unhandled is None:
                warnings.append(f"{date}: meta.sweep.unhandled が未記録")
            elif unhandled != 0:
                errors.append(
                    f"{date}: meta.sweep.unhandled={unhandled}（未処理を残したままコミットしてはならない）"
                )

    return errors, warnings


def discover_dates(root: Path) -> list[str]:
    outputs = root / "outputs"
    if not outputs.is_dir():
        return []
    return sorted(
        path.name for path in outputs.iterdir()
        if path.is_dir() and re.fullmatch(r"\d{4}-\d{2}-\d{2}", path.name)
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="日次レポート JSON と派生テキストの整合性を検査する（読み取り専用）",
    )
    parser.add_argument("--date", help="検査する日付 YYYY-MM-DD（既定: JST の本日）")
    parser.add_argument("--all", action="store_true", help="outputs/ 配下の全日付を検査する")
    parser.add_argument("--root", default=".", help="リポジトリルート（既定: カレント）")
    parser.add_argument("--quiet", action="store_true", help="エラー・警告のみ出力する")
    args = parser.parse_args()

    root = Path(args.root).resolve()

    if args.all:
        dates = discover_dates(root)
        if not dates:
            print("outputs/ に検査対象が無い", file=sys.stderr)
            return 1
    else:
        dates = [args.date or datetime.now(JST).strftime("%Y-%m-%d")]

    total_errors: list[str] = []
    total_warnings: list[str] = []
    checked = 0
    for date in dates:
        if args.all and not report_paths(root, date)["json"].is_file():
            continue  # JSON 導入以前の旧形式レポート
        checked += 1
        errors, warnings = check_date(root, date, skip_if_no_json=args.all)
        total_errors.extend(errors)
        total_warnings.extend(warnings)

    for message in total_warnings:
        print(f"[WARN] {message}")
    for message in total_errors:
        print(f"[ERROR] {message}")

    if not args.quiet:
        print(
            f"\n検査対象 {checked}日分 / エラー {len(total_errors)}件 / 警告 {len(total_warnings)}件"
        )
        if not total_errors:
            print("JSON と派生テキストの整合性に問題なし。")

    return 1 if total_errors else 0


if __name__ == "__main__":
    sys.exit(main())
