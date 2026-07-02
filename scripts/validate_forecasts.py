#!/usr/bin/env python3
"""forecast サイドカー JSON のスキーマバリデータ。

forecaster/forecasts/daily/YYYY-MM-DD.json を
forecaster/schema/forecast.schema.json（v1.0 wrapper 形式）に照らして検査する。

- 依存: Python 3 標準ライブラリのみ（jsonschema 非依存・自前チェック）
- デフォルト: forecaster/forecasts/daily/*.json を全件検査
- --date YYYY-MM-DD で単日指定
- 違反は「ファイル:forecast_id:項目: 内容」形式で列挙し exit 1、全パスで exit 0
- Markdown のみでサイドカー JSON が存在しない日はスキップ対象（存在する .json のみ検査）
- 自動修正は行わない

検査内容:
- wrapper 構造（_schema_version・forecasts 配列・1日最大2件）
- forecast の必須フィールド・許可フィールド（additionalProperties: false 相当）
- enum フィールド（tier / confidence / forecast_class / outcome_channel / window 等）
- forecast_id の形式（fc-YYYYMMDD-N）とファイル名日付・forecast_index との整合
- deadline_date が発行日（ファイル名日付）以降であること
- base_rate_estimate が 0〜1 の範囲であること

使い方:
    python3 scripts/validate_forecasts.py
    python3 scripts/validate_forecasts.py --date 2026-07-02
"""

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime

# リポジトリルート = このスクリプトの親ディレクトリの親
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORECASTS_DIR = os.path.join(REPO_ROOT, "forecaster", "forecasts", "daily")

SCHEMA_VERSION = "1.0"
ALLOWED_SCHEMA_VERSIONS = {"1.0"}

MAX_FORECASTS_PER_DAY = 2

# wrapper で許可するトップレベルキー
ALLOWED_TOP_KEYS = {
    "_schema_version",
    "_forecast_date",
    "_source_markdown",
    "forecasts",
}

# forecast の必須キー
REQUIRED_FORECAST_KEYS = [
    "forecast_id",
    "forecast_index",
    "subject",
    "tier",
    "confidence",
    "forecast_class",
    "outcome_channel",
    "window",
    "deadline_date",
    "hit_criteria",
    "exclusions",
    "base_rate_estimate",
    "related_observation_ids",
]

# forecast で許可するキー（additionalProperties: false 相当）
ALLOWED_FORECAST_KEYS = set(REQUIRED_FORECAST_KEYS) | {
    "forecast_class_rationale",
    "kev_snapshot",
    "evidence",
    "anchor",
    "related_group",
    "estimated_portion",
    "verified_outcome",
}

ALLOWED_KEV_SNAPSHOT_KEYS = {"cve", "date_added", "ransomware_flag", "reference_set_hash"}
ALLOWED_ANCHOR_KEYS = {
    "epss_percentile",
    "epss_model_date",
    "kev_registered",
    "ssvc_decision",
    "automatable",
}

# enum 定義（forecast.schema.json に準拠）
ENUM_TIER = {"T1", "T2", "T3"}
ENUM_CONFIDENCE = {"high", "medium", "low"}
ENUM_FORECAST_CLASS = {"fast_72h", "slow_7d"}
ENUM_OUTCOME_CHANNEL = {"E1", "E2", "E3", "E4"}
ENUM_WINDOW = {"fast_72h", "slow_7d"}
ENUM_RANSOMWARE_FLAG = {"Known", "Unknown", None}
ENUM_SSVC_DECISION = {"Act", "Attend", "Track", "Track*", None}
ENUM_AUTOMATABLE = {"yes", "no", None}
ENUM_VERIFIED_OUTCOME = {"hit", "partial", "miss", "unverifiable", None}

# パターン定義
RE_FORECAST_ID = re.compile(r"^fc-(\d{8})-(\d+)$")
RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
RE_OBSERVATION_ID = re.compile(r"^obs-\d{4}-\d{4}-\d{3}$")
RE_FILENAME_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})\.json$")


class Reporter:
    """違反を「ファイル:forecast_id:項目: 内容」形式で蓄積する。"""

    def __init__(self):
        self.violations = []

    def add(self, filename, fc_id, item, message):
        self.violations.append(f"{filename}:{fc_id}:{item}: {message}")

    @property
    def count(self):
        return len(self.violations)


def is_valid_date(value):
    """YYYY-MM-DD 形式かつ実在する日付かを判定する。"""
    if not isinstance(value, str):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}$", value))


def check_date_field(rep, fname, fc_id, obj, key, required=False):
    if key not in obj:
        if required:
            rep.add(fname, fc_id, key, "必須フィールドが欠落")
        return
    value = obj[key]
    if not is_valid_date(value):
        rep.add(fname, fc_id, key, f"日付形式 YYYY-MM-DD ではない: {value!r}")


def check_string_array(rep, fname, fc_id, obj, key, pattern=None, pattern_desc=None):
    if key not in obj:
        return
    value = obj[key]
    if not isinstance(value, list):
        rep.add(fname, fc_id, key, f"配列ではない: {type(value).__name__}")
        return
    for i, item in enumerate(value):
        if not isinstance(item, str):
            rep.add(fname, fc_id, f"{key}[{i}]", f"文字列ではない: {item!r}")
        elif pattern is not None and not pattern.match(item):
            rep.add(fname, fc_id, f"{key}[{i}]", f"パターン不一致（{pattern_desc}）: {item!r}")


def check_kev_snapshot(rep, fname, fc_id, snapshot):
    if not isinstance(snapshot, dict):
        rep.add(fname, fc_id, "kev_snapshot", f"オブジェクトではない: {type(snapshot).__name__}")
        return
    for key in snapshot:
        if key not in ALLOWED_KEV_SNAPSHOT_KEYS:
            rep.add(fname, fc_id, f"kev_snapshot.{key}", "スキーマに定義されていないフィールド")
    if "cve" in snapshot:
        cve = snapshot["cve"]
        if not (isinstance(cve, str) and RE_CVE.match(cve)):
            rep.add(fname, fc_id, "kev_snapshot.cve", f"パターン ^CVE-\\d{{4}}-\\d{{4,}}$ に不一致: {cve!r}")
    if "date_added" in snapshot:
        v = snapshot["date_added"]
        if v is not None and not is_valid_date(v):
            rep.add(fname, fc_id, "kev_snapshot.date_added", f"日付形式 YYYY-MM-DD または null ではない: {v!r}")
    if "ransomware_flag" in snapshot and snapshot["ransomware_flag"] not in ENUM_RANSOMWARE_FLAG:
        rep.add(
            fname, fc_id, "kev_snapshot.ransomware_flag",
            f"enum 違反: {snapshot['ransomware_flag']!r}（許可値: ['Known', 'Unknown', null]）",
        )
    if "reference_set_hash" in snapshot and not (
        snapshot["reference_set_hash"] is None or isinstance(snapshot["reference_set_hash"], str)
    ):
        rep.add(
            fname, fc_id, "kev_snapshot.reference_set_hash",
            f"string または null ではない: {snapshot['reference_set_hash']!r}",
        )


def check_anchor(rep, fname, fc_id, anchor):
    if not isinstance(anchor, dict):
        rep.add(fname, fc_id, "anchor", f"オブジェクトではない: {type(anchor).__name__}")
        return
    for key in anchor:
        if key not in ALLOWED_ANCHOR_KEYS:
            rep.add(fname, fc_id, f"anchor.{key}", "スキーマに定義されていないフィールド")
    if "epss_percentile" in anchor:
        v = anchor["epss_percentile"]
        if v is not None and not (isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 1):
            rep.add(fname, fc_id, "anchor.epss_percentile", f"0〜1 の数値または null ではない: {v!r}")
    if "epss_model_date" in anchor:
        v = anchor["epss_model_date"]
        if v is not None and not is_valid_date(v):
            rep.add(fname, fc_id, "anchor.epss_model_date", f"日付形式 YYYY-MM-DD または null ではない: {v!r}")
    if "kev_registered" in anchor:
        v = anchor["kev_registered"]
        if v is not None and not isinstance(v, bool):
            rep.add(fname, fc_id, "anchor.kev_registered", f"boolean または null ではない: {v!r}")
    if "ssvc_decision" in anchor and anchor["ssvc_decision"] not in ENUM_SSVC_DECISION:
        rep.add(
            fname, fc_id, "anchor.ssvc_decision",
            f"enum 違反: {anchor['ssvc_decision']!r}（許可値: {sorted(v for v in ENUM_SSVC_DECISION if v)} + null）",
        )
    if "automatable" in anchor and anchor["automatable"] not in ENUM_AUTOMATABLE:
        rep.add(
            fname, fc_id, "anchor.automatable",
            f"enum 違反: {anchor['automatable']!r}（許可値: ['yes', 'no', null]）",
        )


def check_forecast(rep, fname, forecast, seen_ids, file_date, day_count):
    """forecast 1件を検査する。seen_ids は全ファイル横断の {forecast_id: ファイル名}。"""
    if not isinstance(forecast, dict):
        rep.add(fname, "-", "forecasts[]", f"オブジェクトではない: {forecast!r}")
        return

    raw_id = forecast.get("forecast_id")
    fc_id = raw_id if isinstance(raw_id, str) and raw_id else "-"

    # 必須フィールド
    for key in REQUIRED_FORECAST_KEYS:
        if key not in forecast:
            rep.add(fname, fc_id, key, "必須フィールドが欠落")

    # additionalProperties: false
    for key in forecast:
        if key not in ALLOWED_FORECAST_KEYS:
            rep.add(fname, fc_id, key, "スキーマに定義されていないフィールド")

    # forecast_id 形式・重複・ファイル名日付との整合
    id_date_part = None
    id_index_part = None
    if raw_id is not None:
        m = RE_FORECAST_ID.match(raw_id) if isinstance(raw_id, str) else None
        if not m:
            rep.add(
                fname, fc_id, "forecast_id",
                f"パターン ^fc-\\d{{8}}-\\d+$ に不一致: {raw_id!r}",
            )
        else:
            id_date_part, id_index_part = m.group(1), int(m.group(2))
            if raw_id in seen_ids:
                rep.add(fname, fc_id, "forecast_id", f"重複（既出: {seen_ids[raw_id]}）")
            else:
                seen_ids[raw_id] = fname
            if file_date is not None:
                expected_date_part = file_date.replace("-", "")
                if id_date_part != expected_date_part:
                    rep.add(
                        fname, fc_id, "forecast_id",
                        f"日付部分がファイル名日付と不一致: {id_date_part}（期待値: {expected_date_part}）",
                    )

    # forecast_index
    idx = forecast.get("forecast_index")
    if "forecast_index" in forecast:
        if not (isinstance(idx, int) and not isinstance(idx, bool) and idx >= 1):
            rep.add(fname, fc_id, "forecast_index", f"1以上の整数ではない: {idx!r}")
        elif id_index_part is not None and idx != id_index_part:
            rep.add(
                fname, fc_id, "forecast_index",
                f"forecast_id の連番と不一致: forecast_index={idx} / forecast_id 連番={id_index_part}",
            )

    # subject
    if "subject" in forecast and not isinstance(forecast["subject"], str):
        rep.add(fname, fc_id, "subject", f"文字列ではない: {forecast['subject']!r}")

    # enum フィールド
    if "tier" in forecast and forecast["tier"] not in ENUM_TIER:
        rep.add(fname, fc_id, "tier", f"enum 違反: {forecast['tier']!r}（許可値: {sorted(ENUM_TIER)}）")
    if "confidence" in forecast and forecast["confidence"] not in ENUM_CONFIDENCE:
        rep.add(
            fname, fc_id, "confidence",
            f"enum 違反: {forecast['confidence']!r}（許可値: {sorted(ENUM_CONFIDENCE)}）",
        )
    if "forecast_class" in forecast and forecast["forecast_class"] not in ENUM_FORECAST_CLASS:
        rep.add(
            fname, fc_id, "forecast_class",
            f"enum 違反: {forecast['forecast_class']!r}（許可値: {sorted(ENUM_FORECAST_CLASS)}）",
        )
    if "outcome_channel" in forecast and forecast["outcome_channel"] not in ENUM_OUTCOME_CHANNEL:
        rep.add(
            fname, fc_id, "outcome_channel",
            f"enum 違反: {forecast['outcome_channel']!r}（許可値: {sorted(ENUM_OUTCOME_CHANNEL)}）",
        )
    if "window" in forecast and forecast["window"] not in ENUM_WINDOW:
        rep.add(fname, fc_id, "window", f"enum 違反: {forecast['window']!r}（許可値: {sorted(ENUM_WINDOW)}）")

    # forecast_class と window の整合（両方存在する場合のみ）
    if (
        "forecast_class" in forecast
        and "window" in forecast
        and forecast["forecast_class"] in ENUM_FORECAST_CLASS
        and forecast["window"] in ENUM_WINDOW
        and forecast["forecast_class"] != forecast["window"]
    ):
        rep.add(
            fname, fc_id, "window",
            f"forecast_class と不一致: forecast_class={forecast['forecast_class']!r} / window={forecast['window']!r}",
        )

    # deadline_date（発行日=ファイル名日付以降であること）
    check_date_field(rep, fname, fc_id, forecast, "deadline_date", required=False)
    if "deadline_date" in forecast and is_valid_date(forecast["deadline_date"]) and file_date is not None:
        deadline = datetime.strptime(forecast["deadline_date"], "%Y-%m-%d")
        issued = datetime.strptime(file_date, "%Y-%m-%d")
        if deadline < issued:
            rep.add(
                fname, fc_id, "deadline_date",
                f"発行日（{file_date}）より前の日付: {forecast['deadline_date']!r}",
            )

    # hit_criteria / exclusions
    if "hit_criteria" in forecast and not isinstance(forecast["hit_criteria"], str):
        rep.add(fname, fc_id, "hit_criteria", f"文字列ではない: {forecast['hit_criteria']!r}")
    if "exclusions" in forecast and not isinstance(forecast["exclusions"], str):
        rep.add(fname, fc_id, "exclusions", f"文字列ではない: {forecast['exclusions']!r}")

    # base_rate_estimate（0〜1）
    if "base_rate_estimate" in forecast:
        v = forecast["base_rate_estimate"]
        if not (isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 1):
            rep.add(fname, fc_id, "base_rate_estimate", f"0〜1 の数値ではない: {v!r}")

    # forecast_class_rationale
    if "forecast_class_rationale" in forecast and not isinstance(forecast["forecast_class_rationale"], str):
        rep.add(
            fname, fc_id, "forecast_class_rationale",
            f"文字列ではない: {forecast['forecast_class_rationale']!r}",
        )
    if forecast.get("forecast_class") == "slow_7d" and not forecast.get("forecast_class_rationale"):
        rep.add(
            fname, fc_id, "forecast_class_rationale",
            "forecast_class=slow_7d の場合は割当根拠（M2）の記載が必須",
        )

    # kev_snapshot
    if "kev_snapshot" in forecast:
        check_kev_snapshot(rep, fname, fc_id, forecast["kev_snapshot"])

    # evidence
    if "evidence" in forecast and not isinstance(forecast["evidence"], str):
        rep.add(fname, fc_id, "evidence", f"文字列ではない: {forecast['evidence']!r}")

    # anchor
    if "anchor" in forecast:
        check_anchor(rep, fname, fc_id, forecast["anchor"])

    # confidence=high は anchor 記録必須（M3）
    if forecast.get("confidence") == "high" and "anchor" not in forecast:
        rep.add(
            fname, fc_id, "anchor",
            "confidence=high の場合は EPSS+SSVC 確度アンカー（M3）の記録が必須",
        )

    # related_observation_ids
    check_string_array(
        rep, fname, fc_id, forecast, "related_observation_ids",
        pattern=RE_OBSERVATION_ID, pattern_desc="^obs-\\d{4}-\\d{4}-\\d{3}$",
    )

    # related_group
    if "related_group" in forecast and not (
        forecast["related_group"] is None or isinstance(forecast["related_group"], str)
    ):
        rep.add(fname, fc_id, "related_group", f"string または null ではない: {forecast['related_group']!r}")

    # estimated_portion
    if "estimated_portion" in forecast and not isinstance(forecast["estimated_portion"], str):
        rep.add(fname, fc_id, "estimated_portion", f"文字列ではない: {forecast['estimated_portion']!r}")

    # verified_outcome（予報生成段階では null 固定を期待するが、値自体の enum は検査する）
    if "verified_outcome" in forecast and forecast["verified_outcome"] not in ENUM_VERIFIED_OUTCOME:
        rep.add(
            fname, fc_id, "verified_outcome",
            f"enum 違反: {forecast['verified_outcome']!r}（許可値: ['hit', 'partial', 'miss', 'unverifiable', null]）",
        )


def check_file(rep, path, seen_ids):
    """forecast サイドカー JSON ファイル1件を検査する。"""
    fname = os.path.relpath(path, REPO_ROOT)
    basename = os.path.basename(path)

    m = RE_FILENAME_DATE.match(basename)
    file_date = f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else None
    if file_date is None:
        rep.add(fname, "-", "(filename)", f"ファイル名が YYYY-MM-DD.json 形式ではない: {basename!r}")
    elif not is_valid_date(file_date):
        rep.add(fname, "-", "(filename)", f"ファイル名の日付が実在しない: {file_date!r}")
        file_date = None

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        rep.add(fname, "-", "(file)", f"JSON として読み込めない: {exc}")
        return

    if isinstance(data, list):
        rep.add(
            fname, "-", "(file)",
            "旧形式（素の JSON 配列）。wrapper 形式 {\"_schema_version\": \"1.0\", \"forecasts\": [...]} に変換が必要",
        )
        for forecast in data:
            check_forecast(rep, fname, forecast, seen_ids, file_date, len(data))
        return

    if not isinstance(data, dict):
        rep.add(fname, "-", "(file)", f"オブジェクトではない: {type(data).__name__}")
        return

    if "_schema_version" not in data:
        rep.add(fname, "-", "_schema_version", "必須フィールドが欠落")
    elif data["_schema_version"] not in ALLOWED_SCHEMA_VERSIONS:
        rep.add(
            fname, "-", "_schema_version",
            f"バージョン不一致: {data['_schema_version']!r}"
            f"（許可値: {sorted(ALLOWED_SCHEMA_VERSIONS)}、新規出力は '1.0' 固定）",
        )

    if "forecasts" not in data:
        rep.add(fname, "-", "forecasts", "必須フィールドが欠落")
    elif not isinstance(data["forecasts"], list):
        rep.add(fname, "-", "forecasts", f"配列ではない: {type(data['forecasts']).__name__}")

    for key in data:
        if key not in ALLOWED_TOP_KEYS:
            rep.add(fname, "-", key, "wrapper に定義されていないトップレベルフィールド")

    if "_forecast_date" in data and not is_valid_date(data["_forecast_date"]):
        rep.add(
            fname, "-", "_forecast_date",
            f"日付形式 YYYY-MM-DD ではない: {data['_forecast_date']!r}",
        )
    if "_forecast_date" in data and is_valid_date(data["_forecast_date"]) and file_date is not None:
        if data["_forecast_date"] != file_date:
            rep.add(
                fname, "-", "_forecast_date",
                f"ファイル名日付と不一致: {data['_forecast_date']!r}（期待値: {file_date!r}）",
            )
    if "_source_markdown" in data and not isinstance(data["_source_markdown"], str):
        rep.add(fname, "-", "_source_markdown", f"文字列ではない: {data['_source_markdown']!r}")

    if isinstance(data.get("forecasts"), list):
        day_count = len(data["forecasts"])
        if day_count > MAX_FORECASTS_PER_DAY:
            rep.add(
                fname, "-", "forecasts",
                f"1日最大{MAX_FORECASTS_PER_DAY}件を超過: {day_count}件"
                "（pipeline-forecast-verification.md 絞り込みルール）",
            )
        for forecast in data["forecasts"]:
            check_forecast(rep, fname, forecast, seen_ids, file_date, day_count)


def collect_files(date=None):
    if date:
        if not is_valid_date(date):
            print(f"エラー: --date は YYYY-MM-DD 形式で指定する: {date!r}", file=sys.stderr)
            sys.exit(2)
        path = os.path.join(FORECASTS_DIR, f"{date}.json")
        if not os.path.isfile(path):
            # 過去の .md のみの日（サイドカー未存在）は検査対象外
            return []
        return [path]
    pattern = os.path.join(FORECASTS_DIR, "*.json")
    return sorted(glob.glob(pattern))


def main():
    parser = argparse.ArgumentParser(
        description="forecaster/forecasts/daily/ の forecast サイドカー JSON をスキーマ v1.0 に照らして検査する。"
        "Markdown のみでサイドカー .json が存在しない日はスキップする。"
    )
    parser.add_argument("--date", help="単日指定（YYYY-MM-DD）。省略時は存在する .json を全件検査。")
    args = parser.parse_args()

    files = collect_files(args.date)
    if not files:
        print("検査対象なし（サイドカー JSON が存在する日がない）。")
        sys.exit(0)

    rep = Reporter()
    seen_ids = {}
    for path in files:
        check_file(rep, path, seen_ids)

    if rep.violations:
        for line in rep.violations:
            print(line)
        print(f"\nNG: {len(files)} ファイル中に違反 {rep.count} 件。", file=sys.stderr)
        sys.exit(1)

    print(f"OK: {len(files)} ファイル・違反 0 件。")
    sys.exit(0)


if __name__ == "__main__":
    main()
