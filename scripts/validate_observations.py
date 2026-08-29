#!/usr/bin/env python3
"""observation ファイルのスキーマバリデータ。

forecaster/observations/YYYY/MM/YYYY-MM-DD.json を
forecaster/schema/observation.schema.json（v1.1 wrapper 形式）に照らして検査する。

- 依存: Python 3 標準ライブラリのみ（jsonschema 非依存・自前チェック）
- デフォルト: forecaster/observations/**/*.json を全件検査
- --date YYYY-MM-DD で単日指定
- 違反は「ファイル:observation_id:項目: 内容」形式で列挙し exit 1、全パスで exit 0
- 自動修正は行わない

使い方:
    python3 scripts/validate_observations.py
    python3 scripts/validate_observations.py --date 2026-07-01
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
OBSERVATIONS_DIR = os.path.join(REPO_ROOT, "forecaster", "observations")

SCHEMA_VERSION = "1.2"
# フィールド構造が同一の後方互換バージョン（例: 2026-07-01 以前の wrapper 形式ファイル）。
# 新規出力は 01-normalize.md により "1.1" 固定だが、既存の "1.0" wrapper ファイルは
# 構造が本バリデータの検査内容と一致する限り許容する。
ALLOWED_SCHEMA_VERSIONS = {"1.0", "1.1", "1.2"}

# wrapper で許可するトップレベルキー
ALLOWED_TOP_KEYS = {
    "_schema_version",
    "_observation_date",
    "_generated_at_utc",
    "_normalization_mode",
    "_normalization_note",
    "_retro_normalized",
    "_retro_note",
    "observations",
}

# observation の必須キー
REQUIRED_OBS_KEYS = [
    "observation_id",
    "observed_date",
    "ingested_date",
    "source",
    "techniques",
    "target",
    "confidence",
    "summary",
    "verified_outcome",
]

# observation で許可するキー（additionalProperties: false 相当）
ALLOWED_OBS_KEYS = set(REQUIRED_OBS_KEYS) | {
    "actor_group",
    "actor_aliases",
    "techniques_note",
    "cve",
    "exploitation_stage",
    "geopolitical_signal",
    "iocs",
    "related_forecast_id",
    "tags",
    "available_at_utc",
    "evidence_ids",
}

ALLOWED_TECHNIQUE_KEYS = {"technique_id", "sub_technique_id", "tactic", "evidence"}
REQUIRED_TECHNIQUE_KEYS = ["technique_id", "tactic", "evidence"]

ALLOWED_IOC_KEYS = {"value", "type", "defanged", "note"}
REQUIRED_IOC_KEYS = ["value", "type"]

ALLOWED_SOURCE_KEYS = {"name", "url", "type"}
REQUIRED_SOURCE_KEYS = ["name", "url", "type"]

# enum 定義（observation.schema.json に準拠）
ENUM_SOURCE_TYPE = {"vendor_report", "osint", "advisory", "news"}
ENUM_CONFIDENCE = {"high", "medium", "low"}
ENUM_VERIFIED_OUTCOME = {"hit", "miss", "partial", None}
ENUM_EXPLOITATION_STAGE = {
    "active_exploitation",
    "kev_listed",
    "poc_public",
    "limited_exploitation",
    "none",
    "unknown",
}
ENUM_GEOPOLITICAL_SIGNAL = {
    "north_korea_nexus",
    "russia_nexus",
    "china_nexus",
    "iran_nexus",
    "geopolitical_unattributed",
    None,
}
ENUM_IOC_TYPE = {"ip", "domain", "hash", "url", "email"}
ENUM_TACTIC = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}

# パターン定義
RE_OBSERVATION_ID = re.compile(r"^obs-\d{4}-\d{4}-\d{3}$")
RE_TECHNIQUE_ID = re.compile(r"^T\d{4}$")
RE_SUB_TECHNIQUE_ID = re.compile(r"^T\d{4}\.\d{3}$")
RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class Reporter:
    """違反を「ファイル:observation_id:項目: 内容」形式で蓄積する。"""

    def __init__(self):
        self.violations = []

    def add(self, filename, obs_id, item, message):
        self.violations.append(f"{filename}:{obs_id}:{item}: {message}")

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


def check_date_field(rep, fname, obs_id, obj, key):
    if key not in obj:
        return
    value = obj[key]
    if not is_valid_date(value):
        rep.add(fname, obs_id, key, f"日付形式 YYYY-MM-DD ではない: {value!r}")


def check_string_array(rep, fname, obs_id, obj, key):
    """任意の string 配列フィールドを検査する。"""
    if key not in obj:
        return
    value = obj[key]
    if not isinstance(value, list):
        rep.add(fname, obs_id, key, f"配列ではない: {type(value).__name__}")
        return
    for i, item in enumerate(value):
        if not isinstance(item, str):
            rep.add(fname, obs_id, f"{key}[{i}]", f"文字列ではない: {item!r}")


def check_source(rep, fname, obs_id, source):
    if not isinstance(source, dict):
        rep.add(fname, obs_id, "source", f"オブジェクトではない: {type(source).__name__}")
        return
    for key in REQUIRED_SOURCE_KEYS:
        if key not in source:
            rep.add(fname, obs_id, f"source.{key}", "必須フィールドが欠落")
    for key in source:
        if key not in ALLOWED_SOURCE_KEYS:
            rep.add(fname, obs_id, f"source.{key}", "スキーマに定義されていないフィールド")
    if "name" in source and not isinstance(source["name"], str):
        rep.add(fname, obs_id, "source.name", f"文字列ではない: {source['name']!r}")
    if "url" in source and not isinstance(source["url"], str):
        rep.add(fname, obs_id, "source.url", f"文字列ではない: {source['url']!r}")
    if "type" in source and source["type"] not in ENUM_SOURCE_TYPE:
        rep.add(
            fname, obs_id, "source.type",
            f"enum 違反: {source['type']!r}（許可値: {sorted(ENUM_SOURCE_TYPE)}）",
        )


def check_techniques(rep, fname, obs_id, techniques):
    if not isinstance(techniques, list):
        rep.add(fname, obs_id, "techniques", f"配列ではない: {type(techniques).__name__}")
        return
    for i, tech in enumerate(techniques):
        prefix = f"techniques[{i}]"
        if not isinstance(tech, dict):
            rep.add(fname, obs_id, prefix, f"オブジェクトではない: {tech!r}")
            continue
        for key in REQUIRED_TECHNIQUE_KEYS:
            if key not in tech:
                rep.add(fname, obs_id, f"{prefix}.{key}", "必須フィールドが欠落")
        for key in tech:
            if key not in ALLOWED_TECHNIQUE_KEYS:
                rep.add(fname, obs_id, f"{prefix}.{key}", "スキーマに定義されていないフィールド")

        tid = tech.get("technique_id")
        if tid is not None and not (isinstance(tid, str) and RE_TECHNIQUE_ID.match(tid)):
            rep.add(
                fname, obs_id, f"{prefix}.technique_id",
                f"パターン ^T\\d{{4}}$ に不一致: {tid!r}"
                "（サブテクニックは sub_technique_id へ記載する）",
            )

        sub = tech.get("sub_technique_id")
        if sub is not None:
            if not (isinstance(sub, str) and RE_SUB_TECHNIQUE_ID.match(sub)):
                rep.add(
                    fname, obs_id, f"{prefix}.sub_technique_id",
                    f"パターン ^T\\d{{4}}\\.\\d{{3}}$ に不一致: {sub!r}",
                )
            elif isinstance(tid, str) and RE_TECHNIQUE_ID.match(tid) and not sub.startswith(tid + "."):
                rep.add(
                    fname, obs_id, f"{prefix}.sub_technique_id",
                    f"technique_id と前方一致しない: {sub!r}（technique_id: {tid!r}）",
                )

        tactic = tech.get("tactic")
        if "tactic" in tech and tactic not in ENUM_TACTIC:
            rep.add(
                fname, obs_id, f"{prefix}.tactic",
                f"enum 違反: {tactic!r}（許可値: {sorted(ENUM_TACTIC)}）",
            )

        evidence = tech.get("evidence")
        if "evidence" in tech and not isinstance(evidence, str):
            rep.add(fname, obs_id, f"{prefix}.evidence", f"文字列ではない: {evidence!r}")


def check_target(rep, fname, obs_id, target):
    if not isinstance(target, dict):
        rep.add(fname, obs_id, "target", f"オブジェクトではない: {type(target).__name__}")
        return
    for key in ("sectors", "geos"):
        if key not in target:
            rep.add(fname, obs_id, f"target.{key}", "必須フィールドが欠落")
    for key in target:
        if key not in {"sectors", "geos"}:
            rep.add(fname, obs_id, f"target.{key}", "スキーマに定義されていないフィールド")
    check_string_array(rep, fname, obs_id, target, "sectors")
    check_string_array(rep, fname, obs_id, target, "geos")
    # target.sectors / target.geos の項目名で報告し直すためのラベル補正は不要
    # （check_string_array は key 名で報告する）


def check_iocs(rep, fname, obs_id, iocs):
    if not isinstance(iocs, list):
        rep.add(fname, obs_id, "iocs", f"配列ではない: {type(iocs).__name__}")
        return
    for i, ioc in enumerate(iocs):
        prefix = f"iocs[{i}]"
        if not isinstance(ioc, dict):
            rep.add(fname, obs_id, prefix, f"オブジェクトではない: {ioc!r}")
            continue
        for key in REQUIRED_IOC_KEYS:
            if key not in ioc:
                rep.add(fname, obs_id, f"{prefix}.{key}", "必須フィールドが欠落")
        for key in ioc:
            if key not in ALLOWED_IOC_KEYS:
                rep.add(fname, obs_id, f"{prefix}.{key}", "スキーマに定義されていないフィールド")
        if "value" in ioc and not isinstance(ioc["value"], str):
            rep.add(fname, obs_id, f"{prefix}.value", f"文字列ではない: {ioc['value']!r}")
        if "type" in ioc and ioc["type"] not in ENUM_IOC_TYPE:
            rep.add(
                fname, obs_id, f"{prefix}.type",
                f"enum 違反: {ioc['type']!r}（許可値: {sorted(ENUM_IOC_TYPE)}）",
            )
        if "defanged" in ioc and not isinstance(ioc["defanged"], bool):
            rep.add(fname, obs_id, f"{prefix}.defanged", f"boolean ではない: {ioc['defanged']!r}")
        if "note" in ioc and not isinstance(ioc["note"], str):
            rep.add(fname, obs_id, f"{prefix}.note", f"文字列ではない: {ioc['note']!r}")


def check_observation(rep, fname, obs, seen_ids):
    """observation 1件を検査する。seen_ids は全ファイル横断の {obs_id: ファイル名}。"""
    if not isinstance(obs, dict):
        rep.add(fname, "-", "observations[]", f"オブジェクトではない: {obs!r}")
        return

    raw_id = obs.get("observation_id")
    obs_id = raw_id if isinstance(raw_id, str) and raw_id else "-"

    # 必須フィールド
    for key in REQUIRED_OBS_KEYS:
        if key not in obs:
            rep.add(fname, obs_id, key, "必須フィールドが欠落")

    # additionalProperties: false
    for key in obs:
        if key not in ALLOWED_OBS_KEYS:
            rep.add(fname, obs_id, key, "スキーマに定義されていないフィールド")

    # observation_id
    if raw_id is not None:
        if not (isinstance(raw_id, str) and RE_OBSERVATION_ID.match(raw_id)):
            rep.add(
                fname, obs_id, "observation_id",
                f"パターン ^obs-\\d{{4}}-\\d{{4}}-\\d{{3}}$ に不一致: {raw_id!r}",
            )
        elif raw_id in seen_ids:
            rep.add(
                fname, obs_id, "observation_id",
                f"重複（既出: {seen_ids[raw_id]}）",
            )
        else:
            seen_ids[raw_id] = fname

    # 日付
    check_date_field(rep, fname, obs_id, obs, "observed_date")
    check_date_field(rep, fname, obs_id, obs, "ingested_date")

    # source
    if "source" in obs:
        check_source(rep, fname, obs_id, obs["source"])

    # actor_group / actor_aliases
    if "actor_group" in obs and not (obs["actor_group"] is None or isinstance(obs["actor_group"], str)):
        rep.add(fname, obs_id, "actor_group", f"string または null ではない: {obs['actor_group']!r}")
    check_string_array(rep, fname, obs_id, obs, "actor_aliases")

    # techniques / techniques_note
    if "techniques" in obs:
        check_techniques(rep, fname, obs_id, obs["techniques"])
    if "techniques_note" in obs and not isinstance(obs["techniques_note"], str):
        rep.add(fname, obs_id, "techniques_note", f"文字列ではない: {obs['techniques_note']!r}")

    # target
    if "target" in obs:
        check_target(rep, fname, obs_id, obs["target"])

    # cve
    if "cve" in obs:
        if not isinstance(obs["cve"], list):
            rep.add(fname, obs_id, "cve", f"配列ではない: {type(obs['cve']).__name__}")
        else:
            for i, cve in enumerate(obs["cve"]):
                if not (isinstance(cve, str) and RE_CVE.match(cve)):
                    rep.add(fname, obs_id, f"cve[{i}]", f"パターン ^CVE-\\d{{4}}-\\d{{4,}}$ に不一致: {cve!r}")

    # enum フィールド
    if "exploitation_stage" in obs and obs["exploitation_stage"] not in ENUM_EXPLOITATION_STAGE:
        rep.add(
            fname, obs_id, "exploitation_stage",
            f"enum 違反: {obs['exploitation_stage']!r}（許可値: {sorted(ENUM_EXPLOITATION_STAGE)}）",
        )
    if "geopolitical_signal" in obs and obs["geopolitical_signal"] not in ENUM_GEOPOLITICAL_SIGNAL:
        allowed = sorted(v for v in ENUM_GEOPOLITICAL_SIGNAL if v is not None) + ["null"]
        rep.add(
            fname, obs_id, "geopolitical_signal",
            f"enum 違反: {obs['geopolitical_signal']!r}（許可値: {allowed}）",
        )
    if "confidence" in obs and obs["confidence"] not in ENUM_CONFIDENCE:
        rep.add(
            fname, obs_id, "confidence",
            f"enum 違反: {obs['confidence']!r}（許可値: {sorted(ENUM_CONFIDENCE)}）",
        )
    if "verified_outcome" in obs and obs["verified_outcome"] not in ENUM_VERIFIED_OUTCOME:
        rep.add(
            fname, obs_id, "verified_outcome",
            f"enum 違反: {obs['verified_outcome']!r}（許可値: ['hit', 'miss', 'partial', null]）",
        )

    # iocs
    if "iocs" in obs:
        check_iocs(rep, fname, obs_id, obs["iocs"])

    # summary / related_forecast_id / tags
    if "summary" in obs and not isinstance(obs["summary"], str):
        rep.add(fname, obs_id, "summary", f"文字列ではない: {obs['summary']!r}")
    if "related_forecast_id" in obs and not (
        obs["related_forecast_id"] is None or isinstance(obs["related_forecast_id"], str)
    ):
        rep.add(
            fname, obs_id, "related_forecast_id",
            f"string または null ではない: {obs['related_forecast_id']!r}",
        )
    check_string_array(rep, fname, obs_id, obs, "tags")


def check_file(rep, path, seen_ids):
    """observation ファイル1件を検査する。"""
    fname = os.path.relpath(path, REPO_ROOT)

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        rep.add(fname, "-", "(file)", f"JSON として読み込めない: {exc}")
        return

    # wrapper 構造
    if isinstance(data, list):
        rep.add(
            fname, "-", "(file)",
            "旧形式（素の JSON 配列）。wrapper 形式 {\"_schema_version\": \"1.1\", \"observations\": [...]} に変換が必要",
        )
        # 中身の observation は配列としてそのまま検査する（違反の全容把握のため）
        for obs in data:
            check_observation(rep, fname, obs, seen_ids)
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
            f"（許可値: {sorted(ALLOWED_SCHEMA_VERSIONS)}、新規出力は '1.2' 固定）",
        )

    if "observations" not in data:
        rep.add(fname, "-", "observations", "必須フィールドが欠落")
    elif not isinstance(data["observations"], list):
        rep.add(fname, "-", "observations", f"配列ではない: {type(data['observations']).__name__}")

    for key in data:
        if key not in ALLOWED_TOP_KEYS:
            rep.add(fname, "-", key, "wrapper に定義されていないトップレベルフィールド")

    if "_observation_date" in data and not is_valid_date(data["_observation_date"]):
        rep.add(
            fname, "-", "_observation_date",
            f"日付形式 YYYY-MM-DD ではない: {data['_observation_date']!r}",
        )
    if data.get("_schema_version") == "1.2":
        try:
            datetime.fromisoformat(str(data.get("_generated_at_utc", "")).replace("Z", "+00:00"))
        except ValueError:
            rep.add(fname, "-", "_generated_at_utc", "v1.2ではUTC date-timeが必須")
        for obs in data.get("observations") or []:
            oid = obs.get("observation_id", "-") if isinstance(obs, dict) else "-"
            if not isinstance(obs, dict):
                continue
            try:
                dt = datetime.fromisoformat(str(obs.get("available_at_utc", "")).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    raise ValueError
            except ValueError:
                rep.add(fname, oid, "available_at_utc", "v1.2ではtimezone付きdate-timeが必須")
            if not isinstance(obs.get("evidence_ids"), list):
                rep.add(fname, oid, "evidence_ids", "v1.2では配列が必須")
    if "_retro_normalized" in data and not isinstance(data["_retro_normalized"], bool):
        rep.add(fname, "-", "_retro_normalized", f"boolean ではない: {data['_retro_normalized']!r}")
    if "_retro_note" in data and not isinstance(data["_retro_note"], str):
        rep.add(fname, "-", "_retro_note", f"文字列ではない: {data['_retro_note']!r}")

    if isinstance(data.get("observations"), list):
        for obs in data["observations"]:
            check_observation(rep, fname, obs, seen_ids)


def collect_files(date=None):
    if date:
        if not is_valid_date(date):
            print(f"エラー: --date は YYYY-MM-DD 形式で指定する: {date!r}", file=sys.stderr)
            sys.exit(2)
        year, month, _ = date.split("-")
        path = os.path.join(OBSERVATIONS_DIR, year, month, f"{date}.json")
        if not os.path.isfile(path):
            print(f"エラー: ファイルが存在しない: {os.path.relpath(path, REPO_ROOT)}", file=sys.stderr)
            sys.exit(2)
        return [path]
    pattern = os.path.join(OBSERVATIONS_DIR, "**", "*.json")
    return sorted(glob.glob(pattern, recursive=True))


def main():
    parser = argparse.ArgumentParser(
        description="forecaster/observations/ の observation ファイルをスキーマ v1.2 に照らして検査する。"
    )
    parser.add_argument("--date", help="単日指定（YYYY-MM-DD）。省略時は全件検査。")
    args = parser.parse_args()

    files = collect_files(args.date)
    if not files:
        print("検査対象ファイルが見つからない。")
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
