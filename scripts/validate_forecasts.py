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

M1-b 頻度ゲート・ゲートE・base_rate 実測アンカー（2026-08-07 追加・Issue #118 対応）:
- fast_72h × E3 を violation として拒否する（実測ハザード 0.015 < 閾値 0.10・教訓16）。
- fast_72h の確度が出口チャネルの実測ハザード上限を超えていないか検査する（ゲートE）。
- base_rate_estimate がアンカー起点値の2倍超なのに base_rate_rationale が無い場合を拒否する。
- これらは「どの主題を発行してよいか」という入口の操作であり、発行済み予報の的中判定条件・
  判定結果には遡及しない（原則D・教訓12）。RULE_EFFECTIVE_DATE_2026_08 より前に発行された
  予報は検査対象外とし、過去ファイルを遡って violation にしない。

勧告（非致命・exit codeに影響しない・stderr表示のみ・Issue #42）:
- fast_72h × E2 で hit_criteria が追随IOC公開期待型の語句を含む予報を検知し、
  03-forecast.md「E2追随IOC除外（全Tier）」・教訓14 に照らした人間レビューを促す。
  一次ソース自身の続報（帰属・エコシステム・C2の3点一致）という正当な残置ケースを
  機械的にブロックしないため、violation ではなく advisory とする（発行済み予報の
  的中判定基準は緩めない・原則D）。
- base_rate_anchor / observation_lag_days の未記載、実測ハザード未測定クラスの採用。

使い方:
    python3 scripts/validate_forecasts.py
    python3 scripts/validate_forecasts.py --date 2026-07-02
"""

import argparse
import glob
import hashlib
import json
import os
import re
import sys
from datetime import datetime

# リポジトリルート = このスクリプトの親ディレクトリの親
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORECASTS_DIR = os.path.join(REPO_ROOT, "forecaster", "forecasts", "daily")

SCHEMA_VERSION = "2.0"
ALLOWED_SCHEMA_VERSIONS = {"1.0", "2.0"}

# 新規発行に v1.0 を使ってよい最終日。これ以降の発行日は v2.0 必須。
# ★既存履歴（〜2026-08-29）は遡及修正しない（原則D）ため、この日以前は 1.0 を許す。
V2_REQUIRED_FROM = "2026-08-30"

# v2.0 で追加された測定固定フィールド（改善計画 Phase 0 §4.3）
REQUIRED_V2_KEYS = [
    "issued_at_utc",
    "cutoff_at_utc",
    "content_sha256",
    "target_event",
    "forecast_probability",
    "reference_base_rate",
    "model_version",
    "evidence_ids",
]

OPTIONAL_V2_KEYS = {
    "candidate_id",
    "cluster_id",
    "legacy_probability_semantics",
    "policy_version",
}

REQUIRED_TARGET_EVENT_KEYS = [
    "channel",
    "entity_id",
    "event_type",
    "window_start_utc",
    "window_end_utc",
    "primary_source",
    "matching_rule_version",
]

ENUM_EVENT_TYPE = {
    "cisa_kev_initial_add",
    "vendor_ioc_initial_publish",
    "cert_initial_advisory",
    "public_exploit_publish",
}

RE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
RE_EVIDENCE_ID = re.compile(r"^ev-\d{8}-[0-9a-f]{5}$")

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
ALLOWED_FORECAST_KEYS = set(REQUIRED_FORECAST_KEYS) | set(REQUIRED_V2_KEYS) | OPTIONAL_V2_KEYS | {
    "forecast_class_rationale",
    "kev_snapshot",
    "evidence",
    "anchor",
    "related_group",
    "estimated_portion",
    "verified_outcome",
    "retrieval",
    "base_rate_anchor",
    "base_rate_rationale",
}

ALLOWED_BASE_RATE_ANCHOR_KEYS = {
    "source_file",
    "source_key",
    "value",
    "observation_lag_days",
}
REQUIRED_BASE_RATE_ANCHOR_KEYS = {"source_file", "value"}
ENUM_BASE_RATE_ANCHOR_SOURCE = {
    "forecaster/knowledge/kev-hazard-stats.json",
    "forecaster/knowledge/advisory-cadence-stats.json",
    "forecaster/knowledge/kev-leadtime-stats.json",
    "forecaster/verification/retrieval-calibration.json",
}

# --- M1-b 頻度ゲート / ゲート E（確度上限）の p_channel 表（2026-08-07・教訓17 で改訂） ---
# 出典は pipeline-forecast-verification.md「M1-b 頻度ゲート」の表と同一。
# 値の更新は knowledge/ の再生成（PR + 人間レビュー）に合わせて行う。
#
# ★p_channel は「Pythia が予報を発行する条件」を条件とする窓内発生率であり、
#   base_rate_estimate に記入する base_rate（広い候補母集団が条件）とは別の量である。
#   E1 では p_channel 0.36 に対し base_rate 0.0003 と約1000倍違う（教訓17）。
#   base_rate のアンカーは kev-hazard-stats.json の strata[].hazard を使うこと。
CHANNEL_HAZARD = {
    # 内部実績 4/11（2026-06〜08）。95%CI [0.15, 0.65]。
    # kev-hazard-stats.json internal_channel_rates.E1 が集計値の正本。
    "E1": 0.36,
    "E2": None,  # 実測不能（発行停止で蓄積経路が閉鎖・教訓14）
    "E3": 0.015,  # advisory-cadence-stats.json E3.combined k=1 ハザード（母集団一致・教訓16）
    "E4": None,  # 未実測（n=1）
}
# M1-b の採否判定に使う Wilson 95%CI 下限（内部実績由来のクラスのみ）。
# 小標本での偶然の高値を採らないため、採否は点推定ではなく下限で判定する。
# ゲートE（確度上限）は約束の最良推定値である点推定を使う（判定基準が異なる）。
CHANNEL_HAZARD_CI_LOWER = {
    "E1": 0.15,
}
M1B_FREQUENCY_THRESHOLD = 0.10
# ゲート E: p_channel が下限を満たさない確度は名乗れない（降格方向のみ）
CONFIDENCE_HAZARD_FLOOR = {"high": 0.40, "medium": 0.20, "low": 0.10}
# base_rate_estimate がアンカー起点値の何倍を超えたら理由記載を必須とするか
BASE_RATE_UPLIFT_LIMIT = 2.0

# M1-b / ゲートE / base_rate アンカーの発効日。
# これらは「どの主題を発行してよいか」という入口の操作であり、発行済み予報の
# 的中判定条件・判定結果には遡及しない（原則D・教訓12）。発効日より前に発行された
# 予報は新ルールの検査対象外とし、過去ファイルを遡って violation にしない。
RULE_EFFECTIVE_DATE_2026_08 = "2026-08-08"


def _is_before_effective_date(forecast, effective_date):
    """forecast_id の発行日が発効日より前か（＝新ルールの遡及対象外か）を返す。"""
    m = RE_FORECAST_ID.match(forecast.get("forecast_id") or "")
    if not m:
        return False  # 日付を特定できない場合は検査する（安全側）
    d = m.group(1)
    return f"{d[:4]}-{d[4:6]}-{d[6:]}" < effective_date

ALLOWED_RETRIEVAL_KEYS = {
    "n_cases",
    "n_hit",
    "n_partial",
    "n_miss",
    "empirical_hit_rate",
    "observed_gate_passed",
    "matched_forecast_ids",
    "external_cases",
}
ALLOWED_EXTERNAL_CASE_KEYS = {"source_name", "source_url", "published_date", "relevance"}
REQUIRED_EXTERNAL_CASE_KEYS = {"source_name", "source_url", "relevance"}

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
RE_FORECAST_ID_FULL = re.compile(r"^fc-\d{8}-\d+$")
RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
RE_OBSERVATION_ID = re.compile(r"^obs-\d{4}-\d{4}-\d{3}$")
RE_FILENAME_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})\.json$")


class Reporter:
    """違反（exit 1 対象）と勧告（非致命・人間レビュー喚起）を分けて蓄積する。"""

    def __init__(self):
        self.violations = []
        self.advisories = []

    def add(self, filename, fc_id, item, message):
        self.violations.append(f"{filename}:{fc_id}:{item}: {message}")

    def advise(self, filename, fc_id, item, message):
        """非致命の勧告。exit code には影響させず stderr に警告表示のみ行う。
        E2追随IOC除外のような『入口（母集団選別）の運用ルール』の見落としを
        機械的に検知して人間レビューを促すために使う。的中判定基準（hit_criteria）を
        機械判定で緩める・厳しくする操作ではない（原則D・M3の出口尺度には触れない）。"""
        self.advisories.append(f"{filename}:{fc_id}:{item}: {message}")

    @property
    def count(self):
        return len(self.violations)

    @property
    def advisory_count(self):
        return len(self.advisories)


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


def _check_nonneg_int(rep, fname, fc_id, obj, key):
    if key in obj:
        v = obj[key]
        if not (isinstance(v, int) and not isinstance(v, bool) and v >= 0):
            rep.add(fname, fc_id, f"retrieval.{key}", f"0以上の整数ではない: {v!r}")


def check_retrieval(rep, fname, fc_id, retrieval):
    """retrieval（類似過去事例検索の集計・監査証跡）を検査する（任意フィールド）。"""
    if retrieval is None:
        return
    if not isinstance(retrieval, dict):
        rep.add(fname, fc_id, "retrieval", f"オブジェクトまたは null ではない: {type(retrieval).__name__}")
        return
    for key in retrieval:
        if key not in ALLOWED_RETRIEVAL_KEYS:
            rep.add(fname, fc_id, f"retrieval.{key}", "スキーマに定義されていないフィールド")

    for key in ("n_cases", "n_hit", "n_partial", "n_miss"):
        _check_nonneg_int(rep, fname, fc_id, retrieval, key)

    # 内訳の整合: n_hit + n_partial + n_miss == n_cases（全キー揃う場合のみ）
    if all(
        isinstance(retrieval.get(k), int) and not isinstance(retrieval.get(k), bool)
        for k in ("n_cases", "n_hit", "n_partial", "n_miss")
    ):
        if retrieval["n_hit"] + retrieval["n_partial"] + retrieval["n_miss"] != retrieval["n_cases"]:
            rep.add(
                fname, fc_id, "retrieval",
                f"内訳合計が n_cases と不一致: hit+partial+miss="
                f"{retrieval['n_hit'] + retrieval['n_partial'] + retrieval['n_miss']} / n_cases={retrieval['n_cases']}",
            )

    if "empirical_hit_rate" in retrieval:
        v = retrieval["empirical_hit_rate"]
        if v is not None and not (isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 1):
            rep.add(fname, fc_id, "retrieval.empirical_hit_rate", f"0〜1 の数値または null ではない: {v!r}")

    if "observed_gate_passed" in retrieval and not isinstance(retrieval["observed_gate_passed"], bool):
        rep.add(
            fname, fc_id, "retrieval.observed_gate_passed",
            f"boolean ではない: {retrieval['observed_gate_passed']!r}",
        )

    if "matched_forecast_ids" in retrieval:
        check_string_array(
            rep, fname, fc_id, retrieval, "matched_forecast_ids",
            pattern=RE_FORECAST_ID_FULL, pattern_desc="^fc-\\d{8}-\\d+$",
        )

    if "external_cases" in retrieval:
        ext = retrieval["external_cases"]
        if not isinstance(ext, list):
            rep.add(fname, fc_id, "retrieval.external_cases", f"配列ではない: {type(ext).__name__}")
        else:
            for i, case in enumerate(ext):
                if not isinstance(case, dict):
                    rep.add(fname, fc_id, f"retrieval.external_cases[{i}]", f"オブジェクトではない: {case!r}")
                    continue
                for k in case:
                    if k not in ALLOWED_EXTERNAL_CASE_KEYS:
                        rep.add(fname, fc_id, f"retrieval.external_cases[{i}].{k}", "スキーマに定義されていないフィールド")
                for k in REQUIRED_EXTERNAL_CASE_KEYS:
                    if k not in case:
                        rep.add(fname, fc_id, f"retrieval.external_cases[{i}].{k}", "必須フィールドが欠落（原則1: 一次ソース出典必須）")


# E2追随IOC除外（03-forecast.md「E2追随IOC除外（全Tier）」・教訓14）の勧告検知に使う語句。
# fast_72h × E2 で hit_criteria がこれらを含む予報は、追随IOC公開期待型の可能性が高いため
# 人間レビューを促す（非致命。一次ソース自身の同一キャンペーン続報＝帰属/エコシステム/C2の
# 3点一致を満たす正当な残置ケースを機械的にブロックしないため、violation ではなく advisory）。
E2_FOLLOWUP_HINT_TERMS = (
    "追随IOC",
    "追随",
    "新規IOC",
    "72時間以内",
    "72h以内",
    "72時間内",
    "追加IOC",
    "追加ドメイン",
    "侵害指標",
)
# 正当な残置（一次ソース自身の続報）を示す3点一致語句。hit_criteria がこれらを明示していれば
# 勧告を抑制する（03-forecast.md 対応2: 帰属・対象エコシステム・C2インフラの3点一致を要求）。
E2_CARVEOUT_TERMS = ("帰属", "エコシステム", "C2")


def check_e2_followup_advisory(rep, fname, fc_id, forecast):
    """fast_72h × E2 の追随IOC公開期待型を非致命の勧告として検知する（Issue #42・教訓14）。"""
    if forecast.get("forecast_class") != "fast_72h" or forecast.get("outcome_channel") != "E2":
        return
    hit_criteria = forecast.get("hit_criteria")
    if not isinstance(hit_criteria, str):
        return
    if not any(term in hit_criteria for term in E2_FOLLOWUP_HINT_TERMS):
        return
    # 一次ソース自身の続報カーブアウト（帰属・エコシステム・C2の3点一致）を明示していれば抑制しない
    # 代わりに、3点一致が揃っているかを勧告メッセージに含めて人間レビューの判断材料にする。
    carveout_hits = [t for t in E2_CARVEOUT_TERMS if t in hit_criteria]
    carveout_note = (
        f"（一次ソース続報カーブアウトの3点一致語句 {carveout_hits} を検出。"
        "帰属・エコシステム・C2の3点一致が hit_criteria に揃っているか確認）"
        if carveout_hits
        else "（一次ソース続報カーブアウトの3点一致〈帰属・エコシステム・C2〉が hit_criteria に不在）"
    )
    rep.advise(
        fname, fc_id, "hit_criteria",
        "fast_72h × E2 で追随IOC公開期待型の可能性。03-forecast.md「E2追随IOC除外（全Tier）」"
        f"・教訓14（8/8=0%で正式除外）に照らして発行可否を人間レビューで確認すること{carveout_note}",
    )


def check_m1b_frequency_gate(rep, fname, fc_id, forecast):
    """M1-b 頻度ゲート: fast_72h の主的中条件は実測ハザード ≥ 0.10 のクラスに限る。

    E2（教訓14）と E3（教訓16）は「別々のチャネルの問題」ではなく、
    出口イベントの発生頻度を検査していないという単一の欠陥の二度の発現である。
    個別の語句マッチではなくチャネル単位のハザードで機械的に塞ぐ。

    E2 は正当な残置ケース（一次ソース自身の続報・帰属/エコシステム/C2の3点一致）が
    あるため従来どおり check_e2_followup_advisory の非致命勧告に委ね、ここでは扱わない。
    E3 にはカーブアウトが存在しないため violation とする。
    """
    if forecast.get("forecast_class") != "fast_72h":
        return
    channel = forecast.get("outcome_channel")
    hazard = CHANNEL_HAZARD.get(channel)

    if channel == "E3":
        rep.add(
            fname, fc_id, "outcome_channel",
            f"fast_72h × E3 は発行禁止（実測ハザード {hazard} < "
            f"M1-b 閾値 {M1B_FREQUENCY_THRESHOLD}）。E3 の初回注意喚起は KEV 追加の"
            "翌日に一極集中し、予報発行時点では既に発火済みか二度と起きない（教訓16・0/13）。"
            "的中条件を E1（KEV初回追加）へ置換するか、本編注意点1行へ格下げすること。",
        )
        return

    # 採否は Wilson 95%CI 下限で判定する（小標本での偶然の高値を採らない）。
    # 下限が定義されていないクラスは点推定で判定する。
    decision_value = CHANNEL_HAZARD_CI_LOWER.get(channel, hazard)
    if decision_value is not None and decision_value < M1B_FREQUENCY_THRESHOLD:
        basis = (
            f"95%CI下限 {decision_value}"
            if channel in CHANNEL_HAZARD_CI_LOWER
            else f"実測ハザード {decision_value}"
        )
        rep.add(
            fname, fc_id, "outcome_channel",
            f"fast_72h × {channel} は {basis} が M1-b 閾値 "
            f"{M1B_FREQUENCY_THRESHOLD} を下回るため主的中条件に採用不可。",
        )
    elif hazard is None and channel not in ("E2",):
        rep.advise(
            fname, fc_id, "outcome_channel",
            f"fast_72h × {channel} は実測ハザード未測定。M1-b は未実測クラスを"
            "fast_72h の主的中条件に採ることを禁じている。確度=低に留めるか、"
            "実測を先に行うこと（pipeline-forecast-verification.md「M1-b 頻度ゲート」）。",
        )


def check_confidence_hazard_ceiling(rep, fname, fc_id, forecast):
    """ゲートE: 出口チャネルの実測ハザードを超える確度は名乗れない（降格方向のみ）。

    確度は『脆弱性の深刻さ』ではなく『hit_criteria のイベントが窓内に起きる確率』の
    約束である。両者の取り違えにより確度=高8.3%・中11.4%・低10.5%と弁別力が
    失われていた（2026-08-07 精度分析）。
    """
    if forecast.get("forecast_class") != "fast_72h":
        return
    channel = forecast.get("outcome_channel")
    confidence = forecast.get("confidence")
    hazard = CHANNEL_HAZARD.get(channel)
    floor = CONFIDENCE_HAZARD_FLOOR.get(confidence)
    if hazard is None or floor is None:
        return
    if hazard < floor:
        allowed = [c for c, f in CONFIDENCE_HAZARD_FLOOR.items() if hazard >= f]
        allowed_note = "・".join(allowed) if allowed else "なし（fast_72h 発行不可）"
        rep.add(
            fname, fc_id, "confidence",
            f"確度={confidence} は出口クラス {channel} の実測ハザード {hazard} では"
            f"名乗れない（ゲートE: 確度={confidence} の下限は {floor}）。"
            f"このチャネルで名乗れる確度: {allowed_note}。",
        )


def check_base_rate_anchor(rep, fname, fc_id, forecast):
    """base_rate_estimate が実測アンカーから導出されているかを検査する（教訓16）。"""
    anchor = forecast.get("base_rate_anchor")
    estimate = forecast.get("base_rate_estimate")

    if anchor is None:
        rep.advise(
            fname, fc_id, "base_rate_anchor",
            "base_rate_anchor 未記載。2026-08-07 改訂で base_rate_estimate は実測アンカー"
            "からの導出が必須になった（主観値では『的が小さすぎる主題』を発行時に検知できない）。"
            "03-forecast.md「base_rate_estimate」手順1〜4に従って記録すること。",
        )
        return

    if not isinstance(anchor, dict):
        rep.add(fname, fc_id, "base_rate_anchor", f"オブジェクトではない: {anchor!r}")
        return

    unknown = set(anchor) - ALLOWED_BASE_RATE_ANCHOR_KEYS
    if unknown:
        rep.add(
            fname, fc_id, "base_rate_anchor",
            f"未知のキー: {sorted(unknown)}",
        )
    missing = REQUIRED_BASE_RATE_ANCHOR_KEYS - set(anchor)
    if missing:
        rep.add(
            fname, fc_id, "base_rate_anchor",
            f"必須キーが不足: {sorted(missing)}",
        )

    source = anchor.get("source_file")
    if source is not None and source not in ENUM_BASE_RATE_ANCHOR_SOURCE:
        rep.add(
            fname, fc_id, "base_rate_anchor.source_file",
            f"許可されていない出典: {source!r}"
            f"（許可: {sorted(ENUM_BASE_RATE_ANCHOR_SOURCE)}）",
        )

    lag = anchor.get("observation_lag_days")
    if lag is None:
        rep.advise(
            fname, fc_id, "base_rate_anchor.observation_lag_days",
            "起点イベントからの発行遅延 k が未記録。ハザードは k に強く依存するため"
            "（E3 は k=0 で 0.097・k=1 で 0.015）必ず数えて記録すること。",
        )
    elif not isinstance(lag, int) or isinstance(lag, bool) or lag < 0:
        rep.add(
            fname, fc_id, "base_rate_anchor.observation_lag_days",
            f"0以上の整数ではない: {lag!r}",
        )

    value = anchor.get("value")
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return
    if not 0 <= value <= 1:
        rep.add(
            fname, fc_id, "base_rate_anchor.value",
            f"0〜1 の範囲外: {value!r}",
        )
        return

    if not isinstance(estimate, (int, float)) or isinstance(estimate, bool):
        return
    limit = value * BASE_RATE_UPLIFT_LIMIT
    if estimate > limit and not forecast.get("base_rate_rationale"):
        ratio = estimate / value if value else float("inf")
        rep.add(
            fname, fc_id, "base_rate_estimate",
            f"アンカー起点値 {value} に対し {estimate}（約{ratio:.0f}倍）を記入しているが "
            "base_rate_rationale が未記載。★これは異常検知ではなく"
            "「予報のスキル主張を明文化する義務」である（教訓17）。"
            "起点値は広い候補母集団のベースレートであり、E1 のように起点値が極端に小さい層では"
            "数百倍〜千倍の上振れが正常だが、その場合も"
            "「この主題がなぜ一般の候補と桁違いに発火が近いのか」を1行で述べること"
            "（03-forecast.md 手順3）。",
        )


def canonical_forecast_hash(forecast):
    """予報本文の content_sha256 を計算する。

    ハッシュ対象から除くのは content_sha256 自身と、発行後に検証ステージが書き込む
    verified_outcome の2つだけ。キーをソートし区切りを固定した canonical JSON を
    UTF-8 でハッシュする。発行後に本文が書き換えられていないことを示すための値である。
    """
    payload = {k: v for k, v in forecast.items()
               if k not in ("content_sha256", "verified_outcome")}
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def parse_utc(value):
    """ISO 8601（末尾 Z 可）を aware datetime にする。失敗したら None。"""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def check_target_event(rep, fname, fc_id, forecast):
    """構造化 target_event を検査する（採点はこのオブジェクトだけで行うため）。"""
    te = forecast.get("target_event")
    if not isinstance(te, dict):
        rep.add(fname, fc_id, "target_event", f"オブジェクトではない: {te!r}")
        return
    for key in REQUIRED_TARGET_EVENT_KEYS:
        if key not in te:
            rep.add(fname, fc_id, f"target_event.{key}", "必須フィールドが欠落")
    for key in te:
        if key not in REQUIRED_TARGET_EVENT_KEYS:
            rep.add(fname, fc_id, f"target_event.{key}", "スキーマに定義されていないフィールド")

    if te.get("channel") not in ENUM_OUTCOME_CHANNEL:
        rep.add(fname, fc_id, "target_event.channel",
                f"enum 違反: {te.get('channel')!r}")
    if te.get("event_type") not in ENUM_EVENT_TYPE:
        rep.add(fname, fc_id, "target_event.event_type",
                f"enum 違反: {te.get('event_type')!r}（許可値: {sorted(ENUM_EVENT_TYPE)}）")
    if te.get("channel") and forecast.get("outcome_channel") \
            and te["channel"] != forecast["outcome_channel"]:
        rep.add(fname, fc_id, "target_event.channel",
                f"outcome_channel（{forecast['outcome_channel']}）と不一致: {te['channel']}")

    start = parse_utc(te.get("window_start_utc"))
    end = parse_utc(te.get("window_end_utc"))
    if te.get("window_start_utc") is not None and start is None:
        rep.add(fname, fc_id, "target_event.window_start_utc",
                f"ISO 8601 として解釈できない: {te.get('window_start_utc')!r}")
    if te.get("window_end_utc") is not None and end is None:
        rep.add(fname, fc_id, "target_event.window_end_utc",
                f"ISO 8601 として解釈できない: {te.get('window_end_utc')!r}")
    if start and end and end <= start:
        rep.add(fname, fc_id, "target_event.window_end_utc",
                f"窓の終端が始端以前: {end.isoformat()} <= {start.isoformat()}")

    issued = parse_utc(forecast.get("issued_at_utc"))
    if start and issued and start < issued:
        # 発行より前に始まる窓は、発行時点で既に発火済みの事象を的中に数えうる。
        rep.add(fname, fc_id, "target_event.window_start_utc",
                f"検証窓が発行時刻より前に始まっている（{start.isoformat()} < {issued.isoformat()}）。"
                "発行前に起きた事象を的中に数えてはならない")


def check_v2_fields(rep, fname, fc_id, forecast):
    """v2.0 の測定固定フィールドを検査する（改善計画 Phase 0）。"""
    for key in REQUIRED_V2_KEYS:
        if key not in forecast:
            rep.add(fname, fc_id, key, "v2.0 の必須フィールドが欠落")

    issued = parse_utc(forecast.get("issued_at_utc"))
    cutoff = parse_utc(forecast.get("cutoff_at_utc"))
    if forecast.get("issued_at_utc") is not None and issued is None:
        rep.add(fname, fc_id, "issued_at_utc",
                f"ISO 8601 として解釈できない: {forecast['issued_at_utc']!r}")
    if forecast.get("cutoff_at_utc") is not None and cutoff is None:
        rep.add(fname, fc_id, "cutoff_at_utc",
                f"ISO 8601 として解釈できない: {forecast['cutoff_at_utc']!r}")
    if issued and cutoff and cutoff > issued:
        rep.add(fname, fc_id, "cutoff_at_utc",
                f"入力上限が発行時刻より後（{cutoff.isoformat()} > {issued.isoformat()}）。"
                "発行後に取得した証拠を入力にできてしまう")

    digest = forecast.get("content_sha256")
    if digest is not None:
        if not (isinstance(digest, str) and RE_SHA256.match(digest)):
            rep.add(fname, fc_id, "content_sha256", f"SHA-256 の形式ではない: {digest!r}")
        else:
            actual = canonical_forecast_hash(forecast)
            if actual != digest:
                rep.add(fname, fc_id, "content_sha256",
                        f"予報本文のハッシュが一致しない（記録={digest[:12]}… 実体={actual[:12]}…）。"
                        "発行後に本文が変更された可能性がある")

    for key in ("forecast_probability", "reference_base_rate"):
        if key in forecast:
            v = forecast[key]
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not (0 <= v <= 1):
                rep.add(fname, fc_id, key, f"0〜1 の数値ではない: {v!r}")

    if "model_version" in forecast and not isinstance(forecast["model_version"], str):
        rep.add(fname, fc_id, "model_version",
                f"文字列ではない: {forecast['model_version']!r}")

    ev = forecast.get("evidence_ids")
    if ev is not None:
        if not isinstance(ev, list) or not ev:
            rep.add(fname, fc_id, "evidence_ids",
                    "1件以上の証拠IDが必要（URLではなく Evidence Ledger のIDで参照する）")
        else:
            for i, e in enumerate(ev):
                if not (isinstance(e, str) and RE_EVIDENCE_ID.match(e)):
                    rep.add(fname, fc_id, f"evidence_ids[{i}]",
                            f"パターン ^ev-\\d{{8}}-[0-9a-f]{{5}}$ に不一致: {e!r}")

    check_target_event(rep, fname, fc_id, forecast)


def check_forecast(rep, fname, forecast, seen_ids, file_date, day_count, schema_version="1.0"):
    """forecast 1件を検査する。seen_ids は全ファイル横断の {forecast_id: ファイル名}。"""
    if not isinstance(forecast, dict):
        rep.add(fname, "-", "forecasts[]", f"オブジェクトではない: {forecast!r}")
        return

    raw_id = forecast.get("forecast_id")
    fc_id = raw_id if isinstance(raw_id, str) and raw_id else "-"

    # 必須フィールド（版で分岐）
    for key in REQUIRED_FORECAST_KEYS:
        if key == "base_rate_estimate" and schema_version != "1.0":
            # v2 では forecast_probability / reference_base_rate へ分離したため必須から外す
            continue
        if key not in forecast:
            rep.add(fname, fc_id, key, "必須フィールドが欠落")

    if schema_version == "2.0":
        check_v2_fields(rep, fname, fc_id, forecast)
    else:
        # v1.0 で v2 専用フィールドを部分的に混ぜると、測定固定の保証がないまま
        # 固定されているように見えるため拒否する。
        for key in REQUIRED_V2_KEYS:
            if key in forecast:
                rep.add(fname, fc_id, key,
                        "v2.0 専用フィールドが _schema_version=1.0 のファイルに含まれている"
                        "（版を 2.0 に上げるか、フィールドを削除する）")

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

    # retrieval（類似過去事例検索の集計・監査証跡・任意）
    if "retrieval" in forecast:
        check_retrieval(rep, fname, fc_id, forecast["retrieval"])

    # E2追随IOC除外の勧告検知（非致命・Issue #42）
    check_e2_followup_advisory(rep, fname, fc_id, forecast)

    # M1-b 頻度ゲート・ゲートE・base_rate 実測アンカー（2026-08-07・Issue #118 対応）
    # 入口の操作であり発行済み予報には遡及しない（原則D）。発効日前の予報はスキップ。
    if not _is_before_effective_date(forecast, RULE_EFFECTIVE_DATE_2026_08):
        check_m1b_frequency_gate(rep, fname, fc_id, forecast)
        check_confidence_hazard_ceiling(rep, fname, fc_id, forecast)
        check_base_rate_anchor(rep, fname, fc_id, forecast)


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
            f"（許可値: {sorted(ALLOWED_SCHEMA_VERSIONS)}、新規発行は '2.0' 固定）",
        )

    # 2026-08-30 以降の発行日は v2.0 必須（Phase 0 の測定固定）。
    # それ以前の既存履歴は 1.0 のまま据え置く（遡及修正しない＝原則D）。
    fdate = data.get("_forecast_date") or file_date
    if (
        isinstance(fdate, str)
        and is_valid_date(fdate)
        and fdate >= V2_REQUIRED_FROM
        and data.get("_schema_version") != "2.0"
    ):
        rep.add(
            fname, "-", "_schema_version",
            f"{V2_REQUIRED_FROM} 以降の発行日は _schema_version='2.0' が必須"
            f"（発行時刻・入力上限時刻・本文ハッシュ・target_event を固定するため）。"
            f"現在: {data.get('_schema_version')!r}",
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
            check_forecast(rep, fname, forecast, seen_ids, file_date, day_count,
                           schema_version=data.get("_schema_version", "1.0"))


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

    # 勧告（非致命）は違反の有無に関わらず stderr に表示する（exit code には影響しない）
    if rep.advisories:
        print("\n[勧告・人間レビュー喚起（非致命・exit codeに影響しない）]", file=sys.stderr)
        for line in rep.advisories:
            print(f"  ⚠ {line}", file=sys.stderr)

    if rep.violations:
        for line in rep.violations:
            print(line)
        print(
            f"\nNG: {len(files)} ファイル中に違反 {rep.count} 件"
            f"（別途 勧告 {rep.advisory_count} 件）。",
            file=sys.stderr,
        )
        sys.exit(1)

    suffix = f"・勧告 {rep.advisory_count} 件（stderr参照）" if rep.advisories else ""
    print(f"OK: {len(files)} ファイル・違反 0 件{suffix}。")
    sys.exit(0)


if __name__ == "__main__":
    main()
