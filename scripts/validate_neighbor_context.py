#!/usr/bin/env python3
"""Section 5（周辺諸国動向）の `neighbor_context` を検証する fail-closed ゲート。

Section 5 は『報告専用』の文脈層であり、予報の入力（観測・ベースライン・base_rate）には
入らない。この性質と、行動原則（事実と推測の分離・帰属の慎重さ・ハルシネーション厳禁）を
機械的に守らせるのが本スクリプトの役割である。

検査項目（エラー = コミットしてはならない）:
  [E] 構造: 必須項目・語彙（国・区分・国との関係・確度・出典区分）
  [E] entry_id 形式（nbr-YYYY-MM-DD-NNN・日付一致・一意）と info_id の再計算一致
  [E] 事実と推測の分離: 事実に『（推測）』が混在しない／評価・非サイバー関連の評価は
      『（推測）』を含み確度を持つ
  [E] 帰属: 国家との関係を情報源が明示した場合のみ attribution（情報源名と原文の言い回し）を
      持てる。それ以外は attribution を持てない。TTP・観測・予報の項目は持てない
  [E] 出典評価: 国営メディアを参照する場合は state_affiliated=true と注意書きが必須
  [E] 処理ゲート: スキャンのゲート対象（窓内・関連度が下限以上・重複除く）の全件が
      『採用』または『理由付き除外』に割り当てられている（--scan 指定時に再計算して照合）
  [E] 予報との分離: 当日の観測ファイルと予報（forecasts / tactical_forecast）に nbr- ID が
      現れない
  [E] statistics.neighbor_context と配列の一致
  [W] neighbor_context が無い（段階導入中は警告。--require でエラーにする）

使い方:
    python3 scripts/validate_neighbor_context.py --date 2026-11-06 \\
        --scan .cache/daily-security-intel/2026-11-06/neighbor-scan.json --require

終了コード: 0=エラーなし / 1=エラーあり（警告のみなら 0）

★読み取り専用。forecaster/knowledge/ を含む一切のファイルを書き換えない（行動原則5）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import watchlist as wl  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
JST = timezone(timedelta(hours=9))

CATEGORIES = ("activity", "policy", "organization", "company", "geopolitical")
COUNTRY_BASES = ("state_attributed_by_source", "located_in_country", "target_country", "context_only")
CONFIDENCES = ("low", "medium", "high")
CONTEXT_TYPES = ("strategy", "politics", "national_sentiment", "military_org")
SOURCE_CLASSES = ("government", "vendor", "research", "news", "state_media", "other")
DECISIONS = ("adopted", "excluded")
EXCLUDE_REASONS = ("no_neighbor_relation", "out_of_scope", "duplicate_of_entry",
                   "insufficient_evidence", "marketing", "mentioned_only")
SCAN_STATUSES = ("ok", "failed", "disabled")

ENTRY_ID_RE = re.compile(r"^nbr-(\d{4}-\d{2}-\d{2})-(\d{3})$")
INFO_ID_RE = re.compile(r"^(\d{8})-NBRC-([0-9a-f]{8})$")
SPECULATION_MARK = "（推測）"
# 予報の入力層に属する項目。Section 5 のエントリは持ってはならない
FORBIDDEN_KEYS = ("techniques", "ttps", "actor_group", "mitre_id", "observation_id",
                  "forecast_id", "base_rate", "base_rate_estimate", "verified_outcome")
MAX_WORDING = 300


def info_id_for(date: str, title: str, first_url: str) -> str:
    """pipeline-output-schema.md「info_id」と同じ規則（カテゴリ NBRC）。"""
    ymd = date.replace("-", "")
    digest = hashlib.sha256(f"{ymd}::{title}::{first_url}".encode("utf-8")).hexdigest()[:8]
    return f"{ymd}-NBRC-{digest}"


def _walk_keys(node, path=""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield f"{path}.{key}" if path else key, key
            yield from _walk_keys(value, f"{path}.{key}" if path else key)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _walk_keys(item, f"{path}[{i}]")


def _is_nonempty_str(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _check_assessment(label: str, obj, errors: list, *, required: bool) -> None:
    if obj is None:
        if required:
            errors.append(f"{label} が null（必須）")
        return
    if not isinstance(obj, dict):
        errors.append(f"{label} がオブジェクトでない")
        return
    text = obj.get("text")
    if not _is_nonempty_str(text):
        errors.append(f"{label}.text が空")
    elif SPECULATION_MARK not in text:
        errors.append(f"{label}.text に『{SPECULATION_MARK}』が無い（推測は明示する・行動原則2）")
    if obj.get("confidence") not in CONFIDENCES:
        errors.append(f"{label}.confidence は {CONFIDENCES} のいずれか（実際: {obj.get('confidence')!r}）")


def _check_fact(label: str, fact, n_refs: int, errors: list) -> None:
    if not isinstance(fact, dict):
        errors.append(f"{label} がオブジェクトでない")
        return
    statement = fact.get("statement")
    if not _is_nonempty_str(statement):
        errors.append(f"{label}.statement が空")
    elif SPECULATION_MARK in statement:
        errors.append(f"{label}.statement に『{SPECULATION_MARK}』が混在している"
                      "（事実と推測は分ける・行動原則2）")
    ref = fact.get("ref")
    if not isinstance(ref, int) or isinstance(ref, bool) or not (0 <= ref < n_refs):
        errors.append(f"{label}.ref が references の範囲外（0〜{n_refs - 1}）: {ref!r}")


def validate_entry(entry, index: int, date: str, enabled: dict) -> list[str]:
    """1 エントリを検査して、エラーメッセージのリストを返す。"""
    eid = entry.get("entry_id") if isinstance(entry, dict) else None
    tag = f"entries[{index}]({eid})"
    errors: list[str] = []
    if not isinstance(entry, dict):
        return [f"entries[{index}] がオブジェクトでない"]

    def err(msg: str) -> None:
        errors.append(f"{tag}: {msg}")

    m = ENTRY_ID_RE.match(eid or "")
    if not m:
        err("entry_id は nbr-YYYY-MM-DD-NNN 形式")
    elif m.group(1) != date:
        err(f"entry_id の日付 {m.group(1)} がレポート日付 {date} と一致しない")

    country = entry.get("country")
    if country not in enabled:
        err(f"country {country!r} は config.yml neighbor_states で有効な国ではない（{sorted(enabled)}）")
    elif entry.get("tier") != enabled[country]:
        err(f"tier {entry.get('tier')!r} は config の {enabled[country]!r} と一致しない")

    category = entry.get("category")
    if category not in CATEGORIES:
        err(f"category は {CATEGORIES} のいずれか（実際: {category!r}）")
    basis = entry.get("country_basis")
    if basis not in COUNTRY_BASES:
        err(f"country_basis は {COUNTRY_BASES} のいずれか（実際: {basis!r}）")
    if not _is_nonempty_str(entry.get("title")):
        err("title が空")
    if entry.get("forecast_input") is not False:
        err("forecast_input は false 固定（Section 5 は予報の入力に使わない）")

    for path, key in _walk_keys(entry):
        if key in FORBIDDEN_KEYS:
            err(f"{path}: 予報の入力層の項目は持てない（TTP・観測・予報は APT エントリ側で扱う）")

    # --- 出典 ---
    refs = entry.get("references")
    if not isinstance(refs, list) or not refs:
        err("references が空（出典の無い主張は記録しない）")
        refs = []
    for i, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"references[{i}] がオブジェクトでない")
            continue
        if not re.match(r"^https?://", str(ref.get("url") or "")):
            err(f"references[{i}].url が http(s) の URL でない")
        if ref.get("source_class") not in SOURCE_CLASSES:
            err(f"references[{i}].source_class は {SOURCE_CLASSES} のいずれか（実際: {ref.get('source_class')!r}）")

    # --- info_id（決定的に再計算できること）---
    info_id = entry.get("info_id")
    im = INFO_ID_RE.match(info_id or "")
    if not im:
        err("info_id は YYYYMMDD-NBRC-xxxxxxxx 形式")
    elif refs and isinstance(refs[0], dict) and _is_nonempty_str(entry.get("title")):
        expected = info_id_for(date, entry["title"], str(refs[0].get("url") or ""))
        if info_id != expected:
            err(f"info_id が規則（日付::title::references[0].url の SHA-256 先頭8桁）と一致しない（期待 {expected}）")

    # --- 事実 ---
    facts = entry.get("facts")
    if not isinstance(facts, list) or not facts:
        err("facts が空（事実を1件以上、出典番号付きで記録する）")
        facts = []
    for i, fact in enumerate(facts):
        sub: list[str] = []
        _check_fact(f"facts[{i}]", fact, len(refs), sub)
        errors.extend(f"{tag}: {m_}" for m_ in sub)

    # --- 推測（評価）---
    sub = []
    _check_assessment("assessment", entry.get("assessment"), sub, required=False)
    errors.extend(f"{tag}: {m_}" for m_ in sub)

    # --- 非サイバー情勢との関連（分析 c）---
    linkage = entry.get("non_cyber_linkage")
    if category == "geopolitical" and linkage is None:
        err("category=geopolitical は non_cyber_linkage が必須"
            "（非サイバー情報は、サイバーとの関連を示す形でのみ記録する）")
    if linkage is not None:
        if not isinstance(linkage, dict):
            err("non_cyber_linkage がオブジェクトでない")
        else:
            if linkage.get("context_type") not in CONTEXT_TYPES:
                err(f"non_cyber_linkage.context_type は {CONTEXT_TYPES} のいずれか"
                    f"（実際: {linkage.get('context_type')!r}）")
            sub = []
            _check_fact("non_cyber_linkage.fact", linkage.get("fact"), len(refs), sub)
            _check_assessment("non_cyber_linkage.assessment", linkage.get("assessment"), sub, required=True)
            errors.extend(f"{tag}: {m_}" for m_ in sub)

    # --- 帰属 ---
    attribution = entry.get("attribution")
    if basis == "state_attributed_by_source":
        if category != "activity":
            err("country_basis=state_attributed_by_source は category=activity のときだけ使える")
        if not isinstance(attribution, dict):
            err("国家との関係を情報源が明示した場合は attribution（stated_by / wording / confidence）が必須")
        else:
            if not _is_nonempty_str(attribution.get("stated_by")):
                err("attribution.stated_by（明示した情報源名）が空")
            wording = attribution.get("wording")
            if not _is_nonempty_str(wording):
                err("attribution.wording（情報源の原文の言い回し）が空")
            elif len(wording) > MAX_WORDING:
                err(f"attribution.wording は {MAX_WORDING} 字以内の引用にする")
            if attribution.get("confidence") not in CONFIDENCES:
                err(f"attribution.confidence は {CONFIDENCES} のいずれか")
    elif attribution is not None:
        err("attribution は country_basis=state_attributed_by_source のときだけ持てる"
            "（TTP の類似や国名の言及だけで帰属を記録しない・行動原則3）")

    # --- 出典の評価（分析 e）---
    sa = entry.get("source_assessment")
    if not isinstance(sa, dict):
        err("source_assessment（出典の妥当性評価）が無い")
    else:
        if not isinstance(sa.get("primary_source"), bool):
            err("source_assessment.primary_source は真偽値")
        n = sa.get("independent_sources")
        if not isinstance(n, int) or isinstance(n, bool) or n < 1:
            err("source_assessment.independent_sources は 1 以上の整数")
        if not isinstance(sa.get("state_affiliated"), bool):
            err("source_assessment.state_affiliated は真偽値")
        has_state_media = any(isinstance(r, dict) and r.get("source_class") == "state_media" for r in refs)
        if has_state_media and sa.get("state_affiliated") is not True:
            err("国営メディアを参照しているが source_assessment.state_affiliated が true でない")
        if sa.get("state_affiliated") is True and not _is_nonempty_str(sa.get("caveat")):
            err("state_affiliated=true のときは caveat"
                "（その国の政府の主張であり事実の裏付けではない旨）が必須")

    for key in ("candidate_ids", "related_apt_campaign_ids", "related_cves"):
        if not isinstance(entry.get(key), list):
            err(f"{key} は配列")
    return errors


def validate(report: dict, *, date: str, enabled: dict, scan: dict | None = None,
             observation_text: str | None = None, require: bool = False) -> tuple[list[str], list[str]]:
    """neighbor_context を検査し (errors, warnings) を返す。純関数（I/O なし）。"""
    errors: list[str] = []
    warnings: list[str] = []
    nc = report.get("neighbor_context")
    if nc is None:
        msg = f"{date}: neighbor_context が無い（Step 2c 未実施の可能性）"
        (errors if require else warnings).append(msg)
        return errors, warnings
    if not isinstance(nc, dict):
        return [f"{date}: neighbor_context がオブジェクトでない"], warnings

    entries = nc.get("entries")
    if not isinstance(entries, list):
        return [f"{date}: neighbor_context.entries が配列でない"], warnings

    seen_ids: set[str] = set()
    for i, entry in enumerate(entries):
        errors.extend(f"{date}: {m}" for m in validate_entry(entry, i, date, enabled))
        eid = entry.get("entry_id") if isinstance(entry, dict) else None
        if eid in seen_ids:
            errors.append(f"{date}: entry_id {eid} が重複している")
        if eid:
            seen_ids.add(eid)
    entry_ids = {e.get("entry_id") for e in entries if isinstance(e, dict)}
    candidates_by_entry = {e.get("entry_id"): set(e.get("candidate_ids") or [])
                           for e in entries if isinstance(e, dict)}

    # --- 処理の記録 ---
    dispositions = nc.get("dispositions")
    if not isinstance(dispositions, list):
        errors.append(f"{date}: neighbor_context.dispositions が配列でない")
        dispositions = []
    handled: set[str] = set()
    excluded_count = 0
    for i, d in enumerate(dispositions):
        if not isinstance(d, dict) or not _is_nonempty_str(d.get("candidate_id")):
            errors.append(f"{date}: dispositions[{i}] に candidate_id が無い")
            continue
        cid = d["candidate_id"]
        decision = d.get("decision")
        if decision not in DECISIONS:
            errors.append(f"{date}: dispositions[{i}]({cid}).decision は {DECISIONS} のいずれか")
            continue
        handled.add(cid)
        if decision == "adopted":
            eid = d.get("entry_id")
            if eid not in entry_ids:
                errors.append(f"{date}: dispositions[{i}]({cid}) の entry_id {eid!r} が entries に無い")
            elif cid not in candidates_by_entry.get(eid, set()):
                errors.append(f"{date}: dispositions[{i}]({cid}) が entries の {eid} の candidate_ids に無い")
        else:
            excluded_count += 1
            reason = d.get("reason")
            if reason not in EXCLUDE_REASONS:
                errors.append(f"{date}: dispositions[{i}]({cid}).reason は {EXCLUDE_REASONS} のいずれか"
                              f"（実際: {reason!r}）")
            if reason == "duplicate_of_entry" and d.get("entry_id") not in entry_ids:
                errors.append(f"{date}: dispositions[{i}]({cid}) の duplicate_of_entry は"
                              " 実在する entry_id を指す必要がある")

    # --- 処理ゲート ---
    declared = nc.get("scan")
    if not isinstance(declared, dict):
        errors.append(f"{date}: neighbor_context.scan が無い（候補件数・未処理件数を転記する）")
        declared = {}
    status = declared.get("status")
    if status not in SCAN_STATUSES:
        errors.append(f"{date}: neighbor_context.scan.status は {SCAN_STATUSES} のいずれか")
    if status == "failed":
        warnings.append(f"{date}: neighbor_context.scan.status=failed（走査失敗。ゲートは評価されていない）")
    elif status == "ok":
        if declared.get("unhandled") != 0:
            errors.append(f"{date}: neighbor_context.scan.unhandled={declared.get('unhandled')!r}"
                          "（未処理を残したままコミットしてはならない）")
        if scan is None:
            warnings.append(f"{date}: --scan が無いためゲートを再計算していない"
                            "（宣言値 unhandled=0 のみを確認）")
        else:
            if scan.get("date") != date:
                errors.append(f"{date}: スキャン結果の日付 {scan.get('date')!r} が一致しない")
            gated = {c["candidate_id"] for c in scan.get("candidates", []) if c.get("gated")}
            missing = sorted(gated - handled)
            if missing:
                errors.append(f"{date}: ゲート対象のうち未処理 {len(missing)}件: "
                              + ", ".join(missing[:8]) + (" ほか" if len(missing) > 8 else "")
                              + "（採用または理由付き除外に割り当てること）")
            counts = scan.get("counts", {})
            for key, actual in (("candidates", counts.get("candidates")), ("gated", counts.get("gated")),
                                ("scanned_items", scan.get("scanned_items"))):
                if declared.get(key) != actual:
                    errors.append(f"{date}: neighbor_context.scan.{key}={declared.get(key)!r} だが"
                                  f"スキャン結果は {actual!r}（転記は推定せず出力をそのまま写す）")
            if declared.get("handled") != len(gated & handled):
                errors.append(f"{date}: neighbor_context.scan.handled={declared.get('handled')!r} だが"
                              f"再計算は {len(gated & handled)}")

    # --- 予報との分離 ---
    if observation_text and "nbr-" in observation_text:
        errors.append(f"{date}: 当日の観測ファイルに nbr- ID が現れる"
                      "（Section 5 は観測へ取り込まない・予報の入力に使わない）")
    for key in ("forecasts", "tactical_forecast"):
        if "nbr-" in json.dumps(report.get(key), ensure_ascii=False):
            errors.append(f"{date}: {key} が nbr- ID を参照している（Section 5 は予報の根拠にしない）")

    # --- statistics ---
    stats = (report.get("statistics") or {}).get("neighbor_context")
    if stats is not None:
        if stats.get("entries") != len(entries):
            errors.append(f"{date}: statistics.neighbor_context.entries={stats.get('entries')!r}"
                          f" だが entries の要素数は {len(entries)}")
        if "excluded" in stats and stats["excluded"] != excluded_count:
            errors.append(f"{date}: statistics.neighbor_context.excluded={stats['excluded']!r}"
                          f" だが除外の処理記録は {excluded_count}")
        by_cat = stats.get("by_category")
        if isinstance(by_cat, dict):
            actual = {c: sum(1 for e in entries if isinstance(e, dict) and e.get("category") == c)
                      for c in CATEGORIES}
            if {k: by_cat.get(k, 0) for k in CATEGORIES} != actual:
                errors.append(f"{date}: statistics.neighbor_context.by_category が entries と一致しない"
                              f"（実際 {actual}）")
    return errors, warnings


def enabled_countries(config: dict, registry: dict) -> dict:
    section = config.get("neighbor_states") or {}
    known = set((registry.get("countries") or {}).keys())
    enabled: dict[str, str] = {}
    for tier in ("primary", "regional"):
        codes = section.get(tier) or []
        if isinstance(codes, str):
            codes = [codes]
        for code in codes:
            code = str(code).upper()
            if code in known:
                enabled.setdefault(code, tier)
    return enabled


def observation_path(root: Path, date: str) -> Path:
    return root / "forecaster" / "observations" / date[:4] / date[5:7] / f"{date}.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Section 5（neighbor_context）を検証する（読み取り専用）")
    parser.add_argument("--date", help="検査する日付 YYYY-MM-DD（既定: JST の本日）")
    parser.add_argument("--root", default=str(REPO_ROOT), help="リポジトリルート")
    parser.add_argument("--scan", help="neighbor_scan.py の出力 JSON（指定するとゲートを再計算する）")
    parser.add_argument("--config", help="config.yml のパス（既定: <root>/config.yml）")
    parser.add_argument("--registry", help="neighbor/states.json のパス（既定: <root>/neighbor/states.json）")
    parser.add_argument("--require", action="store_true", help="neighbor_context が無い場合をエラーにする")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    date = args.date or datetime.now(JST).strftime("%Y-%m-%d")
    report_path = root / "outputs" / date / f"{date}-security-report.json"
    if not report_path.is_file():
        print(f"[ERROR] {date}: JSON が存在しない: {report_path}")
        return 1
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        print(f"[ERROR] {date}: JSON をパースできない: {err}")
        return 1

    registry_path = Path(args.registry) if args.registry else root / "neighbor" / "states.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8")) if registry_path.is_file() else {}
    config_path = Path(args.config) if args.config else root / "config.yml"
    config = wl.load_config(str(config_path)) if config_path.is_file() else {}
    enabled = enabled_countries(config, registry)

    scan = None
    if args.scan:
        scan = json.loads(Path(args.scan).read_text(encoding="utf-8"))
    obs_path = observation_path(root, date)
    obs_text = obs_path.read_text(encoding="utf-8") if obs_path.is_file() else None

    errors, warnings = validate(report, date=date, enabled=enabled, scan=scan,
                                observation_text=obs_text, require=args.require)
    for message in warnings:
        print(f"[WARN] {message}")
    for message in errors:
        print(f"[ERROR] {message}")
    if not args.quiet:
        nc = report.get("neighbor_context")
        n = len(nc.get("entries", [])) if isinstance(nc, dict) else 0
        print(f"\n{date}: neighbor_context {n}件 / エラー {len(errors)}件 / 警告 {len(warnings)}件")
        if not errors:
            print("Section 5 の検査に問題なし。")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
