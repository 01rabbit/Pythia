#!/usr/bin/env python3
"""類似過去事例検索（Case-Based Retrieval）— 予報エンジン Step C'' の決定論的検索器。

forecaster/case-based-retrieval-design.md の §3〜§6 を実装する。当日の予報候補
（発行前）に類似する『検証済みの過去予報』を、蓄積データから決定論的に検索し、
その検証実績（hit/miss/partial）を集計して返す。LLM の記憶に過去事例を捏造させず、
出典のあるデータのみから引く（CLAUDE.md 行動原則1・Evidence起点）。

データソース（すべて既存・読み取り専用）:
- forecaster/verification/YYYY-MM.json      … 予報→実績の紐付け（一次価値）
- forecaster/forecasts/daily/YYYY-MM-DD.json … 過去予報のサイドカー（related_group / kev_snapshot 等）
- forecaster/observations/YYYY/MM/*.json     … related_observation_ids で join（TTP・actor・CVE・stage）
- forecaster/knowledge/group-aliases.json    … actor 名寄せ（canonical / parent_group）
- forecaster/knowledge/product-categories.json … CVE/製品→カテゴリ抽象化

濫用防止ガード（design §6・非交渉）:
- verified_outcome を持つ事例のみ集計（未検証 null / unverifiable は分母に入れない）
- 最小サンプル数ゲート（既定3件）未満は observed_gate_passed=false（base_rate 較正に使わない）
- 本スクリプトは読むだけ。knowledge / 予報の書き換えは一切しない
- スコア重み・閾値は暫定値。現バイアス定義セットで過学習しないこと（design §8）

使い方:
    # 候補キーをインラインJSONで渡す
    python3 scripts/retrieve_similar_cases.py --date 2026-07-10 \
        --candidate '{"outcome_channel":"E1","cve":["CVE-2026-8451"],"actor_group":"APT38","techniques":["T1190"],"exploitation_stage":"kev_listed","forecast_class":"fast_72h","tier":"T1"}'

    # 候補キーをファイルで渡す
    python3 scripts/retrieve_similar_cases.py --date 2026-07-10 --candidate path/to/candidate.json

出力: 集計結果 JSON を stdout（--out 指定時はファイルへ）。design §5.1 の構造。
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORECASTER = os.path.join(REPO_ROOT, "forecaster")
VERIFICATION_DIR = os.path.join(FORECASTER, "verification")
FORECASTS_DIR = os.path.join(FORECASTER, "forecasts", "daily")
OBSERVATIONS_GLOB = os.path.join(FORECASTER, "observations", "*", "*", "*.json")
ALIASES_PATH = os.path.join(FORECASTER, "knowledge", "group-aliases.json")
PRODUCT_CATEGORIES_PATH = os.path.join(FORECASTER, "knowledge", "product-categories.json")

# design §4.2 の重み（暫定・過学習禁止）。合計 1.0。
WEIGHTS = {
    "outcome_channel": 0.30,
    "actor_canonical": 0.20,
    "cve_product_category": 0.20,
    "techniques": 0.15,
    "tactics": 0.05,
    "exploitation_stage": 0.05,
    "forecast_class": 0.05,
}

DEFAULT_TOP_N = 5
DEFAULT_MIN_SIMILARITY = 0.50
DEFAULT_MIN_SAMPLE = 3

# 集計対象とする検証結果（verified_outcome を持つもののみ・design §6 ガード4）。
# unverifiable / null / 未知値は分母に入れない。
COUNTED_OUTCOMES = {"hit", "partial", "miss"}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def is_valid_date(value):
    if not isinstance(value, str):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def jaccard(a, b):
    """集合 a, b の Jaccard 係数。両方空なら 0（共通の根拠なしとみなす）。"""
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0


# ---------------------------------------------------------------------------
# knowledge ロード
# ---------------------------------------------------------------------------

def build_alias_maps(aliases_path):
    """group-aliases.json から (canonical化マップ, canonical->parent) を作る。
    キーは小文字化した alias/canonical。値は正規 canonical 文字列。"""
    alias_to_canonical = {}
    canonical_to_parent = {}
    if not os.path.isfile(aliases_path):
        return alias_to_canonical, canonical_to_parent
    data = load_json(aliases_path)
    for canonical, entry in data.get("groups", {}).items():
        canon = entry.get("canonical", canonical)
        alias_to_canonical[canon.lower()] = canon
        for al in entry.get("aliases", []):
            alias_to_canonical[al.lower()] = canon
        parent = entry.get("parent_group")
        if parent:
            canonical_to_parent[canon] = parent
    return alias_to_canonical, canonical_to_parent


def normalize_actor(raw, alias_to_canonical, canonical_to_parent):
    """生の actor 文字列を {canonical, parent} の集合へ正規化する（名寄せ・アンブレラ含む）。
    未知グループは元文字列のまま単集合で返す。"""
    if not raw or not isinstance(raw, str):
        return set()
    canon = alias_to_canonical.get(raw.lower(), raw)
    result = {canon}
    parent = canonical_to_parent.get(canon)
    if parent:
        result.add(parent)
    return result


def build_product_category_resolver(path):
    """product-categories.json から CVE→カテゴリ集合を解決する関数を返す。
    resolver(cve, summary_text) -> set[str]。"""
    if os.path.isfile(path):
        data = load_json(path)
    else:
        data = {}
    cve_overrides = {
        k: v for k, v in data.get("cve_overrides", {}).items() if not k.startswith("_")
    }
    keyword_map = {
        k: v for k, v in data.get("product_keyword_map", {}).items() if not k.startswith("_")
    }

    def resolver(cve, summary_text):
        cats = set()
        if cve and cve in cve_overrides:
            cats.add(cve_overrides[cve])
            return cats
        hay = (summary_text or "").lower()
        for kw, cat in keyword_map.items():
            if kw in hay:
                cats.add(cat)
        return cats

    return resolver


# ---------------------------------------------------------------------------
# 観測インデックス（observation_id -> observation, および CVE→summary 逆引き用）
# ---------------------------------------------------------------------------

def build_observation_index():
    obs_by_id = {}
    for path in glob.glob(OBSERVATIONS_GLOB):
        try:
            data = load_json(path)
        except (json.JSONDecodeError, OSError):
            continue
        for obs in data.get("observations", []):
            oid = obs.get("observation_id")
            if oid:
                obs_by_id[oid] = obs
    return obs_by_id


def summary_for_cve(cve, obs_by_id):
    """CVE を含む observation の summary + source.name を連結して返す（製品キーワード照合用）。"""
    parts = []
    for obs in obs_by_id.values():
        if cve in (obs.get("cve") or []):
            parts.append(obs.get("summary", ""))
            parts.append((obs.get("source") or {}).get("name", ""))
    return " ".join(parts)


# ---------------------------------------------------------------------------
# 候補・過去事例のキー抽出
# ---------------------------------------------------------------------------

def extract_keys_from_candidate(cand, alias_to_canonical, canonical_to_parent,
                                cat_resolver, obs_by_id):
    """当日の予報候補（キーJSON）から検索キーを組み立てる。"""
    cve_list = cand.get("cve") or []
    categories = set()
    for cve in cve_list:
        categories |= cat_resolver(cve, summary_for_cve(cve, obs_by_id))
    # 候補が product カテゴリを直接指定していれば併合（CVE未確定時の手動指定を許容）
    for c in cand.get("product_categories") or []:
        categories.add(c)

    actors = set()
    actors |= normalize_actor(cand.get("actor_group"), alias_to_canonical, canonical_to_parent)
    for a in cand.get("related_group") if isinstance(cand.get("related_group"), list) else []:
        actors |= normalize_actor(a, alias_to_canonical, canonical_to_parent)
    if isinstance(cand.get("related_group"), str):
        actors |= normalize_actor(cand.get("related_group"), alias_to_canonical, canonical_to_parent)

    return {
        "outcome_channel": cand.get("outcome_channel"),
        "forecast_class": cand.get("forecast_class"),
        "tier": cand.get("tier"),
        "exploitation_stage": cand.get("exploitation_stage"),
        "actor_canonical": actors,
        "cve_product_category": categories,
        "techniques": set(cand.get("techniques") or []),
        "tactics": set(cand.get("tactics") or []),
    }


def extract_keys_from_case(entry, forecast_sidecar, obs_by_id,
                           alias_to_canonical, canonical_to_parent, cat_resolver):
    """検証エントリ + サイドカー予報 + 関連観測から、過去事例の検索キーを組み立てる。"""
    related_ids = entry.get("related_observation_ids") or []
    related_obs = [obs_by_id[i] for i in related_ids if i in obs_by_id]

    # CVE集合: 検証エントリの kev_snapshot_diff + サイドカー kev_snapshot + 関連観測の cve
    cves = set()
    diff = entry.get("kev_snapshot_diff") or {}
    if diff.get("cve_id"):
        cves.add(diff["cve_id"])
    if forecast_sidecar:
        snap = forecast_sidecar.get("kev_snapshot") or {}
        if snap.get("cve"):
            cves.add(snap["cve"])
    for obs in related_obs:
        for c in obs.get("cve") or []:
            cves.add(c)

    categories = set()
    for cve in cves:
        categories |= cat_resolver(cve, summary_for_cve(cve, obs_by_id))

    # actor: サイドカー related_group を優先、なければ関連観測の actor_group
    actors = set()
    if forecast_sidecar and forecast_sidecar.get("related_group"):
        actors |= normalize_actor(forecast_sidecar["related_group"],
                                  alias_to_canonical, canonical_to_parent)
    for obs in related_obs:
        actors |= normalize_actor(obs.get("actor_group"),
                                  alias_to_canonical, canonical_to_parent)

    techniques = set()
    tactics = set()
    for obs in related_obs:
        for t in obs.get("techniques") or []:
            if t.get("technique_id"):
                techniques.add(t["technique_id"])
            if t.get("tactic"):
                tactics.add(t["tactic"])

    # exploitation_stage: 関連観測の最上位ステージ（優先順は observation.schema の定義に従う）
    stage_priority = ["active_exploitation", "kev_listed", "poc_public",
                      "limited_exploitation", "none", "unknown"]
    stages = [obs.get("exploitation_stage") for obs in related_obs
              if obs.get("exploitation_stage")]
    exploitation_stage = None
    for s in stage_priority:
        if s in stages:
            exploitation_stage = s
            break

    return {
        "outcome_channel": entry.get("outcome_channel"),
        "forecast_class": entry.get("forecast_class"),
        "tier": entry.get("tier"),
        "exploitation_stage": exploitation_stage,
        "actor_canonical": actors,
        "cve_product_category": categories,
        "techniques": techniques,
        "tactics": tactics,
    }


# ---------------------------------------------------------------------------
# 類似度スコアリング（design §4.2）
# ---------------------------------------------------------------------------

def score_case(cand_keys, case_keys):
    """候補と過去事例の重み付き類似度（0〜1）と、寄与した要素名リストを返す。"""
    matched_on = []
    total = 0.0

    def exact(name):
        cv, xv = cand_keys.get(name), case_keys.get(name)
        if cv is not None and xv is not None and cv == xv:
            return 1.0
        return 0.0

    # 完全一致系
    for name in ("outcome_channel", "exploitation_stage", "forecast_class"):
        s = exact(name)
        if s > 0:
            matched_on.append(name)
        total += WEIGHTS[name] * s

    # actor: 集合の共通要素があれば一致（canonical / parent どちらでも）
    if cand_keys["actor_canonical"] & case_keys["actor_canonical"]:
        total += WEIGHTS["actor_canonical"]
        matched_on.append("actor_canonical")

    # 集合系（Jaccard）
    for name in ("cve_product_category", "techniques", "tactics"):
        s = jaccard(cand_keys[name], case_keys[name])
        if s > 0:
            matched_on.append(name)
        total += WEIGHTS[name] * s

    return round(total, 4), matched_on


# ---------------------------------------------------------------------------
# メイン検索
# ---------------------------------------------------------------------------

def load_all_verification_entries():
    entries = []
    for path in sorted(glob.glob(os.path.join(VERIFICATION_DIR, "*.json"))):
        try:
            data = load_json(path)
        except (json.JSONDecodeError, OSError):
            continue
        for e in data.get("entries", []):
            entries.append(e)
    return entries


def load_forecast_sidecar(forecast_date, forecast_index):
    """指定日のサイドカー予報から forecast_index の1件を返す（なければ None）。"""
    path = os.path.join(FORECASTS_DIR, f"{forecast_date}.json")
    if not os.path.isfile(path):
        return None
    try:
        data = load_json(path)
    except (json.JSONDecodeError, OSError):
        return None
    for fc in data.get("forecasts", []):
        if fc.get("forecast_index") == forecast_index:
            return fc
    return None


def retrieve(cand, issue_date, top_n, min_similarity, min_sample):
    alias_to_canonical, canonical_to_parent = build_alias_maps(ALIASES_PATH)
    cat_resolver = build_product_category_resolver(PRODUCT_CATEGORIES_PATH)
    obs_by_id = build_observation_index()

    cand_keys = extract_keys_from_candidate(
        cand, alias_to_canonical, canonical_to_parent, cat_resolver, obs_by_id
    )

    scored = []
    for entry in load_all_verification_entries():
        fdate = entry.get("forecast_date")
        if not is_valid_date(fdate):
            continue
        # 過去事例のみ（発行日より前）。同日以降は未来リークになるため除外。
        if issue_date is not None and fdate >= issue_date:
            continue
        outcome = entry.get("outcome")
        if outcome not in COUNTED_OUTCOMES:
            continue  # ガード4: 未検証・検証不能は集計対象外

        findex = entry.get("forecast_index")
        sidecar = load_forecast_sidecar(fdate, findex)
        case_keys = extract_keys_from_case(
            entry, sidecar, obs_by_id,
            alias_to_canonical, canonical_to_parent, cat_resolver
        )
        similarity, matched_on = score_case(cand_keys, case_keys)
        if similarity < min_similarity:
            continue

        fid = f"fc-{fdate.replace('-', '')}-{findex}" if findex else None
        scored.append({
            "forecast_id": fid,
            "forecast_date": fdate,
            "forecast_title": entry.get("forecast_title"),
            "similarity": similarity,
            "outcome": outcome,
            "outcome_channel": entry.get("outcome_channel"),
            "tier": entry.get("tier"),
            "confidence": entry.get("confidence"),
            "matched_on": matched_on,
            "verification_evidence": (entry.get("evidence_for_outcome") or "")[:280],
        })

    scored.sort(key=lambda x: x["similarity"], reverse=True)
    matched = scored[:top_n]

    n = len(matched)
    n_hit = sum(1 for c in matched if c["outcome"] == "hit")
    n_partial = sum(1 for c in matched if c["outcome"] == "partial")
    n_miss = sum(1 for c in matched if c["outcome"] == "miss")
    empirical = round((n_hit + n_partial) / n, 4) if n else None
    strict = round(n_hit / n, 4) if n else None

    return {
        "_generated_for_date": issue_date,
        "candidate_keys": {
            "outcome_channel": cand_keys["outcome_channel"],
            "forecast_class": cand_keys["forecast_class"],
            "tier": cand_keys["tier"],
            "exploitation_stage": cand_keys["exploitation_stage"],
            "actor_canonical": sorted(cand_keys["actor_canonical"]),
            "cve_product_category": sorted(cand_keys["cve_product_category"]),
            "techniques": sorted(cand_keys["techniques"]),
            "tactics": sorted(cand_keys["tactics"]),
        },
        "params": {
            "top_n": top_n,
            "min_similarity": min_similarity,
            "min_sample": min_sample,
            "weights": WEIGHTS,
        },
        "matched_cases": matched,
        "aggregate": {
            "n_cases": n,
            "n_hit": n_hit,
            "n_partial": n_partial,
            "n_miss": n_miss,
            "empirical_hit_rate": empirical,
            "hit_rate_strict": strict,
            "observed_gate_passed": n >= min_sample,
            "matched_forecast_ids": [c["forecast_id"] for c in matched if c["forecast_id"]],
        },
        "guidance": _guidance(n, min_sample, empirical),
    }


def _guidance(n, min_sample, empirical):
    """スクリプト自身が返す運用ガイダンス（design §5.2・§6）。予報生成側が読む注意書き。"""
    if n == 0:
        return ("類似過去事例なし。base_rate_estimate の較正には使えない。"
                "「過去パターン」欄は該当なしとし、他ステップの観測事実で予報する。")
    if n < min_sample:
        return (f"類似事例 {n} 件（最小サンプル {min_sample} 未満）。observed_gate_passed=false。"
                "参考表示に留め、base_rate_estimate の自動較正には使わない（design §6 ガード3）。")
    hint = ""
    if empirical is not None and empirical == 0.0:
        hint = ("★類似事例が全滅（経験的的中率0%）。この型は確度降格・発行見送り・注意点格下げの"
                "根拠にしてよい（降格方向のみ・design §6 ガード1）。教訓14型の自動再発見に相当。")
    return (f"類似事例 {n} 件・observed_gate_passed=true。empirical_hit_rate を base_rate_estimate の"
            f"較正の参考に使える。ただし確度の引き上げには使わない（降格方向のみ）。{hint}")


def parse_candidate(arg):
    """--candidate をインラインJSONまたはファイルパスとして読む。"""
    if arg is None:
        print("エラー: --candidate は必須（候補キーの JSON かファイルパス）。", file=sys.stderr)
        sys.exit(2)
    if os.path.isfile(arg):
        return load_json(arg)
    try:
        return json.loads(arg)
    except json.JSONDecodeError as exc:
        print(f"エラー: --candidate を JSON として解釈できない: {exc}", file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(
        description="類似過去事例検索（Case-Based Retrieval・予報 Step C''）。"
        "検証済み過去予報から当日候補に類似する事例を引き、実績を集計して JSON で返す。"
    )
    parser.add_argument("--date", help="発行日（YYYY-MM-DD）。これより前の過去事例のみ対象（未来リーク防止）。")
    parser.add_argument("--candidate", help="予報候補キーの JSON（インラインまたはファイルパス）。")
    parser.add_argument("--top-n", type=int, default=DEFAULT_TOP_N)
    parser.add_argument("--min-similarity", type=float, default=DEFAULT_MIN_SIMILARITY)
    parser.add_argument("--min-sample", type=int, default=DEFAULT_MIN_SAMPLE)
    parser.add_argument("--out", help="出力先ファイル（省略時は stdout）。")
    args = parser.parse_args()

    if args.date is not None and not is_valid_date(args.date):
        print(f"エラー: --date は YYYY-MM-DD 形式で指定する: {args.date!r}", file=sys.stderr)
        sys.exit(2)

    cand = parse_candidate(args.candidate)
    result = retrieve(cand, args.date, args.top_n, args.min_similarity, args.min_sample)

    out_text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out_text + "\n")
        print(f"書き出し: {args.out}", file=sys.stderr)
    else:
        print(out_text)


if __name__ == "__main__":
    main()
