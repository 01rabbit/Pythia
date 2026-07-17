#!/usr/bin/env python3
"""
forecaster/baseline/technique-freq.json と group-activity.json を
02-baseline.md（改訂版）のルールに厳密準拠して再生成する。

再実行可能。入力: forecaster/observations/**/*.json,
                  forecaster/knowledge/group-aliases.json
出力: forecaster/baseline/technique-freq.json
      forecaster/baseline/group-activity.json
"""
import json
import glob
import os
import statistics
from collections import defaultdict, Counter
from datetime import date, timedelta

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TODAY = date(2026, 7, 17)  # currentDate context

# ---------------------------------------------------------------------------
# 1. 観測データ読み込み
# ---------------------------------------------------------------------------
obs_files = sorted(glob.glob(f"{REPO}/forecaster/observations/**/*.json", recursive=True))

all_observations = []  # list of (observed_date: date, obs dict)
backfill_skipped = []  # machine_backfill_* ファイル（ベースライン統計から除外）
for f in obs_files:
    d = json.load(open(f))
    # 機械バックフィル産の観測（scripts/backfill_observations.py）は日次ルーチンと
    # 収集レジームが異なり観測密度が別物のため、混ぜると mean/stddev が歪む。除外する。
    if str(d.get("_normalization_mode", "")).startswith("machine_backfill"):
        backfill_skipped.append(os.path.basename(f))
        continue
    for o in d.get("observations", []):
        odate = date.fromisoformat(o["observed_date"])
        all_observations.append((odate, o))

if backfill_skipped:
    print(f"[backfill] machine_backfill ファイル {len(backfill_skipped)} 件を"
          f"ベースライン統計から除外 ({backfill_skipped[0]} .. {backfill_skipped[-1]})")

observed_dates_present = sorted({d for d, _ in all_observations})
period_start = observed_dates_present[0]
period_end = observed_dates_present[-1]
period_days_calendar = (period_end - period_start).days + 1

# 欠落日（カレンダー上は範囲内だが、観測ファイルが存在しない日）
all_calendar_days = [period_start + timedelta(days=i) for i in range(period_days_calendar)]
missing_days = [d for d in all_calendar_days if d not in observed_dates_present]
# データなし日は日数分母から除外する
data_days = [d for d in all_calendar_days if d not in missing_days]
baseline_period_days = len(data_days)  # 実データがある日数（分母）

print(f"[period] {period_start} .. {period_end} (calendar {period_days_calendar}d, "
      f"data_days={baseline_period_days}, missing={[str(m) for m in missing_days]})")

# ---------------------------------------------------------------------------
# 2. グループ名寄せ（group-aliases.json）
# ---------------------------------------------------------------------------
aliases_path = f"{REPO}/forecaster/knowledge/group-aliases.json"
aliases_data = json.load(open(aliases_path))
groups_def = aliases_data["groups"]

# alias(lowercase) -> canonical, canonical(lowercase) -> canonical
alias_lookup = {}
canonical_parent = {}  # canonical -> parent_group (or None)
canonical_meta = {}    # canonical -> def dict
for canon, meta in groups_def.items():
    canonical_meta[canon] = meta
    canonical_parent[canon] = meta.get("parent_group")
    alias_lookup[canon.lower()] = canon
    for a in meta.get("aliases", []):
        alias_lookup.setdefault(a.lower(), canon)  # exact-preferred handled by exact pass below

# exact-match table (case-sensitive) takes priority
exact_lookup = {}
for canon, meta in groups_def.items():
    exact_lookup[canon] = canon
    for a in meta.get("aliases", []):
        exact_lookup.setdefault(a, canon)


def resolve_canonical(actor_group):
    if actor_group is None:
        return None
    if actor_group in exact_lookup:
        return exact_lookup[actor_group]
    low = actor_group.lower()
    if low in alias_lookup:
        return alias_lookup[low]
    # 未収載グループはその名前自体を canonical として扱う
    return actor_group


unmapped_groups = set()
for odate, o in all_observations:
    ag = o.get("actor_group")
    if ag is None:
        continue
    if ag not in exact_lookup and ag.lower() not in alias_lookup:
        unmapped_groups.add(ag)

# ---------------------------------------------------------------------------
# 3. 完結週（月曜起算）の算出
# ---------------------------------------------------------------------------
def week_monday(d: date) -> date:
    return d - timedelta(days=d.weekday())


current_week_monday = week_monday(TODAY)

# 観測期間内に現れる週(月曜日付)を全て列挙
weeks_present = sorted({week_monday(d) for d in observed_dates_present})

completed_weeks = []
for wm in weeks_present:
    week_days = [wm + timedelta(days=i) for i in range(7)]
    # 完結週の条件: 7日分すべてが「集計対象期間」に含まれる週（月曜〜日曜が period_start..period_end に収まる）
    if wm == current_week_monday:
        continue  # 進行中の当週は除外
    if week_days[0] >= period_start and week_days[-1] <= period_end:
        completed_weeks.append(wm)

print(f"[weeks] current_week_monday={current_week_monday}, "
      f"weeks_present={[str(w) for w in weeks_present]}, "
      f"completed_weeks={[str(w) for w in completed_weeks]}")

current_week_elapsed_days = (TODAY - current_week_monday).days + 1
print(f"[weeks] current_week_elapsed_days={current_week_elapsed_days}")

# ---------------------------------------------------------------------------
# 4. technique-freq.json の算出
# ---------------------------------------------------------------------------
MIN_PERIOD_DAYS = 14
MIN_NONZERO_UNITS = 3

# technique_id -> per-day counts across data_days, sample_count, last_observed, tactic votes, sub-technique breakdown
tech_day_counts = defaultdict(lambda: defaultdict(int))  # technique_id -> {date: count}
tech_sample_count = Counter()
tech_last_observed = {}
tech_tactic_votes = defaultdict(Counter)
tech_subtech_breakdown = defaultdict(Counter)

for odate, o in all_observations:
    if odate in missing_days:
        continue
    for t in o.get("techniques", []):
        tid = t["technique_id"]
        tech_day_counts[tid][odate] += 1
        tech_sample_count[tid] += 1
        tech_tactic_votes[tid][t["tactic"]] += 1
        if tid not in tech_last_observed or odate > tech_last_observed[tid]:
            tech_last_observed[tid] = odate
        sub = t.get("sub_technique_id")
        if sub:
            tech_subtech_breakdown[tid][sub] += 1
        else:
            tech_subtech_breakdown[tid]["(none)"] += 1

# 既存 baseline の tactic 値（tie-break フォールバック用）
existing_tf_path = f"{REPO}/forecaster/baseline/technique-freq.json"
existing_tf = json.load(open(existing_tf_path))
existing_tactic = {
    tid: v.get("tactic")
    for tid, v in existing_tf.get("techniques", {}).items()
    if v.get("tactic") and v.get("tactic") != "unknown"
}

# MITRE 標準の代表タクティック（複数タクティックを持つ Technique の代表値。
# 確証のある根拠がある場合のみ使用。ここでは T1078 (Valid Accounts) が該当。
MITRE_PRIMARY_TACTIC_FALLBACK = {
    "T1078": "persistence",  # MITRE ATT&CK: Valid Accounts は defense-evasion/persistence/
                              # privilege-escalation/initial-access の複数タクティックを持つ。
                              # 観測内で 1-1 タイのため既存 baseline の値(persistence)を踏襲。
}

tactic_resolution_notes = {}

technique_freq = {}
not_established_tech = []
established_tech = []

for tid in sorted(tech_day_counts.keys()):
    day_counts_map = tech_day_counts[tid]
    daily_series = [day_counts_map.get(d, 0) for d in data_days]
    mean_per_day = statistics.fmean(daily_series)
    stddev = statistics.pstdev(daily_series)  # 母標準偏差
    sample_count = tech_sample_count[tid]
    nonzero_days = sum(1 for v in daily_series if v > 0)

    # tactic 決定: 多数決。タイの場合は既存 baseline 値 → フォールバック表 → null
    votes = tech_tactic_votes[tid]
    top_count = max(votes.values())
    top_tactics = sorted([t for t, c in votes.items() if c == top_count])
    if len(top_tactics) == 1:
        tactic = top_tactics[0]
        tactic_resolution_notes[tid] = "single_majority"
    else:
        # tie
        if tid in existing_tactic and existing_tactic[tid] in top_tactics:
            tactic = existing_tactic[tid]
            tactic_resolution_notes[tid] = f"tie_broken_by_existing_baseline({tactic})"
        elif tid in MITRE_PRIMARY_TACTIC_FALLBACK and MITRE_PRIMARY_TACTIC_FALLBACK[tid] in top_tactics:
            tactic = MITRE_PRIMARY_TACTIC_FALLBACK[tid]
            tactic_resolution_notes[tid] = f"tie_broken_by_mitre_fallback({tactic})"
        else:
            tactic = None
            tactic_resolution_notes[tid] = f"tie_unresolved_among({top_tactics})_set_null"

    meets_min_sample = (baseline_period_days >= MIN_PERIOD_DAYS) and (nonzero_days >= MIN_NONZERO_UNITS)
    baseline_status = "established" if meets_min_sample else "not_established"

    if baseline_status == "established":
        established_tech.append(tid)
    else:
        not_established_tech.append(tid)

    entry = {
        "technique_id": tid,
        "tactic": tactic,
        "mean_per_day": round(mean_per_day, 4),
        "stddev": round(stddev, 4),
        "sample_count": sample_count,
        "nonzero_days": nonzero_days,
        "last_observed": tech_last_observed[tid].isoformat(),
        "baseline_status": baseline_status,
    }
    if tactic is None:
        entry["tactic_note"] = (
            "techniques観測間でtacticが割れており(多数決タイ)、既存baseline/MITREフォールバックでも"
            "解決不能のためnullとした。人間レビューが必要。 tie_among="
            + str(top_tactics)
        )
    # サブテクニック内訳（既存構造に無いが有用な情報として維持）
    subbreak = dict(tech_subtech_breakdown[tid])
    if subbreak:
        entry["sub_technique_breakdown"] = subbreak

    technique_freq[tid] = entry

# ---------------------------------------------------------------------------
# 5. group-activity.json の算出
# ---------------------------------------------------------------------------
# 名寄せ後 canonical 単位で週別カウントを作る
group_week_counts = defaultdict(lambda: defaultdict(int))  # canonical -> {week_monday: count}
group_sample_count = Counter()
group_last_observed = {}
group_current_week_count = Counter()

for odate, o in all_observations:
    ag = o.get("actor_group")
    if ag is None:
        continue
    canon = resolve_canonical(ag)
    wm = week_monday(odate)
    group_week_counts[canon][wm] += 1
    group_sample_count[canon] += 1
    if canon not in group_last_observed or odate > group_last_observed[canon]:
        group_last_observed[canon] = odate
    if wm == current_week_monday:
        group_current_week_count[canon] += 1

all_canonical_groups = sorted(group_sample_count.keys())


def compute_group_stats(week_counts_map, sample_count, last_observed, current_week_count,
                         member_groups=None):
    completed_series = [week_counts_map.get(w, 0) for w in completed_weeks]
    nonzero_weeks = sum(1 for v in completed_series if v > 0)

    if completed_series:
        mean_per_week = statistics.fmean(completed_series)
        stddev = statistics.pstdev(completed_series)
    else:
        mean_per_week = 0.0
        stddev = 0.0

    current_week_prorated = (
        round(current_week_count * 7 / current_week_elapsed_days, 4)
        if current_week_elapsed_days > 0 else None
    )

    meets_min_sample = (
        baseline_period_days >= MIN_PERIOD_DAYS and nonzero_weeks >= MIN_NONZERO_UNITS
    )
    baseline_status = "established" if meets_min_sample else "not_established"

    sigma_deviation = None
    sigma_note = None
    if meets_min_sample and stddev > 0 and current_week_prorated is not None:
        sigma_deviation = round((current_week_prorated - mean_per_week) / stddev, 4)
        if current_week_elapsed_days < 3:
            sigma_note = "week_early_provisional"

    entry = {
        "mean_per_week": round(mean_per_week, 4),
        "stddev": round(stddev, 4),
        "sample_count": sample_count,
        "nonzero_weeks_in_completed": nonzero_weeks,
        "completed_weeks_used": len(completed_weeks),
        "last_observed": last_observed.isoformat(),
        "current_week_count": current_week_count,
        "current_week_prorated": current_week_prorated,
        "sigma_deviation": sigma_deviation,
        "baseline_status": baseline_status,
    }
    if sigma_note:
        entry["sigma_note"] = sigma_note
    if member_groups is not None:
        entry["member_groups"] = member_groups
    return entry


group_activity = {}
for canon in all_canonical_groups:
    meta = canonical_meta.get(canon, {})
    entry = compute_group_stats(
        group_week_counts[canon],
        group_sample_count[canon],
        group_last_observed[canon],
        group_current_week_count.get(canon, 0),
    )
    entry_out = {"actor_group": canon, "aliases": meta.get("aliases", [])}
    entry_out.update(entry)
    group_activity[canon] = entry_out

# parent_rollups
parent_members = defaultdict(list)
for canon in all_canonical_groups:
    parent = canonical_parent.get(canon)
    if parent:
        parent_members[parent].append(canon)

parent_rollups = {}
for parent, members in sorted(parent_members.items()):
    combined_week_counts = defaultdict(int)
    combined_sample_count = 0
    combined_last_observed = None
    combined_current_week_count = 0
    for m in members:
        for wm, c in group_week_counts[m].items():
            combined_week_counts[wm] += c
        combined_sample_count += group_sample_count[m]
        lo = group_last_observed[m]
        if combined_last_observed is None or lo > combined_last_observed:
            combined_last_observed = lo
        combined_current_week_count += group_current_week_count.get(m, 0)

    entry = compute_group_stats(
        combined_week_counts,
        combined_sample_count,
        combined_last_observed,
        combined_current_week_count,
        member_groups=members,
    )
    entry_out = {"parent_group": parent}
    entry_out.update(entry)
    parent_rollups[parent] = entry_out

# ---------------------------------------------------------------------------
# 6. 有効性判定
# ---------------------------------------------------------------------------
if baseline_period_days < 14:
    validity = "insufficient_under_14_days"
    validity_note = "警告: ベースライン期間が14日未満。予報の定量的根拠として不十分。"
elif baseline_period_days < 30:
    validity = "caution_under_30_days"
    validity_note = f"注意: ベースライン期間が{baseline_period_days}日（30日未満）。参考値として使用可能だが精度は低い。"
elif baseline_period_days < 90:
    validity = "valid"
    validity_note = f"有効: ベースライン期間{baseline_period_days}日。予報生成に使用可能。"
else:
    validity = "stable"
    validity_note = "安定: 90日以上の安定ベースライン。"

# ---------------------------------------------------------------------------
# 7. 出力
# ---------------------------------------------------------------------------
today_str = TODAY.isoformat()

technique_freq_out = {
    "_comment": "Technique 出現頻度ベースライン。ステージ02が observations/ の全履歴から算出・更新する。90日分の観測が蓄積されてから安定する。サブテクニックは親technique_idに集約して集計する（sub_technique_breakdownに内訳を残す）。",
    "_schema_version": "1.1",
    "_last_updated": today_str,
    "_observation_count": len(all_observations),
    "_baseline_period_start": period_start.isoformat(),
    "_baseline_period_end": period_end.isoformat(),
    "_baseline_period_days": baseline_period_days,
    "_baseline_period_calendar_days": period_days_calendar,
    "_missing_days": [d.isoformat() for d in missing_days],
    "_missing_days_note": "観測ファイルが存在しない日。ゼロ観測日として扱わず、日数分母（_baseline_period_days）から除外した。",
    "_min_sample_rule": "sigma_deviation算出には(a)観測期間14日以上 かつ (b)非ゼロ観測日3日以上を要する。満たさないエントリはbaseline_status:not_establishedとしtacticはtechnique自体には影響しない(tacticは別ロジック)。",
    "_validity": validity,
    "_validity_note": validity_note,
    "_tactic_resolution_note": "tacticは観測内のtechnique×tactic出現の多数決で決定。タイの場合は既存baseline値→MITRE標準フォールバック→nullの順で解決を試みる。null化したエントリはtactic_noteに理由を記録。",
    "techniques": technique_freq,
}

group_activity_out = {
    "_comment": "グループ活性度ベースライン。ステージ02が observations/ の全履歴から算出・更新する。90日分の観測が蓄積されてから安定する。actor_groupはforecaster/knowledge/group-aliases.jsonでcanonicalへ名寄せ済み。parent_rollupsはDPRK系(Lazarus Group傘下)等のアンブレラ帰属の合算統計。",
    "_schema_version": "1.1",
    "_last_updated": today_str,
    "_observation_count": sum(group_sample_count.values()),
    "_baseline_period_start": period_start.isoformat(),
    "_baseline_period_end": period_end.isoformat(),
    "_baseline_period_days": baseline_period_days,
    "_baseline_period_calendar_days": period_days_calendar,
    "_missing_days": [d.isoformat() for d in missing_days],
    "_missing_days_note": "観測ファイルが存在しない日。ゼロ観測日として扱わず、日数分母から除外した。",
    "_current_week_monday": current_week_monday.isoformat(),
    "_current_week_elapsed_days": current_week_elapsed_days,
    "_completed_weeks_used": [w.isoformat() for w in completed_weeks],
    "_week_reset_note": f"現在週 {current_week_monday.isoformat()}（月曜起算）。mean_per_week/stddevは完結週（{len(completed_weeks)}週）のみから算出。当週はcurrent_week_countとcurrent_week_prorated(日割り換算)で別途記録。",
    "_min_sample_rule": "sigma_deviation算出には(a)観測期間14日以上 かつ (b)非ゼロ観測週3週以上を要する。満たさないエントリはsigma_deviation:null, baseline_status:not_establishedとする。",
    "_validity": validity,
    "_validity_note": validity_note,
    "_unmapped_groups": sorted(unmapped_groups),
    "_unmapped_groups_note": "group-aliases.jsonに未収載のためグループ名自体をcanonicalとして扱った。追加はIssue/PR経由で人間レビューへ提案すること（knowledge/自動書き換え禁止）。" if unmapped_groups else "全グループがgroup-aliases.jsonに収載済み。",
    "groups": group_activity,
    "parent_rollups": parent_rollups,
}

out_tf_path = f"{REPO}/forecaster/baseline/technique-freq.json"
out_ga_path = f"{REPO}/forecaster/baseline/group-activity.json"

with open(out_tf_path, "w") as f:
    json.dump(technique_freq_out, f, indent=2, ensure_ascii=False)
    f.write("\n")

with open(out_ga_path, "w") as f:
    json.dump(group_activity_out, f, indent=2, ensure_ascii=False)
    f.write("\n")

print(f"\nWrote {out_tf_path}")
print(f"Wrote {out_ga_path}")

print(f"\n[summary] techniques={len(technique_freq)} established={len(established_tech)} not_established={len(not_established_tech)}")
print(f"[summary] groups(canonical)={len(all_canonical_groups)} parent_rollups={len(parent_rollups)}")
print(f"[summary] unmapped_groups={sorted(unmapped_groups)}")
print(f"[summary] tactic_resolution_notes (non single_majority):")
for tid, note in tactic_resolution_notes.items():
    if note != "single_majority":
        print(f"    {tid}: {note}")
