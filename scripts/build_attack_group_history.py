#!/usr/bin/env python3
"""MITRE ATT&CK STIX から追跡対象グループの過去事例知識を抽出する。

目的:
  APT の学習を「これから観測する事例」だけでなく「過去の事例」まで広げる。
  ATT&CK Groups / Campaigns は過去事例の出典付き蒸留であり、
  attack-groups.json の evidence_basis 区分でいう「cited」に相当する
  知識ソースとして利用できる。

設計原則（CLAUDE.md・forecaster/README.md の運用ルールに準拠）:
  - 出力は forecaster/knowledge/attack-group-history.json。
    knowledge/ は自動書き換え禁止のため、本スクリプトは日次ルーチンからは
    実行せず、再生成は必ず PR として提案し人間レビューを経ること。
  - 手書きキュレーションの attack-groups.json / group-aliases.json には
    一切触れない（別ファイルとして提供し、マージ判断は人間が行う）。
  - 全エントリの根拠は MITRE ATT&CK（バージョン・URL 明記）。推測による
    追加はしない。revoked / deprecated オブジェクトは除外する。
  - この知識は「予報の事前分布・過去事例の掌握」用である。日次正規化
    （01-normalize.md R3/R4）で観測に Technique / 帰属を付与する根拠には
    使ってはならない（グループの既知TTPからの類推付与は禁止のまま）。

入力:
  - forecaster/knowledge/group-aliases.json（追跡対象グループの正規名・エイリアス）
  - ATT&CK enterprise STIX bundle（--stix-file 指定またはネット取得）

使い方:
    python3 scripts/build_attack_group_history.py --stix-file /path/to/enterprise-attack.json
    python3 scripts/build_attack_group_history.py            # ネット取得（約50MB）
"""

import argparse
import json
import os
import sys
import urllib.request
from collections import defaultdict
from datetime import date

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALIASES_PATH = os.path.join(REPO_ROOT, "forecaster", "knowledge", "group-aliases.json")
OUT_PATH = os.path.join(
    REPO_ROOT, "forecaster", "knowledge", "attack-group-history.json"
)

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def is_active(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def attack_ext(obj):
    """external_references から mitre-attack の (external_id, url) を返す。"""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


# STIX の tactic 語彙 → observation.schema.json の enum への正規化。
# 使用する ATT&CK STIX（v19系）は defense-evasion を stealth / defense-impairment に
# 改称・分割しているため、システム全体で一貫した tactic 語彙にするためスキーマの
# defense-evasion へ写像する（backfill_cisa_advisories.py と同一方針）。
STIX_TACTIC_TO_SCHEMA = {
    "stealth": "defense-evasion",
    "defense-impairment": "defense-evasion",
}


def tactics_of(pattern):
    return sorted(
        {
            STIX_TACTIC_TO_SCHEMA.get(ph["phase_name"], ph["phase_name"])
            for ph in pattern.get("kill_chain_phases", [])
            if ph.get("kill_chain_name") == "mitre-attack"
        }
    )


def to_date(ts):
    return ts[:10] if isinstance(ts, str) else None


def load_stix(stix_file):
    if stix_file:
        with open(stix_file) as f:
            return json.load(f)
    print(f"[fetch] ATT&CK STIX: {STIX_URL}")
    req = urllib.request.Request(
        STIX_URL, headers={"User-Agent": "pythia-attack-history/1.0"}
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.load(resp)


def main():
    ap = argparse.ArgumentParser(
        description="ATT&CK STIX から追跡対象グループの過去事例知識を抽出する。"
    )
    ap.add_argument("--stix-file", help="enterprise-attack.json のローカルパス（省略時はネット取得）")
    ap.add_argument("--out", default=OUT_PATH, help=f"出力先（既定: {OUT_PATH}）")
    args = ap.parse_args()

    aliases_data = json.load(open(ALIASES_PATH))
    tracked = aliases_data.get("groups", {})

    bundle = load_stix(args.stix_file)
    objs = bundle.get("objects", [])
    by_id = {o["id"]: o for o in objs}

    coll = next((o for o in objs if o["type"] == "x-mitre-collection"), {})
    attack_version = coll.get("x_mitre_version", "unknown")

    intrusion_sets = [o for o in objs if o["type"] == "intrusion-set" and is_active(o)]
    campaigns = [o for o in objs if o["type"] == "campaign" and is_active(o)]

    # name/alias（小文字）→ intrusion-set
    is_lookup = {}
    for g in intrusion_sets:
        for name in [g["name"]] + list(g.get("aliases", [])):
            is_lookup.setdefault(name.lower(), g)

    # T-code → attack-pattern カタログ（親 technique の名称・tactic 補完用）
    pattern_by_tid = {}
    for p in objs:
        if p["type"] == "attack-pattern" and is_active(p):
            tid, _ = attack_ext(p)
            if tid:
                pattern_by_tid[tid] = p

    # uses / attributed-to 関係の索引
    uses_by_source = defaultdict(list)  # source_ref -> [attack-pattern obj]
    attributed = defaultdict(list)  # intrusion-set id -> [campaign obj]
    for r in objs:
        if r["type"] != "relationship" or not is_active(r):
            continue
        if r["relationship_type"] == "uses":
            target = by_id.get(r.get("target_ref"))
            if target and target["type"] == "attack-pattern" and is_active(target):
                uses_by_source[r["source_ref"]].append(target)
        elif r["relationship_type"] == "attributed-to":
            src = by_id.get(r.get("source_ref"))
            if src and src["type"] == "campaign" and is_active(src):
                attributed[r["target_ref"]].append(src)

    def technique_entries(source_id, group_url):
        """uses 関係から technique エントリ一覧を作る（親に集約・subは内訳）。"""
        parents = {}
        for pattern in uses_by_source.get(source_id, []):
            tid, _ = attack_ext(pattern)
            if not tid:
                continue
            parent_id = tid.split(".")[0]
            entry = parents.setdefault(
                parent_id,
                {
                    "technique_id": parent_id,
                    "name": None,
                    "tactics": [],
                    "sub_techniques": [],
                    "citation": {
                        "source": f"MITRE ATT&CK v{attack_version}",
                        "url": group_url,
                    },
                },
            )
            if pattern.get("x_mitre_is_subtechnique"):
                entry["sub_techniques"].append(
                    {"sub_technique_id": tid, "name": pattern.get("name")}
                )
            else:
                entry["name"] = pattern.get("name")
                entry["tactics"] = tactics_of(pattern)
        for e in parents.values():
            e["sub_techniques"].sort(key=lambda s: s["sub_technique_id"])
            # サブテクニックのみ使用のグループでは親エントリが未命名になる。
            # ATT&CK カタログの親 attack-pattern から名称・tactic を補完する。
            parent_pattern = pattern_by_tid.get(e["technique_id"])
            if parent_pattern:
                if e["name"] is None:
                    e["name"] = parent_pattern.get("name")
                if not e["tactics"]:
                    e["tactics"] = tactics_of(parent_pattern)
        return sorted(parents.values(), key=lambda e: e["technique_id"])

    result, unmatched = {}, []
    for canon, meta in tracked.items():
        names = [canon] + list(meta.get("aliases", []))
        g = next((is_lookup[n.lower()] for n in names if n.lower() in is_lookup), None)
        if g is None:
            unmatched.append(canon)
            continue
        gid, gurl = attack_ext(g)
        camp_entries = []
        for c in sorted(
            attributed.get(g["id"], []), key=lambda c: c.get("first_seen") or ""
        ):
            cid, curl = attack_ext(c)
            camp_techniques = sorted(
                {
                    attack_ext(p)[0].split(".")[0]
                    for p in uses_by_source.get(c["id"], [])
                    if attack_ext(p)[0]
                }
            )
            camp_entries.append(
                {
                    "campaign_id": cid,
                    "name": c.get("name"),
                    "first_seen": to_date(c.get("first_seen")),
                    "last_seen": to_date(c.get("last_seen")),
                    "technique_ids": camp_techniques,
                    "citation": {
                        "source": f"MITRE ATT&CK v{attack_version}",
                        "url": curl,
                    },
                }
            )
        result[canon] = {
            "attack_id": gid,
            "attack_name": g["name"],
            "attack_url": gurl,
            "matched_via": canon if g["name"].lower() != canon.lower() else "name",
            "attack_aliases": sorted(g.get("aliases", [])),
            "techniques": technique_entries(g["id"], gurl),
            "campaigns": camp_entries,
        }
        print(
            f"[match] {canon} -> {gid} ({g['name']}): "
            f"techniques={len(result[canon]['techniques'])} "
            f"campaigns={len(camp_entries)}"
        )

    out = {
        "_comment": (
            "追跡対象グループ（group-aliases.json）の過去事例知識。MITRE ATT&CK の "
            "Groups / Campaigns から機械抽出した出典付き（cited 相当）データ。"
            "予報生成時の事前知識・過去事例の掌握に使う。"
            "★日次正規化（01-normalize.md R3/R4）で観測に Technique / 帰属を"
            "付与する根拠には使用禁止（既知TTPからの類推付与は禁止のまま）。"
        ),
        "_schema_version": "1.0",
        "_machine_generated": True,
        "_generator": "scripts/build_attack_group_history.py",
        "_attack_version": attack_version,
        "_generated_on": date.today().isoformat(),
        "_source": STIX_URL,
        "_governance": (
            "knowledge/ の自動書き換え禁止ルールに従い、再生成は日次ルーチンからは"
            "行わず、必ず PR として提案し人間レビューを経てコミットする。"
        ),
        "_unmatched_groups": sorted(unmatched),
        "_unmatched_note": (
            "group-aliases.json に登録されているが ATT&CK v"
            + str(attack_version)
            + " の Groups に該当が見つからなかったグループ。"
        ),
        "groups": result,
    }
    with open(args.out, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(
        f"[done] {os.path.relpath(args.out, REPO_ROOT)}: "
        f"matched={len(result)} unmatched={len(unmatched)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
