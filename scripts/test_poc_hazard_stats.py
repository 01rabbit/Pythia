#!/usr/bin/env python3
"""build_poc_hazard_stats.py（E4 外部実測・Issue #186）の集計規則を機械的に検査する。

依存は Python 3 標準ライブラリのみ。ネットワークへは出ない。
合成フィクスチャで各規則が期待どおり働くことを確認する。

検査する規則:
  1. Exploit-DB の codes 列（';' 区切り・CVE 以外混在）から CVE だけを拾い date_added の最小を採る
  2. PoC-in-GitHub の created_at の最小日を採り、壊れた JSON は None
  3. Metasploit mod_time は include_msf=False のとき初出に寄与しない
  4. 複数ソースの初出は最小日を採り、採用ソース名を残す
  5. サンプル日時点で既に PoC がある CVE はリスク集合から外れる（未発火条件付き）
  6. 発火は [D+1, D+3] のみ（D 当日・D+4 は発火でない）
  7. 窓の終端が as_of を超えるサンプル日は右打ち切りとして除外される
  8. 経過日数層（le_7d / le_30d / le_90d / any）は入れ子で単調（risk も fired も）
  9. ラグ分布は before_kev / 各 bin / none_as_of の合計が母集団数に一致し、起点 > as_of は除外
 10. 同一入力から同一出力が再現する（決定論）

使い方:
    python3 scripts/test_poc_hazard_stats.py
"""

import json
import os
import sys
from datetime import date

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

import build_poc_hazard_stats as bph  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'OK' if cond else 'NG'}] {name}" + (f"  — {detail}" if detail and not cond else ""))


EDB_CSV = """id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url
1,a,x,2026-01-05,me,remote,linux,,2026-01-06,2026-01-06,0,CVE-2026-1;OSVDB-1,,,,,
2,b,y,2026-01-01,me,remote,linux,,2026-01-02,2026-01-02,0,CVE-2026-1;CVE-2026-2,,,,,
3,c,z,2026-01-10,me,remote,linux,,2026-01-10,2026-01-10,0,OSVDB-9,,,,,
4,d,w,,me,remote,linux,,,,0,CVE-2026-3,,,,,
"""


def main():
    print("1. Exploit-DB 解析")
    edb = bph.parse_exploitdb(EDB_CSV)
    check("CVE だけを拾う", set(edb) == {"CVE-2026-1", "CVE-2026-2"}, str(sorted(edb)))
    check("複数行の date_added 最小", edb["CVE-2026-1"][0] == "2026-01-02", str(edb))
    check("date_published 最小も保持", edb["CVE-2026-1"][1] == "2026-01-01", str(edb))

    print("2. PoC-in-GitHub 解析")
    gh = bph.parse_poc_github_cve(json.dumps([
        {"created_at": "2026-02-10T05:00:00Z"}, {"created_at": "2026-02-03T23:59:59Z"}, {"x": 1}
    ]))
    check("created_at 最小日", gh == "2026-02-03", str(gh))
    check("壊れた JSON は None", bph.parse_poc_github_cve("{not json") is None)
    idx = bph.parse_poc_github_index("# t\n### CVE-2026-5 (2026-01-01)\nbody\n### CVE-2025-7\n")
    check("README 索引から CVE 集合", idx == {"CVE-2026-5", "CVE-2025-7"}, str(idx))

    print("3./4. ソース統合")
    msf = bph.parse_metasploit({
        "m1": {"mod_time": "2026-01-20 10:00:00 +0000", "references": ["CVE-2026-9", "URL-x"]},
        "m2": {"mod_time": "2026-01-15 10:00:00 +0000", "references": ["CVE-2026-9"]},
    })
    check("Metasploit mod_time 最小", msf == {"CVE-2026-9": "2026-01-15"}, str(msf))
    first_with = bph.combine_first_poc({"CVE-2026-9": ("2026-01-18", "2026-01-18")}, {"CVE-2026-9": "2026-01-17"}, msf, True)
    first_without = bph.combine_first_poc({"CVE-2026-9": ("2026-01-18", "2026-01-18")}, {"CVE-2026-9": "2026-01-17"}, msf, False)
    check("最小日＝Metasploit（含む）", first_with["CVE-2026-9"] == {"date": "2026-01-15", "source": "metasploit"}, str(first_with))
    check("Metasploit 除外時は GitHub", first_without["CVE-2026-9"] == {"date": "2026-01-17", "source": "github"}, str(first_without))

    print("5./6./7./8. 層別ハザード")
    # 起点（KEV 追加）: A=D-1, B=D-10, C=D-50, E=D-200, F=D（当日）
    D = date(2026, 3, 10)
    origin = {
        "A": "2026-03-09",  # PoC D+2 → 発火
        "B": "2026-02-28",  # PoC D   → 既発火、リスク集合外
        "C": "2026-01-19",  # PoC D+4 → 窓外、リスク集合内・非発火
        "E": "2025-08-22",  # PoC なし
        "F": "2026-03-10",  # PoC D+1 → 発火（起点当日も cohort）
        "G": "2026-03-20",  # 起点が D より後 → cohort 外
    }
    first = {
        "A": {"date": "2026-03-12", "source": "github"},
        "B": {"date": "2026-03-10", "source": "exploit_db"},
        "C": {"date": "2026-03-14", "source": "github"},
        "F": {"date": "2026-03-11", "source": "exploit_db"},
    }
    days = bph.sample_days(D, date(2026, 3, 13))
    check("as_of=D+3 で D は採用", days == [D], str(days))
    check("as_of=D+2 で D は右打ち切り", bph.sample_days(D, date(2026, 3, 12)) == [])
    st, per_day = bph.measure_strata([D], origin, first, "kev_added")
    s7, s30, s90, sany = (st["kev_added_le_7d_no_poc"], st["kev_added_le_30d_no_poc"], st["kev_added_le_90d_no_poc"], st["kev_added_any_no_poc"])
    check("le_7d: risk={A,F} fired={A,F}", (s7["risk_set_total"], s7["fired_total"]) == (2, 2), str(s7))
    check("le_30d: B は既発火で除外", (s30["risk_set_total"], s30["fired_total"]) == (2, 2), str(s30))
    check("le_90d: C は窓外で非発火", (s90["risk_set_total"], s90["fired_total"]) == (3, 2), str(s90))
    check("any: E（PoC なし）を含み G（未来起点）を含まない", (sany["risk_set_total"], sany["fired_total"]) == (4, 2), str(sany))
    check("層は入れ子で単調", s7["risk_set_total"] <= s30["risk_set_total"] <= s90["risk_set_total"] <= sany["risk_set_total"] and s7["fired_total"] <= sany["fired_total"])
    check("発火 CVE が記録される", sany["fired_cves_distinct"] == ["A", "F"], str(sany))
    check("Wilson CI が付く", sany["hazard_wilson_95ci"] is not None and 0 <= sany["hazard_wilson_95ci"][0] <= sany["hazard"] <= sany["hazard_wilson_95ci"][1])
    check("stable 判定は fired>=10", sany["stable"] is False)

    print("9. ラグ分布")
    lag = bph.lag_distribution(origin, first, date(2026, 3, 13))
    b = lag["bins"]
    check("起点 > as_of（G）は除外", lag["n_origin_cves"] == 5, str(lag))
    check("B: lag=10 → d8_30", b["d8_30"] == 1, str(b))
    check("A: lag=3 → d0_3, F: lag=1 → d0_3", b["d0_3"] == 2, str(b))
    check("C: lag=54 → d31_90", b["d31_90"] == 1, str(b))
    check("E: none_as_of", lag["none_as_of"] == 1, str(lag))
    check("合計が母集団数", sum(b.values()) + lag["none_as_of"] == lag["n_origin_cves"])
    lag2 = bph.lag_distribution({"X": "2026-03-01"}, {"X": {"date": "2026-02-20", "source": "github"}}, date(2026, 3, 13))
    check("起点前の PoC は before_kev", lag2["bins"]["before_kev"] == 1, str(lag2))

    print("10. 決定論")
    st2, _ = bph.measure_strata([D], origin, first, "kev_added")
    check("同一入力で同一出力", json.dumps(st, sort_keys=True) == json.dumps(st2, sort_keys=True))

    print(f"\n{len(PASS)} 件成功 / {len(FAIL)} 件失敗")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
