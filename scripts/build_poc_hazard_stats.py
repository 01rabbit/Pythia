#!/usr/bin/env python3
"""E4（PoC/エクスプロイトコード公開）の窓内発生率を、母集団を明示して機械実測する。

背景（Issue #186）:
  M1-b 頻度ゲート（p_channel >= 0.10）と確度ゲートE（p_channel >= 0.40 で確度=高）は
  E1 を内部実績（verification 記録）、E3 を母集団一致の外部実測
  （advisory-cadence-stats.json）で裏づけているが、E4 は内部実績 n=1 のまま停滞し、
  「未実測につき確度=低に限る」運用が続いている。内部実績だけでは n が増えにくく、
  E2 が「発行停止で実績蓄積が止まる」フィードバックループに陥った前例（教訓17）と
  同型のリスクを抱える。本スクリプトは E1（build_kev_hazard_stats.py）・
  E3（build_advisory_cadence_stats.py）と同じ手法を E4 に展開し、
  外部母集団ベースの実測を供給する。

★Pythia が実際に発行した E4 予報の母集団（2026-07-29・2026-08-29 の2件）は
  「実悪用が確認済み（KEV 収載済み／直後）だが公開 PoC がまだ無い CVE」であった。
  本スクリプトの主層（kev_added_le_*d_no_poc）はこの条件に合わせて取っている。
  したがって本ファイルは p_channel 推定順位1（母集団一致の外部実測）の**候補**になるが、
  候補を p_channel として採用するかは人間レビューで判断する（本スクリプトは判断しない）。

測るもの:
  サンプル日 D ごとに、
    リスク集合 = KEV 初回追加日が [D-k, D] に入り、かつ D 時点で公開 PoC が無い CVE
    発火        = 公開 PoC の初出日が [D+1, D+3]（fast_72h の検証窓）に入る
  を数え、全サンプル日でプールしてハザードを算出する（k = 7 / 30 / 90 日、
  および KEV 収載全体）。あわせて KEV 追加日から PoC 初出までのラグ分布と、
  KEV 追加時点で既に PoC があった割合（「未発火」の事前確認に使う）を出す。
  --with-nvd 指定時は NVD の CRITICAL（CVSS v3 9.0 以上）新規公開 CVE を母集団に
  取った補助層も測る（KEV 非依存の広い母集団＝base_rate 側の参考）。

PoC 初出日の一次データ（pipeline-forecast-verification.md 観測出口クラス表の E4 固定ソース
GitHub / ExploitDB / Metasploit に対応）:
  - Exploit-DB  files_exploits.csv の date_added（EDB への収録日。codes 列の CVE で紐付け）
  - GitHub      nomi-sec/PoC-in-GitHub の CVE 別 JSON（リポジトリ created_at の最小値）
  - Metasploit  modules_metadata_base.json の mod_time（★最終更新時刻であり初出の上界。
                主ハザードは Metasploit を含む/含まないの両方を出す）

測らないもの:
  - 予報の主題選別スキルそのもの（内部実績との差分として事後に現れる）。
  - PoC が「動作する実証コード」かどうかの品質判定（検証ステージの exclusions 準拠判断は
    人手で行う。本統計は収録・作成の有無だけを数える）。

設計原則:
  - 日付スタンプ付き一次データのみ。報道・要約記事は使わない。
  - サンプル日は週次固定間隔（窓3日が重ならない最小間隔）。
  - 右打ち切り: PoC ソースは「現在の状態」のダンプなので、窓の終端が --as-of を超える
    サンプル日は除外する（窓未満了を「起きなかった」と数えない）。
  - 出力は forecaster/knowledge/ の機械生成ファイル。knowledge/ の自動書き換え禁止
    （行動原則5）に従い、再生成は日次ルーチンからは行わず PR 提案+人間レビュー経由のみ。
  - 本統計は hit_criteria の変更・発行済み予報の再採点には使用禁止（原則D・教訓12）。

使い方:
    python3 scripts/build_poc_hazard_stats.py --start 2024-10-01 --as-of 2026-10-04 \
        --cache-dir /tmp/poc-cache
    python3 scripts/build_poc_hazard_stats.py --with-nvd --cache-dir /tmp/poc-cache
"""

import argparse
import csv
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build_kev_hazard_stats import (  # noqa: E402
    kev_first_added,
    summarize_internal_channel_rates,
    wilson,
)
from kev_data_sources import KEV_FEED_URL, load_kev  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(REPO_ROOT, "forecaster", "knowledge", "poc-hazard-stats.json")

EXPLOITDB_CSV_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)
POC_GITHUB_INDEX_URL = (
    "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/README.md"
)
POC_GITHUB_CVE_URL = (
    "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
)
METASPLOIT_META_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/"
    "db/modules_metadata_base.json"
)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "pythia-calibration/1.0"

FAST_WINDOW_DAYS = 3
SAMPLE_INTERVAL_DAYS = 7  # 窓（3日）が重ならない最小間隔。独立サンプルを保つ
RECENCY_DAYS = (7, 30, 90)  # KEV 追加からの経過日数で層を切る
MIN_FIRED_FOR_STABLE = 10  # ハザードを「安定」と見なす最小発火数
CENSOR_MARGIN_DAYS = 7  # PoC ソースの反映遅れを見込んで as-of をこれだけ手前に置く
LAG_BINS = (("before_kev", None, -1), ("d0_3", 0, 3), ("d4_7", 4, 7), ("d8_30", 8, 30), ("d31_90", 31, 90), ("gt_90", 91, None))
NVD_MAX_RANGE_DAYS = 120  # NVD API の pubStartDate〜pubEndDate 上限


# --------------------------------------------------------------------------
# 取得
# --------------------------------------------------------------------------


def _fetch_bytes(url, cache_dir, cache_name, timeout=120):
    """URL を取得して bytes を返す。cache_dir があればそこに保存・再利用する。"""
    path = os.path.join(cache_dir, cache_name) if cache_dir else None
    if path and os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        blob = resp.read()
    if path:
        os.makedirs(os.path.dirname(path) or cache_dir, exist_ok=True)
        with open(path, "wb") as f:
            f.write(blob)
    return blob


def _cve_year(cve):
    parts = cve.split("-")
    return parts[1] if len(parts) == 3 and parts[1].isdigit() else None


# --------------------------------------------------------------------------
# 各ソースの「CVE → PoC 初出日」抽出（純関数・テスト対象）
# --------------------------------------------------------------------------


def parse_exploitdb(csv_text):
    """Exploit-DB files_exploits.csv → {CVE: (date_added 最小, date_published 最小)}。

    codes 列は ';' 区切りで複数の識別子（CVE / OSVDB 等）を持つ。CVE だけを採る。
    """
    out = {}
    for row in csv.DictReader(io.StringIO(csv_text)):
        added = (row.get("date_added") or "")[:10]
        published = (row.get("date_published") or "")[:10]
        if not added:
            continue
        for code in (row.get("codes") or "").split(";"):
            code = code.strip()
            if not code.startswith("CVE-"):
                continue
            prev = out.get(code)
            if prev is None:
                out[code] = (added, published or added)
            else:
                out[code] = (min(prev[0], added), min(prev[1], published or added))
    return out


def parse_poc_github_index(readme_text):
    """nomi-sec README.md → 公開 PoC リポジトリが1件以上ある CVE の集合。"""
    cves = set()
    for line in readme_text.splitlines():
        if line.startswith("### CVE-"):
            cves.add(line[4:].split()[0])
    return cves


def parse_poc_github_cve(json_text):
    """nomi-sec CVE 別 JSON → リポジトリ created_at の最小日（YYYY-MM-DD）。無ければ None。"""
    try:
        repos = json.loads(json_text)
    except json.JSONDecodeError:
        return None
    dates = [
        (r.get("created_at") or "")[:10]
        for r in repos
        if isinstance(r, dict) and r.get("created_at")
    ]
    return min(dates) if dates else None


def parse_metasploit(meta):
    """modules_metadata_base.json → {CVE: mod_time の最小日}。

    ★mod_time はモジュールの最終更新時刻であり、初出日の**上界**にしかならない。
    """
    out = {}
    for mod in meta.values():
        mt = (mod.get("mod_time") or "")[:10]
        if not mt:
            continue
        for ref in mod.get("references") or []:
            if ref.startswith("CVE-"):
                out[ref] = min(out.get(ref, mt), mt)
    return out


def combine_first_poc(edb, github, msf, include_msf):
    """ソース別の初出日を CVE ごとに最小化する。{CVE: {"date", "source"}}。"""
    first = {}

    def put(cve, d, src):
        if not d:
            return
        cur = first.get(cve)
        if cur is None or d < cur["date"]:
            first[cve] = {"date": d, "source": src}

    for cve, (added, _published) in edb.items():
        put(cve, added, "exploit_db")
    for cve, d in github.items():
        put(cve, d, "github")
    if include_msf:
        for cve, d in msf.items():
            put(cve, d, "metasploit")
    return first


# --------------------------------------------------------------------------
# 集計（純関数・テスト対象）
# --------------------------------------------------------------------------


def sample_days(start, as_of):
    """週次サンプル日。窓の終端（D+3）が as_of を超える日は右打ち切りとして除外する。"""
    days = []
    d = start
    while d + timedelta(days=FAST_WINDOW_DAYS) <= as_of:
        days.append(d)
        d += timedelta(days=SAMPLE_INTERVAL_DAYS)
    return days


def measure_strata(days, origin_dates, first_poc, strata_prefix):
    """origin_dates: {CVE: 起点日 'YYYY-MM-DD'}（KEV 追加日や NVD 公開日）。

    層 = 起点日が [D-k, D] に入る CVE（k ∈ RECENCY_DAYS）＋ 起点日 <= D の全体。
    リスク集合 = 層のうち D 時点で PoC 初出が無い CVE。発火 = 初出が [D+1, D+3]。
    """
    pooled = defaultdict(lambda: {"risk": 0, "fired": 0, "sample_days": 0, "fired_cves": []})
    per_day = []
    for d in days:
        ds = d.isoformat()
        win_lo = (d + timedelta(days=1)).isoformat()
        win_hi = (d + timedelta(days=FAST_WINDOW_DAYS)).isoformat()
        row = {"date": ds, "strata": {}}
        for k in list(RECENCY_DAYS) + [None]:
            name = f"{strata_prefix}_le_{k}d_no_poc" if k else f"{strata_prefix}_any_no_poc"
            lo = (d - timedelta(days=k)).isoformat() if k else None
            cohort = [c for c, o in origin_dates.items() if o <= ds and (lo is None or o >= lo)]
            risk = [c for c in cohort if not (c in first_poc and first_poc[c]["date"] <= ds)]
            fired = [c for c in risk if c in first_poc and win_lo <= first_poc[c]["date"] <= win_hi]
            p = pooled[name]
            p["risk"] += len(risk)
            p["fired"] += len(fired)
            p["sample_days"] += 1
            p["fired_cves"].extend(fired)
            row["strata"][name] = {"risk": len(risk), "fired": len(fired)}
        per_day.append(row)

    result = {}
    for name, v in pooled.items():
        hz = v["fired"] / v["risk"] if v["risk"] else None
        result[name] = {
            "sample_days": v["sample_days"],
            "risk_set_total": v["risk"],
            "risk_set_mean_per_day": round(v["risk"] / v["sample_days"], 1) if v["sample_days"] else None,
            "fired_total": v["fired"],
            "hazard": round(hz, 5) if hz is not None else None,
            "hazard_wilson_95ci": wilson(v["fired"], v["risk"]) if v["risk"] else None,
            "stable": v["fired"] >= MIN_FIRED_FOR_STABLE,
            "fired_cves_distinct": sorted(set(v["fired_cves"])),
        }
    return result, per_day


def lag_distribution(origin_dates, first_poc, as_of):
    """起点日（KEV 追加日）→ PoC 初出のラグ分布。

    起点日時点で既に PoC があるものは before_kev。初出が無いものは as_of までの
    右打ち切り（none_as_of）として分母に残す（「起きなかった」とは数えない）。
    """
    bins = {name: 0 for name, _, _ in LAG_BINS}
    none_as_of = 0
    lags = []
    for cve, o in origin_dates.items():
        od = date.fromisoformat(o)
        if od > as_of:
            continue
        fp = first_poc.get(cve)
        if not fp:
            none_as_of += 1
            continue
        lag = (date.fromisoformat(fp["date"]) - od).days
        lags.append(lag)
        for name, lo, hi in LAG_BINS:
            if (lo is None or lag >= lo) and (hi is None or lag <= hi):
                bins[name] += 1
                break
    n = len(lags) + none_as_of
    return {
        "n_origin_cves": n,
        "with_poc_as_of": len(lags),
        "none_as_of": none_as_of,
        "bins": bins,
        "pct": {k: round(v / n, 4) if n else None for k, v in bins.items()},
        "pct_none_as_of": round(none_as_of / n, 4) if n else None,
        "_note": (
            "pct は分母に none_as_of（as_of 時点で PoC 未観測）を含む。"
            "before_kev は KEV 追加時点で既に PoC があった割合であり、E4 予報を発行する前の"
            "『未発火確認』の重要性を示す。"
        ),
    }


def component_coverage(origin_cves, edb, github, msf):
    """起点 CVE 集合に対する各ソースの被覆（何件に PoC 記録があるか）。"""
    return {
        "exploit_db": sum(1 for c in origin_cves if c in edb),
        "github": sum(1 for c in origin_cves if c in github),
        "metasploit": sum(1 for c in origin_cves if c in msf),
        "any_without_metasploit": sum(1 for c in origin_cves if c in edb or c in github),
        "any": sum(1 for c in origin_cves if c in edb or c in github or c in msf),
        "n_origin_cves": len(origin_cves),
    }


# --------------------------------------------------------------------------
# NVD 補助層（任意）
# --------------------------------------------------------------------------


def fetch_nvd_critical_published(start, end, cache_dir):
    """NVD から CVSS v3 CRITICAL の新規公開 CVE を {CVE: published 日} で返す。

    pubStartDate〜pubEndDate は 120 日以内に制限されるため分割して取得する。
    レート制限（鍵なし 5req/30s）に従い 6.5 秒間隔で呼ぶ。
    """
    out = {}
    api_key = os.environ.get("NVD_API_KEY")
    ws = start
    while ws <= end:
        we = min(ws + timedelta(days=NVD_MAX_RANGE_DAYS - 1), end)
        start_index = 0
        while True:
            params = {
                "cvssV3Severity": "CRITICAL",
                "pubStartDate": f"{ws.isoformat()}T00:00:00.000",
                "pubEndDate": f"{we.isoformat()}T23:59:59.999",
                "resultsPerPage": 2000,
                "startIndex": start_index,
            }
            url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
            cache_name = f"nvd-critical-{ws.isoformat()}-{we.isoformat()}-{start_index}.json"
            try:
                blob = _fetch_bytes(url, cache_dir, cache_name, timeout=180)
            except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
                print(f"[warn] NVD 取得失敗 {ws}..{we} idx={start_index}: {exc}", file=sys.stderr)
                break
            data = json.loads(blob)
            page = data.get("vulnerabilities", [])
            for v in page:
                c = v.get("cve", {})
                cid = c.get("id")
                pub = (c.get("published") or "")[:10]
                if cid and pub:
                    out[cid] = pub
            start_index += len(page)
            if not page or start_index >= data.get("totalResults", 0):
                break
            time.sleep(1.0 if api_key else 6.5)
        time.sleep(1.0 if api_key else 6.5)
        ws = we + timedelta(days=1)
    return out


# --------------------------------------------------------------------------
# 文書化
# --------------------------------------------------------------------------


def build_document(args, kev, strata_main, strata_nomsf, strata_nvd, per_day, lag, cov, internal, sources_meta):
    return {
        "_comment": (
            "E4（PoC/エクスプロイトコード公開）の窓内発生率を母集団を明示して実測したもの。"
            "主層（kev_added_*）の母集団は『KEV 収載済みで公開 PoC がまだ無い CVE』であり、"
            "Pythia が実際に発行した E4 予報の条件（実悪用確認済み・PoC 未公開）に近い。"
            "したがって p_channel 推定順位1（母集団一致の外部実測）の候補になるが、"
            "候補を p_channel に採用するかは人間レビューで判断する。"
            "発行済み予報の hit_criteria・的中判定結果の変更には使用禁止（原則D・教訓12）。"
        ),
        "_schema_version": "1.0",
        "_machine_generated": True,
        "_generator": "scripts/build_poc_hazard_stats.py",
        "_generated_on": date.today().isoformat(),
        "_issue": "#186",
        "_source": {
            "exploit_db_csv": EXPLOITDB_CSV_URL,
            "poc_in_github_index": POC_GITHUB_INDEX_URL,
            "poc_in_github_cve_json": POC_GITHUB_CVE_URL,
            "metasploit_metadata": METASPLOIT_META_URL,
            "kev_feed": KEV_FEED_URL,
            "kev_catalog_version": kev.get("catalogVersion"),
            "nvd_api": NVD_API if strata_nvd else None,
            "sample_start": args.start,
            "as_of": args.as_of,
            "censor_margin_days": CENSOR_MARGIN_DAYS,
            "sample_interval_days": SAMPLE_INTERVAL_DAYS,
            "window_days": FAST_WINDOW_DAYS,
            **sources_meta,
        },
        "_governance": (
            "knowledge/ の自動書き換え禁止ルール（行動原則5）に従い、再生成は日次ルーチンからは"
            "行わず、必ず PR として提案し人間レビューを経てコミットする。"
        ),
        "_definitions": {
            "first_poc": (
                "Exploit-DB date_added / PoC-in-GitHub リポジトリ created_at / Metasploit mod_time"
                " の最小日。strata_without_metasploit は Metasploit を除いた値。"
            ),
            "risk_set": (
                "サンプル日 D の時点で起点条件（KEV 追加が D-k〜D）を満たし、かつ D 時点で"
                " first_poc が無い（＝まだ発火していない）CVE。"
            ),
            "fired": f"first_poc が [D+1, D+{FAST_WINDOW_DAYS}] に入ること。",
            "hazard": "fired_total / risk_set_total（全サンプル日でプール）。Wilson 95%CI を併記。",
            "p_channel_vs_base_rate": (
                "p_channel = P(窓内発火 | Pythia の発行条件)。主層 kev_added_le_7d_no_poc /"
                " le_30d_no_poc がこれに最も近い母集団。base_rate = P(窓内発火 | 広い候補母集団)。"
                " nvd_critical_* 層（--with-nvd 時）がこれに当たる。両者は別の量である（教訓17）。"
            ),
        },
        "_limitations": [
            "★本ファイルの値を p_channel に自動代入してはならない。主層は Pythia の E4 発行条件に"
            "近いが完全一致ではない（Pythia は KEV 収載前の実悪用報道を起点に発行することがある）。"
            "採用は pipeline-forecast-verification.md の p_channel 推定順位表の更新として"
            "人間レビューを経る。",
            "PoC ソースは『現在の状態』のダンプである。削除された GitHub リポジトリは"
            " PoC-in-GitHub から消えるため、過去の発火は過少に数えられる（生存バイアス）。"
            "Exploit-DB は収録削除が稀でこの影響は小さい。",
            "PoC-in-GitHub の created_at はリポジトリ作成時刻であり、CVE 名を後から付けた"
            "リポジトリでは PoC 公開より前の日付になる。KEV 追加前の日付は before_kev に"
            "集計され、リスク集合からは除外される方向（保守的）に働く。",
            "Metasploit の mod_time は最終更新時刻であり初出の上界。モジュール初出が窓内でも"
            " mod_time が後日なら発火を取り逃がし、逆に窓内の更新を初出と誤認しうる。"
            "主判断には strata_without_metasploit を優先し、差分を Metasploit 由来の不確かさとして読む。",
            "本統計は PoC が『動作する実証コード』かを判定しない（2026-08-29 の E4 的中判定で"
            "プレースホルダコミットを除外した判断は人手による）。収録・作成の有無だけを数える。",
            "サンプルは週次固定間隔であり、KEV 追加の曜日偏りと位相が固定される。",
            "fired_total が少ない層（stable=false）の hazard は信頼区間が広い。桁の目安としてのみ読む。",
            "nvd_critical_* 層は cvssV3Severity=CRITICAL で絞っており、CVSS v4 のみ・v2 のみの"
            " CVE を含まない（網羅スイープが severity フィルタを使わない理由と同じ欠落）。"
            "base_rate 側の参考値であり p_channel には使わない。",
            "本統計は的中条件（hit_criteria）を緩める根拠には使用禁止（原則D・教訓12）。"
            "使ってよいのは M1-b 頻度ゲートの判定値候補（人間レビュー経由）と"
            " base_rate_estimate の情報量測定のみ。",
        ],
        "strata": strata_main,
        "strata_without_metasploit": strata_nomsf,
        "strata_nvd_critical": strata_nvd,
        "lag_kev_added_to_first_poc": lag,
        "source_coverage_on_kev": cov,
        "internal_channel_rates": {
            "_note": (
                "verification 記録から集計した E4 の内部実績（build_kev_hazard_stats.py と同じ集計）。"
                "n が小さく信頼区間は広い。"
            ),
            "channels": {k: v for k, v in internal.items() if k == "E4"},
        },
        "per_sample_day": per_day,
    }


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--start", default="2024-10-01", help="サンプル開始日 YYYY-MM-DD")
    ap.add_argument("--as-of", default=None, help=f"右打ち切り基準日（既定: 今日-{CENSOR_MARGIN_DAYS}日）")
    ap.add_argument("--kev-file", help="CISA KEV catalog のローカルパス")
    ap.add_argument("--cache-dir", help="取得物のディスクキャッシュ（再現性のため推奨）")
    ap.add_argument("--with-nvd", action="store_true", help="NVD CRITICAL 新規公開を母集団とした補助層も測る")
    ap.add_argument("--workers", type=int, default=8, help="PoC-in-GitHub CVE 別 JSON の並列取得数")
    ap.add_argument("--out", default=OUT_PATH)
    args = ap.parse_args()

    start = date.fromisoformat(args.start)
    as_of = date.fromisoformat(args.as_of) if args.as_of else date.today() - timedelta(days=CENSOR_MARGIN_DAYS)
    args.as_of = as_of.isoformat()
    days = sample_days(start, as_of)
    print(f"[sample] {len(days)} 日（週次・{start} 〜 {days[-1] if days else '-'}・as_of {as_of}）")

    kev = load_kev(args.kev_file)
    kadd = kev_first_added(kev)
    kev_cves = set(kadd)
    print(f"[kev] 収載 {len(kadd)} CVE")

    print(f"[fetch] Exploit-DB: {EXPLOITDB_CSV_URL}")
    edb = parse_exploitdb(_fetch_bytes(EXPLOITDB_CSV_URL, args.cache_dir, "files_exploits.csv").decode("utf-8", "replace"))
    print(f"[fetch] PoC-in-GitHub index: {POC_GITHUB_INDEX_URL}")
    gh_index = parse_poc_github_index(_fetch_bytes(POC_GITHUB_INDEX_URL, args.cache_dir, "poc-in-github-README.md").decode("utf-8", "replace"))
    print(f"[fetch] Metasploit metadata: {METASPLOIT_META_URL}")
    msf = parse_metasploit(json.loads(_fetch_bytes(METASPLOIT_META_URL, args.cache_dir, "modules_metadata_base.json")))

    origin_sets = {"kev_added": kadd}
    nvd_pub = {}
    if args.with_nvd:
        print("[fetch] NVD CRITICAL 新規公開（レート制限に従い時間がかかります）")
        nvd_pub = fetch_nvd_critical_published(start - timedelta(days=max(RECENCY_DAYS)), as_of, args.cache_dir)
        print(f"[nvd] CRITICAL 公開 {len(nvd_pub)} CVE")
        origin_sets["nvd_critical"] = nvd_pub

    # PoC-in-GitHub の CVE 別 JSON は、起点集合 ∩ index の CVE だけ取得する
    targets = sorted((kev_cves | set(nvd_pub)) & gh_index)
    print(f"[fetch] PoC-in-GitHub CVE 別 JSON: {len(targets)} 件")

    def fetch_one(cve):
        year = _cve_year(cve)
        if not year:
            return cve, None
        try:
            blob = _fetch_bytes(POC_GITHUB_CVE_URL.format(year=year, cve=cve), args.cache_dir, os.path.join("poc-in-github", f"{cve}.json"), timeout=60)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return cve, None
            print(f"[warn] PoC-in-GitHub 取得失敗 {cve}: {exc}", file=sys.stderr)
            return cve, None
        except (urllib.error.URLError, OSError) as exc:
            print(f"[warn] PoC-in-GitHub 取得失敗 {cve}: {exc}", file=sys.stderr)
            return cve, None
        return cve, parse_poc_github_cve(blob.decode("utf-8", "replace"))

    github = {}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for cve, d in ex.map(fetch_one, targets):
            if d:
                github[cve] = d
    print(f"[github] created_at 取得 {len(github)} CVE")

    first_all = combine_first_poc(edb, github, msf, include_msf=True)
    first_nomsf = combine_first_poc(edb, github, msf, include_msf=False)

    strata_main, per_day = measure_strata(days, kadd, first_all, "kev_added")
    strata_nomsf, _ = measure_strata(days, kadd, first_nomsf, "kev_added")
    strata_nvd = None
    if nvd_pub:
        strata_nvd, _ = measure_strata(days, nvd_pub, first_all, "nvd_critical")

    recent_kev = {c: d for c, d in kadd.items() if d >= start.isoformat()}
    lag = lag_distribution(recent_kev, first_all, as_of)
    lag["_origin"] = f"KEV 初回追加日が {start} 以降の CVE"
    cov = component_coverage(sorted(recent_kev), edb, github, msf)
    internal = summarize_internal_channel_rates()
    sources_meta = {
        "exploit_db_cves_indexed": len(edb),
        "poc_in_github_cves_indexed": len(gh_index),
        "metasploit_cves_indexed": len(msf),
    }
    doc = build_document(args, kev, strata_main, strata_nomsf, strata_nvd, per_day, lag, cov, internal, sources_meta)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print(f"\n[out] {args.out}")
    for label, st in (("主層（Metasploit 含む）", strata_main), ("主層（Metasploit 除く）", strata_nomsf), ("NVD CRITICAL 補助層", strata_nvd)):
        if not st:
            continue
        print(f"  {label}:")
        for name, v in st.items():
            flag = "" if v["stable"] else "  ※fired少・桁の目安のみ"
            hz = f"{v['hazard']:.5f}" if v["hazard"] is not None else "n/a"
            print(f"    {name:32s} hazard={hz} CI={v['hazard_wilson_95ci']} (risk {v['risk_set_total']:,} / fired {v['fired_total']}){flag}")
    print(f"  KEV追加→PoC初出ラグ（n={lag['n_origin_cves']}）: {lag['pct']} none_as_of={lag['pct_none_as_of']}")
    e4 = internal.get("E4")
    if e4:
        print(f"  内部実績 E4: {e4['hit']}/{e4['total']} 95%CI {e4['wilson_95ci']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
