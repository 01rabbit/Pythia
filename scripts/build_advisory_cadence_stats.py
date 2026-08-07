#!/usr/bin/env python3
"""E3（CERT系初回注意喚起）出口チャネルの発行頻度を一次ソースから機械実測する。

目的:
  M1 観測可能性ゲートは「的中条件が一次・二値・反証可能なイベントか」しか
  検査しておらず、「そのイベントが検証窓に対して十分な頻度で発生するか」を
  検査していない。この穴により E2（追随IOC・0/6）に続き E3（0/13）が
  構造的過信として発生した（2026-08-07 精度分析）。
  本スクリプトは E3 チャネルの実効発生率を実測し、M1 頻度ゲートと
  base_rate_estimate 記入の実測アンカーを供給する。

本統計の使い方（正確な定義・限界は出力 JSON の _limitations が正）:
  - 測るもの:
    (a) チャネル容量 — JPCERT/CC 注意喚起・IPA 重要なセキュリティ情報が
        「何らかの主題について」単位時間あたり何本発行されるか。
        任意の72時間窓に1本以上出る確率は、特定主題予報の的中率の**上限**である。
    (b) 主題特定性 — CISA KEV 収載CVE（Pythia が予報母集団とする「実悪用確認済み
        CVE」の近似）のうち、当該チャネルが個別に名指しした割合（coverage_ratio）。
    (c) タイミング — 名指しされた場合に KEV 追加日から何日で発行されるかの分布。
  - 導出する主要値: p_specific_cve_within_72h = coverage_ratio × pct_lag_0_to_3d
    ＝「実悪用確認済みCVE 1件を選んだとき、その後72時間以内に当該チャネルが
    それを名指しした初回注意喚起を出す確率」の実測推定。
  - 測らないもの: 予報の主題選別スキル。本値は「予報のスキルなしに偶然成立する
    確率」（base_rate_estimate の定義）であり、予報の良し悪しではない。
  - 用途は M1 頻度ゲートの判定と base_rate_estimate の実測アンカーに限定する。
    **発行済み予報の hit_criteria・的中判定結果の変更には使用禁止**（原則D・教訓12）。

設計原則:
  - 日付スタンプ付き一次ソースのみ使用（JPCERT/CC AT 各文書の「（公開）」日・
    IPA 索引の公開日・CISA KEV dateAdded）。二次情報・要約記事は使わない。
  - 出力は forecaster/knowledge/ の機械生成ファイル。knowledge/ の自動書き換え
    禁止（行動原則5）に従い、再生成は日次ルーチンからは行わず PR 提案+人間レビュー経由のみ。
  - 部分年（実行年）は days_covered で正規化し、年次件数をそのまま比較しない。

入力:
  - JPCERT/CC 注意喚起 年次索引 https://www.jpcert.or.jp/at/YYYY.html + 各 AT 文書
  - IPA 重要なセキュリティ情報 年次索引 https://www.ipa.go.jp/security/security-alert/YYYY/index.html
    + 各アラート文書
  - CISA KEV catalog（--kev-file 指定またはネット取得）

出力:
  forecaster/knowledge/advisory-cadence-stats.json

使い方:
    python3 scripts/build_advisory_cadence_stats.py --as-of 2026-08-07
    python3 scripts/build_advisory_cadence_stats.py --kev-file kev.json --cache-dir /tmp/cadence
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kev_data_sources import KEV_FEED_URL, load_kev, percentile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(
    REPO_ROOT, "forecaster", "knowledge", "advisory-cadence-stats.json"
)
KEV_LEADTIME_PATH = os.path.join(
    REPO_ROOT, "forecaster", "knowledge", "kev-leadtime-stats.json"
)

USER_AGENT = "pythia-calibration/1.0"
JPCERT_INDEX = "https://www.jpcert.or.jp/at/{year}.html"
JPCERT_DOC = "https://www.jpcert.or.jp{path}"
IPA_INDEX = "https://www.ipa.go.jp/security/security-alert/{year}/index.html"
IPA_DOC = "https://www.ipa.go.jp{path}"

DEFAULT_START_YEAR = 2021  # KEV カタログ運用開始（BOD 22-01）に合わせる
FAST_WINDOW_DAYS = 3  # fast_72h の検証窓（発行日 +3日）
MIN_SAMPLE_LAG = 5  # ラグ分布を採用する最小サンプル数
MAX_OBSERVATION_LAG = 7  # ハザード曲線を算出する観測遅延 k の上限（日）
PIPELINE_OBSERVATION_LAG = 1  # 日次パイプラインの標準観測遅延（前日分を 07:00 JST に収集）

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


# --------------------------------------------------------------------------
# 取得
# --------------------------------------------------------------------------


def fetch_text(url, cache_dir=None, timeout=60):
    """HTML を取得する。cache_dir 指定時はディスクキャッシュを使う。"""
    cache_path = None
    if cache_dir:
        safe = re.sub(r"[^0-9A-Za-z]+", "_", url)[-180:]
        cache_path = os.path.join(cache_dir, safe)
        if os.path.exists(cache_path):
            with open(cache_path, encoding="utf-8", errors="replace") as f:
                return f.read()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        print(f"[warn] 取得失敗 {url}: {exc}", file=sys.stderr)
        return None
    if cache_path:
        os.makedirs(cache_dir, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            f.write(body)
    return body


def strip_tags(html):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


# --------------------------------------------------------------------------
# JPCERT/CC 注意喚起
# --------------------------------------------------------------------------


def jpcert_year_docs(year, cache_dir):
    """年次索引から当該年の AT 文書パス一覧を返す。索引が引けない年は None。

    None（索引到達不可）と []（索引はあるが発行0件）を区別する。前者を 0 件として
    集計すると分母だけ伸びて発行頻度を過小評価するため（IPA 2021-2023 の 404 で
    実際に発生した欠陥）、呼び出し側で可用年を絞り込む。
    """
    html = fetch_text(JPCERT_INDEX.format(year=year), cache_dir)
    if not html:
        return None
    return sorted(set(re.findall(rf"/at/{year}/at\d+\.html", html)))


def parse_jpcert_doc(html):
    """AT 文書から (初版公開日, 名指しCVE集合) を返す。

    文書ヘッダは「YYYY-MM-DD（公開）」形式で初版日を持つ。更新版でも初版日が
    残るため、最終更新日ではなく初版日を採る（カデンツは初回発行の頻度で測る）。
    """
    text = strip_tags(html)
    m = re.search(r"(\d{4}-\d{2}-\d{2})\s*[（(]公開[）)]", text)
    if not m:
        # 初版のみで未更新の文書は「最終更新: YYYY-MM-DD」しか持たない場合がある
        m = re.search(r"最終更新[:：]\s*(\d{4}-\d{2}-\d{2})", text)
    published = m.group(1) if m else None
    cves = set(CVE_RE.findall(text))
    return published, cves


def collect_jpcert(years, cache_dir, workers):
    """JPCERT/CC 注意喚起の (文書一覧, 索引到達可能だった年集合) を返す。"""
    tasks = []
    available = set()
    for year in years:
        paths = jpcert_year_docs(year, cache_dir)
        if paths is None:
            continue
        available.add(year)
        tasks.extend((year, p) for p in paths)
    print(f"[jpcert] 文書数 {len(tasks)} 件 / 可用年 {sorted(available)}")

    def work(item):
        year, path = item
        html = fetch_text(JPCERT_DOC.format(path=path), cache_dir)
        if not html:
            return None
        published, cves = parse_jpcert_doc(html)
        if not published:
            print(f"[warn] jpcert 発行日を抽出できません: {path}", file=sys.stderr)
            return None
        return {"date": published, "cves": sorted(cves), "ref": path, "index_year": year}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return [r for r in pool.map(work, tasks) if r], available


# --------------------------------------------------------------------------
# IPA 重要なセキュリティ情報
# --------------------------------------------------------------------------

IPA_ROW_RE = re.compile(
    r"(\d{4})年(\d{1,2})月(\d{1,2})日.{0,400}?"
    r'href="(/security/security-alert/\d{4}/[0-9a-zA-Z\-_]+\.html)"',
    re.S,
)


def collect_ipa(years, cache_dir, workers):
    """IPA 重要なセキュリティ情報の (発行日, CVE集合) 一覧を返す。

    索引ページは「YYYY年M月D日」と文書リンクを持つ。索引のタイトルは製品名
    ベースで CVE を含まないことが多いため、CVE は各文書本文から抽出する。
    """
    entries = {}
    available = set()
    for year in years:
        html = fetch_text(IPA_INDEX.format(year=year), cache_dir)
        if not html:
            # IPA は 2024 年のサイト改編で旧年次索引が失われている（404）。
            # 到達不能な年を「発行0件」として集計しないよう可用年から除外する。
            continue
        available.add(year)
        for y, mo, d, path in IPA_ROW_RE.findall(html):
            iso = f"{int(y):04d}-{int(mo):02d}-{int(d):02d}"
            # 索引は前年度分も併載するため、リンク先の年ディレクトリで年を確定する
            if not path.startswith(f"/security/security-alert/{y}/"):
                continue
            entries.setdefault(path, iso)
    print(f"[ipa] 文書数 {len(entries)} 件 / 可用年 {sorted(available)}")

    def work(item):
        path, iso = item
        html = fetch_text(IPA_DOC.format(path=path), cache_dir)
        cves = sorted(set(CVE_RE.findall(strip_tags(html)))) if html else []
        return {"date": iso, "cves": cves, "ref": path, "index_year": int(iso[:4])}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(work, entries.items())), available


# --------------------------------------------------------------------------
# 集計
# --------------------------------------------------------------------------


def days_in_year(year, as_of):
    """当該年のうち as_of までの日数（部分年の正規化用）。"""
    start = date(year, 1, 1)
    end = min(date(year, 12, 31), as_of)
    if end < start:
        return 0
    return (end - start).days + 1


def cadence_summary(advisories, years, as_of):
    """発行頻度（年次・全期間）と72h窓での「何らかの発行」確率を返す。"""
    by_year = defaultdict(list)
    for a in advisories:
        y = int(a["date"][:4])
        if y in years:
            by_year[y].append(a)

    per_year = {}
    total_docs = 0
    total_days = 0
    for y in sorted(years):
        d = days_in_year(y, as_of)
        if d == 0:
            continue
        n = len(by_year.get(y, []))
        cves = {c for a in by_year.get(y, []) for c in a["cves"]}
        per_year[str(y)] = {
            "advisories": n,
            "days_covered": d,
            "partial_year": d < days_in_year(y, date(y, 12, 31)),
            "advisories_per_day": round(n / d, 5),
            "distinct_cves_named": len(cves),
        }
        total_docs += n
        total_days += d

    rate = total_docs / total_days if total_days else 0.0
    return {
        "by_year": per_year,
        "total_advisories": total_docs,
        "total_days_covered": total_days,
        "advisories_per_day": round(rate, 5),
        "mean_days_between_advisories": round(1 / rate, 2) if rate else None,
        "p_any_advisory_in_72h_window": round(1 - (1 - rate) ** FAST_WINDOW_DAYS, 4),
    }


def kev_overlap(advisories, kev_entries, years, as_of):
    """KEV 追加を時間原点として、当該チャネルの窓内発生率を直接実測する。

    p_specific_cve_within_72h は
      「KEV 追加後 0〜3 日以内に当該CVEを名指しした注意喚起が1本以上出た CVE 数」
      ÷「対象期間に KEV へ追加された CVE 数」
    の直接推定である。coverage_ratio と タイミング分布の積では算出しない
    （両者の独立を仮定せずに済むため。積による近似は初版の実装で採用していたが、
    『注意喚起が出る主題』と『早く出る主題』の相関を無視する欠陥があった）。
    """
    # CVE -> その CVE を名指しした全注意喚起の発行日リスト
    named_dates = defaultdict(list)
    for a in advisories:
        for cve in a["cves"]:
            named_dates[cve].append(a["date"])

    kev_in_scope = {}
    for e in kev_entries:
        added = (e.get("dateAdded") or "")[:10]
        if not added:
            continue
        y = int(added[:4])
        if y not in years or added > as_of.isoformat():
            continue
        cve = e.get("cveID")
        if cve and (cve not in kev_in_scope or added < kev_in_scope[cve]):
            kev_in_scope[cve] = added

    n_kev = len(kev_in_scope)
    covered_cves = [c for c in kev_in_scope if c in named_dates]

    first_lags = []  # 初回注意喚起のラグ（分布の記述用）
    n_in_window = 0  # 窓 [0, +3] に1本以上ある CVE 数（主要値の分子）
    n_in_window_sym = 0  # 窓 [-3, +3]（感度分析用の上限側）
    for cve in covered_cves:
        added = datetime.strptime(kev_in_scope[cve], "%Y-%m-%d").date()
        lags = [
            (datetime.strptime(d, "%Y-%m-%d").date() - added).days
            for d in named_dates[cve]
        ]
        first_lags.append(min(lags))
        if any(0 <= x <= FAST_WINDOW_DAYS for x in lags):
            n_in_window += 1
        if any(abs(x) <= FAST_WINDOW_DAYS for x in lags):
            n_in_window_sym += 1

    lag_stats = {"n": len(first_lags)}
    if first_lags:
        s = sorted(first_lags)
        lag_stats.update(
            {
                "_note": "初回注意喚起のラグ（日）。負値は KEV 追加より前の発行。",
                "median_days": percentile(s, 50, ndigits=1),
                "p25_days": percentile(s, 25, ndigits=1),
                "p75_days": percentile(s, 75, ndigits=1),
                "min_days": s[0],
                "max_days": s[-1],
                "pct_first_advisory_before_kev": round(
                    sum(1 for x in s if x < 0) / len(s), 4
                ),
                "sufficient_sample": len(s) >= MIN_SAMPLE_LAG,
            }
        )

    # --- 観測遅延つき条件付きハザード（M1 頻度ゲートの主要値） ---
    # 予報は起点イベント（KEV追加）から k 日後に発行される。的中条件は「初回」
    # 注意喚起であるため、発行時点で既に発火済みの主題は的中しえない。したがって
    # 必要なのは無条件確率ではなく「発行時点で未発火」を条件とするハザードであり、
    # かつ発行日と同日の発行は日次収集で既に観測済み（予報にならない）ため
    # 分子は発行日の**翌日以降** [k+1, k+3] に限る。
    first_lag = {}
    for cve, added_str in kev_in_scope.items():
        added = datetime.strptime(added_str, "%Y-%m-%d").date()
        if cve in named_dates:
            first_lag[cve] = min(
                (datetime.strptime(d, "%Y-%m-%d").date() - added).days
                for d in named_dates[cve]
            )
        else:
            first_lag[cve] = None  # 生涯未発火

    hazard = {}
    for k in range(MAX_OBSERVATION_LAG + 1):
        at_risk = [c for c, v in first_lag.items() if v is None or v > k]
        fired = [
            c
            for c in at_risk
            if first_lag[c] is not None
            and k + 1 <= first_lag[c] <= k + FAST_WINDOW_DAYS
        ]
        hazard[str(k)] = {
            "at_risk": len(at_risk),
            "fired_in_window": len(fired),
            "hazard": round(len(fired) / len(at_risk), 5) if at_risk else None,
        }

    return {
        "kev_cves_added_in_scope": n_kev,
        "kev_cves_named_by_channel": len(covered_cves),
        "coverage_ratio": round(len(covered_cves) / n_kev, 4) if n_kev else None,
        "_coverage_ratio_note": (
            "『KEV収載CVEが当該チャネルにいつか名指しされる確率』。"
            "窓の制約を含まないため、窓内発生率の上限として読む。"
        ),
        "kev_cves_with_advisory_in_window": n_in_window,
        "p_specific_cve_within_72h_unconditional": (
            round(n_in_window / n_kev, 5) if n_kev else None
        ),
        "_unconditional_note": (
            "無条件版（KEV追加日を起点とし、[0,+3] に1本以上あれば計上）。"
            "予報発行時点で既に発火済みの事例を分子に含むため、実際の予報が"
            "達成しうる的中率の**上限**であり、base_rate_estimate には使わない。"
            "M1 頻度ゲートと base_rate_estimate は hazard_by_observation_lag を使う。"
        ),
        "hazard_by_observation_lag": {
            "_definition": (
                "予報が起点イベント（KEV追加）から k 日後に発行されたとき、"
                "発行日の翌日〜+3日（fast_72h の検証窓）に当該CVEの初回注意喚起が"
                "出る確率。分母は発行時点で未発火の CVE のみ（既発火は的中しえないため除外）。"
            ),
            "_why_conditional": (
                "無条件確率は『いつか出た』事例を含むが、E3 の的中条件は『初回』発行である。"
                "発行済みの主題を予報しても的中しえないため、無条件確率は base_rate として"
                "系統的に過大となる。E3 が 0/13 に終わった主因はこの条件付けの誤りである"
                "（2026-08-07 精度分析）。"
            ),
            "by_k_days": hazard,
            "pipeline_default_k": PIPELINE_OBSERVATION_LAG,
            "_pipeline_default_note": (
                "Pythia の日次パイプラインは前日分の観測を翌 07:00 JST に収集するため、"
                "起点イベントから予報発行までの標準遅延は 1 日である。"
                "特段の事情がない限り by_k_days['1'] を base_rate_estimate の起点に採る。"
            ),
        },
        "p_specific_cve_within_72h": (
            hazard.get(str(PIPELINE_OBSERVATION_LAG), {}).get("hazard")
        ),
        "_p_specific_note": (
            "M1 頻度ゲートが参照する主要値。"
            "hazard_by_observation_lag.by_k_days[pipeline_default_k].hazard と同値。"
        ),
        "p_specific_cve_within_72h_symmetric_sensitivity": (
            round(n_in_window_sym / n_kev, 5) if n_kev else None
        ),
        "_symmetric_note": (
            "窓を [-3日, +3日] に広げた感度分析値。予報発行の時間原点が KEV 追加とは"
            "限らない（ベンダー勧告起点の予報もある）ことへの上限側ロバストネス確認用。"
            "M1 頻度ゲートの判定には主要値（片側 [0,+3]）を用いる。"
        ),
        "lag_kev_added_to_first_advisory": lag_stats,
    }


def load_e1_reference():
    """E1 の比較用実測値を kev-leadtime-stats.json から読む（再計算はしない）。"""
    if not os.path.exists(KEV_LEADTIME_PATH):
        return None
    try:
        with open(KEV_LEADTIME_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    era = data.get("era_2023_plus_recommended", {})
    return {
        "_source_file": "forecaster/knowledge/kev-leadtime-stats.json",
        "_note": (
            "E1 は本スクリプトでは再計算せず既存実測を参照する。時間原点が NVD 公開で"
            "あり E3 の KEV 追加起点とは条件付けが異なるため、両者の数値を直接比較"
            "する際は _limitations を必ず併読すること。"
        ),
        "pct_within_3d": era.get("pct_within_3d"),
        "n": era.get("n"),
    }


# --------------------------------------------------------------------------
# 出力
# --------------------------------------------------------------------------


def build_document(jpcert, jp_years, ipa, ipa_years, kev, as_of):
    combined = jpcert + ipa
    kev_entries = kev.get("vulnerabilities", [])
    # 成分ごとに索引到達可能だった年が異なる（IPA は 2024 年のサイト改編で
    # 旧年次索引が 404）。combined は両成分が揃う年の積集合でのみ集計する。
    combined_years = jp_years & ipa_years

    components = {
        "jpcert_cc_at": {
            "_name": "JPCERT/CC 注意喚起",
            "_index": "https://www.jpcert.or.jp/at/",
            "years_available": [str(y) for y in sorted(jp_years)],
            "cadence": cadence_summary(jpcert, jp_years, as_of),
            "kev_overlap": kev_overlap(jpcert, kev_entries, jp_years, as_of),
        },
        "ipa_security_alert": {
            "_name": "IPA 重要なセキュリティ情報",
            "_index": "https://www.ipa.go.jp/security/security-alert/",
            "years_available": [str(y) for y in sorted(ipa_years)],
            "_availability_note": (
                "IPA は 2024 年のサイト改編により 2023 年以前の年次索引が 404 で"
                "到達不能。到達不能年を発行0件として集計すると頻度を過小評価するため、"
                "本成分および combined の集計期間から除外している。"
            ),
            "cadence": cadence_summary(ipa, ipa_years, as_of),
            "kev_overlap": kev_overlap(ipa, kev_entries, ipa_years, as_of),
        },
    }

    e3 = {
        "_definition": (
            "E3 = JPCERT/CC・IPA・CERT/CC の初回注意喚起発行"
            "（pipeline-forecast-verification.md 観測出口クラス表）。"
            "本統計は実運用で hit_criteria に指定される JPCERT/CC・IPA の2成分を"
            "実測する。CERT/CC は Pythia の hit_criteria での指定頻度が低く"
            "索引の機械取得形式も異なるため本版では未計測（_limitations 参照）。"
        ),
        "components": components,
        "combined": {
            "_note": (
                "両成分の索引が揃う年のみで集計した E3 の代表値。"
                "M1 頻度ゲートと base_rate_estimate はこの combined 値を参照する。"
            ),
            "years_available": [str(y) for y in sorted(combined_years)],
            "cadence": cadence_summary(combined, combined_years, as_of),
            "kev_overlap": kev_overlap(combined, kev_entries, combined_years, as_of),
        },
    }

    doc = {
        "_comment": (
            "E3（CERT系初回注意喚起）出口チャネルの発行頻度実測。"
            "M1 頻度ゲートの判定値と base_rate_estimate の実測アンカーを供給する。"
            "★測っているのは『予報のスキルなしに的中条件が偶然成立する確率』であり、"
            "予報の良し悪しではない。発行済み予報の hit_criteria・的中判定結果の"
            "変更には使用禁止（原則D・教訓12）。"
        ),
        "_schema_version": "1.0",
        "_machine_generated": True,
        "_generator": "scripts/build_advisory_cadence_stats.py",
        "_generated_on": as_of.isoformat(),
        "_source": {
            "jpcert_cc_at_index": "https://www.jpcert.or.jp/at/YYYY.html",
            "ipa_security_alert_index": (
                "https://www.ipa.go.jp/security/security-alert/YYYY/index.html"
            ),
            "kev_feed": KEV_FEED_URL,
            "kev_catalog_version": kev.get("catalogVersion"),
            "_years_note": (
                "集計対象年は成分ごとに異なる。各 channels.E3.*.years_available を参照。"
            ),
        },
        "_governance": (
            "knowledge/ の自動書き換え禁止ルール（行動原則5）に従い、再生成は"
            "日次ルーチンからは行わず、必ず PR として提案し人間レビューを経てコミットする。"
        ),
        "_limitations": [
            "coverage_ratio の分母は『当該期間に KEV へ追加された CVE』であり、"
            "Pythia が実際に予報候補とする母集団（実悪用確認・PoC公開・APT関連等）と"
            "完全には一致しない。予報母集団は KEV より注目度が高い側に偏る可能性があり、"
            "その場合 coverage_ratio は真値の下限寄りになる。",
            "p_specific_cve_within_72h の時間原点は KEV 追加日であり、Pythia の予報"
            "発行日ではない。予報は KEV 追加以外（ベンダー勧告・PoC公開・APT報道）を"
            "起点に発行されることがあり、その場合の窓は本統計の窓とずれる。"
            "この時間原点のずれに対するロバストネスは "
            "p_specific_cve_within_72h_symmetric_sensitivity（窓 [-3,+3]）で確認できる。",
            "注意喚起の初回発行が KEV 追加より前になる事例が相当割合ある"
            "（lag_kev_added_to_first_advisory.pct_first_advisory_before_kev 参照）。"
            "これは JPCERT/CC が日本国内で影響の大きい主題を CISA より早く扱う"
            "ケースがあるためであり（推測）、E3 が『KEV の後追い』だけではないことを示す。"
            "ただし主要値は片側窓 [0,+3] で測っており、これらは分子に計上されない。",
            "JPCERT/CC の発行日は各文書の「（公開）」表記（初版日）を採用している。"
            "同一主題の更新版は初版日に丸められるため、更新公開を的中条件とする予報の"
            "ベースレートには本統計を使わない（M1 は初回発行のみを E3 と定義している）。",
            "IPA の CVE 抽出は文書本文の CVE-ID 文字列一致による。製品名のみで CVE を"
            "明記しない告知は CVE 単位の coverage に計上されず、IPA 側の coverage_ratio は"
            "過小評価となる。この過小評価は combined 値にも波及する。",
            "CERT/CC（kb.cert.org VU#）は本版では未計測。E3 の定義には含まれるため、"
            "combined 値は E3 全体のわずかな過小評価となる。CERT/CC の VU# 発行頻度は"
            "JPCERT/CC・IPA と同程度かそれ以下であり、結論（E3 の窓内発生率が低い）を"
            "反転させる規模ではない（推測・未実測）。",
            "部分年（実行年）は days_covered で正規化しているが、注意喚起の発行は"
            "月例更新サイクル（マイクロソフト第2火曜等）に同期して不均一に分布する。"
            "72時間窓の確率は一様ポアソン近似であり、月例週とそれ以外で実際の確率は上下する。",
            "ハザードの分母『未発火』は KEV 追加を時間原点とする近似である。"
            "予報がベンダー勧告・PoC公開など KEV 以外を起点に発行された場合、"
            "実際の未発火判定はずれる。個別予報では hit_criteria 記載時点で"
            "当該チャネルに既存の注意喚起がないことを直接確認すること"
            "（本統計は母集団の見積もりであり、個別の未発火確認の代替にはならない）。",
            "本統計は的中条件（hit_criteria）を緩める根拠には使用禁止。"
            "使ってよいのは (1) M1 頻度ゲートによる発行前の主題選別（入口）、"
            "(2) base_rate_estimate の記入アンカー、の2用途のみ（原則D・教訓12）。",
        ],
        "_usage": {
            "m1_frequency_gate": (
                "fast_72h の主的中条件に採用してよいのは、当該チャネルの"
                "p_specific_cve_within_72h（＝観測遅延 k を条件とする実測ハザード）が "
                "m1_frequency_gate_threshold 以上のチャネルに限る。"
                "下回るチャネルは slow_7d へ割当てるか、注意点1行へ格下げする。"
                "起点イベントからの遅延 k が既知の場合は by_k_days[k] を使う"
                "（k が大きいほどハザードは急減する）。"
            ),
            "m1_frequency_gate_threshold": 0.10,
            "_threshold_rationale": (
                "確度『低』の目標帯上限が 0.40、E1（KEV初回追加）の実測窓内発生率が "
                "0.30（kev-leadtime-stats.json era_2023_plus_recommended.pct_within_3d）"
                "であることから、実運用で機能しているチャネルは 0.30 前後にある。"
                "その 1/3 を下限とし、これを下回るチャネルは fast_72h の主的中条件に"
                "採らない。閾値の変更は人間レビュー経由でのみ行う。"
            ),
            "base_rate_estimate": (
                "当該チャネルの hazard_by_observation_lag.by_k_days[k]（k=起点イベントから"
                "予報発行までの日数・既定は pipeline_default_k）を記入の起点とし、"
                "個別 Evidence の強さに応じて調整する。起点から 2 倍を超えて"
                "上振れさせる場合は forecast の根拠欄に理由を明記する。"
            ),
        },
        "channels": {
            "E3": e3,
            "E1_reference": load_e1_reference(),
        },
    }
    return doc


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--as-of", default=date.today().isoformat(), help="集計基準日 YYYY-MM-DD")
    ap.add_argument("--start-year", type=int, default=DEFAULT_START_YEAR)
    ap.add_argument("--kev-file", help="CISA KEV catalog のローカルパス")
    ap.add_argument("--cache-dir", help="HTML ディスクキャッシュのディレクトリ")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--out", default=OUT_PATH)
    args = ap.parse_args()

    as_of = datetime.strptime(args.as_of, "%Y-%m-%d").date()
    years = list(range(args.start_year, as_of.year + 1))

    jpcert, jp_years = collect_jpcert(years, args.cache_dir, args.workers)
    ipa, ipa_years = collect_ipa(years, args.cache_dir, args.workers)
    if not jpcert:
        raise SystemExit("[fatal] JPCERT/CC 注意喚起を1件も取得できませんでした。")
    if not jp_years & ipa_years:
        raise SystemExit(
            "[fatal] JPCERT/CC と IPA の索引が両方揃う年がありません。"
            "combined 値を算出できないため中断します。"
        )
    kev = load_kev(args.kev_file)

    doc = build_document(jpcert, jp_years, ipa, ipa_years, kev, as_of)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")

    c = doc["channels"]["E3"]["combined"]
    o = c["kev_overlap"]
    print(f"\n[out] {args.out}")
    print(f"  E3 combined 対象年: {c['years_available']}")
    print(
        f"  発行 {c['cadence']['total_advisories']}本 / "
        f"{c['cadence']['total_days_covered']}日 = "
        f"{c['cadence']['advisories_per_day']}本/日"
    )
    print(f"  P(72h窓に何らかの発行) = {c['cadence']['p_any_advisory_in_72h_window']}（上限）")
    print(
        f"  KEV coverage = {o['kev_cves_named_by_channel']}"
        f"/{o['kev_cves_added_in_scope']} = {o['coverage_ratio']}"
    )
    print(
        f"  無条件 p_within_72h = {o['p_specific_cve_within_72h_unconditional']}"
        f"（窓内該当 {o['kev_cves_with_advisory_in_window']}件・上限値）"
    )
    print("  観測遅延 k 条件付きハザード:")
    for k, v in o["hazard_by_observation_lag"]["by_k_days"].items():
        mark = " ←パイプライン既定" if int(k) == PIPELINE_OBSERVATION_LAG else ""
        print(
            f"    k={k}: {v['hazard']}  "
            f"(未発火 {v['at_risk']}件中 {v['fired_in_window']}件){mark}"
        )
    print(f"  ★p_specific_cve_within_72h = {o['p_specific_cve_within_72h']}")
    print(f"  M1 頻度ゲート閾値 = {doc['_usage']['m1_frequency_gate_threshold']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
