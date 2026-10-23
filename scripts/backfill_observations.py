#!/usr/bin/env python3
"""過去日付の observation を CISA KEV から機械バックフィルする。

目的:
  日次ルーチン開始（2026-06-15）より前の「実悪用確認イベント」を
  forecaster/observations/ に遡及蓄積し、過去事象の掌握と
  類似過去事例検索（scripts/retrieve_similar_cases.py）の母集団を拡充する。

設計原則（forecaster/README.md・CLAUDE.md の運用ルールに準拠）:
  - 日付スタンプ付きソースのみ使用する。KEV の dateAdded は「その日に
    実悪用確認と判定された」ことを示す一次記録であり、as-of 汚染がない。
    ただし summary に補完する CVSS は実行時点の NVD 値（事後付与・事後改訂を
    含みうる付随情報）である点に注意（敵対的レビュー 2026-07-12 指摘）。
  - Technique / actor_group の推測付与は行わない（techniques: [] 固定・
    ハルシネーション厳禁）。付与する場合は人間レビューを経ること。
  - 予報（forecasts/）・検証（verification/）は生成しない。過去日付の
    「予報」を後から作ることは後知恵バイアスとなり検証ループを汚染する。
  - 生成ファイルは _normalization_mode: "machine_backfill_kev" でマーキングし、
    ベースライン統計（scripts/regen_baseline.py）からは除外される。
    ライブ収集日と観測密度が異なるため、混ぜると σ 逸脱スコアが歪む。
  - 既存の観測ファイル（日次ルーチン産）は絶対に上書きしない。
  - reported-*.md / outputs/ には一切触れない（レポートしていないものを
    既報扱いにしない）。

入力:
  - CISA KEV catalog（--kev-file 指定またはネット取得）
  - NVD API hasKev 一括照会（CVSS 補完。--no-nvd で省略可）

出力:
  forecaster/observations/YYYY/MM/YYYY-MM-DD.json（対象期間内で KEV 追加が
  あった日のみ。追加ゼロの日は既定ではファイルを作らない）
  --emit-empty 指定時は、KEV 追加ゼロの日にも observations: [] の
  「欠測日ファイル」を置く（日次ルーチン未実行日を「観測なし」として明示し、
  ファイル不在＝未処理 と区別するため・2026-10-23 追加）。空ファイルも
  _normalization_mode: machine_backfill_kev でマーキングされ、ベースライン統計・
  参照率からは除外される。既存ファイルは --emit-empty でも上書きしない。

使い方:
    python3 scripts/backfill_observations.py --start 2026-01-01 --end 2026-06-14
    python3 scripts/backfill_observations.py --start 2026-01-01 --end 2026-06-14 --dry-run
    python3 scripts/backfill_observations.py --start 2026-06-20 --end 2026-06-20  # 欠損日の単日補完
    python3 scripts/backfill_observations.py --start 2026-09-12 --end 2026-09-12 --emit-empty  # KEV追加ゼロの欠測日

実行後は python3 scripts/validate_observations.py で違反ゼロを確認してからコミットする。
"""

import argparse
import json
import os
import sys
import urllib.request
from collections import defaultdict
from datetime import date, datetime, timedelta

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBSERVATIONS_DIR = os.path.join(REPO_ROOT, "forecaster", "observations")

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_CATALOG_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
NVD_KEV_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
    "?hasKev&resultsPerPage=2000&startIndex={start_index}"
)

NORMALIZATION_MODE = "machine_backfill_kev"

TECHNIQUES_NOTE = (
    "機械バックフィル（KEV遡及取り込み）のため、shortDescription からの "
    "Technique 付与は行っていない。付与する場合は人間レビューを要する。"
)


def fetch_json(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": "pythia-backfill/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def load_kev(kev_file):
    if kev_file:
        with open(kev_file) as f:
            return json.load(f)
    print(f"[fetch] CISA KEV: {KEV_FEED_URL}")
    return fetch_json(KEV_FEED_URL)


def load_nvd_cvss(nvd_file):
    """NVD hasKev 一括照会から {CVE-ID: 'V3.1 9.8' 形式のCVSS文字列} を作る。"""
    vulns = []
    if nvd_file:
        with open(nvd_file) as f:
            data = json.load(f)
        vulns = data.get("vulnerabilities", [])
    else:
        start_index = 0
        while True:
            url = NVD_KEV_URL.format(start_index=start_index)
            print(f"[fetch] NVD hasKev: startIndex={start_index}")
            data = fetch_json(url)
            vulns.extend(data.get("vulnerabilities", []))
            start_index += len(data.get("vulnerabilities", []))
            if start_index >= data.get("totalResults", 0) or not data.get(
                "vulnerabilities"
            ):
                break

    cvss_map = {}
    preference = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id")
        metrics = cve.get("metrics", {})
        for key in preference:
            entries = metrics.get(key) or []
            if not entries:
                continue
            primary = next(
                (e for e in entries if e.get("type") == "Primary"), entries[0]
            )
            cvss_data = primary.get("cvssData", {})
            score = cvss_data.get("baseScore")
            version = cvss_data.get("version", "")
            if score is not None:
                cvss_map[cve_id] = f"{score}（v{version}）"
            break
    return cvss_map


def build_observation(entry, seq, ingested_date, cvss_map):
    date_added = entry["dateAdded"]
    cve_id = entry["cveID"]
    vendor = (entry.get("vendorProject") or "").strip()
    product = (entry.get("product") or "").strip()
    vuln_name = (entry.get("vulnerabilityName") or "").strip()

    cvss = cvss_map.get(cve_id)
    cvss_text = cvss if cvss else "非公開"

    # CVSS は実行時点の NVD 値（事後改訂を含みうる）のため取得時点を明記する
    summary = (
        f"{vendor} {product} の脆弱性 {cve_id} が CISA KEV に追加された"
        f"（実悪用確認に基づく）。CVSS {cvss_text}（{ingested_date}時点のNVD値）。"
        f"種別: {vuln_name}。"
    )

    tags = ["backfill", "kev"]
    if entry.get("knownRansomwareCampaignUse") == "Known":
        tags.append("ransomware")

    y, m, d = date_added.split("-")
    return {
        "observation_id": f"obs-{y}-{m}{d}-{seq:03d}",
        "observed_date": date_added,
        "ingested_date": ingested_date,
        "source": {
            "name": "CISA KEV",
            "url": KEV_CATALOG_PAGE,
            "type": "advisory",
        },
        "actor_group": None,
        "techniques": [],
        "techniques_note": TECHNIQUES_NOTE,
        "target": {"sectors": [], "geos": []},
        "cve": [cve_id],
        "exploitation_stage": "kev_listed",
        "confidence": "high",
        "summary": summary,
        "verified_outcome": None,
        "related_forecast_id": None,
        "tags": tags,
    }


def target_path(day):
    y, m, _ = day.split("-")
    return os.path.join(OBSERVATIONS_DIR, y, m, f"{day}.json")


def main():
    ap = argparse.ArgumentParser(
        description="CISA KEV の dateAdded に基づき過去日付の observation を機械生成する。"
    )
    ap.add_argument("--start", required=True, help="対象期間の開始日（YYYY-MM-DD・含む）")
    ap.add_argument("--end", required=True, help="対象期間の終了日（YYYY-MM-DD・含む）")
    ap.add_argument("--kev-file", help="KEV catalog JSON のローカルパス（省略時はネット取得）")
    ap.add_argument("--nvd-file", help="NVD hasKev 応答 JSON のローカルパス（省略時はネット取得）")
    ap.add_argument("--no-nvd", action="store_true", help="NVD による CVSS 補完を行わない")
    ap.add_argument(
        "--force",
        action="store_true",
        help="既存の machine_backfill_kev ファイルを上書きする（他モードのファイルは対象外）",
    )
    ap.add_argument(
        "--emit-empty",
        action="store_true",
        help="期間内で KEV 追加が無い日にも observations: [] の欠測日ファイルを置く（既存ファイルは上書きしない）",
    )
    ap.add_argument("--dry-run", action="store_true", help="ファイルを書き込まず件数のみ表示")
    args = ap.parse_args()

    for v in (args.start, args.end):
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            ap.error(f"日付形式が不正: {v}")
    if args.start > args.end:
        ap.error("--start は --end 以前であること")

    kev = load_kev(args.kev_file)
    catalog_version = kev.get("catalogVersion", "unknown")
    in_window = [
        e for e in kev.get("vulnerabilities", [])
        if args.start <= e.get("dateAdded", "") <= args.end
    ]
    print(
        f"[kev] catalog {catalog_version}: "
        f"{len(in_window)} 件が期間 {args.start}..{args.end} 内"
    )
    if not in_window and not args.emit_empty:
        print("[done] 対象期間内の KEV 追加なし。生成ファイルなし（--emit-empty で欠測日ファイルを置ける）。")
        return 0

    cvss_map = {}
    if not args.no_nvd:
        try:
            cvss_map = load_nvd_cvss(args.nvd_file)
            print(f"[nvd] CVSS 取得: {len(cvss_map)} 件")
        except Exception as e:  # CVSS は補完情報なので取得失敗でも続行する
            print(f"[warn] NVD 取得失敗（CVSS は「非公開」表記で続行）: {e}")

    by_day = defaultdict(list)
    for e in in_window:
        by_day[e["dateAdded"]].append(e)
    days = set(by_day)
    if args.emit_empty:
        # 期間内の全日付を対象にし、KEV 追加ゼロの日は空の欠測日ファイルにする
        d = datetime.strptime(args.start, "%Y-%m-%d").date()
        end = datetime.strptime(args.end, "%Y-%m-%d").date()
        while d <= end:
            days.add(d.isoformat())
            d += timedelta(days=1)

    ingested = date.today().isoformat()
    written, skipped = [], []
    for day in sorted(days):
        path = target_path(day)
        rel = os.path.relpath(path, REPO_ROOT)
        if os.path.exists(path):
            with open(path) as f:
                existing = json.load(f)
            if existing.get("_normalization_mode") != NORMALIZATION_MODE:
                skipped.append((rel, "既存の非バックフィルファイル（上書き禁止）"))
                continue
            if not args.force:
                skipped.append((rel, "既存バックフィルファイル（--force で上書き可）"))
                continue

        entries = sorted(by_day.get(day, []), key=lambda e: e["cveID"])
        observations = [
            build_observation(e, i + 1, ingested, cvss_map)
            for i, e in enumerate(entries)
        ]
        if observations:
            note = (
                f"機械バックフィル: CISA KEV catalog {catalog_version} の dateAdded に基づき "
                f"{ingested} に scripts/backfill_observations.py が生成。"
                "Technique/actor_group の推測付与なし。"
                "ベースライン統計からは除外される（regen_baseline.py が machine_backfill_* をスキップ）。"
            )
        else:
            note = (
                f"欠測日（日次ルーチン未実行）: CISA KEV catalog {catalog_version} に当日 dateAdded の"
                f"エントリは無く、{ingested} に scripts/backfill_observations.py --emit-empty が"
                "観測 0 件の空ファイルとして生成。ファイル不在（未処理）と区別するためのマーカーであり、"
                "当日のニュース系観測は収集されていない（観測なし ≠ 事象なし）。"
                "ベースライン統計からは除外される（regen_baseline.py が machine_backfill_* をスキップ）。"
            )
        wrapper = {
            "_schema_version": "1.1",
            "_observation_date": day,
            "_normalization_mode": NORMALIZATION_MODE,
            "_normalization_note": note,
            "_retro_normalized": True,
            "_retro_note": (
                f"{ingested} 遡及生成: 日次ルーチン対象外期間の KEV 追加イベントを機械取り込み。"
                if observations
                else f"{ingested} 遡及生成: 日次ルーチン未実行日の欠測マーカー（観測 0 件）。"
            ),
            "observations": observations,
        }
        if args.dry_run:
            print(f"[dry-run] {rel}: {len(observations)} observations")
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(wrapper, f, ensure_ascii=False, indent=2)
            f.write("\n")
        written.append((rel, len(observations)))
        print(f"[write] {rel}: {len(observations)} observations")

    for rel, reason in skipped:
        print(f"[skip] {rel}: {reason}")
    total_obs = sum(n for _, n in written)
    print(
        f"[done] 書き込み {len(written)} ファイル / {total_obs} observations, "
        f"スキップ {len(skipped)} ファイル"
    )
    if written:
        print("[next] python3 scripts/validate_observations.py で検証してからコミットすること。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
