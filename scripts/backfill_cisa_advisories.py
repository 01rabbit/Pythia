#!/usr/bin/env python3
"""CISA サイバーセキュリティ勧告（AAシリーズ）から過去の APT 観測を機械バックフィルする。

目的:
  CISA の AA 勧告は「発行日・明示的な ATT&CK テーブル・明示的な帰属」を備えた
  数少ない一次ソースであり、APT 活動の過去事象を R3/R4（evidence-based 原則）を
  満たしたまま観測として遡及蓄積できる。日次ルーチン開始（2026-06-15）より前の
  APT 事象の掌握と類似過去事例検索の母集団拡充が目的。

データ取得経路:
  cisa.gov は本実行環境のプロキシで直接取得不可のため、Internet Archive
  （Wayback Machine）のスナップショット経由で取得する。アーカイブは取得時点で
  凍結されたページであり、as-of 忠実性の面でもむしろ望ましい。

設計原則（backfill_observations.py と同じ枠組み）:
  - 観測のみ。予報・検証の遡及生成はしない（後知恵バイアス防止）。
  - Technique 付与は勧告本文の ATT&CK テーブルへのリンクとして明示された
    ID のみ（推測付与なし・R3）。tactic は ATT&CK 定義で一意な場合、または
    ページ内の直前 tactic 見出しが当該 Technique の正当な tactic である場合のみ
    付与し、決められない Technique は techniques_note に記録して除外する。
  - actor_group はタイトルに group-aliases.json 記載の正規名/エイリアスが
    現れる場合のみ（単語境界一致・R4）。それ以外は null。
  - 生成ファイルは `_normalization_mode: "machine_backfill_cisa_advisory"` で
    マーキング（既存 KEV バックフィルファイルと同日の場合はマージし
    "machine_backfill_mixed" とする）。ベースライン統計からは除外される
    （regen_baseline.py が machine_backfill_* をスキップ）。
  - 日次ルーチン産の既存ファイルは絶対に上書きしない。日次ルーチン開始日
    （2026-06-15）以降の勧告は対象外（ライブ収集の領分）。
  - reported-*.md / outputs/ には触れない。

入力:
  - Wayback CDX API（AA 勧告 URL の列挙）+ Wayback スナップショット
  - MITRE ATT&CK enterprise STIX（--attack-stix・tactic 解決に必須）
  - forecaster/knowledge/group-aliases.json（帰属の正規名照合）

使い方:
    python3 scripts/backfill_cisa_advisories.py --attack-stix enterprise-attack.json \
        --cache-dir /path/to/cache [--limit 5] [--dry-run]
"""

import argparse
import gzip
import html
import io
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import date, timedelta

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBSERVATIONS_DIR = os.path.join(REPO_ROOT, "forecaster", "observations")
ALIASES_PATH = os.path.join(REPO_ROOT, "forecaster", "knowledge", "group-aliases.json")

CDX_API = "https://web.archive.org/cdx/search/cdx"
WAYBACK_RAW = "https://web.archive.org/web/{ts}id_/{url}"
CDX_PATTERNS = [
    "us-cert.cisa.gov/ncas/alerts/aa*",
    "www.cisa.gov/uscert/ncas/alerts/aa*",
    "www.cisa.gov/news-events/cybersecurity-advisories/aa*",
]
CANONICAL_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories/{aid}"

MODE = "machine_backfill_cisa_advisory"
MODE_MIXED = "machine_backfill_mixed"
LIVE_ROUTINE_START = "2026-06-15"  # これ以降はライブ日次収集の領分（対象外）
CVE_LIMIT = 100  # 1観測あたりの CVE 記録上限（超過分は新しい順に採用・cve_truncated 記録）
TECHNIQUE_CATALOG_THRESHOLD = 40  # これ超は汎用ベストプラクティス勧告のカタログとみなす

# タイトル単語境界一致だけでは誤帰属しうる一般英単語のエイリアス。
# これらは title-only 照合の対象から除外する（R4・誤帰属防止・敵対的レビュー P2）。
# 例: Snake(Turla)/Agenda(Qilin)/Armageddon(Gamaredon)/ZINC(Lazarus) は一般語と衝突する。
AMBIGUOUS_ALIASES = {"snake", "agenda", "armageddon", "zinc"}

ADVISORY_ID_RE = re.compile(r"/(aa(\d{2})-(\d{3})([a-z])?)(?:$|[/?#])", re.I)
TECHNIQUE_LINK_RE = re.compile(
    r"attack\.mitre\.org/(?:versions/v\d+/)?techniques/(T\d{4})(?:/(\d{3}))?", re.I
)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
RELEASE_DATE_RE = re.compile(
    r"Release\s*Date[^A-Za-z0-9]{0,40}?"
    r"([A-Z][a-z]+ \d{1,2}, \d{4}|\d{4}-\d{2}-\d{2})"
)
TAG_RE = re.compile(r"<[^>]+>")

MONTHS = {
    m: i + 1
    for i, m in enumerate(
        "January February March April May June July August September October November December".split()
    )
}

# STIX の tactic 語彙 → observation.schema.json の enum への正規化。
# 使用する ATT&CK STIX（v19系）は defense-evasion を stealth / defense-impairment に
# 改称・分割しているため、スキーマの defense-evasion へ写像する。写像しないと
# defense-evasion 系 technique の tactic が丸ごと欠落・誤付与される（敵対的レビュー
# 2026-07-12 の C1/C2 指摘）。恒等写像のものは辞書に載せない。
STIX_TACTIC_TO_SCHEMA = {
    "stealth": "defense-evasion",
    "defense-impairment": "defense-evasion",
}

# observation.schema.json が許可する Enterprise ATT&CK の14 tactic。
# Mobile/ICS 由来はスキーマ外のため除外する。
ENTERPRISE_TACTICS = {
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

# ページ見出し表記 → ATT&CK tactic slug
TACTIC_HEADINGS = {
    "reconnaissance": "reconnaissance",
    "resource development": "resource-development",
    "initial access": "initial-access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege escalation": "privilege-escalation",
    "defense evasion": "defense-evasion",
    "credential access": "credential-access",
    "discovery": "discovery",
    "lateral movement": "lateral-movement",
    "collection": "collection",
    "command and control": "command-and-control",
    "exfiltration": "exfiltration",
    "impact": "impact",
}


def http_get(url, timeout=90):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "pythia-cisa-backfill/1.0",
            "Accept-Encoding": "gzip",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip" or body[:2] == b"\x1f\x8b":
            body = gzip.GzipFile(fileobj=io.BytesIO(body)).read()
        return body.decode("utf-8", "replace")


def http_get_with_retry(url, timeout=90, retries=4):
    for attempt in range(retries):
        try:
            return http_get(url, timeout=timeout)
        except Exception as e:
            wait = 2 ** (attempt + 1)
            print(f"[warn] 取得失敗（retry in {wait}s）: {url}: {e}")
            time.sleep(wait)
    raise RuntimeError(f"取得が {retries} 回失敗: {url}")


def enumerate_advisories(cache_dir):
    """CDX で AA 勧告の全スナップショットを列挙し {aid: [(timestamp, original), ...]} を返す。

    複数スナップショットを保持し、選択（発行直後の最古版）は呼び出し側で行う。
    最新版を採ると発行の数年後に追記された未来 CVE・関連勧告が混入するため
    （敵対的レビュー 2026-07-12 の C3 指摘）、発行日以降で最古のスナップショットを使う。"""
    cache_path = os.path.join(cache_dir, "cdx-aa.json") if cache_dir else None
    if cache_path and os.path.exists(cache_path):
        return {k: [tuple(s) for s in v] for k, v in json.load(open(cache_path)).items()}
    snaps = defaultdict(list)
    for pattern in CDX_PATTERNS:
        params = urllib.parse.urlencode(
            {
                "url": pattern,
                "output": "json",
                "collapse": "timestamp:8",  # 1日1スナップショットに間引く
                "fl": "original,timestamp,statuscode",
                "filter": "statuscode:200",
                "limit": "20000",
            }
        )
        rows = json.loads(http_get_with_retry(f"{CDX_API}?{params}", timeout=180))
        for original, ts, _status in rows[1:]:
            if "?" in original:  # クエリ付き・付録URLを除外
                continue
            m = ADVISORY_ID_RE.search(original.lower())
            if not m:
                continue
            snaps[m.group(1)].append((ts, original))
        time.sleep(1.0)
    result = {aid: sorted(lst) for aid, lst in snaps.items()}
    if cache_path:
        with open(cache_path, "w") as f:
            json.dump({k: [list(s) for s in v] for k, v in result.items()}, f)
    return result


def select_snapshot(snapshots, pub_date):
    """発行日（YYYY-MM-DD）以降で最古のスナップショットを選ぶ。

    発行後に追記された未来情報の混入を避ける。発行日以降が無ければ全体の最古。
    戻り値: (timestamp, original) または None。"""
    if not snapshots:
        return None
    pub_compact = pub_date.replace("-", "") if pub_date else None
    if pub_compact:
        after = [s for s in snapshots if s[0][:8] >= pub_compact]
        if after:
            return min(after)
    return min(snapshots)


def advisory_date_from_id(aid):
    """aa{yy}-{ddd}{x} の年+年内通日から発行日を導く。"""
    m = re.match(r"aa(\d{2})-(\d{3})", aid)
    year, doy = 2000 + int(m.group(1)), int(m.group(2))
    if not 1 <= doy <= 366:
        return None
    try:
        return (date(year, 1, 1) + timedelta(days=doy - 1)).isoformat()
    except ValueError:
        return None


def parse_page_date(raw_html):
    m = RELEASE_DATE_RE.search(TAG_RE.sub(" ", raw_html))
    if not m:
        return None
    v = m.group(1)
    if re.match(r"^\d{4}-\d{2}-\d{2}$", v):
        return v
    mon, day, year = re.match(r"([A-Z][a-z]+) (\d{1,2}), (\d{4})", v).groups()
    if mon not in MONTHS:
        return None
    return f"{int(year):04d}-{MONTHS[mon]:02d}-{int(day):02d}"


def parse_title(raw_html):
    m = re.search(r"<title[^>]*>(.*?)</title>", raw_html, re.S | re.I)
    if not m:
        return None
    t = html.unescape(TAG_RE.sub("", m.group(1))).strip()
    return re.sub(r"\s*\|\s*CISA\s*$", "", t) or None


def load_attack_tactics(stix_path):
    """ATT&CK STIX から {T-code: [tactic slug]} を作る（親・サブとも）。"""
    bundle = json.load(open(stix_path))
    tactics_of = {}
    for o in bundle.get("objects", []):
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get(
            "x_mitre_deprecated"
        ):
            continue
        tid = next(
            (
                r.get("external_id")
                for r in o.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not tid:
            continue
        # STIX 語彙をスキーマ enum へ正規化してから保持する
        tactics_of[tid] = sorted(
            {
                STIX_TACTIC_TO_SCHEMA.get(ph["phase_name"], ph["phase_name"])
                for ph in o.get("kill_chain_phases", [])
                if ph.get("kill_chain_name") == "mitre-attack"
            }
        )

    # フェイルファスト: 正規化後も14 tactic を網羅していなければ STIX 語彙が想定外。
    # 特に defense-evasion 欠落は tactic の系統的欠落・誤付与を招くため中断する。
    covered = {t for ts in tactics_of.values() for t in ts}
    missing = ENTERPRISE_TACTICS - covered
    if missing:
        raise SystemExit(
            f"[fatal] STIX の tactic 語彙がスキーマ enum を網羅していません（未カバー: "
            f"{sorted(missing)}）。STIX_TACTIC_TO_SCHEMA の写像を見直してください。"
        )
    return tactics_of


def load_alias_matchers():
    """group-aliases.json から (正規名, コンパイル済みパターン, 表記) を返す。"""
    data = json.load(open(ALIASES_PATH))
    matchers = []
    for canon, meta in data.get("groups", {}).items():
        for name in [canon] + list(meta.get("aliases", [])):
            if len(name) < 4:  # 短すぎる別名（誤爆源）は照合対象外
                continue
            if name.lower() in AMBIGUOUS_ALIASES:  # 一般語衝突する別名を除外（R4）
                continue
            pat = re.compile(
                r"(?<![A-Za-z0-9])" + re.escape(name) + r"(?![A-Za-z0-9])", re.I
            )
            matchers.append((canon, pat, name))
    return matchers


def extract_techniques(raw_html, tactics_of, aid, url):
    """ATT&CK リンクから technique エントリを作る。tactic を決められないものは note へ。"""
    text = TAG_RE.sub("\n", raw_html)
    # 位置→直前の tactic 見出し を引けるように、見出し出現位置を記録する
    heading_positions = []
    lower = text.lower()
    for heading, slug in TACTIC_HEADINGS.items():
        for m in re.finditer(re.escape(heading), lower):
            heading_positions.append((m.start(), slug))
    heading_positions.sort()

    def nearest_heading_before(pos):
        best = None
        for p, slug in heading_positions:
            if p > pos:
                break
            best = slug
        return best

    found = {}  # (parent, sub) -> tactic or None
    for m in TECHNIQUE_LINK_RE.finditer(raw_html):
        parent = m.group(1).upper()
        sub = f"{parent}.{m.group(2)}" if m.group(2) else None
        key = (parent, sub)
        if key in found:
            continue
        code = sub or parent
        # Enterprise 定義の tactic のみ候補にする（Mobile/ICS 由来を除外）
        valid = [
            t
            for t in (tactics_of.get(code) or tactics_of.get(parent) or [])
            if t in ENTERPRISE_TACTICS
        ]
        tactic = None
        if len(valid) == 1:
            tactic = valid[0]
        elif len(valid) > 1:
            # HTML中の同リンク近傍位置をテキスト位置へ概算対応させるのは不安定なため、
            # タグ除去後テキストで technique ID 表記の位置を探して直前見出しと突合する
            tm = re.search(re.escape(code), text)
            if tm:
                cand = nearest_heading_before(tm.start())
                if cand in valid:
                    tactic = cand
        found[key] = tactic

    techniques, skipped = [], []
    evidence = f"CISA 勧告 {aid.upper()} の ATT&CK テーブルにリンク明示（{url}）"
    for (parent, sub), tactic in sorted(
        found.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")
    ):
        if tactic is None:
            skipped.append(sub or parent)
            continue
        entry = {"technique_id": parent, "tactic": tactic, "evidence": evidence}
        if sub:
            entry["sub_technique_id"] = sub
        techniques.append(entry)
    return techniques, skipped


def target_path(day):
    y, m, _ = day.split("-")
    return os.path.join(OBSERVATIONS_DIR, y, m, f"{day}.json")


def main():
    ap = argparse.ArgumentParser(
        description="CISA AA 勧告（Wayback 経由）から過去 APT 観測を機械生成する。"
    )
    ap.add_argument("--attack-stix", required=True, help="ATT&CK enterprise STIX のローカルパス")
    ap.add_argument("--cache-dir", help="CDX/ページのキャッシュディレクトリ")
    ap.add_argument("--limit", type=int, help="処理する勧告数の上限（パイロット実行用）")
    ap.add_argument("--dry-run", action="store_true", help="ファイルを書き込まず内容を表示")
    args = ap.parse_args()

    tactics_of = load_attack_tactics(args.attack_stix)
    matchers = load_alias_matchers()

    advisories = enumerate_advisories(args.cache_dir)
    print(f"[cdx] 勧告 {len(advisories)} 件を列挙")

    ids = sorted(advisories)
    if args.limit:
        ids = ids[: args.limit]

    obs_by_day = defaultdict(list)
    skipped_live, failed = [], []
    for i, aid in enumerate(ids, 1):
        # observed_date は AA番号由来（年内通日・レビューで実勧告日と一致確認済み）を
        # 一次とする。発行日以降で最古のスナップショットを使い未来情報混入を防ぐ。
        pub_date = advisory_date_from_id(aid)
        if not pub_date:
            failed.append((aid, "AA番号から発行日を導けず"))
            continue
        if pub_date >= LIVE_ROUTINE_START:
            skipped_live.append(aid)
            continue
        snap = select_snapshot(advisories[aid], pub_date)
        if snap is None:
            failed.append((aid, "スナップショットなし"))
            continue
        ts, original = snap
        page_cache = (
            os.path.join(args.cache_dir, f"page-{aid}-{ts[:8]}.html")
            if args.cache_dir
            else None
        )
        try:
            if page_cache and os.path.exists(page_cache):
                raw = open(page_cache).read()
            else:
                raw = http_get_with_retry(WAYBACK_RAW.format(ts=ts, url=original))
                if page_cache:
                    with open(page_cache, "w") as f:
                        f.write(raw)
                time.sleep(1.0)
        except RuntimeError as e:
            failed.append((aid, str(e)))
            continue

        # 発行日以降で最古のスナップショットでも、ページ内の実 Release Date と
        # AA番号由来日が食い違う場合は前者を優先（稀な再採番・訂正への保険）
        page_date = parse_page_date(raw)
        observed = page_date or pub_date
        if observed >= LIVE_ROUTINE_START:
            skipped_live.append(aid)
            continue

        title = parse_title(raw) or aid.upper()
        techniques, tech_skipped = extract_techniques(
            raw, tactics_of, aid, CANONICAL_URL.format(aid=aid)
        )
        # CVE は新しい順に最大 CVE_LIMIT 件。切り捨てた場合は観測に明示する
        # （旧実装の昇順[:20]は Lazarus 勧告 aa24-207a 等で新しいCVEを静かに欠落させた）
        all_cves = sorted(set(CVE_RE.findall(raw)), reverse=True)
        cves = all_cves[:CVE_LIMIT]
        cve_truncated = len(all_cves) > CVE_LIMIT
        if cve_truncated:
            print(
                f"[info] {aid}: CVE {len(all_cves)}件のうち新しい {CVE_LIMIT} 件のみ採用"
            )

        actor, matched_alias = None, None
        for canon, pat, name in matchers:
            if pat.search(title):
                actor, matched_alias = canon, name
                break

        # Technique も帰属も無い観測は R3/R4 上の情報価値が無く、旧 us-cert 形式や
        # リスト/リダイレクトのスナップショットで頻発する（本文・ATT&CKテーブルが
        # 取れていない）。予報の観測材料にならないため出力しない。
        if not techniques and not actor:
            failed.append((aid, f"Technique・帰属とも抽出できず（title={title[:40]!r}）"))
            continue

        # 多数 Technique（>40）は特定キャンペーンでなく汎用ベストプラクティス勧告の
        # カタログ的テーブルであることが多い。単一観測が retrieval 母集団を支配する
        # ノイズになるため confidence を下げ、人間レビュー tag を付す（P1）。
        distinct_parents = len({t["technique_id"] for t in techniques})
        is_catalog = distinct_parents > TECHNIQUE_CATALOG_THRESHOLD
        obs = {
            "observed_date": observed,
            "ingested_date": date.today().isoformat(),
            "source": {
                "name": f"CISA Cybersecurity Advisory {aid.upper()}",
                "url": CANONICAL_URL.format(aid=aid),
                "type": "advisory",
            },
            "actor_group": actor,
            "techniques": techniques,
            "target": {"sectors": [], "geos": []},
            "confidence": "medium" if is_catalog else "high",
            "summary": (
                f"CISA が勧告 {aid.upper()}「{title}」を公開した。"
                + (f"帰属: {actor}（タイトルに明示）。" if actor else "")
                + f"ATT&CK Technique {distinct_parents} 種がリンク明示されている。"
                + ("（多数のためカタログ的勧告と推定）" if is_catalog else "")
            ),
            "verified_outcome": None,
            "related_forecast_id": None,
            "tags": ["backfill", "cisa_advisory"],
        }
        if actor and matched_alias and matched_alias != actor:
            obs["actor_aliases"] = [matched_alias]
        if cves:
            obs["cve"] = cves
        if cve_truncated:
            obs["tags"] = obs["tags"] + ["cve_truncated"]
        if is_catalog:
            obs["tags"] = obs["tags"] + ["catalog_advisory", "human_review"]
        note_parts = []
        if tech_skipped:
            note_parts.append(
                f"tactic を機械的に確定できず除外した Technique: {', '.join(tech_skipped[:10])}"
                + ("等" if len(tech_skipped) > 10 else "")
                + "（複数tacticかつ見出し照合不成立・人間レビューで付与可）"
            )
        note_parts.append(
            "機械バックフィル（Wayback スナップショット由来）のため本文精読による"
            "追加付与は行っていない。"
        )
        obs["techniques_note"] = " ".join(note_parts)
        obs_by_day[observed].append(obs)
        if i % 20 == 0 or i == len(ids):
            print(f"[progress] {i}/{len(ids)} 件処理済み")

    written, skipped_files = [], []
    for day in sorted(obs_by_day):
        path = target_path(day)
        rel = os.path.relpath(path, REPO_ROOT)
        existing = None
        if os.path.exists(path):
            existing = json.load(open(path))
            mode = str(existing.get("_normalization_mode", ""))
            if not mode.startswith("machine_backfill"):
                skipped_files.append((rel, "既存の非バックフィルファイル（上書き禁止）"))
                continue
            if any("cisa_advisory" in (o.get("tags") or []) for o in existing.get("observations", [])):
                skipped_files.append((rel, "CISA勧告バックフィル済み（--force 相当の再実行は未対応）"))
                continue

        base_obs = existing.get("observations", []) if existing else []
        y, m, d = day.split("-")
        merged = list(base_obs)
        # 既存 observation_id の最大連番から続ける（件数依存ではなく実測max。
        # 既存IDが非連番でも衝突しない）
        seq_re = re.compile(rf"^obs-{y}-{m}{d}-(\d{{3}})$")
        used = [
            int(mo.group(1))
            for o in base_obs
            for mo in [seq_re.match(o.get("observation_id", ""))]
            if mo
        ]
        next_seq = (max(used) if used else 0) + 1
        for k, obs in enumerate(obs_by_day[day], start=next_seq):
            merged.append({"observation_id": f"obs-{y}-{m}{d}-{k:03d}", **obs})
        wrapper = {
            "_schema_version": "1.1",
            "_observation_date": day,
            "_normalization_mode": MODE_MIXED if existing else MODE,
            "_normalization_note": (
                ("KEV機械バックフィルに CISA勧告バックフィルを追記（mixed）。" if existing else "")
                + f"CISA AA勧告（Wayback Machine スナップショット）から "
                f"{date.today().isoformat()} に scripts/backfill_cisa_advisories.py が生成。"
                "Technique はリンク明示分のみ・actor はタイトル明示分のみ（R3/R4）。"
                "ベースライン統計からは除外される（machine_backfill_*）。"
            ),
            "_retro_normalized": True,
            "_retro_note": f"{date.today().isoformat()} 遡及生成: 日次ルーチン対象外期間の CISA 勧告イベントを機械取り込み。",
            "observations": merged,
        }
        if args.dry_run:
            print(f"[dry-run] {rel}: +{len(obs_by_day[day])} obs（計{len(merged)}）")
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(wrapper, f, ensure_ascii=False, indent=2)
            f.write("\n")
        written.append((rel, len(obs_by_day[day])))

    print(
        f"[done] 書込 {len(written)} ファイル / "
        f"{sum(n for _, n in written)} observations, "
        f"スキップ(既存) {len(skipped_files)}, ライブ期間除外 {len(skipped_live)}, 失敗 {len(failed)}"
    )
    for aid, why in failed[:10]:
        print(f"[fail] {aid}: {why}")
    if written:
        print("[next] python3 scripts/validate_observations.py で検証してからコミットすること。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
