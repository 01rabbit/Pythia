#!/usr/bin/env python3
"""観測の情報源を、予報 universe が宣言する確認チャネルへ決定論的に解決する。

★判定は「掲載元ホスト」で行う。組織名の言及では一次情報にしない。

  なぜ source.type を使わないか:
    source.type は媒体種別ではなく記事内容で付与されており、同一媒体でも値が割れる。
    実測: 「The Hacker News」= news 79 / vendor_report 3 / advisory 4。
    type を受理条件に使うと、一次機関の記録が型の誤りで検証から外れる。

  なぜ source.name のトークンで昇格させないか:
    複合表記の一次組織を根拠にすると、実際の掲載元が集約ニュースでも hit になる。
    実測: 「CISA / BleepingComputer」の URL ホストは www.bleepingcomputer.com、
          「Microsoft Threat Intelligence / The Hacker News」は thehackernews.com、
          「CERT.PL / SecurityWeek」は www.securityweek.com。
    これらを cert / vendor として受理すると「二次報道を確認事実にしない」契約が壊れる。
    そのため name は診断（primary_reference の欠落警告）にのみ使う。

  なぜ本文から推定しないか:
    原則1（ハルシネーション厳禁）。根拠は構造化フィールドの URL だけである。

★fail-closed: 登録簿にないホストは "unattributed" を返し、hit にしない。
  ただし「解決できなかった」ことは呼び出し側で計数し、沈黙させない。
"""

import glob
import json
import os
from urllib.parse import urlparse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(REPO_ROOT, "forecaster", "knowledge", "source-channels.json")
MANIFEST_GLOB = os.path.join(REPO_ROOT, "forecaster", "evidence", "manifests",
                             "*", "*", "*.json")

UNATTRIBUTED = "unattributed"
AGGREGATOR = "aggregator_news"
_CACHE = {}


def load_evidence_records(pattern=MANIFEST_GLOB):
    """evidence_id -> {source_url, retrieved_at_utc} を返す。

    ★primary_reference を一次確認として受理するには、その原典が Evidence Ledger に
      取得証跡（URL と取得時刻）付きで存在しなければならない。許可ホストのURLを
      書くだけで hit を作れると、計測が汚染される（PR #175 レビュー指摘）。
    """
    if pattern in _CACHE:
        return _CACHE[pattern]
    out = {}
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for ev in doc.get("evidence", []):
            eid = ev.get("evidence_id")
            if eid and ev.get("source_url") and ev.get("retrieved_at_utc"):
                out[eid] = {"source_url": ev["source_url"],
                            "retrieved_at_utc": ev["retrieved_at_utc"]}
    _CACHE[pattern] = out
    return out


def load_registry(path=REGISTRY):
    """{"hosts": {host: channel}, "orgs": {name_lower: channel}} を返す。"""
    if path in _CACHE:
        return _CACHE[path]
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    hosts = {}
    for channel, names in doc["hosts"].items():
        for host in names:
            hosts[host.lower()] = channel
    orgs = {}
    for channel, names in (doc.get("organizations") or {}).items():
        if channel.startswith("_"):
            continue
        for name in names:
            orgs[name.lower()] = channel
    table = {"hosts": hosts, "orgs": orgs}
    _CACHE[path] = table
    return table


def host_of(url):
    try:
        return (urlparse(url or "").netloc or "").lower()
    except ValueError:
        return ""


def _channel_of_url(url, table):
    return table["hosts"].get(host_of(url))


def resolve_channel(source, table=None, evidence=None):
    """observation.source から確認チャネルを返す（後方互換のため文字列を返す）。"""
    return resolve(source, table, evidence)[0]


def evidence_backs_reference(reference, evidence):
    """primary_reference が Evidence Ledger の取得証跡に裏づけられているか。

    要件（すべて満たすときのみ昇格を許す）:
      1. reference.evidence_id が Ledger に存在する
      2. その証跡の source_url のホストが reference.url のホストと一致する
      3. 証跡に取得時刻がある（load_evidence_records が保証）
    """
    if not evidence:
        return False
    record = evidence.get((reference or {}).get("evidence_id"))
    if not record:
        return False
    return host_of(record["source_url"]) == host_of(reference.get("url"))


def resolve(source, table=None, evidence=None):
    """(channel, basis) を返す。

    解決順:
      1. source.primary_reference.url のホスト
         — ただし **Evidence Ledger の取得証跡に裏づけられている場合のみ**。
           許可ホストのURLを書くだけでは昇格しない（計測汚染の防止）。
      2. source.url のホスト
      3. どちらも登録簿に無ければ UNATTRIBUTED
    """
    table = load_registry() if table is None else table
    source = source or {}

    reference = source.get("primary_reference") or {}
    if reference:
        ref_channel = _channel_of_url(reference.get("url"), table)
        if ref_channel and ref_channel != AGGREGATOR:
            if evidence_backs_reference(reference, evidence):
                return ref_channel, "primary_reference_url"
            # 証跡が無い原典URLは昇格させない。掲載元ホストへ落とす。
            fallback = _channel_of_url(source.get("url"), table)
            return (fallback or UNATTRIBUTED), "primary_reference_unverified"

    channel = _channel_of_url(source.get("url"), table)
    if channel:
        return channel, "publication_host"
    return UNATTRIBUTED, "unknown_host"


def cited_primary_organizations(source, table=None):
    """source.name が言及している一次組織を返す（診断専用・昇格には使わない）。

    集約ニュースの掲載でも一次組織を引用している場合に、
    「primary_reference を構造化すれば受理できる」ことを示すために使う。
    """
    table = load_registry() if table is None else table
    name = (source or {}).get("name") or ""
    low = name.lower()
    found = []
    for org, channel in table["orgs"].items():
        if org in low:
            found.append((org, channel))
    return found


def needs_primary_reference(source, table=None, evidence=None):
    """掲載元が集約ニュースだが一次組織を引用しており、原典URLが未記録か。"""
    table = load_registry() if table is None else table
    channel, _basis = resolve(source, table, evidence)
    if channel != AGGREGATOR:
        return False
    if (source or {}).get("primary_reference", {}).get("url"):
        return False
    return bool(cited_primary_organizations(source, table))


def accepted_by(universe, channel):
    """universe が宣言したチャネル集合に含まれるか。"""
    return channel in set(universe.get("sources") or [])
