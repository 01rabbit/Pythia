#!/usr/bin/env python3
"""観測の情報源を、予報 universe が宣言する確認チャネルへ決定論的に解決する。

★なぜ source.type を使わないか（Blocker 1a）:
  source.type は媒体種別ではなく記事内容で付与されており、同一媒体でも値が割れる。
  実測: 「The Hacker News」= news 79 / vendor_report 3 / advisory 4、
        「Security NEXT」  = news 87 / vendor_report 3 / advisory 4。
  type を採用条件に使うと、一次機関の記録が媒体種別の誤りで検証から外れる。
  実際 `CISA KEV` を名乗る観測155件のうち4件が news 型になっており、
  そのうち1件（CVE-2026-8452）は唯一の前進確認だった。

★なぜ本文から推定しないか:
  原則1（ハルシネーション厳禁）。解決根拠は構造化フィールド（source.name および
  任意の source.primary_channel）のみで、summary からのキーワード推定は行わない。

★fail-closed:
  登録簿にない組織は "unattributed" を返す。unattributed は hit にしない。
  ただし「解決できなかった」ことは呼び出し側で計数し、沈黙させない。
"""

import json
import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(REPO_ROOT, "forecaster", "knowledge", "source-channels.json")

UNATTRIBUTED = "unattributed"
AGGREGATOR = "aggregator_news"
SPLIT_RE = re.compile(r"[/／,、()（）\[\]【】]")
_CACHE = {}


def load_registry(path=REGISTRY):
    """組織名（小文字）→チャネルの辞書を返す。"""
    if path in _CACHE:
        return _CACHE[path]
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    table = {}
    for channel, names in doc["channels"].items():
        for name in names:
            table[name.lower()] = channel
    _CACHE[path] = table
    return table


def tokenize(name):
    """複合表記の情報源名を組織トークンへ分解する。"""
    return [t.strip() for t in SPLIT_RE.split(name or "") if t.strip()]


def _match(token, table):
    """1トークンをチャネルへ解決する。完全一致→前方一致の順。"""
    low = token.lower()
    if low in table:
        return table[low]
    for key, channel in table.items():
        # 「CISA Cybersecurity Advisory AA23-061A」→ cert のように、
        # 組織名で始まる長い表記を拾う。誤爆を避けるため4文字以上のキーに限る。
        if len(key) >= 4 and low.startswith(key) and not low[len(key):len(key) + 1].isalnum():
            return channel
    return None


def resolve_channel(source, table=None):
    """observation.source から確認チャネルを返す。

    優先順位:
      1. source.primary_channel（正規化時に構造化されていればそれが正本）
      2. source.name のトークン解決。非 aggregator が1つでもあればそれを採る
      3. aggregator_news しか出なければ aggregator_news
      4. 何も解決しなければ UNATTRIBUTED
    """
    table = load_registry() if table is None else table
    source = source or {}
    declared = source.get("primary_channel")
    if declared:
        return declared
    name = source.get("name")
    # 「JPCERT/CC」のように組織名自体が区切り文字を含む場合があるため、
    # 分割前の全体名も候補に入れる。非 aggregator 優先の規則は後段で共通に効く。
    candidates = [_match(name or "", table)]
    candidates += [_match(t, table) for t in tokenize(name)]
    found = [c for c in candidates if c]
    for channel in found:
        if channel != AGGREGATOR:
            return channel
    return AGGREGATOR if found else UNATTRIBUTED


def accepted_by(universe, channel):
    """universe が宣言したチャネル集合に含まれるか。"""
    return channel in set(universe.get("sources") or [])
