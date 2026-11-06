#!/usr/bin/env python3
"""ウォッチリスト（官側・運用者指定の監視対象）の読み込みと照合。

`config.yml` の `watchlist:` 節を唯一の定義とし、以下の 2 箇所が共有する。

- `scripts/nvd_window_sweep.py`（Step 0.7）: NVD 窓内公開・KEV 窓内追加の全量から
  ウォッチリスト該当を CVSS 閾値に関係なく母集団へ加える（`watchlist_in_window`）
- `scripts/watchlist_scan.py`（Step 0.8）: RSS 機械収集 raw（news-*.json）を
  アクター・トピック・製品・CVE のキーワードで走査し、Step 1b / 2 の無条件採用候補を作る

★設計上の約束
- ウォッチリスト該当は「採用条件を満たさなくても採用する」だけであり、優先度・確度の
  判定は Step 3 の重みづけと行動原則（根拠なき Technique / 帰属の付与禁止）に従う
- 照合は大文字小文字を無視した部分一致。語の揺れ（別名）はリスト側で列挙する
- `scope.priority_groups`（Phase フォーカスグループ）は actors に自動的に含める
- このモジュールは knowledge/ を含め何も書き換えない（読み取り専用）
- 依存: 標準ライブラリのみ。PyYAML があれば使い、無ければ config.yml の
  必要な節だけを最小パーサで読む（Routine 環境に PyYAML が無くても動くため）
"""

from __future__ import annotations

import os
import re
from typing import Any, Iterable

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG_PATH = os.path.join(REPO_ROOT, "config.yml")

CATEGORIES = ("cves", "products", "actors", "topics")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# --------------------------------------------------------------------------
# config.yml の読み込み
# --------------------------------------------------------------------------

def _strip_comment(line: str) -> str:
    """行末コメントを落とす（引用符の中の # は残す）。"""
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out).rstrip()


def _scalar(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1]
    if text.lower() in ("true", "yes"):
        return True
    if text.lower() in ("false", "no"):
        return False
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def _inline_list(text: str) -> list:
    inner = text.strip()[1:-1].strip()
    if not inner:
        return []
    items, buf, quote = [], [], None
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            continue
        if ch == ",":
            items.append(_scalar("".join(buf)))
            buf = []
            continue
        buf.append(ch)
    if "".join(buf).strip():
        items.append(_scalar("".join(buf)))
    return items


def parse_minimal_yaml(text: str) -> dict:
    """config.yml の形（2 階層のマップ + スカラー / リスト）だけを読む最小パーサ。

    PyYAML が無い環境向けのフォールバック。アンカー・複数行スカラー・3 階層以上の
    ネストは扱わない（config.yml はそれらを使っていない）。
    """
    root: dict = {}
    section: dict | None = None
    current_key: str | None = None
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if indent == 0:
            key, _, rest = body.partition(":")
            key = key.strip()
            if rest.strip():
                root[key] = _inline_list(rest) if rest.strip().startswith("[") else _scalar(rest)
                section, current_key = None, None
            else:
                root[key] = {}
                section, current_key = root[key], None
            continue
        if section is None:
            continue
        if body.startswith("- "):
            if current_key is None:
                continue
            section.setdefault(current_key, [])
            if not isinstance(section[current_key], list):
                section[current_key] = []
            section[current_key].append(_scalar(body[2:]))
            continue
        key, _, rest = body.partition(":")
        key = key.strip()
        current_key = key
        if rest.strip():
            section[key] = _inline_list(rest) if rest.strip().startswith("[") else _scalar(rest)
        else:
            section[key] = []
    return root


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except ImportError:
        return parse_minimal_yaml(text)


def _as_terms(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    terms: list[str] = []
    for item in value:
        if item is None:
            continue
        term = " ".join(str(item).split())
        if term and term not in terms:
            terms.append(term)
    return terms


def load_watchlist(path: str | None = DEFAULT_CONFIG_PATH) -> dict:
    """ウォッチリストを {category: [terms]} で返す。

    `path` が None または存在しない場合は空（全カテゴリ空リスト）。
    `scope.priority_groups` は actors に必ず含める（Phase フォーカスの監視を落とさないため）。
    """
    empty = {cat: [] for cat in CATEGORIES}
    if not path or not os.path.exists(path):
        return {**empty, "_source": None}
    config = load_config(path)
    raw = config.get("watchlist") or {}
    if not isinstance(raw, dict):
        raw = {}
    result = {cat: _as_terms(raw.get(cat)) for cat in CATEGORIES}
    scope = config.get("scope") or {}
    if isinstance(scope, dict):
        for group in _as_terms(scope.get("priority_groups")):
            if group not in result["actors"]:
                result["actors"].append(group)
    result["cves"] = [t.upper() for t in result["cves"] if CVE_RE.fullmatch(t.strip())]
    result["_source"] = path
    return result


def is_empty(watchlist: dict) -> bool:
    return not any(watchlist.get(cat) for cat in CATEGORIES)


def term_counts(watchlist: dict) -> dict:
    return {cat: len(watchlist.get(cat) or []) for cat in CATEGORIES}


# --------------------------------------------------------------------------
# 照合
# --------------------------------------------------------------------------

def _norm(text: str) -> str:
    return " ".join(str(text).split()).lower()


def match_terms(text: str, terms: Iterable[str]) -> list[str]:
    """text に部分一致する語をリスト順で返す（大文字小文字無視・空白正規化）。"""
    haystack = _norm(text)
    if not haystack:
        return []
    return [t for t in terms if t and _norm(t) in haystack]


def match_cve_ids(text: str, cve_terms: Iterable[str]) -> list[str]:
    wanted = {t.upper() for t in cve_terms}
    if not wanted:
        return []
    found = {m.upper() for m in CVE_RE.findall(text or "")}
    return sorted(found & wanted)


def match_item(watchlist: dict, *, text: str, cve_ids: Iterable[str] = ()) -> dict:
    """1 件分の自由文（タイトル + 要約 + 説明等）を全カテゴリで照合する。

    戻り値は {category: [matched terms]}（該当カテゴリのみ）。空 dict なら非該当。
    """
    matched: dict = {}
    ids = {str(c).upper() for c in cve_ids if c}
    cve_hits = sorted(ids & set(watchlist.get("cves") or []))
    cve_hits += [c for c in match_cve_ids(text, watchlist.get("cves") or []) if c not in cve_hits]
    if cve_hits:
        matched["cves"] = cve_hits
    for cat in ("products", "actors", "topics"):
        hits = match_terms(text, watchlist.get(cat) or [])
        if hits:
            matched[cat] = hits
    return matched


def flatten_matches(matched: dict) -> list[str]:
    """表示用: ["products:Ivanti", "actors:Lazarus Group"] の形に潰す。"""
    out: list[str] = []
    for cat in CATEGORIES:
        for term in matched.get(cat) or []:
            out.append(f"{cat}:{term}")
    return out
