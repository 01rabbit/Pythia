#!/usr/bin/env python3
"""product-categories.json の CVE/製品→カテゴリ解決を一箇所に集約する共有モジュール。

従来 retrieve_similar_cases.py（部分一致）・build_kev_leadtime_stats.py・
build_zeroday_itw_priors.py（単語境界一致）に3つの実装が分散し、照合意味論が
乖離していた（同一CVEが別カテゴリになる）。本モジュールに一本化する。

照合方式は**エッジ条件付き単語境界一致**に統一する。単純部分一致は KEV/観測の
英語混じり文で偽陽性を生む（実測: sap→WhatsApp/Sapphire Sleet、unifi→Cisco
Unified、nsd→Firefox nsDocShell）。一方、単純な ASCII 単語境界（両端に
`(?![a-z0-9])`）は、日本語キーワードの直後に ASCII バージョン接尾辞が付くと
末尾境界が壊れて正当な一致を落とす（実測: rpgツクールMV → rpgツクール が不一致）。

そこで境界アサーションは**キーワードの当該エッジ文字が ASCII 英数のときだけ**適用する:
  - 先頭が ASCII 英数 → 左境界 `(?<![a-z0-9])` を付与（例: sap の前に文字が続く Sapphire を排除）
  - 末尾が ASCII 英数 → 右境界 `(?![a-z0-9])` を付与（例: sap の後に続く WhatsApp を排除）
  - エッジが非 ASCII（日本語等）→ その側の境界は付けない（rpgツクールMV に一致）
これで ASCII キーワードの偽陽性を排除しつつ、日本語キーワードは接尾辞連結でも一致する。

既知の限界: 末尾が ASCII 英字のキーワードは、直後に数字が連結するバージョン表記
（例: "FortiOS7.4"）に一致しない（空白区切り "FortiOS 7.4" は一致）。現行の観測・KEV
コーパスでは実害0だが、将来のために _matching_note に記録する。

resolver(text, cve=None) -> set[str]:
  (1) cve が cve_overrides にあればそのカテゴリのみ（最優先・従来どおり）。
  (2) なければ text にキーワードをエッジ条件付き境界一致で走査し、一致カテゴリの集合。
  (3) いずれもなければ空集合。大文字小文字は無視する。
"""

import json
import os
import re


def _compile_keyword(kw):
    """キーワードを、ASCII 英数エッジのみ境界を付けた正規表現へコンパイルする。"""
    low = kw.lower()
    left = r"(?<![a-z0-9])" if (low[:1].isascii() and low[:1].isalnum()) else ""
    right = r"(?![a-z0-9])" if (low[-1:].isascii() and low[-1:].isalnum()) else ""
    return re.compile(left + re.escape(low) + right)


def build_resolver(path):
    """product-categories.json を読み、(resolver, schema_version) を返す。

    resolver(text, cve=None) -> set[str]。"""
    data = {}
    if os.path.isfile(path):
        with open(path) as f:
            data = json.load(f)
    cve_overrides = {
        k: v for k, v in data.get("cve_overrides", {}).items() if not k.startswith("_")
    }
    compiled = [
        (_compile_keyword(kw), cat)
        for kw, cat in data.get("product_keyword_map", {}).items()
        if not kw.startswith("_")
    ]

    def resolver(text, cve=None):
        if cve and cve in cve_overrides:
            return {cve_overrides[cve]}
        hay = (text or "").lower()
        return {cat for pat, cat in compiled if pat.search(hay)}

    return resolver, data.get("_schema_version")
