#!/usr/bin/env python3
"""Tactical artifacts の正規化ハッシュを一か所で定義する。"""

import hashlib
import json


def canonical_bytes(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_value(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def hash_without(mapping, *excluded):
    return sha256_value({k: v for k, v in mapping.items() if k not in excluded})

