#!/usr/bin/env python3
"""戦術予報の as-of 時刻を一箇所で扱う共有モジュール。

日付しか持たない旧 observation は、その日の終了後（翌日 00:00 JST）に初めて
利用可能とみなす。これは精度より先見性の証明を優先する保守的な互換規則である。
新規 event/evidence は available_at_utc を持ち、このフォールバックを使わない。
"""

import glob
import json
import os
from datetime import date, datetime, time, timedelta, timezone

UTC = timezone.utc
JST = timezone(timedelta(hours=9))


def parse_utc(value):
    """ISO 8601文字列をUTC aware datetimeへ変換する。"""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError(f"UTC時刻がない: {value!r}")
    if dt.tzinfo is None:
        raise ValueError(f"timezoneがない: {value!r}")
    return dt.astimezone(UTC)


def iso_utc(value):
    return parse_utc(value).isoformat().replace("+00:00", "Z")


def conservative_date_availability(value):
    """date-only入力は翌日00:00 JSTに利用可能になったとみなす。"""
    d = value if isinstance(value, date) else date.fromisoformat(value)
    return datetime.combine(d + timedelta(days=1), time.min, tzinfo=JST).astimezone(UTC)


def load_evidence_index(repo_root):
    """全Evidence Ledgerから evidence_id -> available datetime を返す。"""
    pattern = os.path.join(repo_root, "forecaster", "evidence", "manifests", "*", "*", "*.json")
    out = {}
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for ev in doc.get("evidence", []):
            eid = ev.get("evidence_id")
            raw = ev.get("available_at_utc") or ev.get("retrieved_at_utc")
            if not eid or not raw:
                continue
            try:
                out[eid] = parse_utc(raw)
            except ValueError:
                continue
    return out


def observation_available_at(observation, evidence_index=None):
    """observationが予報入力として利用可能になった最早ではなく確実な時刻を返す。

    複数evidenceを使うobservationは、すべて揃った時刻（最大値）を採る。
    evidence参照が一つでも解決できなければ日付フォールバックへ倒す。
    """
    evidence_index = evidence_index or {}
    direct = observation.get("available_at_utc") or observation.get("retrieved_at_utc")
    if direct:
        return parse_utc(direct)

    ids = observation.get("evidence_ids") or []
    if ids and all(eid in evidence_index for eid in ids):
        return max(evidence_index[eid] for eid in ids)

    fallback = observation.get("ingested_date") or observation.get("observed_date")
    if fallback:
        return conservative_date_availability(fallback)

    # 時刻を証明できない観測は永久にas-of入力へ入れない。
    return datetime.max.replace(tzinfo=UTC)


def available_by_cutoff(observation, cutoff, evidence_index=None):
    return observation_available_at(observation, evidence_index) <= parse_utc(cutoff)
