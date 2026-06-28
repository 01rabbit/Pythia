"""CVE collector: NVD API v2.0 + VulDB RSS.

Collects CVEs, merges by CVE ID, notifies Slack of IMPORTANT CVEs only
(deduplicated via state file), and ALWAYS writes standardized raw JSON to
``data/raw/``.

Network calls are referenced at module level (``requests.get``,
``requests.post``, ``feedparser.parse``) so tests can monkeypatch them.
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import feedparser
import requests

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

SCHEMA_VERSION = "1.0"
SOURCE_TYPE = "cve"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VULDB_RSS_URLS = (
    "https://vuldb.com/?rss.recent",
    "https://vuldb.com/?rss.updates",
)

DATA_RAW_DIR = Path("data") / "raw"
CVE_SEEN_FILE = Path("cve_seen.json")
CVE_META_FILE = Path("cve_meta.json")

NVD_RETRY_STATUS = {429, 500, 502, 503, 504}
NVD_MAX_RETRIES = 3
NVD_BACKOFF_SECONDS = 1.0  # kept small; tests monkeypatch time.sleep anyway

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

PRIORITY_VENDORS = (
    "fortinet", "palo alto", "cisco", "ivanti", "juniper", "sonicwall",
    "vmware", "citrix", "kubernetes", "docker", "windows", "linux kernel",
    "macos", "ios", "chrome", "firefox", "safari", "edge", "gitlab",
    "github enterprise", "jenkins", "atlassian", "apache", "redis",
    "postgresql", "nginx", "wordpress",
)

# vuln type -> list of case-insensitive keyword substrings
VULN_TYPE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "RCE": ("remote code execution", "arbitrary code"),
    "AUTH_BYPASS": ("authentication bypass", "auth bypass"),
    "PRIV_ESC": ("privilege escalation", "elevation of privilege"),
    "SANDBOX_ESCAPE": ("sandbox escape",),
    "DOS": ("denial of service", "dos"),
    "INFO_DISCLOSURE": (
        "information disclosure", "info leak", "sensitive information",
    ),
}

SEVERE_VULN_TYPES = {"RCE", "AUTH_BYPASS", "PRIV_ESC", "SANDBOX_ESCAPE"}


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso8601(dt: datetime) -> str:
    """Return an ISO8601 UTC string with a trailing ``Z``."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_to_utc_iso(value: str | None) -> str | None:
    """Best-effort parse of an arbitrary timestamp string to ISO8601 UTC."""
    if not value:
        return None
    raw = value.strip()
    candidate = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(candidate)
    except (ValueError, TypeError):
        # Fall back to a few common formats.
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%a, %d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S %Z",
        ):
            try:
                dt = datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return iso8601(dt)


def nvd_timestamp(dt: datetime) -> str:
    """NVD ISO format e.g. ``2024-01-01T00:00:00.000``."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


# --------------------------------------------------------------------------- #
# State persistence
# --------------------------------------------------------------------------- #

def load_json_file(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default
    except (OSError, json.JSONDecodeError):
        return default


def write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


def load_seen() -> set[str]:
    data = load_json_file(CVE_SEEN_FILE, [])
    if isinstance(data, dict):
        data = data.get("seen", [])
    if not isinstance(data, list):
        return set()
    return {str(x) for x in data}


def save_seen(seen: set[str]) -> None:
    write_json_file(CVE_SEEN_FILE, sorted(seen))


def load_meta() -> dict[str, Any]:
    data = load_json_file(CVE_META_FILE, {})
    return data if isinstance(data, dict) else {}


def save_meta(meta: dict[str, Any]) -> None:
    write_json_file(CVE_META_FILE, meta)


# --------------------------------------------------------------------------- #
# CVSS / severity
# --------------------------------------------------------------------------- #

def severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return None


def extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    """Return (max base score, severity) across all CVSS metric versions."""
    best_score: float | None = None
    best_severity: str | None = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30",
                "cvssMetricV2"):
        for entry in metrics.get(key, []) or []:
            cvss_data = entry.get("cvssData", {}) if isinstance(entry, dict) else {}
            score = cvss_data.get("baseScore")
            if score is None:
                continue
            try:
                score_f = float(score)
            except (TypeError, ValueError):
                continue
            if best_score is None or score_f > best_score:
                best_score = score_f
                # Prefer an explicit severity from the highest-scoring metric.
                sev = (
                    cvss_data.get("baseSeverity")
                    or entry.get("baseSeverity")
                )
                best_severity = str(sev).upper() if sev else None
    if best_score is not None and not best_severity:
        best_severity = severity_from_score(best_score)
    return best_score, best_severity


# --------------------------------------------------------------------------- #
# CPE / vendor-product
# --------------------------------------------------------------------------- #

def extract_vendor_product(configurations: list[dict[str, Any]]) -> str:
    for config in configurations or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                # cpe:2.3:a:vendor:product:...  -> idx 3 vendor, idx 4 product
                if len(parts) > 4 and parts[0].lower() == "cpe":
                    vendor = parts[3]
                    product = parts[4]
                    if vendor and vendor != "*":
                        product = "" if product in ("*", "-") else product
                        return f"{vendor} {product}".strip()
    return ""


# --------------------------------------------------------------------------- #
# Vuln type detection
# --------------------------------------------------------------------------- #

def detect_vuln_types(text: str) -> list[str]:
    lowered = (text or "").lower()
    found: list[str] = []
    for vuln_type, keywords in VULN_TYPE_KEYWORDS.items():
        for kw in keywords:
            if kw == "dos":
                # avoid matching substrings inside other words
                if re.search(r"\bdos\b", lowered):
                    found.append(vuln_type)
                    break
            elif kw in lowered:
                found.append(vuln_type)
                break
    return found


def is_priority(vendor_product: str, text: str) -> bool:
    haystack = f"{vendor_product} {text}".lower()
    return any(v in haystack for v in PRIORITY_VENDORS)


# --------------------------------------------------------------------------- #
# NVD
# --------------------------------------------------------------------------- #

def _empty_record(cve_id: str) -> dict[str, Any]:
    cve_id = cve_id.upper()
    return {
        "id": cve_id,
        "cve_id": cve_id,
        "title": cve_id,
        "description": None,
        "url": None,
        "published_at": None,
        "modified_at": None,
        "cvss_score": None,
        "severity": None,
        "references": [],
        "affected": [],
        "vendor_product": "",
        "tags": [],
        "vuln_types": [],
        "report_reason": None,
        "raw": {},
        # internal bookkeeping (stripped before output)
        "_sources": set(),
    }


def parse_nvd_item(vuln: dict[str, Any]) -> dict[str, Any]:
    """Build a CVE record from a single NVD ``vulnerabilities[]`` entry."""
    cve = vuln.get("cve", {}) if isinstance(vuln, dict) else {}
    cve_id = str(cve.get("id", "")).upper()
    record = _empty_record(cve_id or "UNKNOWN")

    descriptions = cve.get("descriptions", []) or []
    description = None
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value")
            break
    if description is None and descriptions:
        description = descriptions[0].get("value")
    record["description"] = description

    references = []
    for ref in cve.get("references", []) or []:
        url = ref.get("url")
        if url:
            references.append(url)
    record["references"] = references
    record["url"] = references[0] if references else None

    record["published_at"] = parse_to_utc_iso(cve.get("published"))
    record["modified_at"] = parse_to_utc_iso(cve.get("lastModified"))

    configurations = cve.get("configurations", []) or []
    vendor_product = extract_vendor_product(configurations)
    record["vendor_product"] = vendor_product
    if vendor_product:
        record["affected"] = [vendor_product]

    score, severity = extract_cvss(cve.get("metrics", {}) or {})
    record["cvss_score"] = score
    record["severity"] = severity

    title = vendor_product or cve_id
    record["title"] = f"{cve_id}: {title}" if vendor_product else cve_id

    text = f"{record['title']} {description or ''}"
    record["vuln_types"] = detect_vuln_types(text)

    record["raw"] = cve
    record["_sources"].add("nvd")
    return record


def fetch_nvd(api_key: str | None) -> list[dict[str, Any]]:
    """Fetch CVEs modified in the last 24h. Returns [] on failure."""
    end = utcnow()
    start = end - timedelta(hours=24)
    params = {
        "lastModStartDate": nvd_timestamp(start),
        "lastModEndDate": nvd_timestamp(end),
    }
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    last_error: Exception | None = None
    for attempt in range(NVD_MAX_RETRIES):
        try:
            resp = requests.get(
                NVD_API_URL, params=params, headers=headers, timeout=30,
            )
        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError) as exc:
            last_error = exc
            time.sleep(NVD_BACKOFF_SECONDS * (attempt + 1))
            continue
        except requests.exceptions.RequestException as exc:
            print(f"[cve_watcher] NVD request error: {exc}")
            return []

        status = getattr(resp, "status_code", 200)
        if status in NVD_RETRY_STATUS:
            last_error = RuntimeError(f"NVD HTTP {status}")
            time.sleep(NVD_BACKOFF_SECONDS * (attempt + 1))
            continue
        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"[cve_watcher] NVD JSON parse error: {exc}")
            return []

        records = []
        for vuln in data.get("vulnerabilities", []) or []:
            try:
                records.append(parse_nvd_item(vuln))
            except Exception as exc:  # noqa: BLE001 - never abort the run
                print(f"[cve_watcher] failed to parse NVD item: {exc}")
        return records

    print(f"[cve_watcher] NVD failed after retries: {last_error}")
    return []


# --------------------------------------------------------------------------- #
# VulDB RSS
# --------------------------------------------------------------------------- #

def _vuldb_signals(text: str) -> tuple[list[str], list[str]]:
    """Return (tags, vuln_signal_tags) detected from a VulDB entry text."""
    lowered = (text or "").lower()
    tags: list[str] = []
    if "proof of concept" in lowered or re.search(r"\bpoc\b", lowered):
        tags.append("poc")
    if "zero-day" in lowered or "zero day" in lowered or "0-day" in lowered:
        tags.append("zero_day")
    if ("actively exploited" in lowered
            or "exploited in the wild" in lowered):
        tags.append("actively_exploited")
    if re.search(r"\bkev\b", lowered):
        tags.append("kev")
    return tags, []


def parse_vuldb_feed(parsed: Any, source_url: str) -> dict[str, dict[str, Any]]:
    """Parse a feedparser result into {cve_id: {tags, references, ...}}."""
    out: dict[str, dict[str, Any]] = {}
    entries = getattr(parsed, "entries", None)
    if entries is None and isinstance(parsed, dict):
        entries = parsed.get("entries", [])
    for entry in entries or []:
        title = _get(entry, "title", "")
        summary = _get(entry, "summary", "") or _get(entry, "description", "")
        link = _get(entry, "link", "") or source_url
        text = f"{title} {summary}"
        ids = {m.upper() for m in CVE_REGEX.findall(text)}
        if not ids:
            continue
        tags, _ = _vuldb_signals(text)
        for cve_id in ids:
            bucket = out.setdefault(
                cve_id,
                {"tags": set(), "references": [], "title": title,
                 "description": summary or None},
            )
            bucket["tags"].update(tags)
            if link and link not in bucket["references"]:
                bucket["references"].append(link)
    return out


def _get(entry: Any, key: str, default: Any = None) -> Any:
    if isinstance(entry, dict):
        return entry.get(key, default)
    return getattr(entry, key, default)


def fetch_vuldb() -> dict[str, dict[str, Any]]:
    """Fetch and merge VulDB recent + updates feeds. Returns {} on failure."""
    merged: dict[str, dict[str, Any]] = {}
    for url in VULDB_RSS_URLS:
        try:
            parsed = feedparser.parse(url)
        except Exception as exc:  # noqa: BLE001 - guard the whole source
            print(f"[cve_watcher] VulDB fetch error ({url}): {exc}")
            continue
        try:
            feed_data = parse_vuldb_feed(parsed, url)
        except Exception as exc:  # noqa: BLE001
            print(f"[cve_watcher] VulDB parse error ({url}): {exc}")
            continue
        for cve_id, info in feed_data.items():
            bucket = merged.setdefault(
                cve_id,
                {"tags": set(), "references": [], "title": info.get("title"),
                 "description": info.get("description")},
            )
            bucket["tags"].update(info["tags"])
            for ref in info["references"]:
                if ref not in bucket["references"]:
                    bucket["references"].append(ref)
            if not bucket.get("title"):
                bucket["title"] = info.get("title")
            if not bucket.get("description"):
                bucket["description"] = info.get("description")
    return merged


# --------------------------------------------------------------------------- #
# Merge
# --------------------------------------------------------------------------- #

def merge_records(
    nvd_records: list[dict[str, Any]],
    vuldb_data: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for rec in nvd_records:
        by_id[rec["cve_id"]] = rec

    for cve_id, info in vuldb_data.items():
        record = by_id.get(cve_id)
        if record is None:
            record = _empty_record(cve_id)
            if info.get("title"):
                record["title"] = f"{cve_id}: {info['title']}"
            record["description"] = info.get("description")
            by_id[cve_id] = record
        record["_sources"].add("vuldb")
        for tag in sorted(info["tags"]):
            if tag not in record["tags"]:
                record["tags"].append(tag)
        for ref in info["references"]:
            if ref not in record["references"]:
                record["references"].append(ref)
        if not record["url"] and info["references"]:
            record["url"] = info["references"][0]
        # Recompute vuln types including any VulDB-provided description.
        text = f"{record['title']} {record.get('description') or ''}"
        record["vuln_types"] = detect_vuln_types(text)

    return list(by_id.values())


# --------------------------------------------------------------------------- #
# Importance judgment
# --------------------------------------------------------------------------- #

def judge_reportable(record: dict[str, Any]) -> str | None:
    """Return a report_reason string if reportable, else None."""
    score = record.get("cvss_score")
    tags = set(record.get("tags", []))
    vuln_types = set(record.get("vuln_types", []))
    vendor_product = record.get("vendor_product", "")
    text = record.get("description") or ""
    priority = is_priority(vendor_product, f"{record.get('title','')} {text}")
    multi_source = len(record.get("_sources", set())) >= 2

    kev = "kev" in tags or "actively_exploited" in tags
    zero_day = "zero_day" in tags
    poc = "poc" in tags

    # --- Inclusion rules -------------------------------------------------- #
    reasons: list[str] = []
    if kev:
        reasons.append("KEV / actively exploited")
    if zero_day:
        reasons.append("zero-day")
    if poc:
        reasons.append("PoC published")
    if score is not None and score >= 9.0 and priority:
        reasons.append("CVSS>=9.0 on priority product")
    if (score is not None and score >= 7.5
            and vuln_types & SEVERE_VULN_TYPES):
        kinds = ",".join(sorted(vuln_types & SEVERE_VULN_TYPES))
        reasons.append(f"CVSS>=7.5 with {kinds}")
    if score is not None and score >= 7.5 and multi_source:
        reasons.append("CVSS>=7.5 observed in NVD+VulDB")

    if not reasons:
        return None

    # --- Exclusion rules (override only soft, score-based inclusions) ----- #
    strong_signal = kev or zero_day or poc
    if not strong_signal:
        if score is None or score < 7.0:
            return None
        only_info = vuln_types == {"INFO_DISCLOSURE"}
        if only_info and score < 8.0:
            return None
        only_dos = vuln_types == {"DOS"}
        if only_dos and score < 8.0:
            return None
        if not priority and score < 9.0:
            return None

    return "; ".join(reasons)


def finalize_records(records: list[dict[str, Any]]) -> None:
    for rec in records:
        rec["report_reason"] = judge_reportable(rec)


# --------------------------------------------------------------------------- #
# Slack
# --------------------------------------------------------------------------- #

def _strip_internal(record: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in record.items() if not k.startswith("_")}
    return out


def build_digest(new_items: list[dict[str, Any]]) -> str:
    lines = ["*CVE Alert Digest (NVD API + VulDB RSS)*", ""]
    # single group for simplicity; spec shows "Group 1"
    lines.append("*Group 1:*")
    for rec in new_items:
        score = rec.get("cvss_score")
        score_str = f"CVSS {score}" if score is not None else "CVSS N/A"
        vp = rec.get("vendor_product") or "unknown product"
        reason = rec.get("report_reason") or ""
        lines.append(
            f"- `{rec['cve_id']}` | {score_str} | {vp} | {reason}"
        )
        refs = rec.get("references", [])[:3]
        if refs:
            lines.append(f"  sources: {', '.join(refs)}")
    return "\n".join(lines)


def post_slack(webhook_url: str, text: str) -> bool:
    try:
        resp = requests.post(webhook_url, json={"text": text}, timeout=15)
    except requests.exceptions.RequestException as exc:
        print(f"[cve_watcher] Slack post failed: {exc}")
        return False
    status = getattr(resp, "status_code", 200)
    if status >= 300:
        print(f"[cve_watcher] Slack returned HTTP {status}")
        return False
    return True


# --------------------------------------------------------------------------- #
# Raw output
# --------------------------------------------------------------------------- #

def write_raw_output(
    run_id: str,
    generated_at: str,
    items: list[dict[str, Any]],
    new_items: list[dict[str, Any]],
) -> tuple[Path, Path]:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": generated_at,
        "source_type": SOURCE_TYPE,
        "items": [_strip_internal(r) for r in items],
        "new_items": [_strip_internal(r) for r in new_items],
    }
    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
    latest = DATA_RAW_DIR / "cves-latest.json"
    dated = DATA_RAW_DIR / f"cves-{generated_at[:10]}.json"
    write_json_file(latest, payload)
    write_json_file(dated, payload)
    return latest, dated


# --------------------------------------------------------------------------- #
# Heartbeat
# --------------------------------------------------------------------------- #

def maybe_heartbeat(
    webhook_url: str | None,
    meta: dict[str, Any],
    now: datetime,
    candidates: int,
    matched_reportable: int,
    sent: int,
) -> None:
    if os.environ.get("HEARTBEAT_NOTIFY", "").lower() not in ("1", "true", "yes"):
        return
    try:
        interval_min = int(os.environ.get("HEARTBEAT_INTERVAL_MINUTES", "0"))
    except ValueError:
        interval_min = 0

    notify_on_zero = os.environ.get("NOTIFY_ON_ZERO", "").lower() in (
        "1", "true", "yes",
    )

    last_str = meta.get("last_heartbeat_at")
    due = True
    if last_str and interval_min > 0:
        last_iso = parse_to_utc_iso(last_str)
        if last_iso:
            last_dt = datetime.fromisoformat(last_iso.replace("Z", "+00:00"))
            due = (now - last_dt) >= timedelta(minutes=interval_min)

    if matched_reportable == 0 and not notify_on_zero:
        # Still update interval bookkeeping, but skip sending.
        if due:
            meta["last_heartbeat_at"] = iso8601(now)
        return

    if not due:
        return

    text = (
        "*[CVE Watcher]* heartbeat\n"
        f"checked_at: {iso8601(now)}\n"
        f"candidates: {candidates}\n"
        f"matched_reportable: {matched_reportable}\n"
        f"sent: {sent}\n"
        "reason: periodic_heartbeat"
    )
    if webhook_url:
        post_slack(webhook_url, text)
    meta["last_heartbeat_at"] = iso8601(now)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> None:
    now = utcnow()
    run_id = os.environ.get("GITHUB_RUN_ID") or iso8601(now)
    generated_at = iso8601(now)

    webhook_url = os.environ.get("SLACK_WEBHOOK_URL") or None
    api_key = os.environ.get("NVD_API_KEY") or None

    seen = load_seen()
    meta = load_meta()

    nvd_records = fetch_nvd(api_key)
    vuldb_data = fetch_vuldb()

    if not nvd_records and not vuldb_data:
        print("[cve_watcher] no data from NVD or VulDB this run")

    records = merge_records(nvd_records, vuldb_data)
    finalize_records(records)

    items = records
    reportable = [r for r in records if r.get("report_reason")]
    new_items = [r for r in reportable if r["cve_id"] not in seen]

    sent = 0
    if new_items and webhook_url:
        digest = build_digest(new_items)
        if post_slack(webhook_url, digest):
            sent = len(new_items)
    # Mark as seen regardless of webhook presence to stay idempotent.
    for rec in new_items:
        seen.add(rec["cve_id"])

    write_raw_output(run_id, generated_at, items, new_items)

    maybe_heartbeat(
        webhook_url, meta, now,
        candidates=len(records),
        matched_reportable=len(reportable),
        sent=sent,
    )

    save_seen(seen)
    save_meta(meta)

    print(
        f"[cve_watcher] candidates={len(records)} "
        f"reportable={len(reportable)} new={len(new_items)} sent={sent}"
    )


if __name__ == "__main__":
    main()
