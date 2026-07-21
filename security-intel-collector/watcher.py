from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import feedparser
import requests

# --- Constants -------------------------------------------------------------

SCHEMA_VERSION = "1.0"

FEEDS_FILE = "feeds.json"
SEEN_FILE = "seen.json"
META_FILE = "rss_meta.json"
RAW_DIR = os.path.join("data", "raw")

# Query parameters stripped during URL normalization.
TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "gclid",
    "fbclid",
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

FIRST_RUN_SEED_COUNT = 3


# --- Generic helpers -------------------------------------------------------


def utc_now_iso() -> str:
    """Current UTC time as ISO8601 string."""
    return datetime.now(timezone.utc).isoformat()


def utc_today_str() -> str:
    """Current UTC date as YYYY-MM-DD."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def env_bool(name: str) -> bool:
    """Interpret an environment variable as a boolean flag."""
    value = os.environ.get(name)
    if value is None:
        return False
    return value.strip().lower() in {"true", "1", "yes"}


def run_id() -> str:
    """Stable identifier for this run."""
    return os.environ.get("GITHUB_RUN_ID") or utc_now_iso()


def load_json(path: str, default: Any) -> Any:
    """Load JSON from path; return default on any failure or absence."""
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"[warn] failed to read {path}: {exc}")
        return default


def dump_json(path: str, data: Any) -> None:
    """Write JSON to path, creating parent directories as needed."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)


# --- URL handling ----------------------------------------------------------


def normalize_url(url: str) -> str:
    """Normalize a URL per the project rules.

    - lowercase scheme and host
    - strip a single trailing slash (keep root "/")
    - remove known tracking query params (stable order otherwise)
    - drop the fragment
    """
    if not url:
        return ""
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = parts.hostname.lower() if parts.hostname else ""

    # Reconstruct netloc preserving userinfo and port if present.
    netloc = host
    if parts.port is not None:
        netloc = f"{host}:{parts.port}"
    if parts.username:
        userinfo = parts.username
        if parts.password:
            userinfo = f"{userinfo}:{parts.password}"
        netloc = f"{userinfo}@{netloc}"

    path = parts.path
    if path and path != "/" and path.endswith("/"):
        path = path[:-1]

    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k not in TRACKING_PARAMS]
    query = urlencode(kept)

    return urlunsplit((scheme, netloc, path, query, ""))


def url_id(normalized_url: str) -> str:
    """Deterministic 16-char id derived from a normalized URL."""
    digest = hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()
    return digest[:16]


# --- Feed / entry parsing --------------------------------------------------


def load_feeds() -> List[Dict[str, Any]]:
    """Load feeds.json; create a sensible default file if missing."""
    if not os.path.exists(FEEDS_FILE):
        default: List[Dict[str, Any]] = []
        try:
            dump_json(FEEDS_FILE, default)
        except OSError as exc:
            print(f"[warn] could not create default {FEEDS_FILE}: {exc}")
        return default

    data = load_json(FEEDS_FILE, [])
    if not isinstance(data, list):
        print(f"[warn] {FEEDS_FILE} is not a list; ignoring")
        return []
    return [f for f in data if isinstance(f, dict)]


def entry_get(entry: Any, key: str, default: Any = None) -> Any:
    """Read a field from a feedparser entry (dict-like or attribute-like)."""
    try:
        getter = getattr(entry, "get", None)
        if callable(getter):
            return entry.get(key, default)
    except Exception:  # pragma: no cover - defensive
        pass
    return getattr(entry, key, default)


def entry_published_iso(entry: Any) -> Optional[str]:
    """Best-effort UTC ISO8601 published timestamp for an entry."""
    parsed = entry_get(entry, "published_parsed") or entry_get(entry, "updated_parsed")
    if parsed is not None:
        try:
            # time.struct_time in UTC as produced by feedparser.
            dt = datetime(*parsed[:6], tzinfo=timezone.utc)
            return dt.isoformat()
        except (TypeError, ValueError):
            pass
    raw = entry_get(entry, "published") or entry_get(entry, "updated")
    return raw if isinstance(raw, str) and raw else None


def entry_key(entry: Any) -> str:
    """Stable dedup key for an entry: prefer id, else normalized link."""
    eid = entry_get(entry, "id")
    if isinstance(eid, str) and eid:
        return eid
    return normalize_url(entry_get(entry, "link", "") or "")


def build_news_item(entry: Any, feed_name: str, tags: List[str]) -> Dict[str, Any]:
    """Convert a feed entry into a standardized news item."""
    raw_url = entry_get(entry, "link", "") or ""
    normalized = normalize_url(raw_url)
    title = entry_get(entry, "title")
    summary = entry_get(entry, "summary")
    return {
        "id": url_id(normalized),
        "title": title if isinstance(title, str) else None,
        "url": normalized,
        "source": feed_name,
        "published_at": entry_published_iso(entry),
        "fetched_at": utc_now_iso(),
        "tags": list(tags),
        "summary": summary if isinstance(summary, str) else None,
        "raw": {
            "id": entry_get(entry, "id"),
            "link": raw_url,
            "title": title if isinstance(title, str) else None,
            "summary": summary if isinstance(summary, str) else None,
            "published": entry_get(entry, "published"),
        },
    }


def extract_cve_items(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract simple CVE items from a news item's title + summary."""
    text = " ".join(
        str(part) for part in (item.get("title"), item.get("summary")) if part
    )
    found: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    for match in CVE_RE.findall(text):
        cve_id = match.upper()
        if cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)
        url = item.get("url", "")
        found.append(
            {
                "id": cve_id,
                "cve_id": cve_id,
                "title": item.get("title"),
                "description": None,
                "url": url,
                "published_at": item.get("published_at"),
                "modified_at": None,
                "cvss_score": None,
                "severity": None,
                "references": [url],
                "affected": [],
                "vendor_product": "",
                "tags": [],
                "vuln_types": [],
                "report_reason": "mentioned_in_rss",
                "raw": {"source_article": url},
            }
        )
    return found


# --- Slack notifications ---------------------------------------------------


def slack_post(webhook: Optional[str], text: str) -> bool:
    """Post a message to Slack. Returns True on success.

    Never logs the webhook URL.
    """
    if not webhook:
        print("[info] no Slack webhook configured; skipping notification")
        return False
    try:
        response = requests.post(webhook, json={"text": text}, timeout=15)
        status = getattr(response, "status_code", None)
        if status is not None and int(status) >= 400:
            print(f"[warn] Slack returned status {status}")
            return False
        return True
    except Exception as exc:  # noqa: BLE001 - network errors are varied
        print(f"[warn] Slack post failed: {exc}")
        return False


def format_news_text(item: Dict[str, Any]) -> str:
    """Render an RSS article notification body."""
    return (
        "@channel\n"
        f"*[{item.get('source')}]* 新着記事\n"
        f"*Title:* {item.get('title')}\n"
        f"*Published:* {item.get('published_at')}\n"
        f"*Summary:* {item.get('summary')}\n"
        f"*URL:* {item.get('url')}"
    )


def format_heartbeat_text(checked_at: str, candidates: int, sent: int) -> str:
    """Render a heartbeat notification body."""
    return (
        "*[RSS Watcher]* heartbeat\n"
        f"checked_at: {checked_at}\n"
        f"candidates: {candidates}\n"
        f"sent: {sent}\n"
        "reason: periodic_heartbeat"
    )


# --- Raw JSON containers ---------------------------------------------------


def build_raw(
    source_type: str,
    items: List[Dict[str, Any]],
    new_items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Assemble a standardized raw-JSON container."""
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id(),
        "generated_at": utc_now_iso(),
        "source_type": source_type,
        "items": items,
        "new_items": new_items,
    }


def write_raw(prefix: str, raw: Dict[str, Any]) -> None:
    """Write both the latest and dated raw files for a prefix."""
    dump_json(os.path.join(RAW_DIR, f"{prefix}-latest.json"), raw)
    dump_json(os.path.join(RAW_DIR, f"{prefix}-{utc_today_str()}.json"), raw)


# --- Seen state ------------------------------------------------------------


def load_seen() -> Dict[str, List[str]]:
    """Load per-feed seen keys, tolerating absent/garbage files."""
    data = load_json(SEEN_FILE, {})
    if not isinstance(data, dict):
        return {}
    result: Dict[str, List[str]] = {}
    for key, value in data.items():
        if isinstance(value, list):
            result[str(key)] = [str(v) for v in value]
    return result


# --- Core processing -------------------------------------------------------


def process_feed(
    feed: Dict[str, Any],
    seen: Dict[str, List[str]],
    webhook: Optional[str],
    force_notify: bool,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
    """Process a single feed.

    Returns (all_items, new_items, notified_count). Raises nothing that the
    caller cannot recover from; callers still guard with try/except so one
    feed's failure cannot affect others.
    """
    name = feed.get("name") or "Unnamed Feed"
    url = feed.get("url")
    tags = feed.get("tags") if isinstance(feed.get("tags"), list) else []

    if not url:
        print(f"[warn] feed '{name}' has no url; skipping")
        return [], [], 0

    parsed = feedparser.parse(url)
    entries = list(getattr(parsed, "entries", []) or [])

    # Optional per-feed cap for very large feeds (e.g. JVN iPedia returns
    # ~500 entries per fetch); keeps data/raw/ and notifications bounded.
    max_items = feed.get("max_items")
    if isinstance(max_items, int) and max_items > 0:
        entries = entries[:max_items]

    feed_key = url
    is_first_run = feed_key not in seen
    seen_keys = set(seen.get(feed_key, []))

    all_items: List[Dict[str, Any]] = []
    new_items: List[Dict[str, Any]] = []
    notified = 0

    # Build items + collect keys (preserve feed order).
    entry_records: List[Tuple[str, Dict[str, Any]]] = []
    for entry in entries:
        key = entry_key(entry)
        item = build_news_item(entry, name, tags)
        all_items.append(item)
        entry_records.append((key, item))

    # Optional per-feed first-run seed size; large feeds should seed all
    # fetched entries so the second run does not flood notifications.
    seed_count = feed.get("seed_count")
    if not (isinstance(seed_count, int) and seed_count > 0):
        seed_count = FIRST_RUN_SEED_COUNT

    if is_first_run:
        # Seed the latest N entries as seen; do not notify them.
        seed_keys = [key for key, _ in entry_records[:seed_count]]
        seen[feed_key] = list(dict.fromkeys(seed_keys))
        print(f"[info] first run for '{name}': seeded {len(seed_keys)} entries")

        if force_notify and entry_records:
            key, item = entry_records[0]
            if slack_post(webhook, format_news_text(item)):
                notified += 1
            new_items.append(item)
            if key not in seen[feed_key]:
                seen[feed_key].append(key)
        return all_items, new_items, notified

    # Subsequent run.
    if force_notify and entry_records:
        forced_key, forced_item = entry_records[0]
    else:
        forced_key, forced_item = None, None

    for key, item in entry_records:
        is_new = key not in seen_keys
        is_forced = force_notify and key == forced_key
        if is_new or is_forced:
            if is_new:
                new_items.append(item)
            if slack_post(webhook, format_news_text(item)):
                notified += 1
            seen_keys.add(key)

    seen[feed_key] = list(seen.get(feed_key, [])) + [
        k for k in seen_keys if k not in set(seen.get(feed_key, []))
    ]
    # Keep ordering stable and deduplicated.
    seen[feed_key] = list(dict.fromkeys(seen[feed_key]))
    return all_items, new_items, notified


def maybe_heartbeat(
    meta: Dict[str, Any],
    webhook: Optional[str],
    candidates: int,
    sent: int,
) -> None:
    """Send a periodic heartbeat if enabled and the interval has elapsed."""
    if not env_bool("HEARTBEAT_NOTIFY"):
        return

    notify_on_zero = env_bool("NOTIFY_ON_ZERO")
    if sent == 0 and not notify_on_zero:
        return

    try:
        interval_min = int(os.environ.get("HEARTBEAT_INTERVAL_MINUTES", "0"))
    except ValueError:
        interval_min = 0

    now = datetime.now(timezone.utc)
    last_raw = meta.get("last_heartbeat_at")
    elapsed_ok = True
    if last_raw and interval_min > 0:
        try:
            last_dt = datetime.fromisoformat(str(last_raw))
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
            elapsed_min = (now - last_dt).total_seconds() / 60.0
            elapsed_ok = elapsed_min >= interval_min
        except ValueError:
            elapsed_ok = True

    if not elapsed_ok:
        return

    checked_at = now.isoformat()
    if slack_post(webhook, format_heartbeat_text(checked_at, candidates, sent)):
        meta["last_heartbeat_at"] = checked_at


def main() -> None:
    """Entry point: collect feeds, notify, and persist raw outputs/state."""
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    force_notify = env_bool("FORCE_NOTIFY")

    feeds = load_feeds()
    seen = load_seen()
    meta = load_json(META_FILE, {})
    if not isinstance(meta, dict):
        meta = {}

    all_news: List[Dict[str, Any]] = []
    new_news: List[Dict[str, Any]] = []
    total_notified = 0

    for feed in feeds:
        if not feed.get("enabled", False):
            print(f"[info] feed '{feed.get('name', 'Unnamed Feed')}' disabled; skipping")
            continue
        name = feed.get("name") or "Unnamed Feed"
        try:
            items, new_items, notified = process_feed(feed, seen, webhook, force_notify)
            all_news.extend(items)
            new_news.extend(new_items)
            total_notified += notified
        except Exception as exc:  # noqa: BLE001 - isolate per-feed failures
            print(f"[error] feed '{name}' failed: {exc}")
            continue

    # CVE extraction.
    all_cves: List[Dict[str, Any]] = []
    new_cves: List[Dict[str, Any]] = []
    for item in all_news:
        all_cves.extend(extract_cve_items(item))
    for item in new_news:
        new_cves.extend(extract_cve_items(item))

    # Always write raw outputs.
    write_raw("news", build_raw("security_news", all_news, new_news))
    write_raw("cves", build_raw("cve", all_cves, new_cves))

    # Heartbeat (optional).
    maybe_heartbeat(meta, webhook, candidates=len(all_news), sent=len(new_news))

    # End-of-run summary notification; failure must not fail the run.
    try:
        summary = (
            "*[RSS Watcher]* run summary\n"
            f"run_id: {run_id()}\n"
            f"feeds_items: {len(all_news)}\n"
            f"new_items: {len(new_news)}\n"
            f"notified: {total_notified}\n"
            f"cves_found: {len(all_cves)}"
        )
        slack_post(webhook, summary)
    except Exception as exc:  # noqa: BLE001 - summary must never break the run
        print(f"[warn] summary notification failed: {exc}")

    # Persist state.
    try:
        dump_json(SEEN_FILE, seen)
        dump_json(META_FILE, meta)
    except OSError as exc:
        print(f"[warn] failed to persist state: {exc}")

    print(
        f"[done] items={len(all_news)} new={len(new_news)} "
        f"notified={total_notified} cves={len(all_cves)}"
    )


if __name__ == "__main__":
    main()
    sys.exit(0)
