from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import watcher  # noqa: E402


# --- Fakes -----------------------------------------------------------------


class FakeEntry:
    """Dict-like feed entry supporting .get() and attribute access."""

    def __init__(self, **fields: Any) -> None:
        self._fields = fields

    def get(self, key: str, default: Any = None) -> Any:
        return self._fields.get(key, default)

    def __getattr__(self, key: str) -> Any:  # pragma: no cover - fallback path
        try:
            return self._fields[key]
        except KeyError as exc:
            raise AttributeError(key) from exc


class FakeParsed:
    def __init__(self, entries: List[FakeEntry]) -> None:
        self.entries = entries


def make_entry(idx: int, url: Optional[str] = None, **extra: Any) -> FakeEntry:
    fields: Dict[str, Any] = {
        "id": f"entry-{idx}",
        "link": url or f"https://example.com/post-{idx}",
        "title": f"Title {idx}",
        "summary": f"Summary {idx}",
        "published": "Mon, 01 Jun 2026 00:00:00 GMT",
    }
    fields.update(extra)
    return FakeEntry(**fields)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/xyz")
    # Clear flags that could leak from the host environment.
    for var in (
        "FORCE_NOTIFY",
        "HEARTBEAT_NOTIFY",
        "NOTIFY_ON_ZERO",
        "HEARTBEAT_INTERVAL_MINUTES",
        "GITHUB_RUN_ID",
    ):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def write_feeds(feeds: List[Dict[str, Any]]) -> None:
    Path("feeds.json").write_text(json.dumps(feeds), encoding="utf-8")


def capture_slack(monkeypatch: pytest.MonkeyPatch) -> List[Dict[str, Any]]:
    posts: List[Dict[str, Any]] = []

    def fake_post(url: str, json: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Any:
        posts.append({"url": url, "json": json})

        class Resp:
            status_code = 200

        return Resp()

    monkeypatch.setattr(watcher.requests, "post", fake_post)
    return posts


def set_parse(monkeypatch: pytest.MonkeyPatch, mapping: Dict[str, FakeParsed]) -> None:
    def fake_parse(url: str, *args: Any, **kwargs: Any) -> FakeParsed:
        return mapping.get(url, FakeParsed([]))

    monkeypatch.setattr(watcher.feedparser, "parse", fake_parse)


# --- Tests -----------------------------------------------------------------


def test_disabled_feed_ignored(env: pytest.MonkeyPatch) -> None:
    posts = capture_slack(env)
    set_parse(env, {"https://a.test/feed": FakeParsed([make_entry(1)])})
    write_feeds([{"name": "A", "url": "https://a.test/feed", "enabled": False, "tags": []}])

    watcher.main()

    seen = json.loads(Path("seen.json").read_text("utf-8"))
    assert "https://a.test/feed" not in seen
    # No article notifications (summary may post, but no @channel news).
    assert all("新着記事" not in (p["json"] or {}).get("text", "") for p in posts)


def test_first_run_seeds_three_no_notify(env: pytest.MonkeyPatch) -> None:
    posts = capture_slack(env)
    entries = [make_entry(i) for i in range(5)]
    set_parse(env, {"https://a.test/feed": FakeParsed(entries)})
    write_feeds([{"name": "A", "url": "https://a.test/feed", "enabled": True, "tags": ["t"]}])

    watcher.main()

    seen = json.loads(Path("seen.json").read_text("utf-8"))
    assert len(seen["https://a.test/feed"]) == 3
    assert seen["https://a.test/feed"] == ["entry-0", "entry-1", "entry-2"]
    assert all("新着記事" not in (p["json"] or {}).get("text", "") for p in posts)


def test_max_items_caps_entries_and_seed_count_overrides(env: pytest.MonkeyPatch) -> None:
    posts = capture_slack(env)
    entries = [make_entry(i) for i in range(20)]
    set_parse(env, {"https://big.test/feed": FakeParsed(entries)})
    write_feeds(
        [
            {
                "name": "Big",
                "url": "https://big.test/feed",
                "enabled": True,
                "tags": [],
                "max_items": 10,
                "seed_count": 10,
            }
        ]
    )

    watcher.main()

    seen = json.loads(Path("seen.json").read_text("utf-8"))
    # All fetched (capped) entries are seeded, so the next run does not flood.
    assert seen["https://big.test/feed"] == [f"entry-{i}" for i in range(10)]
    assert all("新着記事" not in (p["json"] or {}).get("text", "") for p in posts)

    latest = json.loads(Path("data/raw/news-latest.json").read_text("utf-8"))
    assert len(latest["items"]) == 10

    # Second run: identical feed content -> nothing new despite entries 10-19
    # never having been stored (they stay beyond the cap).
    watcher.main()
    latest = json.loads(Path("data/raw/news-latest.json").read_text("utf-8"))
    assert latest["new_items"] == []


def test_already_seen_not_notified(env: pytest.MonkeyPatch) -> None:
    posts = capture_slack(env)
    entries = [make_entry(0), make_entry(1)]
    set_parse(env, {"https://a.test/feed": FakeParsed(entries)})
    write_feeds([{"name": "A", "url": "https://a.test/feed", "enabled": True, "tags": []}])
    Path("seen.json").write_text(
        json.dumps({"https://a.test/feed": ["entry-0", "entry-1"]}), encoding="utf-8"
    )

    watcher.main()

    assert all("新着記事" not in (p["json"] or {}).get("text", "") for p in posts)


def test_only_new_entries_notified(env: pytest.MonkeyPatch) -> None:
    posts = capture_slack(env)
    entries = [make_entry(0), make_entry(1), make_entry(2)]
    set_parse(env, {"https://a.test/feed": FakeParsed(entries)})
    write_feeds([{"name": "A", "url": "https://a.test/feed", "enabled": True, "tags": []}])
    Path("seen.json").write_text(
        json.dumps({"https://a.test/feed": ["entry-0"]}), encoding="utf-8"
    )

    watcher.main()

    news_posts = [p for p in posts if "新着記事" in (p["json"] or {}).get("text", "")]
    assert len(news_posts) == 2
    texts = " ".join(p["json"]["text"] for p in news_posts)
    assert "Title 1" in texts and "Title 2" in texts and "Title 0" not in texts


def test_force_notify_latest_one(env: pytest.MonkeyPatch) -> None:
    env.setenv("FORCE_NOTIFY", "true")
    posts = capture_slack(env)
    entries = [make_entry(0), make_entry(1), make_entry(2)]
    set_parse(env, {"https://a.test/feed": FakeParsed(entries)})
    write_feeds([{"name": "A", "url": "https://a.test/feed", "enabled": True, "tags": []}])
    # All seen already -> only the forced latest (entry-0) should notify.
    Path("seen.json").write_text(
        json.dumps({"https://a.test/feed": ["entry-0", "entry-1", "entry-2"]}),
        encoding="utf-8",
    )

    watcher.main()

    news_posts = [p for p in posts if "新着記事" in (p["json"] or {}).get("text", "")]
    assert len(news_posts) == 1
    assert "Title 0" in news_posts[0]["json"]["text"]


def test_url_normalization() -> None:
    raw = "HTTPS://Example.COM/Path/?utm_source=x&gclid=1&keep=2&fbclid=z#frag"
    norm = watcher.normalize_url(raw)
    assert norm == "https://example.com/Path?keep=2"

    assert watcher.normalize_url("https://example.com/") == "https://example.com/"
    assert watcher.normalize_url("https://example.com/a/") == "https://example.com/a"


def test_url_hash_stable() -> None:
    a = watcher.url_id(watcher.normalize_url("https://example.com/a/?utm_source=x"))
    b = watcher.url_id(watcher.normalize_url("https://EXAMPLE.com/a"))
    assert a == b
    assert len(a) == 16


def test_cve_extraction_produces_item(env: pytest.MonkeyPatch) -> None:
    capture_slack(env)
    entry = make_entry(0, title="Critical cve-2026-12345 exploited", summary="see CVE-2026-12345")
    set_parse(env, {"https://a.test/feed": FakeParsed([entry])})
    write_feeds([{"name": "A", "url": "https://a.test/feed", "enabled": True, "tags": []}])

    watcher.main()

    cves = json.loads((Path("data/raw") / "cves-latest.json").read_text("utf-8"))
    ids = [c["cve_id"] for c in cves["items"]]
    assert "CVE-2026-12345" in ids
    assert len([c for c in cves["items"] if c["cve_id"] == "CVE-2026-12345"]) == 1


def test_raw_json_latest_and_dated(env: pytest.MonkeyPatch) -> None:
    capture_slack(env)
    set_parse(env, {"https://a.test/feed": FakeParsed([make_entry(0)])})
    write_feeds([{"name": "A", "url": "https://a.test/feed", "enabled": True, "tags": []}])

    watcher.main()

    today = watcher.utc_today_str()
    for prefix in ("news", "cves"):
        latest = Path("data/raw") / f"{prefix}-latest.json"
        dated = Path("data/raw") / f"{prefix}-{today}.json"
        assert latest.exists() and dated.exists()
        data = json.loads(latest.read_text("utf-8"))
        assert data["schema_version"] == "1.0"
        assert "items" in data and "new_items" in data


def test_one_feed_failure_does_not_stop_others(env: pytest.MonkeyPatch) -> None:
    posts = capture_slack(env)
    good_entries = [make_entry(0)]

    def fake_parse(url: str, *args: Any, **kwargs: Any) -> FakeParsed:
        if url == "https://bad.test/feed":
            raise RuntimeError("boom")
        return FakeParsed(good_entries)

    env.setattr(watcher.feedparser, "parse", fake_parse)
    write_feeds(
        [
            {"name": "Bad", "url": "https://bad.test/feed", "enabled": True, "tags": []},
            {"name": "Good", "url": "https://good.test/feed", "enabled": True, "tags": []},
        ]
    )

    watcher.main()  # must not raise

    seen = json.loads(Path("seen.json").read_text("utf-8"))
    assert "https://good.test/feed" in seen
    assert "https://bad.test/feed" not in seen
    # News raw still written.
    assert (Path("data/raw") / "news-latest.json").exists()
