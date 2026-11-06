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


def test_feed_language_is_recorded_on_items(env: pytest.MonkeyPatch) -> None:
    capture_slack(env)
    set_parse(env, {
        "https://ko.test/feed": FakeParsed([make_entry(1, url="https://ko.test/1")]),
        "https://x.test/feed": FakeParsed([make_entry(2, url="https://x.test/2")]),
    })
    write_feeds([
        {"name": "KO", "url": "https://ko.test/feed", "enabled": True, "tags": [], "language": "ko"},
        {"name": "X", "url": "https://x.test/feed", "enabled": True, "tags": []},
    ])

    watcher.main()

    raw = json.loads(Path("data/raw/news-latest.json").read_text("utf-8"))
    by_source = {item["source"]: item for item in raw["items"]}
    assert by_source["KO"]["language"] == "ko"
    assert by_source["X"]["language"] is None


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


def test_include_terms_syntax() -> None:
    patterns = watcher.compile_include_terms(
        ["cyber*", "APT", "サイバー", "export control*", "", None, 3]
    )
    assert len(patterns) == 4  # blank / non-string terms are ignored

    def hit(title: str) -> bool:
        return watcher.entry_matches_terms(make_entry(1, title=title, summary=""), patterns)

    assert hit("Cyberattack on a ministry")        # prefix match
    assert hit("The cyber-espionage case")         # hyphen is a boundary
    assert hit("APT groups regroup")               # whole word
    assert not hit("We must adapt quickly")        # APT is not a substring match
    assert hit("日本のサイバー防衛")                  # CJK substring
    assert hit("New Export Controls announced")    # multi-word + prefix, case-insensitive
    assert not hit("A routine budget debate")


def test_repo_feeds_json_is_well_formed() -> None:
    """The real feeds.json must keep its shape (guards PR edits, runs in CI)."""
    import re

    feeds = json.loads((Path(__file__).resolve().parent.parent / "feeds.json").read_text("utf-8"))
    assert isinstance(feeds, list) and feeds
    names: set = set()
    urls: set = set()
    for feed in feeds:
        name, url = feed["name"], feed["url"]
        assert name not in names, f"duplicate feed name: {name}"
        assert url not in urls, f"duplicate feed url: {url}"
        names.add(name)
        urls.add(url)
        assert re.match(r"^https?://", url), f"{name}: url must be http(s)"
        assert isinstance(feed.get("enabled"), bool), f"{name}: enabled must be boolean"
        assert isinstance(feed.get("tags"), list), f"{name}: tags must be a list"
        assert feed.get("language") in {"ja", "en", "zh", "ko", "ru", "fr"}, f"{name}: language"
        for key in ("max_items", "seed_count"):
            if key in feed:
                assert isinstance(feed[key], int) and feed[key] > 0, f"{name}: {key}"
        if "include_terms" in feed:
            terms = feed["include_terms"]
            assert isinstance(terms, list) and terms, f"{name}: include_terms must be a non-empty list"
            assert all(isinstance(t, str) and t.strip() for t in terms), f"{name}: include_terms entries"
            assert len(watcher.compile_include_terms(terms)) == len(terms)
        # A state-run outlet must be tagged so downstream steps flag it (Section 5)
        if feed["name"].startswith("TASS"):
            assert "state_media" in feed["tags"]


def test_include_terms_absent_or_empty_means_no_filter() -> None:
    assert watcher.compile_include_terms(None) == []
    assert watcher.compile_include_terms([]) == []
    assert watcher.compile_include_terms("cyber") == []  # not a list -> ignored


def test_include_terms_filters_before_max_items(env: pytest.MonkeyPatch) -> None:
    capture_slack(env)
    entries = []
    for i in range(10):
        title = f"Hackers hit target {i}" if i % 2 == 0 else f"Weather report {i}"
        entries.append(make_entry(i, url=f"https://broad.test/{i}", title=title, summary=""))
    set_parse(env, {"https://broad.test/feed": FakeParsed(entries)})
    write_feeds(
        [
            {
                "name": "Broad",
                "url": "https://broad.test/feed",
                "enabled": True,
                "tags": [],
                "include_terms": ["hack*"],
                "max_items": 3,
            }
        ]
    )

    watcher.main()

    latest = json.loads(Path("data/raw/news-latest.json").read_text("utf-8"))
    titles = [item["title"] for item in latest["items"]]
    # 5 of 10 match; the cap of 3 counts matching entries only (feed order kept).
    assert titles == ["Hackers hit target 0", "Hackers hit target 2", "Hackers hit target 4"]


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


def test_dated_raw_merges_across_runs(env: pytest.MonkeyPatch) -> None:
    """Running twice on the same UTC date must union items, not overwrite.

    Feeds show only their newest N entries; with several runs per day the
    dated file has to keep what scrolled off between runs.
    """
    capture_slack(env)
    write_feeds([{"name": "A", "url": "https://a.test/feed", "enabled": True, "tags": []}])

    set_parse(env, {"https://a.test/feed": FakeParsed([make_entry(0), make_entry(1)])})
    watcher.main()
    # Second run: entry 0 scrolled off, entry 2 appeared.
    set_parse(env, {"https://a.test/feed": FakeParsed([make_entry(1), make_entry(2)])})
    watcher.main()

    today = watcher.utc_today_str()
    dated = json.loads((Path("data/raw") / f"news-{today}.json").read_text("utf-8"))
    latest = json.loads((Path("data/raw") / "news-latest.json").read_text("utf-8"))

    assert [i["url"] for i in dated["items"]] == [
        "https://example.com/post-0",
        "https://example.com/post-1",
        "https://example.com/post-2",
    ]
    assert [i["url"] for i in latest["items"]] == [
        "https://example.com/post-1",
        "https://example.com/post-2",
    ]
    # new_items accumulate too (entry 2 is the only post-seed new item).
    assert [i["url"] for i in dated["new_items"]] == ["https://example.com/post-2"]
    assert len(dated["run_ids"]) == 2
    assert dated["first_generated_at"]


def test_merge_dated_raw_ignores_foreign_or_corrupt_existing() -> None:
    raw = watcher.build_raw("security_news", [{"id": "x"}], [])
    assert watcher.merge_dated_raw(None, raw) == raw
    assert watcher.merge_dated_raw("garbage", raw) == raw
    other = watcher.build_raw("cve", [{"id": "y"}], [])
    assert watcher.merge_dated_raw(other, raw) == raw
