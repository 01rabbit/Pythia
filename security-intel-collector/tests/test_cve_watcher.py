"""Tests for cve_watcher (no network; everything monkeypatched)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cve_watcher  # noqa: E402


# --------------------------------------------------------------------------- #
# Sample data builders
# --------------------------------------------------------------------------- #

def make_nvd_vuln(
    cve_id: str = "CVE-2024-0001",
    description: str = "A remote code execution flaw in the product.",
    metrics: dict[str, Any] | None = None,
    criteria: str = "cpe:2.3:a:fortinet:fortios:7.0.0:*:*:*:*:*:*:*",
    published: str = "2024-01-01T00:00:00.000",
    last_modified: str = "2024-01-02T00:00:00.000",
) -> dict[str, Any]:
    if metrics is None:
        metrics = {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
            ]
        }
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [
                {"lang": "en", "value": description},
                {"lang": "es", "value": "ignored"},
            ],
            "published": published,
            "lastModified": last_modified,
            "references": [
                {"url": "https://example.com/ref1"},
                {"url": "https://example.com/ref2"},
            ],
            "metrics": metrics,
            "configurations": [
                {"nodes": [{"cpeMatch": [{"criteria": criteria}]}]}
            ],
        }
    }


def make_nvd_response(*vulns: dict[str, Any]) -> dict[str, Any]:
    return {"vulnerabilities": list(vulns)}


def fake_feed(*entries: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(entries=list(entries))


# --------------------------------------------------------------------------- #
# 1. Build a CVE record from a sample NVD response
# --------------------------------------------------------------------------- #

def test_parse_nvd_item_basic() -> None:
    rec = cve_watcher.parse_nvd_item(make_nvd_vuln())
    assert rec["cve_id"] == "CVE-2024-0001"
    assert rec["id"] == "CVE-2024-0001"
    assert rec["description"].startswith("A remote code execution")
    assert rec["url"] == "https://example.com/ref1"
    assert rec["references"] == [
        "https://example.com/ref1",
        "https://example.com/ref2",
    ]
    assert rec["published_at"] == "2024-01-01T00:00:00Z"
    assert rec["modified_at"] == "2024-01-02T00:00:00Z"
    assert rec["cvss_score"] == 9.8
    assert rec["severity"] == "CRITICAL"
    assert rec["vendor_product"] == "fortinet fortios"
    assert "nvd" in rec["_sources"]


# --------------------------------------------------------------------------- #
# 2. CVSS max across versions
# --------------------------------------------------------------------------- #

def test_cvss_max_across_versions() -> None:
    metrics = {
        "cvssMetricV40": [{"cvssData": {"baseScore": 8.1}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
        "cvssMetricV30": [{"cvssData": {"baseScore": 7.5}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}],
    }
    score, severity = cve_watcher.extract_cvss(metrics)
    assert score == 9.8
    assert severity == "CRITICAL"


def test_severity_derived_when_absent() -> None:
    metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 7.2}}]}
    score, severity = cve_watcher.extract_cvss(metrics)
    assert score == 7.2
    assert severity == "HIGH"


# --------------------------------------------------------------------------- #
# 3. vendor/product from CPE criteria
# --------------------------------------------------------------------------- #

def test_vendor_product_from_cpe() -> None:
    configs = [
        {"nodes": [
            {"cpeMatch": [
                {"criteria": "cpe:2.3:a:paloaltonetworks:pan_os:11.0:*:*:*"}
            ]}
        ]}
    ]
    assert cve_watcher.extract_vendor_product(configs) == "paloaltonetworks pan_os"


# --------------------------------------------------------------------------- #
# 4. Vuln type detection
# --------------------------------------------------------------------------- #

def test_detect_vuln_types() -> None:
    assert "RCE" in cve_watcher.detect_vuln_types("Remote Code Execution issue")
    assert "RCE" in cve_watcher.detect_vuln_types("allows arbitrary code")
    assert "AUTH_BYPASS" in cve_watcher.detect_vuln_types(
        "an authentication bypass vulnerability")
    assert "AUTH_BYPASS" in cve_watcher.detect_vuln_types("auth bypass here")
    assert "PRIV_ESC" in cve_watcher.detect_vuln_types("privilege escalation")
    assert "PRIV_ESC" in cve_watcher.detect_vuln_types("elevation of privilege")
    assert "DOS" in cve_watcher.detect_vuln_types("leads to denial of service")
    assert "DOS" in cve_watcher.detect_vuln_types("a DoS condition")
    assert "INFO_DISCLOSURE" in cve_watcher.detect_vuln_types(
        "information disclosure bug")
    # negative: "endossed" should not trigger DOS
    assert "DOS" not in cve_watcher.detect_vuln_types("the endorsement window")


# --------------------------------------------------------------------------- #
# 5. KEV / zero-day / PoC make a CVE reportable
# --------------------------------------------------------------------------- #

def test_reportable_signals() -> None:
    for tag, _ in (("kev", 1), ("zero_day", 1), ("poc", 1),
                   ("actively_exploited", 1)):
        rec = cve_watcher._empty_record("CVE-2024-1000")
        rec["cvss_score"] = 5.0  # low, but signal should override
        rec["tags"] = [tag]
        reason = cve_watcher.judge_reportable(rec)
        assert reason is not None, tag


# --------------------------------------------------------------------------- #
# 6. Low CVSS with no signals excluded
# --------------------------------------------------------------------------- #

def test_low_cvss_excluded() -> None:
    rec = cve_watcher._empty_record("CVE-2024-2000")
    rec["cvss_score"] = 5.5
    rec["vendor_product"] = "fortinet fortios"
    rec["vuln_types"] = ["RCE"]
    assert cve_watcher.judge_reportable(rec) is None


# --------------------------------------------------------------------------- #
# 7. DoS-only and INFO_DISCLOSURE-only low-CVSS excluded
# --------------------------------------------------------------------------- #

def test_dos_only_low_excluded() -> None:
    rec = cve_watcher._empty_record("CVE-2024-3000")
    rec["cvss_score"] = 7.6
    rec["vendor_product"] = "fortinet fortios"
    rec["vuln_types"] = ["DOS"]
    rec["_sources"] = {"nvd"}
    assert cve_watcher.judge_reportable(rec) is None


def test_info_disclosure_only_low_excluded() -> None:
    rec = cve_watcher._empty_record("CVE-2024-3001")
    rec["cvss_score"] = 7.7
    rec["vendor_product"] = "fortinet fortios"
    rec["vuln_types"] = ["INFO_DISCLOSURE"]
    rec["_sources"] = {"nvd"}
    assert cve_watcher.judge_reportable(rec) is None


def test_info_disclosure_high_included() -> None:
    rec = cve_watcher._empty_record("CVE-2024-3002")
    rec["cvss_score"] = 8.2
    rec["vendor_product"] = "fortinet fortios"
    rec["vuln_types"] = ["INFO_DISCLOSURE", "RCE"]
    rec["_sources"] = {"nvd"}
    assert cve_watcher.judge_reportable(rec) is not None


# --------------------------------------------------------------------------- #
# 8. NVD + VulDB merged by CVE ID into one record
# --------------------------------------------------------------------------- #

def test_merge_nvd_and_vuldb() -> None:
    nvd = [cve_watcher.parse_nvd_item(make_nvd_vuln("CVE-2024-0001"))]
    vuldb = {
        "CVE-2024-0001": {
            "tags": {"poc", "zero_day"},
            "references": ["https://vuldb.com/?id.1"],
            "title": "VulDB title",
            "description": "exploited in the wild",
        },
        "CVE-2024-9999": {  # not in NVD -> included with null fields
            "tags": {"kev"},
            "references": ["https://vuldb.com/?id.2"],
            "title": "Solo vuldb",
            "description": None,
        },
    }
    merged = cve_watcher.merge_records(nvd, vuldb)
    by_id = {r["cve_id"]: r for r in merged}
    assert set(by_id) == {"CVE-2024-0001", "CVE-2024-9999"}

    combined = by_id["CVE-2024-0001"]
    assert "poc" in combined["tags"]
    assert "zero_day" in combined["tags"]
    assert "https://vuldb.com/?id.1" in combined["references"]
    assert combined["_sources"] == {"nvd", "vuldb"}

    solo = by_id["CVE-2024-9999"]
    assert solo["cvss_score"] is None
    assert solo["published_at"] is None
    assert solo["_sources"] == {"vuldb"}
    assert "kev" in solo["tags"]


# --------------------------------------------------------------------------- #
# 9. Already-notified CVE is not re-notified
# --------------------------------------------------------------------------- #

def test_already_notified_not_resent(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cve_watcher.time, "sleep", lambda *_: None)

    # CVE-2024-0001 already seen, CVE-2024-0002 new.
    (tmp_path / "cve_seen.json").write_text(
        json.dumps(["CVE-2024-0001"]), encoding="utf-8")

    nvd_resp = make_nvd_response(
        make_nvd_vuln("CVE-2024-0001"),
        make_nvd_vuln("CVE-2024-0002",
                      criteria="cpe:2.3:a:cisco:ios:1.0:*:*:*:*:*:*:*"),
    )

    def fake_get(url: str, **kwargs: Any) -> Any:
        return SimpleNamespace(status_code=200, json=lambda: nvd_resp)

    posted: list[str] = []

    def fake_post(url: str, **kwargs: Any) -> Any:
        posted.append(kwargs.get("json", {}).get("text", ""))
        return SimpleNamespace(status_code=200)

    def fake_parse(url: str) -> Any:
        return fake_feed()

    monkeypatch.setattr(cve_watcher.requests, "get", fake_get)
    monkeypatch.setattr(cve_watcher.requests, "post", fake_post)
    monkeypatch.setattr(cve_watcher.feedparser, "parse", fake_parse)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/abc")
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    cve_watcher.main()

    # Exactly one Slack post, mentioning only the new CVE.
    assert len(posted) == 1
    assert "CVE-2024-0002" in posted[0]
    assert "CVE-2024-0001" not in posted[0]

    seen = json.loads((tmp_path / "cve_seen.json").read_text())
    assert "CVE-2024-0001" in seen
    assert "CVE-2024-0002" in seen


# --------------------------------------------------------------------------- #
# 10. raw JSON written for BOTH latest and dated files
# --------------------------------------------------------------------------- #

def test_raw_json_written_both(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cve_watcher.time, "sleep", lambda *_: None)

    nvd_resp = make_nvd_response(make_nvd_vuln("CVE-2024-0001"))

    def fake_get(url: str, **kwargs: Any) -> Any:
        return SimpleNamespace(status_code=200, json=lambda: nvd_resp)

    def fake_post(url: str, **kwargs: Any) -> Any:
        return SimpleNamespace(status_code=200)

    def fake_parse(url: str) -> Any:
        return fake_feed({
            "title": "CVE-2024-0001 exploited",
            "summary": "actively exploited in the wild, PoC available",
            "link": "https://vuldb.com/?id.1",
        })

    monkeypatch.setattr(cve_watcher.requests, "get", fake_get)
    monkeypatch.setattr(cve_watcher.requests, "post", fake_post)
    monkeypatch.setattr(cve_watcher.feedparser, "parse", fake_parse)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    cve_watcher.main()

    raw_dir = tmp_path / "data" / "raw"
    latest = raw_dir / "cves-latest.json"
    assert latest.exists()

    payload = json.loads(latest.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert payload["source_type"] == "cve"
    generated_at = payload["generated_at"]
    dated = raw_dir / f"cves-{generated_at[:10]}.json"
    assert dated.exists()

    assert len(payload["items"]) == 1
    # merged signals -> reportable -> in new_items
    assert len(payload["new_items"]) == 1
    item = payload["items"][0]
    assert "_sources" not in item  # internal field stripped
    assert item["cve_id"] == "CVE-2024-0001"
    assert "poc" in item["tags"]


# --------------------------------------------------------------------------- #
# Bonus: NVD failure does not abort run when VulDB yields data
# --------------------------------------------------------------------------- #

def test_nvd_failure_vuldb_continues(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cve_watcher.time, "sleep", lambda *_: None)

    def fake_get(url: str, **kwargs: Any) -> Any:
        return SimpleNamespace(status_code=503, json=lambda: {})

    def fake_parse(url: str) -> Any:
        return fake_feed({
            "title": "CVE-2024-7777 zero-day",
            "summary": "0-day actively exploited in the wild",
            "link": "https://vuldb.com/?id.7",
        })

    monkeypatch.setattr(cve_watcher.requests, "get", fake_get)
    monkeypatch.setattr(cve_watcher.feedparser, "parse", fake_parse)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    cve_watcher.main()

    payload = json.loads(
        (tmp_path / "data" / "raw" / "cves-latest.json").read_text())
    ids = {i["cve_id"] for i in payload["items"]}
    assert "CVE-2024-7777" in ids
