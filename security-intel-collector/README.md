# security-intel-collector

## 1. Overview

Collects security intelligence from two sources and emits standardized raw JSON
for downstream AI analysis:

- **Security news** from RSS/Atom feeds (`watcher.py`).
- **CVEs** from the NVD API v2.0, enriched with best-effort signals from the
  VulDB RSS feed (`cve_watcher.py`).

New items are posted to Slack and written as standardized raw JSON to
`data/raw/`. Both collectors run every 3 hours on GitHub Actions and can also be
run locally.

## 2. Features

- RSS/Atom collection (`watcher.py`).
- CVE collection from NVD API v2.0 + VulDB RSS enrichment (`cve_watcher.py`).
- Slack notifications (optional — skipped when no webhook is configured).
- Deduplication via JSON state files so each item is reported once.
- Standardized raw JSON output to `data/raw/` for downstream AI analysis.
- Daily history files (`*-YYYY-MM-DD.json`) in addition to the `*-latest.json` files.
- Artifact upload of `data/raw/` from the GitHub Actions workflows.
- Auto-commit of state files and raw JSON back to the repository.

## 3. File Layout

```
README.md
requirements.txt
feeds.json                 # active feed list (used by watcher.py)
feeds.example.json         # sample feed list to copy from
watcher.py                 # RSS/Atom collector
cve_watcher.py             # NVD + VulDB CVE collector
seen.json                  # RSS dedup state (seen entry IDs)
rss_meta.json              # RSS run metadata
cve_seen.json              # CVE dedup state (seen CVE IDs)
cve_meta.json              # CVE run metadata
data/raw/
  news-latest.json         # most recent RSS run
  cves-latest.json         # most recent CVE run
  news-YYYY-MM-DD.json     # daily RSS history
  cves-YYYY-MM-DD.json     # daily CVE history
tests/
  test_watcher.py
  test_cve_watcher.py
.github/workflows/
  rss-watch.yml
  cve-watch.yml
```

## 4. GitHub Secrets

Configure these in the repository settings (Settings → Secrets and variables → Actions):

- `SLACK_WEBHOOK_URL_RSS` — Slack incoming webhook for RSS news notifications.
- `SLACK_WEBHOOK_URL_CVE` — Slack incoming webhook for CVE notifications.
- `NVD_API_KEY` — NVD API key (raises rate limits; strongly recommended).

## 5. Environment Variables (local run)

- `SLACK_WEBHOOK_URL` — Slack incoming webhook. If unset, notifications are skipped.
- `NVD_API_KEY` — NVD API key for `cve_watcher.py`.
- `GITHUB_RUN_ID` — run identifier recorded in raw JSON (`run_id`). Set automatically in Actions.
- `FORCE_NOTIFY` — when truthy, notify even for already-seen items.
- `HEARTBEAT_NOTIFY` — when truthy, allow periodic heartbeat notifications.
- `HEARTBEAT_INTERVAL_MINUTES` — minimum minutes between heartbeat notifications.
- `NOTIFY_ON_ZERO` — when truthy, send a notification even when there are no new items.

## 6. Local Run

```bash
pip install -r requirements.txt

# configure feeds (first time)
cp feeds.example.json feeds.json   # then edit as needed

python watcher.py
python cve_watcher.py
```

Slack is optional: if `SLACK_WEBHOOK_URL` is unset, the collectors simply skip
notification. The raw JSON in `data/raw/` is produced either way.

## 7. GitHub Actions

Two workflows live in `.github/workflows/`:

- `rss-watch.yml` — runs `watcher.py`.
- `cve-watch.yml` — runs `cve_watcher.py`.

Both run every 3 hours on a schedule and support manual `workflow_dispatch`.
`rss-watch.yml` exposes a `force_notify` input for manual runs. Each workflow
validates its raw JSON output with `jq`, uploads `data/raw/` as a build
artifact, and auto-commits the updated state files and raw JSON back to the
repository.

## 8. Common Raw JSON Schema

Every raw JSON file shares a common envelope:

- `schema_version` — schema version string.
- `run_id` — run identifier (`GITHUB_RUN_ID` when available).
- `generated_at` — ISO 8601 UTC timestamp of the run.
- `source_type` — `"news"` or `"cve"`.
- `items` — all items considered in the run.
- `new_items` — items new since the previous run (the ones notified).

### News item fields

- `id` — stable entry identifier.
- `title`
- `link`
- `summary`
- `published` — published timestamp.
- `source` — feed name.
- `tags` — feed tags.

### CVE item fields

- `id` — CVE ID.
- `title`
- `description`
- `cvss_score`
- `cvss_severity`
- `vendor`
- `vuln_types` — list of vuln type codes (see below).
- `references` — list of reference URLs.
- `published`
- `last_modified`
- `signals` — enrichment signals (e.g. KEV / actively exploited / PoC / VulDB).
- `reportable` — whether the CVE met the importance rules.

## 9. CVE Importance Rules

A CVE is **reportable** if any of the following holds:

- It is in CISA KEV / actively exploited.
- It is a zero-day.
- A public PoC exists.
- `cvss_score >= 9.0` and the vendor is a priority vendor.
- `cvss_score >= 7.5` and it is RCE, AuthBypass, PrivEsc, or SandboxEscape.
- `cvss_score >= 7.5` and it is observed in multiple sources.

**Exclusions** (not reportable):

- `cvss_score < 7.0` with no exploitation signals.
- Information-disclosure-only with `cvss_score < 8.0`.
- DoS-only with `cvss_score < 8.0`.
- Non-priority vendor with `cvss_score < 9.0`.

**Priority vendors:** Microsoft, Cisco, Fortinet, Palo Alto Networks, Ivanti,
Citrix, VMware, Apache, Atlassian, Google, Apple, Oracle, Adobe, F5, SonicWall.

**Vuln type codes:** `RCE`, `AUTH_BYPASS`, `PRIV_ESC`, `SANDBOX_ESCAPE`, `DOS`,
`INFO_DISCLOSURE`.

## 10. Tests

```bash
pytest -q
```

## 11. Known Limitations

- NVD enforces API rate limits; set `NVD_API_KEY` to raise them.
- VulDB RSS is used as best-effort signal enrichment only; it is not exhaustive.
- The first run for a feed seeds 3 entries without notifying (to avoid backfill spam).
- There is no external database; all state is kept in JSON files in the repo.
