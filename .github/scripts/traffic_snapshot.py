#!/usr/bin/env python3
"""Snapshot GitHub repository traffic into committed CSV history.

The GitHub traffic API only retains the last 14 days of clones and views, and
referrers are a point-in-time top list. This script fetches all three and
merges them into CSVs under ``metrics/`` so the record survives beyond the
14-day window:

- ``metrics/clones.csv``   date,count,uniques   (one row per day, merged)
- ``metrics/views.csv``    date,count,uniques   (one row per day, merged)
- ``metrics/referrers.csv``  snapshot_date,referrer,count,uniques  (appended)

Clone and view days overlap between runs; the newest fetch is authoritative, so
a day already present is overwritten with the latest values rather than
duplicated. Referrers are appended with the run date, since they are a snapshot
rather than a time series.

Environment:
- ``GH_TOKEN``    a token that can read the traffic API (fine-grained PAT with
                  ``Administration: read``, or a classic PAT with ``repo``).
                  The built-in ``GITHUB_TOKEN`` cannot read traffic.
- ``REPO``        ``owner/name`` (GitHub Actions sets this as github.repository).

Standard library only; no third-party dependencies.
"""

from __future__ import annotations

import csv
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.github.com"
METRICS = Path("metrics")


def fetch(path: str, token: str) -> dict | list:
    req = urllib.request.Request(
        f"{API}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "bellbook-traffic-snapshot",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def merge_daily(filename: str, rows: list[dict], key: str) -> None:
    """Merge a clones/views time series into a date-keyed CSV."""
    path = METRICS / filename
    by_date: dict[str, tuple[str, str]] = {}
    if path.exists():
        with path.open(newline="") as fh:
            for row in csv.DictReader(fh):
                by_date[row["date"]] = (row["count"], row["uniques"])
    for item in rows:
        date = item["timestamp"][:10]  # ISO 8601 -> YYYY-MM-DD
        by_date[date] = (str(item["count"]), str(item["uniques"]))
    METRICS.mkdir(exist_ok=True)
    with path.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["date", "count", "uniques"])
        for date in sorted(by_date):
            count, uniques = by_date[date]
            writer.writerow([date, count, uniques])
    print(f"{filename}: {len(by_date)} day(s) total (fetched {len(rows)})")


def append_referrers(referrers: list[dict], today: str) -> None:
    path = METRICS / "referrers.csv"
    METRICS.mkdir(exist_ok=True)
    new = path.exists() is False
    with path.open("a", newline="") as fh:
        writer = csv.writer(fh)
        if new:
            writer.writerow(["snapshot_date", "referrer", "count", "uniques"])
        for r in referrers:
            writer.writerow([today, r["referrer"], r["count"], r["uniques"]])
    print(f"referrers.csv: appended {len(referrers)} row(s) for {today}")


def main() -> int:
    token = os.environ.get("GH_TOKEN")
    repo = os.environ.get("REPO")
    if not token or not repo:
        print("GH_TOKEN and REPO must be set", file=sys.stderr)
        return 1
    try:
        clones = fetch(f"/repos/{repo}/traffic/clones", token)
        views = fetch(f"/repos/{repo}/traffic/views", token)
        referrers = fetch(f"/repos/{repo}/traffic/popular/referrers", token)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        print(f"traffic API error {exc.code}: {detail}", file=sys.stderr)
        if exc.code in (401, 403):
            print(
                "The token cannot read traffic. Use a PAT with "
                "Administration: read (fine-grained) or repo (classic); "
                "the built-in GITHUB_TOKEN does not work here.",
                file=sys.stderr,
            )
        return 1

    merge_daily("clones.csv", clones.get("clones", []), "clones")
    merge_daily("views.csv", views.get("views", []), "views")

    # Derive the run date from the latest datapoint when available, so the
    # output is deterministic and does not depend on wall-clock at commit time.
    dated = [d["timestamp"][:10] for d in views.get("views", [])]
    today = max(dated) if dated else "unknown"
    append_referrers(referrers if isinstance(referrers, list) else [], today)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
