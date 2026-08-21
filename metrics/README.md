# Traffic metrics

Weekly snapshots of GitHub repository traffic, written by the
[`traffic-snapshot`](../.github/workflows/traffic-snapshot.yml) workflow. GitHub
only retains 14 days of traffic, so this directory is the long-term record.

- `clones.csv` - `date,count,uniques`, one row per day (merged, not duplicated).
- `views.csv` - `date,count,uniques`, one row per day.
- `referrers.csv` - `snapshot_date,referrer,count,uniques`, appended each run
  (referrers are a point-in-time top list, not a time series).

These are aggregate, non-personal counts. `uniques` is a better adoption proxy
than raw `count`, and a clone/view trend that does not track your CI schedule is
the signal worth watching. See [ADOPTERS.md](../ADOPTERS.md) for the qualitative
counterpart.

The CSV files appear here after the first successful run of the workflow, which
needs a `TRAFFIC_TOKEN` secret (the built-in `GITHUB_TOKEN` cannot read the
traffic API).
