# NMRbox file-open audit pipeline

Three Python 3.12 scripts that install auditd, watch the configured paths for
file opens by NMRbox users, and write one compressed SQLite database per
calendar day.

```
auditd  ──(format=string)──►  nmrbox_audit_collector.py  ──►  /<store>/nmrbox_audit_YYYY-MM-DD.db
   ▲                              (audisp plugin, root)              (live, today)
   │                                                                 nmrbox_audit_YYYY-MM-DD.db.xz
nmrbox_audit_setup.py                                                (sealed, prior days)
(rules + plugin + install)
                              nmrbox_audit_query.py  ──►  reads .db or .db.xz transparently
```

## Files

| Script | Role |
|---|---|
| `nmrbox_audit_setup.py` | Installs auditd, writes rules from the YAML, registers the collector as an audisp plugin, loads everything. |
| `nmrbox_audit_collector.py` | The audisp plugin. Correlates SYSCALL+PATH+CWD+PROCTITLE, writes the daily SQLite file. |
| `nmrbox_audit_query.py` | Reads the daily databases (live or sealed) for ad-hoc queries. |

## Configuration

Reads `/etc/nmrhub.d/nmrbox_audit.yaml`:

```yaml
monitor:            # directories watched recursively
  - /reboxitory
  - /usr/software
  - /public
  - /scratch
  - /home/nmrbox
store: /accountinglogs/   # where the daily .db / .db.xz files are written
audit:
  backlog_limit: 16_384
  wait_time_us: 120_000   # microseconds; 120_000 = 120 ms
# optional:
# min_auid: 30001         # only audit auid >= this (default 30001)
# seal_compress: true     # LZMA-compress prior-day files (default true)
```

## Deploy

```bash
sudo python3 nmrbox_audit_setup.py            # uses /etc/nmrhub.d/nmrbox_audit.yaml
sudo python3 nmrbox_audit_setup.py --dry-run  # preview, change nothing
```

The collector is run by auditd, so there is no separate service to manage —
auditd starts/stops/reloads it. Confirm it is live:

```bash
sudo auditctl -s | grep -E 'backlog|lost|wait'
sudo auditctl -l | grep nmrbox
```

For the cluster, push the YAML + run setup via Ansible. Per-node-type backlog
differences (e.g. larger on login nodes) are just a different `backlog_limit`
in that host group's YAML.

## Query

```bash
# Everything user 30137 opened on a day
nmrbox_audit_query.py --day 2026-06-23 --auid 30137

# Most-opened files under /reboxitory across all retained days
nmrbox_audit_query.py --path /reboxitory --top 25

# Per-user open counts for a day
nmrbox_audit_query.py --day 2026-06-23 --summary
```

## How compression works

1. **In-DB string interning** — exe, comm, syscall, key, path, nametype, and
   hostname are stored once in a `strings` table and referenced by integer id.
   Audit data repeats heavily, so the live (queryable) DB stays small.
2. **Seal-and-compress at rollover** — when the next day's file opens, the prior
   day is VACUUMed and LZMA-compressed to `.db.xz`, and the plain `.db` removed.
   `nmrbox_audit_query.py` decompresses sealed files to a temp DB on read.

Both layers are pure standard library (`sqlite3`, `lzma`) — no external audit
processor or compression extension to package.

## Expected footprint (per earlier sizing)

- CPU: well under 1% of a compute node steady-state; under ~0.25% during job-
  start bursts. `backlog_wait_time` itself costs no CPU (kernel sleep).
- Storage: roughly 0.2–0.3 KB per event after interning; on the order of tens of
  MB/day per node, ~1.6 GB/day cluster-wide, ~145 GB for 90-day retention.

## Testing without a live audit feed

The collector can replay a saved log (also useful for backfill):

```bash
python3 nmrbox_audit_collector.py --config nmrbox_audit.yaml --replay /var/log/audit/audit.log
```

## Operational notes

- The collector runs as root under auditd and writes to `store` (created 0750).
- A mid-day restart is safe: the string cache and event-id counter are rebuilt
  from the open day's DB, so no key collisions or duplicate strings.
- Watch `auditctl -s | grep lost` — a rising `lost` count means events are being
  dropped before the collector ever sees them; raise `backlog_limit`.
- The collector only persists syscalls that produced a PATH record (real opens);
  unrelated record types are ignored.
```
