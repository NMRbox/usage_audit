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
min_auid: 30001           # only audit auid >= this
audit:
  backlog_limit: 16_384
  wait_time_us: 120_000   # microseconds; 120_000 = 120 ms
  failure_mode: 1         # auditd -f mode (1 = printk/log)
# optional:
# ignore uids:            # accounts to skip entirely (auid or uid)
#   - 303034
# combine seconds: 60     # collapse repeat opens of one file into one row
# seal_compress: true     # LZMA-compress prior-day files (default true)
```

`store`, `monitor`, `min_auid`, `audit.backlog_limit`, `audit.wait_time_us`, and
`audit.failure_mode` are required; `nmrbox_audit_setup.py` raises if any is
missing.

### Cutting volume

Two independent knobs, and they work at different layers:

`ignore uids` becomes `-F auid!=N -F uid!=N` clauses on every watch, so the
kernel never generates the event: no backlog pressure, no audispd pipe traffic,
no parse. Both fields are excluded so an account is skipped whether it appears
as a login session or as a daemon identity. Re-run `nmrbox_audit_setup.py`
after changing it — the collector also honours the list, but only as a backstop
for `--replay` of logs captured before the rule existed. A rule holds at most 64
`-F` clauses, capping the list at 29 entries; setup raises rather than emitting
a rule `auditctl` would reject.

`combine seconds` is collector-side, and has no kernel equivalent — audit can
drop events by uid or path but not "the same thing again". Within the window,
repeat opens of one path by the same user and program become a single row whose
`events.combined` column carries the count, instead of N rows. Repeats are most
of the volume on a busy box. The cost is that a row is held in memory until its
window closes, so writes lag by up to that many seconds. Set `0` to store every
open individually. `nmrbox_audit_query.py` sums `combined`, so `--top` and
`--summary` report true open counts either way; a listing marks a combined row
`xN`.

## failure mode
```   -f [0..2]
              Set failure mode 0=silent 1=printk 2=panic. This option lets you determine how you want the kernel to handle critical errors. Example conditions where this mode may have an effect includes: transmission  errors
              to userspace audit daemon, backlog limit exceeded, out of kernel memory, and rate limit exceeded. The default value is 1. Secure environments will probably want to set this to 2.
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


## nmrbox_audit_setup.py

Install and configure the NMRbox file-open audit pipeline from
/etc/nmrhub.d/nmrbox_audit.yaml.

What it does (idempotently):
  1. Ensures auditd is installed (apt) and the store directory exists.
  2. Writes /etc/audit/rules.d/40-nmrbox.rules:
       - backlog limit + backlog_wait_time from the config
       - one open/openat/openat2 watch per monitored path (b64 and b32),
         filtered to real NMRbox users (auid >= min_auid) so daemon/root
         activity is dropped in-kernel, and excluding every account in
         `ignore uids`.
       - a watch on every filesystem mounted underneath a monitored path
         too. Audit directory watches don't cross mount points, so e.g.
         /reboxitory's many NFS submounts (one per data snapshot) would
         otherwise go unaudited; the mount table (/proc/mounts) is read at
         setup time and any mount nested under a monitored path gets its
         own watch, in addition to the configured path itself.
  3. Installs the collector to /opt/nmrbox.d and registers it as an audisp
     plugin in /etc/audit/plugins.d/nmrbox.conf.
  4. Loads the rules (augenrules --load) and restarts auditd.

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
