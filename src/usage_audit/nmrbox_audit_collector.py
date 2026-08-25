#!/usr/bin/env python3
"""nmrbox_audit_collector.py

audisp plugin that consumes the auditd event stream (format=string on stdin),
correlates the multi-record events (SYSCALL + PATH + CWD + PROCTITLE) emitted
for open/openat/openat2, and writes them into a per-calendar-day SQLite file in
the configured store directory.

Compression strategy
--------------------
Three layers, all pure stdlib:

0. Combining: audit's dominant volume is the same file being reopened over and
   over -- a shared library loaded by every process start, a data file read in
   a loop. Within `combine seconds` of the first open, repeat opens of the same
   path by the same user and program are collapsed into one row carrying a
   `combined` count instead of N rows. Set `combine seconds: 0` to store every
   open individually.

1. In-DB normalization ("interning"): every repeated string -- exe, comm,
   syscall, key, path name, nametype, hostname -- is stored once in a `strings`
   table and referenced by integer id. On audit data (the same exe and path
   prefixes repeat endlessly) this alone shrinks the live DB several-fold while
   keeping it fully queryable.

2. Seal-and-compress at day rollover: when a new day's file is opened, the
   previous day's file is VACUUMed and LZMA-compressed to `<name>.db.xz`,
   then the plain `.db` is removed. Today's file stays uncompressed and live
   for ingestion. (nmrbox_audit_query.py reads either form transparently.)

This script is normally launched by auditd via /etc/audit/plugins.d/nmrbox.conf
and runs as root. It can also be run by hand against a saved log with --replay
for testing or backfill.

Requires Python >= 3.12.
"""

import argparse
import logging
import logging.handlers
import lzma
import os
import re
import select
import signal
import sqlite3
import sys
import time
import yaml
from datetime import datetime, timedelta
from pathlib import Path

# This does not run in usage_audit virtual environment
DEFAULT_CONFIG = "/etc/nmrbox.d/nmrbox_audit.yaml"


# --- tuning knobs -----------------------------------------------------------
COMMIT_EVERY_ROWS = 500       # flush the insert batch after this many events
COMMIT_EVERY_SECS = 2.0       # ...or after this long, whichever comes first
EVENT_IDLE_FLUSH = 0.75       # finalize a held-open event after this idle gap
READ_TIMEOUT = 1.0            # select() timeout; also the housekeeping cadence
SQLITE_PAGE_SIZE = 16384      # bigger pages pack long path strings efficiently

# Keys whose unquoted values may be hex-encoded by the kernel.
_HEXABLE = {"name", "proctitle", "cwd", "exe", "comm"}
_HEX_RE = re.compile(r"\A[0-9A-Fa-f]+\Z")

# type=SYSCALL msg=audit(1750000000.123:4567): <fields...>
_HEAD_RE = re.compile(r"\Atype=(\S+)\s+msg=audit\(([\d.]+):(\d+)\):\s*(.*)\Z")

# Filter constants
UNSET_AUID = 4294967295  # -1 as u32: login uid not set (daemons, kernel threads)
SYSTEM_UID_THRESHOLD = 1000

log = logging.getLogger("nmrbox-audit")


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def _as_int(value, default=None):
    """Coerce YAML 16_384 / "16_384" / 16384 all to int, tolerantly."""
    if value is None:
        return default
    try:
        return int(str(value).replace("_", "").strip())
    except (TypeError, ValueError):
        return default


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    store = str(raw.get("store", "/accountinglogs/"))
    cfg = {
        "store": store,
        "monitor": list(raw.get("monitor", [])),
        "min_auid": _as_int(raw.get("min_auid"), 30001),
        "combine_seconds": _as_int(raw.get("combine seconds"), 0),
        "ignore_uids": frozenset(
            u for u in (_as_int(x) for x in (raw.get("ignore uids") or []))
            if u is not None),
        "seal_compress": bool(raw.get("seal_compress", True)),
        "log_level": str(raw.get("log level", "INFO")).upper(),
    }
    return cfg


# --------------------------------------------------------------------------- #
# Audit record parsing
# --------------------------------------------------------------------------- #
def _tokenize(rest: str) -> dict[str, tuple[str, bool]]:
    """Split 'a=1 b="two words" c=3' -> {a:(1,False), b:(two words,True), ...}.

    The bool is True when the value was double-quoted.
    """
    out: dict[str, tuple[str, bool]] = {}
    i, n = 0, len(rest)
    while i < n:
        while i < n and rest[i] == " ":
            i += 1
        if i >= n:
            break
        eq = rest.find("=", i)
        if eq < 0:
            break
        key = rest[i:eq]
        j = eq + 1
        if j < n and rest[j] == '"':
            k = rest.find('"', j + 1)
            if k < 0:
                val, j, quoted = rest[j + 1:], n, True
            else:
                val, j, quoted = rest[j + 1:k], k + 1, True
        else:
            k = j
            while k < n and rest[k] != " ":
                k += 1
            val, j, quoted = rest[j:k], k, False
        out[key] = (val, quoted)
        i = j
    return out


def _text(fields, key):
    pair = fields.get(key)
    if pair is None:
        return None
    val, quoted = pair
    if val in ("(null)", "?", ""):
        return None
    if not quoted and key in _HEXABLE and len(val) % 2 == 0 and _HEX_RE.match(val):
        try:
            decoded = bytes.fromhex(val).decode("utf-8", "replace")
            return decoded.replace("\x00", " ").strip()
        except ValueError:
            return val
    return val


def _intval(fields, key, base=10):
    pair = fields.get(key)
    if pair is None:
        return None
    val = pair[0]
    try:
        return int(val, base)
    except (TypeError, ValueError):
        return None


class Event:
    """Accumulates the records that share one audit(ts:serial) id."""

    __slots__ = ("ts", "serial", "syscall", "success", "auid", "uid", "gid",
                 "pid", "ppid", "ses", "exe", "comm", "key", "proctitle",
                 "cwd", "paths", "last_seen")

    def __init__(self, ts: float, serial: int):
        self.ts = ts
        self.serial = serial
        self.syscall = self.success = self.auid = self.uid = self.gid = None
        self.pid = self.ppid = self.ses = None
        self.exe = self.comm = self.key = self.proctitle = self.cwd = None
        self.paths: list[dict] = []
        self.last_seen = time.monotonic()

    def add(self, rtype: str, fields: dict) -> None:
        self.last_seen = time.monotonic()
        log.debug("event %s:%s record=%s", self.ts, self.serial, rtype)
        if rtype == "SYSCALL":
            self.syscall = _text(fields, "syscall") or (
                fields.get("syscall", ("", False))[0] or None)
            succ = fields.get("success", ("", False))[0]
            self.success = 1 if succ == "yes" else 0 if succ == "no" else None
            self.auid = _intval(fields, "auid")
            self.uid = _intval(fields, "uid")
            self.gid = _intval(fields, "gid")
            self.pid = _intval(fields, "pid")
            self.ppid = _intval(fields, "ppid")
            self.ses = _intval(fields, "ses")
            self.exe = _text(fields, "exe")
            self.comm = _text(fields, "comm")
            self.key = _text(fields, "key")
        elif rtype == "PATH":
            self.paths.append({
                "item": _intval(fields, "item"),
                "name": _text(fields, "name"),
                "nametype": _text(fields, "nametype"),
                "inode": _intval(fields, "inode"),
                "mode": _intval(fields, "mode", 8),
                "ouid": _intval(fields, "ouid"),
                "ogid": _intval(fields, "ogid"),
            })
        elif rtype == "CWD":
            self.cwd = _text(fields, "cwd")
        elif rtype == "PROCTITLE":
            self.proctitle = _text(fields, "proctitle")

    def is_open(self) -> bool:
        """We only persist real file-open syscalls that produced a path."""
        return bool(self.paths) and self.syscall is not None

    def is_filtered(self, ignore_uids: frozenset = frozenset()) -> bool:
        """Return True if event should be ignored.

        Two cases: daemon/kernel activity (auid unset and a system uid), and
        accounts listed under `ignore uids` in the config. The audit rules
        already drop the latter in-kernel; repeating the check here costs a
        set lookup and keeps --replay correct against logs captured before
        the rule existed.
        """
        if (self.auid == UNSET_AUID and
                self.uid is not None and self.uid < SYSTEM_UID_THRESHOLD):
            return True
        return self.auid in ignore_uids or self.uid in ignore_uids

    def __repr__(self) -> str:
        return (f"Event(ts={self.ts}:{self.serial} syscall={self.syscall} "
                f"key={self.key} auid={self.auid} uid={self.uid} "
                f"comm={self.comm} paths={len(self.paths)})")


# --------------------------------------------------------------------------- #
# Per-day SQLite store
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY, v TEXT
);
CREATE TABLE IF NOT EXISTS strings (
    id  INTEGER PRIMARY KEY,
    val TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY,
    ts        REAL    NOT NULL,
    serial    INTEGER NOT NULL,
    auid      INTEGER,
    uid       INTEGER,
    gid       INTEGER,
    pid       INTEGER,
    ppid      INTEGER,
    ses       INTEGER,
    success   INTEGER,
    syscall_id   INTEGER,
    exe_id       INTEGER,
    comm_id      INTEGER,
    key_id       INTEGER,
    cwd_id       INTEGER,
    proctitle_id INTEGER,
    -- How many opens this row stands for: 1 unless the combine window
    -- collapsed repeats of the same path by the same user and program.
    combined  INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS paths (
    event_id    INTEGER NOT NULL,
    item        INTEGER,
    name_id     INTEGER,
    nametype_id INTEGER,
    inode       INTEGER,
    mode        INTEGER,
    ouid        INTEGER,
    ogid        INTEGER
);
CREATE INDEX IF NOT EXISTS ix_events_auid_ts ON events(auid, ts);
CREATE INDEX IF NOT EXISTS ix_paths_event    ON paths(event_id);
CREATE INDEX IF NOT EXISTS ix_paths_name     ON paths(name_id);
"""


class DailyStore:
    def __init__(self, store_dir: Path, day: str, hostname: str):
        self.day = day
        self.path = store_dir / f"nmrbox_audit_{day}.db"
        self.conn = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        self._pragmas()
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.execute(
            "INSERT OR IGNORE INTO meta(k, v) VALUES ('created', ?)",
            (datetime.now().isoformat(timespec="seconds"),))
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('hostname', ?)",
            (hostname,))
        # Caches/counters, rebuilt from disk so we survive a mid-day restart.
        self._strcache: dict[str, int] = dict(
            self.conn.execute("SELECT val, id FROM strings"))
        row = self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()
        self._next_id = int(row[0]) + 1
        self._ev_batch: list[tuple] = []
        self._pa_batch: list[tuple] = []
        self._in_txn = False
        self._last_commit = time.monotonic()

    def _migrate(self) -> None:
        """CREATE TABLE IF NOT EXISTS leaves an existing day's file alone, so
        add columns introduced after it was created."""
        cols = {row[1] for row in self.conn.execute("PRAGMA table_info(events)")}
        if "combined" not in cols:
            log.info("adding events.combined to %s", self.path.name)
            self.conn.execute("ALTER TABLE events "
                              "ADD COLUMN combined INTEGER NOT NULL DEFAULT 1")

    def _pragmas(self) -> None:
        c = self.conn
        c.execute(f"PRAGMA page_size={SQLITE_PAGE_SIZE}")
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA auto_vacuum=INCREMENTAL")
        c.execute("PRAGMA temp_store=MEMORY")

    def _begin(self) -> None:
        if not self._in_txn:
            self.conn.execute("BEGIN")
            self._in_txn = True

    def _intern(self, val):
        if val is None:
            return None
        sid = self._strcache.get(val)
        if sid is not None:
            return sid
        self._begin()
        cur = self.conn.execute("INSERT INTO strings(val) VALUES (?)", (val,))
        sid = int(cur.lastrowid)
        self._strcache[val] = sid
        return sid

    def add(self, ev: Event, combined: int = 1) -> None:
        self._begin()
        eid = self._next_id
        self._next_id += 1
        log.debug("store[%s] add id=%d combined=%d %r", self.day, eid,
                  combined, ev)
        self._ev_batch.append((
            eid, ev.ts, ev.serial, ev.auid, ev.uid, ev.gid, ev.pid, ev.ppid,
            ev.ses, ev.success,
            self._intern(ev.syscall), self._intern(ev.exe),
            self._intern(ev.comm), self._intern(ev.key),
            self._intern(ev.cwd), self._intern(ev.proctitle),
            combined,
        ))
        for p in ev.paths:
            self._pa_batch.append((
                eid, p["item"], self._intern(p["name"]),
                self._intern(p["nametype"]), p["inode"], p["mode"],
                p["ouid"], p["ogid"],
            ))

    def maybe_commit(self, force: bool = False) -> None:
        due = (len(self._ev_batch) >= COMMIT_EVERY_ROWS
               or (time.monotonic() - self._last_commit) >= COMMIT_EVERY_SECS)
        if not (force or due):
            return
        log.debug("store[%s] commit: %d events, %d paths (force=%s)",
                  self.day, len(self._ev_batch), len(self._pa_batch), force)
        if self._ev_batch:
            self.conn.executemany(
                "INSERT INTO events VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", self._ev_batch)
            self._ev_batch.clear()
        if self._pa_batch:
            self.conn.executemany(
                "INSERT INTO paths VALUES (?,?,?,?,?,?,?,?)", self._pa_batch)
            self._pa_batch.clear()
        if self._in_txn:
            self.conn.execute("COMMIT")
            self._in_txn = False
        self._last_commit = time.monotonic()

    def close(self) -> None:
        self.maybe_commit(force=True)
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.conn.execute("PRAGMA optimize")
        except sqlite3.Error as exc:
            log.warning("checkpoint/optimize failed for %s: %s", self.path, exc)
        self.conn.close()

    def seal(self, compress: bool) -> None:
        """Finalize a completed day: VACUUM, then optionally LZMA-compress."""
        log.debug("store[%s] sealing (compress=%s)", self.day, compress)
        try:
            self.conn.execute("VACUUM")
        except sqlite3.Error as exc:
            log.warning("VACUUM failed for %s: %s", self.path, exc)
        self.close()
        if not compress:
            return
        xz_path = self.path.with_suffix(".db.xz")
        try:
            with open(self.path, "rb") as src, \
                    lzma.open(xz_path, "wb", preset=3) as dst:
                while chunk := src.read(1 << 20):
                    dst.write(chunk)
            os.replace(xz_path, xz_path)  # ensure flush to dir entry
            self.path.unlink()
            log.info("sealed %s -> %s", self.path.name, xz_path.name)
        except OSError as exc:
            log.error("compression of %s failed, leaving plain db: %s",
                      self.path, exc)


class StoreManager:
    """Routes each event to the DailyStore for its calendar day and seals
    the prior day when the date advances."""

    def __init__(self, store_dir: Path, hostname: str, seal_compress: bool):
        self.dir = store_dir
        self.hostname = hostname
        self.seal_compress = seal_compress
        self.dir.mkdir(parents=True, exist_ok=True)
        self._stores: dict[str, DailyStore] = {}

    @staticmethod
    def day_of(ts: float) -> str:
        # Local calendar day -- accounting is reported in local time.
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")

    def store_for(self, ts: float) -> DailyStore:
        day = self.day_of(ts)
        st = self._stores.get(day)
        if st is None:
            log.debug("store_for ts=%s -> day=%s (opening new store)", ts, day)
            st = DailyStore(self.dir, day, self.hostname)
            self._stores[day] = st
            log.info("opened %s", st.path.name)
            self._seal_older_than(day)
        else:
            log.debug("store_for ts=%s -> day=%s (existing store)", ts, day)
        return st

    def _seal_older_than(self, current_day: str) -> None:
        for day in sorted(d for d in self._stores if d < current_day):
            log.debug("sealing older store day=%s (current=%s)", day, current_day)
            st = self._stores.pop(day)
            st.seal(self.seal_compress)

    def housekeeping(self) -> None:
        for st in self._stores.values():
            st.maybe_commit()

    def shutdown(self) -> None:
        for st in self._stores.values():
            st.close()
        self._stores.clear()


def _next_local_midnight(ts: float) -> float:
    """Epoch seconds of the start of the day after the one containing ts."""
    midnight = datetime.fromtimestamp(ts).replace(
        hour=0, minute=0, second=0, microsecond=0)
    return (midnight + timedelta(days=1)).timestamp()


class Combiner:
    """Collapses repeat opens of the same file into one row with a count.

    The first open of a (user, program, path) starts a window; opens of the
    same triple within `window` seconds only bump its counter. When the window
    closes the event is stored once with the total. This is the one reduction
    the kernel cannot do for us -- audit rules can drop events by uid or path,
    but not "the same thing again" -- and on a busy box repeats are most of
    the volume.

    Cost is a held Event per distinct triple seen in the window, and up to
    `window` seconds of write delay. window <= 0 stores every open as it
    arrives.

    Windows are measured in audit event time, not wall clock, so --replay of a
    saved log combines exactly as the live run would have and does not hoard
    the whole log in memory.
    """

    def __init__(self, mgr: StoreManager, window: int):
        self.mgr = mgr
        self.window = window
        # key -> [event, count, expiry]. Every entry gets the same window and
        # audit timestamps advance, so insertion order is expiry order and
        # sweep() can stop at the first unexpired entry instead of scanning the
        # whole dict. An out-of-order timestamp only delays that entry's flush
        # until the head expires; drain() forces the rest out regardless.
        self._pending: dict[tuple, list] = {}
        self._day_end = 0.0
        self.clock = 0.0        # latest event timestamp seen
        self.combined_away = 0  # repeats never written, for the shutdown log

    @staticmethod
    def _key(ev: Event) -> tuple:
        # pid is deliberately absent: collapsing across the processes of one
        # program is the point. exe/comm are present so two different programs
        # touching one file stay distinguishable.
        return (ev.auid, ev.uid, ev.exe, ev.comm,
                tuple(p["name"] for p in ev.paths))

    def add(self, ev: Event) -> None:
        if self.window <= 0:
            self.mgr.store_for(ev.ts).add(ev)
            return
        self.clock = max(self.clock, ev.ts)
        # Flush before the date advances: store_for() seals the previous day
        # once a new day's store opens, and a held event must land first.
        if ev.ts >= self._day_end:
            self.sweep(force=True)
            self._day_end = _next_local_midnight(ev.ts)
        key = self._key(ev)
        slot = self._pending.get(key)
        if slot is None:
            self._pending[key] = [ev, 1, ev.ts + self.window]
        else:
            slot[1] += 1
            self.combined_away += 1
        self.sweep(self.clock)

    def sweep(self, now: float = 0.0, force: bool = False) -> None:
        """Write out every window that closed at or before `now`."""
        while self._pending:
            key = next(iter(self._pending))
            ev, count, expiry = self._pending[key]
            if not force and expiry > now:
                break
            del self._pending[key]
            log.debug("combine: flushing %r as %d open(s)", ev, count)
            self.mgr.store_for(ev.ts).add(ev, count)


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #
class Pipeline:
    def __init__(self, mgr: StoreManager, combine_seconds: int = 0,
                 ignore_uids: frozenset = frozenset(), live: bool = True):
        self.mgr = mgr
        self.comb = Combiner(mgr, combine_seconds)
        self.ignore_uids = ignore_uids
        self.live = live
        self._open: Event | None = None
        self._open_id: str | None = None

    def feed_line(self, line: str) -> None:
        m = _HEAD_RE.match(line)
        if not m:
            log.debug("feed_line: no match, dropping line: %.200r", line)
            return
        rtype, ts_s, serial_s, rest = m.groups()
        eid = f"{ts_s}:{serial_s}"
        if eid != self._open_id:
            log.debug("feed_line: new event id=%s (was %s), finalizing prior",
                      eid, self._open_id)
            self._finalize_open()
            self._open = Event(float(ts_s), int(serial_s))
            self._open_id = eid
        self._open.add(rtype, _tokenize(rest))

    def _finalize_open(self) -> None:
        ev = self._open
        self._open = None
        self._open_id = None
        if ev is None:
            return
        if not ev.is_open():
            log.debug("finalize: dropped (not open) %r", ev)
            return
        if ev.is_filtered(self.ignore_uids):
            log.debug("finalize: dropped (filtered) %r", ev)
            return
        log.debug("finalize: persisting %r", ev)
        self.comb.add(ev)

    def idle_flush(self) -> None:
        if self._open and (time.monotonic() - self._open.last_seen) > EVENT_IDLE_FLUSH:
            log.debug("idle_flush: flushing stale open event id=%s", self._open_id)
            self._finalize_open()
        # A live stream's timestamps track wall clock, so an idle gap still
        # closes windows. Replaying a saved log advances only with its events.
        self.comb.sweep(time.time() if self.live else self.comb.clock)

    def drain(self) -> None:
        log.debug("drain: finalizing any open event id=%s", self._open_id)
        self._finalize_open()
        self.comb.sweep(force=True)
        if self.comb.window > 0:
            log.info("combining suppressed %d repeat open(s)",
                     self.comb.combined_away)


def setup_logging(level_name: str = "INFO") -> None:
    import stat
    level = logging.getLevelName(level_name)
    if not isinstance(level, int):
        level = logging.INFO
    log.setLevel(level)
    handler: logging.Handler | None = None
    dev_log = "/dev/log"
    try:
        if stat.S_ISSOCK(os.stat(dev_log).st_mode):
            h = logging.handlers.SysLogHandler(address=dev_log)
            h.setFormatter(logging.Formatter(
                "nmrbox-audit[%(process)d]: %(message)s"))
            handler = h
    except OSError:
        handler = None
    if handler is None:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)


def run(stream, mgr: StoreManager, *, is_pipe: bool,
        combine_seconds: int = 0, ignore_uids: frozenset = frozenset()) -> None:
    pipe = Pipeline(mgr, combine_seconds, ignore_uids, live=is_pipe)
    stop = {"flag": False}

    def _sig(_signum, _frame):
        stop["flag"] = True
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    fd = stream.fileno()
    buf = b""
    while not stop["flag"]:
        if is_pipe:
            r, _, _ = select.select([fd], [], [], READ_TIMEOUT)
            if not r:
                pipe.idle_flush()
                mgr.housekeeping()
                continue
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                log.debug("run: EOF on stream")
                break  # EOF
        else:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                log.debug("run: EOF on stream")
                break
        log.debug("run: read %d bytes", len(chunk))
        buf += chunk
        *lines, buf = buf.split(b"\n")
        for raw in lines:
            pipe.feed_line(raw.decode("utf-8", "replace"))
        pipe.idle_flush()
        mgr.housekeeping()

    if buf.strip():
        pipe.feed_line(buf.decode("utf-8", "replace"))
    pipe.drain()
    mgr.shutdown()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=DEFAULT_CONFIG,
                    help=f"YAML config (default {DEFAULT_CONFIG})")
    ap.add_argument("--replay", metavar="AUDIT_LOG",
                    help="process a saved audit.log instead of stdin "
                         "(testing / backfill)")
    args, _unknown = ap.parse_known_args(argv)

    cfg = load_config(args.config)
    setup_logging(cfg["log_level"])
    hostname = os.uname().nodename
    audit_log_dir = Path(cfg["store"])
    mgr = StoreManager(audit_log_dir, hostname, cfg["seal_compress"])
    log.info("collector starting: store=%s seal_compress=%s combine=%ss "
             "ignore_uids=%s log_level=%s",
             audit_log_dir, cfg["seal_compress"], cfg["combine_seconds"],
             sorted(cfg["ignore_uids"]) or "none", cfg["log_level"])

    opts = {"combine_seconds": cfg["combine_seconds"],
            "ignore_uids": cfg["ignore_uids"]}
    if args.replay:
        with open(args.replay, "rb") as fh:
            run(fh, mgr, is_pipe=False, **opts)
    else:
        run(sys.stdin, mgr, is_pipe=True, **opts)
    log.info("collector stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
