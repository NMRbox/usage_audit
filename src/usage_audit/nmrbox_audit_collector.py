#!/usr/bin/env python3
"""nmrbox_audit_collector.py

audisp plugin that consumes the auditd event stream (format=string on stdin),
correlates the multi-record events (SYSCALL + PATH + CWD + PROCTITLE) emitted
for open/openat/openat2, and writes them into a per-calendar-day SQLite file in
the configured store directory.

Compression strategy
--------------------
Two layers, both pure stdlib:

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

from __future__ import annotations

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
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    sys.stderr.write("PyYAML is required (apt-get install -y python3-yaml)\n")
    raise

DEFAULT_CONFIG = "/etc/nmrhub.d/nmrbox_audit.yaml"

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
        "seal_compress": bool(raw.get("seal_compress", True)),
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
    proctitle_id INTEGER
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

    def add(self, ev: Event) -> None:
        self._begin()
        eid = self._next_id
        self._next_id += 1
        self._ev_batch.append((
            eid, ev.ts, ev.serial, ev.auid, ev.uid, ev.gid, ev.pid, ev.ppid,
            ev.ses, ev.success,
            self._intern(ev.syscall), self._intern(ev.exe),
            self._intern(ev.comm), self._intern(ev.key),
            self._intern(ev.cwd), self._intern(ev.proctitle),
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
        if self._ev_batch:
            self.conn.executemany(
                "INSERT INTO events VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", self._ev_batch)
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
            st = DailyStore(self.dir, day, self.hostname)
            self._stores[day] = st
            log.info("opened %s", st.path.name)
            self._seal_older_than(day)
        return st

    def _seal_older_than(self, current_day: str) -> None:
        for day in sorted(d for d in self._stores if d < current_day):
            st = self._stores.pop(day)
            st.seal(self.seal_compress)

    def housekeeping(self) -> None:
        for st in self._stores.values():
            st.maybe_commit()

    def shutdown(self) -> None:
        for st in self._stores.values():
            st.close()
        self._stores.clear()


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #
class Pipeline:
    def __init__(self, mgr: StoreManager):
        self.mgr = mgr
        self._open: Event | None = None
        self._open_id: str | None = None

    def feed_line(self, line: str) -> None:
        m = _HEAD_RE.match(line)
        if not m:
            return
        rtype, ts_s, serial_s, rest = m.groups()
        eid = f"{ts_s}:{serial_s}"
        if eid != self._open_id:
            self._finalize_open()
            self._open = Event(float(ts_s), int(serial_s))
            self._open_id = eid
        self._open.add(rtype, _tokenize(rest))

    def _finalize_open(self) -> None:
        ev = self._open
        self._open = None
        self._open_id = None
        if ev is None or not ev.is_open():
            return
        self.mgr.store_for(ev.ts).add(ev)

    def idle_flush(self) -> None:
        if self._open and (time.monotonic() - self._open.last_seen) > EVENT_IDLE_FLUSH:
            self._finalize_open()

    def drain(self) -> None:
        self._finalize_open()


def setup_logging() -> None:
    import stat
    log.setLevel(logging.INFO)
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


def run(stream, mgr: StoreManager, *, is_pipe: bool) -> None:
    pipe = Pipeline(mgr)
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
                break  # EOF
        else:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
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

    setup_logging()
    cfg = load_config(args.config)
    hostname = os.uname().nodename
    mgr = StoreManager(Path(cfg["store"]), hostname, cfg["seal_compress"])
    log.info("collector starting: store=%s seal_compress=%s",
             cfg["store"], cfg["seal_compress"])

    if args.replay:
        with open(args.replay, "rb") as fh:
            run(fh, mgr, is_pipe=False)
    else:
        run(sys.stdin, mgr, is_pipe=True)
    log.info("collector stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
