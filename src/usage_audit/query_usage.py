#!/usr/bin/env python3
from usage_audit import DEFAULT_CONFIG

doc  = """nmrbox_audit_query.py

Read the per-day audit databases written by nmrbox_audit_collector.py.
Handles both the live `nmrbox_audit_YYYY-MM-DD.db` and the sealed, LZMA-
compressed `nmrbox_audit_YYYY-MM-DD.db.xz` (decompressed to a temp file on
the fly). Joins the interned string ids back to text.

Examples
--------
  # Everything user 30137 opened on a given day
  nmrbox_audit_query.py --day 2026-06-23 --auid 30137

  # Most-opened files under /reboxitory across all available days
  nmrbox_audit_query.py --path /reboxitory --top 25

  # Per-user open counts for one day
  nmrbox_audit_query.py --day 2026-06-23 --summary

Requires Python >= 3.12.
"""

import argparse
import contextlib
import lzma
import sqlite3
import sys
import tempfile
import yaml
from datetime import datetime
from pathlib import Path

DEFAULT_STORE = "/accountinglogs/"


def store_dir(config_path: str) -> Path:
    if yaml is not None:
        with contextlib.suppress(OSError):
            with open(config_path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            return Path(str(raw.get("store", DEFAULT_STORE)))
    return Path(DEFAULT_STORE)


@contextlib.contextmanager
def open_day(path: Path):
    """Yield a read-only sqlite3 connection for a .db or .db.xz file."""
    if path.suffix == ".xz":
        with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
            with lzma.open(path, "rb") as src:
                while chunk := src.read(1 << 20):
                    tmp.write(chunk)
            tmp.flush()
            conn = sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True)
            try:
                yield conn
            finally:
                conn.close()
    else:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            yield conn
        finally:
            conn.close()


def discover(sd: Path, day: str | None) -> list[Path]:
    if day:
        for ext in (".db", ".db.xz"):
            p = sd / f"nmrbox_audit_{day}{ext}"
            if p.exists():
                return [p]
        return []
    found: dict[str, Path] = {}
    for p in sorted(sd.glob("nmrbox_audit_*.db*")):
        # Prefer the live .db over .db.xz if both somehow exist.
        stem = p.name.split(".db")[0]
        if stem not in found or p.suffix == ".db":
            found[stem] = p
    return list(found.values())


def combined_col(conn, alias: str = "e") -> str:
    """`combined` (opens this row stands for) if the database has it.

    Databases written before the collector combined repeat opens have no such
    column; there every row is exactly one open.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
    return f"{alias}.combined" if "combined" in cols else "1"


BASE = """
SELECT e.ts, e.auid, e.uid,
       se.val AS exe, sc.val AS comm, sy.val AS syscall,
       sn.val AS path, {combined} AS opens
FROM events e
JOIN paths  p  ON p.event_id = e.id
LEFT JOIN strings sn ON sn.id = p.name_id
LEFT JOIN strings se ON se.id = e.exe_id
LEFT JOIN strings sc ON sc.id = e.comm_id
LEFT JOIN strings sy ON sy.id = e.syscall_id
"""


def query_rows(conn, *, auid, path_like, limit):
    where, params = [], []
    if auid is not None:
        where.append("e.auid = ?")
        params.append(auid)
    if path_like:
        where.append("sn.val LIKE ?")
        params.append(f"{path_like}%")
    sql = BASE.format(combined=combined_col(conn))
    sql += ("WHERE " + " AND ".join(where) if where else "")
    sql += " ORDER BY e.ts"
    if limit:
        sql += f" LIMIT {int(limit)}"
    return conn.execute(sql, params).fetchall()


# Every column of an event (interned strings resolved back to text), joined to
# each of its path records. Column order/names drive the --all-fields output.
FULL = """
SELECT e.ts, e.serial, e.auid, e.uid, e.gid, e.pid, e.ppid, e.ses, e.success,
       sy.val  AS syscall,
       se.val  AS exe,
       sc.val  AS comm,
       sk.val  AS key,
       scw.val AS cwd,
       sp.val  AS proctitle,
       {combined} AS opens,
       p.item, sn.val AS name, snt.val AS nametype,
       p.inode, p.mode, p.ouid, p.ogid
FROM events e
JOIN paths  p  ON p.event_id = e.id
LEFT JOIN strings sn  ON sn.id  = p.name_id
LEFT JOIN strings snt ON snt.id = p.nametype_id
LEFT JOIN strings sy  ON sy.id  = e.syscall_id
LEFT JOIN strings se  ON se.id  = e.exe_id
LEFT JOIN strings sc  ON sc.id  = e.comm_id
LEFT JOIN strings sk  ON sk.id  = e.key_id
LEFT JOIN strings scw ON scw.id = e.cwd_id
LEFT JOIN strings sp  ON sp.id  = e.proctitle_id
"""


def query_full(conn, *, auid, path_like, limit):
    where, params = [], []
    if auid is not None:
        where.append("e.auid = ?")
        params.append(auid)
    if path_like:
        where.append("sn.val LIKE ?")
        params.append(f"{path_like}%")
    sql = FULL.format(combined=combined_col(conn))
    sql += ("WHERE " + " AND ".join(where) if where else "")
    sql += " ORDER BY e.ts"
    if limit:
        sql += f" LIMIT {int(limit)}"
    cur = conn.execute(sql, params)
    cols = [d[0] for d in cur.description]
    return cols, cur.fetchall()


def run_listing(paths, args):
    n = opens = 0
    for db in paths:
        with open_day(db) as conn:
            for ts, auid, uid, exe, comm, syscall, path, count in query_rows(
                    conn, auid=args.auid, path_like=args.path, limit=args.limit):
                when = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                repeats = f"  x{count}" if count and count > 1 else ""
                print(f"{when}  auid={auid}  {comm or '-'}  {path}{repeats}")
                n += 1
                opens += count or 1
    extra = f" ({opens} opens)" if opens != n else ""
    print(f"\n{n} event(s){extra}.", file=sys.stderr)


def run_all_fields(paths, args):
    n = 0
    for db in paths:
        with open_day(db) as conn:
            cols, rows = query_full(
                conn, auid=args.auid, path_like=args.path, limit=args.limit)
            width = max(len(c) for c in cols)
            for row in rows:
                if n:
                    print("-" * 40)
                for col, val in zip(cols, row):
                    if col == "ts" and val is not None:
                        val = datetime.fromtimestamp(val).strftime(
                            "%Y-%m-%d %H:%M:%S")
                    print(f"{col:>{width}} = {'' if val is None else val}")
                n += 1
    print(f"\n{n} event(s).", file=sys.stderr)


def run_top(paths, args):
    counts: dict[str, int] = {}
    for db in paths:
        with open_day(db) as conn:
            sql = (f"SELECT sn.val, SUM({combined_col(conn)}) FROM paths p "
                   "JOIN events e ON e.id = p.event_id "
                   "JOIN strings sn ON sn.id = p.name_id ")
            params = []
            if args.path:
                sql += "WHERE sn.val LIKE ? "
                params.append(f"{args.path}%")
            sql += "GROUP BY sn.val"
            for name, c in conn.execute(sql, params):
                if name:
                    counts[name] = counts.get(name, 0) + c
    for name, c in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:args.top]:
        print(f"{c:>9}  {name}")


def run_summary(paths, args):
    counts: dict[int, int] = {}
    for db in paths:
        with open_day(db) as conn:
            for auid, c in conn.execute(
                    f"SELECT auid, SUM({combined_col(conn, 'events')}) "
                    "FROM events GROUP BY auid"):
                counts[auid] = counts.get(auid, 0) + c
    print(f"{'auid':>10}  opens")
    for auid, c in sorted(counts.items(), key=lambda kv: kv[1], reverse=True):
        print(f"{auid:>10}  {c}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=doc,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--store", help="override store dir from config")
    ap.add_argument("--day", help="YYYY-MM-DD (default: all available days)")
    ap.add_argument("--auid", type=int, help="filter by audit/login uid")
    ap.add_argument("--path", help="filter by path prefix")
    ap.add_argument("--limit", type=int, default=0, help="max rows in listing")
    ap.add_argument("--top", type=int, metavar="N",
                    help="show N most-opened files instead of a listing")
    ap.add_argument("--summary", action="store_true",
                    help="per-user open counts instead of a listing")
    ap.add_argument("--all-fields", action="store_true",
                    help="dump every event field (and path fields) per record")
    args = ap.parse_args(argv)

    sd = Path(args.store) if args.store else store_dir(args.config)
    paths = discover(sd, args.day)
    if not paths:
        print(f"no audit databases found in {sd}"
              + (f" for {args.day}" if args.day else ""), file=sys.stderr)
        return 1

    if args.top:
        run_top(paths, args)
    elif args.summary:
        run_summary(paths, args)
    elif args.all_fields:
        run_all_fields(paths, args)
    else:
        run_listing(paths, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
