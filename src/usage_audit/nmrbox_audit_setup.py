#!/usr/bin/env python3
#!/usr/bin/env -S uv run --script
# /// script
# dependencies = [
#   "requests",
#   "pyyaml",
# ]
# ///
"""nmrbox_audit_setup.py

Install and configure the NMRbox file-open audit pipeline from
/etc/nmrhub.d/nmrbox_audit.yaml.

What it does (idempotently):
  1. Ensures the store directory exists.
  2. Writes /etc/audit/rules.d/40-nmrbox.rules:
       - backlog limit + backlog_wait_time from the config
       - one open/openat/openat2 watch per monitored path (b64 and b32),
         filtered to real NMRbox users (auid >= min_auid) so daemon/root
         activity is dropped in-kernel.
       - exclusions for every account in the config's `ignore uids`, also
         applied in-kernel so those events are never generated at all.
       - a watch on every filesystem mounted underneath a monitored path
         too: audit directory watches do not cross mount points, so e.g.
         /reboxitory's many NFS submounts each need their own watch or
         opens inside them go unaudited.
       - a -F path= watch per Python package __init__.py located by plocate,
         minus the copies that are redundant (already inside a monitored
         subtree), unwanted (under an `exclude paths` prefix), or unloadable
         (parent directory gone). See filter_python_watches.
  3. Installs the collector to /opt/nmrbox.d and registers it as an audisp
     plugin in /etc/audit/plugins.d/nmrbox.conf.
  4. Loads the rules (augenrules --load) and restarts auditd.

Run as root. Use --dry-run to preview without changing anything.

Use --uninstall to reverse the above: removes the rules file, plugin
config, and collector, then reloads auditd. Does not remove auditd /
audispd-plugins (installed via apt) or the log store directory.

Requires Python >= 3.12.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import requests
import yaml
from pathlib import Path

from usage_audit import DEFAULT_CONFIG

RULES_PATH = Path("/etc/audit/rules.d/40-nmrbox.rules")
PLUGIN_PATH = Path("/etc/audit/plugins.d/nmrbox.conf")
AUDITD_CONF_PATH = Path("/etc/audit/auditd.conf")
COLLECTOR_DEST = Path("/opt/nmrbox.d/nmrbox_audit_collector.py")
COLLECTOR_SRC = Path(__file__).resolve().parent / "nmrbox_audit_collector.py"

UNSET_AUID = 4294967295  # -1 as u32: login uid not set (daemons, kernel threads)

# The kernel caps a single audit rule at AUDIT_MAX_FIELDS (64) -F clauses. Each
# of our rules already spends 5 (arch, dir, auid>=, auid!=unset, key) and every
# ignored account costs 2 more (auid!= and uid!=).
AUDIT_MAX_FIELDS = 64
FIXED_RULE_FIELDS = 5

# Sample paths shown per drop reason when reporting the watch filter.
EXAMPLES_PER_REASON = 3

MOUNTS_PATH = Path("/proc/mounts")
_MOUNT_ESCAPE_RE = re.compile(r"\\([0-7]{3})")

# Matches e.g. "-a always,exclude -F msgtype=PATH" (either field order). Some
# hardening baselines add a rule like this to cut audit log volume, which
# silently blinds our watches: the collector needs the PATH record to learn
# which file was opened.
PATH_EXCLUDE_RE = re.compile(r"-a\s+\S*exclude\S*.*-F\s+msgtype=PATH\b", re.IGNORECASE)


def _as_int(value):
    return int(str(value).replace("_", "").strip())


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    audit = raw["audit"]
    return {
        "store": str(raw["store"]),
        "monitor": [str(p).rstrip("/") or "/" for p in raw["monitor"]],
        "min_auid": _as_int(raw["min_auid"]),
        "ignore_uids": sorted({_as_int(u) for u in (raw.get("ignore uids") or [])}),
        "exclude_paths": [str(p).rstrip("/")
                          for p in (raw.get("exclude paths") or [])],
        "backlog_limit": _as_int(audit["backlog_limit"]),
        "wait_time": _as_int(audit["wait_time_us"]),
        "failure_mode": _as_int(audit["failure_mode"]),
        "python_map_url": str(raw["python map url"]),
    }


def fetch_python_map(url: str) -> dict[str, str]:
    """GET {"data": {module: import_name, ...}, "type": "success"} from url."""
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()["data"]


def is_top_level_package(init_file: str, import_name: str) -> bool:
    """True if init_file is the __init__.py of a top-level `import_name`.

    plocate matches a substring of the whole path, so querying
    "numpy/__init__.py" also returns:

      numpy/__init__.pyi                    type stubs -- the query is a
                                            prefix of the .pyi name
      uncertainties/unumpy/__init__.py      directory merely *ends* in numpy
      pandas/compat/numpy/__init__.py       a nested subpackage
      sklearn/externals/_scipy/__init__.py  a vendored copy

    Attributing those to the mapped package inflates precisely the popular
    ones: every pandas import would score as numpy usage, every sklearn
    import as scipy. Two conditions make a hit genuine -- the path really
    ends in <import_name>/__init__.py, and the directory holding
    <import_name> is not itself a package, so <import_name> is what gets
    imported rather than a submodule of something else.

    An unreadable parent falls through to True, keeping the watch: better a
    watch we did not need than a silently unmonitored package.
    """
    path = Path(init_file)
    if path.name != "__init__.py" or path.parent.name != import_name:
        return False
    return not (path.parent.parent / "__init__.py").exists()


def resolve_python_watches(python_map: dict[str, str]) -> list[tuple[str, str]]:
    """Look up each import's __init__.py in the plocate database and return
    (init file, audit key) pairs.

    Monitored packages live inside NMRbox users' own venvs, not this script's
    environment, so the system-wide plocate database is searched instead of
    importing each package -- this also picks up every user's separate copy
    of a package, not just one. Hits are narrowed to real top-level packages
    by is_top_level_package.

    Installed packages vary from host to host, so a module with no match is
    normal and simply noted; the rest of the modules must still get their
    watches.
    """
    watches = []
    for module, import_name in python_map.items():
        result = subprocess.run(
            ["plocate", "-0", f"{import_name}/__init__.py"],
            capture_output=True, text=True, check=False)
        hits = [p for p in result.stdout.split("\0") if p]
        init_files = [p for p in hits
                      if is_top_level_package(p, import_name)]
        if len(init_files) != len(hits):
            print(f"  {module}: ignored {len(hits) - len(init_files)} nested "
                  f"or non-package plocate hit(s)")
        if not init_files:
            print(f"  note: {import_name} not installed on this host "
                  f"(module {module!r})")
            continue
        key = f"nmrbox_{module}"
        watches.extend((init_file, key) for init_file in init_files)
    return watches


def _device_of(path: Path) -> int | None:
    """st_dev of path, or None if it cannot be stat'ed."""
    try:
        return path.stat().st_dev
    except OSError:
        return None


def filter_python_watches(
        watches: list[tuple[str, str]], monitor: list[str],
        exclude_paths: list[str]) -> tuple[list[tuple[str, str]],
                                           dict[str, list[str]]]:
    """Drop watches that are redundant, unwanted, or would break the rule load.

    plocate indexes the whole filesystem, so resolve_python_watches() returns
    every copy of a package on the box: package build trees, IDE caches, and
    files that already sit inside a monitored subtree. Each one costs rule
    load time and an fsnotify mark on its parent directory, and the redundant
    ones also make `key=` ambiguous -- the -F dir= rule and the -F path= rule
    both match the same open, so which key lands is not something we control.

    Four reasons to drop a watch:
      - it is under an `exclude paths` prefix (build trees, caches);
      - it is already inside a monitored -F dir= subtree *on the same
        filesystem* (see below);
      - its parent directory is gone, so auditctl would reject the rule and
        abort every rule after it in the file. Note this stats the *parent*,
        not the file: audit watches attach to the parent directory, so a
        missing __init__.py still loads and arms itself if the package is
        later (re)installed;
      - a duplicate of a path already emitted, which would otherwise produce
        two rules for one file under different keys.

    Coverage is a device comparison, not a string prefix. A -F dir= rule does
    not cross mount points, so /reboxitory's rule does not see a package on
    the /reboxitory/2026/05 submount -- dropping that path as "covered" on
    the strength of its prefix would leave it watched by nothing at all. A
    path counts as covered only when some monitored directory both prefixes
    it and sits on the same filesystem, which is exactly when that directory's
    rule can reach it. (Two mounts of one filesystem share an st_dev, so a
    bind mount can still read as covered; the expanded monitor list normally
    carries its own rule for such a mount anyway.)

    Returns (kept, dropped) where dropped maps each reason to its paths.
    """
    excluded = tuple(p.rstrip("/") + "/" for p in exclude_paths)
    # A monitored directory we cannot stat covers nothing: keep the watch
    # rather than assume a rule we cannot verify will reach the file.
    covered = [(p.rstrip("/") + "/", dev) for p, dev in
               ((p, _device_of(Path(p))) for p in monitor) if dev is not None]
    kept: list[tuple[str, str]] = []
    dropped: dict[str, list[str]] = {
        "duplicate of an earlier watch": [],
        "under an exclude paths prefix": [],
        "already inside a monitored subtree": [],
        "parent directory missing": [],
    }
    seen: set[str] = set()
    for path, key in watches:
        if path in seen:
            dropped["duplicate of an earlier watch"].append(path)
            continue
        seen.add(path)
        if path.startswith(excluded):
            dropped["under an exclude paths prefix"].append(path)
            continue
        parent = Path(path).parent
        parent_dev = _device_of(parent) if parent.is_dir() else None
        if parent_dev is None:
            dropped["parent directory missing"].append(path)
        elif any(path.startswith(prefix) and parent_dev == dev
                 for prefix, dev in covered):
            dropped["already inside a monitored subtree"].append(path)
        else:
            kept.append((path, key))
    return kept, dropped


def _key_for(path: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")
    return f"nmrbox_{slug}"[:60]


def read_mount_points() -> list[str]:
    """Return every mount point currently in the mount table."""
    try:
        lines = MOUNTS_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    points = []
    for line in lines:
        fields = line.split()
        if len(fields) < 2:
            continue
        # /proc/mounts octal-escapes spaces/tabs/newlines/backslashes in paths.
        points.append(_MOUNT_ESCAPE_RE.sub(
            lambda m: chr(int(m.group(1), 8)), fields[1]))
    return points


def expand_monitor_paths(monitor: list[str], mount_points: list[str]) -> list[str]:
    """Add a watch target for every filesystem mounted underneath each
    monitored path.

    Audit directory watches (-F dir=) do not cross mount points -- a watch
    on /reboxitory does not see opens inside /reboxitory/data/alphafold/1.0
    if that's a separate (e.g. NFS) mount. Without an explicit watch on each
    nested mount, files opened there are silently unaudited.
    """
    expanded = []
    seen = set()
    for path in monitor:
        if path not in seen:
            expanded.append(path)
            seen.add(path)
        prefix = path.rstrip("/") + "/"
        for mp in sorted(set(mount_points)):
            if mp not in seen and mp.startswith(prefix):
                expanded.append(mp)
                seen.add(mp)
    return expanded


def build_ignore_fields(ignore_uids: list[int]) -> str:
    """Render the -F clauses that drop an ignored account's opens in-kernel.

    Excluding here rather than in the collector means the event is never
    generated: no backlog pressure, no audispd pipe traffic, no parse. Both
    auid and uid are excluded so the account is ignored whether it shows up
    as a login session or as a daemon identity (auid unset). Clauses on one
    rule are AND-ed, so the event is dropped if either field matches.
    """
    if not ignore_uids:
        return ""
    needed = FIXED_RULE_FIELDS + 2 * len(ignore_uids)
    if needed > AUDIT_MAX_FIELDS:
        raise ValueError(
            f"{len(ignore_uids)} ignored uids need {needed} rule fields, over "
            f"the kernel's limit of {AUDIT_MAX_FIELDS}; auditctl would reject "
            f"the rule. Drop to at most "
            f"{(AUDIT_MAX_FIELDS - FIXED_RULE_FIELDS) // 2} entries.")
    return "".join(f" -F auid!={uid} -F uid!={uid}" for uid in ignore_uids)


def build_rules(cfg: dict) -> str:
    lines = [
        "# Managed by nmrbox_audit_setup.py -- edits will be overwritten.",
        "# Source: NMRbox audit YAML configuration.",
        "",
        f"-b {cfg['backlog_limit']}",
        f"--backlog_wait_time {cfg['wait_time']}",
        f"-f {cfg['failure_mode']}",
        "",
    ]
    floor = cfg["min_auid"]
    ignored = build_ignore_fields(cfg["ignore_uids"])
    for path in cfg["monitor"]:
        key = _key_for(path)
        for arch in ("b64", "b32"):
            lines.append(
                f"-a always,exit -F arch={arch} -S open,openat,openat2 "
                f"-F dir={path} -F auid>={floor} -F auid!={UNSET_AUID}"
                f"{ignored} -F key={key}")
        lines.append("")
    for path, key in cfg["python_watches"]:
        for arch in ("b64", "b32"):
            lines.append(
                f"-a always,exit -F arch={arch} -S open,openat,openat2 "
                f"-F path={path} -F auid>={floor} -F auid!={UNSET_AUID}"
                f"{ignored} -F key={key}")
        lines.append("")
    return "\n".join(lines) + "\n"


def build_plugin_conf(config_path: str) -> str:
    return (
        "# Managed by nmrbox_audit_setup.py\n"
        "active = yes\n"
        "direction = out\n"
        f"path = {COLLECTOR_DEST}\n"
        "type = always\n"
        "format = string\n"
        f"args = --config {config_path}\n"
    )


def update_auditd_conf(audit_log_path: Path, dry: bool) -> None:
    """Update /etc/audit/auditd.conf to set log_file to audit subdirectory."""
    if not AUDITD_CONF_PATH.exists():
        print(f"  {AUDITD_CONF_PATH} does not exist (will be created by auditd)")
        return

    try:
        content = AUDITD_CONF_PATH.read_text(encoding="utf-8")
    except Exception as e:
        print(f"  warning: could not read {AUDITD_CONF_PATH}: {e}")
        return

    # Update log_file line (case-insensitive, strip whitespace)
    lines = content.splitlines(keepends=True)
    updated = False
    new_lines = []
    log_file_str = f"log_file = {audit_log_path}/audit.log"

    for line in lines:
        # Match "log_file = ..." (case-insensitive, skip comments)
        if line.strip() and not line.strip().startswith("#"):
            stripped = line.split("#")[0].strip()
            if stripped.lower().startswith("log_file"):
                new_lines.append(log_file_str + "\n")
                updated = True
                continue
        new_lines.append(line)

    if not updated:
        # If no existing log_file line, append it
        new_lines.append(log_file_str + "\n")
        updated = True

    new_content = "".join(new_lines)
    if new_content != content:
        _write(AUDITD_CONF_PATH, new_content, 0o640, dry)
    else:
        print(f"  {AUDITD_CONF_PATH} already correct")


# --------------------------------------------------------------------------- #
def _run(cmd: list[str], dry: bool) -> int:
    print("  $", " ".join(cmd))
    if dry:
        return 0
    return subprocess.run(cmd, check=False).returncode


def _write(path: Path, content: str, mode: int, dry: bool) -> None:
    print(f"  write {path} (mode {mode:o})")
    if dry:
        print("    " + content.replace("\n", "\n    ").rstrip())
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def ensure_auditd(dry: bool) -> None:
    if shutil.which("auditctl") and shutil.which("augenrules"):
        return
    raise ValueError("audit not installed")


def ensure_pyyaml_runtime(dry: bool) -> None:
    # The collector runs under auditd's environment and needs PyYAML too.
    try:
        import yaml  # noqa: F401
        print("python3-yaml available")
    except ModuleNotFoundError:
        raise ValueError("python3-yaml not installed")


def find_path_exclusions() -> list[str]:
    """Return audit rule lines (from rules.d and the currently loaded rule
    set) that exclude msgtype=PATH. Our watches are useless without it."""
    hits: list[str] = []

    rules_dir = Path("/etc/audit/rules.d")
    if rules_dir.is_dir():
        for rules_file in sorted(rules_dir.glob("*.rules")):
            if rules_file == RULES_PATH:
                continue  # ours never excludes PATH
            try:
                lines = rules_file.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in lines:
                if PATH_EXCLUDE_RE.search(line):
                    hits.append(f"{rules_file}: {line.strip()}")

    if shutil.which("auditctl"):
        result = subprocess.run(["auditctl", "-l"], capture_output=True,
                                 text=True, check=False)
        for line in result.stdout.splitlines():
            if PATH_EXCLUDE_RE.search(line):
                hits.append(f"auditctl -l: {line.strip()}")

    return hits


def ensure_path_not_excluded(dry: bool) -> None:
    hits = find_path_exclusions()
    if not hits:
        print("PATH records not excluded")
        return
    print("  found rule(s) excluding PATH records:")
    for hit in hits:
        print(f"    {hit}")
    raise ValueError(
        "an existing audit rule excludes msgtype=PATH; NMRbox watches rely "
        "on PATH records to capture the file name being opened. Remove the "
        "exclude rule and re-run setup.")


def _remove(path: Path, dry: bool) -> None:
    if not path.exists():
        print(f"  skip {path} (not present)")
        return
    print(f"  remove {path}")
    if not dry:
        path.unlink()


def uninstall(dry: bool, no_restart: bool) -> int:
    """Reverse the file/rule changes made by setup. Leaves apt packages alone."""
    print("uninstalling NMRbox audit pipeline\n")

    _remove(RULES_PATH, dry)
    _remove(PLUGIN_PATH, dry)
    _remove(COLLECTOR_DEST, dry)

    collector_dir = COLLECTOR_DEST.parent
    if collector_dir.exists() and not any(collector_dir.iterdir()):
        print(f"  rmdir {collector_dir}")
        if not dry:
            collector_dir.rmdir()

    if no_restart:
        print("\n--no-restart: skipping rule reload and auditd restart")
        return 0

    print("\nreloading rules and restarting auditd")
    _run(["augenrules", "--load"], dry)
    rc = _run(["systemctl", "restart", "auditd"], dry)
    if rc != 0 and not dry:
        print("  systemctl restart failed; trying 'service auditd restart'")
        _run(["service", "auditd", "restart"], dry)

    print("\nDone.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would change, make no changes")
    ap.add_argument("--no-restart", action="store_true",
                    help="configure but do not load rules / restart auditd")
    ap.add_argument("--uninstall", action="store_true",
                    help="remove the rules, plugin config, and collector "
                         "installed by a prior run, then reload auditd. "
                         "Does not remove apt packages or the log store.")
    args = ap.parse_args(argv)

    if os.geteuid() != 0 and not args.dry_run:
        sys.stderr.write("must run as root (or use --dry-run)\n")
        return 1

    if args.uninstall:
        return uninstall(args.dry_run, args.no_restart)

    cfg = load_config(args.config)
    configured_monitor = cfg["monitor"]
    cfg["monitor"] = expand_monitor_paths(configured_monitor, read_mount_points())
    nested_mounts = [p for p in cfg["monitor"] if p not in configured_monitor]

    python_map = fetch_python_map(cfg["python_map_url"])
    found = resolve_python_watches(python_map)
    cfg["python_watches"], dropped = filter_python_watches(
        found, cfg["monitor"], cfg["exclude_paths"])

    print(f"config: {args.config}")
    print(f"  store        = {cfg['store']}")
    print(f"  monitor      = {configured_monitor}")
    print(f"  python_map   = {cfg['python_map_url']} "
          f"({len(cfg['python_watches'])} watches / {len(python_map)} modules)")
    if len(cfg["python_watches"]) != len(found):
        print(f"  + filtered {len(found)} plocate hits down to "
              f"{len(cfg['python_watches'])} watches:")
        for reason, paths in dropped.items():
            if not paths:
                continue
            print(f"      {len(paths):>6} {reason}")
            for example in paths[:EXAMPLES_PER_REASON]:
                print(f"             e.g. {example}")
            if len(paths) > EXAMPLES_PER_REASON:
                print(f"             ... and "
                      f"{len(paths) - EXAMPLES_PER_REASON} more")
    if nested_mounts:
        print(f"  + nested mounts watched separately ({len(nested_mounts)}):")
        for mp in nested_mounts:
            print(f"      {mp}")
    print(f"  min_auid     = {cfg['min_auid']}")
    print(f"  ignore uids  = {cfg['ignore_uids'] or 'none'}")
    print(f"  backlog_limit= {cfg['backlog_limit']}")
    print(f"  wait_time    = {cfg['wait_time']}  (~{cfg['wait_time']/1000:.0f} ms)")
    print()

    if not COLLECTOR_SRC.exists():
        sys.stderr.write(f"collector not found next to setup: {COLLECTOR_SRC}\n")
        return 1

    ensure_auditd(args.dry_run)
    ensure_pyyaml_runtime(args.dry_run)
    ensure_path_not_excluded(args.dry_run)

    # Audit log directory: <store>/audit/, root-owned, not world-readable.
    audit_log_dir = Path(cfg["store"]) / "audit"
    print(f"ensure audit log dir {audit_log_dir}")
    if not args.dry_run:
        audit_log_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(audit_log_dir, 0o750)

    # Configure auditd to log to the audit subdirectory.
    print(f"update auditd.conf log_file")
    update_auditd_conf(audit_log_dir, args.dry_run)

    # Install collector.
    print(f"install collector -> {COLLECTOR_DEST}")
    if not args.dry_run:
        COLLECTOR_DEST.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(COLLECTOR_SRC, COLLECTOR_DEST)
        os.chmod(COLLECTOR_DEST, 0o755)

    # Check if rules have changed to avoid reloading unchanged rules
    new_rules = build_rules(cfg)
    rules_unchanged = False
    if RULES_PATH.exists() and not args.dry_run:
        try:
            existing_rules = RULES_PATH.read_text(encoding="utf-8")
            if existing_rules == new_rules:
                rules_unchanged = True
                print("NMRbox audit rules unchanged")
        except Exception:
            pass

    _write(RULES_PATH, new_rules, 0o640, args.dry_run)
    _write(PLUGIN_PATH, build_plugin_conf(args.config), 0o640, args.dry_run)

    if args.no_restart:
        print("\n--no-restart: skipping rule load and auditd restart")
        return 0

    if rules_unchanged:
        print("audit.rules reload skipped (rules unchanged)")
        return 0

    print("\nloading rules and restarting auditd")
    _run(["augenrules", "--load"], args.dry_run)
    rc = _run(["systemctl", "restart", "auditd"], args.dry_run)
    if rc != 0 and not args.dry_run:
        print("  systemctl restart failed; trying 'service auditd restart'")
        _run(["service", "auditd", "restart"], args.dry_run)

    if not args.dry_run:
        print("\ncurrent audit status:")
        subprocess.run(["auditctl", "-s"], check=False)
        print("\nloaded NMRbox rules:")
        subprocess.run("auditctl -l | grep -F nmrbox || true",
                       shell=True, check=False)
    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
