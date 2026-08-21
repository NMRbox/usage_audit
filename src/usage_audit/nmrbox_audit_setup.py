#!/usr/bin/env python3
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
       - a watch on every filesystem mounted underneath a monitored path
         too: audit directory watches do not cross mount points, so e.g.
         /reboxitory's many NFS submounts each need their own watch or
         opens inside them go unaudited.
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
import yaml 
from pathlib import Path

from usage_audit import DEFAULT_CONFIG

RULES_PATH = Path("/etc/audit/rules.d/40-nmrbox.rules")
PLUGIN_PATH = Path("/etc/audit/plugins.d/nmrbox.conf")
AUDITD_CONF_PATH = Path("/etc/audit/auditd.conf")
COLLECTOR_DEST = Path("/opt/nmrbox.d/nmrbox_audit_collector.py")
COLLECTOR_SRC = Path(__file__).resolve().parent / "nmrbox_audit_collector.py"

UNSET_AUID = 4294967295  # -1 as u32: login uid not set (daemons, kernel threads)

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
        "backlog_limit": _as_int(audit["backlog_limit"]),
        "wait_time": _as_int(audit["wait_time_us"]),
        "failure_mode": _as_int(audit["failure_mode"]),
    }


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
    for path in cfg["monitor"]:
        key = _key_for(path)
        for arch in ("b64", "b32"):
            lines.append(
                f"-a always,exit -F arch={arch} -S open,openat,openat2 "
                f"-F dir={path} -F auid>={floor} -F auid!={UNSET_AUID} "
                f"-F key={key}")
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

    print(f"config: {args.config}")
    print(f"  store        = {cfg['store']}")
    print(f"  monitor      = {configured_monitor}")
    if nested_mounts:
        print(f"  + nested mounts watched separately ({len(nested_mounts)}):")
        for mp in nested_mounts:
            print(f"      {mp}")
    print(f"  min_auid     = {cfg['min_auid']}")
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
