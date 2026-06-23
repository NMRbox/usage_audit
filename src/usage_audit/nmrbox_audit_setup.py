#!/usr/bin/env python3
"""nmrbox_audit_setup.py

Install and configure the NMRbox file-open audit pipeline from
/etc/nmrhub.d/nmrbox_audit.yaml.

What it does (idempotently):
  1. Ensures auditd is installed (apt) and the store directory exists.
  2. Writes /etc/audit/rules.d/40-nmrbox.rules:
       - backlog limit + backlog_wait_time from the config
       - one open/openat/openat2 watch per monitored path (b64 and b32),
         filtered to real NMRbox users (auid >= min_auid) so daemon/root
         activity is dropped in-kernel.
  3. Installs the collector to /usr/local/bin and registers it as an audisp
     plugin in /etc/audit/plugins.d/nmrbox.conf.
  4. Loads the rules (augenrules --load) and restarts auditd.

Run as root. Use --dry-run to preview without changing anything.
Requires Python >= 3.12.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_CONFIG = "/etc/nmrhub.d/nmrbox_audit.yaml"
RULES_PATH = Path("/etc/audit/rules.d/40-nmrbox.rules")
PLUGIN_PATH = Path("/etc/audit/plugins.d/nmrbox.conf")
COLLECTOR_DEST = Path("/usr/local/bin/nmrbox_audit_collector.py")
COLLECTOR_SRC = Path(__file__).resolve().parent / "nmrbox_audit_collector.py"

UNSET_AUID = 4294967295  # -1 as u32: login uid not set (daemons, kernel threads)


def _as_int(value, default):
    try:
        return int(str(value).replace("_", "").strip())
    except (TypeError, ValueError):
        return default


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    audit = raw.get("audit", {}) or {}
    return {
        "store": str(raw.get("store", "/accountinglogs/")),
        "monitor": [str(p).rstrip("/") or "/" for p in raw.get("monitor", [])],
        "min_auid": _as_int(raw.get("min_auid"), 30001),
        "backlog_limit": _as_int(audit.get("backlog_limit"), 16384),
        "wait_time": _as_int(audit.get("wait_time_us"), 120000),
        "failure_mode": _as_int(audit.get("failure_mode"), 1),
    }


def _key_for(path: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")
    return f"nmrbox_{slug}"[:60]


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
        print("auditd already installed")
        return
    print("installing auditd")
    _run(["apt-get", "update"], dry)
    _run(["apt-get", "install", "-y", "auditd", "audispd-plugins"], dry)


def ensure_pyyaml_runtime(dry: bool) -> None:
    # The collector runs under auditd's environment and needs PyYAML too.
    try:
        import yaml  # noqa: F401
        print("python3-yaml available")
    except ModuleNotFoundError:
        print("installing python3-yaml")
        _run(["apt-get", "install", "-y", "python3-yaml"], dry)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would change, make no changes")
    ap.add_argument("--no-restart", action="store_true",
                    help="configure but do not load rules / restart auditd")
    args = ap.parse_args(argv)

    if os.geteuid() != 0 and not args.dry_run:
        sys.stderr.write("must run as root (or use --dry-run)\n")
        return 1

    cfg = load_config(args.config)
    print(f"config: {args.config}")
    print(f"  store        = {cfg['store']}")
    print(f"  monitor      = {cfg['monitor']}")
    print(f"  min_auid     = {cfg['min_auid']}")
    print(f"  backlog_limit= {cfg['backlog_limit']}")
    print(f"  wait_time    = {cfg['wait_time']}  (~{cfg['wait_time']/1000:.0f} ms)")
    print()

    if not COLLECTOR_SRC.exists():
        sys.stderr.write(f"collector not found next to setup: {COLLECTOR_SRC}\n")
        return 1

    ensure_auditd(args.dry_run)
    ensure_pyyaml_runtime(args.dry_run)

    # Store directory: root-owned, not world-readable (paths can be sensitive).
    print(f"ensure store dir {cfg['store']}")
    if not args.dry_run:
        Path(cfg["store"]).mkdir(parents=True, exist_ok=True)
        os.chmod(cfg["store"], 0o750)

    # Install collector.
    print(f"install collector -> {COLLECTOR_DEST}")
    if not args.dry_run:
        COLLECTOR_DEST.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(COLLECTOR_SRC, COLLECTOR_DEST)
        os.chmod(COLLECTOR_DEST, 0o755)

    _write(RULES_PATH, build_rules(cfg), 0o640, args.dry_run)
    _write(PLUGIN_PATH, build_plugin_conf(args.config), 0o640, args.dry_run)

    if args.no_restart:
        print("\n--no-restart: skipping rule load and auditd restart")
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
