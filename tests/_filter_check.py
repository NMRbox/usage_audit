# /// script
# requires-python = ">=3.12"
# dependencies = ["pyyaml"]
# ///
"""Checks for the two watch filters in nmrbox_audit_setup.

is_top_level_package is exercised against a synthetic package tree that
reproduces the six wrong attributions found in the production rule set, so
the result does not depend on what happens to be installed here.

filter_python_watches is exercised against real mount boundaries: /proc is
always a separate filesystem from /, standing in for the /reboxitory
submount case without needing root or a test mount.
"""
import argparse
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
from usage_audit.nmrbox_audit_setup import (
    _device_of, filter_python_watches, is_top_level_package)

RULE_RE = re.compile(r" -F path=(\S+) .*? -F key=(\S+)")

# Package dirs to create; each gets an __init__.py.
TREE = [
    "numpy", "seaborn", "Bio", "prody", "pdbtools", "pynmrstar_parser",
    "scipy", "pandas", "pandas/compat", "pandas/compat/numpy",
    "uncertainties", "uncertainties/unumpy",
    "sklearn", "sklearn/externals", "sklearn/externals/_scipy",
    "astropy", "astropy/io", "astropy/io/misc", "astropy/io/misc/pandas",
    "hypothesis", "hypothesis/extra", "hypothesis/extra/pandas",
]

# (path relative to site-packages, import_name, should be watched)
CASES = [
    # The six wrong attributions, in production right now.
    ("numpy/__init__.pyi", "numpy", False),
    ("uncertainties/unumpy/__init__.py", "numpy", False),
    ("pandas/compat/numpy/__init__.py", "numpy", False),
    ("sklearn/externals/_scipy/__init__.py", "scipy", False),
    ("astropy/io/misc/pandas/__init__.py", "pandas", False),
    ("hypothesis/extra/pandas/__init__.py", "pandas", False),
    # The genuine top-level packages must survive.
    ("numpy/__init__.py", "numpy", True),
    ("pandas/__init__.py", "pandas", True),
    ("scipy/__init__.py", "scipy", True),
    ("Bio/__init__.py", "Bio", True),
    ("seaborn/__init__.py", "seaborn", True),
    ("prody/__init__.py", "prody", True),
    ("pdbtools/__init__.py", "pdbtools", True),
    ("pynmrstar_parser/__init__.py", "pynmrstar_parser", True),
]


def check(name, got, want):
    ok = got == want
    detail = "" if ok else f"  (got {got!r}, want {want!r})"
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{detail}")
    return ok


def package_tests() -> bool:
    ok = True
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "lib" / "python3.12" / "site-packages"
        for pkg in TREE:
            d = root / pkg
            d.mkdir(parents=True, exist_ok=True)
            (d / "__init__.py").touch()
        (root / "numpy" / "__init__.pyi").touch()

        for rel, import_name, want in CASES:
            got = is_top_level_package(str(root / rel), import_name)
            ok &= check(f"{rel} as {import_name}", got, want)
    return bool(ok)


def mount_boundary_tests() -> bool:
    root_dev = _device_of(Path("/"))
    proc_dev = _device_of(Path("/proc/self"))
    print(f"  st_dev: / = {root_dev}, /proc/self = {proc_dev}")
    if root_dev == proc_dev:
        print("  SKIP: /proc shares a device with /; cannot test boundaries")
        return True

    ok = True
    # Nested mount: prefixed by "/" but on another filesystem, so dir=/
    # cannot reach it. Must be KEPT.
    kept, dropped = filter_python_watches(
        [("/proc/self/environ", "nmrbox_x")], ["/"], [])
    ok &= check("nested mount kept", [p for p, _ in kept],
                ["/proc/self/environ"])
    ok &= check("nested mount not called covered",
                dropped["already inside a monitored subtree"], [])
    # Same filesystem: dir=/ does reach it, so it is genuinely redundant.
    _, dropped = filter_python_watches(
        [("/etc/hostname", "nmrbox_x")], ["/"], [])
    ok &= check("same-fs path dropped as covered",
                dropped["already inside a monitored subtree"],
                ["/etc/hostname"])
    # Monitoring the nested mount itself does cover it.
    _, dropped = filter_python_watches(
        [("/proc/self/environ", "nmrbox_x")], ["/", "/proc"], [])
    ok &= check("explicit submount rule covers it",
                dropped["already inside a monitored subtree"],
                ["/proc/self/environ"])
    # Exclude wins over everything.
    _, dropped = filter_python_watches(
        [("/proc/self/environ", "nmrbox_x")], ["/proc"], ["/proc"])
    ok &= check("exclude takes precedence",
                dropped["under an exclude paths prefix"],
                ["/proc/self/environ"])
    # Missing parent is reported, not silently kept.
    _, dropped = filter_python_watches(
        [("/nonexistent-dir-xyz/pkg/__init__.py", "nmrbox_x")], ["/"], [])
    ok &= check("missing parent dropped",
                dropped["parent directory missing"],
                ["/nonexistent-dir-xyz/pkg/__init__.py"])
    # Duplicates collapse.
    kept, _ = filter_python_watches(
        [("/proc/self/environ", "nmrbox_a"),
         ("/proc/self/environ", "nmrbox_b")], ["/"], [])
    ok &= check("duplicate collapsed", len(kept), 1)
    return bool(ok)


def replay(rules: str, config: str) -> None:
    import yaml
    cfg = yaml.safe_load(Path(config).read_text())
    seen, watches = set(), []
    for line in Path(rules).read_text().splitlines():
        m = RULE_RE.search(line)
        if m and m.group(1) not in seen:      # collapse the b64/b32 pair
            seen.add(m.group(1))
            watches.append((m.group(1), m.group(2)))
    monitor = [str(p).rstrip("/") for p in cfg["monitor"]]
    exclude = [str(p).rstrip("/") for p in (cfg.get("exclude paths") or [])]
    kept, dropped = filter_python_watches(watches, monitor, exclude)
    print(f"\nreplay of {rules}:")
    print(f"  input   {len(watches):>5} unique paths")
    for reason, paths in dropped.items():
        print(f"  dropped {len(paths):>5} {reason}")
    print(f"  kept    {len(kept):>5} paths -> {len(kept) * 2} rules")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rules", default="40-nmrbox.rules")
    ap.add_argument("--config", default="nmrbox_audit.yaml")
    args = ap.parse_args()

    print("top-level package tests:")
    ok = package_tests()
    print("mount-boundary tests:")
    ok &= mount_boundary_tests()
    replay(args.rules, args.config)
    print("\nOK" if ok else "\nFAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
