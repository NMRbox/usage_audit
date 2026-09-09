#!/usr/bin/env python3
#!/usr/bin/env -S uv run --script
# /// script
# dependencies = [
#   "requests",
#   "pyotp",
#   "qrcode[svg]",
#   "pyyaml",
# ]
# ///
import argparse
import collections
import glob
import logging
import os
import re
import subprocess
import tempfile
import venv
from typing import Container

import yaml

from usage_audit import usage_audit_logger

APT_LISTS_GLOB = '/var/lib/apt/lists/*'
NMRBOX_PYTHON3_RE = re.compile(r'Nmrbox-Python3:\s*([A-Za-z0-9_.-]+)(?:==\S+)?')

class PythonMapper:

    def __init__(self,yfile):
        with open(yfile) as f:
            config = yaml.safe_load(f)
        self.modules = config[3]['packages']
        self.modules.extend(self._apt_lists_modules())

    @staticmethod
    def _apt_lists_modules():
        modules = []
        for path in glob.glob(APT_LISTS_GLOB):
            try:
                with open(path, errors='ignore') as f:
                    for line in f:
                        match = NMRBOX_PYTHON3_RE.search(line)
                        if match:
                            modules.append(match.group(1))
            except OSError:
                continue
        return modules

    def map(self,fn=None,skip:Container=frozenset()):
        if fn is None:
            fn = self.payload
        for module in self.modules:
            if module not in skip:
                self._map_module(module, fn)
            else:
                usage_audit_logger.debug(f"skipping {module}")

    def _map_module(self, module, fn):
        with tempfile.TemporaryDirectory() as venv_dir:
            venv.create(venv_dir, with_pip=True)
            python = os.path.join(venv_dir, 'bin', 'python')
            site_packages = self._site_packages(python)

            before = self._init_files(site_packages)
            subprocess.run([python, '-m', 'pip', 'install', '--no-deps', module],
                            check=True, capture_output=True)
            after = self._init_files(site_packages)

            import_names = {self._import_name(site_packages, f) for f in after - before}
            for import_name in sorted(import_names):
                fn(module, import_name)

    @staticmethod
    def _site_packages(python):
        result = subprocess.run(
            [python, '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'],
            check=True, capture_output=True, text=True)
        return result.stdout.strip()

    @staticmethod
    def _init_files(site_packages):
        return set(glob.glob(os.path.join(site_packages, '**', '__init__.py'), recursive=True))

    @staticmethod
    def _import_name(site_packages, init_file):
        rel = os.path.relpath(init_file, site_packages)
        return rel.split(os.sep)[0]

    def payload(self,module,import_name):
        print(f"{module} -> {import_name}")



def main():
    logging.basicConfig()
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-l', '--loglevel', default='WARN', help="Python logging level")
    parser.add_argument('--python-spec',default='/etc/nmrbox.d/pipmanager.yaml')


    args = parser.parse_args()
    usage_audit_logger.setLevel(getattr(logging,args.loglevel))
    pm = PythonMapper(args.python_spec)
    usage_audit_logger.info(pm.modules)
    pm.map()



if __name__ == "__main__":
    main()
