#!/usr/bin/env python3
import argparse
import collections
import functools
import logging

import yaml

from usage_audit import usage_audit_logger
from postgresql_access import DatabaseDict

from usage_audit.python_mapper import PythonMapper


def recorder(module,import_name,name_map):
    usage_audit_logger.info(f"record {module} {import_name}")
    name_map[module].add(import_name)


def main():
    logging.basicConfig()
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-l', '--loglevel', default='WARN', help="Python logging level")
    parser.add_argument('--python-spec',default='/etc/nmrbox.d/pipmanager.yaml')
    parser.add_argument('--dbyaml',default='/etc/nmrbox.d/usage_loader.yaml',help="Database YAML")
    parser.add_argument('--reset',action='store_true',help="Delete existing database entries")

    args = parser.parse_args()
    usage_audit_logger.setLevel(getattr(logging,args.loglevel))
    with open(args.dbyaml) as f:
        dconfig = yaml.safe_load(f)
    db = DatabaseDict(dictionary=dconfig['database'])
    with db.connect(application_name='usage.audit loader') as conn:
        name_map = collections.defaultdict(set)
        collector = functools.partial(recorder, name_map=name_map)
        with conn.cursor() as curs:
            skip = set()
            if args.reset:
                curs.execute("delete from audit.python_map")
            else:
                curs.execute("select module from audit.python_map")
                skip = set(r[0] for r in curs.fetchall())



            pm = PythonMapper(args.python_spec)
            pm.map(collector,skip=skip)
            for mod,imports in name_map.items():
                for imp in imports:
                    usage_audit_logger.info(f"insert {mod} {imp}")
                    curs.execute("insert into audit.python_map(module,import_name)  values(%s,%s)",(mod,imp))
        conn.commit()





if __name__ == "__main__":
    main()
