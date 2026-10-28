#!/usr/bin/env python3
"""Read-only strict unpaced MySQL acceptance; default is an offline plan."""
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fast_mysql_full_population_acceptance', HERE / 'verify-ebpf-mysql.py')
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
CONTRACT = BASE.AcceptanceContract('mysql-fast')


def main(argv=None):
    return BASE.main(argv, CONTRACT)


if __name__ == '__main__':
    raise SystemExit(main())
