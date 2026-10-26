#!/usr/bin/env python3
"""Record real lab health/schema/query evidence without copying credentials."""

import argparse
import datetime
import json
import pathlib
import subprocess

import lab


def text_command(args):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if result.returncode:
        raise RuntimeError("Evidence command failed: " + str(args[0:3]))
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("/tmp/traflens-lab-20261026"))
    args = parser.parse_args()
    root = args.root.resolve()
    lab.prepare_root(root)
    evidence = root / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    password = (root / "mysql-password").read_text().strip()
    mysql = text_command([
        "docker", "exec", "traflens-lab-mysql", "sh", "-c",
        'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -h127.0.0.1 -N -uroot deepflow -e '
        "'SELECT version FROM db_version; "
        "SELECT count(*) FROM information_schema.tables WHERE table_schema=database(); "
        "SELECT count(*) FROM vtap;'",
    ])
    clickhouse = text_command([
        "docker", "exec", "traflens-lab-clickhouse", "clickhouse-client", "--multiquery", "--query",
        "SELECT version(); SELECT database,count(*) FROM system.tables "
        "WHERE database NOT IN ('system','INFORMATION_SCHEMA','information_schema') "
        "GROUP BY database ORDER BY database;",
    ])
    version = text_command(["docker", "exec", "traflens-lab-server", "/bin/deepflow-server", "-v"])
    health = lab.health()
    query_sql = "SELECT Count(row) FROM l7_flow_log"
    query = lab.query(query_sql)
    resources = []
    for name in ("mysql", "clickhouse", "server"):
        container = lab.inspect("container", "traflens-lab-" + name)
        lab.require_owned(container, root, "container")
        host = container["HostConfig"]
        state = container["State"]
        resources.append({
            "name": container["Name"], "image": container["Config"]["Image"],
            "image_id": container["Image"], "running": state["Running"],
            "oom_killed": state["OOMKilled"], "memory_bytes": host["Memory"],
            "memory_swap_bytes": host["MemorySwap"], "nano_cpus": host["NanoCpus"],
            "pids_limit": host["PidsLimit"], "port_bindings": host["PortBindings"],
        })
    logs = subprocess.run(
        ["docker", "logs", "traflens-lab-server"], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
    ).stdout
    secret_in_logs = password in logs
    values = {
        "mysql-schema.tsv": mysql, "clickhouse-schema.tsv": clickhouse,
        "server-version.txt": version,
        "server-errors-sanitized.log": "\n".join(logs.replace(password, "<redacted>").splitlines()[-200:]) + "\n",
        "health.json": json.dumps(health, indent=2) + "\n",
        "query-ready.json": json.dumps(query, indent=2) + "\n",
        "resources.json": json.dumps(resources, indent=2) + "\n",
    }
    for name, value in values.items():
        lab.private_write(evidence / name, value)
    summary = {
        "verified_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "controller_healthy": bool(health), "mysql_schema_version": mysql.splitlines()[0],
        "mysql_table_count": int(mysql.splitlines()[1]), "agent_count": int(mysql.splitlines()[2]),
        "query_status": query.get("OPT_STATUS"), "all_containers_running": all(v["running"] for v in resources),
        "query_sql": query_sql,
        "private_password_found_in_server_logs": secret_in_logs,
        "note": "Storage/query readiness only; no Agent traffic or performance-parity claim.",
    }
    lab.private_write(evidence / "summary.json", json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    if not health or query.get("OPT_STATUS") != "SUCCESS" or not summary["all_containers_running"] or secret_in_logs:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
