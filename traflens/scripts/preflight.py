#!/usr/bin/env python3
"""Collect a read-only TrafLens build/test host snapshot as JSON."""

import argparse
import datetime
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys


SCHEMA_VERSION = 1
TOOLS = {
    "python3": ["python3", "--version"],
    "git": ["git", "--version"],
    "go": ["go", "version"],
    "rustc": ["rustc", "--version"],
    "cargo": ["cargo", "--version"],
    "clang": ["clang", "--version"],
    "cmake": ["cmake", "--version"],
    "make": ["make", "--version"],
    "protoc": ["protoc", "--version"],
    "node": ["node", "--version"],
    "npm": ["npm", "--version"],
    "docker": ["docker", "--version"],
    "ip": ["ip", "-Version"],
    "iperf3": ["iperf3", "--version"],
}


def run_command(arguments):
    """Run a fixed argv without a shell; never query a remote service."""
    try:
        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "error": "command not found"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "error": "command timed out after 5s"}
    except OSError as exc:
        return {"ok": False, "stdout": "", "error": str(exc)}
    return {
        "ok": result.returncode == 0,
        "stdout": result.stdout.rstrip("\r\n"),
        "error": (result.stderr.strip() or "command exited with status %s" % result.returncode) if result.returncode else None,
        "returncode": result.returncode,
    }


def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def probe_tool(arguments):
    executable = shutil.which(arguments[0])
    if executable is None:
        return {"available": False, "path": None, "version": None, "error": "command not found"}
    result = run_command([executable] + arguments[1:])
    lines = result["stdout"].splitlines()
    return {
        "available": True,
        "path": executable,
        "version": lines[0] if lines else None,
        "error": None if result["ok"] else result["error"] or "nonzero exit status",
    }


def collect_source(repo):
    revision = run_command(["git", "-C", str(repo), "rev-parse", "HEAD"])
    status = run_command(["git", "-C", str(repo), "status", "--short"])
    upstream = {"sha": None, "error": None}
    metadata = repo / "traflens" / "upstream.json"
    try:
        data = json.loads(metadata.read_text(encoding="utf-8"))
        sha = data.get("sha") if isinstance(data, dict) else None
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", sha):
            upstream["error"] = "upstream.json must contain a full hexadecimal sha"
        else:
            upstream["sha"] = sha.lower()
    except (OSError, ValueError) as exc:
        upstream["error"] = str(exc)
    return {
        "root": str(repo),
        "git_sha": revision["stdout"] if revision["ok"] else None,
        "git_status": status["stdout"].splitlines() if status["ok"] else None,
        "git_error": revision["error"] or status["error"],
        "upstream": upstream,
    }


def collect_memory():
    contents = read_text("/proc/meminfo")
    result = {"total_bytes": None, "available_bytes": None, "swap_total_bytes": None}
    if contents is None:
        return result
    keys = {"MemTotal": "total_bytes", "MemAvailable": "available_bytes", "SwapTotal": "swap_total_bytes"}
    for line in contents.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0].rstrip(":") in keys:
            try:
                result[keys[fields[0].rstrip(":")]] = int(fields[1]) * 1024
            except ValueError:
                continue
    return result


def collect_host(repo):
    model = None
    for line in (read_text("/proc/cpuinfo") or "").splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() in ("model name", "Processor"):
            model = value.strip()
            break
    try:
        disk = shutil.disk_usage(str(repo))
        storage = {"total_bytes": disk.total, "used_bytes": disk.used, "free_bytes": disk.free, "error": None}
    except OSError as exc:
        storage = {"total_bytes": None, "used_bytes": None, "free_bytes": None, "error": str(exc)}
    return {
        "hostname": platform.node(),
        "system": platform.system(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "cpu": {"logical_count": os.cpu_count(), "model": model},
        "memory": collect_memory(),
        "disk": storage,
    }


def optional_integer(value):
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def collect_interface(name):
    result = {
        "name": name,
        "exists": False,
        "operstate": None,
        "carrier": None,
        "speed_mbps": None,
        "addresses": [],
        "errors": [],
    }
    if name in (".", "..") or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", name):
        result["errors"].append("invalid interface name")
        return result
    directory = Path("/sys/class/net") / name
    if not directory.is_dir():
        result["errors"].append("interface not found in /sys/class/net")
        return result
    result["exists"] = True
    result["operstate"] = read_text(directory / "operstate")
    result["carrier"] = optional_integer(read_text(directory / "carrier"))
    speed = optional_integer(read_text(directory / "speed"))
    result["speed_mbps"] = speed if speed is not None and speed >= 0 else None
    addresses = run_command(["ip", "-j", "address", "show", "dev", name])
    if not addresses["ok"]:
        result["errors"].append(addresses["error"] or "ip address query failed")
        return result
    try:
        entries = json.loads(addresses["stdout"])
        if not isinstance(entries, list):
            raise ValueError("expected an array")
        selected = []
        for entry in entries:
            for address in entry.get("addr_info", []):
                selected.append({
                    "family": address.get("family"),
                    "address": address.get("local"),
                    "prefix_length": address.get("prefixlen"),
                })
        result["addresses"] = selected
    except (ValueError, AttributeError, TypeError):
        result["errors"].append("invalid JSON schema from ip address query")
    return result


def collect_preflight(repo, interfaces):
    repo = Path(repo).resolve()
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": collect_source(repo),
        "host": collect_host(repo),
        "tools": {name: probe_tool(arguments) for name, arguments in TOOLS.items()},
        "network_interfaces": [collect_interface(name) for name in dict.fromkeys(interfaces)],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--interface", action="append", default=[], help="interface to inspect; may be repeated")
    parser.add_argument("--output", type=Path, help="also write JSON to this explicit path")
    arguments = parser.parse_args(argv)
    if arguments.repo is None:
        script_path = Path(__file__).resolve()
        arguments.repo = script_path.parents[2] if len(script_path.parents) >= 3 else Path.cwd()
    document = json.dumps(collect_preflight(arguments.repo, arguments.interface), indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(document, encoding="utf-8")
    sys.stdout.write(document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
