#!/usr/bin/env python3
"""Lease bench-only IPv4 /32 addresses and a direct peer route; default is plan."""

import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

ROLES = {
    "dev-79": {"interface": "enp1s0f0", "mac": "58:47:ca:77:66:e2",
               "local": "198.18.0.79", "peer": "198.18.0.240"},
    "dev-240": {"interface": "enp2s0f0", "mac": "58:47:ca:7c:78:59",
                "local": "198.18.0.240", "peer": "198.18.0.79"},
}
METRIC = 42796


class UnknownIPResult(RuntimeError):
    """The child died before confirming whether the kernel applied its request."""


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def ip(*arguments, read=False):
    argv = ["ip", *arguments]
    result = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=5)
    if result.returncode < 0:
        raise UnknownIPResult("ip command killed by signal {}: {}".format(-result.returncode, " ".join(argv)))
    if result.returncode:
        raise RuntimeError("ip command failed ({}): {}".format(result.returncode, " ".join(argv)))
    if read:
        value = json.loads(result.stdout)
        if not isinstance(value, list):
            raise RuntimeError("Unexpected ip JSON result")
        return value


def plan(role, marker, seconds):
    if role not in ROLES or not re.fullmatch(r"[a-z0-9-]{1,48}", marker):
        raise ValueError("Unknown role or invalid marker")
    if not 10 <= seconds <= 300:
        raise ValueError("Lease duration must be between 10 and 300 seconds")
    peer = dict(ROLES[role])
    interface = peer["interface"]
    address = ["-4", "address", "add", peer["local"] + "/32", "dev", interface,
               "label", interface + ":tlens"]
    route = ["-4", "route", "add", peer["peer"] + "/32", "dev", interface,
             "src", peer["local"], "proto", "static", "metric", str(METRIC), "table", "main"]
    return {"schema_version": 1, "role": role, **peer, "marker": marker, "seconds": seconds,
            "lease_dir": "/tmp/traflens-tunnel-link-" + marker,
            "add_argv": [["ip", *address], ["ip", *route]]}


def address_matches(addresses, target):
    matches = []
    for interface in addresses:
        for address in interface.get("addr_info", []):
            if address.get("family") == "inet" and target in (
                    address.get("local"), address.get("peer", "").split("/")[0]):
                matches.append({"interface": interface.get("ifname"),
                                **{key: address[key] for key in ("local", "peer", "prefixlen", "label")
                                   if key in address}})
    return matches


def route_network(route):
    destination = route.get("dst", "default")
    if destination == "default":
        return None
    network = ipaddress.ip_network(destination, strict=False)
    return network if network.version == 4 and network.prefixlen else None


def related_routes(routes, targets):
    return [route for route in routes if (network := route_network(route)) is not None
            and any(ipaddress.ip_address(target) in network for target in targets)]


def link_identity(config, require_up=True):
    links = ip("-j", "link", "show", "dev", config["interface"], read=True)
    if len(links) != 1:
        raise RuntimeError("Expected exactly one direct-link interface")
    link = links[0]
    if link.get("ifname") != config["interface"] or link.get("address", "").lower() != config["mac"]:
        raise RuntimeError("Direct-link interface MAC identity differs")
    if require_up and ("UP" not in link.get("flags", []) or link.get("operstate") != "UP"):
        raise RuntimeError("Direct-link interface must be UP")
    return {key: link.get(key) for key in ("ifindex", "ifname", "address", "flags", "operstate")}


def preflight(config):
    link = link_identity(config)
    addresses = ip("-j", "-4", "address", "show", read=True)
    routes = ip("-j", "-4", "route", "show", "table", "all", read=True)
    matches = [entry for target in (config["local"], config["peer"])
               for entry in address_matches(addresses, target)]
    covering = related_routes(routes, (config["local"], config["peer"]))
    if matches or covering:
        raise RuntimeError("Bench address or a covering non-default route already exists")
    # Never persist the host-wide address/route dump.
    return {"link": link, "bench_addresses": [], "covering_nondefault_routes": []}


def private_json(path, value):
    temporary = path.with_suffix(".json.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
    os.replace(temporary, path)


class Lease:
    def __init__(self, config):
        self.config = config
        self.address_added = False
        self.route_added = False
        self.link = None
        self.uncertain_add = None

    def add(self, before_add=None):
        checked = preflight(self.config)
        self.link = checked["link"]
        if before_add:
            before_add(checked)
        try:
            ip(*self.config["add_argv"][0][1:])
        except (subprocess.TimeoutExpired, UnknownIPResult):
            self.uncertain_add = "address"
            raise
        self.address_added = True
        try:
            ip(*self.config["add_argv"][1][1:])
        except (subprocess.TimeoutExpired, UnknownIPResult):
            self.uncertain_add = "route"
            raise
        self.route_added = True

    def cleanup(self):
        if self.uncertain_add:
            return ["{} add has an unknown result; refusing destructive cleanup".format(self.uncertain_add)]
        if not self.address_added and not self.route_added:
            return []
        config = self.config
        try:
            current_link = link_identity(config, require_up=False)
            if current_link["ifindex"] != self.link["ifindex"]:
                raise RuntimeError("Direct-link interface was replaced; refusing cleanup")
            if self.route_added:
                routes = ip("-j", "-4", "route", "show", "table", "all", read=True)
                candidates = related_routes(routes, (config["peer"],))
                if candidates:
                    expected = ipaddress.ip_network(config["peer"] + "/32")
                    owned = (len(candidates) == 1 and route_network(candidates[0]) == expected
                             and candidates[0].get("dev") == config["interface"]
                             and candidates[0].get("prefsrc") == config["local"]
                             and candidates[0].get("metric") == METRIC
                             and candidates[0].get("protocol") == "static"
                             and candidates[0].get("table", "main") in ("main", 254))
                    if not owned:
                        raise RuntimeError("Peer route ownership changed; refusing route and address cleanup")
                    argv = list(config["add_argv"][1][1:])
                    argv[2] = "del"
                    ip(*argv)
                self.route_added = False
            if self.address_added:
                addresses = ip("-j", "-4", "address", "show", read=True)
                candidates = address_matches(addresses, config["local"])
                if candidates:
                    owned = (len(candidates) == 1 and candidates[0].get("interface") == config["interface"]
                             and candidates[0].get("local") == config["local"]
                             and candidates[0].get("prefixlen") == 32
                             and candidates[0].get("label") == config["interface"] + ":tlens"
                             and "peer" not in candidates[0])
                    if not owned:
                        raise RuntimeError("Bench address ownership changed; refusing address cleanup")
                    argv = list(config["add_argv"][0][1:])
                    argv[2] = "del"
                    ip(*argv)
                self.address_added = False
            return []
        except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
            return [str(error)]


def execute(config, argv):
    if os.geteuid() != 0:
        raise RuntimeError("Executing the lease requires root")
    directory = Path(config["lease_dir"])
    directory.mkdir(mode=0o700)  # Existing paths, including symlinks, are never reused.
    stop = threading.Event()
    previous = {}
    lease = Lease(config)
    started = time.monotonic()
    state = {**config, "pid": os.getpid(), "started_at_utc": utc_now(), "status": "starting"}
    error = None
    cleanup_errors = []
    try:
        private_json(directory / "argv.json", argv)
        private_json(directory / "lease.json", state)
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[number] = signal.signal(number, lambda signum, frame: stop.set())
        def before_add(checked):
            private_json(directory / "preflight.json", checked)
            if stop.is_set() or time.monotonic() >= started + config["seconds"]:
                raise RuntimeError("Lease stopped or expired before network changes")

        lease.add(before_add)
        state.update(status="ready", ready_at_utc=utc_now(),
                     deadline_monotonic=started + config["seconds"], interface_identity=lease.link)
        private_json(directory / "lease.json", state)
        print(json.dumps({"event": "ready", **state}), flush=True)
        while not stop.is_set():
            remaining = started + config["seconds"] - time.monotonic()
            if remaining <= 0:
                break
            stop.wait(min(remaining, 0.5))
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as caught:
        error = str(caught)
    finally:
        cleanup_errors = lease.cleanup()
        state.update(status="finished", finished_at_utc=utc_now(),
                     elapsed_seconds=round(time.monotonic() - started, 3),
                     cleanup_ok=not cleanup_errors, cleanup_errors=cleanup_errors,
                     address_added=lease.address_added, route_added=lease.route_added,
                     uncertain_add=lease.uncertain_add, error=error)
        try:
            private_json(directory / "lease.json", state)
        except OSError as caught:
            state["error"] = "Could not save final lease state: " + str(caught)
            error = state["error"]
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
        print(json.dumps({"event": "finished", **state}), flush=True)
    return 1 if error or cleanup_errors else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=tuple(ROLES), required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--seconds", type=int, default=180)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = plan(args.role, args.marker, args.seconds)
        if not args.execute:
            print(json.dumps({"event": "plan", **config}), flush=True)
            return 0
        return execute(config, sys.argv if argv is None else argv)
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"event": "error", "error": str(error)}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
