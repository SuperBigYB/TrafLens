#!/usr/bin/env python3
"""Bounded, explicitly coordinated restart acceptance for the isolated lab.

Run on dev-240. This helper never starts an Agent or a workload: prepare writes
the exact server/client commands; root coordinates them on the two hosts.
Only the restart command may restart the one snapshotted owned ClickHouse.
Recovery may start that same container, without a second restart or recreation.
"""

import argparse
import datetime
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import lab

HOST = "fe80::5a47:caff:fe7c:7859"
CLIENT_REPO = Path("/root/yb/git/TrafLens")
PROTOCOLS = {"http": (20, 18080, "traffic.py"),
             "dns": (120, 18053, "dns-traffic.py"),
             "mysql": (60, 18060, "mysql-traffic.py")}
PHASES = ("before", "during", "after")
OWNED = tuple("traflens-lab-" + name for name in ("mysql", "clickhouse", "server"))
CH = "traflens-lab-clickhouse"
VOLUMES = {"/var/lib/clickhouse": "traflens-lab-clickhouse-data",
           "/var/lib/clickhouse_storage": "traflens-lab-clickhouse-storage"}
DEADLINE_EPOCH = None


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def timestamp(value):
    moment = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError("Fixture timestamps must include a timezone")
    return moment.timestamp()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    lab.private_write(path, json.dumps(value, indent=2, allow_nan=False) + "\n")


def remaining(state):
    value = state["deadline_epoch"] - time.time()
    if value <= 0:
        raise RuntimeError("Fault-test total deadline expired")
    return value


def bounded_timeout(timeout):
    if DEADLINE_EPOCH is not None:
        timeout = min(timeout, DEADLINE_EPOCH - time.time())
    if timeout <= 0:
        raise RuntimeError("Fault-test total deadline expired")
    return timeout


def command(args, timeout=10):
    return subprocess.run(args, capture_output=True, text=True, timeout=bounded_timeout(timeout), check=True).stdout


def inspect(kind, name):
    try:
        return json.loads(command(["docker", kind, "inspect", name], timeout=5))[0]
    except subprocess.CalledProcessError:
        return None


def public_container(info):
    return {"id": info["Id"], "name": info["Name"], "image_id": info["Image"],
            "started_at": info["State"]["StartedAt"], "running": info["State"]["Running"],
            "volume_mounts": {value["Destination"]: value["Name"] for value in info["Mounts"]
                              if value["Type"] == "volume"}}


def snapshot(root):
    owned = {}
    for name in OWNED:
        info = inspect("container", name)
        if info is None:
            raise RuntimeError("Missing owned lab container: " + name)
        lab.require_owned(info, root, "container")
        owned[name] = public_container(info)
        for volume in owned[name]["volume_mounts"].values():
            value = inspect("volume", volume)
            if value is None:
                raise RuntimeError("Missing owned lab volume")
            lab.require_owned(value, root, "volume")
    if owned[CH]["volume_mounts"] != VOLUMES:
        raise RuntimeError("Unexpected ClickHouse data-volume identity")
    unrelated = {}
    for ident in command(["docker", "ps", "-aq"]).split():
        info = inspect("container", ident)
        if info and info["Name"].lstrip("/") not in OWNED:
            value = public_container(info)
            unrelated[value["name"]] = {key: value[key] for key in ("id", "started_at", "running")}
    return {"at_utc": utc(), "owned": owned, "unrelated": unrelated}


def check_snapshot(baseline, current, allow_ch_started_change=False):
    for name, expected in baseline["owned"].items():
        actual = current["owned"][name]
        for key in ("id", "image_id", "volume_mounts"):
            if actual[key] != expected[key]:
                raise RuntimeError("Owned container/volume identity changed: " + name)
        if name != CH or not allow_ch_started_change:
            if actual["started_at"] != expected["started_at"]:
                raise RuntimeError("An unexpected lab container restart occurred: " + name)
    for name, expected in baseline["unrelated"].items():
        if current["unrelated"].get(name) != expected:
            raise RuntimeError("An unrelated container changed during the test: " + name)


def marker(run_id, phase, protocol):
    return run_id + phase[0] + protocol


def traffic_path(directory, protocol, side, value):
    return directory / ("traffic-%s-%s-%s.json" % (protocol, side, value))


def build_plan(run_id, directory):
    phases = {}
    for phase in PHASES:
        phases[phase] = {}
        interval = 1000 if phase == "during" else 100
        for protocol, (_ident, port, script) in PROTOCOLS.items():
            value = marker(run_id, phase, protocol)
            bounded = ["timeout", "--signal=TERM", "--kill-after=5s", "75s", "python3"]
            common = ["--address", HOST, "--marker", value, "--port", str(port),
                      "--count", "20", "--timeout", "75", "--interval-ms", str(interval)]
            phases[phase][protocol] = {
                "marker": value,
                "server_command": bounded + [str(lab.HERE / script), "serve"] + common + [
                    "--interface", "enp2s0f0", "--output", str(traffic_path(directory, protocol, "server", value))],
                "client_command": bounded + [str(CLIENT_REPO / "traflens/lab" / script), "client"] + common + [
                    "--interface", "enp1s0f0", "--output", str(traffic_path(
                        CLIENT_REPO / ".traflens/work/fault-tests" / run_id, protocol, "client", value))],
                "client_json_destination_on_dev240": str(traffic_path(directory, protocol, "client", value)),
            }
    return {"run_id": run_id, "phases": phases,
            "coordination": "Start all three servers and wait for their ready events; launch clients in parallel. Copy client JSON to the named dev-240 paths. During clients last about 19 seconds: restart about 2 seconds after launch. No warm-up requests.",
            "limits": {"requests_per_protocol_phase": 20, "phases": 3, "maximum_restarts": 1,
                       "fixture_timeout_seconds": 75, "fixture_termination_grace_seconds": 5,
                       "test_ports": [18053, 18060, 18080], "agent_started_by_helper": False}}


def load_helper(name, filename):
    spec = importlib.util.spec_from_file_location(name, lab.HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expected_records(protocol, value, client, server):
    if client.get("marker") != value or server.get("marker") != value:
        raise ValueError("Fixture marker mismatch")
    left, right = client["records"], server["records"]
    if len(left) != 20 or len(right) != 20:
        raise ValueError("Expected exactly 20 client and server records")
    expected = []
    if protocol == "http":
        paths = ["/traflens-e2e/%s/%d" % (value, i) for i in range(20)]
        if [record["path"] for record in left] != paths or [record["path"] for record in right] != paths:
            raise ValueError("Unexpected or repeated HTTP paths")
        if any(record["status"] != 200 for record in left + right):
            raise ValueError("HTTP fixture response failed")
        expected = [{"request_resource": path, "request_type": "GET", "response_code": 200,
                     "response_status": 0} for path in paths]
    elif protocol == "dns":
        dns = load_helper("fault_dns", "dns-traffic.py")
        if not all(document.get("complete") is True and document.get("errors") == [] for document in (client, server)):
            raise ValueError("DNS fixture did not complete cleanly")
        keys = ("sequence", "id", "name", "address", "rcode", "ttl", "query_hex", "response_hex")
        for wanted, request, response in zip(dns.workload(value, 20), left, right):
            if (any(request[key] != response[key] for key in keys)
                    or any(request[key] != expected_value for key, expected_value in wanted.items())
                    or request.get("verified") is not True or response.get("verified") is not True):
                raise ValueError("DNS wire records differ")
            dns.verify_response(bytes.fromhex(request["response_hex"]), wanted["id"], wanted["name"], wanted["address"])
            expected.append({"request_resource": wanted["name"], "request_type": "A", "response_code": 0,
                             "response_status": 0, "response_result": "A=%s TTL=60" % wanted["address"]})
    else:
        mysql = load_helper("fault_mysql", "mysql-traffic.py")
        if not all(document.get("success") is True and document.get("quit_verified") is True
                   and document.get("database_execution") is False for document in (client, server)):
            raise ValueError("MySQL wire fixture did not complete cleanly")
        for sequence, (request, response) in enumerate(zip(left, right)):
            wanted = mysql.query_record(value, sequence)
            if (any(request[key] != item or response[key] != item for key, item in wanted.items())
                    or request.get("verified") is not True or response.get("verified") is not True):
                raise ValueError("MySQL wire records differ")
            expected.append({"request_resource": wanted["request_resource"], "request_type": "COM_QUERY",
                             "response_code": None, "response_status": 0})
    return expected


def overlap(server, protocol, restart):
    key = "received_at_utc" if protocol == "dns" else "time"
    times = [timestamp(record[key]) for record in server["records"]]
    begin, end = timestamp(restart["begin_at_utc"]), timestamp(restart["returned_at_utc"])
    return {"before_restart": sum(value < begin for value in times),
            "during_restart_call": sum(begin <= value <= end for value in times),
            "after_restart_return": sum(value > end for value in times)}


def require_after(server, protocol, restart):
    key = "received_at_utc" if protocol == "dns" else "time"
    if any(timestamp(record[key]) <= timestamp(restart["returned_at_utc"]) for record in server["records"]):
        raise ValueError("After-phase server records precede the restart return")


def query(sql, timeout):
    body = urllib.parse.urlencode({"db": "flow_log", "sql": sql}).encode()
    request = urllib.request.Request("http://127.0.0.1:20416/v1/query/", data=body)
    with urllib.request.urlopen(request, timeout=bounded_timeout(timeout)) as response:
        return json.load(response)


def healthy(timeout):
    try:
        if command(["docker", "exec", CH, "clickhouse-client", "--query", "SELECT 1"], timeout=min(timeout, 5)).strip() != "1":
            return False
        with urllib.request.urlopen("http://127.0.0.1:20417/v1/health/", timeout=bounded_timeout(min(timeout, 3))) as response:
            if json.load(response).get("OPT_STATUS") != "SUCCESS":
                return False
        return query("SELECT Count(row) FROM l7_flow_log", min(timeout, 5)).get("OPT_STATUS") == "SUCCESS"
    except (OSError, ValueError, subprocess.SubprocessError, urllib.error.URLError):
        return False


def helpers():
    names = [value[2] for value in PROTOCOLS.values()] + ["lab.py", "verify-requests.py", "fault-test.py"]
    return {name: digest(lab.HERE / name) for name in names}


def ensure_scope(state, root, allow_restart, allow_new_start=False):
    if helpers() != state["helper_sha256"]:
        raise RuntimeError("Fixture/helper sources changed after prepare")
    current = snapshot(root)
    check_snapshot(state["baseline"], current, allow_restart)
    if allow_restart and not allow_new_start:
        expected = state.get("expected_ch_started_at", state["baseline"]["owned"][CH]["started_at"])
        if current["owned"][CH]["started_at"] != expected:
            raise RuntimeError("An unrecorded extra ClickHouse start/restart occurred")
    return current


def prepare(args, directory):
    if directory.exists() or directory.resolve() != directory:
        raise RuntimeError("Run directory already exists; use a new unique run-id")
    baseline = snapshot(args.root)
    if not all(value["running"] for value in baseline["owned"].values()) or not healthy(5):
        raise RuntimeError("Prepare requires all three owned containers and query health")
    directory.mkdir(mode=0o700, parents=True)
    state = {"schema": 1, "owner": lab.PREFIX, "root": str(args.root), "run_id": args.run_id,
             "prepared_at_utc": utc(), "deadline_epoch": DEADLINE_EPOCH or time.time() + args.deadline_seconds,
             "deadline_seconds": args.deadline_seconds, "baseline": baseline,
             "helper_sha256": helpers(), "restart_consumed": False, "phases": {}}
    save(directory / "state.json", state)
    save(directory / "plan.json", build_plan(args.run_id, directory))
    print(json.dumps({"prepared": True, "directory": str(directory), "plan": str(directory / "plan.json"),
                      "deadline_seconds": args.deadline_seconds}, indent=2))


def restore(state, directory, root):
    remaining(state)
    current = ensure_scope(state, root, True)
    if not current["owned"][CH]["running"]:
        command(["docker", "start", CH], timeout=min(20, remaining(state)))
        after = ensure_scope(state, root, True, allow_new_start=True)
        state["expected_ch_started_at"] = after["owned"][CH]["started_at"]
        save(directory / "state.json", state)
    end = time.monotonic() + min(60, remaining(state))
    while time.monotonic() < end:
        if healthy(min(5, end - time.monotonic())):
            state["recovery"] = {"at_utc": utc(), "healthy": True, "action": "start-only-if-stopped"}
            save(directory / "state.json", state)
            return
        time.sleep(min(1, max(0, end - time.monotonic())))
    raise RuntimeError("Owned ClickHouse recovery did not restore query health within its deadline")


def restart(state, directory, root):
    if state["restart_consumed"]:
        raise RuntimeError("This run already consumed its single ClickHouse restart")
    if not state["phases"].get("before", {}).get("passed") or not state.get("during_armed_at_utc"):
        raise RuntimeError("Pass before and arm during before restarting ClickHouse")
    if remaining(state) < 120:
        raise RuntimeError("Insufficient total deadline left for restart and recovery")
    current = ensure_scope(state, root, False)
    if not all(value["running"] for value in current["owned"].values()):
        raise RuntimeError("Restart requires all owned containers running")
    state["restart_consumed"] = True
    state["restart"] = {"begin_at_utc": utc(), "success": False, "command": ["docker", "restart", "--time", "10", CH]}
    save(directory / "state.json", state)  # consume before the only mutation; no retry
    try:
        command(state["restart"]["command"], timeout=min(60, remaining(state)))
        state["restart"]["returned_at_utc"] = utc()
        after = ensure_scope(state, root, True, allow_new_start=True)
        if after["owned"][CH]["started_at"] == current["owned"][CH]["started_at"]:
            raise RuntimeError("ClickHouse StartedAt did not change")
        state["restart"]["new_started_at"] = after["owned"][CH]["started_at"]
        state["expected_ch_started_at"] = after["owned"][CH]["started_at"]
        state["restart"]["success"] = True
        save(directory / "state.json", state)
        restore(state, directory, root)
    except Exception as error:
        # A failed/timeout CLI may have reached the daemon. Only this consumed
        # restart may adopt the observed start, after checking every other identity.
        observed = ensure_scope(state, root, True, allow_new_start=True)
        state["expected_ch_started_at"] = observed["owned"][CH]["started_at"]
        state["restart"]["observed_started_at_after_error"] = observed["owned"][CH]["started_at"]
        state["restart"]["success"] = False
        state["restart"]["returned_at_utc"] = state["restart"].get("returned_at_utc", utc())
        state["restart"]["error_type"] = type(error).__name__
        save(directory / "state.json", state)
        restore(state, directory, root)
        raise


def require_phase_progress(state, phase):
    if phase != "before" and not state["phases"].get("before", {}).get("passed"):
        raise RuntimeError("Before phase has not passed")
    if phase == "during" and not state.get("restart", {}).get("success"):
        raise RuntimeError("During verification requires the recorded successful single restart")
    if phase == "before" and state["restart_consumed"]:
        raise RuntimeError("Before phase must be verified before the restart")
    if phase == "after":
        during = state["phases"].get("during", {})
        if type(during.get("passed")) is not bool or not during.get("acceptance_sha256"):
            raise RuntimeError("During acceptance must complete before after verification")
        if not state.get("recovery", {}).get("healthy"):
            raise RuntimeError("ClickHouse recovery must succeed before after verification")


def verify_phase(args, state, directory):
    phase = args.phase
    remaining(state)
    ensure_scope(state, args.root, state["restart_consumed"])
    require_phase_progress(state, phase)
    if phase == "after" and not healthy(5):
        raise RuntimeError("After verification requires restored live query health")
    verifier = load_helper("fault_verify", "verify-requests.py")
    reports = {}
    for protocol, (ident, _port, _script) in PROTOCOLS.items():
        value = marker(args.run_id, phase, protocol)
        client_path = traffic_path(directory, protocol, "client", value)
        server_path = traffic_path(directory, protocol, "server", value)
        client = json.loads(client_path.read_text())
        server = json.loads(server_path.read_text())
        records = expected_records(protocol, value, client, server)
        document = {"marker": value, "protocol": ident, "records": records}
        fields = verifier.validate_expected(document)
        sql = ("SELECT " + ",".join(fields) + " FROM l7_flow_log WHERE request_resource LIKE '%"
               + value + "%' AND l7_protocol=" + str(ident) + " LIMIT 1001")
        report = {"marker": value, "protocol": ident, "expected": records, "fields": fields,
                  "sql": sql, "attempts": [], "consecutive": 0,
                  "input_sha256": {client_path.name: digest(client_path), server_path.name: digest(server_path)}}
        if phase == "during":
            report["overlap"] = overlap(server, protocol, state["restart"])
            if not all(report["overlap"].values()):
                raise RuntimeError("During workload did not span and overlap the restart: " + protocol)
        if phase == "after":
            require_after(server, protocol, state["restart"])
        reports[protocol] = report
    end = time.monotonic() + min(args.verify_seconds, remaining(state))
    while time.monotonic() < end and not all(value["consecutive"] >= 2 for value in reports.values()):
        for report in reports.values():
            if time.monotonic() >= end:
                break
            before = time.monotonic()
            attempt = {"at_utc": utc()}
            try:
                response = query(report["sql"], min(5, end - time.monotonic(), remaining(state)))
                comparison = verifier.compare_records(report["expected"], response, report["fields"])
                report["final_query"] = response
                attempt.update(comparison)
                report["consecutive"] = report["consecutive"] + 1 if comparison["exact_match"] else 0
            except (OSError, ValueError, RuntimeError, KeyError) as error:
                report["consecutive"] = 0
                attempt.update({"exact_match": False, "error_type": type(error).__name__})
            attempt["elapsed_seconds"] = round(time.monotonic() - before, 6)
            report["attempts"].append(attempt)
        if not all(value["consecutive"] >= 2 for value in reports.values()):
            time.sleep(min(2, max(0, end - time.monotonic())))
    passed = all(value["consecutive"] >= 2 for value in reports.values())
    acceptance_path = directory / (phase + "-acceptance.json")
    save(acceptance_path, {"phase": phase, "passed": passed, "protocols": reports})
    state["phases"][phase] = {"passed": passed, "verified_at_utc": utc(),
                              "acceptance_sha256": digest(acceptance_path)}
    save(directory / "state.json", state)
    if not passed:
        raise RuntimeError("Exact no-loss/no-duplicate phase acceptance failed: " + phase)


def finalize(state, directory, root):
    save(directory / "final.json", {"at_utc": utc(), "passed": False, "status": "verification-in-progress"})
    remaining(state)
    current = ensure_scope(state, root, True)
    passed = (state["restart_consumed"] and state.get("restart", {}).get("success")
              and all(state["phases"].get(phase, {}).get("passed") for phase in PHASES)
              and all(value["running"] for value in current["owned"].values()) and healthy(5))
    reports = []
    if passed:
        verifier = load_helper("fault_verify_final", "verify-requests.py")
        for phase in PHASES:
            path = directory / (phase + "-acceptance.json")
            if digest(path) != state["phases"][phase]["acceptance_sha256"]:
                raise RuntimeError("Verified phase evidence changed: " + phase)
            for report in json.loads(path.read_text())["protocols"].values():
                if any(digest(directory / name) != expected for name, expected in report["input_sha256"].items()):
                    raise RuntimeError("Verified wire evidence changed: " + phase)
                reports.append(report)
        for read in range(2):
            for report in reports:
                response = query(report["sql"], min(5, remaining(state)))
                result = verifier.compare_records(report["expected"], response, report["fields"])
                report.setdefault("final_reads", []).append({"at_utc": utc(), **result})
                passed = passed and result["exact_match"]
            if read == 0:
                time.sleep(min(2, remaining(state)))
    save(directory / "final.json", {"at_utc": utc(), "passed": bool(passed), "restart_count": int(state["restart_consumed"]),
         "phases": state["phases"], "final_snapshot": current,
         "final_query_reads": [{"marker": report["marker"], "reads": report.get("final_reads", [])} for report in reports],
         "scope": "60 records per protocol across before/during/after one owned ClickHouse restart; functional loss/duplicate acceptance, not performance parity"})
    if not passed:
        raise RuntimeError("Fault-test final acceptance did not pass")


def main():
    global DEADLINE_EPOCH
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("prepare", "arm-during", "restart", "verify", "recover", "finalize"))
    parser.add_argument("--root", type=Path, default=Path("/tmp/traflens-lab-20261026"))
    parser.add_argument("--run-id", required=True, help="Unique 5-25 lowercase alphanumeric chars, starting with a letter")
    parser.add_argument("--deadline-seconds", type=int, default=600)
    parser.add_argument("--phase", choices=PHASES)
    parser.add_argument("--verify-seconds", type=int, default=90)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z][a-z0-9]{4,24}", args.run_id):
        parser.error("Use a unique 5-25 character lowercase alphanumeric run-id")
    if not 120 <= args.deadline_seconds <= 900 or not 5 <= args.verify_seconds <= 120:
        parser.error("Total deadline must be 120-900 seconds; verify window 5-120 seconds")
    if args.action == "verify" and not args.phase:
        parser.error("verify requires --phase")
    args.root = args.root.resolve()
    lab.prepare_root(args.root)
    directory = args.root / "fault-tests" / args.run_id
    if args.action == "prepare":
        DEADLINE_EPOCH = time.time() + args.deadline_seconds
        prepare(args, directory)
        return
    if not directory.is_dir() or directory.resolve() != directory:
        raise RuntimeError("Missing or redirected prepared run directory")
    with (directory / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = json.loads((directory / "state.json").read_text())
        if any(state.get(key) != value for key, value in {"schema": 1, "owner": lab.PREFIX,
                   "root": str(args.root), "run_id": args.run_id}.items()):
            raise RuntimeError("Prepared run ownership mismatch")
        DEADLINE_EPOCH = state["deadline_epoch"]
        if args.action == "arm-during":
            remaining(state)
            ensure_scope(state, args.root, False)
            if not state["phases"].get("before", {}).get("passed") or state.get("during_armed_at_utc"):
                raise RuntimeError("Pass before once before arming the during window")
            state["during_armed_at_utc"] = utc()
            save(directory / "state.json", state)
        elif args.action == "restart":
            restart(state, directory, args.root)
        elif args.action == "verify":
            verify_phase(args, state, directory)
        elif args.action == "recover":
            restore(state, directory, args.root)
        else:
            finalize(state, directory, args.root)
        print(json.dumps({"action": args.action, "run_id": args.run_id, "at_utc": utc(), "completed": True}))


if __name__ == "__main__":
    main()
