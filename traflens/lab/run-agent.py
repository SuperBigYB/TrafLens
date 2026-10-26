#!/usr/bin/env python3
"""Run the lab Agent for a finite duration, allowing bounded config-restart exits."""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import time

DEFAULT_REPO = pathlib.Path("/root/yb/git/TrafLens")


def process_snapshot(pid):
    directory = pathlib.Path("/proc") / str(pid)
    fields = (directory / "stat").read_text().rsplit(")", 1)[1].split()
    command = (directory / "cmdline").read_bytes().decode().split("\0")
    if len(command) < 2:
        raise RuntimeError("Supervisor command line is unavailable")
    cwd = (directory / "cwd").resolve(strict=True)
    observed_repo = DEFAULT_REPO
    for index, argument in enumerate(command[2:]):
        if argument == "--repo":
            observed_repo = pathlib.Path(command[index + 3])
        elif argument.startswith("--repo="):
            observed_repo = pathlib.Path(argument.split("=", 1)[1])
    return {
        "start_ticks": int(fields[19]),
        "repo": str((cwd / observed_repo).resolve()),
        "script": str((cwd / command[1]).resolve()),
    }


def check_supervisor_identity(identity, pid, repo, script):
    expected = {"pid": pid, "repo": str(repo.resolve()), "script": str(script.resolve())}
    if any(identity.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Supervisor identity belongs to another scope")
    snapshot = process_snapshot(pid)
    if (not isinstance(identity.get("start_ticks"), int)
            or snapshot["start_ticks"] != identity["start_ticks"]
            or snapshot["repo"] != expected["repo"]
            or snapshot["script"] != expected["script"]):
        raise RuntimeError("Supervisor PID was reused or its command scope changed")


def signal_owned_supervisor(identity, pid, repo, script):
    check_supervisor_identity(identity, pid, repo, script)
    os.kill(pid, signal.SIGTERM)


def refuse_live_supervisor(work, repo, script):
    pidfile = work / "supervisor.pid"
    if not pidfile.exists():
        return
    pid = int(pidfile.read_text().strip())
    if not (pathlib.Path("/proc") / str(pid)).exists():
        return
    identity_file = work / "supervisor-identity.json"
    if not identity_file.is_file():
        raise RuntimeError("A live supervisor PID has no identity; refusing launch")
    check_supervisor_identity(json.loads(identity_file.read_text()), pid, repo, script)
    raise RuntimeError("An owned supervisor is already running")


def request_stop(_signum, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=pathlib.Path, default=DEFAULT_REPO)
    parser.add_argument("--seconds", type=int, default=900)
    parser.add_argument("--stop", action="store_true", help="Stop only this checkout's recorded supervisor and its child group")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 900:
        parser.error("Lab runtime must be between 1 and 900 seconds")
    repo = args.repo.resolve()
    work = repo / ".traflens/work/agent-run"
    config = work / "config.yaml"
    binary = repo / "agent/target/debug/deepflow-agent"
    script = pathlib.Path(__file__).resolve()
    if args.stop:
        supervisor_pid = int((work / "supervisor.pid").read_text().strip())
        process_dir = pathlib.Path("/proc") / str(supervisor_pid)
        if not process_dir.exists():
            print("Recorded supervisor already exited")
            return
        identity_file = work / "supervisor-identity.json"
        if not identity_file.is_file():
            raise RuntimeError("Supervisor identity is missing; refusing to signal")
        identity = json.loads(identity_file.read_text())
        signal_owned_supervisor(identity, supervisor_pid, repo, script)
        for _ in range(75):
            if not process_dir.exists():
                print("Owned supervisor stopped")
                return
            time.sleep(0.2)
        raise RuntimeError("Owned supervisor did not exit within stop grace")
    if not config.is_file() or not binary.is_file():
        parser.error("Prepare the static config and build the native packet Agent first")
    refuse_live_supervisor(work, repo, script)
    pidfile = work / "deepflow-agent.pid"
    if pidfile.exists():
        pid = int(pidfile.read_text().strip())
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise RuntimeError("An Agent PID already exists; refusing a second process")
    os.umask(0o077)
    (work / "supervisor-finished.json").unlink(missing_ok=True)
    identity = {"pid": os.getpid(), "repo": str(repo), "script": str(script),
                "start_ticks": process_snapshot(os.getpid())["start_ticks"]}
    identity_file = work / "supervisor-identity.json"
    identity_file.write_text(json.dumps(identity, indent=2) + "\n")
    identity_file.chmod(0o600)
    (work / "supervisor.pid").write_text(str(os.getpid()) + "\n")
    started = datetime.datetime.now(datetime.timezone.utc)
    provenance = {
        "started_at_utc": started.isoformat(), "maximum_runtime_seconds": args.seconds,
        "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
        "source_status": subprocess.check_output(["git", "status", "--short"], cwd=repo, text=True).splitlines(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "binary_version": subprocess.check_output([str(binary), "-v"], text=True),
        "console_start_offset": (work / "console.log").stat().st_size if (work / "console.log").exists() else 0,
    }
    (work / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    deadline = time.monotonic() + args.seconds
    signal.signal(signal.SIGTERM, request_stop)
    with (work / "console.log").open("a", encoding="utf-8") as console:
        for attempt in range(1, 4):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            console.write("\nLAB supervisor start attempt {}\n".format(attempt))
            console.flush()
            process = subprocess.Popen([str(binary), "-f", str(config)], stdout=console,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                returncode = process.wait(timeout=remaining)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                console.write("LAB supervisor stopped Agent at runtime limit or stop request\n")
                break
            console.write("LAB Agent exited with code {}\n".format(returncode))
            console.flush()
            # Configuration changes request exit/restart; never retry indefinitely.
            time.sleep(min(1, max(0, deadline - time.monotonic())))
    (work / "supervisor-finished.json").write_text(json.dumps({
        "finished_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "attempts": attempt,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
