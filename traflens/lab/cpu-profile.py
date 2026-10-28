#!/usr/bin/env python3
"""Finite profile-only native integration. Default plan has no side effects."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import subprocess
import sys
import time

from cpu_profile_common import RUN, SHA, load, private_dir, profile_only, receipt, require, save, validate_controller_url

HERE = Path(__file__).resolve().parent
LIMITS = {"namespace": (100000000, 33554432, 16), "agent": (1000000000, 1073741824, 384),
          "upload": (100000000, 67108864, 32)}


def call(argv, timeout=35, check=True, body=None):
    result = subprocess.run(argv, input=body, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        # Do not copy arbitrary tool stderr, configuration or credentials into receipts.
        raise RuntimeError("Command failed: " + Path(argv[0]).name + " status " + str(result.returncode))
    return result


def inspect(kind, name):
    result = call(["docker", kind, "inspect", name], check=False)
    if result.returncode:
        # Daemon, permission, transport and malformed errors do not prove absence.
        missing = re.compile(r"(?:Error(?: response from daemon)?: )?(?:No such (?:object|container|image|network): "
                             + re.escape(name) + r"|network " + re.escape(name) + r" not found)\Z")
        lines = [line.strip() for line in result.stderr.splitlines() if line.strip()]
        if lines and all(missing.fullmatch(line) for line in lines):
            return None
        raise RuntimeError("Docker inspection failed; resource absence is unproven")
    values = json.loads(result.stdout)
    require(isinstance(values, list) and len(values) == 1 and isinstance(values[0], dict), "Malformed Docker inspection")
    return values[0]


def file_hash(path):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve() and path.is_file() and not path.is_symlink(),
            "Runtime executable must be a canonical regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def owned(info, state, kind):
    if not info:
        return False
    labels = info.get("Config", {}).get("Labels", {})
    host = info.get("HostConfig", {})
    expected = LIMITS[kind]
    return (labels.get("io.traflens.run") == state["run"]
            and labels.get("io.traflens.purpose") == "traflens.cpu-profile." + kind
            and labels.get("io.traflens.output") == state["output"]
            and info.get("Image") == state["image_id"]
            and (host.get("NanoCpus"), host.get("Memory"), host.get("PidsLimit")) == expected
            and not host.get("Privileged") and host.get("CapDrop") == ["ALL"] and host.get("ReadonlyRootfs")
            and host.get("PortBindings") in (None, {}) and host.get("PidMode") != "host"
            and host.get("RestartPolicy", {}).get("Name") in ("", "no")
            and host.get("NetworkMode") == state["network_modes"][kind])


def container_base(state, kind):
    cpu, memory, pids = LIMITS[kind]
    return ["docker", "create", "--name", state["names"][kind], "--network", state["network_modes"][kind],
            "--cpus", str(cpu / 10**9), "--memory", str(memory), "--memory-swap", str(memory),
            "--pids-limit", str(pids), "--cap-drop", "ALL", "--read-only", "--restart", "no",
            "--security-opt", "no-new-privileges", "--ulimit", "core=0:0",
            "--label", "io.traflens.run=" + state["run"], "--label", "io.traflens.output=" + state["output"],
            "--label", "io.traflens.purpose=traflens.cpu-profile." + kind,
            "--log-opt", "max-size=2m", "--log-opt", "max-file=1"]


def snapshot(controller_ip):
    return {"containers": call(["docker", "ps", "-q", "--no-trunc"]).stdout.split(),
            "networks": call(["docker", "network", "ls", "-q", "--no-trunc"]).stdout.split(),
            "route": json.loads(call(["ip", "-j", "route", "get", controller_ip]).stdout),
            "bpf": sorted((r["id"], r.get("tag", ""), r.get("name", ""))
                          for r in json.loads(call(["bpftool", "-j", "prog", "show"]).stdout))}


def backend(state, action, value):
    args = state["args"]
    remote = ["python3", str(Path(args["backend_code"]) / "cpu-profile.py"), "controller", action,
              "--work", args.get("backend_output") or str(Path(args["backend_root"]) / "cpu-profiles" / state["run"]),
              "--backend-root", args["backend_root"], "--server-container", args["server_container"],
              "--controller-url", args["controller_url"]]
    result = call(["ssh", "-o", "BatchMode=yes", "--", args["backend_host"], shlex.join(remote)],
                  timeout=100, body=json.dumps(value))
    response = json.loads(result.stdout)
    require(response.get("prepared" if action == "prepare" else "cleaned") is True,
            "Controller lifecycle did not acknowledge completion")
    return response


def listener_ready(anchor, logs):
    # Host /proc selects exactly the owned anchor network namespace. No probe POST.
    pid = anchor["State"]["Pid"]
    listening = False
    for name in ("tcp", "tcp6"):
        path = Path("/proc") / str(pid) / "net" / name
        for row in path.read_text().splitlines()[1:]:
            fields = row.split()
            if fields[1].rsplit(":", 1)[-1].upper() == format(39093, "04X") and fields[3] == "0A":
                listening = True
    text = "\n".join(p.read_text(errors="replace") for p in logs.glob("*CURRENT.log"))
    return listening and any("integration collector listening on http://" in line and ":39093" in line
                             for line in text.splitlines())


def journal(work, event, value):
    return save(work / (str(time.time_ns()) + "-" + event + ".json"), value)


def cleanup(work, state):
    errors = []
    agent_exit = None
    for kind in ("upload", "agent"):
        try:
            info = inspect("container", state["names"][kind])
            if info is None:
                continue
            require(owned(info, state, kind), "Refusing foreign or changed container")
            cid = info["Id"]
            if info["State"]["Running"]:
                call(["docker", "stop", "--time", "40", cid], timeout=50)
            info = inspect("container", cid)
            require(owned(info, state, kind) and not info["State"]["Running"], "Owned collector still running")
            if kind == "agent":
                agent_exit = {"exit_code": info["State"]["ExitCode"], "oom": info["State"]["OOMKilled"]}
                journal(work, "agent-exit", agent_exit)
                logs = call(["docker", "logs", cid])
                (work / (str(time.time_ns()) + "-agent-docker.log")).write_text(logs.stdout + logs.stderr)
            call(["docker", "rm", cid])
        except Exception as error:
            errors.append(kind + ": " + type(error).__name__)
    try:
        stopped = all(inspect("container", state["names"][kind]) is None for kind in ("agent", "upload"))
    except Exception:
        stopped = False
        errors.append("collector removal: inspection unavailable")
    if state.get("controller_attempted") and stopped:
        try:
            proof = {"run": state["run"], "agent_stopped": True, "owned_agent_removed": True}
            backend(state, "cleanup", proof)
            journal(work, "controller-cleanup", {"cleaned": True})
        except Exception as error:
            errors.append("controller: " + type(error).__name__)
    elif state.get("controller_attempted"):
        errors.append("controller: collector removal not proven")
    if stopped:
        try:
            info = inspect("container", state["names"]["namespace"])
            if info:
                require(owned(info, state, "namespace"), "Refusing foreign namespace")
                if info["State"]["Running"]:
                    call(["docker", "stop", "--time", "2", info["Id"]])
                call(["docker", "rm", info["Id"]])
            network = inspect("network", state["names"]["network"])
            if network:
                labels = network.get("Labels", {})
                require(labels.get("io.traflens.run") == state["run"]
                        and labels.get("io.traflens.output") == state["output"]
                        and labels.get("io.traflens.purpose") == "traflens.cpu-profile.network"
                        and network.get("Driver") == "bridge" and not network.get("Containers"),
                        "Refusing foreign, changed or populated network")
                call(["docker", "network", "rm", network["Id"]])
        except Exception as error:
            errors.append("namespace/network: " + type(error).__name__)
    try:
        before = load(work / "before.json")
        after = snapshot(state["args"]["controller_ip"])
        if before:
            require(set(before["containers"]) <= set(after["containers"])
                    and set(before["networks"]) <= set(after["networks"])
                    and before["route"] == after["route"] and before["bpf"] == [list(v) for v in after["bpf"]],
                    "Original host resources changed")
        journal(work, "restoration", {"baseline_preserved": True, "snapshot": after})
    except Exception as error:
        errors.append("baseline: " + type(error).__name__)
    return {"cleaned": not errors, "cleanup_errors": errors, "agent_exit": agent_exit}


def process_start(pid):
    return Path("/proc", str(pid), "stat").read_text().rsplit(")", 1)[1].split()[19]


def stop(work):
    work = private_dir(work)
    state = load(work / "state.json")
    require(state and state["output"] == str(work) and RUN.fullmatch(state["run"]), "Invalid lifecycle receipt")
    supervisor = load(work / "supervisor.json")
    if supervisor and Path("/proc", str(supervisor["pid"])).exists():
        require(process_start(supervisor["pid"]) == supervisor["start_ticks"], "Supervisor PID identity changed")
        command = Path("/proc", str(supervisor["pid"]), "cmdline").read_bytes().split(b"\x00")
        cwd = Path("/proc", str(supervisor["pid"]), "cwd").resolve()
        helpers = [(cwd / os.fsdecode(arg)).resolve() for arg in command if arg and os.fsdecode(arg).endswith("cpu-profile.py")]
        require(HERE / "cpu-profile.py" in helpers and str(work).encode() in command,
                "Supervisor command identity differs")
        os.kill(supervisor["pid"], signal.SIGTERM)
    with (work / "lifecycle.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = load(work / "state.json")
        result = cleanup(work, state)
        journal(work, "stop", result)
        print(json.dumps(result))
        return 0 if result["cleaned"] else 1


def execute(args):
    os.umask(0o077)
    validate_controller_url(args.controller_url)
    for key in ("backend_host", "backend_root", "backend_code", "controller_ip", "image", "agent", "agent_sha256",
                "libs", "uploader", "uploader_sha256", "profile", "receipt", "output"):
        require(getattr(args, key), "Execute requires --" + key.replace("_", "-"))
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}", args.backend_host), "Invalid explicit SSH host")
    for key in ("backend_root", "backend_code"):
        require(Path(getattr(args, key)).is_absolute(), "Backend paths must be absolute")
    if args.backend_output:
        require(Path(args.backend_output).is_absolute(), "Backend output must be absolute")
    require(SHA.fullmatch(args.agent_sha256) and SHA.fullmatch(args.uploader_sha256), "Runtime SHA256 values required")
    require(file_hash(args.agent) == args.agent_sha256 and file_hash(args.uploader) == args.uploader_sha256,
            "Runtime executable SHA256 differs")
    libs = Path(args.libs)
    require(libs.is_absolute() and libs == libs.resolve() and libs.is_dir(), "Canonical runtime libraries directory required")
    library_hashes = {p.name: file_hash(str(p)) for p in libs.iterdir()}
    require(library_hashes, "Agent runtime libraries missing")
    for value in (args.agent, args.libs, args.uploader, args.profile, args.output):
        require("," not in value and "\n" not in value and "\r" not in value, "Mount paths must not contain separator characters")
    require(Path(args.output).is_absolute(), "Output must be absolute")
    original = receipt(args.profile, args.receipt)
    profile = profile_only(HERE, args.controller_ip, args.controller_port, args.ingester_port)
    image = inspect("image", args.image)
    require(image and image["Id"].startswith("sha256:"), "Preloaded image required; no image pull is performed")
    work = private_dir(args.output, fresh=True)
    run = "cpu-" + secrets.token_hex(12)
    names = {kind: "traflens-" + run + "-" + kind for kind in LIMITS}
    names["network"] = "traflens-" + run
    state = {"run": run, "output": str(work), "args": vars(args), "image_id": image["Id"], "names": names,
             "network_modes": {"namespace": names["network"], "agent": "", "upload": ""},
             "controller_attempted": False, "sampling": original, "library_hashes": library_hashes}
    save(work / "state.json", state)
    save(work / "supervisor.json", {"pid": os.getpid(), "start_ticks": process_start(os.getpid())})
    result = {"pass": False, "run": run, "ingestion_verified": False, "sampling_started": False}
    def interrupted(_signum, _frame):
        raise InterruptedError("Lifecycle interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with (work / "lifecycle.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            save(work / "before.json", snapshot(args.controller_ip))
            for kind, name in names.items():
                require(inspect("network" if kind == "network" else "container", name) is None,
                        "Fresh run resource name already exists")
            network = call(["docker", "network", "create", "--driver", "bridge",
                            "--label", "io.traflens.run=" + run, "--label", "io.traflens.output=" + str(work),
                            "--label", "io.traflens.purpose=traflens.cpu-profile.network", names["network"]]).stdout.strip()
            journal(work, "network-created", {"id": network})
            anchor = call(container_base(state, "namespace") + ["--entrypoint", "/usr/bin/sleep", image["Id"], "300"]).stdout.strip()
            require(owned(inspect("container", anchor), state, "namespace"), "Namespace guard failed")
            call(["docker", "start", anchor])
            av = inspect("container", anchor)
            endpoint = av["NetworkSettings"]["Networks"][names["network"]]
            state["network_modes"].update(agent="container:" + anchor, upload="container:" + anchor)
            metadata = dict(original, run=run, app_service=run, ctrl_ip=endpoint["IPAddress"], ctrl_mac=endpoint["MacAddress"],
                            controller_ip=args.controller_ip, controller_port=args.controller_port, ingester_port=args.ingester_port,
                            profile=profile)
            save(work / "metadata.json", metadata)
            state["controller_attempted"] = True
            replace_state(work, state)
            context = backend(state, "prepare", metadata)
            metadata["agent_id"] = context["agent_id"]
            save(work / "ingestion-metadata.json", metadata)
            bootstrap = work / "profile-bootstrap.yaml"
            bootstrap.write_text("controller-ips: [" + args.controller_ip + "]\ncontroller-port: " + str(args.controller_port)
                + "\nvtap-group-id-request: " + json.dumps(context["group_short_uuid"])
                + "\noverride-os-hostname: traflens-" + run + "\nasync-worker-thread-number: 2\nlog-file: /var/log/traflens/deepflow-agent.log\npid-file: /run/traflens/agent.pid\ncgroups-disabled: true\nliveness-probe-enabled: true\nliveness-probe-port: 39091\n")
            logs, native_state = work / "native-logs", work / "native-state"
            logs.mkdir(mode=0o700); native_state.mkdir(mode=0o700)
            argv = container_base(state, "agent") + ["--env", "LD_LIBRARY_PATH=/opt/traflens-libs", "--env", "IN_CONTAINER=yes", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"]
            for source, target, writable in ((args.agent, "/opt/traflens/deepflow-agent", False), (args.libs, "/opt/traflens-libs", False),
                    (bootstrap, "/etc/traflens/agent.yaml", False), (logs, "/var/log/traflens", True), (native_state, "/run/traflens", True)):
                argv += ["--mount", "type=bind,source=" + str(source) + ",target=" + target + ("" if writable else ",readonly")]
            argv += ["--entrypoint", "/usr/bin/timeout", image["Id"], "--signal=TERM", "--kill-after=40s", "180",
                     "/opt/traflens/deepflow-agent", "--cgroups-disabled", "-f", "/etc/traflens/agent.yaml"]
            agent = call(argv).stdout.strip()
            require(owned(inspect("container", agent), state, "agent"), "Agent guard failed")
            call(["docker", "start", agent])
            deadline = time.monotonic() + 65
            while time.monotonic() < deadline:
                info = inspect("container", agent)
                require(owned(info, state, "agent") and info["State"]["Running"], "Owned Agent exited before listener readiness")
                if listener_ready(inspect("container", anchor), logs):
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Actual owned namespace listener was not ready")
            journal(work, "listener-ready", {"actual_socket": True, "port": 39093})
            argv = container_base(state, "upload")
            for source, target in ((args.uploader, "/opt/upload"), (args.profile, "/profile/cpu.pprof")):
                argv += ["--mount", "type=bind,source=" + source + ",target=" + target + ",readonly"]
            argv += ["--entrypoint", "/opt/upload", image["Id"], "--execute", "--profile", "/profile/cpu.pprof",
                     "--sha256", original["profile_sha256"], "--name", run, "--from", str(original["from"]), "--until", str(original["to"])]
            upload = call(argv).stdout.strip()
            require(owned(inspect("container", upload), state, "upload"), "Upload guard failed")
            call(["docker", "start", upload])
            rc = int(call(["docker", "wait", upload], timeout=15).stdout)
            raw = call(["docker", "logs", upload])
            (work / "upload.log").write_text(raw.stdout + raw.stderr)
            require(rc == 0, "Owned upload failed")
            ack = json.loads(raw.stdout)
            require(ack.get("http_acknowledged") is True and ack.get("profile_sha256") == original["profile_sha256"], "Upload acknowledgement differs")
            result.update(http_acknowledged=True, agent_id=context["agent_id"], original_sample=original)
            time.sleep(3)
            result["pass"] = True
        except Exception as error:
            result["error_type"] = type(error).__name__
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            restoration = cleanup(work, state)
            result.update(restoration)
            exit_status = restoration["agent_exit"]
            result["pass"] = bool(result["pass"] and restoration["cleaned"] and exit_status
                                  and exit_status["exit_code"] == 0 and not exit_status["oom"])
            save(work / "result.json", result)
    print(json.dumps(result))
    return 0 if result["pass"] else 1


def replace_state(work, state):
    # Atomic recovery journal: a failed command can be reconciled by fresh labels/names.
    temporary = work / (str(time.time_ns()) + "-state.json")
    save(temporary, state)
    os.replace(temporary, work / "state.json")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    stop_parser = sub.add_parser("stop", help="Stop only resources bound to a private lifecycle receipt")
    stop_parser.add_argument("--output", required=True)
    controller = sub.add_parser("controller", help="Run on the owned backend over SSH; stdin is metadata or stopped proof")
    controller.add_argument("action", choices=("prepare", "cleanup"))
    controller.add_argument("--work", required=True)
    controller.add_argument("--backend-root", required=True)
    controller.add_argument("--server-container", default="traflens-lab-server")
    controller.add_argument("--controller-url", default="http://127.0.0.1:20417")
    parser.add_argument("--execute", action="store_true")
    for key in ("backend-host", "backend-root", "backend-code", "backend-output", "controller-ip", "image", "agent", "agent-sha256",
                "libs", "uploader", "uploader-sha256", "profile", "receipt", "output"):
        parser.add_argument("--" + key)
    parser.add_argument("--controller-port", type=int, default=20035)
    parser.add_argument("--ingester-port", type=int, default=20033)
    parser.add_argument("--controller-url", default="http://127.0.0.1:20417")
    parser.add_argument("--server-container", default="traflens-lab-server")
    args = parser.parse_args(argv)
    if args.command == "controller":
        os.umask(0o077)
        from cpu_profile_controller import dispatch
        dispatch(args)
        return 0
    if args.command == "stop":
        return stop(args.output)
    if not args.execute:
        print(json.dumps({"execute": False, "creates_files": False, "starts_sampling": False, "starts_network": False,
                          "source": "existing_go_runtime_pprof_self_to_native_integration", "agent_license": [11],
                          "profile_port": 39093, "ingestion_verified": False, "max_agent_seconds": 180}))
        return 0
    return execute(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"pass": False, "error_type": type(error).__name__, "private_receipts_retained": True}))
        raise SystemExit(1)
