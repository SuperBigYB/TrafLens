#!/usr/bin/env python3
"""Bounded private-netns synthetic gate supervisor. Default is an offline plan."""
import argparse
import ctypes
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import time
import uuid

IMAGE = "ghcr.io/deepflowio/rust-build@sha256:b018b2a5970d3c8f36a95f56dec56ad780020ec782419e42c571c7be5867d310"
PURPOSE = "traflens.exclusive-netns-synthetic-gate"
NS_GET_NSTYPE = 0xb703
CLONE_NEWNET = 0x40000000
CAPS = ["SYS_ADMIN", "SYS_RESOURCE", "BPF", "PERFMON"]
TRACING_MOUNTS = [
    ("/sys/kernel/debug", "/sys/kernel/debug", False),
    ("/sys/kernel/tracing", "/sys/kernel/tracing", False),
    ("/sys/kernel/btf", "/sys/kernel/btf", False),
]
def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n")

def run(args, timeout=15):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout)

def inspect(ref):
    p = run(["docker", "inspect", ref])
    if p.returncode:
        # A daemon or permission error is not proof of absence.
        error = p.stderr.lower()
        if "no such object" in error or "no such container" in error:
            return None
        raise RuntimeError("docker inspect failed")
    value = json.loads(p.stdout)
    if len(value) != 1:
        raise RuntimeError("ambiguous container identity")
    return value[0]

def bpf_ids():
    if os.uname().machine != "x86_64":
        raise RuntimeError("BPF inventory syscall is qualified for x86_64 only")
    libc = ctypes.CDLL(None, use_errno=True)
    ids, start = [], 0
    for _ in range(200000):
        attr = (ctypes.c_uint32 * 36)()
        attr[0] = start
        ret = libc.syscall(321, 11, ctypes.byref(attr), ctypes.sizeof(attr))
        if ret:
            err = ctypes.get_errno()
            if err == 2:
                return ids
            raise OSError(err, "BPF_PROG_GET_NEXT_ID")
        nxt = int(attr[1])
        if nxt <= start:
            raise RuntimeError("non-increasing program ID")
        ids.append(nxt)
        start = nxt
    raise RuntimeError("BPF inventory bound exceeded")

def tracefs():
    root = Path("/sys/kernel/debug/tracing")
    return {n: (root / n).read_text() for n in ("kprobe_events", "uprobe_events")}

def regular_executable(path):
    path = Path(path).resolve(strict=True)
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111 or st.st_mode & 0o022:
        raise RuntimeError("unsafe executable")
    return path

class Spec:
    def __init__(self, case, role, executable, argv, mounts):
        self.name = case.name + "-" + role
        self.role = role
        self.executable = executable
        self.argv = argv
        self.mounts = list(mounts)
        self.run_id = case.name
        self.tracer = role == "tracer"

    def create(self):
        args = ["docker", "create", "--name", self.name,
                "--label", "io.traflens.purpose=" + PURPOSE,
                "--label", "io.traflens.run=" + self.run_id,
                "--label", "io.traflens.role=" + self.role,
                "--network", "none", "--cpuset-cpus", "0,1",
                "--cpus", "2" if self.tracer else "0.25",
                "--memory", "2g" if self.tracer else "64m",
                "--memory-swap", "2g" if self.tracer else "64m",
                "--pids-limit", "256" if self.tracer else "8",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--log-driver", "none", "--entrypoint", self.executable]
        if self.tracer:
            args += ["--pid", "host"]
            for cap in CAPS:
                args += ["--cap-add", cap]
            args += ["--ulimit", "memlock=-1:-1"]
        for src, dst, writable in self.mounts:
            args += ["--mount", "type=bind,source=" + str(src) + ",target=" + dst +
                     ("" if writable else ",readonly")]
        return args + [IMAGE] + self.argv

    def matches(self, c):
        if not c:
            return False
        cfg, host = c["Config"], c["HostConfig"]
        labels = cfg.get("Labels") or {}
        actual = {(m["Source"], m["Destination"], bool(m["RW"])) for m in c.get("Mounts", [])}
        expected = {(str(s), d, w) for s, d, w in self.mounts}
        return (c["Name"] == "/" + self.name and cfg["Image"] == IMAGE and
                labels.get("io.traflens.purpose") == PURPOSE and
                labels.get("io.traflens.run") == self.run_id and
                labels.get("io.traflens.role") == self.role and
                cfg.get("Entrypoint") == [self.executable] and
                (cfg.get("Cmd") or []) == self.argv and
                host.get("NetworkMode") == "none" and
                host.get("PidMode") == ("host" if self.tracer else "") and
                not host.get("Privileged") and actual == expected and
                set(host.get("CapDrop") or []) == {"ALL"} and
                {v.removeprefix("CAP_") for v in (host.get("CapAdd") or [])} ==
                (set(CAPS) if self.tracer else set()) and
                host.get("Memory") == (2147483648 if self.tracer else 67108864) and
                host.get("PidsLimit") == (256 if self.tracer else 8))

class Case:
    def __init__(self, work, mode, tracer_bin, traffic_bin, port):
        self.name = "traflens-netns-" + uuid.uuid4().hex[:12]
        self.mode, self.port = mode, port
        self.root = work / (mode + "-" + self.name[-12:])
        self.root.mkdir(mode=0o700)
        self.control, self.evidence = self.root / "control", self.root / "evidence"
        self.control.mkdir(mode=0o700)
        self.evidence.mkdir(mode=0o700)
        self.tracer_bin, self.traffic_bin = tracer_bin, traffic_bin
        self.specs, self.ids, self.fds, self.children = [], {}, [], []
        self.deadline = time.monotonic() + 210
        self.result = {"schema": "traflens.netns-gate.private.v1", "mode": mode,
                       "pass": False, "source_sha256": {}, "error": None}
        self.started = time.monotonic()

    def check_time(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("case wall-clock deadline")

    def create(self, spec):
        if inspect(spec.name) is not None:
            raise RuntimeError("fresh name already exists")
        self.specs.append(spec)  # Uncertain creation remains owned and must be inspected.
        write_json(self.root / (spec.role + "-create-command.json"), spec.create())
        p = run(spec.create(), timeout=20)
        c = inspect(spec.name)
        if c and not spec.matches(c):
            raise RuntimeError("created object scope mismatch")
        if c:
            self.ids[spec.role] = c["Id"]
        if p.returncode or not c or not re.fullmatch("[0-9a-f]{64}", p.stdout.strip()):
            raise RuntimeError("container creation failed or uncertain")
        if p.stdout.strip() != c["Id"]:
            raise RuntimeError("create ID mismatch")
        def log_bound():
            resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))
        with (self.root / (spec.role + "-console.log")).open("w") as log:
            child = subprocess.Popen(["docker", "start", "--attach", c["Id"]],
                                     stdout=log, stderr=subprocess.STDOUT, text=True,
                                     preexec_fn=log_bound)
        self.children.append(child)
        until = min(self.deadline, time.monotonic() + 15)
        while time.monotonic() < until:
            state = self.state(spec.role)
            if state["Running"]:
                return c["Id"]
            if child.poll() is not None:
                raise RuntimeError("container start failed")
            time.sleep(0.05)
        raise TimeoutError("container did not start")

    def state(self, role):
        c = inspect(self.ids[role])
        spec = next(s for s in self.specs if s.role == role)
        if not spec.matches(c):
            raise RuntimeError("container ownership changed")
        return c["State"]

    def wait_json(self, name, role="tracer", seconds=75):
        until = min(self.deadline, time.monotonic() + seconds)
        p = self.evidence / name
        while time.monotonic() < until:
            if p.exists():
                st = p.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
                    raise RuntimeError("unsafe evidence entry")
                obj = json.loads(p.read_text())
                if not obj.get("pass", obj.get("ready", False)):
                    raise RuntimeError("gate reported failed: " + name)
                return obj
            state = self.state(role)
            if not state["Running"]:
                self.result[role + "_failure_state"] = state
                raise RuntimeError(role + " exited before " + name)
            time.sleep(0.05)
        raise TimeoutError("waiting for " + name)

    def wait_exit(self, role, seconds=20):
        until = min(self.deadline, time.monotonic() + seconds)
        while time.monotonic() < until:
            state = self.state(role)
            if not state["Running"]:
                if state["ExitCode"] != 0 or state.get("OOMKilled"):
                    raise RuntimeError(role + " failed")
                return state
            time.sleep(0.05)
        raise TimeoutError(role + " did not terminate")

    def pin(self, role):
        state = self.state(role)
        pid = state["Pid"]
        if not state["Running"] or pid <= 0:
            raise RuntimeError("namespace owner is not running")
        ns = os.open("/proc/" + str(pid) + "/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        self.fds.append(ns)
        inode = os.fstat(ns).st_ino
        if fcntl.ioctl(ns, NS_GET_NSTYPE) != CLONE_NEWNET or not 0 < inode <= 0xffffffff:
            raise RuntimeError("not a representable network namespace")
        # Same PID/executable must still be the container ENTRYPOINT after opening nsfs.
        if self.state(role)["Pid"] != pid:
            raise RuntimeError("namespace owner changed")
        executable = self.traffic_bin if role in ("positive", "negative") else Path("/usr/bin/sleep")
        if role in ("positive", "negative"):
            if sha("/proc/" + str(pid) + "/exe") != sha(executable):
                raise RuntimeError("ENTRYPOINT executable mismatch")
            ready = self.wait_json(role + ".ready.json", role)
            if ready.get("role") != role or ready.get("marker") != self.marker or ready.get("netns_inode") != inode:
                raise RuntimeError("worker readiness identity mismatch")
        return {"pid": pid, "inode": inode, "fd": ns,
                "source": "/proc/" + str(os.getpid()) + "/fd/" + str(ns)}

    def command(self, role, phase, rounds):
        valid = ((role == "positive" and phase == 2 and rounds == 20) or
                 (role == "negative" and (phase, rounds) in [(1, 10), (2, 20), (3, 10)]))
        if not valid:
            raise ValueError("unknown synthetic phase")
        path = self.control / (role + ".command")
        temp = self.control / ("command-" + uuid.uuid4().hex)
        with temp.open("x") as f:
            f.write(str(phase) + " " + str(rounds) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)

    def receipt(self, role, phase, rounds, first):
        r = self.wait_json(role + "." + str(phase) + ".done", role)
        expected = {"phase": phase, "rounds_requested": rounds, "roundtrips": rounds,
                    "marker": self.marker, "role": role, "first_index": first}
        if any(r.get(k) != v for k, v in expected.items()):
            raise RuntimeError("synthetic receipt contract mismatch")
        return r

    def execute(self):
        self.marker = "s" + uuid.uuid4().hex[:20]
        common = [(self.control, "/control", True), (self.evidence, "/evidence", True),
                  (self.traffic_bin, "/traffic", False)]
        for role in ("positive", "negative"):
            argv = ["traffic", "--role", role, "--marker", self.marker, "--seconds", "240",
                    "--port", str(self.port)]
            self.create(Spec(self, role, "/traffic", argv, common))
        positive, negative = self.pin("positive"), self.pin("negative")
        if positive["inode"] == negative["inode"]:
            raise RuntimeError("workers do not have distinct private namespaces")
        target = positive
        if self.mode == "deny":
            # Fresh owned quiet namespace, pinned independently; no arbitrary inode.
            self.create(Spec(self, "quiet", "/usr/bin/sleep", ["240"], []))
            target = self.pin("quiet")
            if target["inode"] in (positive["inode"], negative["inode"]):
                raise RuntimeError("deny namespace collides with traffic namespace")
        mounts = [(self.control, "/control", True), (self.evidence, "/evidence", True),
                  (self.tracer_bin, "/gate", False)] + TRACING_MOUNTS
        argv = ["trace", "--mode", self.mode, "--marker", self.marker,
                "--positive-tgid", str(positive["pid"]), "--seconds", "180",
                "--port", str(self.port)]
        if self.mode != "legacy":
            mounts += [(Path(target["source"]), "/target-netns", False)]
            argv += ["--target-netns", "/target-netns", "--expected-inode", str(target["inode"])]
        self.create(Spec(self, "tracer", "/gate", argv, mounts))
        loader = self.state("tracer")["Pid"]
        loader_inode = os.stat("/proc/" + str(loader) + "/ns/net").st_ino
        if loader_inode in (positive["inode"], negative["inode"], target["inode"]):
            raise RuntimeError("loader must be in a different private namespace")
        self.result["namespace_ownership"] = {
            "positive": {k: v for k, v in positive.items() if k != "fd"},
            "negative": {k: v for k, v in negative.items() if k != "fd"},
            "target": {k: v for k, v in target.items() if k != "fd"},
            "loader_pid": loader, "loader_inode": loader_inode,
            "namespace_fds_held_through_detach": True}
        ready = self.wait_json("ready.json")
        if (not ready.get("running") or not ready.get("maps_verified") or
                ready.get("positive_tgid") != positive["pid"] or
                ready.get("marker") != self.marker or ready.get("mode") != self.mode or
                ready.get("target_inode") != (0 if self.mode == "legacy" else target["inode"])):
            raise RuntimeError("tracer readiness identity or map readback failed")
        self.result["ready"] = ready
        self.command("negative", 1, 10)
        self.receipt("negative", 1, 10, 1)
        self.wait_json("negative-before.checked.json")
        self.command("positive", 2, 20)
        self.command("negative", 2, 20)
        self.receipt("positive", 2, 20, 1)
        self.receipt("negative", 2, 20, 11)
        drain = self.wait_json("drained.json", seconds=20)
        expected_payload = 80 if self.mode == "scoped" else 0
        if drain.get("payload_reads") != expected_payload:
            raise RuntimeError("exact payload callback count failed")
        self.command("negative", 3, 10)
        self.receipt("negative", 3, 10, 31)
        self.wait_json("negative-after.checked.json", seconds=20)
        (self.control / "stop").touch(exist_ok=False)
        self.wait_exit("tracer")
        gate = self.wait_json("gate.json")
        if (gate.get("payload_reads") != expected_payload or
                gate.get("foreign_pid_records") or gate.get("outside_pid_payload_read") or
                gate.get("invalid_metadata") or gate.get("invalid_wire") or
                gate.get("attached_wrappers_after") != 0):
            raise RuntimeError("final capture or detach contract failed")
        for role, expected in (("positive", 20), ("negative", 40)):
            r = self.wait_json(role + ".result.json", role)
            self.wait_exit(role)
            if r.get("roundtrips") != expected or len(r.get("records", [])) != expected:
                raise RuntimeError("synthetic worker final count failed")
        self.result["gate"] = gate
        self.result["pass"] = True

    def cleanup(self):
        errors = []
        tracer = next((s for s in self.specs if s.role == "tracer"), None)
        tracer_gone = tracer is None
        # A failed/unknown tracer stop must never release namespace pins or
        # remove workers. Retry only the exact immutable owned ID, then verify.
        if tracer is not None:
            try:
                c = inspect(self.ids.get("tracer", tracer.name))
                if c is None:
                    tracer_gone = True
                else:
                    if not tracer.matches(c):
                        raise RuntimeError("tracer cleanup ownership mismatch")
                    cid = c["Id"]
                    if c["State"]["Running"]:
                        run(["docker", "stop", "--time", "5", cid], timeout=15)
                        c = inspect(cid)
                        if c is not None and not tracer.matches(c):
                            raise RuntimeError("tracer ownership changed during stop")
                    if c is not None and c["State"]["Running"]:
                        # The exact owned process failed graceful stop; force
                        # removal only after rechecking its immutable identity.
                        run(["docker", "rm", "--force", cid], timeout=15)
                        c = inspect(cid)
                        if c is not None and not tracer.matches(c):
                            raise RuntimeError("tracer ownership changed during recovery")
                    if c is not None and c["State"]["Running"]:
                        raise RuntimeError("owned tracer still running; retain namespace pins and workers")
                    tracer_gone = True
                    if c is not None:
                        p = run(["docker", "rm", cid])
                        if p.returncode or inspect(cid) is not None:
                            errors.append("stopped owned tracer container removal failed")
            except BaseException as exc:
                errors.append("tracer: " + repr(exc))
        if not tracer_gone:
            self.result["namespace_pins_released"] = False
            self.result["workers_cleanup_deferred"] = True
            return errors
        self.result["tracer_exit_confirmed_before_namespace_release"] = True
        for role in ["positive", "negative", "quiet"]:
            spec = next((s for s in self.specs if s.role == role), None)
            if not spec:
                continue
            try:
                c = inspect(self.ids.get(role, spec.name))
                if c is None:
                    continue
                if not spec.matches(c):
                    raise RuntimeError("cleanup ownership mismatch")
                cid = c["Id"]
                if c["State"]["Running"]:
                    p = run(["docker", "stop", "--time", "5", cid], timeout=15)
                    if p.returncode:
                        raise RuntimeError("owned stop failed")
                p = run(["docker", "rm", cid])
                if p.returncode or inspect(cid) is not None:
                    raise RuntimeError("owned removal failed")
            except BaseException as exc:
                errors.append(role + ": " + repr(exc))
        for fd in self.fds:
            os.close(fd)
        self.fds.clear()
        self.result["namespace_pins_released"] = True
        for child in self.children:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
                errors.append("owned Docker attach child did not exit")
        return errors

def interrupted(sig, _frame):
    raise KeyboardInterrupt("signal " + str(sig))

def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path)
    parser.add_argument("--tracer-bin", type=Path)
    parser.add_argument("--traffic-bin", type=Path)
    parser.add_argument("--port", type=int, default=18089)
    parser.add_argument("--mode", choices=["all", "legacy", "deny", "scoped"], default="all")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1..65535")
    return args

def main():
    args = arguments()
    if not args.execute:
        print(json.dumps({"execute": False, "modes": ["legacy", "deny", "scoped"],
                          "positive_roundtrips_per_case": 20, "negative_roundtrips_per_case": 40,
                          "scoped_exact_payload_callbacks": 80, "port": args.port,
                          "loader_namespace_distinct": True, "namespace_fd_pinned": True, "loader_pid_mode": "host",
                          "traffic_pid_mode": "private", "traffic_process_entrypoint": "stdlib C"}))
        return 0
    if os.geteuid() != 0 or not all([args.work, args.tracer_bin, args.traffic_bin]):
        raise RuntimeError("explicit work and binaries are required as root")
    os.umask(0o077)
    work = args.work.resolve()
    work.mkdir(parents=True, mode=0o700, exist_ok=True)
    st = work.stat()
    if work.is_symlink() or st.st_uid != 0 or st.st_mode & 0o077:
        raise RuntimeError("work must be an owned private directory")
    lock = (work / "runtime.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    tracer_bin, traffic_bin = map(regular_executable, [args.tracer_bin, args.traffic_bin])
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    assert Path("/proc/sys/net/core/bpf_jit_enable").read_text().strip() == "1"
    active = run(["docker", "ps", "-aq", "--filter", "label=io.traflens.purpose=" + PURPOSE])
    if active.returncode or active.stdout.strip():
        raise RuntimeError("another gate container exists or inventory failed")
    for item in Path("/proc").iterdir():
        if item.name.isdecimal():
            try:
                comm = (item / "comm").read_text().strip()
            except OSError:
                continue
            if comm in {"deepflow-agent", "socket_tracer", "tlens-ebpf-gate"}:
                raise RuntimeError("existing socket tracer process")
    initial_tracefs, initial_ids = tracefs(), bpf_ids()
    if any("_deepflow_" in value for value in initial_tracefs.values()):
        raise RuntimeError("existing DeepFlow attachment")
    p = run(["docker", "ps", "-q", "--no-trunc"])
    if p.returncode:
        raise RuntimeError("container inventory failed")
    initial_containers = set(p.stdout.split())
    overall = {"schema": "traflens.netns-gate.private.aggregate.v1", "pass": False,
               "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source_binaries": {"tracer": sha(tracer_bin), "traffic": sha(traffic_bin)},
               "cases": []}
    modes = ["legacy", "deny", "scoped"] if args.mode == "all" else [args.mode]
    try:
        for mode in modes:
            case = Case(work, mode, tracer_bin, traffic_bin, args.port)
            try:
                case.execute()
            except BaseException as exc:
                case.result["error"] = repr(exc)
                case.result["pass"] = False
            finally:
                case.result["cleanup_errors"] = case.cleanup()
                time.sleep(1)
                now_ids, now_tracefs = bpf_ids(), tracefs()
                own = case.result.get("gate", {}).get("own_program_ids", [])
                if not own and (case.evidence / "gate.json").is_file():
                    try:
                        own = json.loads((case.evidence / "gate.json").read_text()).get("own_program_ids", [])
                    except (ValueError, OSError):
                        pass
                case.result["own_program_ids_gone"] = bool(own) and not set(own) & set(now_ids)
                case.result["bpf_inventory_restored"] = set(now_ids) == set(initial_ids)
                case.result["tracefs_unchanged"] = now_tracefs == initial_tracefs
                p = run(["docker", "ps", "-q", "--no-trunc"])
                case.result["preexisting_containers_still_running"] = p.returncode == 0 and initial_containers <= set(p.stdout.split())
                case.result["pass"] = bool(case.result["pass"] and not case.result["cleanup_errors"] and
                    case.result["own_program_ids_gone"] and case.result["bpf_inventory_restored"] and
                    case.result["tracefs_unchanged"] and case.result["preexisting_containers_still_running"])
                write_json(case.root / "result.json", case.result)
                overall["cases"].append(case.result)
            if not case.result["pass"]:
                break
        overall["pass"] = len(overall["cases"]) == len(modes) and all(c["pass"] for c in overall["cases"])
    finally:
        overall["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write_json(work / "result.json", overall)
    print(json.dumps({"pass": overall["pass"], "cases": [
        {"mode": c["mode"], "pass": c["pass"], "error": c["error"],
         "payload_reads": c.get("gate", {}).get("payload_reads")} for c in overall["cases"]]}))
    return 0 if overall["pass"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
