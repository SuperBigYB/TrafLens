#!/usr/bin/env python3
"""Bounded owned C HTTP workers; only explicit coordinator phase commands emit HTTP."""
import argparse
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

REPO = Path(__file__).resolve().parents[2]
TASK = Path(__file__).resolve().parent
IMAGE = None  # Explicit immutable cached runtime image required for execution.
TRAFFIC_SHA = "1882c6fa3b5c3a18afb4b32c401044f86e750cb671870a2d81f472e8306c212f"
HELPER_SHA = "150b76329362b46aacaeebc5d9dc1bc95c8960025a4dad455ad8b93bc329add7"
PURPOSE = "traflens.managed-ebpf-owned-workload"
PHASES = {"before": (1, 10), "mixed": (2, 20), "after": (3, 10)}
NS_GET_NSTYPE, CLONE_NEWNET = 0xb703, 0x40000000
cancelled = False

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def load_helper():
    path = REPO / "traflens/lab/runtime-netns.py"
    if sha(path) != HELPER_SHA:
        raise RuntimeError("reviewed runtime helper changed")
    spec = importlib.util.spec_from_file_location("managed_runtime_support", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.IMAGE, module.PURPOSE = IMAGE, PURPOSE
    return module

M = load_helper()

def atomic_json(path, value):
    tmp = path.parent / (".json-" + uuid.uuid4().hex)
    with tmp.open("x") as f:
        os.chmod(tmp, 0o600)
        json.dump(value, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def read_private(path):
    st = path.lstat()
    if not path.is_file() or path.is_symlink() or st.st_uid != os.geteuid() or st.st_mode & 0o022:
        raise RuntimeError("unsafe private input")
    if st.st_size > 65536:
        raise RuntimeError("private control input exceeds bound")
    return json.loads(path.read_text())

def expected(marker, role, count):
    return {"marker": marker, "protocol": 20,
            "fixture_kind": "synthetic C HTTP over private loopback",
            "expected_session_copies_per_resource": 2 if role == "positive" else 0,
            "expected_tap_sides": {"c-p": 20, "s-p": 20} if role == "positive" else {},
            "records": [{"request_resource": f"/traflens-ebpf/{marker}/{role}/{i:02d}",
                         "request_domain": "traflens-ebpf.invalid", "request_type": "GET",
                         "response_code": 200, "response_status": 0}
                        for i in range(1, count + 1)]}

def program_type(prog_id):
    """Read only BPF program type/id; never maps, instructions or payload."""
    libc = ctypes.CDLL(None, use_errno=True)
    attr = (ctypes.c_uint32 * 36)()
    attr[0] = prog_id
    fd = libc.syscall(321, 13, ctypes.byref(attr), ctypes.sizeof(attr))
    if fd < 0:
        raise OSError(ctypes.get_errno(), "BPF_PROG_GET_FD_BY_ID")
    try:
        class InfoAttr(ctypes.Structure):
            _fields_ = [("fd", ctypes.c_uint32), ("size", ctypes.c_uint32),
                        ("info", ctypes.c_uint64)]
        info = (ctypes.c_uint32 * 64)()
        request = InfoAttr(fd, ctypes.sizeof(info), ctypes.addressof(info))
        if libc.syscall(321, 15, ctypes.byref(request), ctypes.sizeof(request)):
            raise OSError(ctypes.get_errno(), "BPF_OBJ_GET_INFO_BY_FD")
        if info[1] != prog_id:
            raise RuntimeError("BPF program identity changed")
        return int(info[0])
    finally:
        os.close(fd)

class WorkerSpec(M.Spec):
    def create(self):
        command = super().create()
        command[2:2] = ["--user", "0:0"]
        return command

    def matches(self, value):
        return super().matches(value) and value["Config"].get("User") == "0:0"

class Lease(M.Case):
    def __init__(self, work, traffic):
        super().__init__(work, "managed", traffic, traffic, 18080)
        self.name = self.name.replace("traflens-netns-", "traflens-managed-ebpf-")
        self.marker = "m" + uuid.uuid4().hex[:20]
        self.started = time.monotonic()
        self.lease_deadline = self.started + 360
        self.cleanup_deadline = self.lease_deadline + 60
        self.deadline = self.lease_deadline
        self.phase = 0
        self.agent = None
        self.approved = False
        self.baseline_bpf = M.bpf_ids()
        self.worker_metadata_ids = set()
        self.baseline_tracefs = M.tracefs()
        if any("_deepflow_" in text for text in self.baseline_tracefs.values()):
            raise RuntimeError("existing DeepFlow tracefs hooks")
        p = M.run(["docker", "ps", "-q", "--no-trunc"])
        if p.returncode:
            raise RuntimeError("container inventory failed")
        self.baseline_containers = set(p.stdout.split())
        self.result = {"schema": "traflens.managed-http.workload.v1", "pass": False,
                       "marker": self.marker, "port": self.port, "error": None,
                       "phase_receipts": [], "agent_control_owned_by_coordinator": True}
        self.positive = self.negative = None

    def metadata(self, status):
        return {"schema": "traflens.managed-http.lease.v1", "status": status,
                "marker": self.marker, "port": self.port, "phase": self.phase,
                "supervisor_pid": os.getpid(), "lease_monotonic_deadline": self.lease_deadline,
                "cleanup_monotonic_deadline": self.cleanup_deadline,
                "worker_hard_alarm_seconds": 240, "required_agent_max_lifetime_seconds": 240,
                "traffic_sha256": TRAFFIC_SHA, "image": IMAGE,
                "positive": self.public_pin(self.positive), "negative": self.public_pin(self.negative),
                "agent_registered": self.agent is not None, "agent_scope_approved": self.approved,
                "agent_container_id": self.agent["id"] if self.agent else None,
                "http_requires_explicit_root_phase": True}

    @staticmethod
    def public_pin(pin):
        return {k: v for k, v in pin.items() if k != "fd"} if pin else None

    def publish_status(self, status):
        atomic_json(self.root / "lease.json", self.metadata(status))

    def prepare(self):
        common = [(self.control, "/control", True), (self.evidence, "/evidence", True),
                  (self.traffic_bin, "/traffic", False)]
        for role in ("positive", "negative"):
            argv = ["traffic", "--role", role, "--marker", self.marker,
                    "--seconds", "240", "--port", str(self.port)]
            self.create(WorkerSpec(self, role, "/traffic", argv, common))
            added = set(M.bpf_ids()) - set(self.baseline_bpf)
            if any(program_type(prog) != 15 for prog in added):
                raise RuntimeError("unexpected non-cgroup-device program appeared during worker creation")
            self.worker_metadata_ids = added
        atomic_json(self.root / "inventory-workers.json",
                    {"original_bpf_ids": self.baseline_bpf,
                     "owned_worker_cgroup_device_ids": sorted(self.worker_metadata_ids)})
        self.positive, self.negative = self.pin("positive"), self.pin("negative")
        if self.positive["inode"] == self.negative["inode"]:
            raise RuntimeError("worker network namespaces must be distinct")
        atomic_json(self.root / "expected-positive.json", expected(self.marker, "positive", 20))
        atomic_json(self.root / "expected-negative.json", expected(self.marker, "negative", 40))
        atomic_json(self.root / "inventory-before.json",
                    {"bpf_ids": self.baseline_bpf, "tracefs": self.baseline_tracefs,
                     "running_containers": sorted(self.baseline_containers)})
        self.publish_status("ready_waiting_root_commands")

    def register_agent(self, cid):
        if not re.fullmatch("[0-9a-f]{64}", cid or ""):
            raise ValueError("exact 64-hex Agent container ID required")
        if self.agent and self.agent["id"] != cid:
            raise RuntimeError("Agent identity cannot change within a lease")
        if time.monotonic() > self.started + 120 and not self.agent:
            raise RuntimeError("Agent must register within 120 seconds of lease start")
        value = M.inspect(cid)
        if not value or value["Id"] != cid:
            raise RuntimeError("Agent container does not exist")
        host = value["HostConfig"]
        if host.get("NetworkMode") != "host" or host.get("PidMode") != "host" or host.get("Privileged"):
            raise RuntimeError("expected nonprivileged hostNET/hostPID Agent")
        mount = next((m for m in value.get("Mounts", [])
                      if m.get("Destination") == "/run/traflens/target.netns"), None)
        if not mount or mount.get("RW") or not self.positive:
            raise RuntimeError("Agent needs read-only target namespace bind")
        source = mount["Source"]
        fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
        try:
            if os.fstat(fd).st_ino != self.positive["inode"] or fcntl.ioctl(fd, NS_GET_NSTYPE) != CLONE_NEWNET:
                raise RuntimeError("Agent bind is not the held positive network namespace")
        finally:
            os.close(fd)
        labels = value["Config"].get("Labels") or {}
        if not any(k.startswith("io.traflens.") for k in labels):
            raise RuntimeError("Agent lacks coordinator ownership label")
        if self.agent and self.agent["image_id"] != value["Image"]:
            raise RuntimeError("Agent immutable image identity changed")
        self.agent = {"id": cid, "image_id": value["Image"],
                      "registered_monotonic": self.agent["registered_monotonic"] if self.agent else time.monotonic(),
                      "namespace_bind_verified": True,
                      "max_lifetime_seconds_from_registration": 240}
        self.result["agent"] = self.agent
        self.publish_status("agent_registered_no_http")

    def approve_agent(self, proof):
        self.register_agent(proof.get("agent_container_id"))
        scope = proof.get("scope_map", {})
        if (not isinstance(scope, dict) or type(scope.get("netns_id")) is not int
                or type(scope.get("validated")) is not int
                or scope.get("netns_id") != self.positive["inode"] or scope.get("validated") != 1):
            raise RuntimeError("coordinator scope-map readback does not match pinned namespace")
        if proof.get("scope_fd_pinned") is not True or proof.get("safe_profile_verified") is not True:
            raise RuntimeError("coordinator must verify Agent pinned FD and safe profile")
        if not re.fullmatch("[0-9a-f]{64}", proof.get("agent_binary_sha256", "")):
            raise RuntimeError("exact Agent binary SHA required")
        if not re.fullmatch("[0-9a-f]{40}", proof.get("source_commit", "")):
            raise RuntimeError("exact Agent source commit required")
        timeout, grace = proof.get("hard_timeout_seconds"), proof.get("kill_grace_seconds")
        if (type(timeout) is not int or type(grace) is not int
                or not 1 <= timeout <= 180 or not 0 <= grace <= 40 or timeout + grace > 220):
            raise RuntimeError("coordinator Agent lifetime must be bounded by 180+40 seconds (total at most220)")
        keys = ["agent_container_id", "scope_map", "scope_fd_pinned", "safe_profile_verified",
                "agent_binary_sha256", "source_commit", "hard_timeout_seconds", "kill_grace_seconds"]
        self.result["coordinator_scope_proof"] = {k: proof[k] for k in keys}
        self.result["coordinator_scope_proof_origin"] = "independent coordinator inspection"
        self.approved = True
        self.publish_status("agent_scope_approved_waiting_root_phase")

    def agent_running(self):
        if not self.agent:
            return False
        value = M.inspect(self.agent["id"])
        if not value:
            return False
        if value["Id"] != self.agent["id"] or value["Image"] != self.agent["image_id"]:
            raise RuntimeError("Agent immutable identity changed")
        return bool(value["State"]["Running"])

    def emit_phase(self, phase):
        if phase not in PHASES:
            raise ValueError("unknown phase")
        number, rounds = PHASES[phase]
        if not self.approved or not self.agent_running():
            raise RuntimeError("coordinator-verified Agent must be running before HTTP")
        if number != self.phase + 1:
            raise RuntimeError("phases must execute before -> mixed -> after once")
        if os.fstat(self.positive["fd"]).st_ino != self.positive["inode"]:
            raise RuntimeError("positive namespace ownership changed")
        self.publish_status("executing_root_phase_" + phase)
        if phase == "mixed":
            self.command("positive", 2, 20)
        self.command("negative", number, rounds)
        receipts = [self.receipt("negative", number, rounds, {1: 1, 2: 11, 3: 31}[number])]
        if phase == "mixed":
            receipts.append(self.receipt("positive", 2, 20, 1))
        self.phase = number
        self.result["phase_receipts"].append({"phase": phase, "pass": True, "receipts": receipts})
        atomic_json(self.root / ("phase-" + phase + ".json"), {"pass": True, "receipts": receipts})
        self.publish_status("phase_" + phase + "_complete_waiting_root")

    def cleanup_ready(self):
        # Workers themselves create cgroup_device programs. Those can remain
        # (or disappear after their hard alarm) before worker teardown. Any
        # other new program, including the Agent's, still prevents pin release.
        current, original = set(M.bpf_ids()), set(self.baseline_bpf)
        allowed = original | self.worker_metadata_ids
        return (not self.agent_running() and original <= current <= allowed
                and M.tracefs() == self.baseline_tracefs)

    def final_workload(self):
        if self.phase != 3:
            return False
        for role, count in (("positive", 20), ("negative", 40)):
            # All HTTP phases have finished. These are immutable completed C
            # receipts; validating them must not reuse the expired emit deadline.
            value = read_private(self.evidence / (role + ".result.json"))
            state = self.state(role)
            if (value.get("pass") is not True or value.get("roundtrips") != count
                    or len(value.get("records", [])) != count or value.get("marker") != self.marker
                    or value.get("role") != role or state["Running"] or state["ExitCode"] != 0
                    or state.get("OOMKilled")):
                return False
            self.result[role + "_result"] = value
        return True

    def handle(self, request):
        action = request.get("action")
        if action == "register-agent":
            self.register_agent(request.get("agent_container_id"))
        elif action == "approve-agent":
            self.approve_agent(request.get("proof", {}))
        elif action == "phase":
            self.emit_phase(request.get("phase"))
        elif action == "release":
            if not self.cleanup_ready():
                raise RuntimeError("Agent must exit and BPF/tracefs inventory restore before release")
            return True
        else:
            raise ValueError("unsupported coordinator action")
        return False

    def supervise(self):
        released = False
        try:
            self.prepare()
            print(json.dumps({"ready": True, "lease": str(self.root),
                              "marker": self.marker, "http_emitted": False}), flush=True)
            while time.monotonic() < self.lease_deadline and not cancelled:
                request_path = self.control / "coordinator-request.json"
                if request_path.exists():
                    request = read_private(request_path)
                    nonce = request.get("nonce")
                    if not re.fullmatch("[0-9a-f]{32}", nonce or ""):
                        raise RuntimeError("invalid coordinator request nonce")
                    request_path.unlink()
                    try:
                        released = self.handle(request)
                        answer = {"accepted": True, "nonce": nonce, "phase": self.phase}
                    except (ValueError, RuntimeError) as exc:
                        answer = {"accepted": False, "nonce": nonce, "error": str(exc)}
                    atomic_json(self.control / ("response-" + nonce + ".json"), answer)
                    if released:
                        break
                time.sleep(0.05)
            if not released:
                self.result["error"] = "lease_expired_or_cancelled"
            self.result["workload_complete"] = self.final_workload() if self.phase == 3 else False
        except BaseException as exc:
            self.result["error"] = repr(exc)
        finally:
            self.publish_status("waiting_for_agent_exit_and_inventory_restore")
            while time.monotonic() < self.cleanup_deadline:
                if self.cleanup_ready():
                    break
                atomic_json(self.root / "cleanup-required.json",
                            {"agent_exit_required": True, "namespace_fds_still_held": True,
                             "coordinator_owns_agent_stop": True})
                time.sleep(1)
            safe = self.cleanup_ready()
            self.result["external_agent_exit_and_inventory_restored"] = safe
            if safe:
                errors = super().cleanup()
                until = time.monotonic() + 5
                while time.monotonic() < until and set(M.bpf_ids()) != set(self.baseline_bpf):
                    time.sleep(0.1)
                self.result["original_host_bpf_inventory_restored"] = set(M.bpf_ids()) == set(self.baseline_bpf)
                self.result["original_tracefs_restored"] = M.tracefs() == self.baseline_tracefs
                if not self.result["original_host_bpf_inventory_restored"] or not self.result["original_tracefs_restored"]:
                    errors.append("original host BPF/tracefs inventory did not restore after worker cleanup")
            else:
                errors = ["Agent or BPF/tracefs remains active; worker/pin cleanup deferred"]
            self.result["cleanup_errors"] = errors
            current = M.run(["docker", "ps", "-q", "--no-trunc"])
            self.result["preexisting_containers_still_running"] = (
                current.returncode == 0 and self.baseline_containers <= set(current.stdout.split()))
            self.result["pass"] = bool(self.result.get("workload_complete") and not self.result["error"]
                and safe and not errors and self.result["preexisting_containers_still_running"])
            self.publish_status("complete" if self.result["pass"] else "failed")
            atomic_json(self.root / "result.json", self.result)
            print(json.dumps({"pass": self.result["pass"], "lease": str(self.root),
                              "workload_complete": self.result.get("workload_complete"),
                              "cleanup_errors": errors}), flush=True)
        return 0 if self.result["pass"] else 1

def control(lease_path, request):
    value = read_private(lease_path / "lease.json")
    if value.get("schema") != "traflens.managed-http.lease.v1":
        raise RuntimeError("not a managed workload lease")
    root = lease_path / "control"
    lock = (root / "coordinator.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    pending = root / "coordinator-request.json"
    if pending.exists():
        raise RuntimeError("another coordinator command is pending")
    nonce = uuid.uuid4().hex
    request["nonce"] = nonce
    atomic_json(pending, request)
    response = root / ("response-" + nonce + ".json")
    until = time.monotonic() + 40
    while time.monotonic() < until:
        if response.exists():
            value = read_private(response)
            print(json.dumps(value))
            return 0 if value.get("accepted") else 1
        time.sleep(0.05)
    raise TimeoutError("coordinator request has no acknowledgement")

def interrupted(_sig, _frame):
    global cancelled
    cancelled = True

def main():
    global IMAGE
    parser = argparse.ArgumentParser()
    parser.add_argument("action", nargs="?", default="plan", choices=["plan", "prepare", "register-agent", "approve-agent", "phase", "release"])
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--work", type=Path, default=TASK / "runs")
    parser.add_argument("--lease", type=Path)
    parser.add_argument("--traffic-bin", type=Path, default=TASK / "assets/gate-traffic")
    parser.add_argument("--agent-id")
    parser.add_argument("--image", help="Cached immutable sha256 image ID; never pulled")
    parser.add_argument("--proof", type=Path)
    parser.add_argument("--phase", choices=PHASES)
    args = parser.parse_args()
    if args.action == "plan" or not args.execute:
        print(json.dumps({"execute": False, "port": 18080, "positive": 20, "negative": [10,20,10],
                          "expected_l7_sessions": 40, "c_p": 20, "s_p": 20,
                          "traffic_sha256": TRAFFIC_SHA, "image": IMAGE,
                          "agent_control": "coordinator only", "http_control": "explicit phase commands"}))
        return 0
    if os.geteuid() != 0:
        raise RuntimeError("root required")
    os.umask(0o077)
    if args.action == "prepare":
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image or ""):
            raise RuntimeError("--image must be an immutable cached sha256 image ID")
        IMAGE = M.IMAGE = args.image
        image = M.run(["docker", "image", "inspect", IMAGE])
        if image.returncode or json.loads(image.stdout)[0]["Id"] != IMAGE:
            raise RuntimeError("Exact runtime image is not cached")
        if not args.work.is_absolute() or args.work != args.work.resolve():
            raise RuntimeError("Canonical absolute work directory required")
        traffic = M.regular_executable(args.traffic_bin)
        if sha(traffic) != TRAFFIC_SHA:
            raise RuntimeError("unverified C traffic artifact")
        args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
        if args.work.stat().st_mode & 0o077:
            raise RuntimeError("work root must be private")
        lock = (args.work / "prepare.lock").open("a")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = M.run(["docker", "ps", "-aq", "--filter", "label=io.traflens.purpose=" + PURPOSE])
        if current.returncode or current.stdout.strip():
            raise RuntimeError("an earlier owned workload still exists")
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, interrupted)
        return Lease(args.work, traffic).supervise()
    if not args.lease:
        raise RuntimeError("--lease is required")
    request = {"action": args.action}
    if args.action == "register-agent":
        request["agent_container_id"] = args.agent_id
    elif args.action == "approve-agent":
        if not args.proof:
            raise RuntimeError("--proof is required")
        request["proof"] = read_private(args.proof)
    elif args.action == "phase":
        request["phase"] = args.phase
    return control(args.lease, request)

if __name__ == "__main__":
    raise SystemExit(main())
