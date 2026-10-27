#!/usr/bin/env python3
"""No Docker, socket, namespace, or tracing operations in these supervisor tests."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
spec = importlib.util.spec_from_file_location("runtime_netns", Path(__file__).resolve().parents[1] / "runtime-netns.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def fixture(spec, running=False):
    return {
        "Name": "/" + spec.name, "Id": "a" * 64, "State": {"Running": running, "Pid": 42, "ExitCode": 0},
        "Config": {"Image": m.IMAGE, "Labels": {"io.traflens.purpose": m.PURPOSE,
            "io.traflens.run": spec.run_id, "io.traflens.role": spec.role},
            "Entrypoint": [spec.executable], "Cmd": spec.argv},
        "HostConfig": {"NetworkMode": "none", "PidMode": "host" if spec.tracer else "",
            "Privileged": False, "CapDrop": ["ALL"], "CapAdd": m.CAPS if spec.tracer else [],
            "Memory": 2147483648 if spec.tracer else 67108864, "PidsLimit": 256 if spec.tracer else 8},
        "Mounts": [{"Source": str(s), "Destination": d, "RW": w} for s, d, w in spec.mounts]
    }

class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.case = m.Case(Path(self.tmp.name), "scoped", Path("/owned/gate"), Path("/owned/traffic"), 18089)
        self.spec = m.Spec(self.case, "tracer", "/gate", ["trace", "--mode", "scoped"],
                           [(Path("/owned/control"), "/control", True), (Path("/owned/gate"), "/gate", False)])

    def test_missing_object_cli_case_and_real_errors(self):
        for error in ["Error: No such object: owned", "error: no such object: owned",
                      "Error response from daemon: No such container: owned"]:
            with patch.object(m, "run", return_value=subprocess.CompletedProcess([], 1, "[]", error)):
                self.assertIsNone(m.inspect("owned"))
        for error in ["permission denied", "Cannot connect to Docker daemon"]:
            with patch.object(m, "run", return_value=subprocess.CompletedProcess([], 1, "", error)):
                self.assertRaises(RuntimeError, m.inspect, "owned")

    def test_exact_identity_accepted(self):
        self.assertTrue(self.spec.matches(fixture(self.spec)))

    def test_identity_and_permission_mutations_rejected(self):
        changes = [
            lambda c: c.update(Name="/other"),
            lambda c: c["Config"].update(Image="untrusted"),
            lambda c: c["Config"]["Labels"].update({"io.traflens.run": "other"}),
            lambda c: c["Config"].update(Entrypoint=["/bin/sh"]),
            lambda c: c["Config"].update(Cmd=["other"]),
            lambda c: c["HostConfig"].update(NetworkMode="host"),
            lambda c: c["HostConfig"].update(PidMode=""),
            lambda c: c["HostConfig"].update(Privileged=True),
            lambda c: c["HostConfig"].update(CapDrop=[]),
            lambda c: c["HostConfig"].update(CapAdd=m.CAPS + ["SYS_PTRACE"]),
            lambda c: c["HostConfig"].update(Memory=0),
            lambda c: c["HostConfig"].update(PidsLimit=-1),
            lambda c: c["Mounts"].append({"Source": "/var/run/docker.sock", "Destination": "/docker", "RW": True}),
            lambda c: c["Mounts"][1].update(RW=True),
        ]
        for change in changes:
            with self.subTest(change=change):
                c = fixture(self.spec)
                change(c)
                self.assertFalse(self.spec.matches(c))

    def test_docker_cap_prefix_normalization_preserves_exact_whitelist(self):
        c = fixture(self.spec)
        c["HostConfig"]["CapAdd"] = ["CAP_" + v for v in m.CAPS]
        self.assertTrue(self.spec.matches(c))
        c["HostConfig"]["CapAdd"].append("CAP_SYS_PTRACE")
        self.assertFalse(self.spec.matches(c))

    def test_worker_is_private_pid_and_zero_capability(self):
        worker = m.Spec(self.case, "positive", "/traffic", ["traffic"], [])
        self.assertTrue(worker.matches(fixture(worker)))
        cmd = worker.create()
        self.assertNotIn("--pid", cmd)
        self.assertNotIn("--cap-add", cmd)
        self.assertEqual(cmd[cmd.index("--entrypoint") + 1], "/traffic")

    def test_tracer_has_host_pid_but_private_network(self):
        cmd = self.spec.create()
        self.assertEqual(cmd[cmd.index("--pid") + 1], "host")
        self.assertEqual(cmd[cmd.index("--network") + 1], "none")

    def test_unknown_phase_does_not_publish(self):
        self.case.marker = "scopeunit01234567"
        for value in [("positive", 1, 20), ("positive", 2, 21), ("negative", 4, 10), ("wrong", 1, 10)]:
            with self.subTest(value=value):
                self.assertRaises(ValueError, self.case.command, *value)
        self.assertEqual(list(self.case.control.iterdir()), [])

    def test_commands_are_exact_and_atomic(self):
        self.case.command("negative", 1, 10)
        self.assertEqual((self.case.control / "negative.command").read_bytes(), b"1 10\n")
        self.case.command("negative", 2, 20)
        self.assertEqual((self.case.control / "negative.command").read_bytes(), b"2 20\n")
        self.assertEqual(len(list(self.case.control.iterdir())), 1)

    def test_receipt_marker_and_count_must_match(self):
        self.case.marker = "scopeunit01234567"
        expected = {"pass": True, "phase": 1, "rounds_requested": 10, "roundtrips": 10,
                    "marker": self.case.marker, "role": "negative", "first_index": 1}
        with patch.object(self.case, "wait_json", return_value=expected):
            self.assertEqual(self.case.receipt("negative", 1, 10, 1), expected)
        for key, value in [("marker", "other"), ("roundtrips", 9), ("role", "positive"), ("first_index", 11)]:
            bad = dict(expected, **{key: value})
            with patch.object(self.case, "wait_json", return_value=bad):
                self.assertRaises(RuntimeError, self.case.receipt, "negative", 1, 10, 1)

    def test_cleanup_deletes_only_exact_owned_container(self):
        self.case.specs = [self.spec]
        c = fixture(self.spec, True)
        calls = []
        def fake_inspect(_ref):
            return None if any(x[:2] == ["docker", "rm"] for x in calls) else c
        def fake_run(args, **_kw):
            calls.append(args)
            if args[:2] == ["docker", "stop"]:
                c["State"]["Running"] = False
            return subprocess.CompletedProcess(args, 0, "", "")
        with patch.object(m, "inspect", side_effect=fake_inspect), patch.object(m, "run", side_effect=fake_run):
            self.assertEqual(self.case.cleanup(), [])
        self.assertEqual(calls, [["docker", "stop", "--time", "5", "a" * 64], ["docker", "rm", "a" * 64]])

    def test_cleanup_refuses_unknown_identity(self):
        self.case.specs = [self.spec]
        bad = fixture(self.spec)
        bad["Config"]["Labels"]["io.traflens.run"] = "other"
        with patch.object(m, "inspect", return_value=bad), patch.object(m, "run") as run:
            self.assertTrue(self.case.cleanup())
            run.assert_not_called()

    def test_unknown_tracer_defers_workers_and_namespace_release(self):
        worker = m.Spec(self.case, "positive", "/traffic", ["traffic"], [])
        self.case.specs = [self.spec, worker]
        self.case.ids = {"tracer": "a" * 64, "positive": "b" * 64}
        self.case.fds = [123]
        bad = fixture(self.spec, True)
        bad["HostConfig"]["Privileged"] = True
        with patch.object(m, "inspect", return_value=bad), patch.object(m, "run") as run, patch.object(m.os, "close") as close:
            self.assertTrue(self.case.cleanup())
            run.assert_not_called()
            close.assert_not_called()
        self.assertEqual(self.case.fds, [123])
        self.assertFalse(self.case.result["namespace_pins_released"])
        self.assertTrue(self.case.result["workers_cleanup_deferred"])

    def test_stop_failure_still_running_retains_workers_and_pins(self):
        worker = m.Spec(self.case, "positive", "/traffic", ["traffic"], [])
        self.case.specs = [self.spec, worker]
        self.case.fds = [123]
        c = fixture(self.spec, True)
        calls = []
        def fake_run(args, **_kw):
            calls.append(args)
            return subprocess.CompletedProcess(args, 1, "", "failed")
        with patch.object(m, "inspect", return_value=c), patch.object(m, "run", side_effect=fake_run), patch.object(m.os, "close") as close:
            self.assertTrue(self.case.cleanup())
            close.assert_not_called()
        self.assertEqual(calls, [["docker", "stop", "--time", "5", "a" * 64],
                                 ["docker", "rm", "--force", "a" * 64]])
        self.assertEqual(self.case.fds, [123])
        self.assertFalse(self.case.result["namespace_pins_released"])

    def test_failed_stop_exact_owned_force_removal_then_pin_release(self):
        self.case.specs = [self.spec]
        self.case.fds = [123]
        c = fixture(self.spec, True)
        calls = []
        def fake_inspect(_ref):
            return None if any(x[:3] == ["docker", "rm", "--force"] for x in calls) else c
        def fake_run(args, **_kw):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0 if "--force" in args else 1, "", "")
        with patch.object(m, "inspect", side_effect=fake_inspect), patch.object(m, "run", side_effect=fake_run), patch.object(m.os, "close") as close:
            self.assertEqual(self.case.cleanup(), [])
            close.assert_called_once_with(123)
        self.assertEqual(self.case.fds, [])
        self.assertTrue(self.case.result["tracer_exit_confirmed_before_namespace_release"])

    def test_uncertain_create_only_adopts_exact_new_name(self):
        self.spec.argv = ["trace"]
        c = fixture(self.spec)
        with patch.object(m, "inspect", side_effect=[None, c]), patch.object(m, "run", return_value=subprocess.CompletedProcess([], 1, "", "error")):
            self.assertRaises(RuntimeError, self.case.create, self.spec)
        self.assertEqual(self.case.ids.get("tracer"), c["Id"])
        self.assertIn(self.spec, self.case.specs)

    def test_failed_evidence_never_passes(self):
        (self.case.evidence / "failed.json").write_text('{"pass":false}')
        self.assertRaises(RuntimeError, self.case.wait_json, "failed.json")

    def test_expired_wait_is_bounded(self):
        self.case.deadline = 0
        self.assertRaises(TimeoutError, self.case.wait_json, "absent.json")
        self.assertRaises(TimeoutError, self.case.wait_exit, "tracer")

    def test_plan_is_offline(self):
        path = Path(__file__).resolve().parents[1] / "runtime-netns.py"
        p = subprocess.run(["python3", str(path), "--port", "18080"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(json.loads(p.stdout)["execute"])
        self.assertEqual(json.loads(p.stdout)["port"], 18080)

    def test_invalid_port_rejected_before_execution(self):
        path = Path(__file__).resolve().parents[1] / "runtime-netns.py"
        p = subprocess.run(["python3", str(path), "--port", "65536"], capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)

if __name__ == "__main__":
    unittest.main(verbosity=2)
