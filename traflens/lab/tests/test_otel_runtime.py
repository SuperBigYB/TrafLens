"""Offline guards for the owned, finite SDK span lifecycle."""
import argparse
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
SPEC = importlib.util.spec_from_file_location("otel_runtime_under_test", LAB / "otel-spans.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def state_fixture(work):
    state = {
        "run": "span-" + "1" * 24,
        "output": str(work),
        "image": "sha256:" + "a" * 64,
        "network": "traflens-owned-span-network",
        "args": {"controller_ip": "192.0.2.240"},
        "controller_attempted": True,
        "resources": {},
    }
    state["resources"]["agent"] = {
        "name": "traflens-owned-span-agent", "id": "c" * 64,
        "network": "container:" + "b" * 64,
        "entrypoint": "/usr/bin/timeout", "command": ["180", "/opt/agent"],
        "mounts": [["/owned/agent", "/opt/agent", False]],
    }
    return state


def info_fixture(state, running=False):
    intent = state["resources"]["agent"]
    cpu, memory, pids = runtime.LIMITS["agent"]
    return {
        "Id": intent["id"], "Image": state["image"],
        "Config": {
            "Labels": {"io.traflens.run": state["run"], "io.traflens.output": state["output"],
                       "io.traflens.purpose": "traflens.otel-spans.agent"},
            "Entrypoint": [intent["entrypoint"]], "Cmd": intent["command"],
        },
        "HostConfig": {"NanoCpus": cpu, "Memory": memory, "PidsLimit": pids,
                       "NetworkMode": intent["network"], "PidMode": "", "CapDrop": ["ALL"],
                       "Privileged": False, "ReadonlyRootfs": True,
                       "RestartPolicy": {"Name": "no"}, "PortBindings": {}},
        "Mounts": [{"Type": "bind", "Source": "/owned/agent", "Destination": "/opt/agent", "RW": False}],
        "State": {"Running": running, "ExitCode": 0, "OOMKilled": False},
    }


class OTelRuntimeGuards(unittest.TestCase):
    def test_default_plan_never_reads_artifacts_or_creates_resources(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "must-not-exist"
            with mock.patch.object(sys, "argv", ["otel-spans.py", "--output", str(output)]), \
                    mock.patch.object(runtime, "private_dir", side_effect=AssertionError("filesystem mutation")), \
                    mock.patch.object(runtime, "inspect", side_effect=AssertionError("Docker inspection")), \
                    mock.patch.object(runtime, "call", side_effect=AssertionError("subprocess")), \
                    mock.patch.object(runtime.util, "file_hash", side_effect=AssertionError("artifact read")), \
                    mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(runtime.main(), 0)
                plan = json.loads(out.getvalue())
            self.assertFalse(output.exists())
            self.assertFalse(plan["execute"])
            self.assertFalse(plan["starts_network"])
            self.assertFalse(plan["creates_resources"])
            self.assertEqual(plan["normal_license_function"], 6)

    def test_invalid_controller_url_is_rejected_before_any_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "never-created"
            for endpoint in ["http://user:secret@127.0.0.1:20417", "http://127.0.0.1:20417?token=secret",
                             "http://192.0.2.240:20417", "https://127.0.0.1:20417", "http://127.0.0.1:20417/other"]:
                with self.subTest(endpoint=endpoint), \
                        mock.patch.object(runtime, "private_dir", side_effect=AssertionError("output before validation")), \
                        mock.patch.object(runtime, "inspect", side_effect=AssertionError("Docker before validation")):
                    args = argparse.Namespace(controller_url=endpoint, output=str(output))
                    with self.assertRaises((RuntimeError, ValueError)):
                        runtime.execute(args)
            self.assertFalse(output.exists())

    def test_owned_requires_exact_id_and_restricted_execution_spec(self):
        state = state_fixture("/owned/output")
        info = info_fixture(state)
        self.assertTrue(runtime.owned(info, state, "agent"))
        changes = [
            lambda v: v.update(Id="d" * 64),
            lambda v: v.update(Image="sha256:" + "d" * 64),
            lambda v: v["Config"]["Labels"].update({"io.traflens.run": "span-" + "2" * 24}),
            lambda v: v["Config"].update(Cmd=["/unrelated"]),
            lambda v: v["Mounts"][0].update(RW=True),
            lambda v: v["HostConfig"].update(NetworkMode="host"),
            lambda v: v["HostConfig"].update(PidMode="host"),
            lambda v: v["HostConfig"].update(Privileged=True),
            lambda v: v["HostConfig"].update(PortBindings={"39093/tcp": [{"HostPort": "39093"}]}),
            lambda v: v["HostConfig"].update(Memory=0),
        ]
        for change in changes:
            changed = copy.deepcopy(info)
            change(changed)
            self.assertFalse(runtime.owned(changed, state, "agent"))
        self.assertFalse(runtime.owned(None, state, "agent"))

    def test_docker_unavailability_does_not_prove_stopped_or_remove_controller(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = state_fixture(work)
            with mock.patch.object(runtime, "inspect", side_effect=RuntimeError("Docker unavailable")), \
                    mock.patch.object(runtime, "call") as call, \
                    mock.patch.object(runtime, "backend") as backend, \
                    mock.patch.object(runtime.util, "snapshot", return_value={"containers": [], "networks": [], "route": [], "bpf": []}):
                result = runtime.cleanup(work, state)
            self.assertFalse(result["cleaned"])
            self.assertTrue(any("absence" in value for value in result["cleanup_errors"]))
            backend.assert_not_called()
            call.assert_not_called()

    def test_foreign_container_is_retained_and_controller_cleanup_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = state_fixture(work)
            info = info_fixture(state, running=True)
            info["Id"] = "e" * 64
            with mock.patch.object(runtime, "inspect", return_value=info), \
                    mock.patch.object(runtime, "call") as call, \
                    mock.patch.object(runtime, "backend") as backend, \
                    mock.patch.object(runtime.util, "snapshot", return_value={"containers": [], "networks": [], "route": [], "bpf": []}):
                result = runtime.cleanup(work, state)
            self.assertFalse(result["cleaned"])
            self.assertTrue(any("controller retained" in value for value in result["cleanup_errors"]))
            backend.assert_not_called()
            call.assert_not_called()

    def test_uncertain_create_retains_spec_before_start_for_later_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = state_fixture(work)
            state["resources"] = {}
            with mock.patch.object(runtime, "inspect", return_value=None), \
                    mock.patch.object(runtime, "call", side_effect=subprocess.TimeoutExpired("docker", 35)) as call:
                with self.assertRaises(subprocess.TimeoutExpired):
                    runtime.create(work, state, "agent", "container:owned-anchor", ["180", "/opt/agent"],
                                   [("/owned/agent", "/opt/agent", False)])
            saved = json.loads((work / "state.json").read_text())
            intent = saved["resources"]["agent"]
            self.assertNotIn("id", intent)
            self.assertEqual(intent["command"], ["180", "/opt/agent"])
            self.assertEqual(intent["mounts"], [["/owned/agent", "/opt/agent", False]])
            self.assertEqual(call.call_count, 1)
            self.assertEqual(call.call_args.args[0][:2], ["docker", "create"])

    def test_path_mount_source_is_persisted_as_string_before_uncertain_create(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            source = work / "agent-binary"
            state = state_fixture(work)
            state["resources"] = {}
            with mock.patch.object(runtime, "inspect", return_value=None), \
                    mock.patch.object(runtime, "call", side_effect=subprocess.TimeoutExpired("docker", 35)) as call:
                with self.assertRaises(subprocess.TimeoutExpired):
                    runtime.create(work, state, "agent", "container:owned-anchor", ["180", "/opt/agent"],
                                   [(source, "/opt/agent", False)])
            intent = json.loads((work / "state.json").read_text())["resources"]["agent"]
            self.assertEqual(intent["mounts"], [[str(source), "/opt/agent", False]])
            self.assertIsInstance(intent["mounts"][0][0], str)
            self.assertNotIn("id", intent)
            self.assertEqual(call.call_count, 1)
            self.assertEqual(call.call_args.args[0][:2], ["docker", "create"])


if __name__ == "__main__":
    unittest.main()
