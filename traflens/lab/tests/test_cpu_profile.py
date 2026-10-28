"""Scope, private evidence and recovery tests; no Docker or network needed."""
import contextlib
import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("cpu_profile_entry", HERE / "cpu-profile.py")
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)
import cpu_profile_common as common
import cpu_profile_controller as controller


class FakeAPI:
    def __init__(self):
        self.groups = [{"ID": 1, "LCUUID": "old-group", "NAME": "default", "SHORT_UUID": "g-old", "TEAM_ID": 1,
                        "USER_ID": 1, "VTAP_LCUUIDS": [], "LICENSE_FUNCTIONS": [2, 4]}]
        self.agents = []
        self.configs = {"old-group": '{"sensitive-token":"never-persist-this-test-secret"}'}
        self.mutations = []
        self.fail_agent = False

    def __call__(self, path, body=None, method="GET"):
        if method != "GET":
            self.mutations.append((method, path))
        if path == "/v1/controllers/":
            value = [{"REGION": "owned-region", "AZS": [{"AZ": "owned-az"}]}]
        elif path == "/v1/agent-group-configuration/template/json":
            value = {}
        elif path == "/v1/vtap-groups/":
            if method == "POST":
                value = dict(body, ID=2, LCUUID="new-group", SHORT_UUID="g-new")
                self.groups.append(value)
            else:
                value = self.groups
        elif path == "/v1/vtaps/":
            if method == "POST":
                if self.fail_agent:
                    raise RuntimeError("Synthetic uncertain create failure")
                value = dict(body, ID=9, LCUUID="new-agent", ENABLE=0, LICENSE_FUNCTIONS=[])
                self.agents.append(value)
                self.groups[-1]["VTAP_LCUUIDS"] = [value["LCUUID"]]
            else:
                value = self.agents
        elif path.startswith("/v1/vtaps-license-type/"):
            self.agents[-1].update(body)
            value = self.agents[-1]
        elif path.startswith("/v1/vtaps/"):
            if method == "DELETE":
                self.agents = [a for a in self.agents if a["LCUUID"] != "new-agent"]
                self.groups[-1]["VTAP_LCUUIDS"] = [v for v in self.groups[-1]["VTAP_LCUUIDS"] if v != "new-agent"]
                value = None
            else:
                self.agents[-1].update(body)
                value = self.agents[-1]
        elif path.startswith("/v1/vtap-groups/"):
            self.groups = [g for g in self.groups if g["LCUUID"] != "new-group"]
            self.configs.pop("new-group", None)
            value = None
        elif path == "/v1/agent-group-configuration/json":
            value = self.configs
        elif path.startswith("/v1/agent-group-configuration/") and path.endswith("/yaml"):
            group = path.split("/")[3]
            if method != "GET":
                self.configs[group] = body
            value = self.configs.get(group, "")
        else:
            raise AssertionError("Unexpected request " + path)
        return {"OPT_STATUS": "SUCCESS", "DATA": copy.deepcopy(value)}


class ControllerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.work.chmod(0o700)
        (self.work / "controller-events").mkdir(mode=0o700)
        controller.WORK = self.work
        self.api = FakeAPI()
        self.config = types.SimpleNamespace(check_keys=lambda value, template: None)
        self.value = {"run": "cpu-" + "a" * 24, "ctrl_ip": "172.29.0.2", "ctrl_mac": "02:00:00:00:00:02",
                      "controller_ip": "192.0.2.24", "controller_port": 20035, "ingester_port": 20033}
        self.value["profile"] = common.profile_only(HERE, self.value["controller_ip"], 20035, 20033)

    def tearDown(self):
        self.tmp.cleanup()

    def prepare(self):
        with contextlib.redirect_stdout(io.StringIO()):
            controller.prepare(self.api, self.config, self.value)

    def cleanup(self):
        with contextlib.redirect_stdout(io.StringIO()):
            controller.cleanup(self.api, {"run": self.value["run"], "agent_stopped": True, "owned_agent_removed": True})

    def test_profile_only_license_and_secret_free_baseline(self):
        self.prepare()
        self.assertEqual(self.api.agents[-1]["LICENSE_FUNCTIONS"], [11])
        for path in self.work.rglob("*.json"):
            self.assertNotIn("never-persist-this-test-secret", path.read_text())
        self.assertIn("old-group", common.load(self.work / "controller-baseline.json")["yaml_hashes"])
        self.cleanup()
        self.assertEqual([g["LCUUID"] for g in self.api.groups], ["old-group"])
        self.assertEqual(self.api.agents, [])
        deletes = [path for method, path in self.api.mutations if method == "DELETE"]
        self.assertEqual(deletes, ["/v1/vtaps/new-agent/", "/v1/vtap-groups/new-group/"])

    def test_partial_group_only_failure_can_be_recovered(self):
        self.api.fail_agent = True
        with self.assertRaises(RuntimeError):
            self.prepare()
        self.cleanup()
        self.assertEqual(len(self.api.groups), 1)
        self.assertFalse(any(method == "DELETE" and path.startswith("/v1/vtaps/") for method, path in self.api.mutations))

    def test_uncertain_agent_create_is_reconciled_by_exact_intent(self):
        underlying = self.api
        def uncertain(path, body=None, method="GET"):
            value = underlying(path, body, method)
            if path == "/v1/vtaps/" and method == "POST":
                raise RuntimeError("Response lost after create")
            return value
        with self.assertRaises(RuntimeError):
            controller.prepare(uncertain, self.config, self.value)
        self.assertFalse((self.work / "controller-agent-created.json").exists())
        self.cleanup()
        self.assertTrue(common.load(self.work / "controller-agent-created.json")["recovered_after_uncertain_create"])
        self.assertEqual(self.api.agents, [])
        self.assertEqual(len(self.api.groups), 1)

    def test_group_with_an_unowned_member_is_not_deleted(self):
        self.prepare()
        self.api.groups[-1]["VTAP_LCUUIDS"].append("foreign-agent")
        with self.assertRaises(RuntimeError):
            self.cleanup()
        self.assertFalse(any(method == "DELETE" and path == "/v1/vtap-groups/new-group/" for method, path in self.api.mutations))

    def test_changed_agent_identity_is_not_deleted(self):
        self.prepare()
        self.api.agents[0]["CTRL_MAC"] = "02:00:00:00:00:ff"
        with self.assertRaises(RuntimeError):
            self.cleanup()
        self.assertFalse(any(method == "DELETE" for method, path in self.api.mutations))

    def test_stopped_proof_required_before_agent_delete(self):
        self.prepare()
        with self.assertRaises(RuntimeError):
            controller.cleanup(self.api, {"run": self.value["run"], "agent_stopped": False})
        self.assertFalse(any(method == "DELETE" for method, path in self.api.mutations))

    def test_scope_cannot_enable_other_collection(self):
        self.value["profile"]["inputs"]["proc"]["enabled"] = True
        with self.assertRaises(RuntimeError):
            self.prepare()
        self.assertEqual(self.api.mutations, [])

    def test_existing_name_and_yaml_changes_fail_closed(self):
        self.api.groups[0]["NAME"] = "traflens-" + self.value["run"]
        with self.assertRaises(RuntimeError):
            self.prepare()
        self.assertEqual(self.api.mutations, [])


class RuntimeGuardTests(unittest.TestCase):
    def test_controller_url_rejected_before_output_or_tool_io(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'must-not-exist'
            for url in ('http://user:secret@127.0.0.1:20417', 'http://127.0.0.1:20417?token=secret',
                        'http://127.0.0.1:20417#secret', 'http://127.0.0.1:20417/path',
                        'http://localhost:20417', 'http://192.0.2.1:20417', 'http://127.0.0.1:20417/credential'):
                args = types.SimpleNamespace(controller_url=url, output=str(output))
                with patch.object(entry, 'call', side_effect=AssertionError('No external call allowed')), \
                     patch.object(entry, 'private_dir', side_effect=AssertionError('No directory allowed')):
                    with self.assertRaises(RuntimeError):
                        entry.execute(args)
                self.assertFalse(output.exists())
                self.assertEqual(list(Path(tmp).iterdir()), [])
        self.assertEqual(common.validate_controller_url('http://127.0.0.1:20417').port, 20417)

    def test_owned_controller_binding_precedes_directory_and_api(self):
        import lab
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            output = root / 'must-not-exist'
            info = {'Config': {'Labels': {'io.traflens.lab': str(root)}},
                    'HostConfig': {'NetworkMode': 'owned-bridge'},
                    'NetworkSettings': {'Ports': {'20417/tcp': [{'HostIp':'127.0.0.1', 'HostPort':'20417'}]}}}
            self.assertEqual(common.validate_controller_binding('http://127.0.0.1:20417', info).port, 20417)
            args = types.SimpleNamespace(controller_url='http://127.0.0.1:20418', backend_root=str(root),
                                         work=str(output), action='prepare', server_container='owned-server')
            with patch.object(lab, 'inspect', return_value=info), \
                 patch.object(controller.urllib.request, 'urlopen', side_effect=AssertionError('No API allowed')):
                with self.assertRaises(RuntimeError):
                    controller.dispatch(args)
            self.assertFalse(output.exists())
            self.assertEqual(list(root.iterdir()), [])
            for address in ('0.0.0.0', '127.0.0.2'):
                changed = copy.deepcopy(info)
                changed['NetworkSettings']['Ports']['20417/tcp'][0]['HostIp'] = address
                with self.assertRaises(RuntimeError):
                    common.validate_controller_binding('http://127.0.0.1:20417', changed)
            changed = copy.deepcopy(info)
            changed['HostConfig']['NetworkMode'] = 'host'
            with self.assertRaises(RuntimeError):
                common.validate_controller_binding('http://127.0.0.1:20417', changed)

    def test_only_exact_missing_inspection_means_absent(self):
        for text in ("Error: No such container: owned-agent\n", "Error response from daemon: No such object: owned-agent\n",
                     "Error response from daemon: network owned-agent not found\n"):
            with patch.object(entry, "call", return_value=types.SimpleNamespace(returncode=1, stderr=text, stdout="[]")):
                self.assertIsNone(entry.inspect("container", "owned-agent"))
        for text in ("permission denied", "Cannot connect to the Docker daemon", "Error: No such container: foreign-agent",
                     "Error: No such container: owned-agent\npermission denied", ""):
            with patch.object(entry, "call", return_value=types.SimpleNamespace(returncode=1, stderr=text, stdout="[]")):
                with self.assertRaises(RuntimeError):
                    entry.inspect("container", "owned-agent")

    def test_unavailable_docker_never_authorizes_controller_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = {"names": {"agent": "owned-agent", "upload": "owned-upload", "namespace": "owned-ns", "network": "owned-network"},
                     "controller_attempted": True, "args": {"controller_ip": "192.0.2.24"}}
            with patch.object(entry, "inspect", side_effect=RuntimeError("Daemon unavailable")), patch.object(entry, "backend") as backend, \
                 patch.object(entry, "snapshot", return_value={}):
                result = entry.cleanup(work, state)
            backend.assert_not_called()
            self.assertFalse(result["cleaned"])

    def test_default_plan_never_calls_external_tools_or_writes(self):
        output = io.StringIO()
        with patch.object(entry, "call", side_effect=AssertionError("No tool allowed")), patch.object(entry, "execute", side_effect=AssertionError("No execute allowed")), contextlib.redirect_stdout(output):
            self.assertEqual(entry.main([]), 0)
        self.assertFalse(json.loads(output.getvalue())["execute"])

    def test_immutable_container_scope(self):
        state = {"run": "cpu-" + "1" * 24, "output": "/private/new", "image_id": "sha256:" + "2" * 64,
                 "network_modes": {"agent": "container:owned-anchor"}}
        info = {"Image": state["image_id"], "Config": {"Labels": {"io.traflens.run": state["run"], "io.traflens.output": state["output"],
                "io.traflens.purpose": "traflens.cpu-profile.agent"}}, "HostConfig": {"NanoCpus": 1000000000, "Memory": 1073741824,
                "PidsLimit": 384, "Privileged": False, "CapDrop": ["ALL"], "ReadonlyRootfs": True, "PortBindings": {},
                "PidMode": "", "RestartPolicy": {"Name": "no"}, "NetworkMode": "container:owned-anchor"}}
        self.assertTrue(entry.owned(info, state, "agent"))
        for key, value in (("Privileged", True), ("ReadonlyRootfs", False), ("NetworkMode", "host"), ("PortBindings", {"39093/tcp": [{}]}), ("CapDrop", [])):
            changed = copy.deepcopy(info)
            changed["HostConfig"][key] = value
            self.assertFalse(entry.owned(changed, state, "agent"))

    def test_profile_receipt_hash_and_original_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "cpu.pprof"
            raw = gzip.compress(b"finite-test-profile")
            profile.write_bytes(raw)
            receipt = {"source": "go_runtime_pprof_self", "sampling_scope": "current process only", "run": "cpu-" + "2" * 24,
                       "completed_duration": True, "stop_reason": "duration", "started_unix_ns": 1700000000123456789,
                       "finished_unix_ns": 1700000008123456789, "profile_bytes": len(raw),
                       "profile_sha256": entry.hashlib.sha256(raw).hexdigest()}
            receipt_path = root / "receipt.json"
            receipt_path.write_text(json.dumps(receipt))
            checked = common.receipt(profile, receipt_path)
            self.assertEqual((checked["from"], checked["to"]), (1700000000, 1700000009))
            profile.write_bytes(raw + b"changed")
            with self.assertRaises(RuntimeError):
                common.receipt(profile, receipt_path)

    def test_private_output_does_not_reuse_or_follow_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            output = common.private_dir(root / "fresh", fresh=True)
            with self.assertRaises(FileExistsError):
                common.private_dir(output, fresh=True)
            (root / "alias").symlink_to(output, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                common.private_dir(root / "alias")


if __name__ == "__main__":
    unittest.main()
