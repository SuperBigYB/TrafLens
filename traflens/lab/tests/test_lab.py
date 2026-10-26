import importlib.util
import io
import json
import os
import pathlib
import signal
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import lab

spec = importlib.util.spec_from_file_location("run_agent", HERE / "run-agent.py")
run_agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_agent)


class SupervisorIdentityTests(unittest.TestCase):
    def setUp(self):
        self.repo = pathlib.Path("/work/repo-a").resolve()
        self.script = pathlib.Path("/work/helpers/run-agent.py").resolve()
        self.pid = 12345
        self.identity = {"pid": self.pid, "start_ticks": 45678,
                         "repo": str(self.repo), "script": str(self.script)}
        self.snapshot = {key: value for key, value in self.identity.items() if key != "pid"}

    def assert_rejected_without_signal(self, identity, snapshot):
        with mock.patch.object(run_agent, "process_snapshot", return_value=snapshot), \
                mock.patch.object(run_agent.os, "kill") as kill:
            with self.assertRaises(RuntimeError):
                run_agent.signal_owned_supervisor(identity, self.pid, self.repo, self.script)
            kill.assert_not_called()

    def test_exact_identity_signals_owned_supervisor(self):
        with mock.patch.object(run_agent, "process_snapshot", return_value=self.snapshot), \
                mock.patch.object(run_agent.os, "kill") as kill:
            run_agent.signal_owned_supervisor(self.identity, self.pid, self.repo, self.script)
            kill.assert_called_once_with(self.pid, signal.SIGTERM)

    def test_reused_pid_never_signals(self):
        self.assert_rejected_without_signal(self.identity, dict(self.snapshot, start_ticks=99999))

    def test_same_script_other_repo_never_signals(self):
        self.assert_rejected_without_signal(self.identity, dict(self.snapshot, repo="/work/repo-b"))

    def test_other_script_never_signals(self):
        self.assert_rejected_without_signal(self.identity, dict(self.snapshot, script="/work/other.py"))

    def test_record_for_other_repo_never_signals(self):
        self.assert_rejected_without_signal(dict(self.identity, repo="/work/repo-b"), self.snapshot)

    def test_missing_start_ticks_never_signals(self):
        identity = dict(self.identity)
        del identity["start_ticks"]
        self.assert_rejected_without_signal(identity, self.snapshot)

    @unittest.skipUnless(pathlib.Path("/proc/self/stat").exists(), "Linux process identity")
    def test_launch_refuses_foreign_live_same_script(self):
        with tempfile.TemporaryDirectory(prefix="traflens-identity-test-") as temporary:
            work = pathlib.Path(temporary)
            identity = dict(self.identity, pid=os.getpid())
            (work / "supervisor.pid").write_text(str(os.getpid()))
            (work / "supervisor-identity.json").write_text(json.dumps(identity))
            with mock.patch.object(run_agent, "process_snapshot", return_value=dict(self.snapshot, repo="/work/repo-b")):
                with self.assertRaises(RuntimeError):
                    run_agent.refuse_live_supervisor(work, self.repo, self.script)


class RuntimeProvenanceTests(unittest.TestCase):
    def container_info(self, root, image):
        return {"Config": {"Labels": {lab.LABEL: str(root)}}, "Image": image}

    def test_existing_server_image_mismatch_requires_recreate(self):
        root = pathlib.Path("/tmp/traflens-test").resolve()
        with mock.patch.object(lab, "inspect", side_effect=[self.container_info(root, "sha256:old"), {"Id": "sha256:new"}]), \
                mock.patch.object(lab, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "--recreate-server"):
                lab.container(root, "server", [], "requested:tag", [], False)
            run.assert_not_called()

    def test_matching_image_can_be_reused(self):
        root = pathlib.Path("/tmp/traflens-test").resolve()
        with mock.patch.object(lab, "inspect", side_effect=[self.container_info(root, "sha256:same"), {"Id": "sha256:same"}]), \
                mock.patch.object(lab, "run") as run, mock.patch("builtins.print"):
            lab.container(root, "server", [], "requested:tag", [], False)
            run.assert_called_once_with(["docker", "start", "traflens-lab-server"], capture=True)

    def archive(self, path, entries):
        with tarfile.open(path, "w:gz") as output:
            for name, content in entries.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                output.addfile(info, io.BytesIO(content))

    def test_upgrade_does_not_keep_removed_assets(self):
        with tempfile.TemporaryDirectory(prefix="traflens-runtime-test-") as temporary:
            directory = pathlib.Path(temporary)
            first, second = directory / "first.tgz", directory / "second.tgz"
            self.archive(first, {"bin/deepflow-server": b"one", "etc/removed.conf": b"old"})
            self.archive(second, {"bin/deepflow-server": b"two"})
            old = lab.extract_runtime(first, directory / "runtimes")
            current = lab.extract_runtime(second, directory / "runtimes")
            self.assertNotEqual(old, current)
            self.assertTrue((old / "etc/removed.conf").is_file())
            self.assertFalse((current / "etc/removed.conf").exists())
            self.assertEqual((current / "bin/deepflow-server").read_bytes(), b"two")
            self.assertEqual(lab.extract_runtime(second, directory / "runtimes"), current)

    def test_incomplete_stage_is_not_reused(self):
        with tempfile.TemporaryDirectory(prefix="traflens-runtime-test-") as temporary:
            directory = pathlib.Path(temporary)
            package = directory / "package.tgz"
            self.archive(package, {"bin/deepflow-server": b"new"})
            digest = lab.hashlib.sha256(package.read_bytes()).hexdigest()
            incomplete = directory / "runtimes" / digest
            incomplete.mkdir(parents=True)
            (incomplete / "obsolete").write_text("old")
            current = lab.extract_runtime(package, directory / "runtimes")
            self.assertNotEqual(incomplete, current)
            self.assertFalse((current / "obsolete").exists())


if __name__ == "__main__":
    unittest.main()
