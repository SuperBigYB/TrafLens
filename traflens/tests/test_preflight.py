import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "preflight", Path(__file__).resolve().parents[1] / "scripts" / "preflight.py"
)
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


class CommandTests(unittest.TestCase):
    @mock.patch.object(preflight.subprocess, "run", side_effect=FileNotFoundError())
    def test_missing_command_is_reported(self, run):
        result = preflight.run_command(["missing"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "command not found")

    @mock.patch.object(preflight.subprocess, "run", side_effect=subprocess.TimeoutExpired("git", 5))
    def test_timeout_does_not_abort_snapshot(self, run):
        self.assertIn("timed out", preflight.run_command(["git", "--version"])["error"])

    @mock.patch.object(preflight.subprocess, "run")
    def test_nonzero_exit_without_stderr_is_explicit(self, run):
        run.return_value = subprocess.CompletedProcess(["git"], 2, "", "")
        result = preflight.run_command(["git"])
        self.assertFalse(result["ok"])
        self.assertIn("2", result["error"])
        self.assertEqual(run.call_args.kwargs["timeout"], 5)
        self.assertNotIn("shell", run.call_args.kwargs)

    @mock.patch.object(preflight.shutil, "which", return_value=None)
    @mock.patch.object(preflight, "run_command")
    def test_missing_tool_keeps_version_null(self, run, which):
        self.assertEqual(preflight.probe_tool(["go", "version"]), {
            "available": False, "path": None, "version": None, "error": "command not found"
        })
        run.assert_not_called()

    @mock.patch.object(preflight.subprocess, "run")
    def test_command_preserves_git_status_columns(self, run):
        run.return_value = subprocess.CompletedProcess(["git"], 0, " M README.md\n", "")
        self.assertEqual(preflight.run_command(["git"])["stdout"], " M README.md")

    @mock.patch.object(preflight.shutil, "which", return_value="/usr/bin/clang")
    @mock.patch.object(preflight, "run_command", return_value={"ok": True, "stdout": "clang version 18\nTarget: x86", "error": None})
    def test_tool_version_keeps_only_first_line(self, run, which):
        result = preflight.probe_tool(["clang", "--version"])
        self.assertEqual(result["version"], "clang version 18")
        run.assert_called_once_with(["/usr/bin/clang", "--version"])


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.assertEqual(self.repo.resolve().parent, Path(__file__).resolve().parent)
        (self.repo / "traflens").mkdir()

    @mock.patch.object(preflight, "run_command")
    def test_source_pin_and_dirty_worktree(self, run):
        run.side_effect = [
            {"ok": True, "stdout": "b" * 40, "error": None},
            {"ok": True, "stdout": " M README.md\n?? local.txt", "error": None},
        ]
        (self.repo / "traflens" / "upstream.json").write_text(json.dumps({
            "sha": "A" * 40,
            "token": "must-not-be-collected",
            "url": "https://secret@example.invalid/repo",
        }), encoding="utf-8")
        result = preflight.collect_source(self.repo)
        self.assertEqual(result["upstream"], {"sha": "a" * 40, "error": None})
        self.assertEqual(result["git_sha"], "b" * 40)
        self.assertEqual(len(result["git_status"]), 2)
        self.assertNotIn("secret", json.dumps(result))
        self.assertNotIn("must-not-be-collected", json.dumps(result))

    @mock.patch.object(preflight, "run_command", return_value={"ok": False, "stdout": "", "error": "not a git repository"})
    def test_git_failure_and_missing_pin_are_explicit(self, run):
        result = preflight.collect_source(self.repo)
        self.assertIsNone(result["git_sha"])
        self.assertIsNone(result["git_status"])
        self.assertEqual(result["git_error"], "not a git repository")
        self.assertIsNotNone(result["upstream"]["error"])

    @mock.patch.object(preflight, "run_command", return_value={"ok": True, "stdout": "", "error": None})
    def test_malformed_and_short_pins_are_rejected(self, run):
        for document in ("{", "[]", '{"sha":"abc123"}'):
            with self.subTest(document=document):
                (self.repo / "traflens" / "upstream.json").write_text(document, encoding="utf-8")
                result = preflight.collect_source(self.repo)
                self.assertIsNone(result["upstream"]["sha"])
                self.assertIsNotNone(result["upstream"]["error"])


class HostTests(unittest.TestCase):
    @mock.patch.object(preflight, "read_text", return_value="MemTotal: 1024 kB\nMemAvailable: 512 kB\nSwapTotal: 0 kB\nOther: 10 kB")
    def test_memory_units_are_bytes(self, read):
        self.assertEqual(preflight.collect_memory(), {
            "total_bytes": 1048576, "available_bytes": 524288, "swap_total_bytes": 0
        })

    @mock.patch.object(preflight, "read_text", return_value=None)
    @mock.patch.object(preflight.shutil, "disk_usage", side_effect=OSError("unavailable"))
    def test_missing_linux_metadata_and_disk_are_not_zero(self, disk, read):
        result = preflight.collect_host(Path("/missing"))
        self.assertIsNone(result["memory"]["total_bytes"])
        self.assertIsNone(result["cpu"]["model"])
        self.assertIsNone(result["disk"]["free_bytes"])
        self.assertEqual(result["disk"]["error"], "unavailable")


class InterfaceTests(unittest.TestCase):
    @mock.patch.object(preflight, "run_command")
    def test_interface_path_traversal_is_rejected(self, run):
        for name in ("..", "../eth0", "eth0;touch file", ""):
            with self.subTest(name=name):
                result = preflight.collect_interface(name)
                self.assertFalse(result["exists"])
                self.assertIn("invalid", result["errors"][0])
        run.assert_not_called()

    @mock.patch.object(preflight.Path, "is_dir", return_value=False)
    def test_nonexistent_interface_is_explicit(self, directory):
        result = preflight.collect_interface("eth99")
        self.assertFalse(result["exists"])
        self.assertIsNone(result["carrier"])
        self.assertEqual(result["addresses"], [])

    @mock.patch.object(preflight.Path, "is_dir", return_value=True)
    @mock.patch.object(preflight, "read_text", side_effect=["up", "1", "10000"])
    @mock.patch.object(preflight, "run_command")
    def test_live_interface_includes_units_and_addresses(self, run, read, directory):
        run.return_value = {"ok": True, "stdout": json.dumps([{"addr_info": [{
            "family": "inet", "local": "192.0.2.1", "prefixlen": 30, "extra": "omitted"
        }]}]), "error": None}
        result = preflight.collect_interface("enp1s0f0")
        self.assertEqual(result["speed_mbps"], 10000)
        self.assertEqual(result["carrier"], 1)
        self.assertEqual(result["addresses"], [{"family": "inet", "address": "192.0.2.1", "prefix_length": 30}])
        run.assert_called_once_with(["ip", "-j", "address", "show", "dev", "enp1s0f0"])

    @mock.patch.object(preflight.Path, "is_dir", return_value=True)
    @mock.patch.object(preflight, "read_text", side_effect=["down", None, "-1"])
    @mock.patch.object(preflight, "run_command", return_value={"ok": False, "stdout": "", "error": "command not found"})
    def test_down_interface_and_missing_ip_are_not_reported_as_ready(self, run, read, directory):
        result = preflight.collect_interface("eth0")
        self.assertEqual(result["operstate"], "down")
        self.assertIsNone(result["carrier"])
        self.assertIsNone(result["speed_mbps"])
        self.assertEqual(result["errors"], ["command not found"])

    @mock.patch.object(preflight.Path, "is_dir", return_value=True)
    @mock.patch.object(preflight, "read_text", return_value=None)
    @mock.patch.object(preflight, "run_command")
    def test_malformed_ip_json_does_not_abort_snapshot(self, run, read, directory):
        for content in ("invalid", "{}", '[{"addr_info": [7]}]'):
            with self.subTest(content=content):
                run.return_value = {"ok": True, "stdout": content, "error": None}
                result = preflight.collect_interface("eth0")
                self.assertEqual(result["addresses"], [])
                self.assertIn("invalid JSON", result["errors"][0])


class SchemaTests(unittest.TestCase):
    @mock.patch.object(preflight, "__file__", "/preflight.py")
    @mock.patch.object(preflight, "collect_preflight", return_value={"schema_version": 1})
    def test_explicit_repo_works_when_script_is_copied_to_shallow_path(self, collect):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(preflight.sys, "stdout", new_callable=io.StringIO):
            self.assertEqual(preflight.main(["--repo", directory]), 0)
            collect.assert_called_once_with(Path(directory), [])

    @mock.patch.object(preflight, "collect_source", return_value={"git_sha": None})
    @mock.patch.object(preflight, "collect_host", return_value={"kernel": "test"})
    @mock.patch.object(preflight, "probe_tool", return_value={"available": False})
    @mock.patch.object(preflight, "collect_interface", side_effect=lambda name: {"name": name})
    def test_top_level_schema_utc_and_interface_deduplication(self, interface, tool, host, source):
        result = preflight.collect_preflight(Path("."), ["eth0", "eth0", "eth1"])
        self.assertEqual(set(result), {"schema_version", "generated_at", "source", "host", "tools", "network_interfaces"})
        self.assertEqual(result["schema_version"], 1)
        self.assertTrue(result["generated_at"].endswith("Z"))
        self.assertEqual(set(result["tools"]), set(preflight.TOOLS))
        self.assertEqual(result["network_interfaces"], [{"name": "eth0"}, {"name": "eth1"}])
        json.dumps(result)


if __name__ == "__main__":
    unittest.main()
